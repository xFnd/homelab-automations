#!/usr/bin/env python3
"""hp-relay-collector: resume (só leitura) o log JSON do Cowrie da VPS2 para o n8n de casa. D4, HOMELAB §7.

Roda como root (hp-relay-collector.service). A cada 15 min grava /var/lib/hp-relay/stats.json (root:hp-relay, 640)
com a janela das últimas 24h. O n8n lê por SSH com a chave de comando forçado (/usr/local/bin/hp-relay).
Tudo que vem do Cowrie (usuário, senha, comando, URL) é texto do atacante: o n8n sanitiza antes de mostrar.

Desde 16/10 (tarefa 2, HOMELAB §15.12) grava também /var/lib/hp-relay/blocklist.json: os IPs que TENTARAM LOGIN
na isca nas últimas 24h (comportamento hostil observado; só conectar não conta, porque scanners de pesquisa
também conectam). O CT 106 (hp-block-sync) lê essa lista e pede bloqueio preventivo de 48h ao CrowdSec da VPS1.

Uso manual (teste): hp-collect.py once   ·   sem argumento = laço do serviço.
"""
import collections, datetime as dt, glob, grp, ipaddress, json, os, re, socket, subprocess, sys, tempfile, time, traceback

OUT = "/var/lib/hp-relay"
GROUP = "hp-relay"
LOGS = "/opt/cowrie/hp/var/log/cowrie/cowrie.json*"
EVERY = 900
UPDATES_EVERY = 6 * 3600
_UPDATES = {"at": 0.0, "val": None}
CUT = 160  # corte de strings vindas do atacante


def run(*cmd, timeout=90):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def now():
    return dt.datetime.now(dt.timezone.utc)


def events(since):
    """Eventos do Cowrie desde `since` (lê o arquivo atual e os rotacionados dos últimos 2 dias)."""
    files = [f for f in glob.glob(LOGS) if os.path.getmtime(f) >= since.timestamp() - 86400]
    for path in sorted(files):
        with open(path, errors="replace") as f:
            for line in f:
                try:
                    e = json.loads(line)
                    t = dt.datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00"))
                except (ValueError, KeyError):
                    continue
                if t >= since:
                    yield e


def top(counter, n=10):
    return [[k, v] for k, v in counter.most_common(n)]


MAX_KEYS = 20000  # R5 (15/10): o atacante controla a cardinalidade (milhões de senhas distintas) → teto de chaves
BLOCK_CAP = 2000  # teto da lista de bloqueio preventivo (os mais recentes ficam)


def add(counter, key):
    if key in counter or len(counter) < MAX_KEYS:
        counter[key] += 1


def note_login(seen, e):
    """Guarda o IP de quem tentou login (falhou ou "conseguiu" no shell falso), com o horário mais recente."""
    if e.get("eventid") in ("cowrie.login.failed", "cowrie.login.success"):
        ip, ts = e.get("src_ip"), str(e.get("timestamp", ""))
        if ip and (ip in seen or len(seen) < MAX_KEYS):
            seen[ip] = max(seen.get(ip, ""), ts)


def build_blocklist(seen, cap=BLOCK_CAP, generated_at=""):
    """Lista para o bloqueio preventivo: só IP público válido, mais recentes primeiro, no máximo `cap`."""
    ok = []
    for ip, ts in seen.items():
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if a.is_global and not a.is_multicast:
            ok.append((ts, a.compressed))
    ok.sort(reverse=True)
    return {"generated_at": generated_at, "window": "24h", "criteria": "tentou login na isca (cowrie.login.failed/success)",
            "count": min(len(ok), cap), "truncated": len(ok) > cap, "ips": [ip for _, ip in ok[:cap]]}


def egress_drops():
    out = run("iptables", "-L", "OUTPUT", "-v", "-n", "-x").stdout
    m = re.search(r"^\s*(\d+)\s+\d+\s+DROP.*owner UID match", out, re.M)
    return int(m.group(1)) if m else None


def system_stats():
    mem = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, v = line.split(":", 1)
            mem[k] = int(v.split()[0]) // 1024
    st = os.statvfs("/")
    if time.time() - _UPDATES["at"] > UPDATES_EVERY:
        sim = run("apt-get", "-s", "-o", "Debug::NoLocking=1", "-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache=",
                  "upgrade", timeout=120)
        inst = [l for l in sim.stdout.splitlines() if l.startswith("Inst ")]
        _UPDATES.update(at=time.time(), val={"total": len(inst), "security": sum("-security" in l for l in inst)}
                        if sim.returncode == 0 else None)
    with open("/proc/uptime") as f:
        uptime = int(float(f.read().split()[0]))
    cowrie_mem = run("systemctl", "show", "cowrie", "-p", "MemoryCurrent", "--value").stdout.strip()
    return {"uptime_s": uptime, "load1": round(os.getloadavg()[0], 2), "mem_available_mb": mem.get("MemAvailable"),
            "swap_used_mb": mem.get("SwapTotal", 0) - mem.get("SwapFree", 0),
            "disk_used_pct": round(100 * (1 - st.f_bavail / st.f_blocks), 1),
            "reboot_required": os.path.exists("/var/run/reboot-required"), "updates_available": _UPDATES["val"],
            "units": {u: run("systemctl", "is-active", u).stdout.strip() for u in ("cowrie", "ssh")},
            "cowrie_mem_mb": int(cowrie_mem) // 2**20 if cowrie_mem.isdigit() else None}


def stats():
    since = now() - dt.timedelta(hours=24)
    sess = {}  # session → {ip, cmds, success}
    ips, users, pwds, pairs, cmds = (collections.Counter() for _ in range(5))
    versions, hassh, downloads, uploads, tcpip = (collections.Counter() for _ in range(5))
    failed = success = redirs = 0
    login_seen = {}  # IP → último login tentado (lista de bloqueio preventivo)
    for e in events(since):
        ev, sid, ip = e.get("eventid", ""), e.get("session"), e.get("src_ip")
        s = sess.setdefault(sid, {"ip": ip, "cmds": 0, "success": False})
        note_login(login_seen, e)
        if ev == "cowrie.session.connect":
            ips[ip] += 1
        elif ev in ("cowrie.login.failed", "cowrie.login.success"):
            u, p = str(e.get("username", ""))[:CUT], str(e.get("password", ""))[:CUT]
            add(users, u)
            add(pwds, p)
            add(pairs, f"{u}:{p}"[:CUT])
            if ev.endswith("success"):
                success += 1
                s["success"] = True
            else:
                failed += 1
        elif ev == "cowrie.command.input":
            add(cmds, str(e.get("input", ""))[:CUT])
            s["cmds"] += 1
        elif ev == "cowrie.client.version":
            add(versions, str(e.get("version", ""))[:CUT])
        elif ev == "cowrie.client.kex":
            add(hassh, str(e.get("hassh", ""))[:64])
        elif ev.startswith("cowrie.session.file_download"):
            # sem URL = arquivo criado por redirecionamento (echo > arq), não download de rede
            if e.get("url"):
                add(downloads, str(e["url"])[:CUT])
            else:
                redirs += 1
        elif ev == "cowrie.session.file_upload":
            add(uploads, f'{str(e.get("filename", ""))[:80]} sha256:{str(e.get("shasum", ""))[:16]}')
        elif ev == "cowrie.direct-tcpip.request":
            add(tcpip, f'{str(e.get("dst_ip", ""))[:64]}:{e.get("dst_port")}')
    by_ip = collections.defaultdict(lambda: {"sessions": 0, "logins_ok": 0, "commands": 0})
    for s in sess.values():
        if not s["ip"]:
            continue
        b = by_ip[s["ip"]]
        b["sessions"] += 1
        b["logins_ok"] += s["success"]
        b["commands"] += s["cmds"]
    top_ips = sorted(({"ip": k, **v} for k, v in by_ip.items()), key=lambda x: (-x["commands"], -x["sessions"]))[:10]
    generated = now().strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "generated_at": generated, "host": socket.gethostname(), "window": "24h",
        "sessions": sum(ips.values()), "distinct_ips": len(ips), "logins_failed": failed, "logins_success": success,
        "interactive_sessions": sum(1 for s in sess.values() if s["cmds"]), "commands_total": sum(cmds.values()),
        "top_ips": top_ips, "top_users": top(users), "top_passwords": top(pwds), "top_pairs": top(pairs),
        "top_commands": top(cmds, 15), "client_versions": top(versions, 5), "hassh": top(hassh, 5),
        "downloads": top(downloads), "redir_files": redirs, "uploads": top(uploads), "direct_tcpip": top(tcpip),
        "egress_drops_total": egress_drops(), "system": system_stats(),
    }, build_blocklist(login_seen, generated_at=generated)


def write(name, obj):
    gid = grp.getgrnam(GROUP).gr_gid
    fd, tmp = tempfile.mkstemp(dir=OUT, prefix=f".{name}.")
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f, ensure_ascii=False, separators=(",", ":"))
    os.chown(tmp, 0, gid)
    os.chmod(tmp, 0o640)
    os.replace(tmp, os.path.join(OUT, f"{name}.json"))


def collect_once():
    st, bl = stats()
    write("stats", st)
    write("blocklist", bl)


def main():
    if len(sys.argv) > 1:
        collect_once()
        return
    while True:
        t0 = time.time()
        try:
            collect_once()
        except Exception:
            print(f"[stats] erro:\n{traceback.format_exc()}", file=sys.stderr, flush=True)
        time.sleep(max(30.0, EVERY - (time.time() - t0)))


if __name__ == "__main__":
    main()
