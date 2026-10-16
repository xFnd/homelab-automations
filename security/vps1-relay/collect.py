#!/usr/bin/env python3
"""crowdsec-relay-collector: exporta (só leitura) alertas e estatísticas da VPS1 para o n8n de casa.

Roda como root (crowdsec-relay-collector.service). A cada 60 s grava alerts.json; a cada 15 min, stats.json.
Os arquivos ficam em /var/lib/crowdsec-relay (root:crowdsec-relay, 640). O n8n lê por SSH com a chave de
comando forçado (/usr/local/bin/crowdsec-relay). Desenho: HOMELAB §15.7.

Uso manual (teste): collect.py alerts | collect.py stats   ·   sem argumento = laço do serviço.
"""
import collections, datetime as dt, glob, grp, json, os, re, socket, subprocess, sys, tempfile, time, traceback

OUT = "/var/lib/crowdsec-relay"
GROUP = "crowdsec-relay"
RELAY_USER = "crowdsec-relay"
# Bloqueio preventivo com os IPs da isca (tarefa 2, 16/10, HOMELAB §15.12): decisões de "cscli decisions import"
# não são detecções desta VPS. Ficam fora das estatísticas de ataque e ganham um bloco próprio ("preventive").
BLOCK_USER = "crowdsec-block"
IMPORT_ORIGIN = "cscli-import"
PREVENTIVE_REASON = "fnd/isca-vps2-login"
PREVENTIVE_STATE = "/var/lib/crowdsec-block/last.json"
PREVENTIVE_KILL_SWITCH = "/etc/crowdsec-block/disabled"
IFACE = "ens3"
TUNNEL_PORT = 2333
ALLOWLIST = "casa"
UNITS = ["caddy", "rathole-server", "crowdsec", "crowdsec-firewall-bouncer", "ssh"]
CERTS = "/var/lib/caddy/.local/share/caddy/certificates/*/*/*.crt"
ALERTS_EVERY, STATS_EVERY = 60, 900
PERSISTENT_MIN = 20  # alertas em 24h sem nenhum ban → IP "insistente"
UPDATES_EVERY = 6 * 3600
_UPDATES = {"at": 0.0, "val": None}
RATHOLE_PROBE = re.compile(r"connection\{addr=([0-9a-fA-F.:]+):\d+\}: rathole::server: "
                           r"(Failed to (?:read|deserialize) hello|Protocol version mismatched)")


def now():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run(*cmd, timeout=90):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def cscli(*args):
    """(ok, dados) de um comando cscli com saída JSON; "null" vira lista vazia."""
    p = run("cscli", *args, "-o", "json")
    if p.returncode != 0:
        return False, None
    try:
        return True, json.loads(p.stdout) if p.stdout.strip() else None
    except json.JSONDecodeError:
        return False, None


def write(name, obj):
    gid = grp.getgrnam(GROUP).gr_gid
    fd, tmp = tempfile.mkstemp(dir=OUT, prefix=f".{name}.")
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f, ensure_ascii=False, separators=(",", ":"))
    os.chown(tmp, 0, gid)
    os.chmod(tmp, 0o640)
    os.replace(tmp, os.path.join(OUT, f"{name}.json"))


def is_ban(a):
    return any(d.get("type") == "ban" and not d.get("simulated") for d in (a.get("decisions") or []))


def split_alerts(alerts):
    """(detecções, imports). Import = alerta criado por "cscli decisions import" (origem cscli-import, sem IP de origem)."""
    det, imp = [], []
    for a in alerts or []:
        (imp if any(d.get("origin") == IMPORT_ORIGIN for d in (a.get("decisions") or [])) else det).append(a)
    return det, imp


def preventive_stats(imports, reason=PREVENTIVE_REASON):
    """Quantos IPs o bloqueio preventivo (motivo `reason`) importou na janela e quando foi a última importação."""
    n, runs, last = 0, 0, None
    for a in imports:
        k = sum(1 for d in (a.get("decisions") or []) if d.get("scenario") == reason)
        if k:
            n, runs = n + k, runs + 1
            last = max(last or "", a.get("created_at") or "") or None
    return {"reason": reason, "imported_24h": n, "imports_24h": runs, "last_import_at": last}


def slim(a):
    src = a.get("source") or {}
    return {
        "id": a.get("id"), "created_at": a.get("created_at"), "start_at": a.get("start_at"), "stop_at": a.get("stop_at"),
        "scenario": a.get("scenario"), "simulated": bool(a.get("simulated")), "events_count": a.get("events_count"),
        "source": {k: src.get(k) for k in ("scope", "value", "ip", "range", "cn", "as_name", "as_number")},
        "decisions": [{k: d.get(k) for k in ("type", "duration", "origin", "simulated")} for d in (a.get("decisions") or [])],
        # meta = contexto do alerta (usuário SSH, URI, user-agent…): vem do atacante, o n8n sanitiza
        "meta": [{"key": m.get("key"), "value": str(m.get("value"))[:600]} for m in (a.get("meta") or [])][:10],
    }


def meta_values(a, key):
    for m in a.get("meta") or []:
        if m.get("key") == key:
            try:
                v = json.loads(m.get("value") or "[]")
            except json.JSONDecodeError:
                v = [m.get("value")]
            return v if isinstance(v, list) else [v]
    return []


def read_int(path):
    try:
        with open(path) as f:
            return int(f.read())
    except (OSError, ValueError):
        return None


def net():
    base = f"/sys/class/net/{IFACE}/statistics/"
    return {"ts": round(time.time(), 1), "rx_bytes": read_int(base + "rx_bytes"), "tx_bytes": read_int(base + "tx_bytes"),
            "conntrack": read_int("/proc/sys/net/netfilter/nf_conntrack_count"),
            "conntrack_max": read_int("/proc/sys/net/netfilter/nf_conntrack_max")}


def tunnel():
    peers = collections.Counter()
    for line in run("ss", "-tnH", "state", "established", f"( sport = :{TUNNEL_PORT} )").stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            peers[parts[3].rsplit(":", 1)[0]] += 1
    return {"established": sum(peers.values()), "peers": dict(peers)}


def alerts_job():
    ok, alerts = cscli("alerts", "list", "--since", "2h", "-l", "0")
    detections, _ = split_alerts(alerts)  # imports do bloqueio preventivo não são ataques: não viram aviso de ban
    write("alerts", {"generated_at": now(), "host": socket.gethostname(), "cscli_ok": ok,
                     "net": net(), "tunnel": tunnel(), "alerts": [slim(a) for a in detections]})


def parse_ssh(log):
    fails = re.findall(r"(?:Invalid user \S* from|Connection closed by (?:authenticating|invalid) user \S* |"
                       r"Failed \S+ for (?:invalid user )?\S* from )([0-9a-fA-F.:]+)", log)
    automation = (RELAY_USER, BLOCK_USER)  # chaves de comando forçado do CT 106: não são logins de gente
    accepted = collections.Counter((u, ip) for u, ip in re.findall(r"Accepted publickey for (\S+) from (\S+)", log)
                                   if u not in automation)
    relay = sum(1 for _ in re.finditer(rf"Accepted publickey for {RELAY_USER} from", log))
    block = sum(1 for _ in re.finditer(rf"Accepted publickey for {BLOCK_USER} from", log))
    return {"failure_lines": len(fails), "failure_ips": len(set(fails)),
            "accepted": [{"user": u, "ip": ip, "count": n} for (u, ip), n in accepted.most_common(10)],
            "relay_logins": relay, "block_logins": block}


def ssh_stats():
    return parse_ssh(run("journalctl", "-u", "ssh", "--since", "-24h", "--no-pager", "-o", "cat", timeout=180).stdout)


def preventive_block(imports):
    """Bloco "preventive" do stats.json: importações em 24h + decisões ativas + última execução do crowdsec-block."""
    p = preventive_stats(imports)
    ok, al = cscli("decisions", "list", "--scenario", PREVENTIVE_REASON, "-l", "0")
    p["active"] = len({d.get("value") for a in (al or []) for d in (a.get("decisions") or [])
                       if d.get("scenario") == PREVENTIVE_REASON}) if ok else None
    p["disabled"] = os.path.exists(PREVENTIVE_KILL_SWITCH)
    try:
        with open(PREVENTIVE_STATE) as f:
            last = json.load(f)
        p["last_run"] = {k: last.get(k) for k in ("at", "ok", "received", "imported", "already_active", "protected", "error")}
    except (OSError, ValueError):
        p["last_run"] = None
    return p


def rathole_stats():
    log = run("journalctl", "-u", "rathole-server", "--since", "-24h", "--no-pager", "-o", "cat", timeout=120).stdout
    hits = RATHOLE_PROBE.findall(log)
    ips = collections.Counter(ip for ip, _ in hits)
    # Desde o Noise (15/10), quem não fala o protocolo cai no handshake, e o rathole registra a falha SEM o IP
    noise = log.count("rathole::server: Failed to do transport handshake")
    return {"probes": len(hits) + noise, "distinct_ips": len(ips), "noise_rejected": noise, "top": ips.most_common(5)}


NFT_TABLES = (("ip", "crowdsec"), ("ip6", "crowdsec6"))
SET_PREFIX = re.compile(r"^crowdsec6?-blacklists-(.+)$")  # crowdsec-blacklists-<origem> / crowdsec6-blacklists-<origem>
DROPS_HIST = os.path.join(OUT, "drops-history.json")
DAY_S = 86400


def parse_nft(tables):
    """Por origem (CAPI, crowdsec, cscli, cscli-import…): IPs nos sets e pacotes/bytes descartados (contadores nomeados
    do firewall-bouncer). Junta IPv4 e IPv6. Entrada: as saídas de `nft -j list table …` (None = tabela ausente)."""
    out = {"active": {}, "dropped_packets": {}, "dropped_bytes": {}}
    for t in tables:
        for o in (t or {}).get("nftables") or []:
            if "set" in o:
                m = SET_PREFIX.match(o["set"].get("name", ""))
                if m:
                    out["active"][m.group(1)] = out["active"].get(m.group(1), 0) + len(o["set"].get("elem") or [])
            elif "counter" in o:
                m = SET_PREFIX.match(o["counter"].get("name", ""))
                if m:
                    k = m.group(1)
                    out["dropped_packets"][k] = out["dropped_packets"].get(k, 0) + int(o["counter"].get("packets") or 0)
                    out["dropped_bytes"][k] = out["dropped_bytes"].get(k, 0) + int(o["counter"].get("bytes") or 0)
    return out


def drops_24h(hist, now, current):
    """Pacotes descartados na janela (até 24h) contra a amostra mais antiga ainda dentro dela.
    Contador menor que antes = bouncer reiniciado: a janela recomeça (window_h None = "desde o reinício")."""
    keep = [h for h in hist if now - h["ts"] <= DAY_S]
    if keep and any(v < keep[0]["p"].get(k, 0) for k, v in current.items()):
        return dict(current), None, [{"ts": now, "p": dict(current)}]
    keep.append({"ts": now, "p": dict(current)})
    base = keep[0]
    return ({k: v - base["p"].get(k, 0) for k, v in current.items()}, round((now - base["ts"]) / 3600, 1), keep)


def bouncer_stats():
    # S51 (16/10): o "cscli metrics show bouncers" lê o SQLite e, dentro do sandbox desta unit, devolve null sem erro.
    # O kernel tem os mesmos números (sets e contadores do firewall-bouncer), e o nft funciona no sandbox.
    tables, ok = [], True
    for fam, name in NFT_TABLES:
        p = run("nft", "-j", "list", "table", fam, name, timeout=60)
        try:
            tables.append(json.loads(p.stdout) if p.returncode == 0 else None)
        except json.JSONDecodeError:
            tables.append(None)
        ok = ok and p.returncode == 0
    out = {"ok": ok, "source": "nft", **parse_nft(tables)}
    try:
        with open(DROPS_HIST) as f:
            hist = json.load(f)
    except (OSError, ValueError):
        hist = []
    out["dropped_packets_24h"], out["window_h"], hist = drops_24h(hist, time.time(), out["dropped_packets"])
    try:
        fd, tmp = tempfile.mkstemp(dir=OUT, prefix=".drops.")
        with os.fdopen(fd, "w") as f:
            json.dump(hist[-200:], f)
        os.replace(tmp, DROPS_HIST)
    except OSError:
        pass
    return out


def cert_stats():
    certs = []
    for path in glob.glob(CERTS):
        end = run("openssl", "x509", "-noout", "-enddate", "-in", path).stdout.strip().split("=", 1)[-1]
        try:
            exp = dt.datetime.strptime(end, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
            days = (exp - dt.datetime.now(dt.timezone.utc)).days
        except ValueError:
            days = None
        certs.append({"name": os.path.basename(path)[:-4], "days_left": days})
    return sorted(certs, key=lambda c: (c["days_left"] is None, c["days_left"]))


def system_stats():
    mem = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, v = line.split(":", 1)
            mem[k] = int(v.split()[0]) // 1024
    st = os.statvfs("/")
    pkgs = []
    if os.path.exists("/var/run/reboot-required.pkgs"):
        with open("/var/run/reboot-required.pkgs") as f:
            pkgs = sorted(set(f.read().split()))
    # simulação do apt sem lock e sem gravar cache (o serviço roda com ProtectSystem=strict).
    # Pesa ~100 MB de RAM, então roda no máximo a cada 6h (o resto do tempo usa o último resultado)
    if time.time() - _UPDATES["at"] > UPDATES_EVERY:
        sim = run("apt-get", "-s", "-o", "Debug::NoLocking=1", "-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache=",
                  "upgrade", timeout=120)
        inst = [l for l in sim.stdout.splitlines() if l.startswith("Inst ")]
        _UPDATES.update(at=time.time(), val={"total": len(inst), "security": sum("-security" in l for l in inst)}
                        if sim.returncode == 0 else None)
    upd = _UPDATES["val"]
    units = {u: run("systemctl", "is-active", u).stdout.strip() for u in UNITS}
    reload = [u for u in UNITS if run("systemctl", "show", u, "-p", "NeedDaemonReload", "--value").stdout.strip() == "yes"]
    with open("/proc/uptime") as f:
        uptime = int(float(f.read().split()[0]))
    return {"uptime_s": uptime, "load1": round(os.getloadavg()[0], 2), "mem_available_mb": mem.get("MemAvailable"),
            "swap_used_mb": mem.get("SwapTotal", 0) - mem.get("SwapFree", 0),
            "disk_used_pct": round(100 * (1 - st.f_bavail / st.f_blocks), 1),
            "reboot_required": os.path.exists("/var/run/reboot-required"), "reboot_pkgs": pkgs,
            "updates_available": upd, "units": units, "need_daemon_reload": reload}


def stats_job():
    ok, a24 = cscli("alerts", "list", "--since", "24h", "-l", "0")
    a24, imports = split_alerts(a24)
    ips, users, uris, sim = {}, collections.Counter(), collections.Counter(), collections.Counter()
    for a in a24:
        src = a.get("source") or {}
        ip = src.get("ip") or src.get("value")
        e = ips.setdefault(ip, {"ip": ip, "cn": src.get("cn"), "as_name": src.get("as_name"),
                                "as_number": src.get("as_number"), "alerts": 0, "bans": 0, "scenarios": collections.Counter()})
        e["alerts"] += 1
        e["bans"] += is_ban(a)
        e["scenarios"][a.get("scenario")] += 1
        for u in meta_values(a, "target_user"):
            users[str(u)[:64]] += 1
        for u in meta_values(a, "target_uri"):
            uris[str(u)[:120]] += 1
        if a.get("simulated"):
            sim[(a.get("scenario"), ip)] += 1
    top = sorted(ips.values(), key=lambda e: -e["alerts"])
    for e in top:
        e["scenarios"] = dict(e["scenarios"].most_common(3))
    ok_allow, allow = cscli("allowlists", "inspect", ALLOWLIST)
    write("stats", {
        "generated_at": now(), "host": socket.gethostname(), "window": "24h", "cscli_ok": ok,
        "alerts": {
            "total": len(a24), "banned": sum(is_ban(a) for a in a24), "simulated": sum(bool(a.get("simulated")) for a in a24),
            "distinct_ips": len(ips),
            "by_scenario": dict(collections.Counter(a.get("scenario") for a in a24).most_common()),
            "top_ips": top[:15],
            "persistent": [e for e in top if e["alerts"] >= PERSISTENT_MIN and e["bans"] == 0][:10],
            "target_users": users.most_common(10), "target_uris": uris.most_common(10),
            "simulated_list": [{"scenario": s, "ip": ip, "count": n} for (s, ip), n in sim.most_common(15)],
        },
        "preventive": preventive_block(imports),
        "ssh": ssh_stats(), "rathole": rathole_stats(), "bouncer": bouncer_stats(), "certs": cert_stats(),
        "system": system_stats(), "net": net(), "tunnel": tunnel(),
        "allowlist_casa": [i.get("value") for i in ((allow or {}).get("items") or [])] if ok_allow else None,
    })


def main():
    jobs = {"alerts": alerts_job, "stats": stats_job}
    if len(sys.argv) > 1:
        jobs[sys.argv[1]]()
        return
    last_stats = 0.0
    while True:
        t0 = time.time()
        for name in ("alerts", "stats"):
            if name == "stats" and t0 - last_stats < STATS_EVERY:
                continue
            try:
                jobs[name]()
            except Exception:
                print(f"[{name}] erro:\n{traceback.format_exc()}", file=sys.stderr, flush=True)
            if name == "stats":
                last_stats = t0
        time.sleep(max(5.0, ALERTS_EVERY - (time.time() - t0)))


if __name__ == "__main__":
    main()
