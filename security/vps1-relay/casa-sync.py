#!/usr/bin/env python3
"""casa-allowlist-sync (A5): mantém a allowlist "casa" do CrowdSec igual ao IP atual de casa. HOMELAB §15.7.

Roda como root por timer (a cada 5 min). Só troca a allowlist quando DUAS provas independentes apontam para o mesmo IP:
  1. o túnel rathole, autenticado por token ("Control channel established" no log), veio desse IP e ele mantém
     pelo menos 3 conexões vivas na porta 2333;
  2. o relay do n8n (outra credencial: chave SSH do usuário crowdsec-relay) logou desse IP nos últimos 15 min.
Quem tiver só uma das duas credenciais não consegue se colocar na allowlist.
Cada troca fica em /var/lib/crowdsec-relay/casa.json e no journal (journalctl -t casa-sync).

Uso: casa-sync.py [--dry-run] [--pretend-allowlist IP]
"""
import collections, datetime as dt, grp, ipaddress, json, os, re, subprocess, sys, tempfile

ALLOWLIST = "casa"
STATE = "/var/lib/crowdsec-relay/casa.json"
GROUP = "crowdsec-relay"
RELAY_USER = "crowdsec-relay"
MIN_TUNNEL_CONNS = 3


def run(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120)


def log(msg):
    print(msg, flush=True)
    run("logger", "-t", "casa-sync", "-p", "auth.notice", msg)


def public_ipv4(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.version == 4 and a.is_global
    except ValueError:
        return False


def rathole_ip():
    out = run("journalctl", "-u", "rathole-server", "--since", "-30d", "--no-pager", "-o", "cat").stdout
    hits = re.findall(r"connection\{addr=([0-9.]+):\d+\}: rathole::server: Control channel established", out)
    return hits[-1] if hits else None


def tunnel_conns():
    peers = collections.Counter()
    for line in run("ss", "-tnH", "state", "established", "( sport = :2333 )").stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            peers[parts[3].rsplit(":", 1)[0]] += 1
    return peers


def relay_ip():
    out = run("journalctl", "-u", "ssh", "--since", "-15min", "--no-pager", "-o", "cat").stdout
    hits = re.findall(rf"Accepted publickey for {RELAY_USER} from ([0-9.]+) ", out)
    return hits[-1] if hits else None


def current_allowlist():
    p = run("cscli", "allowlists", "inspect", ALLOWLIST, "-o", "json")
    if p.returncode != 0:
        raise SystemExit(f"cscli allowlists inspect falhou: {p.stderr.strip()[:200]}")
    return [i["value"] for i in (json.loads(p.stdout).get("items") or [])]


def save_state(entry):
    hist = []
    try:
        with open(STATE) as f:
            hist = json.load(f).get("history", [])
    except (OSError, ValueError):
        pass
    hist = (hist + [entry])[-20:]
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(STATE), prefix=".casa.")
    with os.fdopen(fd, "w") as f:
        json.dump({"last": entry, "history": hist}, f)
    os.chown(tmp, 0, grp.getgrnam(GROUP).gr_gid)
    os.chmod(tmp, 0o640)
    os.replace(tmp, STATE)


def main():
    dry = "--dry-run" in sys.argv
    pretend = sys.argv[sys.argv.index("--pretend-allowlist") + 1] if "--pretend-allowlist" in sys.argv else None
    tun, rel, conns = rathole_ip(), relay_ip(), tunnel_conns()
    allow = [pretend] if pretend else current_allowlist()
    print(f"túnel autenticado: {tun} ({conns.get(tun, 0)} conexões vivas) · relay n8n: {rel} · allowlist '{ALLOWLIST}': {allow}")
    if not (tun and rel and tun == rel and public_ipv4(tun) and conns.get(tun, 0) >= MIN_TUNNEL_CONNS):
        print("sem duas provas concordantes → nada a fazer (se o IP mudou, o n8n avisa 'IP de casa fora da allowlist')")
        return
    if allow == [tun]:
        print("allowlist já está certa")
        return
    log(f"IP de casa mudou: allowlist '{ALLOWLIST}' {allow} → ['{tun}'] (túnel e relay concordam){' [dry-run]' if dry else ''}")
    if dry:
        return
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    p = run("cscli", "allowlists", "add", ALLOWLIST, tun, "-d", f"IP residencial (casa-sync {stamp[:10]})")
    if p.returncode != 0:
        log(f"ERRO ao adicionar {tun}: {p.stderr.strip()[:200]}")
        raise SystemExit(1)
    for old in allow:
        if old != tun:
            run("cscli", "allowlists", "remove", ALLOWLIST, old)
    save_state({"changed_at": stamp, "old": [a for a in allow if a != tun], "new": tun})
    print("allowlist agora:", current_allowlist())


if __name__ == "__main__":
    main()
