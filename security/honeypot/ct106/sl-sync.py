#!/opt/oci-sl-sync/venv/bin/python
"""sl-sync (D6): mantém a regra TCP 22022 da Security List do honeypot (VPS2) apontando para o IP atual de casa.
HOMELAB §7 / §15.7.

Roda no CT 106 como root (timer de 5 min). Credencial: usuário IAM dedicado "homelab-sl-sync", cuja política só deixa
LER security lists e ATUALIZAR (SECURITY_LIST_UPDATE) as que estão no compartimento "honeypot". Se a chave vazar,
o máximo que alguém faz é mexer no firewall da VPS2, que não tem nada de valor.

O IP de casa vem do relay da VPS1 (o "client" que a VPS1 enxerga no SSH do n8n), um caminho já autenticado.
Só mexe nas regras de entrada TCP com destino 22022; as outras e as de saída ficam intactas.
Avisa no Discord (#seguranca) a cada troca ou erro. Máximo de 6 trocas por dia (proteção contra loop).

Uso: sl-sync.py [--dry-run]
"""
import datetime as dt, ipaddress, json, os, subprocess, sys, urllib.request

import oci

CONF = "/etc/oci-sl-sync/sl-sync.json"  # {"security_list_id": "...", "channel_id": "...", "port": 22022}
STATE = "/var/lib/oci-sl-sync/state.json"
RELAY = ["ssh", "-n", "-i", "/root/.secrets/crowdsec-relay", "-o", "UserKnownHostsFile=/root/.secrets/known_hosts_vps1",
         "-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
         "crowdsec-relay@203.0.113.10", "ping"]
BOT_ENV = "/root/discord-bot/.env"
MAX_CHANGES_PER_DAY = 6
# R4 (15/10): antes de MUDAR a regra, o IP que a VPS1 informa precisa ser confirmado por uma fonte externa
# independente. Uma VPS1 comprometida sozinha não consegue apontar a 22022 para outro IP.
ECHO_URLS = ["https://api.ipify.org", "https://icanhazip.com", "https://ifconfig.me/ip"]


def external_ips():
    seen = set()
    for url in ECHO_URLS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
            seen.add(urllib.request.urlopen(req, timeout=10).read().decode().strip())
        except Exception:
            pass
    return seen


def home_ip():
    out = subprocess.run(RELAY, capture_output=True, text=True, timeout=60).stdout
    ip = json.loads(out)["client"]
    a = ipaddress.ip_address(ip)
    if a.version != 4 or not a.is_global:
        raise ValueError(f"IP de casa inválido: {ip}")
    return ip


def notify(cfg, title, desc, color):
    key = next((l.split("=", 1)[1].strip().strip("'\"") for l in open(BOT_ENV) if l.startswith("NOTIFY_KEY=")), "")
    # Mesma marcação de origem dos alertas do n8n: o aviso é sobre o firewall da VPS2 (honeypot).
    body = {"channelId": cfg["channel_id"], "embeds": [{"title": f"🍯 VPS2 · {title}"[:256], "description": desc, "color": color,
            "author": {"name": "VPS2 · honeypot (isca isolada, sem dados reais)"},
            "footer": {"text": "CT 106 · sl-sync (D6)"}, "timestamp": dt.datetime.now(dt.timezone.utc).isoformat()}]}
    req = urllib.request.Request("http://127.0.0.1:3001/notify", data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "X-Notify-Key": key})
    urllib.request.urlopen(req, timeout=15).read()


def load_state():
    try:
        with open(STATE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"changes": []}


def main():
    dry = "--dry-run" in sys.argv
    cfg = json.load(open(CONF))
    port = int(cfg.get("port", 22022))
    vn = oci.core.VirtualNetworkClient(oci.config.from_file())
    ip = home_ip()
    sl = vn.get_security_list(cfg["security_list_id"]).data
    rules = sl.ingress_security_rules
    target = [r for r in rules if r.protocol == "6" and r.tcp_options and r.tcp_options.destination_port_range
              and r.tcp_options.destination_port_range.min == port and r.tcp_options.destination_port_range.max == port]
    want = f"{ip}/32"
    print(f"IP de casa: {ip} · regras da {port}: {[r.source for r in target]}")
    if not target:
        raise SystemExit(f"nenhuma regra TCP {port} na Security List: não crio regra nova por conta própria")
    if all(r.source == want for r in target):
        print("regra já está certa")
        return
    st = load_state()
    ext = external_ips()
    if ip not in ext:
        hour = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H")
        if st.get("mismatch_alert") != hour:  # no máximo um aviso por hora
            st["mismatch_alert"] = hour
            os.makedirs(os.path.dirname(STATE), exist_ok=True)
            with open(STATE, "w") as f:
                json.dump(st, f)
            notify(cfg, "🟠 sl-sync: IP de casa não confirmado",
                   f"A VPS1 diz `{ip}`, as fontes externas dizem {', '.join(f'`{x}`' for x in sorted(ext)) or 'nada (sem resposta)'}. "
                   "A regra da 22022 **não** foi alterada. Se a VPS1 estiver mentindo, ela pode estar comprometida.", 0xe67e22)
        raise SystemExit(f"IP {ip} não confirmado por fonte externa ({sorted(ext)}): nada alterado")
    today = dt.date.today().isoformat()
    st["changes"] = [c for c in st.get("changes", []) if c["at"][:10] == today]
    if len(st["changes"]) >= MAX_CHANGES_PER_DAY:
        notify(cfg, "🔴 sl-sync parado (muitas trocas hoje)", f"Já foram {len(st['changes'])} trocas da regra {port} hoje. Conferir na mão.", 0xe74c3c)
        raise SystemExit("limite diário de trocas atingido")
    old = sorted({r.source for r in target})
    print(f"trocar {old} → {want}{' [dry-run]' if dry else ''}")
    if dry:
        return
    for r in target:
        r.source = want
    vn.update_security_list(cfg["security_list_id"], oci.core.models.UpdateSecurityListDetails(ingress_security_rules=rules))
    st["changes"].append({"at": dt.datetime.now(dt.timezone.utc).isoformat(), "old": old, "new": want})
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    with open(STATE, "w") as f:
        json.dump(st, f)
    notify(cfg, "🏠 Regra do SSH real atualizada", f"Security List do honeypot: SSH real (TCP {port}) agora aceita `{want}` (era {', '.join(f'`{o}`' for o in old)}).", 0x3498db)
    print("atualizado")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:  # erro inesperado: avisa (uma vez por execução) e falha
        try:
            notify(json.load(open(CONF)), "🔴 sl-sync falhou", f"`{type(e).__name__}: {str(e)[:300]}`", 0xe74c3c)
        except Exception:
            pass
        raise
