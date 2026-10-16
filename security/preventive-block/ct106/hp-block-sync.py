#!/usr/bin/python3
"""hp-block-sync (CT 106, tarefa 2 de 16/10/2026, HOMELAB §15.12.1): IPs que tentaram login na isca → bloqueio
preventivo de 48h no CrowdSec do gateway.

  VPS2 (isca)  ── SSH 22022, usuário hp-relay, verbo "blocklist" (só leitura) ──►  lista de IPs (24h)
  VPS1         ── SSH 22, usuário crowdsec-relay, verbo "ping" (só leitura) ──►  IP de casa visto pela VPS1
  CT 106       ── valida: só IP público, sem o IP de casa e sem as próprias VPS; volume normal (≤ 400)
  VPS1         ◄── SSH 22, usuário crowdsec-block, verbo "import" (comando forçado) ── a VPS1 confere tudo de novo,
                   tira allowlists, dependências críticas e o que já está bloqueado e aplica 48h ("fnd/isca-vps2-login")

A isca é NÃO CONFIÁVEL por definição (é feita para ser atacada): por isso o IP de casa vem da VPS1, e uma lista
anormal (grande demais, ou recusada pelo teto do gateway) não é enviada e gera aviso IMEDIATO no Discord
(revisão independente de 16/10). Falhas comuns avisam depois de 3 seguidas; a volta ao normal também avisa.

Uso: hp-block-sync.py [--dry-run]   (dry-run: lê a isca e mostra o que seria enviado, sem enviar)
"""
import datetime as dt, ipaddress, json, os, subprocess, sys, urllib.request

CONF = "/etc/hp-block-sync.json"  # {"channel_id": "..."}
STATE = "/var/lib/hp-block-sync/state.json"
SSH = ["ssh", "-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15"]
HP = SSH + ["-n", "-i", "/root/.secrets/hp-relay", "-o", "UserKnownHostsFile=/root/.secrets/known_hosts_vps2",
            "-p", "22022", "hp-relay@203.0.113.20", "blocklist"]
RELAY = SSH + ["-n", "-i", "/root/.secrets/crowdsec-relay", "-o", "UserKnownHostsFile=/root/.secrets/known_hosts_vps1",
               "crowdsec-relay@203.0.113.10", "ping"]
CS = SSH + ["-i", "/root/.secrets/crowdsec-block", "-o", "UserKnownHostsFile=/root/.secrets/known_hosts_vps1",
            "crowdsec-block@203.0.113.10", "import"]
BOT_ENV = "/root/discord-bot/.env"
OWN = {"203.0.113.10", "203.0.113.20"}  # VPS1 e VPS2 nunca vão para a lista
MAX_SEND = 400    # igual ao teto do gateway; o normal é ~110–200
MAX_AGE_MIN = 60  # lista mais velha que isso = coletor da isca parado → não envia
FAIL_ALERT_AFTER = 3


class Anomaly(Exception):
    """Volume ou resposta fora do normal: pode ser a isca comprometida. Avisa na hora."""


def _ip(v):
    """IP canônico (IPv4 mapeado vira IPv4) ou None se inválido/com zona."""
    try:
        a = ipaddress.ip_address(str(v))
    except ValueError:
        return None
    if getattr(a, "scope_id", None):
        return None
    return getattr(a, "ipv4_mapped", None) or a


def home_from_ping(out):
    """IP de casa como a VPS1 o vê (resposta do relay autenticado, não da isca)."""
    try:
        a = _ip(json.loads(out).get("client"))
    except (ValueError, AttributeError):
        a = None
    if a is None or not a.is_global:
        raise ValueError("a VPS1 não informou um IP de casa válido")
    return a.compressed


def select_ips(env, now, home, max_age_min=MAX_AGE_MIN):
    """Valida a resposta do hp-relay e devolve os IPs a enviar. Erro de formato ou lista velha → ValueError."""
    if not home:
        raise ValueError("sem IP de casa confirmado pela VPS1: não envio nada")
    if not isinstance(env, dict) or "data" not in env or "client" not in env:
        raise ValueError(f"resposta inesperada da isca: {str(env)[:120]}")
    data = env["data"]
    if not isinstance(data, dict) or not isinstance(data.get("ips"), list):
        raise ValueError("lista de IPs ausente")
    gen = dt.datetime.fromisoformat(str(data.get("generated_at", "")).replace("Z", "+00:00"))
    if (now - gen).total_seconds() > max_age_min * 60:
        raise ValueError(f"lista da isca velha demais ({data.get('generated_at')}): coletor da VPS2 parado?")
    bait_client = _ip(env["client"])
    skip = OWN | {home} | ({bait_client.compressed} if bait_client else set())
    out, seen = [], set()
    for v in data["ips"]:
        a = _ip(v)
        if a is None or not a.is_global or a.is_multicast:
            continue
        s = a.compressed
        if s in skip or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def check_volume(ips):
    if len(ips) > MAX_SEND:
        raise Anomaly(f"a isca mandou {len(ips)} IPs (teto {MAX_SEND}, normal ~110–200): nada enviado")


def parse_result(out):
    try:
        r = json.loads(out)
    except ValueError:
        raise RuntimeError(f"resposta do gateway não é JSON: {out[:120]!r}")
    if not isinstance(r, dict) or not r.get("ok"):
        err = (r or {}).get("error") if isinstance(r, dict) else r
        if "teto" in str(err):
            raise Anomaly(f"o gateway recusou: {err}")
        raise RuntimeError(f"gateway recusou: {err}")
    return r


def notify(title, desc, color):
    cfg = json.load(open(CONF))
    key = next((l.split("=", 1)[1].strip().strip("'\"") for l in open(BOT_ENV) if l.startswith("NOTIFY_KEY=")), "")
    body = {"channelId": cfg["channel_id"], "embeds": [{
        "title": f"🛡️ VPS1 · {title}"[:256], "description": desc, "color": color,
        "author": {"name": "VPS1 · gateway real (exposto na internet)"},
        "footer": {"text": "CT 106 · hp-block-sync (isca → bloqueio preventivo)"},
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat()}]}
    req = urllib.request.Request("http://127.0.0.1:3001/notify", data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "X-Notify-Key": key})
    urllib.request.urlopen(req, timeout=15).read()


def load_state():
    try:
        with open(STATE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"fails": 0}


def save_state(st):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    with open(STATE + ".tmp", "w") as f:
        json.dump(st, f)
    os.replace(STATE + ".tmp", STATE)


def run_once(dry):
    home = home_from_ping(subprocess.run(RELAY, capture_output=True, text=True, timeout=60).stdout)
    hp = subprocess.run(HP, capture_output=True, text=True, timeout=90)
    try:
        env = json.loads(hp.stdout)
    except ValueError:
        raise RuntimeError(f"isca não respondeu (rc={hp.returncode}): {hp.stderr.strip()[:160]}")
    ips = select_ips(env, dt.datetime.now(dt.timezone.utc), home)
    print(f"isca: {len(env['data']['ips'])} IPs na lista · {len(ips)} para enviar")
    check_volume(ips)
    if dry:
        return {"dry_run": True, "would_send": len(ips)}
    if not ips:
        return {"sent": 0}
    cs = subprocess.run(CS, input="\n".join(ips) + "\n", capture_output=True, text=True, timeout=300)
    r = parse_result(cs.stdout.strip())
    print("gateway: " + " ".join(f"{k}={r.get(k)}" for k in ("imported", "already_active", "protected", "not_global",
                                                              "over_max_active", "active_after")))
    return {"sent": len(ips), **{k: r.get(k) for k in ("imported", "already_active", "protected", "active_after")}}


def _try_notify(*a):
    try:
        notify(*a)
    except Exception:
        pass


def main():
    dry = "--dry-run" in sys.argv
    st = load_state()
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        res = run_once(dry)
    except Exception as e:
        if dry:
            raise
        st["fails"] = st.get("fails", 0) + 1
        st["last_error"] = f"{type(e).__name__}: {str(e)[:300]}"
        st["last_error_at"] = now
        if isinstance(e, Anomaly) and not st.get("anomaly"):
            st["anomaly"] = True
            _try_notify("🟠 Bloqueio preventivo: lista anormal da isca",
                        f"`{str(e)[:300]}`\nNada foi bloqueado. A isca (VPS2) pode ter sido comprometida ou recebido uma "
                        "onda fora do comum. Ver `journalctl -u hp-block-sync` (CT 106) e o resumo da isca.", 0xe67e22)
        elif st["fails"] == FAIL_ALERT_AFTER:
            _try_notify("🔴 Bloqueio preventivo (isca) parado",
                        f"{FAIL_ALERT_AFTER} execuções seguidas falharam. Último erro: `{st['last_error'][:250]}`.\n"
                        "Os bloqueios já aplicados continuam valendo até expirar (48h). Ver `journalctl -u hp-block-sync` no CT 106.",
                        0xe74c3c)
        save_state(st)
        raise
    if dry:
        return
    if st.get("fails", 0) >= FAIL_ALERT_AFTER or st.get("anomaly"):
        _try_notify("🟢 Bloqueio preventivo (isca) normalizado", f"Voltou a funcionar depois de {st.get('fails', 0)} falhas.", 0x2ecc71)
    st.update(fails=0, anomaly=False, last_ok_at=now, last=res)
    save_state(st)


if __name__ == "__main__":
    main()
