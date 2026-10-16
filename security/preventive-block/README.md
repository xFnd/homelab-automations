# Bloqueio preventivo: isca (VPS2) → CrowdSec do gateway (VPS1)

Tarefa 2 de 16/10/2026 (HOMELAB §15.12.1). IPs que **tentaram login** no honeypot Cowrie viram decisões locais do
CrowdSec da VPS1 por **48h**, com o motivo `fnd/isca-vps2-login`. Só defesa: nada sai da VPS1 em direção ao atacante.

```text
VPS2  hp-relay-collector (15 min) → /var/lib/hp-relay/blocklist.json (IPs com cowrie.login.* em 24h, públicos, ≤ 2000)
CT106 hp-block-sync.timer (15 min) ── SSH 22022, hp-relay, verbo "blocklist" (só leitura) ──► lê a lista
      valida (IP público, sem o IP de casa, sem as VPS, ≤ 1000)
      ── SSH 22, crowdsec-block, verbo "import" (comando forçado) ──► VPS1
VPS1  /usr/local/bin/crowdsec-block → sudo → /usr/local/sbin/crowdsec-block-apply import
      valida de novo · tira allowlists (casa, anthropic-mcp, infra) e as VPS · tira quem já está bloqueado
      → cscli decisions import --format values -d 48h -R fnd/isca-vps2-login   (teto: 5000 ativos)
      → firewall-bouncer → nftables (set crowdsec-blacklists-cscli-import; IP que já está na CAPI fica no set da CAPI)
```

## Arquivos

| Onde | Arquivo | Fonte |
|---|---|---|
| VPS2 | `/usr/local/lib/hp-relay/hp-collect.py` (grava também `blocklist.json`) · `/usr/local/bin/hp-relay` (verbo `blocklist`) | `../honeypot/` |
| VPS1 | `/usr/local/bin/crowdsec-block` (comando forçado) · `/usr/local/sbin/crowdsec-block-apply` (root via sudo) · `/etc/sudoers.d/crowdsec-block` · usuário `crowdsec-block` (home `/var/lib/crowdsec-block-home`, só a chave do CT106) · `/var/lib/crowdsec-block/last.json` · interruptor `/etc/crowdsec-block/disabled` | `vps1/` |
| VPS1 | `collect.py` do relay: alertas de import fora das detecções + bloco `preventive` no `stats.json` | `../vps1-relay/collect.py` |
| CT106 | `/opt/hp-block-sync/hp-block-sync.py` · `hp-block-sync.{service,timer}` · `/etc/hp-block-sync.json` (canal) · `/var/lib/hp-block-sync/state.json` · chave `/root/.secrets/crowdsec-block` | `ct106/` |

## Operação

| Quero… | Comando |
|---|---|
| Ver os bloqueios preventivos | VPS1: `sudo cscli decisions list --scenario fnd/isca-vps2-login` |
| Ver a última execução | CT106: `journalctl -u hp-block-sync -n 20` · VPS1: `sudo journalctl -t crowdsec-block -n 20` |
| Simular (sem enviar) | CT106: `python3 /opt/hp-block-sync/hp-block-sync.py --dry-run` |
| **Pausar** (lado da VPS1) | `sudo touch /etc/crowdsec-block/disabled` (voltar: `sudo rm /etc/crowdsec-block/disabled`) |
| **Pausar** (lado de casa) | CT106: `systemctl disable --now hp-block-sync.timer` |
| **Desbloquear um IP** | VPS1: `sudo cscli decisions delete --ip <IP>` (se ele voltar a atacar a isca, volta na próxima rodada; para nunca bloquear, ponha-o numa allowlist: `sudo cscli allowlists add infra <IP> -d motivo`) |
| **Remover todos os preventivos** | VPS1: `sudo cscli decisions delete --scenario fnd/isca-vps2-login` |
| Remover de vez | CT106: `systemctl disable --now hp-block-sync.timer` + apagar os arquivos acima e a chave · VPS1: `sudo userdel -r crowdsec-block`, `sudo rm /etc/sudoers.d/crowdsec-block /usr/local/bin/crowdsec-block /usr/local/sbin/crowdsec-block-apply` + o `delete --scenario` acima |

## Testes (16/10)

- Unitários: `python -m unittest` em `deploy/tests/` (validação, proteção por allowlist/CIDR e VPS, deduplicação,
  tetos, entrada > 64 KiB recusada inteira, interruptor, resposta inválida do cscli, lista velha da isca).
- Ponta a ponta: entrada só com o que **nunca** pode ser bloqueado (privado, documentação, casa, VPS1, VPS2,
  faixa da Anthropic, lixo) → `imported=0`. Recusados e registrados: `id`, `import; id`, `status --debug`, sem
  comando (shell). Port-forward (`-W`) → `administratively prohibited`. sudo com outro argumento → negado. Primeira carga real: 110 IPs; 2ª execução: 0 novos (110 já ativos).
