# 🛡️ Defesa do homelab: borda, isca, alertas e firewall

Subconjunto **de referência** do que roda no meu homelab (atualizado em 16/10/2026). Todos os IPs, nomes e IDs daqui
são **de documentação** (RFC 5737 / RFC 3849 e `example.org`): VPS gateway `203.0.113.10`, VPS isca `203.0.113.20`,
casa `198.51.100.x`, LAN `192.168.50.0/24`. Os comentários "HOMELAB §…" apontam para a minha documentação privada.

## Desenho em uma tela

```text
Internet ─► VPS gateway (Caddy + CrowdSec + nftables) ═══ túnel rathole (Noise, aberto DE CASA) ═══► serviços em casa
         └► VPS isca (Cowrie na porta 22, sem rede de saída, sem túnel, sem segredo)

Casa (n8n) ──SSH, chave de comando forçado──► relays SÓ LEITURA nas duas VPS  (pull: a VPS nunca alcança a casa)
          └─► Discord (#seguranca): bans com IP Intelligence, saúde, resumo diário, card no Homepage
Casa (timer) ── IPs que tentaram login na isca ──► bloqueio preventivo de 48h no CrowdSec do gateway
Gateway (Gatus) ── testa os sites de fora para dentro ──► Discord direto (avisa mesmo com a casa fora)
Proxmox ── firewall: CTs não alcançam o host (exceto Homepage e n8n, só na API); os de mídia também não alcançam os CTs administrativos nem o roteador
```

Princípios: **toda conexão casa ↔ nuvem é iniciada de casa**; cada chave SSH faz uma coisa só (comando forçado,
`restrict`, host key fixada do lado de casa); segredo nunca no código (vem de arquivo `600` ou de *credential*);
serviços com sandbox do systemd; tudo com teste.

## Pastas

| Pasta | O que é |
|---|---|
| [`vps1-relay/`](vps1-relay/) | Coletor (`collect.py`) que exporta alertas e estatísticas do CrowdSec para casa ler (a cada 60 s / 15 min), o comando forçado da chave de leitura e o `casa-sync` (mantém o IP de casa na allowlist do CrowdSec quando duas provas independentes concordam: túnel autenticado + login do relay). Inclui parser e cenário do CrowdSec para varredura na porta do túnel e o profile que passa a banir o `ssh-time-based-bf`. Os números do bloqueio vêm direto do kernel (`nft -j`), porque o `cscli metrics` não funciona dentro do sandbox |
| [`honeypot/`](honeypot/) | Cowrie com sandbox forte, coletor das últimas 24h (com teto de cardinalidade, porque o atacante controla os textos), relay só leitura e o `sl-sync` (atualiza a regra do SSH real da isca na Security List da Oracle quando o IP de casa muda, com um usuário IAM que só pode isso) |
| [`preventive-block/`](preventive-block/) | **Bloqueio preventivo**: quem tentou login na isca ganha 48h de ban no gateway. Chave com comando forçado + `sudo` só para um aplicador que valida tudo (IP público, allowlists, hosts próprios, sem duplicar, tetos, interruptor). Ver o README da pasta |
| [`n8n/`](n8n/) | Code nodes dos workflows (aviso de ban sanitizado, saúde, resumo diário, card do Homepage, honeypot) e o `deploy_n8n.py`, que publica pela API sem reiniciar o n8n (`code` troca só o código de um nó e preserva IP whitelist e estado) |
| [`gatus/`](gatus/) | Monitor de fora para dentro na borda: 2 sentinelas direto no túnel (separam "a casa caiu" de "um serviço caiu"), sites com validade do certificado e DNS. Interface só em `127.0.0.1` |
| [`proxmox-firewall/`](proxmox-firewall/) | Firewall do Proxmox VE: entrada do host em `DROP`, só Homepage/n8n alcançam a API; CTs de mídia com saída recusada para host, CTs administrativos, painel do roteador e portas de movimento lateral dos PCs (IPv4 e IPv6) |
| [`caddy/`](caddy/) | Exemplo de site no Caddy para o Navidrome com o log **sem** as credenciais que a API Subsonic manda na query |
| [`tests/`](tests/) | `python -m unittest discover -s security/tests` e `node --test security/tests/` (os Code nodes do n8n rodam fora do n8n com um harness) |

## Notas

- O túnel usa rathole com `transport.type = "noise"` (chave privada só no servidor; clientes têm só a pública) e um token por serviço. Acrescentar serviço é hot reload; mudar `[server]`/`[client]` reinicia tudo.
- Dados da isca são usados **só** como estatística e bloqueio preventivo no próprio gateway. Nada de "revidar".
- O bot do Discord de produção já migrou para comandos de barra (`/proxmox`, `/scan`, `/ip`, `/filme`…); a pasta [`../discord-bot`](../discord-bot) ainda mostra a versão com `!`, porque o código novo inclui a integração com um projeto privado.
