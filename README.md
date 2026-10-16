# 🏠 Homelab Automations

Um sistema de automação pro meu homelab, controlado pelo Discord. Ele cobre três frentes: **segurança**, **infraestrutura** e **mídia**.

Os temas são só uma forma de organizar. Por baixo é **um sistema só**: um bot de Discord como ponto de entrada, um n8n fazendo o trabalho pesado e um `.env` com a configuração.

| | Tema | O que resolve | Comandos |
|---|---|---|---|
| 🛡️ | [**Segurança**](#️-segurança) | Triagem de URLs e IPs suspeitos direto do chat | `!scan` `!ip` |
| 🖥️ | [**Infraestrutura**](#️-infraestrutura) | Status e controle do servidor Proxmox, alertas do homelab | `!proxmox` · `POST /notify` |
| 🎬 | [**Mídia**](#-mídia) | Pedidos de filmes e séries pro stack *arr + Jellyfin | `!filme` `!serie` `!fila` `!cancelar` `!novidades` |
| 🧱 | [**Defesa do homelab**](#-defesa-do-homelab-out2026) | Borda com CrowdSec, honeypot, bloqueio preventivo, alertas, monitor externo e firewall do Proxmox | [`security/`](security/) |

## Arquitetura

```mermaid
flowchart LR
    U["👤 Discord"] --> B["🤖 discord-bot<br/>(Node.js)"]
    B --> N["⚙️ n8n"]
    N -. "POST /notify (alertas e avisos)" .-> B

    subgraph SEC["🛡️ Segurança"]
        VT["VirusTotal"]
        US["urlscan.io"]
        AB["AbuseIPDB"]
        II["IPInfo"]
        DNS["Google DNS"]
    end

    subgraph INF["🖥️ Infraestrutura"]
        PVE["Proxmox VE"]
    end

    subgraph MED["🎬 Mídia"]
        J["Jellyseerr"]
        AR["Radarr / Sonarr"]
    end

    N -->|"!scan / !ip"| SEC
    N -->|"!proxmox"| INF
    B -->|"!filme / !serie / !fila"| MED
    J -. "webhook: chegou" .-> N
```

O bot não tem lógica de análise: ele valida o comando, chama o serviço certo e formata a resposta. Segurança e infraestrutura passam pelos workflows do n8n. A mídia fala direto com o Jellyseerr e o Radarr/Sonarr, porque depende de menus e botões interativos do Discord. O caminho de volta (o aviso de que o pedido chegou) passa pelo n8n.

---

## 🛡️ Segurança

Triagem de indicadores (URLs e IPs) sem sair do chat: você cola o suspeito e recebe um veredito, com o que cada fonte disse.

```
!scan https://site-suspeito.com   → SAFE / SUSPICIOUS / PHISHING (VirusTotal + urlscan.io)
!ip 185.220.101.1                 → risk score 0–100, reputação, geolocalização, ASN e DNS reverso
```

| Automação | Destaques | Pasta |
|---|---|---|
| 🔎 **URL Reputation Scanner** | Combina VirusTotal e urlscan.io num veredito único. URLs perigosas voltam *defanged* (`hxxps://site[.]com`) pra ninguém clicar sem querer. Consulta o VirusTotal até 5 vezes se a análise demorar. | [`n8n-workflows/url-reputation-scanner`](n8n-workflows/url-reputation-scanner) |
| 🌐 **IP Intelligence Pipeline** | 4 fontes em paralelo (VirusTotal, AbuseIPDB, IPInfo, DNS reverso). Se uma fonte cai, o relatório sai assim mesmo e mostra qual falhou. | [`n8n-workflows/ip-intelligence`](n8n-workflows/ip-intelligence) |

## 🖥️ Infraestrutura

Visão e controle do servidor pelo Discord, e um canal de alertas que qualquer automação do homelab pode usar.

```
!proxmox                  → CPU, RAM, VMs, containers e storage
!proxmox restart 103      → reinicia uma VM ou container pelo ID
```

| Automação | Destaques | Pasta |
|---|---|---|
| 📊 **Proxmox Dashboard** | Relatório do host e start/stop/restart pelo ID, sem precisar dizer se é VM ou container. O `stop` desliga pelo sistema operacional, e o token de API tem só 4 permissões. | [`n8n-workflows/proxmox-dashboard`](n8n-workflows/proxmox-dashboard) |
| 🚨 **Alertas (`/notify`)** | Endpoint HTTP autenticado no bot. O n8n, ou qualquer script do homelab, posta alertas no Discord sem precisar do token do bot. | [`discord-bot`](discord-bot#endpoint-de-alertas-post-notify) |

## 🎬 Mídia

Pedidos de filmes e séries pro stack de mídia (Jellyseerr, Radarr, Sonarr, qBittorrent e Jellyfin), com menus e botões nativos do Discord.

```
!serie breaking bad   → escolhe o título no menu → escolhe as temporadas → confirma no botão
!fila                 → o que está baixando, com % e tempo restante
!cancelar             → remove o torrent, desmonitora e apaga o pedido
                      → ✅ @você seu pedido chegou! 🍿  (aviso automático quando fica disponível)
```

| Automação | Destaques | Pasta |
|---|---|---|
| 🍿 **Pedidos de mídia** | Fluxo interativo (busca → escolha → temporadas → confirmação) que só quem pediu pode usar. Pede só as temporadas que faltam e cancela de ponta a ponta, pra o Radarr/Sonarr não baixar de novo. | [`discord-bot`](discord-bot#pedidos-de-mídia-mediajs) (`media.js`) |
| 📬 **Aviso de "chegou"** | Quando o título fica disponível, o Jellyseerr avisa o n8n, que posta no Discord com pôster e marca quem pediu. | [`n8n-workflows/media-notifications`](n8n-workflows/media-notifications) |

## 🧱 Defesa do homelab (out/2026)

O que protege o próprio homelab, em produção desde outubro de 2026. Detalhes e desenho em [`security/README.md`](security/README.md).

| Peça | Destaques | Pasta |
|---|---|---|
| 📡 **Alertas sem abrir a casa** | Casa **puxa** os alertas do CrowdSec da VPS por SSH com chave de comando forçado (só leitura). Aviso de ban com IP Intelligence e texto do atacante sanitizado, saúde (VPS, túnel, certificados, IP de casa) e resumo diário no Discord | [`security/vps1-relay`](security/vps1-relay) · [`security/n8n`](security/n8n) |
| 🍯 **Honeypot isolado** | Cowrie numa VPS separada, sem rede de saída e sem túnel para casa; relay só leitura e resumo diário | [`security/honeypot`](security/honeypot) |
| 🚫 **Bloqueio preventivo** | Quem tenta login na isca fica 48h bloqueado no gateway, com allowlist dos próprios hosts, validação e tetos | [`security/preventive-block`](security/preventive-block) |
| 🩺 **Monitor de fora para dentro** | Gatus na borda separa "a casa caiu" de "um serviço caiu" e avisa certificado perto de vencer, direto no Discord | [`security/gatus`](security/gatus) |
| 🧱 **Firewall do Proxmox** | Nenhum container alcança o host; os de mídia não alcançam o host, os serviços administrativos nem o roteador | [`security/proxmox-firewall`](security/proxmox-firewall) |

> O bot de produção migrou para **comandos de barra** em 16/10/2026. A pasta [`discord-bot`](discord-bot) continua com a versão `!` (o código novo inclui a integração com um projeto privado).

---

## Estrutura

```
.
├── discord-bot/                  # 🤖 ponto de entrada único (um processo, um .env)
│   ├── bot.js                    #    🛡️ !scan !ip · 🖥️ !proxmox e /notify
│   ├── media.js                  #    🎬 !filme !serie !fila !cancelar !novidades
│   ├── package.json
│   ├── package-lock.json
│   └── .env.example
├── n8n-workflows/
│   ├── url-reputation-scanner/   # 🛡️
│   ├── ip-intelligence/          # 🛡️
│   ├── proxmox-dashboard/        # 🖥️
│   └── media-notifications/      # 🎬
└── security/                     # 🧱 defesa do homelab (out/2026): relays, honeypot, bloqueio, Gatus, firewall, testes
```

Cada pasta de workflow tem o `workflow.json` pra importar no n8n e um README com o fluxo, o formato da resposta e as credenciais necessárias.

## Rodando

1. **n8n**: importe os `workflow.json` (menu `...` → *Import from File*), crie as credenciais listadas no README de cada workflow e ative.
2. **Bot**: veja [`discord-bot/README.md`](discord-bot/README.md).

Dá pra usar só uma parte: sem as chaves do Jellyseerr, os comandos de mídia só avisam que falta configuração, e um workflow que não foi importado só afeta o comando dele.

## 🔐 Cuidados de segurança do projeto

- **Nenhuma chave neste repositório.** As chaves de API ficam nas *Credentials* do n8n, e os tokens do bot ficam no `.env` (modelo em [`.env.example`](discord-bot/.env.example)).
- O endpoint `/notify` exige o header `X-Notify-Key`, comparado em tempo constante (`crypto.timingSafeEqual`), e envia as mensagens com `allowedMentions: { parse: [] }`, então nunca dispara `@everyone`.
- Cada comando só funciona no canal configurado pra ele, então quem pode usar o quê é controlado pelas permissões de canal do Discord.
- O token do Proxmox usa um papel com só 4 permissões (leitura + liga/desliga). O passo a passo está no [README do workflow](n8n-workflows/proxmox-dashboard).
- Dependências fixadas no `package-lock.json` e verificadas com `npm audit`.

## Stack

| | |
|---|---|
| **Base** | n8n · Node.js · discord.js v14 · axios |
| 🛡️ **Segurança** | VirusTotal v3 · urlscan.io · AbuseIPDB v2 · IPInfo · Google Public DNS |
| 🖥️ **Infraestrutura** | Proxmox VE API |
| 🎬 **Mídia** | Jellyseerr · Radarr v3 · Sonarr v3 |
