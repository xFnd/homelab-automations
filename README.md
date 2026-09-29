# 🤖 Automações — Segurança & Homelab

Automações que rodam no meu homelab. Um **bot de Discord** serve de painel de comando, e os **workflows no n8n** fazem o trabalho pesado: consultam APIs de threat intelligence, controlam o Proxmox e devolvem tudo formatado pra ler no chat.

```
!scan https://site-suspeito.com   → phishing ou não? (VirusTotal + urlscan.io)
!ip 185.220.101.1                 → reputação, geolocalização, ASN e DNS reverso
!proxmox                          → dashboard do servidor (CPU, RAM, VMs, storage)
!proxmox restart 103              → reinicia uma VM ou container
!serie breaking bad               → pedido de mídia com menus e botões
```

## Arquitetura

```mermaid
flowchart LR
    U["👤 Usuário no Discord"] --> B["discord-bot<br/>(Node.js)"]

    B -->|"!scan / !ip / !proxmox"| N["n8n"]
    N -->|"JSON / relatório"| B
    N -->|"POST /notify (alertas)"| B

    N --> VT["VirusTotal"]
    N --> US["urlscan.io"]
    N --> AB["AbuseIPDB"]
    N --> II["IPInfo"]
    N --> DNS["Google DNS"]
    N --> PVE["Proxmox VE API"]

    B -->|"!filme / !serie / !fila"| J["Jellyseerr"]
    B --> AR["Radarr / Sonarr"]
```

O bot não tem lógica de análise: ele valida a entrada, chama o webhook certo do n8n e formata a resposta. Dá pra trocar a interface (Telegram, Slack, CLI) sem mexer nos workflows, e dá pra chamar os workflows direto via HTTP, sem o bot.

## Automações

| Automação | O que faz | Pasta |
|---|---|---|
| 🔎 **URL Reputation Scanner** | Envia a URL pro VirusTotal e pro urlscan.io, espera as análises, combina os resultados e classifica como `SAFE` / `SUSPICIOUS` / `PHISHING`. URLs perigosas voltam *defanged* (`hxxps://site[.]com`). | [`n8n-workflows/url-reputation-scanner`](n8n-workflows/url-reputation-scanner) |
| 🌐 **IP Intelligence Pipeline** | Consulta 4 fontes em paralelo (VirusTotal, AbuseIPDB, IPInfo, DNS reverso) e calcula um risk score de 0 a 100. Se uma fonte cai, o relatório sai assim mesmo e mostra qual fonte falhou. | [`n8n-workflows/ip-intelligence`](n8n-workflows/ip-intelligence) |
| 📊 **Proxmox Dashboard** | Relatório de CPU, RAM, VMs, containers e storage, e start/stop/restart pelo ID, com um token de permissão mínima. | [`n8n-workflows/proxmox-dashboard`](n8n-workflows/proxmox-dashboard) |
| 🎬 **Pedidos de mídia** | Busca e pede filmes/séries no Jellyseerr com menus e botões do Discord. Mostra a fila de download e cancela de ponta a ponta (torrent, monitoramento e pedido). | [`discord-bot`](discord-bot) (`media.js`) |
| 🤖 **Discord Bot** | Interface de comandos + endpoint `/notify` autenticado pro n8n mandar alertas no Discord. | [`discord-bot`](discord-bot) |

## Estrutura

```
.
├── discord-bot/                  # Node.js (discord.js + axios)
│   ├── bot.js                    # comandos + servidor /notify
│   ├── media.js                  # Jellyseerr / Radarr / Sonarr
│   ├── package.json
│   ├── package-lock.json
│   └── .env.example
└── n8n-workflows/
    ├── url-reputation-scanner/   # workflow.json + documentação
    ├── ip-intelligence/
    └── proxmox-dashboard/
```

## Rodando

1. **n8n**: importe os `workflow.json` (menu `...` → *Import from File*), crie as credenciais listadas no README de cada workflow e ative.
2. **Bot**: veja [`discord-bot/README.md`](discord-bot/README.md).

## Segurança

- **Nenhuma chave neste repositório.** As chaves de API ficam nas *Credentials* do n8n, e os tokens do bot ficam no `.env` (modelo em [`.env.example`](discord-bot/.env.example)).
- O endpoint `/notify` exige o header `X-Notify-Key`, comparado em tempo constante (`crypto.timingSafeEqual`), e envia as mensagens com `allowedMentions: { parse: [] }`, então nunca dispara `@everyone`.
- Cada comando só funciona no canal configurado pra ele, e os pedidos de mídia podem ser restritos a usuários específicos.
- O token do Proxmox usa um papel com só 4 permissões (leitura + liga/desliga). O passo a passo está no [README do workflow](n8n-workflows/proxmox-dashboard).
- Dependências fixadas no `package-lock.json` e verificadas com `npm audit`.

## Stack

`n8n` · `Node.js` · `discord.js v14` · `axios` · APIs: VirusTotal v3, urlscan.io, AbuseIPDB v2, IPInfo, Google Public DNS, Proxmox VE, Jellyseerr, Radarr/Sonarr v3
