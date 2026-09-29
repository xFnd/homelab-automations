# 🤖 FND Security Bot

Bot de Discord em Node.js que serve de interface pros workflows do n8n. Ele valida o comando, chama o webhook certo e formata a resposta.

## Comandos

| Comando | Canal | O que faz | Backend |
|---|---|---|---|
| `!scan <url>` | `SCAN_CHANNEL_ID` | Reputação da URL (phishing/malicioso) | n8n → `/webhook/discord-command` |
| `!ip <ipv4>` | `IP_CHANNEL_ID` | Relatório de inteligência do IP | n8n → `/webhook/ip-intel` |
| `!proxmox [start\|stop\|restart <id>]` | `PROXMOX_CHANNEL_ID` | Dashboard e controle de VMs/LXC | n8n → `/webhook/proxmox-status` |
| `!filme` / `!serie` / `!fila` / `!cancelar` / `!novidades` | qualquer | Pedidos de mídia | Jellyseerr (`media.js`) |
| `!help` | qualquer | Lista os comandos | — |

Os comandos de segurança e de infra só respondem no canal configurado pra eles. Assim dá pra restringir quem usa cada um pelas permissões de canal do Discord.

## Contrato com o n8n

O bot faz `POST` com um JSON simples e espera um JSON de volta:

```jsonc
// !scan  →  POST {N8N_BASE_URL}/webhook/discord-command
{ "url": "https://exemplo.com" }

// !ip    →  POST {N8N_BASE_URL}/webhook/ip-intel
{ "ip": "8.8.8.8" }

// !proxmox → POST {N8N_BASE_URL}/webhook/proxmox-status
{ "action": "status" }                  // ou
{ "action": "restart", "vmid": "103" }  // resposta esperada: { "report": "texto pronto" }
```

O formato de resposta de cada workflow está documentado na pasta dele, em [`../n8n-workflows`](../n8n-workflows).

## Endpoint de alertas (`POST /notify`)

O bot sobe um servidor HTTP interno (porta `HTTP_PORT`, padrão 3001) pra que o n8n, ou qualquer script do homelab, poste mensagens no Discord sem precisar do token do bot:

```bash
curl -X POST http://localhost:3001/notify \
  -H "Content-Type: application/json" \
  -H "X-Notify-Key: $NOTIFY_KEY" \
  -d '{"content": "⚠️ Disco do servidor acima de 90%"}'
```

| Campo | Tipo | |
|---|---|---|
| `content` | string | Texto (cortado em 2000 caracteres) |
| `embeds` | array | Até 10 embeds do Discord |
| `channelId` | string | Opcional. Se não vier, usa `ALERT_CHANNEL_ID` |

Proteções: a chave é comparada com `crypto.timingSafeEqual`, o body tem limite de 256 KB e as menções ficam desativadas (`allowedMentions: { parse: [] }`), então um alerta nunca pinga `@everyone`. Também existe `GET /health`, que responde `OK` pra healthcheck.

## Rodando

Precisa de Node.js 18 ou mais novo.

```bash
cd discord-bot
npm install
cp .env.example .env   # preencha o token, os IDs dos canais e a NOTIFY_KEY
node bot.js
```

No [Discord Developer Portal](https://discord.com/developers/applications), ative o **Message Content Intent** do bot. Sem ele, o bot não consegue ler os comandos com `!`.
