# 🤖 FND Security Bot

Bot de Discord em Node.js que serve de interface pros workflows do n8n e pro stack de mídia do homelab. Ele valida o comando, chama o serviço certo e formata a resposta.

| Arquivo | Responsabilidade |
|---|---|
| `bot.js` | Comandos de segurança/infra (chamam o n8n) e servidor HTTP `/notify` |
| `media.js` | Pedidos de filmes e séries (Jellyseerr, Radarr, Sonarr) com menus e botões do Discord |

## Comandos

| Comando | Canal | O que faz | Backend |
|---|---|---|---|
| `!scan <url>` | `SCAN_CHANNEL` | Reputação da URL (phishing/malicioso) | n8n → `/webhook/discord-command` |
| `!ip <ipv4>` | `IP_CHANNEL` | Relatório de inteligência do IP | n8n → `/webhook/ip-intel` |
| `!proxmox [start\|stop\|restart <id>]` | `PROXMOX_CHANNEL` | Dashboard e controle de VMs/LXC | n8n → `/webhook/proxmox-status` |
| `!filme <nome>` / `!serie <nome>` | `MEDIA_CHANNEL` | Busca, escolha no menu e pedido | Jellyseerr |
| `!fila` | `MEDIA_CHANNEL` | O que está baixando, com % e tempo restante | Radarr + Sonarr |
| `!cancelar` | `MEDIA_CHANNEL` | Cancela downloads em andamento | Radarr + Sonarr + Jellyseerr |
| `!novidades` | `MEDIA_CHANNEL` | Últimos títulos disponíveis | Jellyseerr |
| `!help` | qualquer | Lista os comandos | — |

Os comandos de segurança e de infra só respondem no canal configurado pra eles. Assim dá pra restringir quem usa cada um pelas permissões de canal do Discord. Os de mídia seguem a mesma ideia: quem tem acesso ao `MEDIA_CHANNEL` pode pedir, consultar e cancelar.

## Pedidos de mídia (`media.js`)

O fluxo é todo interativo, com os componentes nativos do Discord:

```
!serie breaking bad
  → menu com até 5 resultados (mostra se já está na biblioteca)
  → menu de temporadas (só as que você ainda não tem nem pediu)
  → embed com pôster, nota e sinopse + botões [✅ Pedir] [❌ Cancelar]
  → pedido criado no Jellyseerr
```

Só quem mandou o comando pode clicar nos menus. Se outra pessoa clicar, recebe um aviso que só ela vê. Cada etapa expira em 2 minutos.

**Série que você já tem em parte** (ex.: saiu a temporada 4 e você tem da 1 à 3): o menu mostra só as temporadas que faltam, com a mesma regra que o Jellyseerr usa pra aceitar o pedido. Se não faltar nenhuma, o bot avisa que a série já está na lista.

> **Quem pode usar:** o controle é feito pelas permissões do canal no Discord. Quem vê o `MEDIA_CHANNEL` pode fazer tudo, inclusive `!cancelar`, que remove torrents e pode tirar títulos do Radarr/Sonarr. Deixe o canal visível só pra quem deve ter esse poder. Sem `MEDIA_CHANNEL` definido, os comandos funcionam em qualquer canal, então defina.

**Com Radarr/Sonarr configurados** (`RADARR_KEY` e `SONARR_KEY`), o bot fala direto com eles:

- `!fila` agrupa os episódios do mesmo torrent numa linha só (`T1 (8 episódios)`) e mostra o progresso real.
- `!cancelar` faz o cancelamento completo: remove da fila e do qBittorrent, desmonitora o filme/temporada (senão o Radarr/Sonarr baixa de novo), apaga o pedido no Jellyseerr e, se você quiser, tira o título do catálogo. Os arquivos já baixados nunca são apagados. Se o pedido da série também cobre outras temporadas, ele é mantido no Jellyseerr pra não afetar o que continua baixando.

Sem essas chaves, `!fila` e `!cancelar` funcionam só pelo Jellyseerr, que não enxerga o progresso nem remove o torrent.

**Aviso de "chegou":** quando o título fica disponível, o Jellyseerr avisa o n8n, que posta no canal de mídia pelo `/notify` e marca quem pediu. A configuração está no workflow [`media-notifications`](../n8n-workflows/media-notifications).

## Contrato com o n8n

O bot faz `POST` com um JSON simples e espera um JSON de volta:

```jsonc
// !scan  →  POST {N8N_BASE_URL}/webhook/discord-command
{ "url": "https://exemplo.com" }

// !ip    →  POST {N8N_BASE_URL}/webhook/ip-intel
{ "ip": "8.8.8.8" }

// !proxmox → POST {N8N_BASE_URL}/webhook/proxmox-status
{ "action": "status" }                  // ou
{ "action": "restart", "vmid": "103" }  // resposta: { "report": "texto pronto" }
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
| `channelId` | string | Opcional. ID do canal de destino |
| `channel` | `"alert"` \| `"media"` | Opcional. Apelido pro `ALERT_CHANNEL` ou `MEDIA_CHANNEL`, pra quem chama não precisar saber IDs. Sem `channelId` nem `channel`, vai pro `ALERT_CHANNEL` |
| `mentionUsers` | array | Opcional. IDs de usuário que podem ser pingados (até 10), ex.: quem pediu o filme |

Proteções: a chave é comparada com `crypto.timingSafeEqual`, o body tem limite de 256 KB e só são pingados os IDs de usuário listados em `mentionUsers` (`allowedMentions: { parse: [], users: [...] }`). Um alerta nunca pinga `@everyone` nem cargos. Também existe `GET /health`, que responde `OK` pra healthcheck.

## Rodando

Precisa de Node.js 18.17 ou mais novo.

```bash
cd discord-bot
npm ci                 # instala as versões exatas do package-lock.json
cp .env.example .env   # preencha o token, os canais e as chaves
npm start
```

No [Discord Developer Portal](https://discord.com/developers/applications), ative o **Message Content Intent** do bot. Sem ele, o bot não consegue ler os comandos com `!`.
