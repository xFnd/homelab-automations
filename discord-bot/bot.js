require("dotenv").config();
const { Client, GatewayIntentBits } = require("discord.js");
const axios = require("axios");
const http = require("http");
const crypto = require("crypto");
const { MEDIA_COMMANDS, handleMediaCommand } = require("./media");

/* ─── Channel IDs (.env) ────────────────────────────────────────── */
const SCAN_CHANNEL     = process.env.SCAN_CHANNEL;
const IP_CHANNEL       = process.env.IP_CHANNEL;
const PROXMOX_CHANNEL  = process.env.PROXMOX_CHANNEL;
const ALERT_CHANNEL    = process.env.ALERT_CHANNEL || PROXMOX_CHANNEL; // alertas do homelab
const MEDIA_CHANNEL    = process.env.MEDIA_CHANNEL;                     // avisos de mídia (ver media.js)

// Apelidos aceitos no /notify: quem chama não precisa saber IDs de canal do Discord
const NOTIFY_CHANNELS  = new Map([["alert", ALERT_CHANNEL], ["media", MEDIA_CHANNEL]]);

/* ─── Config (.env) ─────────────────────────────────────────────── */
const TOKEN      = process.env.DISCORD_TOKEN;
const NOTIFY_KEY = process.env.NOTIFY_KEY || "";  // chave que o n8n usa pra pedir alertas ao bot
const PREFIX     = "!";
const HTTP_PORT  = Number(process.env.HTTP_PORT) || 3001;

/* ─── n8n webhook URLs ───────────────────────────────────────────── */
const N8N_BASE_URL         = (process.env.N8N_BASE_URL || "http://localhost:5678").replace(/\/+$/, "");
const N8N_SCAN_WEBHOOK     = `${N8N_BASE_URL}/webhook/discord-command`;
const N8N_IPINTEL_WEBHOOK  = `${N8N_BASE_URL}/webhook/ip-intel`;
const N8N_PROXMOX_WEBHOOK  = `${N8N_BASE_URL}/webhook/proxmox-status`;

/* ─── Discord client ─────────────────────────────────────────────── */
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
  ],
});

// Sem isso, um erro inesperado derruba o bot inteiro
client.on("error", (err) => console.error("[discord] Error:", err.message));
process.on("unhandledRejection", (err) => console.error("[unhandledRejection]", err?.message || err));

/* ─── Helpers ────────────────────────────────────────────────────── */
function isValidIP(ip) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) &&
    ip.split(".").every((octet) => parseInt(octet, 10) <= 255);
}

function riskEmoji(level) {
  if (level === "High")   return "🔴";
  if (level === "Medium") return "🟠";
  return "🟢";
}

function sourceStatus(ok) {
  return ok ? "✅" : "❌";
}

/* ═══════════════════════════════════════════════════════════════════
   SERVIDOR HTTP (porta 3001)
     GET  /health  → "OK" (healthcheck)
     POST /notify  → posta uma mensagem no Discord (usado pelo n8n)
                     header X-Notify-Key: <NOTIFY_KEY do .env>
                     body   { "content": "...", "embeds": [...],
                              "channelId": "opcional" | "channel": "alert" | "media",
                              "mentionUsers": ["IDs de usuário que podem ser pingados"] }
   ═══════════════════════════════════════════════════════════════════ */
function sendJson(res, status, obj) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(obj));
}

function keyMatches(given) {
  const a = Buffer.from(String(given || ""));
  const b = Buffer.from(NOTIFY_KEY);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function readBody(req, limit = 256 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(Object.assign(new Error("payload muito grande"), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

async function handleNotify(req, res) {
  if (!NOTIFY_KEY)                         return sendJson(res, 503, { ok: false, error: "NOTIFY_KEY não configurada no .env" });
  if (!keyMatches(req.headers["x-notify-key"])) return sendJson(res, 401, { ok: false, error: "chave inválida" });
  if (!client.isReady())                   return sendJson(res, 503, { ok: false, error: "bot ainda não conectou ao Discord" });

  let body;
  try {
    body = JSON.parse(await readBody(req));
  } catch (err) {
    return sendJson(res, err.status || 400, { ok: false, error: err.status ? err.message : "JSON inválido" });
  }

  const content = typeof body.content === "string" ? body.content.slice(0, 2000) : undefined;
  const embeds  = Array.isArray(body.embeds) ? body.embeds.slice(0, 10) : undefined;
  if (!content && !(embeds && embeds.length)) {
    return sendJson(res, 400, { ok: false, error: "envie content e/ou embeds" });
  }

  try {
    // Só pinga quem vier em mentionUsers (ex.: quem pediu o filme); @everyone e cargos, nunca
    const mentionUsers = Array.isArray(body.mentionUsers)
      ? body.mentionUsers.map(String).filter((id) => /^\d{17,20}$/.test(id)).slice(0, 10)
      : [];
    const channel = await client.channels.fetch(body.channelId || NOTIFY_CHANNELS.get(body.channel) || ALERT_CHANNEL);
    const msg = await channel.send({ content, embeds, allowedMentions: { parse: [], users: mentionUsers } });
    return sendJson(res, 200, { ok: true, id: msg.id });
  } catch (err) {
    console.error("[/notify] Error:", err.message);
    return sendJson(res, 502, { ok: false, error: err.message });
  }
}

http.createServer(async (req, res) => {
  try {
    if (req.url === "/health") {
      res.writeHead(200);
      return res.end("OK");
    }
    if (req.method === "POST" && req.url === "/notify") {
      return await handleNotify(req, res);
    }
    return sendJson(res, 404, { ok: false, error: "rota não encontrada" });
  } catch (err) {
    console.error("[http] Error:", err.message);
    if (!res.headersSent) sendJson(res, 500, { ok: false, error: "erro interno" });
  }
}).listen(HTTP_PORT);

/* ═══════════════════════════════════════════════════════════════════
   MESSAGE HANDLER
   ═══════════════════════════════════════════════════════════════════ */
client.on("messageCreate", async (message) => {
  if (message.author.bot) return;

  if (!message.content.startsWith(PREFIX)) return;

  const args    = message.content.slice(PREFIX.length).trim().split(/ +/);
  const command = args.shift().toLowerCase();

  /* ═══════════════════════════════════════
     !help
  ═══════════════════════════════════════ */
  if (command === "help") {
    const reply = `
🤖 **FND Security Bot**

📋 **Comandos disponíveis**

🔎 **!scan <url>**
Analisa uma URL e verifica se ela pode ser phishing ou maliciosa.
Exemplo: \`!scan https://google.com\`

🌐 **!ip <endereço>**
Investigação completa de IP: geolocalização, reputação, ASN e DNS reverso.
Exemplo: \`!ip 8.8.8.8\`

🎬 **!filme <nome>** / 📺 **!serie <nome>**
Pede um filme ou série pro servidor baixar.
Exemplo: \`!filme duna\`

📥 **!fila**
Mostra o que está sendo baixado agora.

🗑️ **!cancelar**
Cancela um pedido que ainda não terminou.

✅ **!novidades**
Últimos títulos que ficaram disponíveis.

ℹ️ **!help**
Mostra esta lista de comandos.
`.trim();
    return message.reply(reply);
  }

  /* ═══════════════════════════════════════
     !filme <nome> | !serie <nome> | !fila
     Pedidos de mídia via Jellyseerr (ver media.js)
  ═══════════════════════════════════════ */
  if (MEDIA_COMMANDS.includes(command)) {
    return handleMediaCommand(message, command === "série" ? "serie" : command, args);
  }

  /* ═══════════════════════════════════════
     !scan <url>
  ═══════════════════════════════════════ */
  if (command === "scan") {
    if (message.channel.id !== SCAN_CHANNEL) return;

    const url = args[0];
    if (!url) return message.reply("⚠️ Use: `!scan https://site.com`");

    const scanningMsg = await message.reply("🔎 Scanning URL...");

    try {
      const response = await axios.post(N8N_SCAN_WEBHOOK, { url }, { timeout: 60000 });
      const data = response.data;

      const malicious   = data.engines?.virustotal?.malicious   ?? "N/A";
      const suspicious  = data.engines?.virustotal?.suspicious  ?? "N/A";
      const harmless    = data.engines?.virustotal?.harmless    ?? "N/A";
      const usMalicious = data.engines?.urlscan?.malicious ? "⚠️ Yes" : "✅ No";
      const usScore     = data.engines?.urlscan?.score     ?? "N/A";
      const usAvailable = data.engines?.urlscan?.available;
      const emoji       = riskEmoji(data.risk_level);
      const timestamp   = data.timestamp
        ? new Date(data.timestamp).toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" })
        : "N/A";

      const result = `
🔎 **URL Scan Result**

🌐 URL: \`${data.url}\`
🕐 ${timestamp}

${emoji} Verdict: **${data.verdict}**
⚠️ Risk Level: **${data.risk_level}**

🦠 **VirusTotal**
> 🔴 Malicious: **${malicious}** | 🟠 Suspicious: **${suspicious}** | 🟢 Harmless: **${harmless}**

🔍 **URLScan.io**
> 🚨 Malicious: **${usMalicious}**
> 📊 Score: **${usScore}**
> ${usAvailable ? "✅ Scan disponível" : "⚠️ Scan indisponível"}
`.trim();

      await scanningMsg.edit(result);
    } catch (error) {
      console.error("[!scan] Error:", error.message);
      await scanningMsg.edit("❌ Error scanning URL. Try again later.");
    }
  }

  /* ═══════════════════════════════════════
     !ip <address>
  ═══════════════════════════════════════ */
  if (command === "ip") {
    if (message.channel.id !== IP_CHANNEL) return;

    const ipInput = args[0];
    if (!ipInput) return message.reply("⚠️ Use: `!ip <endereço>` — Ex: `!ip 8.8.8.8`");
    if (!isValidIP(ipInput)) return message.reply(`❌ IP inválido: \`${ipInput}\`. Use o formato: \`1.2.3.4\``);

    const loadingMsg = await message.reply(`🔍 Investigando IP \`${ipInput}\`...`);

    try {
      const response = await axios.post(N8N_IPINTEL_WEBHOOK, { ip: ipInput }, { timeout: 30000 });
      const d = response.data;

      const emoji      = riskEmoji(d.risk?.level);
      const riskScore  = d.risk?.score  ?? "N/A";
      const riskLevel  = d.risk?.level  ?? "Unknown";

      const vtMal  = d.reputation?.virustotal?.malicious   ?? "N/A";
      const vtSus  = d.reputation?.virustotal?.suspicious  ?? "N/A";
      const vtHarm = d.reputation?.virustotal?.harmless    ?? "N/A";
      const vtRep  = d.reputation?.virustotal?.reputation != null
        ? `${d.reputation.virustotal.reputation}` : "N/A";
      const vtLast = d.reputation?.virustotal?.last_analysis
        ? new Date(d.reputation.virustotal.last_analysis).toLocaleDateString("pt-BR", { timeZone: "America/Sao_Paulo" })
        : "N/A";

      const abuseScore   = d.reputation?.abuseipdb?.abuseConfidenceScore ?? "N/A";
      const abuseReports = d.reputation?.abuseipdb?.totalReports         ?? "N/A";
      const abuseUsage   = d.reputation?.abuseipdb?.usageType            ?? "N/A";
      const abuseWL      = d.reputation?.abuseipdb?.isWhitelisted ? "Yes" : "No";
      const abuseLast    = d.reputation?.abuseipdb?.lastReportedAt       ?? "N/A";

      const country = d.country              || "Unknown";
      const region  = d.region               || "Unknown";
      const city    = d.city                 || "Unknown";
      const tz      = d.timezone             || "Unknown";
      const asn     = d.asn                  || "Unknown";
      const org     = d.org                  || "Unknown";
      const isp     = d.network?.isp         || "Unknown";
      const domain  = d.network?.domain      || "N/A";
      const revDns  = d.reverse_dns          || "N/A";
      const lat     = d.location?.lat        ?? "?";
      const lon     = d.location?.lon        ?? "?";

      const srcVT    = sourceStatus(d.sources?.virustotal);
      const srcAbuse = sourceStatus(d.sources?.abuseipdb);
      const srcIP    = sourceStatus(d.sources?.ipinfo);
      const srcDNS   = sourceStatus(d.sources?.dns);

      const result = `
${emoji} **IP Intelligence Report** — \`${d.ip}\`

${emoji} **Risk Score: ${riskScore}/100** — ${riskLevel}

📍 **Geolocalização**
> 🌍 País: **${country}** | Região: **${region}** | Cidade: **${city}**
> 🕐 Timezone: \`${tz}\`
> 📌 Coords: \`${lat}, ${lon}\`

🏢 **Rede**
> 🔢 ASN: \`${asn}\`
> 🏭 Org: **${org}**
> 🌐 ISP: ${isp}
> 🔗 Domínio: \`${domain}\`
> 🔄 Reverse DNS: \`${revDns}\`

🦠 **VirusTotal**
> 🔴 Malicious: **${vtMal}** | 🟠 Suspicious: **${vtSus}** | 🟢 Harmless: **${vtHarm}**
> ⭐ Reputation: ${vtRep}
> 📅 Última análise: ${vtLast}

🚨 **AbuseIPDB**
> 📊 Confidence Score: **${abuseScore}%**
> 📋 Total Reports: **${abuseReports}**
> 🏷️ Usage Type: ${abuseUsage}
> ✅ Whitelisted: ${abuseWL}
> 📅 Último Report: ${abuseLast}

📡 **Fontes consultadas**
> VirusTotal ${srcVT} | AbuseIPDB ${srcAbuse} | IPInfo ${srcIP} | DNS ${srcDNS}
`.trim();

      await loadingMsg.edit(result);
    } catch (error) {
      console.error("[!ip] Error:", error.message);
      if (error.response) {
        console.error("[!ip] Response status:", error.response.status);
        console.error("[!ip] Response data:",   error.response.data);
      }
      await loadingMsg.edit(
        `❌ Erro ao investigar o IP \`${ipInput}\`. Verifique se o workflow n8n está ativo e tente novamente.`
      );
    }
  }

  /* ═══════════════════════════════════════
     !proxmox  [comando interno]
     Uso:
       !proxmox             → dashboard geral
       !proxmox start <id>  → inicia VM ou LXC
       !proxmox stop <id>   → para VM ou LXC
       !proxmox restart <id>→ reinicia VM ou LXC
  ═══════════════════════════════════════ */
  if (command === "proxmox") {
    if (message.channel.id !== PROXMOX_CHANNEL) return;

    const subcommand = (args[0] || "").toLowerCase();
    const vmid       = args[1] || null;

    const actionCommands = ["start", "stop", "restart"];

    let payload     = {};
    let loadingText = "";

    if (!subcommand || !actionCommands.includes(subcommand)) {
      payload     = { action: "status" };
      loadingText = "⏳ Consultando Proxmox...";
    } else {
      if (!vmid) {
        return message.reply(`⚠️ Informe o ID. Ex: \`!proxmox ${subcommand} 103\``);
      }
      const actionEmoji = { start: "▶️", stop: "⏹️", restart: "🔄" };
      payload     = { action: subcommand, vmid };
      loadingText = `${actionEmoji[subcommand]} Executando **${subcommand}** no ID \`${vmid}\`...`;
    }

    const loadingMsg = await message.reply(loadingText);

    try {
      const response = await axios.post(N8N_PROXMOX_WEBHOOK, payload, { timeout: 25000 });
      const report   = response.data?.report;

      if (!report) {
        return await loadingMsg.edit("❌ Resposta inválida do workflow. Verifique o n8n.");
      }

      if (report.length <= 2000) {
        await loadingMsg.edit(report);
      } else {
        await loadingMsg.edit(report.slice(0, 1990) + "\n…");
        const rest = report.slice(1990);
        if (rest.trim()) await message.channel.send(rest);
      }
    } catch (error) {
      console.error("[!proxmox] Error:", error.message);
      await loadingMsg.edit("❌ Erro ao consultar o Proxmox. Verifique se o workflow n8n está ativo.");
    }
  }
});

/* ─── Bot ready ──────────────────────────────────────────────────── */
client.once("clientReady", () => {
  console.log(`✅ FND Security Bot online — ${client.user.tag}`);
  console.log(`   Scan webhook      : ${N8N_SCAN_WEBHOOK}`);
  console.log(`   IP Intel webhook  : ${N8N_IPINTEL_WEBHOOK}`);
  console.log(`   Proxmox webhook   : ${N8N_PROXMOX_WEBHOOK}`);
  console.log(`   Alertas (/notify) : porta ${HTTP_PORT} → canal ${ALERT_CHANNEL}${NOTIFY_KEY ? "" : " (DESATIVADO: falta NOTIFY_KEY no .env)"}`);
});

client.login(TOKEN);
