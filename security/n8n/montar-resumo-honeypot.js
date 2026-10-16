// 🍯 Resumo diário (08:05) do honeypot Cowrie da VPS2. HOMELAB §7 (D4).
// Usuário, senha, comando e URL são texto do atacante: ficam em `código`, cortados, e URLs/domínios saem
// "desarmados" (hxxp://exemplo[.]com), como em relatório de ameaça — ninguém clica sem querer.
const CHANNEL_ID = '__CHANNEL_ID__';
const S = $getWorkflowStaticData('global');
const clean = (s, max = 80) => String(s ?? '')
  .replace(/[\u0000-\u001f\u007f​-‏‪-‮⁦-⁩]/g, ' ').replace(/`/g, "'").trim().slice(0, max);
const defang = s => String(s ?? '')
  // URLs inteiras: esquema trocado e todos os pontos entre colchetes
  .replace(/\b(?:https?|ftp|tftp):\/\/[^\s'"`<>]+/gi, u => u.replace(/^(t?)ftp/i, '$1fxp').replace(/^http/i, 'hxxp').replace(/\./g, '[.]'))
  // domínios soltos dentro de comandos (wget evil.ru/x)
  .replace(/\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz|cc|tk|me|co|online|site|br|su|pw|in)\b/gi, h => h.replace(/\./g, '[.]'));
const code = (s, max) => '`' + (clean(s, max) || '—') + '`';
const ioc = (s, max) => code(defang(s), max);
// Origem no título e no topo do embed: dá para saber na hora se é o servidor real ou a isca.
const ORIGEM = { tag: '🍯 VPS2', autor: 'VPS2 · honeypot (isca isolada, sem dados reais)' };
const rotular = (e) => ({ ...e, author: { name: ORIGEM.autor }, title: `${ORIGEM.tag} · ${e.title || ''}`.slice(0, 256) });
const payload = (embeds) => { embeds = embeds.map(rotular); return (CHANNEL_ID && !CHANNEL_ID.startsWith('__')) ? { channelId: CHANNEL_ID, embeds } : { channel: 'alert', embeds }; };
const fmtN = x => Number(x || 0).toLocaleString('pt-BR');
const lines = (arr, max = 1000) => {
  let s = '';
  for (const l of arr) { if ((s + l + '\n').length > max) { s += '…'; break; } s += l + '\n'; }
  return s.trim() || '—';
};
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

let env = null;
try { env = JSON.parse($input.first().json.stdout || ''); } catch (e) { /* tratado abaixo */ }
if (!env || !env.data) {
  return [{ json: { route: 'notify', payload: payload([{ title: '🟠 Resumo do honeypot indisponível',
    description: 'O relay da VPS2 não respondeu às 08:05.', color: 0xe67e22, timestamp: new Date().toISOString() }]) } }];
}
const d = env.data, prev = S.digestPrev || {};
const fields = [];
const kv = (arr, max, f = ioc) => lines((arr || []).map(([k, v]) => `${f(k, max)} ×${v}`));
fields.push({ name: '👤 Usuários mais tentados', value: kv(d.top_users, 30, code), inline: true });
fields.push({ name: '🔑 Senhas mais tentadas', value: kv(d.top_passwords, 30, code), inline: true });
fields.push({ name: '🧑‍💻 Comandos mais digitados', value: kv(d.top_commands, 90) });
fields.push({ name: '🌍 IPs mais ativos', value: lines((d.top_ips || []).slice(0, 8).map(x => {
  const ip = String(x.ip || '');
  const link = IPV4.test(ip) ? ` · [AbuseIPDB](https://www.abuseipdb.com/check/${ip})` : '';
  return `${code(ip, 40)} ${x.sessions} sessões · ${x.logins_ok} logins · ${x.commands} comandos${link}`;
})) });
if ((d.downloads || []).length) fields.push({ name: '📥 Downloads tentados (saída bloqueada)', value: kv(d.downloads, 100) });
if ((d.uploads || []).length) fields.push({ name: '📤 Arquivos enviados pelo atacante', value: kv(d.uploads, 100) });
if (d.redir_files) fields.push({ name: '📝 Arquivos criados no shell falso', value: `${fmtN(d.redir_files)} (via \`echo … > arquivo\`, guardados para análise)`, inline: true });
if ((d.direct_tcpip || []).length) fields.push({ name: '🔀 Tentativas de usar como proxy', value: kv(d.direct_tcpip, 60) });
fields.push({ name: '🧰 Clientes SSH', value: kv(d.client_versions, 60, code) });
const drops = (prev.egress !== undefined && d.egress_drops_total >= prev.egress) ? fmtN(d.egress_drops_total - prev.egress) : `${fmtN(d.egress_drops_total)} (acumulado)`;
fields.push({ name: '🚫 Saídas de rede bloqueadas', value: `${drops} pacotes do Cowrie barrados`, inline: true });
const sy = d.system || {};
fields.push({ name: '🖥️ VPS2', value: [
  `uptime ${Math.floor((sy.uptime_s || 0) / 86400)} d · RAM livre ${sy.mem_available_mb} MB · Cowrie ${sy.cowrie_mem_mb ?? '?'} MB · disco ${sy.disk_used_pct}%`,
  `${sy.reboot_required ? '⚠️ reboot pendente' : 'sem reboot pendente'} · updates: ${sy.updates_available ? `${sy.updates_available.total} (${sy.updates_available.security} de segurança)` : '?'}`,
].join('\n'), inline: true });

S.digestPrev = { egress: d.egress_drops_total, at: d.generated_at };

const embed = {
  title: 'Resumo · últimas 24h',
  description: `**${fmtN(d.sessions)}** conexões de **${fmtN(d.distinct_ips)}** IPs · logins: ${fmtN(d.logins_failed)} recusados / **${fmtN(d.logins_success)}** aceitos (shell falso)\n` +
    `**${fmtN(d.interactive_sessions)}** sessões digitaram comandos (${fmtN(d.commands_total)} no total)`,
  color: 0xf39c12,
  fields: fields.slice(0, 25),
  footer: { text: 'VPS2 · Cowrie · dados de ' + new Date(d.generated_at).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' }) },
  timestamp: new Date().toISOString(),
};
while (JSON.stringify(embed).length > 5800 && embed.fields.length > 3) embed.fields.pop();
return [{ json: { route: 'notify', payload: payload([embed]) } }];
