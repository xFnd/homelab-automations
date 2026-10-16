// 🛡️ Resumo diário (08:00) da VPS1, a partir do stats.json (janela de 24h, atualizado a cada 15 min).
const CHANNEL_ID = '__CHANNEL_ID__';
const CERT_IGNORE = ['site.example.org'];
const S = $getWorkflowStaticData('global');
const clean = (s, max = 80) => String(s ?? '')
  .replace(/[\u0000-\u001f\u007f​-‏‪-‮⁦-⁩]/g, ' ').replace(/`/g, "'").trim().slice(0, max);
const code = (s, max) => '`' + (clean(s, max) || '—') + '`';
// Origem no título e no topo do embed: dá para saber na hora se é o servidor real ou a isca.
const ORIGEM = { tag: '🛡️ VPS1', autor: 'VPS1 · gateway real (exposto na internet)' };
const rotular = (e) => ({ ...e, author: { name: ORIGEM.autor }, title: `${ORIGEM.tag} · ${e.title || ''}`.slice(0, 256) });
const payload = (embeds) => { embeds = embeds.map(rotular); return (CHANNEL_ID && !CHANNEL_ID.startsWith('__')) ? { channelId: CHANNEL_ID, embeds } : { channel: 'alert', embeds }; };
const flag = cc => /^[A-Z]{2}$/.test(cc || '') ? String.fromCodePoint(...[...cc].map(c => 127397 + c.charCodeAt(0))) : '🏳️';
const fmtN = x => Number(x || 0).toLocaleString('pt-BR');
const short = s => String(s || '').replace(/^crowdsecurity\//, '');
const lines = (arr, max = 1000) => {
  let s = '';
  for (const l of arr) { if ((s + l + '\n').length > max) { s += '…'; break; } s += l + '\n'; }
  return s.trim() || '—';
};

let env = null;
try { env = JSON.parse($input.first().json.stdout || ''); } catch (e) { /* tratado abaixo */ }
if (!env || !env.data) {
  return [{ json: { route: 'notify', payload: payload([{ title: '🟠 Resumo de segurança indisponível',
    description: 'O relay da VPS1 não respondeu às 08:00. O poll de 1 min avisa se a VPS1 estiver fora.', color: 0xe67e22,
    timestamp: new Date().toISOString() }]) } }];
}
const d = env.data, A = d.alerts || {}, prev = S.digestPrev || {};
const fields = [];
fields.push({ name: '🎯 Por cenário', value: lines(Object.entries(A.by_scenario || {}).slice(0, 10).map(([k, v]) => `${code(short(k), 45)} ${v}`)) });
fields.push({ name: '🌍 Top IPs', value: lines((A.top_ips || []).slice(0, 8).map(e =>
  `${flag(e.cn)} ${code(e.ip, 40)} ${e.alerts}× · ${clean(e.as_name || '?', 28)}${e.bans ? ` · 🚫${e.bans}` : ''}`)) });
const pers = A.persistent || [];
fields.push({ name: '🔁 Insistentes sem ban (≥20 alertas)', value: pers.length ? lines(pers.map(e =>
  `${flag(e.cn)} ${code(e.ip, 40)} ${e.alerts}× · ${clean(Object.keys(e.scenarios || {}).map(short).join(', '), 60)}`)) : 'nenhum ✅' });
const ssh = d.ssh || {};
fields.push({ name: '🔑 SSH', value: [
  `falhas: ${fmtN(ssh.failure_lines)} de ${fmtN(ssh.failure_ips)} IPs`,
  `mais tentados: ${(A.target_users || []).slice(0, 6).map(([u, k]) => `${code(u, 20)}×${k}`).join(' ') || '—'}`,
  `logins aceitos: ${(ssh.accepted || []).map(x => `${code(x.user, 20)}@${code(x.ip, 40)}×${x.count}`).join(', ') || 'nenhum'} · relay: ${fmtN(ssh.relay_logins)}`,
].join('\n') });
const rh = d.rathole || {};
fields.push({ name: '🚪 Porta 2333 (rathole)', value: `${fmtN(rh.probes)} conexões de scanner` +
  (rh.noise_rejected ? ` · ${fmtN(rh.noise_rejected)} recusadas no handshake Noise (sem IP no log)` : '') +
  (rh.distinct_ips ? ` · ${fmtN(rh.distinct_ips)} IPs identificados` : ''), inline: true });
// S51 (16/10): o coletor lê os números do nftables e já entrega a janela de 24h (dropped_packets_24h)
const b = d.bouncer || {}, ba = b.active || {}, d24 = b.dropped_packets_24h || {};
const bOk = b.ok !== false && b.source === 'nft'; // revisão de 16/10: sem dados, mostrar "indisponível", nunca 0
const jan = (b.window_h === null || b.window_h === undefined) ? 'desde o reinício do bouncer' : `${b.window_h}h`;
fields.push({ name: '🧱 Bloqueio (nftables)', value: bOk
  ? `comunidade (CAPI): ${fmtN(ba.CAPI)} IPs · bans locais ativos: ${fmtN(ba.crowdsec)}\n` +
    `pacotes barrados (${jan}): CAPI ${fmtN(d24.CAPI)} · locais ${fmtN(d24.crowdsec)} · isca ${fmtN(d24['cscli-import'])}`
  : `indisponível (o coletor não leu o nftables: ${code(b.error || 'sem dados', 40)}; ver \`journalctl -u crowdsec-relay-collector\`)` });
const pv = d.preventive;
if (pv) fields.push({ name: '🍯→🧱 Bloqueio preventivo (isca)', inline: true, value: pv.ok === false
  ? `indisponível (${code(pv.error || 'erro', 40)})`
  : `${pv.active === null || pv.active === undefined ? '?' : fmtN(pv.active)} IPs bloqueados por 48h · ${fmtN(pv.imported_24h)} novos em 24h` +
    (pv.disabled ? ' · ⏸️ desligado' : '') + (pv.last_run && pv.last_run.ok === false ? ' · ⚠️ última execução falhou' : '') });
const sim = A.simulated_list || [];
fields.push({ name: '🧪 Simulação http-dos (não bane)', value: sim.length ? lines(sim.map(x => `${code(short(x.scenario), 40)} ${code(x.ip, 40)} ×${x.count}`)) : 'nada teria sido banido ✅' });
const n = d.net || {};
const gb = x => (x / 1e9).toFixed(2);
const traffic = (prev.net && n.rx_bytes >= prev.net.rx_bytes && n.tx_bytes >= prev.net.tx_bytes)
  ? `⬇️ ${gb(n.rx_bytes - prev.net.rx_bytes)} GB · ⬆️ ${gb(n.tx_bytes - prev.net.tx_bytes)} GB` : 'primeiro resumo (sem base)';
fields.push({ name: '📶 Tráfego desde o último resumo', value: `${traffic}\nconntrack: ${n.conntrack}/${n.conntrack_max}`, inline: true });
const certs = (d.certs || []).filter(c => !CERT_IGNORE.includes(c.name) && c.days_left !== null);
fields.push({ name: '🔐 Certificado mais perto de vencer', value: certs.length ? `${code(certs[0].name, 50)} ${certs[0].days_left} dias` : '—', inline: true });
const sy = d.system || {};
fields.push({ name: '🖥️ Sistema', value: [
  `uptime ${Math.floor((sy.uptime_s || 0) / 86400)} d · load ${sy.load1} · RAM livre ${sy.mem_available_mb} MB · swap ${sy.swap_used_mb} MB · disco ${sy.disk_used_pct}%`,
  sy.reboot_required ? `⚠️ reboot pendente: ${clean((sy.reboot_pkgs || []).join(', '), 200)}` : 'sem reboot pendente',
  `updates: ${sy.updates_available ? `${sy.updates_available.total} (${sy.updates_available.security} de segurança)` : '?'}` +
    ((sy.need_daemon_reload || []).length ? ' · daemon-reload pendente' : ''),
].join('\n') });
const allow = d.allowlist_casa;
fields.push({ name: '🏠 IP de casa', value: Array.isArray(allow)
  ? (allow.includes(env.client) ? `${code(env.client, 45)} na allowlist ✅` : `⚠️ ${code(env.client, 45)} **fora** da allowlist (${allow.map(x => code(x, 45)).join(', ')})`)
  : 'allowlist não lida', inline: true });
if ((S.queue || []).length) fields.push({ name: '📨 Fila do ip-intel', value: `${S.queue.length} bans aguardando enriquecimento`, inline: true });

S.digestPrev = { net: { rx_bytes: n.rx_bytes, tx_bytes: n.tx_bytes }, at: d.generated_at };

const embed = {
  title: 'Resumo de segurança · últimas 24h',
  description: `**${fmtN(A.total)}** alertas de **${fmtN(A.distinct_ips)}** IPs · **${fmtN(A.banned)}** com ban · ${fmtN(A.simulated)} em simulação`,
  color: 0x3498db,
  fields: fields.slice(0, 25),
  footer: { text: 'VPS1 · relay crowdsec · dados de ' + new Date(d.generated_at).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' }) },
  timestamp: new Date().toISOString(),
};
while (JSON.stringify(embed).length > 5800 && embed.fields.length > 3) embed.fields.pop(); // limite de 6000 do Discord
return [{ json: { route: 'notify', payload: payload([embed]) } }];
