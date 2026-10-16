// 🛡️ Monta o embed do ban: alerta do CrowdSec + resposta do "📍 IP Intelligence Pipeline".
// Usuário SSH, URI e user-agent vêm do atacante → sanitizados e sempre em `código` (sem markdown nem links).
const CHANNEL_ID = '__CHANNEL_ID__';
const clean = (s, max = 80) => String(s ?? '')
  .replace(/[\u0000-\u001f\u007f​-‏‪-‮⁦-⁩]/g, ' ').replace(/`/g, "'").trim().slice(0, max);
const code = (s, max) => '`' + (clean(s, max) || '—') + '`';
// Origem no título e no topo do embed: dá para saber na hora se é o servidor real ou a isca.
const ORIGEM = { tag: '🛡️ VPS1', autor: 'VPS1 · gateway real (exposto na internet)' };
const rotular = (e) => ({ ...e, author: { name: ORIGEM.autor }, title: `${ORIGEM.tag} · ${e.title || ''}`.slice(0, 256) });
const payload = (embeds) => { embeds = embeds.map(rotular); return (CHANNEL_ID && !CHANNEL_ID.startsWith('__')) ? { channelId: CHANNEL_ID, embeds } : { channel: 'alert', embeds }; };
const flag = cc => /^[A-Z]{2}$/.test(cc || '') ? String.fromCodePoint(...[...cc].map(c => 127397 + c.charCodeAt(0))) : '🏳️';
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const COLORS = { High: 0xe74c3c, Medium: 0xe67e22, Low: 0xf1c40f };
const hhmm = s => { const t = new Date(s); return isNaN(t) ? '?' : t.toLocaleTimeString('pt-BR', { timeZone: 'America/Sao_Paulo', hour: '2-digit', minute: '2-digit' }); };
const human = s => {
  const m = /(?:(\d+)h)?(?:(\d+)m)?(?:([\d.]+)s)?/.exec(String(s || ''));
  const t = (+m[1] || 0) * 3600 + (+m[2] || 0) * 60 + (+m[3] || 0);
  return t >= 3000 ? Math.round(t / 3600) + 'h' : t ? Math.round(t / 60) + ' min' : '?';
};
const metaVals = (a, key) => {
  const m = (a.meta || []).find(x => x.key === key);
  if (!m) return [];
  try { const v = JSON.parse(m.value); return Array.isArray(v) ? v : [v]; } catch (e) { return [m.value]; }
};

return $input.all().map(({ json: j }) => {
  const a = j.alert || {};
  const src = a.source || {};
  const ip = String(j.ip || src.value || '');
  const intelOk = !j.error && j.risk && j.reputation;
  const ban = (a.decisions || []).find(x => x.type === 'ban') || {};
  const fields = [
    { name: 'Cenário', value: code(a.scenario, 80), inline: true },
    { name: 'Eventos', value: `${a.events_count ?? '?'} · ${hhmm(a.start_at)}–${hhmm(a.stop_at)}`, inline: true },
    { name: 'Reincidência', value: `${j.bans7d || 1}º ban em 7 dias`, inline: true },
  ];
  const users = metaVals(a, 'target_user').slice(0, 4).map(u => code(u, 32)).join(' ');
  const uris = metaVals(a, 'target_uri').slice(0, 3).map(u => code(u, 90)).join('\n');
  const ua = metaVals(a, 'user_agent').slice(0, 1).map(u => code(u, 100)).join('');
  if (users) fields.push({ name: 'Usuários tentados', value: users });
  if (uris) fields.push({ name: 'URIs', value: uris });
  if (ua) fields.push({ name: 'User-agent', value: ua });
  if (intelOk) {
    const vt = j.reputation.virustotal || {}, ab = j.reputation.abuseipdb || {};
    const place = [j.city, j.region].filter(x => x && x !== 'Unknown').join(', ');
    fields.push({ name: `Inteligência · risco ${clean(j.risk.level, 10)} (${Number(j.risk.score) || 0}/100)`, value: [
      `VirusTotal: **${Number(vt.malicious) || 0}** maliciosos · ${Number(vt.suspicious) || 0} suspeitos`,
      `AbuseIPDB: **${Number(ab.abuseConfidenceScore) || 0}%** · ${Number(ab.totalReports) || 0} denúncias${ab.isWhitelisted ? ' · whitelisted' : ''}`,
      `Uso: ${clean(ab.usageType || 'n/d', 60)} · ISP: ${clean((j.network && j.network.isp) || 'n/d', 60)}`,
      `rDNS: ${code(j.reverse_dns || 'N/A', 80)}${place ? ' · ' + clean(place, 60) : ''}`,
    ].join('\n') });
  } else {
    const why = typeof j.error === 'string' ? j.error : (j.error && j.error.message) || 'ip-intel sem resposta';
    fields.push({ name: 'Inteligência', value: `indisponível: ${code(why, 120)}` });
  }
  if (IPV4.test(ip)) fields.push({ name: 'Links', value:
    `[AbuseIPDB](https://www.abuseipdb.com/check/${ip}) · [VirusTotal](https://www.virustotal.com/gui/ip-address/${ip}) · ` +
    `[CrowdSec CTI](https://app.crowdsec.net/cti/${ip}) · [Shodan](https://www.shodan.io/host/${ip})` });
  const asn = src.as_number ? `AS${clean(src.as_number, 10)} ` : '';
  return { json: { route: 'notify', payload: payload([{
    title: `🚫 Ban ${human(ban.duration)} · ${clean(String(a.scenario || '').replace(/^crowdsecurity\//, ''), 70)}`,
    description: `${flag(src.cn)} **${code(ip, 45)}** · ${clean(src.cn || '??', 2)} · ${asn}${clean(src.as_name || '', 50)}`,
    color: intelOk ? (COLORS[j.risk.level] || 0x95a5a6) : 0x95a5a6,
    fields,
    footer: { text: `VPS1 · alerta #${Number(a.id) || '?'} · CrowdSec` },
    timestamp: a.created_at || new Date().toISOString(),
  }]) } };
});
