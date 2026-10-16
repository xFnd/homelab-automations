// 📊 Status de segurança para o card do Homepage (A6). Lê os relays da VPS1 e da VPS2 e devolve só indicadores.
// Endpoint sem autenticação, mas só na LAN: por isso NÃO devolve IP nem nada sensível, só ✅/⚠️ e contagens.
// Cache de 60 s no static data: chamadas repetidas não viram rajada de SSH nas VPS.
const S = $getWorkflowStaticData('global');
const parse = (name) => {
  try {
    const r = $(name).first().json;
    const env = JSON.parse(r.stdout || '');
    return env && env.data ? env : null;
  } catch (e) { return null; }
};
const v1 = parse('SSH: stats VPS1');
const v2 = parse('SSH: stats VPS2');
const fmtAge = iso => { const m = Math.round((Date.now() - Date.parse(iso)) / 60000); return isNaN(m) ? '?' : `${m} min`; };

let casa = '⚠️ VPS1 sem resposta', bans = null, alertas = null, tunel = '⚠️ sem dados', vps1 = '🔴 sem resposta';
if (v1) {
  const d = v1.data, allow = d.allowlist_casa;
  casa = Array.isArray(allow) ? (allow.includes(v1.client) ? '✅ protegido' : '⚠️ fora da allowlist') : '⚠️ allowlist ilegível';
  bans = (d.alerts && d.alerts.banned) || 0;
  alertas = (d.alerts && d.alerts.total) || 0;
  const n = (d.tunnel && d.tunnel.established) || 0;
  tunel = n > 0 ? `✅ ${n} conexões` : '🔴 caído';
  const down = Object.entries((d.system && d.system.units) || {}).filter(([, st]) => st !== 'active').map(([u]) => u);
  vps1 = down.length ? `⚠️ parado: ${down.join(', ')}` : `✅ ok (dados de ${fmtAge(d.generated_at)})`;
}
// Tarefa 3 (16/10): 2ª linha do card com o CrowdSec da VPS1. Só contagens (nenhum IP).
let cs = { cs_alertas_24h: null, cs_bans_ativos: null, cs_isca: null, cs_barrados_24h: null };
if (v1) {
  const d = v1.data, b = d.bouncer || {}, a = b.active || {}, d24 = b.dropped_packets_24h || {}, p = d.preventive || {};
  const bouncerOk = b.ok !== false && b.source === 'nft';
  cs = {
    cs_alertas_24h: (d.alerts && d.alerts.total) || 0,                 // eventos: alertas de detecção em 24h
    cs_bans_ativos: bouncerOk ? (a.crowdsec || 0) + (a.cscli || 0) : null, // IPs banidos agora por detecção/manual
    cs_isca: Number.isInteger(p.active) ? p.active : null,               // bloqueio preventivo (isca → 48h)
    cs_barrados_24h: bouncerOk ? Object.values(d24).reduce((s, x) => s + (x || 0), 0) : null, // pacotes descartados
  };
}
let honeypot = null, vps2 = '⚠️ sem resposta';
if (v2) {
  honeypot = v2.data.sessions || 0;
  const u = (v2.data.system && v2.data.system.units) || {};
  vps2 = u.cowrie === 'active' ? '✅ honeypot ativo' : '⚠️ Cowrie parado';
}
const body = {
  casa, bans_24h: bans, alertas_24h: alertas, honeypot_24h: honeypot, tunel, vps1, vps2, ...cs,
  atualizado: new Date().toLocaleTimeString('pt-BR', { timeZone: 'America/Sao_Paulo', hour: '2-digit', minute: '2-digit' }),
};
S.cache = { at: Date.now(), body };
return [{ json: { body } }];
