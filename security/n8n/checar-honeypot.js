// 🍯 Saúde do honeypot (VPS2), a cada 15 min: VPS2 inacessível, Cowrie parado, coletor parado. HOMELAB §7 (D4).
const CHANNEL_ID = '__CHANNEL_ID__';
const FAIL_AFTER = 2;   // polls de 15 min seguidos sem resposta → alerta (30 min)
const STALE_MIN = 40;   // stats.json mais velho que isso → coletor parado
const S = $getWorkflowStaticData('global');
const out = [];
const RED = 0xe74c3c, GREEN = 0x2ecc71;
const clean = (s, max = 80) => String(s ?? '')
  .replace(/[\u0000-\u001f\u007f​-‏‪-‮⁦-⁩]/g, ' ').replace(/`/g, "'").trim().slice(0, max);
const code = (s, max) => '`' + (clean(s, max) || '—') + '`';
// Origem no título e no topo do embed: dá para saber na hora se é o servidor real ou a isca.
const ORIGEM = { tag: '🍯 VPS2', autor: 'VPS2 · honeypot (isca isolada, sem dados reais)' };
const rotular = (e) => ({ ...e, author: { name: ORIGEM.autor }, title: `${ORIGEM.tag} · ${e.title || ''}`.slice(0, 256) });
const payload = (embeds) => { embeds = embeds.map(rotular); return (CHANNEL_ID && !CHANNEL_ID.startsWith('__')) ? { channelId: CHANNEL_ID, embeds } : { channel: 'alert', embeds }; };
const notify = (title, description, color) => out.push({ json: { route: 'notify', payload: payload([{
  title, description, color, footer: { text: 'VPS2 · honeypot' }, timestamp: new Date().toISOString() }]) } });
const edge = (key, bad, title, msgBad, msgOk) => {
  S.state = S.state || {};
  if (bad && !S.state[key]) notify('🔴 ' + title, msgBad, RED);
  if (!bad && S.state[key]) notify('🟢 ' + title + ' · normalizado', msgOk, GREEN);
  S.state[key] = bad;
};

const r = $input.first().json;
let err = typeof r.error === 'string' ? r.error : (r.error && r.error.message) || '';
let env = null;
try { if (!err && r.stdout) env = JSON.parse(r.stdout); } catch (e) { err = 'resposta do relay não é JSON'; }
if (env && env.error) { err = env.error; env = null; }
if (!env || !env.data) {
  S.fail = (S.fail || 0) + 1;
  if (S.fail === FAIL_AFTER) notify('🔴 sem resposta',
    `O relay da VPS2 não responde há ~${FAIL_AFTER * 15} min (SSH na 22022 a partir de casa).\nErro: ${code(err || r.stderr, 200)}\n` +
    'Se o IP de casa mudou, a regra da 22022 na Security List da VPS2 precisa do IP novo.', RED);
  return out;
}
if ((S.fail || 0) >= FAIL_AFTER) notify('🟢 respondendo de novo', `Voltou depois de ~${S.fail * 15} min.`, GREEN);
S.fail = 0;
const d = env.data;
const ageMin = (Date.now() - Date.parse(d.generated_at)) / 60000;
edge('stale', ageMin > STALE_MIN, 'Coletor do honeypot parado',
  `O stats.json tem ${Math.round(ageMin)} min. Ver \`systemctl status hp-relay-collector\` na VPS2.`, 'O coletor voltou a atualizar.');
const units = (d.system && d.system.units) || {};
edge('cowrie', units.cowrie !== 'active', 'Cowrie parado',
  `O honeypot está ${code(units.cowrie, 20)}. Ver \`systemctl status cowrie\` na VPS2.`, 'O Cowrie voltou.');
return out;
