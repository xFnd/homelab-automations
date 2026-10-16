// 🛡️ Saúde da VPS1 (stats.json, a cada 15 min): serviços, certificados e IP de casa × allowlist "casa".
// Falha de SSH é ignorada aqui: o poll de 1 min já avisa quando a VPS1 não responde.
const CHANNEL_ID = '__CHANNEL_ID__';
const CERT_WARN_DAYS = 21;
const CERT_IGNORE = ['site.example.org']; // domínio apagado em 12/10: o certificado vai vencer de propósito
const S = $getWorkflowStaticData('global');
const out = [];
const RED = 0xe74c3c, GREEN = 0x2ecc71, ORANGE = 0xe67e22;
const clean = (s, max = 80) => String(s ?? '')
  .replace(/[\u0000-\u001f\u007f​-‏‪-‮⁦-⁩]/g, ' ').replace(/`/g, "'").trim().slice(0, max);
const code = (s, max) => '`' + (clean(s, max) || '—') + '`';
// Origem no título e no topo do embed: dá para saber na hora se é o servidor real ou a isca.
const ORIGEM = { tag: '🛡️ VPS1', autor: 'VPS1 · gateway real (exposto na internet)' };
const rotular = (e) => ({ ...e, author: { name: ORIGEM.autor }, title: `${ORIGEM.tag} · ${e.title || ''}`.slice(0, 256) });
const payload = (embeds) => { embeds = embeds.map(rotular); return (CHANNEL_ID && !CHANNEL_ID.startsWith('__')) ? { channelId: CHANNEL_ID, embeds } : { channel: 'alert', embeds }; };
const notify = (title, description, color) => out.push({ json: { route: 'notify', payload: payload([{
  title, description, color, footer: { text: 'VPS1 · relay crowdsec' }, timestamp: new Date().toISOString() }]) } });
const edge = (key, bad, title, msgBad, msgOk) => {
  S.state = S.state || {};
  if (bad && !S.state[key]) notify('🔴 ' + title, msgBad, RED);
  if (!bad && S.state[key]) notify('🟢 ' + title + ' · normalizado', msgOk, GREEN);
  S.state[key] = bad;
};

let env = null;
try { env = JSON.parse($input.first().json.stdout || ''); } catch (e) { /* sem resposta: o poll de 1 min cuida */ }
if (!env || !env.data) return [];
const d = env.data;

for (const [unit, st] of Object.entries((d.system && d.system.units) || {})) {
  edge('unit:' + unit, st !== 'active', `Serviço ${clean(unit, 40)} parado`,
    `${code(unit, 40)} está ${code(st, 20)}. Ver \`systemctl status ${clean(unit, 40)}\` na VPS1.`, `${code(unit, 40)} ativo de novo.`);
}

const today = new Date().toISOString().slice(0, 10);
S.certWarn = S.certWarn || {};
for (const c of d.certs || []) {
  if (CERT_IGNORE.includes(c.name) || c.days_left === null || c.days_left >= CERT_WARN_DAYS) continue;
  if (S.certWarn[c.name] === today) continue;
  S.certWarn[c.name] = today;
  notify('🟠 Certificado perto de vencer', `${code(c.name, 80)} vence em **${c.days_left} dias**. O Caddy renova sozinho a partir de ~30 dias; se chegou aqui, a renovação está falhando (ver \`journalctl -u caddy\`).`, ORANGE);
}

const allow = d.allowlist_casa;
// A5: a VPS1 atualiza a allowlist sozinha (casa-sync, 5 min) quando túnel e relay concordam; aqui só avisamos a troca
if (Array.isArray(allow)) {
  const now = allow.slice().sort().join(', ');
  if (S.allowPrev !== undefined && S.allowPrev !== now && allow.includes(env.client)) {
    notify('🏠 IP de casa mudou', `A allowlist \`casa\` da VPS1 foi atualizada automaticamente: ${code(S.allowPrev || 'vazia', 60)} → ${code(now, 60)}.\n` +
      'A regra da porta 22022 da VPS2 também é ajustada sozinha (D6). Nada a fazer, a não ser que chegue alerta de erro.', 0x3498db);
  }
  S.allowPrev = now;
}
if (Array.isArray(allow) && env.client) {
  edge('homeip', !allow.includes(env.client), 'IP de casa fora da allowlist',
    `O relay chegou de ${code(env.client, 45)}, mas a allowlist \`casa\` tem ${allow.map(x => code(x, 45)).join(', ') || 'nada'}.\n` +
    'O IP residencial mudou e a atualização automática (casa-sync) ainda não confirmou o IP novo.\n' +
    'Ela espera o túnel e o relay concordarem; se o aviso persistir por mais de 15 min, ver `journalctl -t casa-sync` na VPS1.\n' +
    'Na mão: `cscli allowlists add casa <novo>` e `cscli allowlists remove casa <antigo>`.',
    `IP de casa ${code(env.client, 45)} está na allowlist.`);
}
return out;
