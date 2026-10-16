// 🛡️ Segurança VPS1 — poll de 1 min do relay (alerts.json). Desenho: HOMELAB §15.7.
// Saída: { route: 'notify', payload } (aviso pronto) ou { route: 'enrich', ip, alert, bans7d } (ban → ip-intel).
// ── Config ──────────────────────────────────────────────────────────────────────────
const CHANNEL_ID = '__CHANNEL_ID__';         // ID do #seguranca; vazio = canal "alert" do bot
const DIGEST_ONLY = [/^fnd\/rathole-scan$/]; // cenários que só entram no resumo diário
const MAX_ENRICH_PER_RUN = 3;                // VirusTotal grátis: 4 consultas/min
const MAX_QUEUE = 50;
const FAIL_ALERT_AFTER = 5;                  // polls seguidos sem resposta → alerta
const TUNNEL_DOWN_AFTER = 3;                 // polls seguidos sem conexão no túnel → alerta
const STALE_MIN = 5;                         // alerts.json mais velho que isso → coletor parado
const TRAFFIC_MBPS = 150;                    // média do minuto (link de 480 Mbps), 2 polls seguidos
const CONNTRACK_PCT = 70;
// ───────────────────────────────────────────────────────────────────────────────────
const S = $getWorkflowStaticData('global');
const out = [];
const RED = 0xe74c3c, GREEN = 0x2ecc71;
const clean = (s, max = 80) => String(s ?? '')
  .replace(/[\u0000-\u001f\u007f​-‏‪-‮⁦-⁩]/g, ' ').replace(/`/g, "'").trim().slice(0, max);
const code = (s, max) => '`' + (clean(s, max) || '—') + '`';
// Origem no título e no topo do embed: dá para saber na hora se é o servidor real ou a isca.
const ORIGEM = { tag: '🛡️ VPS1', autor: 'VPS1 · gateway real (exposto na internet)' };
const rotular = (e) => ({ ...e, author: { name: ORIGEM.autor }, title: `${ORIGEM.tag} · ${e.title || ''}`.slice(0, 256) });
const payload = (embeds) => { embeds = embeds.map(rotular); return (CHANNEL_ID && !CHANNEL_ID.startsWith('__')) ? { channelId: CHANNEL_ID, embeds } : { channel: 'alert', embeds }; };
const notify = (title, description, color) => out.push({ json: { route: 'notify', payload: payload([{
  title, description, color, footer: { text: 'VPS1 · relay crowdsec' }, timestamp: new Date().toISOString() }]) } });
// avisa só quando o estado muda (ok → problema e problema → ok)
const edge = (key, bad, title, msgBad, msgOk) => {
  S.state = S.state || {};
  if (bad && !S.state[key]) notify('🔴 ' + title, msgBad, RED);
  if (!bad && S.state[key]) notify('🟢 ' + title + ' · normalizado', msgOk, GREEN);
  S.state[key] = bad;
};

// 1) Resposta do SSH (o nó SSH continua em caso de erro e entrega { error })
const r = $input.first().json;
let err = typeof r.error === 'string' ? r.error : (r.error && r.error.message) || '';
let env = null;
try { if (!err && r.stdout) env = JSON.parse(r.stdout); } catch (e) { err = 'resposta do relay não é JSON'; }
if (env && env.error) { err = env.error; env = null; }
if (!env || !env.data) {
  S.fail = (S.fail || 0) + 1;
  if (S.fail === FAIL_ALERT_AFTER) notify('🔴 sem resposta',
    `O relay não responde há ${FAIL_ALERT_AFTER} min (SSH a partir de casa).\nErro: ${code(err || r.stderr, 200)}\n` +
    'Se foi a internet de casa que caiu, este aviso só chega quando ela voltar.', RED);
  return out;
}
if ((S.fail || 0) >= FAIL_ALERT_AFTER) notify('🟢 respondendo de novo', `Voltou depois de ~${S.fail} min sem resposta.`, GREEN);
S.fail = 0;
const d = env.data;
const nowMs = Date.now();

// 2) Saúde do relay, do CrowdSec e do túnel
const ageMin = (nowMs - Date.parse(d.generated_at)) / 60000;
edge('stale', ageMin > STALE_MIN, 'Coletor do relay parado',
  `O alerts.json tem ${Math.round(ageMin)} min. Ver \`systemctl status crowdsec-relay-collector\` na VPS1.`, 'O coletor voltou a atualizar.');
edge('cscli', d.cscli_ok === false, 'CrowdSec não respondeu ao relay',
  'O `cscli alerts list` falhou: o CrowdSec (LAPI) pode estar parado.', 'O CrowdSec voltou a responder.');
const tun = (d.tunnel && d.tunnel.established) || 0;
S.tunZero = tun === 0 ? (S.tunZero || 0) + 1 : 0;
edge('tunnel', S.tunZero >= TUNNEL_DOWN_AFTER, 'Túnel rathole sem conexões',
  `Nenhuma conexão de casa na porta 2333 há ${S.tunZero} min → **os sites publicados estão fora**.\n` +
  'Ver `rathole-client` (CT 106) e `rathole-brain` (CT 107).', `Túnel de volta (${tun} conexões).`);

// 3) Tráfego e conntrack (flood volumétrico não é bloqueável na VPS; aqui só avisamos)
const n = d.net || {};
if (S.net && n.ts > S.net.ts && n.rx_bytes >= S.net.rx_bytes && n.tx_bytes >= S.net.tx_bytes) {
  const sec = n.ts - S.net.ts;
  const rx = (n.rx_bytes - S.net.rx_bytes) * 8 / sec / 1e6, tx = (n.tx_bytes - S.net.tx_bytes) * 8 / sec / 1e6;
  S.hot = Math.max(rx, tx) > TRAFFIC_MBPS ? (S.hot || 0) + 1 : 0;
  edge('traffic', S.hot >= 2, 'Tráfego alto',
    `Média do último minuto: ⬇️ ${rx.toFixed(0)} Mbps · ⬆️ ${tx.toFixed(0)} Mbps (link de 480 Mbps).\n` +
    'Pode ser flood ou streaming pesado. O CrowdSec só bloqueia abuso por IP (L7).',
    `Tráfego normal: ⬇️ ${rx.toFixed(1)} · ⬆️ ${tx.toFixed(1)} Mbps.`);
}
S.net = { ts: n.ts, rx_bytes: n.rx_bytes, tx_bytes: n.tx_bytes };
if (n.conntrack_max) {
  const pct = 100 * n.conntrack / n.conntrack_max;
  edge('conntrack', pct > CONNTRACK_PCT, 'Tabela de conexões quase cheia',
    `conntrack: ${n.conntrack}/${n.conntrack_max} (${pct.toFixed(0)}%). Sinal de flood/SYN flood; em 100% a VPS descarta conexões novas.`,
    `conntrack: ${n.conntrack}/${n.conntrack_max}.`);
}

// 4) Alertas novos → bans entram na fila do ip-intel (dedupe de 24h por IP)
const alerts = (d.alerts || []).filter(a => Number.isInteger(a.id)).sort((a, b) => a.id - b.id);
const maxId = alerts.length ? alerts[alerts.length - 1].id : 0;
if (S.lastId === undefined) S.lastId = maxId; // 1ª execução: não reenvia o histórico
const fresh = alerts.filter(a => a.id > S.lastId);
S.lastId = Math.max(S.lastId, maxId);

const DAY = 864e5, WEEK = 7 * DAY;
S.seen = S.seen || {}; S.bans = S.bans || {}; S.queue = S.queue || [];
for (const [k, t] of Object.entries(S.seen)) if (nowMs - t > DAY) delete S.seen[k];
for (const k of Object.keys(S.bans)) {
  S.bans[k] = S.bans[k].filter(t => nowMs - t < WEEK);
  if (!S.bans[k].length) delete S.bans[k];
}
for (const a of fresh) {
  const banned = !a.simulated && (a.decisions || []).some(x => x.type === 'ban' && !x.simulated);
  if (!banned) continue; // sem ban → só no resumo diário
  const key = String((a.source && (a.source.value || a.source.ip)) || '');
  if (!key) continue;
  (S.bans[key] = S.bans[key] || []).push(nowMs);
  if (DIGEST_ONLY.some(rx => rx.test(a.scenario || ''))) continue;
  if (S.seen[key]) continue; // já avisado nas últimas 24h
  S.seen[key] = nowMs;
  S.queue.push({ key, alert: a });
}
if (S.queue.length > MAX_QUEUE) S.queue.splice(0, S.queue.length - MAX_QUEUE);
for (const q of S.queue.splice(0, MAX_ENRICH_PER_RUN)) {
  out.push({ json: { route: 'enrich', ip: q.key, alert: q.alert, bans7d: (S.bans[q.key] || []).length } });
}
return out;
