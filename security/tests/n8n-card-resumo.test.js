// Tarefa 3 (16/10): card "Segurança" do Homepage com números do CrowdSec + resumo diário com o bloqueio preventivo.
// Rodar: node --test deploy/tests/
const test = require('node:test');
const assert = require('node:assert');
const { runCode, sshOut } = require('./n8n-harness');

const VPS1 = {
  generated_at: new Date().toISOString(),
  alerts: { total: 21, banned: 21, simulated: 0, distinct_ips: 14, by_scenario: { 'crowdsecurity/ssh-bf': 2 }, top_ips: [] },
  allowlist_casa: ['198.51.100.8'],
  tunnel: { established: 63 },
  system: { units: { caddy: 'active', crowdsec: 'active' } },
  bouncer: {
    ok: true, source: 'nft',
    active: { CAPI: 18343, crowdsec: 2, cscli: 0, 'cscli-import': 76 },
    dropped_packets: { CAPI: 4735, crowdsec: 8781, 'cscli-import': 12 },
    dropped_packets_24h: { CAPI: 400, crowdsec: 300, 'cscli-import': 12 }, window_h: 24,
  },
  preventive: { reason: 'fnd/isca-vps2-login', active: 110, imported_24h: 110, imports_24h: 1, disabled: false,
    last_run: { ok: true, imported: 0 } },
  ssh: {}, rathole: {}, net: {}, certs: [],
};
const VPS2 = { sessions: 4925, system: { units: { cowrie: 'active' } } };

test('card: segunda linha com alertas, bans ativos, isca e pacotes barrados (24h)', () => {
  const [{ json: { body } }] = runCode('n8n/status-homepage.js', {
    nodes: { 'SSH: stats VPS1': sshOut(VPS1), 'SSH: stats VPS2': sshOut(VPS2) } });
  assert.strictEqual(body.cs_alertas_24h, 21);
  assert.strictEqual(body.cs_bans_ativos, 2);
  assert.strictEqual(body.cs_isca, 110);
  assert.strictEqual(body.cs_barrados_24h, 712);
  assert.strictEqual(body.casa, '✅ protegido');
});

test('card: sem resposta da VPS1, os campos do CrowdSec ficam nulos (o Homepage mostra "-")', () => {
  const [{ json: { body } }] = runCode('n8n/status-homepage.js', {
    nodes: { 'SSH: stats VPS1': { stdout: '' }, 'SSH: stats VPS2': sshOut(VPS2) } });
  for (const k of ['cs_alertas_24h', 'cs_bans_ativos', 'cs_isca', 'cs_barrados_24h']) assert.strictEqual(body[k], null, k);
});

test('card: o JSON público (só LAN) continua sem nenhum IP', () => {
  const [{ json: { body } }] = runCode('n8n/status-homepage.js', {
    nodes: { 'SSH: stats VPS1': sshOut(VPS1), 'SSH: stats VPS2': sshOut(VPS2) } });
  assert.doesNotMatch(JSON.stringify(body), /\b\d{1,3}(\.\d{1,3}){3}\b/);
});

test('resumo 08:00: bloco do preventivo e pacotes barrados na janela de 24h', () => {
  const [{ json: { payload } }] = runCode('n8n/montar-resumo.js', { input: [sshOut(VPS1)], staticData: {} });
  const fields = payload.embeds[0].fields;
  const prev = fields.find((f) => f.name.includes('preventivo'));
  assert.ok(prev, 'campo do bloqueio preventivo');
  assert.match(prev.value, /110 IPs/);
  const fw = fields.find((f) => f.name.includes('Bloqueio (nftables)'));
  assert.match(fw.value, /24h/);
  assert.match(fw.value, /isca 12/);
});
