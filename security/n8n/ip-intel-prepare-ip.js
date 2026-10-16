const raw = $input.first().json;

// n8n v2 webhook aninha o body em .body, v1 coloca direto
const ip = (raw.body && raw.body.ip) ? raw.body.ip : raw.ip;

if (!ip || typeof ip !== 'string') {
  throw new Error('IP address is required'); // não ecoa o request: ele traz headers (A3, 14/10/2026)
}

const ipTrim = ip.trim();
const m = ipTrim.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
if (!m || m.slice(1).some(o => Number(o) > 255 || (o.length > 1 && o[0] === '0'))) {
  throw new Error('Invalid IP address format: ' + ipTrim.slice(0, 64));
}

// Só IP público: privado, loopback, CGNAT, link-local, multicast/reservado e redes de documentação não são consultados
const [a, b, c] = m.slice(1, 4).map(Number);
const blocked = a === 0 || a === 10 || a === 127 || a >= 224 ||
  (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
  (a === 192 && b === 168) || (a === 192 && b === 0 && (c === 0 || c === 2)) || (a === 198 && (b === 18 || b === 19)) ||
  (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113);
if (blocked) {
  throw new Error('IP não público, não consultado: ' + ipTrim);
}

const reversed = ipTrim.split('.').reverse().join('.');
return [{ json: { ip: ipTrim, reversed_ip: reversed + '.in-addr.arpa' } }];
