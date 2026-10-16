// Roda um Code node do n8n fora do n8n: o código é o corpo de uma função (o n8n permite "return" no topo).
// Simula $input, $('Nome do nó'), $getWorkflowStaticData e o fuso; devolve o que o nó retornaria.
const fs = require('fs');
const path = require('path');

function runCode(file, { input = [], nodes = {}, staticData = {} } = {}) {
  const code = fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
  const $ = (name) => ({ first: () => ({ json: nodes[name] }) });
  const $input = { first: () => ({ json: input[0] }), all: () => input.map((json) => ({ json })) };
  // eslint-disable-next-line no-new-func
  const fn = new Function('$getWorkflowStaticData', '$', '$input', code);
  return fn(() => staticData, $, $input);
}

// stdout do nó SSH (relay): {"client": ..., "data": {...}}
const sshOut = (data, client = '198.51.100.8') => ({ stdout: JSON.stringify({ client, data }) });

module.exports = { runCode, sshOut };
