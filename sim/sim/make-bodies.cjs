// make-bodies.cjs -- build the controller's request bodies for the current run.
// Usage: node make-bodies.cjs --ip 192.168.137.57 --port 41000 --out <dir> [--pad-register 6156]
'use strict';
const fs = require('fs');
const path = require('path');
const pb = require('./pblite.cjs');

const argv = process.argv.slice(2);
const val = (k, d) => { const i = argv.indexOf('--' + k); return i >= 0 && i + 1 < argv.length ? argv[i + 1] : d; };
const IP = val('ip', '192.168.137.50');
const PORT = parseInt(val('port', '41000'), 10);
const OUT = path.resolve(val('out', path.join(__dirname, '..', 'payload')));
const PAD = parseInt(val('pad-register', '0'), 10);
const CAP = path.resolve(__dirname, '..', '..', '..', 'live-cert-test', 'captures');

function captureHex(name) {
  const f = fs.readdirSync(CAP).find((x) => x.includes(name) && x.endsWith('.hex'));
  if (!f) throw new Error('capture missing for ' + name + ' in ' + CAP);
  return fs.readFileSync(path.join(CAP, f), 'utf8').trim();
}
fs.mkdirSync(OUT, { recursive: true });

const logBatch = Buffer.from(captureHex('log_batch'), 'hex');
const fwcheck = Buffer.from(captureHex('v1_FirmwareVersionCheck'), 'hex');

const reg = pb.registerBody({ ip: IP, port: PORT, padTo: PAD });
const regs = [0, 1, 2].map(() => pb.registerBody({ ip: IP, port: PORT }));

// gmsg poll: first without ack (fetch), second acking id 1 (must NOT redeliver)
const poll0 = pb.gmsgBody(reg.fields.token, undefined);
const pollAck = pb.gmsgBody(reg.fields.token, 1);

const files = {
  'log_batch.bin': logBatch,
  'fwcheck.bin': fwcheck,
  'register.bin': reg.body,
  'register_par0.bin': regs[0].body,
  'register_par1.bin': regs[1].body,
  'register_par2.bin': regs[2].body,
  'gmsg_poll0.bin': poll0,
  'gmsg_poll_ack.bin': pollAck,
};
for (const [n, b] of Object.entries(files)) fs.writeFileSync(path.join(OUT, n), b);

const meta = {
  generatedAt: new Date().toISOString(),
  candidateIp: IP, candidatePort: PORT,
  registerBytes: reg.body.length, registerPadTo: PAD,
  udn: reg.fields.udn, token: reg.fields.token, ufrag: reg.fields.ufrag,
  pwd: reg.fields.pwd, fingerprint: reg.fields.fp,
  parallelUfrags: regs.map((r) => r.fields.ufrag),
  sizes: Object.fromEntries(Object.entries(files).map(([n, b]) => [n, b.length])),
};
fs.writeFileSync(path.join(OUT, 'meta.json'), JSON.stringify(meta, null, 2));
console.log(`bodies -> ${OUT}`);
for (const [n, b] of Object.entries(files)) console.log(`  ${n.padEnd(20)} ${String(b.length).padStart(5)} B`);
console.log(`  candidate ${IP}:${PORT}  ufrag=${meta.ufrag}  pad=${PAD}`);
