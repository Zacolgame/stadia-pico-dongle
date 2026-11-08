// sim/dtls-probe.cjs -- T2 gate: STUN + DTLS handshake-initiation probes.
//
// Runs the two shell probes (probes/stun-probe.sh, probes/dtls-probe.sh) on the
// phone against the Pico AP and judges their verdict lines. No deps, ASCII only.
//
//   node sim/dtls-probe.cjs --serial <adb-serial> --adb adb --out out [--ip 192.168.137.1]
//
// Exit 0 = all checks pass. Writes out/t2-result.json.
'use strict';
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

function arg(name, def) {
  const i = process.argv.indexOf('--' + name);
  return (i >= 0 && i + 1 < process.argv.length) ? process.argv[i + 1] : def;
}

const SERIAL = arg('serial', '');
const ADB = arg('adb', 'adb');
if (!SERIAL) { console.error('[FATAL] pass --serial <adb-serial>'); process.exit(9); }
const OUT = arg('out', 'out');
const IP = arg('ip', '192.168.137.1');
const HERE = __dirname;
const PHONE_DIR = '/data/local/tmp/simctrl';

function adb(...a) {
  try {
    return execFileSync(ADB, ['-s', SERIAL, ...a], { encoding: 'utf8', timeout: 90000 });
  } catch (e) {
    return (e.stdout || '') + '\n[adb error] ' + (e.message || e);
  }
}

const checks = [];
function check(name, ok, detail) {
  checks.push({ name, ok: !!ok, detail: String(detail || '').slice(0, 160) });
  console.log((ok ? 'T2 ' : 'FAIL ') + name + ': ' + String(detail || '').slice(0, 140));
}

// Push the probe scripts (they live in probes/, next to sim/).
for (const f of ['stun-probe.sh', 'dtls-probe.sh']) {
  adb('push', path.join(HERE, '..', 'probes', f), PHONE_DIR + '/' + f);
}

// 1. STUN binding request to :40000 (UDP path + ICE candidate validity).
let stunOut = adb('shell', `su -c 'sh ${PHONE_DIR}/stun-probe.sh ${IP} 40000'`);
check('stun.response', /STUN_OK/.test(stunOut), stunOut.split('\n').slice(-3).join(' / '));

// 2. Bare DTLS 1.2 ClientHello (no cookie) to :40000. A live server answers
// ServerHello (cipher + use_srtp echo) + Certificate flight -> DTLS_ALIVE.
let dtlsOut = adb('shell', `su -c 'sh ${PHONE_DIR}/dtls-probe.sh ${IP} 40000'`);
check('dtls.serverhello', /DTLS_ALIVE/.test(dtlsOut), dtlsOut.split('\n').slice(-4).join(' / '));

// Evidence copies (best effort).
try { adb('pull', `${PHONE_DIR}/stun.resp`, path.join(OUT, 'stun.resp')); } catch (_) {}
try { adb('pull', `${PHONE_DIR}/dtls.resp`, path.join(OUT, 'dtls.resp')); } catch (_) {}

const pass = checks.every((c) => c.ok);
fs.writeFileSync(path.join(OUT, 't2-result.json'),
  JSON.stringify({ tier: 'T2', pass, checks }, null, 2));
console.log(pass ? 'RESULT T2 PASS' : 'RESULT T2 FAIL');
process.exit(pass ? 0 : 1);
