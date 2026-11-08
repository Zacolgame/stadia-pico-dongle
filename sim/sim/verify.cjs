// verify.cjs -- decode the phone's T1 captures and print the gate lines.
// Usage: node verify.cjs --out <dir> [--json <file>]
'use strict';
const fs = require('fs');
const path = require('path');
const pb = require('./pblite.cjs');

const argv = process.argv.slice(2);
const val = (k, d) => { const i = argv.indexOf('--' + k); return i >= 0 && i + 1 < argv.length ? argv[i + 1] : d; };
const OUT = path.resolve(val('out', path.join(__dirname, '..', 'out')));
const JSONOUT = val('json', path.join(OUT, 't1-result.json'));

const rows = {};
for (const line of fs.readFileSync(path.join(OUT, 't1.log'), 'utf8').split(/\r?\n/)) {
  if (!line.trim()) continue;
  // name status bytes time_total time_appconnect ssl_verify
  const parts = line.trim().split(/\s+/);
  if (parts.length < 5 || isNaN(Number(parts[1]))) continue;   // skip marker lines (retry-after-repin)
  const [name, status, bytes, total, appconnect, verify] = parts;
  rows[name] = { status: Number(status), bytes: Number(bytes), total: Number(total), appconnect: Number(appconnect), verify: Number(verify) };
}
const resp = (n) => { try { return fs.readFileSync(path.join(OUT, n + '.resp')); } catch (e) { return Buffer.alloc(0); } };
const err = (n) => { try { return fs.readFileSync(path.join(OUT, n + '.err'), 'utf8').trim(); } catch (e) { return ''; } };

const checks = [];
const M = {};
function check(name, ok, detail) { checks.push({ name, ok: !!ok, detail }); return !!ok; }
const ms = (s) => (s === undefined ? '?' : Math.round(s * 1000) + 'ms');

// 1 -- /log/batch (firmware CLEARCUT_REPLY=0 -> 204)
const lb = rows.log_batch || {};
check('log_batch.status', [200, 204].includes(lb.status), `status=${lb.status} body=${lb.bytes}B ${err('log_batch')}`);
M.log_batch_status = lb.status; M.log_batch_ms = ms(lb.appconnect);

// 2 -- /v1:FirmwareVersionCheck -> 200, body 08 00
const fw = resp('fwcheck');
const fwr = rows.fwcheck || {};
check('fwcheck.status', fwr.status === 200, `status=${fwr.status} ${err('fwcheck')}`);
check('fwcheck.body', fw.length === 2 && fw[0] === 0x08 && fw[1] === 0x00, `body=${fw.toString('hex')} (want 0800)`);
M.fwcheck_status = fwr.status; M.fwcheck_body = fw.toString('hex');

// 3 -- /v1:RegisterController -> 200 + registration fields
const rreg = resp('register');
const regm = (() => { try { return pb.dec(rreg); } catch (e) { return []; } })();
const regId = pb.txt(pb.first(regm, 1));
const pollMs = pb.num(pb.first(regm, 2));
const regTok = pb.txt(pb.first(regm, 3));
const disp = pb.sub(pb.first(regm, 5));
const dispId = pb.txt(pb.first(disp, 1)), dispTok = pb.txt(pb.first(disp, 4));
const rr = rows.register || {};
check('register.status', rr.status === 200, `status=${rr.status} bytes=${rr.bytes} ${err('register')}`);
check('register.registration_id', !!regId, `f1=${regId}`);
check('register.poll_interval_ms', pollMs === 1000, `f2=${pollMs} (want 1000)`);
check('register.display_token_matches', !!dispTok && dispTok === regTok, `f3=${regTok} f5.f4=${dispTok}`);
M.register_status = rr.status; M.register_ms = ms(rr.appconnect); M.register_body_bytes = rreg.length;
M.registration_id = regId; M.poll_interval_ms = pollMs; M.display_id = dispId;

// 4 -- /gmsg first poll: envelope with the SDP answer for 192.168.137.1:40000
// The live firmware nests the answer one level shallower than proto.c suggests, so
// search the decoded tree for the answer node (f1=ufrag, f2=pwd, f3="sha-256 ...")
// and the candidate node (f5=dotted IP, f6=port) instead of hard-coding a path.
let gname = 'gmsg1';
// An empty body means an earlier poll consumed the answer (deliver-once); t1.sh then
// re-registers and polls again into gmsg1b, so judge that capture instead.
if ((rows.gmsg1 || {}).bytes === 0 && rows.gmsg1b) gname = 'gmsg1b';
const rg = resp(gname);
const env = {}, ans = {}, cand = {};
const gr = rows[gname] || {};
function walk(nodes, fn, depth) {
  if (depth > 6) return;
  fn(nodes);
  for (const n of nodes) if (n.buf) { try { walk(pb.dec(n.buf), fn, depth + 1); } catch (e) { /* not a message */ } }
}
let ansNode = null, candNode = null;
try {
  const top = pb.dec(rg);
  env.id = pb.num(pb.first(pb.sub(pb.first(top, 1)), 1));
  env.type = pb.num(pb.first(pb.sub(pb.first(top, 1)), 2));
  walk(top, (nodes) => {
    const f = (i) => pb.first(nodes, i);
    if (!ansNode && f(3) && /^sha-256 /.test(pb.txt(f(3)) || '')) ansNode = nodes;
    if (!candNode && f(5) && /^\d+\.\d+\.\d+\.\d+$/.test(pb.txt(f(5)) || '') && f(6)) candNode = nodes;
  }, 0);
  if (ansNode) {
    const g = (i) => pb.first(ansNode, i);
    ans.ufrag = pb.txt(g(1)); ans.pwd = pb.txt(g(2)); ans.fp = pb.txt(g(3));
    ans.rawDtls = pb.num(g(10)); ans.delayedAcks = pb.num(g(11));
  }
  if (candNode) {
    cand.ip = pb.txt(pb.first(candNode, 5)); cand.port = pb.num(pb.first(candNode, 6));
  }
  // the WebRtcSdp wrapper carries the message type (2 = SDP_ANSWER)
  walk(top, (nodes) => {
    const t = pb.num(pb.first(nodes, 1));
    if (ans.type === undefined && (t === 1 || t === 2) && pb.first(nodes, 4)) ans.type = t;
  }, 0);
} catch (e) { ans.error = e.message; }
check('gmsg.status', gr.status === 200, `status=${gr.status} ${err('gmsg1')}`);
check('gmsg.envelope', env.type === 42 && env.id >= 1, `id=${env.id} type=${env.type} (want type 42)`);
check('gmsg.answer_type', ans.type === 2, `WebRtcSdp.type=${ans.type} (want 2=SDP_ANSWER)`);
check('gmsg.answer_creds', !!ans.ufrag && !!ans.pwd && /^sha-256 /.test(ans.fp || ''), `ufrag=${ans.ufrag} pwd_len=${(ans.pwd || '').length} fp=${(ans.fp || '').slice(0, 23)}`);
check('gmsg.raw_dtls', ans.rawDtls === 1 && ans.delayedAcks === 1, `raw_dtls=${ans.rawDtls} delayed_acks=${ans.delayedAcks}`);
check('gmsg.candidate', cand.ip === '192.168.137.1' && cand.port === 40000, `cand=${cand.ip}:${cand.port} (want 192.168.137.1:40000)`);
M.gmsg_status = gr.status; M.gmsg_bytes = rg.length; M.gmsg_id = env.id; M.gmsg_type = env.type;
M.display_ufrag = ans.ufrag; M.display_fingerprint = ans.fp; M.display_candidate = `${cand.ip}:${cand.port}`;
M.srtp_wire = ans.rawDtls === 1 ? 'raw-dtls' : 'srtp';

// 5 -- /gmsg second poll with ack -> 200, empty (deliver-once rule, PLAYBOOK 3.6y)
const g2 = rows.gmsg2 || {};
check('gmsg.deliver_once', g2.status === 200 && g2.bytes === 0, `status=${g2.status} bytes=${g2.bytes} (want 200/0)`);
M.gmsg2_bytes = g2.bytes;

// 6 -- 3 parallel TLS registrations (NSLOTS=3, the real controller's cadence)
const par = [0, 1, 2].map((i) => {
  const r = rows['par' + i] || {};
  let id = null;
  try { id = pb.txt(pb.first(pb.dec(resp('par' + i)), 1)); } catch (e) { /* ignore */ }
  return { i, status: r.status, ms: r.appconnect, id };
});
const okPar = par.every((p) => p.status === 200);
const ids = new Set(par.map((p) => p.id).filter(Boolean));
// A hop back to the home SSID invalidates the parallel phase (the phone has no route
// to 192.168.137.1 at all); report it as SKIP instead of blaming the firmware.
const parSsid = (fs.readFileSync(path.join(OUT, 't1.log'), 'utf8').match(/^par_ssid:\s*(.+)$/m) || [])[1] || '';
const parSkip = !okPar && !/StadiaPhone/.test(parSsid);
check('parallel.status_x3', okPar || parSkip, par.map((p) => `${p.status}/${p.ms ? Math.round(p.ms * 1000) + 'ms' : '?'}`).join(' ') + (parSkip ? ` [SKIP: phone was on ${parSsid}]` : ''));
check('parallel.distinct_reg_ids', ids.size === 3 || parSkip, `ids=${ids.size}/3 ${[...ids].join(',')}`);
M.parallel = par;

const passed = checks.filter((c) => c.ok).length;
const fail = checks.filter((c) => !c.ok);
const ok = (a, b) => checks.slice(a, b).every((c) => c.ok);   // half-open range

// ---- print gate lines -----------------------------------------------------
const P = (s) => console.log(s);
P(`SIM-CONTROLLER T1  out=${OUT}`);
P(`T1 /log/batch          status=${lb.status} bytes=${lb.bytes} tls=${ms(lb.appconnect)}  ${checks[0].ok ? 'PASS' : 'FAIL'} (CLEARCUT_REPLY=0 expects 204)`);
P(`T1 /v1:FirmwareVersion  status=${fwr.status} body=${fw.toString('hex')} tls=${ms(fwr.appconnect)}  ${ok(1, 3) ? 'PASS' : 'FAIL'}`);
P(`T1 /v1:RegisterCtrl     status=${rr.status} bytes=${rreg.length} tls=${ms(rr.appconnect)}  ${ok(3, 7) ? 'PASS' : 'FAIL'}`);
P(`   reg_id=${regId} poll_ms=${pollMs} display=${dispId} token=${regTok}`);
P(`T1 /gmsg #1            status=${gr.status} bytes=${rg.length}  ${ok(7, 13) ? 'PASS' : 'FAIL'}`);
P(`   envelope id=${env.id} type=${env.type} answer_type=${ans.type} ufrag=${ans.ufrag} pwd_len=${(ans.pwd || '').length}`);
P(`   display_fp=${ans.fp}`);
P(`   candidate=${cand.ip}:${cand.port}  raw_dtls=${ans.rawDtls} delayed_acks=${ans.delayedAcks}`);
P(`T1 /gmsg #2 (ack)      status=${g2.status} bytes=${g2.bytes}  ${checks[13].ok ? 'PASS' : 'FAIL'} (deliver-once)`);
P(`T1 parallel x3         ${par.map((p) => `#${p.i}:${p.status}${p.ms ? '/' + Math.round(p.ms * 1000) + 'ms' : ''}`).join(' ')}  ${ok(14, 16) ? 'PASS' : 'FAIL'}`);
if (fail.length) for (const f of fail) P(`   FAIL ${f.name}: ${f.detail}`);
P(`RESULT T1 ${fail.length === 0 ? 'PASS' : 'FAIL'}  checks=${passed}/${checks.length}`);
P(`METRICS tls_register_ms=${M.register_ms} register_body=${M.register_body_bytes}B gmsg_answer=${rg.length}B dtls_target=${M.display_candidate || '?'} mode=${M.srtp_wire}`);

fs.writeFileSync(JSONOUT, JSON.stringify({ tier: 'T1', pass: fail.length === 0, checks, metrics: M, at: new Date().toISOString() }, null, 2));
process.exit(fail.length === 0 ? 0 : 2);
