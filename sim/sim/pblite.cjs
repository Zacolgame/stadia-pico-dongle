// pblite.cjs -- minimal protobuf wire codec + the exact request bodies a Stadia
// controller puts on the wire (derived from the firmware's parsers in
// research/pico2w/stadia-one/src/{cloud,proto}.c and the captured real body in
// research/live-cert-test/captures/). No dependencies.
'use strict';

function vint(n) {
  n = Math.max(0, Math.floor(n));
  const b = [];
  while (n > 127) { b.push((n & 0x7f) | 0x80); n = Math.floor(n / 128); }
  b.push(n);
  return Buffer.from(b);
}
const tag = (f, w) => vint((f << 3) | w);
const u64 = (f, n) => Buffer.concat([tag(f, 0), vint(n)]);
const bytes = (f, b) => Buffer.concat([tag(f, 2), vint(b.length), b]);
const str = (f, s) => bytes(f, Buffer.from(String(s), 'utf8'));

function varintAt(buf, i) {
  let n = 0n, shift = 0n, b;
  do {
    if (i >= buf.length) throw new Error('truncated varint');
    b = buf[i++];
    n |= BigInt(b & 0x7f) << shift; shift += 7n;
  } while (b & 0x80);
  return [n, i];
}

// -> [{field, wire, v|buf}]
function dec(buf) {
  const out = []; let i = 0;
  while (i < buf.length) {
    let k; [k, i] = varintAt(buf, i);
    const field = Number(k >> 3n), wire = Number(k & 7n);
    if (wire === 0) { let v; [v, i] = varintAt(buf, i); out.push({ field, wire, v }); }
    else if (wire === 2) { let l; [l, i] = varintAt(buf, i); l = Number(l); out.push({ field, wire, buf: buf.subarray(i, i + l) }); i += l; }
    else if (wire === 5) { out.push({ field, wire, v: buf.readUInt32LE(i) }); i += 4; }
    else if (wire === 1) { out.push({ field, wire, v: buf.readBigUInt64LE(i) }); i += 8; }
    else throw new Error('unsupported wire type ' + wire + ' at ' + i);
  }
  return out;
}
const first = (m, f) => m.find((x) => x.field === f);
const all = (m, f) => m.filter((x) => x.field === f);
const num = (x) => (x ? Number(x.v) : undefined);
const txt = (x) => (x && x.buf ? x.buf.toString('utf8') : undefined);
const sub = (x) => (x && x.buf ? dec(x.buf) : []);

const ALNUM = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
function rnd(n, abc = ALNUM) {
  const c = require('crypto').randomBytes(n);
  let s = '';
  for (let i = 0; i < n; i++) s += abc[c[i] % abc.length];
  return s;
}
function uuid() {
  const b = require('crypto').randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
  const h = b.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
function fingerprint() {
  const b = require('crypto').randomBytes(32);
  const parts = [];
  for (let i = 0; i < 32; i++) parts.push(b[i].toString(16).toUpperCase().padStart(2, '0'));
  return 'sha-256 ' + parts.join(':');
}

// ---- request bodies -------------------------------------------------------
// RegisterControllerRequest{f1 udn, f4 token, f5{ f1 uuid, f9{1:1}, f4 bundle }, f6 0}
// bundle = WebRtcSdpAndIceCandidates{ 1:WebRtcSdp{1:type=1, 3:RtcSdpOffer}, 2:WebRtcSdp{1:type=3, 5:cand} }
// RtcSdpOffer{3:ufrag, 4:pwd, 5:fingerprint, 21:raw_dtls=1, 23:delayed_acks=1, 2:1}
function registerBody(opts) {
  const o = {
    ip: opts.ip, port: opts.port, padTo: opts.padTo || 0,
    udn: opts.udn || uuid(), token: opts.token || rnd(22),
    ufrag: opts.ufrag || rnd(6), pwd: opts.pwd || rnd(22),
    fp: opts.fp || fingerprint(),
  };
  const offer = Buffer.concat([str(3, o.ufrag), str(4, o.pwd), str(5, o.fp),
    u64(2, 1), u64(21, 1), u64(23, 1)]);
  const sdp = Buffer.concat([u64(1, 1), bytes(3, offer)]);       // type=1 (SDP_OFFER)
  const cand = Buffer.concat([str(1, 'data'), str(3, '1'), u64(4, 2130706431),
    str(5, o.ip), u64(6, o.port)]);
  const candWrap = Buffer.concat([u64(1, 3), bytes(5, cand)]);   // WebRtcSdp{type=3,...}
  const bundle = Buffer.concat([bytes(1, sdp), bytes(2, candWrap)]);
  let inner = Buffer.concat([str(1, o.udn), bytes(9, u64(1, 1)), bytes(4, bundle)]);
  // --pad-to N: append an unknown length-delimited field inside f5 (ignored by the
  // firmware parser) so the HTTP request can be grown to the real-machine 6156 B
  // that overflowed the old 6144-byte buffer. Protocol-legal, semantically inert.
  if (o.padTo > 0) {
    const head = Buffer.concat([str(1, o.udn), str(4, o.token)]);
    const tail = Buffer.concat([bytes(5, Buffer.concat([inner, bytes(90, Buffer.alloc(8))])), u64(6, 0)]);
    let body = Buffer.concat([head, tail]);
    if (body.length < o.padTo) {
      body = Buffer.concat([head,
        bytes(5, Buffer.concat([inner, bytes(90, Buffer.alloc(o.padTo - body.length + 8))])),
        u64(6, 0)]);
    }
    o.body = body;
  } else {
    o.body = Buffer.concat([str(1, o.udn), str(4, o.token), bytes(5, inner), u64(6, 0)]);
  }
  o.fields = o;
  return o;
}

// GmsgRequest: f1 subscription/token, f2{f1 acked_id}
function gmsgBody(token, ackedId) {
  const parts = [str(1, token || 'pico-display-1')];
  if (ackedId !== undefined && ackedId !== null) parts.push(bytes(2, u64(1, ackedId)));
  return Buffer.concat(parts);
}

module.exports = { vint, tag, u64, bytes, str, dec, first, all, num, txt, sub, rnd, uuid, fingerprint, registerBody, gmsgBody };
