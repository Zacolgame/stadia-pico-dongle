#include "proto.h"
#include "config.h"   // BISECT_0826 and friends
#include <stdio.h>
#include <stdlib.h>

// ---------- discovery_api ----------

void build_register_controller_response(pb_out_t *o, const reg_resp_t *r) {
    uint8_t db[128]; pb_out_t d; pbo_init(&d, db, sizeof db);
    pbo_str(&d, 1, r->display_id);
    pbo_str(&d, 4, r->display_token);
    uint8_t b[256]; pb_out_t t; pbo_init(&t, b, sizeof b);
    pbo_str(&t, 1, r->registration_id);
    pbo_u64(&t, 2, 1000);              // poll_interval_ms (required > 0)
    pbo_str(&t, 3, r->registration_token);
    pbo_msg(&t, 5, &d);                // display oneof
    pbo_raw(o, t.buf, t.len);
}

void build_discover_display_response(pb_out_t *o, const char *display_id, const char *display_token) {
    pbo_str(o, 1, display_id);
    pbo_str(o, 4, display_token);      // required non-empty
}

void build_fwcheck_response(pb_out_t *o) {
    pbo_tag(o, 1, 0); pbo_varint(o, 0); // requires_update = false
}

// ---------- gmsg ----------
// GmsgEnvelope{message{id=1, type=2:42, ext 269197544{controller_command{payload}}}}
void build_gmsg_envelope(pb_out_t *o, int64_t msg_id, const uint8_t *payload, int payload_len) {
    static uint8_t cc[768]; pb_out_t c; pbo_init(&c, cc, sizeof cc);
#if BISECT_0826
    pbo_bytes(&c, 1, payload, payload_len);      // p3-0826: ext -> #1: payload (one level)
#else
    static uint8_t inner[528]; pb_out_t in; pbo_init(&in, inner, sizeof inner);
    pbo_bytes(&in, 1, payload, payload_len);
    pbo_msg(&c, 1, &in);                         // ext -> #1 -> #1: payload
#endif
    static uint8_t ext[800]; pb_out_t e; pbo_init(&e, ext, sizeof ext);
    pbo_msg(&e, 269197544, &c);
    static uint8_t msg[840]; pb_out_t m; pbo_init(&m, msg, sizeof msg);
    pbo_u64(&m, 1, (uint64_t)msg_id);
    pbo_u64(&m, 2, 42);
    pbo_raw(&m, e.buf, e.len);
    pbo_msg(o, 1, &m);
}

// ---------- SDP ----------

// bundle = WebRtcSdpAndIceCandidates{ 1: sdp(WebRtcSdp), 2: repeated ice_candidate }
// WebRtcSdp        = { 1: type, 2: raw_value, 3: sdp_offer, 4: sdp_answer, 5: ice_candidate }
// The offer therefore lives at bundle#1#3. The old code read bundle#1#2, which is
// WebRtcSdp.raw_value (absent for a structured offer), so a REAL controller request
// yielded no offer at all and the answer was built from a zeroed struct.
int find_sdp_offer(const uint8_t *bundle, int len, const uint8_t **offer, int *offer_len) {
    const uint8_t *sdp; int sl = 0;
    sdp = pb_get_bytes(bundle, len, 1, &sl);
    if (sdp && sl > 0) {
        const uint8_t *o = pb_get_bytes(sdp, sl, 3, offer_len);
        if (o && *offer_len > 0) { *offer = o; return 1; }
        return 0;                       // it is a bundle but carries no sdp_offer
    }
    *offer = bundle; *offer_len = len;  // not a bundle: treat it as a bare RtcSdpOffer
    return 1;
}

int parse_rtc_sdp_offer(const uint8_t *offer, int len, sdp_offer_info_t *out) {
    memset(out, 0, sizeof *out);
    out->raw_dtls = -1; out->delayed_acks = -1; out->use_rtp_timestamps = -1;
    pb_it_t it; pbi_init(&it, offer, len);
    while (pbi_next(&it)) {
        switch (it.field) {
        case 3: { int n = it.body_len < 15 ? it.body_len : 15; memcpy(out->offer_ufrag, it.body, n); break; }
        case 4: { int n = it.body_len < 39 ? it.body_len : 39; memcpy(out->offer_pwd, it.body, n); break; }
        case 5: { int n = it.body_len < (int)sizeof out->offer_fp - 1 ? it.body_len
                                                                    : (int)sizeof out->offer_fp - 1;
                  memcpy(out->offer_fp, it.body, n); break; }
        case 8: out->audio_ssrc = (uint32_t)it.v; break;
        case 16: if (out->video_format_len == 0 && it.wire == 2 && it.body_len <= (int)sizeof out->video_format) {
                     memcpy(out->video_format, it.body, it.body_len); out->video_format_len = it.body_len; } break;
        case 17: if (out->audio_format_len == 0 && it.wire == 2 && it.body_len <= (int)sizeof out->audio_format) {
                     memcpy(out->audio_format, it.body, it.body_len); out->audio_format_len = it.body_len; } break;
        case 21: out->raw_dtls = (int)it.v; break;
        case 23: out->delayed_acks = (int)it.v; break;
        case 25: out->use_rtp_timestamps = (int)it.v; break;
        default: break;
        }
    }
    return 0;
}

void build_rtc_sdp_answer(pb_out_t *o, const sdp_offer_info_t *inf, const rtc_creds_t *ours) {
    pbo_str(o, 1, ours->ufrag);
    pbo_str(o, 2, ours->pwd);
    pbo_str(o, 3, ours->fingerprint);
    pbo_str(o, 4, ours->fingerprint);          // secondary_fingerprint: same cert
    if (inf->raw_dtls > 0) { pbo_tag(o, 10, 0); pbo_varint(o, 1); }
    if (inf->delayed_acks > 0) { pbo_tag(o, 11, 0); pbo_varint(o, 1); }
#if BISECT_0826
    // p3-0826 also echoed the codec formats and set these flags; the controller still
    // started ICE with them present, so keep them selectable for the bisect.
    if (inf->video_format_len) pbo_bytes(o, 8, inf->video_format, inf->video_format_len);
    if (inf->audio_format_len) pbo_bytes(o, 9, inf->audio_format, inf->audio_format_len);
    pbo_tag(o, 12, 0); pbo_varint(o, 1);
    pbo_tag(o, 13, 0); pbo_varint(o, 1);
    pbo_tag(o, 15, 0); pbo_varint(o, 1);
    if (inf->use_rtp_timestamps > 0) { pbo_tag(o, 17, 0); pbo_varint(o, 1); }
#endif
}

void build_rtc_ice_candidate(pb_out_t *o, const char *ip, uint32_t port) {
    pbo_str(o, 1, "data");                    // sdp_mid (live sample uses "data", not "0")
    // sdp_mline_index is 0; proto3 leaves default values out (the live spec's
    // signaling.candidate_message produces no bytes for it either).
    pbo_str(o, 3, "1");                       // foundation
    pbo_u64(o, 4, 2130706431);                // priority ~ host
    pbo_str(o, 5, ip);
    pbo_u64(o, 6, port);
}

void build_sdp_answer_bundle(pb_out_t *o, const sdp_offer_info_t *inf, const rtc_creds_t *disp,
                             const char *our_ip, uint32_t our_port) {
    // 192 was too small: the answer is ~200 bytes, and pbo_raw silently drops what
// does not fit AFTER writing the tag and length - producing a protobuf that declares
// a field but carries no data. The controller then cannot parse the GMsg, never
// acks it and never starts ICE.
    static uint8_t ans[512]; pb_out_t a; pbo_init(&a, ans, sizeof ans);
    build_rtc_sdp_answer(&a, inf, disp);
    // WebRtcSdp{1: type, 4: sdp_answer}.  Schema (verified against the live spec's
    // signaling.build_answer):  #3 is sdp_OFFER and #4 is sdp_ANSWER - the previous code
    // wrote the answer into #3, so the controller saw type=SDP_ANSWER with the offer
    // field filled and could not start ICE.
    static uint8_t sdp[512]; pb_out_t s; pbo_init(&s, sdp, sizeof sdp);
    pbo_u64(&s, 1, 2);                        // Type.SDP_ANSWER
    pbo_msg(&s, 4, &a);                       // sdp_answer
    // WebRtcSdpAndIceCandidates#2 expects a WebRtcSdp, not a bare RtcIceCandidate:
    // WebRtcSdp{1: type=ICE_CANDIDATE, 5: ice_candidate{...}} (signaling.candidate_message).
    uint8_t cand[96]; pb_out_t ci; pbo_init(&ci, cand, sizeof cand);
    build_rtc_ice_candidate(&ci, our_ip, our_port);
    static uint8_t candw[192]; pb_out_t cw; pbo_init(&cw, candw, sizeof candw);
    pbo_u64(&cw, 1, 3);                       // Type.ICE_CANDIDATE
    pbo_msg(&cw, 5, &ci);                     // ice_candidate
    uint8_t b[420]; pb_out_t t; pbo_init(&t, b, sizeof b);
    pbo_msg(&t, 1, &s);                       // WebRtcSdpAndIceCandidates.sdp
    pbo_msg(&t, 2, &cw);                      // .ice_candidate (a WebRtcSdp)
    pbo_raw(o, t.buf, t.len);
}

// ---------- streamer ----------

void build_streamer_init_response(pb_out_t *o, const sdp_offer_info_t *inf, const rtc_creds_t *game,
                                   const char *our_ip, uint32_t our_port) {
    // 192 was too small: the answer is ~200 bytes, and pbo_raw silently drops what
// does not fit AFTER writing the tag and length - producing a protobuf that declares
// a field but carries no data. The controller then cannot parse the GMsg, never
// acks it and never starts ICE.
    static uint8_t ans[512]; pb_out_t a; pbo_init(&a, ans, sizeof ans);
    build_rtc_sdp_answer(&a, inf, game);
    uint8_t cand[96]; pb_out_t c; pbo_init(&c, cand, sizeof cand);
    build_rtc_ice_candidate(&c, our_ip, our_port);
    static uint8_t initr[304]; pb_out_t ir; pbo_init(&ir, initr, sizeof initr);
    pbo_bytes(&ir, 1, a.buf, a.len);          // answer
    pbo_bytes(&ir, 2, c.buf, c.len);          // candidate
    static uint8_t sr[320]; pb_out_t s; pbo_init(&s, sr, sizeof sr);
    pbo_msg(&s, 1, &ir);                      // initialization oneof
    pbo_raw(o, s.buf, s.len);
}

// ---------- rpc ----------

void build_rpc_response(pb_out_t *o, uint32_t ticket, int code, const uint8_t *payload, int payload_len) {
    static uint8_t b[640]; pb_out_t t; pbo_init(&t, b, sizeof b);
    pbo_u64(&t, 1, ticket);
    // Always serialize code and message like the verified reference (stadiacast
    // controller.py _answer_request -> rpc_response(ticket, code=0, message="")):
    // proto2 optional fields explicitly set serialize even at defaults. Omitting is
    // schema-legal but unverified against the controller's nanopb parser - the oracle
    // caught the heartbeat reply differing: 1202084d vs 1206084d10001a00.
    pbo_u64(&t, 2, (uint64_t)code);
    pbo_str(&t, 3, "");
    if (payload_len) pbo_bytes(&t, 4, payload, payload_len);
    pbo_msg(o, 2, &t);
}

void build_rpc_request(pb_out_t *o, uint32_t ticket, const uint8_t *payload, int payload_len) {
    static uint8_t b[640]; pb_out_t t; pbo_init(&t, b, sizeof b);
    pbo_u64(&t, 1, ticket);
    pbo_bytes(&t, 2, payload, payload_len);
    pbo_msg(o, 1, &t);
}

void build_get_controller_state_request(pb_out_t *o) {
    pbo_tag(o, 2, 0); pbo_varint(o, 0);       // display_supports_send_log_report = false
}

void build_start_game(pb_out_t *o, const char *key) {
    pbo_str(o, 1, key);
    pbo_u64(o, 2, 1);
}

void build_current_time_response(pb_out_t *o, uint64_t controller_time_us, uint64_t display_time_us) {
    pbo_u64(o, 1, controller_time_us);        // echo unchanged (firmware rtt check)
    pbo_u64(o, 2, display_time_us);
}

// ---------- rumble feedback series (game link 0x66) --------------------------

// Numeric caps on purpose (p3-2710). sizeof(pb_out_t) is platform-dependent - 12 B on
// ARM32, 16 B on x64 - so a `pbo_init(&x, buf, sizeof x)` typo in shared code would
// pass the x64 host test (4+12 <= 16 fits) and STILL truncate on the device (4+12 >
// 12 drops the f10 content, the exact 27 B start frame of 2026-11-05). Fixed numbers
// make host and device produce identical bytes; a too-small number fails the
// byte-exact oracle (R15_*/R16_* vectors) instead of the motor.
enum { RUMBLE_VIB_CAP = 24, RUMBLE_FB_CAP = 32, RUMBLE_SLIM_CAP = 48, RUMBLE_SERIES_CAP = 112 };
// Worst-case occupancy check (5-byte varints everywhere + a 64 B session echo):
//   vib 6+6+6=18 <= 24; fb 2+18=20 <= 32; slim 2+2+20=24 <= 48;
//   series 66+6+10+(2+24)=108 <= 112; msg 2+108=110 <= caller's buffer.

void build_rumble_series(pb_out_t *o, uint32_t gamepad_id, uint32_t left, uint32_t right,
                         uint32_t seq, uint64_t base_ts_us,
                         const uint8_t *session_id, int session_id_len) {
    uint8_t vib[RUMBLE_VIB_CAP]; pb_out_t v; pbo_init(&v, vib, RUMBLE_VIB_CAP);
    // vib.id mirrors send_vibration: the gamepad id the controller announced
    // (g["gamepad_id"] or 0) - ota.282115 registers id=1 in its first series.
    pbo_u64(&v, 1, gamepad_id);
    pbo_u64(&v, 2, left);
    pbo_u64(&v, 3, right);
    uint8_t fb[RUMBLE_FB_CAP]; pb_out_t f; pbo_init(&f, fb, RUMBLE_FB_CAP);
    pbo_msg(&f, 1, &v);                 // InputFeedbackMessage_V2.gamepad_vibration
    uint8_t slim[RUMBLE_SLIM_CAP]; pb_out_t s; pbo_init(&s, slim, RUMBLE_SLIM_CAP);
    pbo_u64(&s, 4, 0);                  // InputMessageSlim.relative_time_us = 0
    pbo_msg(&s, 10, &f);                // slim.input_feedback_message_v2
    uint8_t series[RUMBLE_SERIES_CAP]; pb_out_t se; pbo_init(&se, series, RUMBLE_SERIES_CAP);
    // Echo the controller's series session_id when it sent one (send_vibration does;
    // ota.282115 sends NONE - its registration series is f2+f3+f4 only - so the echo
    // is correctly absent for that controller, see learn_series_session below).
    if (session_id_len > 0) pbo_bytes(&se, 1, session_id, session_id_len);
    pbo_u64(&se, 2, seq);
    pbo_u64(&se, 3, base_ts_us);
    pbo_msg(&se, 4, &s);                // messages[0] IS the slim message - no {1: slim}
                                        // wrapper (a parser would read that as V1)
    pbo_msg(o, 7, &se);                 // no f4 piggyback: the reference's series
}                                       // messages never carry ack_sequence_number

int learn_series_session(const uint8_t *series, int len, uint8_t *out, int cap) {
    int sl = 0;
    const uint8_t *sid = pb_get_bytes(series, len, 1, &sl);
    if (!sid || sl <= 0 || sl > cap) return 0;   // absent / empty / over cap: keep the
    memcpy(out, sid, (size_t)sl);                // previous learning (reference keeps a
    return sl;                                   // truthy session_id until replaced)
}

int wh2_wrap(uint8_t *out, int cap, uint16_t id, const uint8_t *payload, int n) {
    int total = 8 + n;
    if (n < 0 || total > cap) return 0;
    out[0] = 0; out[1] = 0;
    out[2] = (uint8_t)id; out[3] = (uint8_t)(id >> 8);
    out[4] = (uint8_t)total; out[5] = (uint8_t)(total >> 8); out[6] = (uint8_t)(total >> 16);
    out[7] = 0;
    if (n) memcpy(out + 8, payload, (size_t)n);
    return total;
}

// ---------- IPv6 Router Advertisement frame (p3-3050-ipv6ra) ------------------
//
// Root cause of the controller's 3-round boot crash lights (Crash* kPatterns
// [38-45], 3x 8000ms yellow<->red): right after associating it brings up IPv6
// and sends Router Solicitations (ICMPv6 type 133 -> ff02::2; 193 frames in a
// ~15 s window). This firmware is IPv4-only (LWIP_IPV6=0), nothing ever
// answered, its IPv6 init timed out and escalated to crash/reboot - which is
// why every reboot cycle advances its state machine a bit further. Android
// phone hotspots DO run an RA speaker, so the hotspot environment never showed
// it. Fix: periodically multicast the one frame a real IPv4-only router should
// send (RFC 4861 s.4.2, and RFC 6980 "router must announce lifetime 0 instead
// of silence when it cannot be a default router"):
//
//   RA: cur hop limit unspecified, M=0 O=0, ROUTER LIFETIME = 0
//       ("router present, but NOT a default router" - the host's IPv6 init
//        completes immediately instead of waiting for more routers),
//       reachable/retrans unspecified, SLLA = our MAC,
//       PIO /64 with L=0 A=0 valid=0 preferred=0 (deprecate anything learned).
//
// Hand-built byte by byte: the lwIP IPv6 stack stays compiled OUT (LWIP_IPV6=0
// in lwipopts.h), so this costs zero stack RAM - the frame is one static 110 B
// buffer and cyw43_send_ethernet(itf=AP, is_pbuf=false) copies it straight
// into the SDPCM tx path. Byte-exact oracle: tests/check_ipv6_ra.py rebuilds
// this frame with an independent checksum implementation and diffs it against
// the ph() vectors of tests/proto_host_test.c (RA_A / RA_B) - the SAME builder
// net_infra.c ipv6_ra_tick() transmits (shared-constructor rule, p3-2710).
//
// Layout (offsets into out, 110 bytes total):
//   [0..5]    33:33:00:00:00:01           ethernet dst = ff02::1 (all nodes)
//   [6..11]   our MAC                     ethernet src (AP BSSID on the air)
//   [12..13]  86 dd                       ethertype IPv6
//   [14..17]  60 00 00 00                 v6, TC 0, flow 0
//   [18..19]  00 38                       payload length = 56
//   [20]      3a                          next header = ICMPv6 (58)
//   [21]      ff                          hop limit 255 (RAs are always 255)
//   [22..37]  fe80::<EUI-64 of MAC>       src link-local (U/L bit inverted)
//   [38..53]  ff02::1                     dst all-nodes
//   [54]      86                          ICMPv6 type 134 = Router Advertisement
//   [55]      00                          code 0
//   [56..57]  checksum                    over pseudo-header + body (below)
//   [58]      00                          cur hop limit: unspecified
//   [59]      00                          M=0 O=0 (no DHCPv6 at all)
//   [60..61]  00 00                       ROUTER LIFETIME = 0   <- the fix
//   [62..65]  00*4                        reachable time: unspecified
//   [66..69]  00*4                        retrans timer: unspecified
//   [70..77]  01 01 <MAC>                 SLLA option (8 B)
//   [78..109] 03 04 40 00 | 0*12 | fd00:: PIO: /64, L=0 A=0, valid=0 preferred=0
static uint32_t v6_cksum_add(uint32_t sum, const uint8_t *p, int n) {
    // 16-bit big-endian word sum with odd-tail padding (RFC 1071).
    while (n >= 2) { sum += ((uint32_t)p[0] << 8) | p[1]; p += 2; n -= 2; }
    if (n) sum += (uint32_t)*p << 8;
    return sum;
}

int build_ipv6_ra(uint8_t *out, const uint8_t mac[6]) {
    memset(out, 0, IPV6_RA_FRAME_LEN);
    memcpy(out + 6, mac, 6);
    out[0] = 0x33; out[1] = 0x33; out[5] = 0x01;        // ff02::1 -> 33:33:0:0:0:1
    out[12] = 0x86; out[13] = 0xdd;                     // ethertype IPv6
    out[14] = 0x60;                                     // version 6, TC 0, flow 0
    out[19] = IPV6_RA_FRAME_LEN - 54;                   // payload length = 56
    out[20] = 58;                                       // next header ICMPv6
    out[21] = 255;                                      // hop limit
    out[22] = 0xfe; out[23] = 0x80;                     // src fe80::/64
    out[30] = (uint8_t)(mac[0] ^ 0x02);                 // EUI-64: invert U/L bit,
    out[31] = mac[1]; out[32] = mac[2];                 // insert ff:fe in the middle
    out[33] = 0xff; out[34] = 0xfe;
    out[35] = mac[3]; out[36] = mac[4]; out[37] = mac[5];
    out[38] = 0xff; out[39] = 0x02; out[53] = 0x01;     // dst ff02::1
    out[54] = 134;                                      // RA
    out[70] = 1; out[71] = 1;                           // SLLA option
    memcpy(out + 72, mac, 6);
    out[78] = 3; out[79] = 4; out[80] = 64;             // PIO /64, L=0 A=0
    out[90] = 0xfd;                                     // prefix fd00:: (inert: the
                                                        // zero lifetimes only deprecate)
    // ICMPv6 checksum (RFC 4443): one's complement of the sum over the IPv6
    // pseudo-header (src || dst || 32-bit payload length || 3 zero bytes + NH)
    // and the ICMPv6 message with its checksum field zero.
    const uint8_t plen32[4] = { 0, 0, 0, out[19] };     // 56 fits in the low byte
    const uint8_t nh58[4] = { 0, 0, 0, 58 };
    uint32_t s = 0;
    s = v6_cksum_add(s, out + 22, 16);                  // pseudo-header src
    s = v6_cksum_add(s, out + 38, 16);                  // pseudo-header dst
    s = v6_cksum_add(s, plen32, 4);                     // upper-layer packet length
    s = v6_cksum_add(s, nh58, 4);                       // zeros + next header
    s = v6_cksum_add(s, out + 54, IPV6_RA_FRAME_LEN - 54); // whole ICMPv6 msg
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    uint16_t ck = (uint16_t)(~s & 0xffff);
    out[56] = (uint8_t)(ck >> 8); out[57] = (uint8_t)ck;
    return IPV6_RA_FRAME_LEN;
}

int verify_ipv6_ra_checksum(const uint8_t *f) {
    const uint8_t plen32[4] = { 0, 0, 0, f[19] };
    const uint8_t nh58[4] = { 0, 0, 0, 58 };
    uint32_t s = 0;
    s = v6_cksum_add(s, f + 22, 16);
    s = v6_cksum_add(s, f + 38, 16);
    s = v6_cksum_add(s, plen32, 4);
    s = v6_cksum_add(s, nh58, 4);
    s = v6_cksum_add(s, f + 54, IPV6_RA_FRAME_LEN - 54);
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)(~s & 0xffff) == (uint16_t)(((uint16_t)f[56] << 8) | f[57]);
}
