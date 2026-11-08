// proto.h — discovery/gmsg/sdp/streamer message builders (see schemas/*.proto).
#pragma once
#include "pb.h"

// ---- discovery_api ---------------------------------------------------------
// RegisterControllerResponse: registration_id, poll_interval_ms(>0 required),
// registration_token (= gmsg subscription), display{display_id, display_token}
typedef struct { char registration_id[24]; char registration_token[32]; char display_id[24]; char display_token[32]; } reg_resp_t;
void build_register_controller_response(pb_out_t *o, const reg_resp_t *r);
// DiscoverDisplayResponse: display_id, display_token(non-empty required)
void build_discover_display_response(pb_out_t *o, const char *display_id, const char *display_token);
// FirmwareVersionCheckResponse: requires_update=false
void build_fwcheck_response(pb_out_t *o);

// ---- gmsg ------------------------------------------------------------------
// GmsgEnvelope{message{id, type=42, extension 269197544 {controller_command{payload}}}}
void build_gmsg_envelope(pb_out_t *o, int64_t msg_id, const uint8_t *payload, int payload_len);

// ---- WebRTC SDP ------------------------------------------------------------
typedef struct {
    char ufrag[8];         // <=7 chars
    char pwd[25];          // <=24 chars
    // "sha-256 " + 32 bytes as upper-case hex separated by ':' = 8 + 95 = 103 chars
    // (+NUL). 64 was too small and would truncate the fingerprint, which makes the
    // controller fail DTLS certificate verification.
    char fingerprint[128];
} rtc_creds_t;
// RtcSdpAnswer{ice_ufrag, ice_password, fingerprint, video_format(echo), audio_format(echo),
//              raw_dtls=true(echo), delayed_acks(echo), use_rtp_timestamps(echo)}
// We echo the offer's flags/formats: parse from offer, then answer.
typedef struct {
    // from the offer (echoed)
    int raw_dtls, delayed_acks, use_rtp_timestamps;
    uint8_t video_format[48]; int video_format_len;   // first H264/VP9 entry, re-encoded
    uint8_t audio_format[32]; int audio_format_len;   // first audio entry, re-encoded
    // A real captured controller offer carries a 103-char fingerprint
    // ("sha-256 " + 32 upper-hex bytes separated by ':'), so 64 was too small and
    // silently truncated it. Nothing reads this field today, but keep it whole.
    char offer_ufrag[16], offer_pwd[40], offer_fp[128];
    uint32_t audio_ssrc;
} sdp_offer_info_t;
int parse_rtc_sdp_offer(const uint8_t *offer, int len, sdp_offer_info_t *out); // 0=ok
// Locate the RtcSdpOffer inside a WebRtcSdpAndIceCandidates blob (bundle#1#3).
int find_sdp_offer(const uint8_t *bundle, int len, const uint8_t **offer, int *offer_len);
void build_rtc_sdp_answer(pb_out_t *o, const sdp_offer_info_t *inf, const rtc_creds_t *ours);
// RtcIceCandidate{sdp_mid="0", mline=0, foundation="1", priority, ip(literal), port}
void build_rtc_ice_candidate(pb_out_t *o, const char *ip, uint32_t port);

// WebRtcSdpAndIceCandidates{sdp{type=ANSWER(2), answer}, ice_candidate} — the gmsg payload
void build_sdp_answer_bundle(pb_out_t *o, const sdp_offer_info_t *inf, const rtc_creds_t *disp,
                             const char *our_ip, uint32_t our_port);

// ---- streamer (game envelope) ----------------------------------------------
// StreamerResponse{initialization{answer: RtcSdpAnswer, candidate: RtcIceCandidate}}
void build_streamer_init_response(pb_out_t *o, const sdp_offer_info_t *inf, const rtc_creds_t *game,
                                  const char *our_ip, uint32_t our_port);

// ---- rpc envelope helpers ---------------------------------------------------
// RpcMessage.response{ticket, code, payload} — payload = DisplayToController message
void build_rpc_response(pb_out_t *o, uint32_t ticket, int code, const uint8_t *payload, int payload_len);
// RpcMessage.request{ticket, payload=DisplayToController}
void build_rpc_request(pb_out_t *o, uint32_t ticket, const uint8_t *payload, int payload_len);
// DisplayToController payloads
void build_get_controller_state_request(pb_out_t *o);
void build_start_game(pb_out_t *o, const char *key);
void build_current_time_response(pb_out_t *o, uint64_t controller_time_us, uint64_t display_time_us);

// ---- rumble feedback series (game link 0x66) --------------------------------
// InputProtocolMessage{7: input_message_series{
//     1: session_id?, 2: sequence_number, 3: base_timestamp_us,
//     4: messages[] = InputMessageSlim{4: relative_time_us = 0,
//         10: InputFeedbackMessage_V2{1: GamepadVibrationMessage_V2{
//             1: id, 2: left_motor_speed, 3: right_motor_speed}}}}}
// Byte-identical to stadiacast game_session.py send_vibration (the construction the
// live e4 session used when the motor verifiably spun). SHARED by rtc.c rumble_flush()
// and tests/proto_host_test.c since p3-2710: the host oracle must assert the
// firmware's OWN constructor, not a replica - the 2026-11-05 27 B start frame (f10
// content dropped right after its length prefix) was a defect of rtc.c's inline
// construction that the host test's inline REPLICA could not see.
void build_rumble_series(pb_out_t *o, uint32_t gamepad_id, uint32_t left, uint32_t right,
                         uint32_t seq, uint64_t base_ts_us,
                         const uint8_t *session_id, int session_id_len);
// Learn InputMessageSeries.session_id (f1) from a controller series body for the
// echo above. Returns the learned length, 0 when the series carries none (the
// ota.282115 baseline - its registration is f2+f3+f4 only) or it exceeds cap.
// Never clears previous learning (the reference only overwrites on a truthy id).
int learn_series_session(const uint8_t *series, int len, uint8_t *out, int cap);
// WireHeader2 framing: 00 00 | id LE16 | total LE24 | 00 (rtc/wire.py
// pack_wire_message). Returns the frame length (8+n), 0 when it does not fit.
// Shared by rtc.c wh2_send() and the host oracle's R15_WH2_* vectors.
int wh2_wrap(uint8_t *out, int cap, uint16_t id, const uint8_t *payload, int n);

// ---- IPv6 Router Advertisement frame (p3-3050-ipv6ra) ------------------------
// Complete Ethernet||IPv6||ICMPv6 RA frame with router_lifetime = 0: "I am a
// router but NOT a default router", so a client that just associated and is
// flooding Router Solicitations completes its IPv6 init immediately instead of
// timing out into the 3-round crash pattern. Hand-built byte by byte (the lwIP
// IPv6 stack stays OFF: LWIP_IPV6=0, zero extra RAM) and host-oracled byte for
// byte by tests/check_ipv6_ra.py. SHARED by net_infra.c ipv6_ra_tick() and the
// host oracle (same shared-constructor rule as build_rumble_series).
#define IPV6_RA_FRAME_LEN 110
// Returns IPV6_RA_FRAME_LEN; out must have IPV6_RA_FRAME_LEN bytes. mac = the
// AP interface MAC (becomes ethernet source, SLLA and the fe80:: EUI-64).
int build_ipv6_ra(uint8_t *out, const uint8_t mac[6]);
// Recompute the ICMPv6 checksum over a built RA frame and return 1 when it
// matches the value embedded at [56..57]. Used by the firmware's one-shot
// boot self-test (net_infra.c) so a checksum defect cannot ship silently.
int verify_ipv6_ra_checksum(const uint8_t *frame);
