#include <stdio.h>
#include <string.h>
#include "pb.h"
#include "proto.h"

static void ph(const char *name, const uint8_t *b, int n) {
    printf("%s = ", name);
    for (int i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

/* RtcSdpOffer built by the live spec (protobuf):
 *   3 ice_ufrag="UFRAG1", 4 ice_password="PWD123456789012345678901234",
 *   5 fingerprint="sha-256 AB:CD:EF", 8 audio_ssrc=12345 */
static const uint8_t SDP_OFFER[] = {
    0x1a,0x06,0x55,0x46,0x52,0x41,0x47,0x31,
    0x22,0x1b,0x50,0x57,0x44,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,
    0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,
    0x2a,0x10,0x73,0x68,0x61,0x2d,0x32,0x35,0x36,0x20,0x41,0x42,0x3a,0x43,0x44,
    0x3a,0x45,0x46,
    0x40,0xb9,0x60 };

/* REAL controller offer captured from the device (research/live-cert-test/real-offer.bin),
 * the inner RtcSdpOffer of WebRtcSdpAndIceCandidates{sdp{type=SDP_OFFER, sdp_offer}}. */
static const uint8_t REAL_OFFER[] = {
    0x0a, 0x10, 0x31, 0x37, 0x39, 0x32, 0x36, 0x31, 0x32, 0x39, 0x39, 0x31,
    0x30, 0x37, 0x32, 0x30, 0x30, 0x30, 0x12, 0x10, 0x31, 0x37, 0x39, 0x32,
    0x36, 0x31, 0x32, 0x39, 0x39, 0x31, 0x30, 0x37, 0x32, 0x30, 0x30, 0x30,
    0x1a, 0x04, 0x48, 0x74, 0x46, 0x30, 0x22, 0x18, 0x42, 0x5a, 0x59, 0x31,
    0x53, 0x44, 0x68, 0x45, 0x41, 0x54, 0x48, 0x74, 0x6c, 0x44, 0x32, 0x34,
    0x6e, 0x2b, 0x76, 0x4f, 0x71, 0x74, 0x50, 0x77, 0x2a, 0x67, 0x73, 0x68,
    0x61, 0x2d, 0x32, 0x35, 0x36, 0x20, 0x32, 0x41, 0x3a, 0x31, 0x35, 0x3a,
    0x32, 0x44, 0x3a, 0x39, 0x42, 0x3a, 0x37, 0x36, 0x3a, 0x33, 0x32, 0x3a,
    0x32, 0x39, 0x3a, 0x46, 0x41, 0x3a, 0x33, 0x42, 0x3a, 0x38, 0x33, 0x3a,
    0x41, 0x33, 0x3a, 0x31, 0x30, 0x3a, 0x45, 0x31, 0x3a, 0x37, 0x44, 0x3a,
    0x34, 0x36, 0x3a, 0x39, 0x30, 0x3a, 0x43, 0x33, 0x3a, 0x37, 0x46, 0x3a,
    0x32, 0x37, 0x3a, 0x31, 0x32, 0x3a, 0x37, 0x31, 0x3a, 0x33, 0x30, 0x3a,
    0x34, 0x46, 0x3a, 0x42, 0x46, 0x3a, 0x39, 0x46, 0x3a, 0x36, 0x32, 0x3a,
    0x31, 0x42, 0x3a, 0x34, 0x39, 0x3a, 0x39, 0x35, 0x3a, 0x42, 0x46, 0x3a,
    0x44, 0x43, 0x3a, 0x43, 0x35, 0x3a, 0x2f, 0x08, 0x06, 0x12, 0x2b, 0x75,
    0x72, 0x6e, 0x3a, 0x69, 0x65, 0x74, 0x66, 0x3a, 0x70, 0x61, 0x72, 0x61,
    0x6d, 0x73, 0x3a, 0x72, 0x74, 0x70, 0x2d, 0x68, 0x64, 0x72, 0x65, 0x78,
    0x74, 0x3a, 0x73, 0x73, 0x72, 0x63, 0x2d, 0x61, 0x75, 0x64, 0x69, 0x6f,
    0x2d, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x40, 0xa5, 0xa5, 0xd6, 0xe4, 0x0a,
    0x52, 0x10, 0x31, 0x43, 0x6d, 0x71, 0x51, 0x46, 0x70, 0x74, 0x5a, 0x71,
    0x38, 0x6a, 0x69, 0x51, 0x69, 0x59, 0xa8, 0x01, 0x01, 0xb8, 0x01, 0x01,
};

/* REAL sdp_offer_bundle from a live controller: 0002-...RegisterController.bin,
 * discovery#4 (a serialized WebRtcSdpAndIceCandidates). */
static const uint8_t REAL_BUNDLE[] = {
    0x0a, 0x81, 0x02, 0x08, 0x01, 0x1a, 0xfc, 0x01, 0x0a, 0x10, 0x31, 0x37,
    0x39, 0x33, 0x35, 0x39, 0x39, 0x31, 0x34, 0x39, 0x30, 0x36, 0x39, 0x30,
    0x30, 0x30, 0x12, 0x10, 0x31, 0x37, 0x39, 0x33, 0x35, 0x39, 0x39, 0x31,
    0x34, 0x39, 0x30, 0x36, 0x39, 0x30, 0x30, 0x30, 0x1a, 0x04, 0x7a, 0x72,
    0x67, 0x47, 0x22, 0x18, 0x7a, 0x71, 0x39, 0x54, 0x71, 0x36, 0x62, 0x36,
    0x33, 0x53, 0x38, 0x73, 0x42, 0x4b, 0x30, 0x47, 0x77, 0x2b, 0x34, 0x4f,
    0x4d, 0x73, 0x39, 0x47, 0x2a, 0x67, 0x73, 0x68, 0x61, 0x2d, 0x32, 0x35,
    0x36, 0x20, 0x39, 0x39, 0x3a, 0x44, 0x43, 0x3a, 0x34, 0x43, 0x3a, 0x43,
    0x38, 0x3a, 0x36, 0x36, 0x3a, 0x34, 0x42, 0x3a, 0x35, 0x41, 0x3a, 0x32,
    0x44, 0x3a, 0x46, 0x44, 0x3a, 0x41, 0x38, 0x3a, 0x30, 0x36, 0x3a, 0x33,
    0x45, 0x3a, 0x43, 0x34, 0x3a, 0x43, 0x41, 0x3a, 0x39, 0x42, 0x3a, 0x33,
    0x32, 0x3a, 0x41, 0x31, 0x3a, 0x43, 0x45, 0x3a, 0x30, 0x33, 0x3a, 0x32,
    0x43, 0x3a, 0x41, 0x31, 0x3a, 0x37, 0x43, 0x3a, 0x32, 0x32, 0x3a, 0x39,
    0x30, 0x3a, 0x34, 0x34, 0x3a, 0x46, 0x39, 0x3a, 0x39, 0x41, 0x3a, 0x30,
    0x44, 0x3a, 0x34, 0x31, 0x3a, 0x44, 0x30, 0x3a, 0x33, 0x42, 0x3a, 0x31,
    0x46, 0x3a, 0x2f, 0x08, 0x06, 0x12, 0x2b, 0x75, 0x72, 0x6e, 0x3a, 0x69,
    0x65, 0x74, 0x66, 0x3a, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x3a, 0x72,
    0x74, 0x70, 0x2d, 0x68, 0x64, 0x72, 0x65, 0x78, 0x74, 0x3a, 0x73, 0x73,
    0x72, 0x63, 0x2d, 0x61, 0x75, 0x64, 0x69, 0x6f, 0x2d, 0x6c, 0x65, 0x76,
    0x65, 0x6c, 0x40, 0x95, 0x8a, 0xfb, 0xd7, 0x07, 0x52, 0x10, 0x4c, 0x6c,
    0x6c, 0x2b, 0x58, 0x78, 0x5a, 0x42, 0x56, 0x74, 0x43, 0x56, 0x32, 0x42,
    0x4f, 0x30, 0xa8, 0x01, 0x01, 0xb8, 0x01, 0x01, 0x12, 0x16, 0x08, 0x03,
    0x2a, 0x12, 0x2a, 0x0c, 0x31, 0x30, 0x2e, 0x36, 0x35, 0x2e, 0x35, 0x33,
    0x2e, 0x31, 0x33, 0x39, 0x30, 0x81, 0x80, 0x03, 0x12, 0x22, 0x08, 0x03,
    0x2a, 0x1e, 0x2a, 0x18, 0x66, 0x65, 0x38, 0x30, 0x3a, 0x3a, 0x66, 0x32,
    0x35, 0x63, 0x3a, 0x37, 0x37, 0x66, 0x66, 0x3a, 0x66, 0x65, 0x31, 0x38,
    0x3a, 0x66, 0x61, 0x31, 0x30, 0x81, 0x80, 0x03,
};

int main(void) {
    uint8_t buf[1024];
    pb_out_t o;

    /* IPv6 RA frame (p3-3050-ipv6ra): the SAME build_ipv6_ra() net_infra.c
     * transmits, asserted byte-for-byte by tests/check_ipv6_ra.py against an
     * independent construction (its own checksum implementation). Two MACs:
     * RA_A = a Pico 2 W production MAC shape, RA_B stresses the U/L-bit flip
     * (locally-administered source) and mixed bytes in EUI-64 + SLLA. */
    {
        static const uint8_t MAC_A[6] = { 0x28, 0xcd, 0xc1, 0x02, 0x03, 0x04 };
        static const uint8_t MAC_B[6] = { 0x02, 0xff, 0x00, 0xab, 0xcd, 0xef };
        uint8_t ra[IPV6_RA_FRAME_LEN];
        int n = build_ipv6_ra(ra, MAC_A);
        ph("RA_A", ra, n);
        n = build_ipv6_ra(ra, MAC_B);
        ph("RA_B", ra, n);
    }

    reg_resp_t r;
    memset(&r, 0, sizeof r);
    strcpy(r.registration_id, "REGID-1234");
    strcpy(r.registration_token, "REGTOKEN-5678");
    strcpy(r.display_id, "DISPLAY-ABCD");
    strcpy(r.display_token, "DTOKEN-EFGH");
    pbo_init(&o, buf, sizeof buf);
    build_register_controller_response(&o, &r);
    ph("R1_register_response", o.buf, o.len);

    uint8_t pl[2] = {0xDE, 0xAD};
    pbo_init(&o, buf, sizeof buf);
    build_rpc_response(&o, 0x1234, 0, pl, 2);
    ph("R2_rpc_response", o.buf, o.len);

    uint8_t pl2[2] = {0x01, 0x02};
    pbo_init(&o, buf, sizeof buf);
    build_rpc_request(&o, 1, pl2, 2);
    ph("R3_rpc_request", o.buf, o.len);

    pbo_init(&o, buf, sizeof buf);
    build_start_game(&o, "abc");
    ph("R4_start_game", o.buf, o.len);

    pbo_init(&o, buf, sizeof buf);
    build_get_controller_state_request(&o);
    ph("R5_state_request", o.buf, o.len);

    pbo_init(&o, buf, sizeof buf);
    build_current_time_response(&o, 111, 222);
    ph("R6_current_time", o.buf, o.len);

    pbo_init(&o, buf, sizeof buf);
    build_fwcheck_response(&o);
    ph("R7_fwcheck", o.buf, o.len);

    pbo_init(&o, buf, sizeof buf);
    build_discover_display_response(&o, "DISPLAY-ABCD", "DTOKEN-EFGH");
    ph("R8_discover_display", o.buf, o.len);

    sdp_offer_info_t inf;
    int rc = parse_rtc_sdp_offer(SDP_OFFER, (int)sizeof SDP_OFFER, &inf);
    printf("S1_sdp rc=%d ufrag=[%s] pwd=[%s] fp=[%s] ssrc=%u raw_dtls=%d delayed=%d\n",
           rc, inf.offer_ufrag, inf.offer_pwd, inf.offer_fp,
           (unsigned)inf.audio_ssrc, inf.raw_dtls, inf.delayed_acks);

    /* R10: rumble message for id=7,left=1000,right=2000,seq=5,base_ts=123456 - built by
     * proto.c build_rumble_series(), the SAME constructor rtc.c rumble_flush() uses
     * (p3-2710; this used to be an inline replica, which is exactly how the 27 B
     * truncated start frame passed a green host test). Must equal the live spec's
     * InputProtocolMessage:
     *   3a16100518c0c407220e2000520a0a08080710e80718d00f
     * NOTE: series.messages[] holds the InputMessageSlim ITSELF. The old code inserted an
     * extra {1: slim} wrapper, which a parser reads as slim.gamepad_message (V1). */
    {
        pbo_init(&o, buf, sizeof buf);
        build_rumble_series(&o, 7, 1000, 2000, 5, 123456, NULL, 0);
        ph("R10_rumble", o.buf, o.len);
    }

    /* R15: rumble series built by proto.c build_rumble_series() - the firmware's OWN
     * constructor since p3-2710 - compared by tests/check_rumble.py against
     * stadiacast's send_vibration for the SAME pinned values - including
     * base_timestamp_us in the epoch-microsecond domain (rumble_wall_us(); the live
     * e4 registration ran at t_us=1793597554953620, which is what BASE pins) and the
     * session_id echo (InputMessageSeries f1, a STRING - echoed whatever the
     * controller announced). Values mirror the live 2026-11-02 13:33 session: id=1,
     * 49151/49151 (75%), _feedback_seq 1,2,3 (rumble_seq starts at 0 since p3-2550).
     * The WH2 forms go through proto.c wh2_wrap() - the same function rtc.c
     * wh2_send() frames with on the device. */
    {
    #define R15_BASE 1793597554953620ULL
        struct r15 { uint32_t id, l, r, seq; const char *sid; };
        struct r15 vecs[3] = {
            { 1, 49151, 49151, 1, NULL },                 /* start frame (75%) */
            { 1, 0, 0, 2, NULL },                          /* explicit 0/0 stop frame */
            { 1, 49151, 49151, 3, "sid-1234567890abcdef" },/* session_id echo (20 B) */
        };
        static const char *names[3] = { "R15_START", "R15_STOP", "R15_SID" };
        int ovf_all = g_pb_overflow;   /* baseline for R16_OVERFLOW: covers the R15+R16 builds */
        for (int i = 0; i < 3; i++) {
            pbo_init(&o, buf, sizeof buf);
            build_rumble_series(&o, vecs[i].id, vecs[i].l, vecs[i].r, vecs[i].seq, R15_BASE,
                                (const uint8_t *)vecs[i].sid,
                                vecs[i].sid ? (int)strlen(vecs[i].sid) : 0);
            ph(names[i], o.buf, o.len);
            if (i == 0 || i == 1) {
                /* the raw-framing wire form: WireHeader2(0x66) + payload, byte for
                 * byte as wh2_send(&Lg, WID_INPUT, ...) writes it on the GF_RAW path */
                uint8_t fr[192];
                int total = wh2_wrap(fr, (int)sizeof fr, 0x66, o.buf, o.len);
                ph(i == 0 ? "R15_WH2_START" : "R15_WH2_STOP", fr, total);
            }
        }

        /* R16: the LEARNING half of the rumble path (p3-2710) + truncation tripwires.
         * R16_REG_LEARN feeds the REAL controller registration series captured on the
         * device (pico-log-20261105-010051.txt, gameframe n=35: 3a19 1001 18<ts> 220c
         * 2000 2a08 0801 800101 880102 - series = f2+f3+f4 ONLY, no f1) through
         * learn_series_session(): the learned echo is EMPTY, which is the live
         * baseline - ota.282115 announces no session_id, and the reference's
         * send_vibration (`if session_id:`) also omits the echo. `sid=0` on the real
         * device is correct behaviour, not a learning failure.
         * R16_SID_CHAIN feeds a synthetic f1-carrying series, learns the 20-byte id
         * and builds the series through the same constructor rumble_flush() calls -
         * must equal R15_SID byte for byte.
         * R16_MAX stresses every buffer with maximal varints + a 64 B session echo;
         * R16_OVERFLOW pins g_pb_overflow: any pbo_raw drop anywhere above (the
         * 2026-11-05 truncation left no other trace) fails the oracle. */
        {
            static const uint8_t REG_SERIES[25] = {
                0x10, 0x01,                                   /* f2 sequence_number = 1 */
                0x18, 0x94, 0xdb, 0xf7, 0x90, 0xc2, 0xbc, 0x98, 0x03, /* f3 base_ts */
                0x22, 0x0c,                                   /* f4 messages, 12 B */
                0x20, 0x00,                                   /*   slim f4 relative_time_us = 0 */
                0x2a, 0x08, 0x08, 0x01, 0x80, 0x01, 0x01, 0x88, 0x01, 0x02 /* f5 gamepad_v2 */
            };
            uint8_t sidbuf[64];
            int rl = learn_series_session(REG_SERIES, (int)sizeof REG_SERIES,
                                          sidbuf, (int)sizeof sidbuf);
            ph("R16_REG_LEARN", sidbuf, rl);      /* empty: no f1 in ota.282115's series */

            /* synthetic controller series WITH f1: learn -> echo through the shared ctor.
             * (pbo_init cap is the ARRAY size `sizeof sbody` - writing `sizeof sb` here
             * reproduced the p3-2710 device bug on the host in miniature: the 20 B sid
             * dropped after its `0a 12` prefix, the parser then failed the length check
             * and learn returned 0 - which R16_LEARNED_SID/R16_SID_CHAIN caught.) */
            uint8_t sbody[96]; pb_out_t sb; pbo_init(&sb, sbody, sizeof sbody);
            pbo_str(&sb, 1, "sid-1234567890abcdef");
            pbo_u64(&sb, 2, 99);
            uint8_t slim0[4]; pb_out_t s0; pbo_init(&s0, slim0, sizeof slim0);
            pbo_u64(&s0, 4, 0);
            pbo_msg(&sb, 4, &s0);
            int ll = learn_series_session(sbody, sb.len, sidbuf, (int)sizeof sidbuf);
            ph("R16_LEARNED_SID", sidbuf, ll);    /* the 20 B echo */
            pbo_init(&o, buf, sizeof buf);
            build_rumble_series(&o, 1, 49151, 49151, 3, R15_BASE, sidbuf, ll);
            ph("R16_SID_CHAIN", o.buf, o.len);    /* == R15_SID */

            /* worst-case occupancy: 5-byte varints everywhere + the 64 B echo cap
             * (MAX_SID in check_rumble.py: a printable string, because protobuf
             * string fields reject raw non-UTF-8 in the dynamic oracle) */
            static const uint8_t maxsid[64] = "sid-max-"
                "xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                "xxxxxxxxxxxxxxxxxxxxxxxxxxxx";
            pbo_init(&o, buf, sizeof buf);
            build_rumble_series(&o, 0xFFFFFFFFu, 0xFFFFu, 0xFFFFu, 0xFFFFFFFFu, R15_BASE,
                                maxsid, (int)sizeof maxsid);
            ph("R16_MAX", o.buf, o.len);
            printf("R16_OVERFLOW = %02x\n", g_pb_overflow - ovf_all);
        }
    #undef R15_BASE
    }

    /* R11: SDP answer bundle. Reference from the live spec's signaling.build_answer +
     * candidate_message + bundle (id/creds/ip/port as below; answer fields in
     * field-number order 1,2,3,12,13,14,15 for a zeroed offer - no 8/9/10/11/17).
     * f14 build_number "stadia-local-receiver/0.1.0" added in p3-0355 (signaling.py:119,
     * SERVER_NAME/__version__ = __init__.py:11/7):
     *   0a59080222550a0655465241473112166162636465666768696a6b6c6d6e6f707172737475761a107368612d3235362041423a43443a454660016801721b7374616469612d6c6f63616c2d72656365697665722f302e312e307801122308032a1f0a01301a013120fffffff7072a0d3139322e3136382e3133372e3130c0b802
     * The firmware output below differs from this reference in exactly ONE field:
     * sdp_mid "data" (live-sample value, kept - D6) instead of the reference "0".
     * Checks: type=SDP_ANSWER with field 4 (sdp_answer, NOT 3), the candidate wrapped
     * as WebRtcSdp{type=ICE_CANDIDATE, 5: ice_candidate}, and the disable_game_stats /
     * disable_frame_tokens / network_type flags at 12/13/15 + build_number at 14. */
    {
        sdp_offer_info_t inf;
        memset(&inf, 0, sizeof inf);
        rtc_creds_t creds;
        memset(&creds, 0, sizeof creds);
        strcpy(creds.ufrag, "UFRAG1");
        strcpy(creds.pwd, "abcdefghijklmnopqrstuv");
        strcpy(creds.fingerprint, "sha-256 AB:CD:EF");
        uint8_t bundleB[512]; pb_out_t bnd; pbo_init(&bnd, bundleB, sizeof bundleB);
        build_sdp_answer_bundle(&bnd, &inf, &creds, "192.168.137.1", 40000);
        ph("R11_sdp_bundle", bnd.buf, bnd.len);

        uint8_t cB[128]; pb_out_t cb; pbo_init(&cb, cB, sizeof cB);
        build_rtc_ice_candidate(&cb, "192.168.137.1", 40000);
        ph("R11b_candidate", cb.buf, cb.len);
    }

    /* R12: GMsg envelope carrying a payload (this is how the SDP answer reaches the
     * controller). Reference from the live spec's Protos.gmsg_envelope(payload=deadbeef,
     * msg_id=7):
     *   0a100807102ac28ef48208060a04deadbeef */
    {
        uint8_t pl12[4] = {0xDE, 0xAD, 0xBE, 0xEF};
        uint8_t gB[128]; pb_out_t gb; pbo_init(&gb, gB, sizeof gB);
        build_gmsg_envelope(&gb, 7, pl12, 4);
        ph("R12_gmsg", gb.buf, gb.len);
    }

    /* R13: parse a REAL controller offer captured live. Expected (from protobuf):
     *   ufrag=HtF0  pwd=BZY1SDhEATHtlD24n+vOqtPw
     *   fp=sha-256 2A:15:2D:9B:...  audio_ssrc=2895483557
     *   raw_dtls=1  delayed_acks=1  use_rtp_timestamps absent  (no video/audio format) */
    {
        sdp_offer_info_t ri;
        int rrc = parse_rtc_sdp_offer(REAL_OFFER, (int)sizeof REAL_OFFER, &ri);
        printf("R13_real_offer rc=%d ufrag=[%s] pwd=[%s] ssrc=%u raw=%d dly=%d rtpts=%d vfmt=%d afmt=%d\n",
               rrc, ri.offer_ufrag, ri.offer_pwd, (unsigned)ri.audio_ssrc,
               ri.raw_dtls, ri.delayed_acks, ri.use_rtp_timestamps,
               ri.video_format_len, ri.audio_format_len);
        printf("R13_fp=[%s]\n", ri.offer_fp);
    }

    /* R14: END-TO-END on a REAL captured sdp_offer_bundle (320 B). This is the exact
     * blob a live controller puts in RegisterControllerRequest.discovery#4.
     * Expected: ufrag=zrgG pwd=zq9Tq6b63S8sBK0Gw+4OMs9G ssrc=2063516949 raw=1 dly=1.
     * The old code read bundle#1#2 (sdp.raw_value) and found nothing. */
    {
        const uint8_t *off = NULL; int ol = 0;
        int found = find_sdp_offer(REAL_BUNDLE, (int)sizeof REAL_BUNDLE, &off, &ol);
        sdp_offer_info_t bi;
        int brc = (found && ol > 0) ? parse_rtc_sdp_offer(off, ol, &bi) : -1;
        printf("R14_bundle found=%d offer_len=%d rc=%d ufrag=[%s] pwd=[%s] ssrc=%u raw=%d dly=%d\n",
               found, ol, brc, bi.offer_ufrag, bi.offer_pwd,
               (unsigned)bi.audio_ssrc, bi.raw_dtls, bi.delayed_acks);
        printf("R14_fp=[%s]\n", bi.offer_fp);
    }

    /* Oracle diff vectors (compared by tests/oracle_rpc.py against the live spec
     * stadiacast). The wrapping is replicated inline because rtc.c is not
     * compiled here: rpc_request_dtc() (rtc.c:415) puts the inner message in
     * DisplayToController{field}, build_rpc_request() produces
     * RpcMessage{1: RpcRequest{1: ticket, 2: payload}}, and wh2_send()
     * (rtc.c:369) prefixes the 8-byte WireHeader2 (id 0x75 = display->controller
     * RPC: byte0=0, byte1=0, bytes2-3 id LE, bytes4-6 total len incl header LE24,
     * byte7=0). Field numbers 2 / 8 = DTC_STATE_REQ / DTC_START_GAME (config.h). */
    {
        uint8_t inner[256], dtc[512];
        pb_out_t io, d;

        /* ticket 1 (first outbound request, D5 alignment): GetControllerStateRequest chain */
        pbo_init(&io, inner, sizeof inner);
        build_get_controller_state_request(&io);
        pbo_init(&d, dtc, sizeof dtc);
        pbo_bytes(&d, 2, io.buf, io.len);          /* DTC_STATE_REQ = 2 */
        uint8_t msgA[768]; pb_out_t ma; pbo_init(&ma, msgA, sizeof msgA);
        build_rpc_request(&ma, 1, d.buf, d.len);
        ph("RPC_GCSR", ma.buf, ma.len);

        /* ticket 2 (next outbound request): StartGame chain */
        pbo_init(&io, inner, sizeof inner);
        build_start_game(&io, "pico");
        pbo_init(&d, dtc, sizeof dtc);
        pbo_bytes(&d, 8, io.buf, io.len);          /* DTC_START_GAME = 8 */
        uint8_t msgB[768]; pb_out_t mb; pbo_init(&mb, msgB, sizeof msgB);
        build_rpc_request(&mb, 2, d.buf, d.len);
        ph("RPC_STARTGAME", mb.buf, mb.len);

        /* WireHeader2(0x75) frame around RPC_GCSR, byte-for-byte as wh2_send() */
        uint8_t frame[780];
        int total = 8 + ma.len;
        frame[0] = 0; frame[1] = 0;
        frame[2] = (uint8_t)0x75; frame[3] = (uint8_t)(0x75 >> 8);
        frame[4] = (uint8_t)total; frame[5] = (uint8_t)(total >> 8); frame[6] = (uint8_t)(total >> 16);
        frame[7] = 0;
        memcpy(frame + 8, ma.buf, ma.len);
        ph("WH2_GCSR", frame, total);

        /* WireHeader2(0x75) frame around RPC_STARTGAME, same as wh2_send() */
        uint8_t frameB[780];
        int totalB = 8 + mb.len;
        frameB[0] = 0; frameB[1] = 0;
        frameB[2] = (uint8_t)0x75; frameB[3] = (uint8_t)(0x75 >> 8);
        frameB[4] = (uint8_t)totalB; frameB[5] = (uint8_t)(totalB >> 8); frameB[6] = (uint8_t)(totalB >> 16);
        frameB[7] = 0;
        memcpy(frameB + 8, mb.buf, mb.len);
        ph("WH2_STARTGAME", frameB, totalB);

        /* Keepalive heartbeat reply: exactly the wire body of rtc.c:519
         * rpc_respond_display(ticket, ST_OK, NULL, 0), i.e. build_rpc_response()
         * with code=0 and no payload (proto.c:174 skips code when 0 and payload
         * when empty). The live reference's keepalive reply (controller.py
         * _answer_request -> send_rpc("response", None) -> p.rpc_response(ticket,
         * code=0, message="")) ALSO serializes code=0 and error_message="" --
         * proto2 optional fields set to their default are still emitted. */
        pbo_init(&o, buf, sizeof buf);
        build_rpc_response(&o, 77, 0, NULL, 0);
        ph("RPC_HEARTBEAT_RESP", o.buf, o.len);

        /* GetCurrentTimeResponse with 64-bit edge values: field 2 has the sign
         * bit set (as uint64 0x99AABBCCDDEEFF00), so its varint is 10 bytes.
         * The oracle builds the same message via stadiacast's DisplayToController
         * .current_time (field 21, config.h DTC_TIME_RESP) with the int64 read
         * as the negative two's-complement value. */
        pbo_init(&o, buf, sizeof buf);
        build_current_time_response(&o, 0x1122334455667788ULL, 0x99AABBCCDDEEFF00ULL);
        ph("TIME_RESP", o.buf, o.len);
    }
    return 0;
}
