// rtc.c — STUN + DTLS servers (display :40000, game :40001) + WireHeader2 RPC +
// game input decode + rumble encode. Controller is the DTLS client on both links.
#include "rtc.h"
#include "config.h"
#include "cloud.h"
#include "certs.h"
#include "proto.h"
#include "pb.h"
#include "net_infra.h"
#include "usb_hid.h"
#include "pico/stdlib.h"
#include "pico/rand.h"
#include "hardware/sync.h"     // save_and_disable_interrupts: rumble state vs HID-IRQ writer
#include <string.h>
#include <stdio.h>

#include "mbedtls/ssl.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"
#include "mbedtls/x509.h"
#include "mbedtls/pk.h"
#include "mbedtls/pem.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "lwip/udp.h"
#include "timing_alt.h"
#include "tone_frames.h"
#include "usb_audio.h"
#include "ipc.h"

volatile pad_state_t pad;
volatile bool pad_fresh;
volatile uint32_t input_seq_seen;

extern const unsigned char TLS_CERT_PEM[]; extern const unsigned int TLS_CERT_PEM_len;
extern const unsigned char TLS_KEY_PEM[];  extern const unsigned int TLS_KEY_PEM_len;

// A clock value that is guaranteed to be inside the server certificate's validity
// window. The SNTP server used to hand out a hard-coded 2025-01-01 epoch while the
// leaf certificate is valid 2026-10 -> 2027-01, so the controller (whose clock comes
// only from us) would consider our certificate "not yet valid" and every HTTPS/TLS
// connection would fail. Derive it from the certificate itself so renewal is automatic.
static uint32_t cert_time_epoch;
int rtc_cert_rc = 999, rtc_key_rc = 999;   // mbedtls parse results (999 = not run)

// days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm)
static int64_t days_from_civil(int y, unsigned m, unsigned d) {
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = (unsigned)(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? (unsigned)-3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int64_t)doe - 719468;
}
static int64_t civil_epoch(const mbedtls_x509_time *t) {
    return days_from_civil(t->year, (unsigned)t->mon, (unsigned)t->day) * 86400
         + t->hour * 3600 + t->min * 60 + t->sec;
}
uint32_t rtc_cert_time_epoch(void) { return cert_time_epoch ? cert_time_epoch : 1790000000u; }

static mbedtls_x509_crt chain;
static mbedtls_x509_crt chain_leaf;   // DTLS: ECDSA P-256 cert (fingerprint-pinned)
static mbedtls_pk_context pkey_leaf;
static mbedtls_pk_context pkey;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;

// ------------------------------------------------------------------ stun
// RFC 5389 FINGERPRINT uses the standard IEEE CRC-32 (zlib.crc32), NOT CRC-32C.
// The reference implementation (stadiacast/rtc/stun.py) calls zlib.crc32, and the
// polynomial below is the reflected 0xEDB88320 that zlib uses.
static uint32_t crc32_ieee(const uint8_t *d, int n) {
    uint32_t c = 0xffffffff;
    for (int i = 0; i < n; i++) { c ^= d[i];
        for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1))); }
    return c ^ 0xffffffff;
}

// Verified against pc-peer.cjs (live-tested): response = 0x0101, XOR-MAPPED, MI, FP.
static int stun_make_response(uint8_t *out, const uint8_t *req, int rlen,
                              const ip4_addr_t *src_ip, uint16_t src_port, const char *pwd) {
    // attributes area starts at 20; body excludes header
    uint8_t *a = out + 20;
    int alen = 0;
    // XOR-MAPPED-ADDRESS 0x0020
    a[0]=0; a[1]=0x20; a[2]=0; a[3]=8;
    a[4]=0; a[5]=1;
    a[6]=(uint8_t)((src_port >> 8) ^ 0x21); a[7]=(uint8_t)((src_port & 0xff) ^ 0x12);
    const uint8_t *ip = (const uint8_t *)&src_ip->addr;       // network order bytes
    a[8]=ip[0]^0x21; a[9]=ip[1]^0x12; a[10]=ip[2]^0xA4; a[11]=ip[3]^0x42;
    alen += 12;
    // header  (STUN length field = total size MINUS the 20-byte header)
    out[0]=0x01; out[1]=0x01;
    memcpy(out+4, req+4, 16);
    // MESSAGE-INTEGRITY 0x0008 (RFC 5389 §15.4):
    //  - the header length field must be adjusted to point PAST the MI attribute
    //  - the HMAC input is the message up to but NOT including the MI attribute
    // The previous code wrote 20+alen+24 (i.e. the TOTAL size) into the length field,
    // which is 20 too large, and hashed 20+alen+4 bytes (including the MI attribute
    // header) instead of 20+alen. Either mistake makes the peer's HMAC/length check fail.
    int len_with_mi = alen + 24;
    out[2]=(uint8_t)(len_with_mi>>8); out[3]=(uint8_t)(len_with_mi&0xff);
    a[alen]=0; a[alen+1]=8; a[alen+2]=0; a[alen+3]=20; // attr header, 20B hmac
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    mbedtls_md_hmac(md, (const unsigned char*)pwd, strlen(pwd), out, 20+alen, a+alen+4);
    alen += 24;
    // FINGERPRINT 0x8028 (RFC 5389 §15.5): length field now includes the FP attribute,
    // CRC32C is computed over everything BEFORE the FP attribute, XOR 0x53545542, big-endian.
    int len_with_fp = alen + 8;
    out[2]=(uint8_t)(len_with_fp>>8); out[3]=(uint8_t)(len_with_fp&0xff);
    uint32_t crc = crc32_ieee(out, 20+alen) ^ 0x5354554Eu;
    a[alen]=0x80; a[alen+1]=0x28; a[alen+2]=0; a[alen+3]=4;
    a[alen+4]=(uint8_t)(crc>>24); a[alen+5]=(uint8_t)(crc>>16);
    a[alen+6]=(uint8_t)(crc>>8);  a[alen+7]=(uint8_t)crc;
    return 20 + alen + 8;
}


// RFC 5245 / 5389 ICE connectivity check (binding REQUEST), built the way the
// live-verified reference does (pc-peer.cjs:831-847):
//   USERNAME = "<remote ufrag>:<local ufrag>"  (sender's view)
//   PRIORITY = 4-byte value 1, USE-CANDIDATE = empty
//   MESSAGE-INTEGRITY keyed with OUR password, then FINGERPRINT.
// rtc_tick()'s header comment has always promised "fast ICE checks" but nothing ever
// sent one; on the proven chain the controller's DTLS ClientHello FOLLOWS our check
// (ice_fast_checks = 1 s), so without this the handshake may never start.
static int stun_make_request(uint8_t *out, const char *remote_ufrag, const char *local_ufrag,
                             const char *pwd, const uint8_t txn12[12]) {
    uint8_t *a = out + 20;
    int alen = 0;
    char uname[64];
    snprintf(uname, sizeof uname, "%s:%s", remote_ufrag, local_ufrag);
    int ul = (int)strlen(uname);
    int upad = (ul + 3) & ~3;
    a[0]=0; a[1]=0x06; a[2]=(uint8_t)(ul>>8); a[3]=(uint8_t)ul;
    memcpy(a+4, uname, (size_t)ul);
    for (int i = ul; i < upad; i++) a[4+i] = 0;
    alen += 4 + upad;
    // PRIORITY must be the host-candidate priority 2130706431, exactly as the reference
    // (endpoint.py:264 struct.pack("!I", HOST_CANDIDATE_PRIORITY)); we had 1.
    a[alen]=0; a[alen+1]=0x24; a[alen+2]=0; a[alen+3]=4;
    a[alen+4]=0x7E; a[alen+5]=0xFF; a[alen+6]=0xFF; a[alen+7]=0xFF;
    alen += 8;
    // We are the ANSWERER, so we are the ICE CONTROLLED agent: the reference emits
    // ATTR_ICE_CONTROLLED (0x8029) with an 8-byte tiebreaker and does NOT set
    // USE-CANDIDATE (that is the controlling agent's job).
    {
        static uint8_t tie[8]; static bool tie_init;
        if (!tie_init) { for (int i = 0; i < 8; i++) tie[i] = (uint8_t)(get_rand_32() >> ((i & 3) * 8)); tie_init = true; }
        a[alen]=0x80; a[alen+1]=0x29; a[alen+2]=0; a[alen+3]=8;
        memcpy(a + alen + 4, tie, 8);
        alen += 12;
    }
    out[0]=0x00; out[1]=0x01;
    out[4]=0x21; out[5]=0x12; out[6]=0xA4; out[7]=0x42;
    memcpy(out+8, txn12, 12);
    int len_with_mi = alen + 24;
    out[2]=(uint8_t)(len_with_mi>>8); out[3]=(uint8_t)(len_with_mi&0xff);
    a[alen]=0; a[alen+1]=8; a[alen+2]=0; a[alen+3]=20;
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    mbedtls_md_hmac(md, (const unsigned char*)pwd, strlen(pwd), out, 20+alen, a+alen+4);
    alen += 24;
    int len_with_fp = alen + 8;
    out[2]=(uint8_t)(len_with_fp>>8); out[3]=(uint8_t)(len_with_fp&0xff);
    uint32_t crc = crc32_ieee(out, 20+alen) ^ 0x5354554Eu;
    a[alen]=0x80; a[alen+1]=0x28; a[alen+2]=0; a[alen+3]=4;
    a[alen+4]=(uint8_t)(crc>>24); a[alen+5]=(uint8_t)(crc>>16);
    a[alen+6]=(uint8_t)(crc>>8);  a[alen+7]=(uint8_t)crc;
    return 20 + alen + 8;
}

// ---------------------------------------------------------- STUN self-test// Vector produced by the LIVE-VERIFIED Python implementation (stadiacast/rtc/stun.py,
// which uses zlib.crc32 and XOR 0x5354554E). The previous expected values were wrong in
// exactly the same way as the firmware, so the self-test validated the bug. Inputs: binding request with txn-id 0x11..0x1C, source 192.168.137.30:54321,
// password "abcdefghijklmnop".
static const uint8_t STUN_TEST_REQ[] = {
    0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c };
static const uint8_t STUN_TEST_EXP[] = {
    0x01, 0x01, 0x00, 0x2c, 0x21, 0x12, 0xa4, 0x42, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x00, 0x20, 0x00, 0x08,
    0x00, 0x01, 0xf5, 0x23, 0xe1, 0xba, 0x2d, 0x5c, 0x00, 0x08, 0x00, 0x14,
    0x6b, 0x5d, 0x05, 0xc8, 0x5a, 0x11, 0x58, 0x56, 0xf8, 0x92, 0xb8, 0xa3,
    0xd1, 0xb1, 0xac, 0xe5, 0xfc, 0x05, 0x7e, 0xe5, 0x80, 0x28, 0x00, 0x04,
    0x79, 0x1f, 0xcb, 0x30 };

static void stun_selftest(void) {
    uint8_t out[96];
    ip4_addr_t ip; IP4_ADDR(&ip, 192, 168, 137, 30);
    int n = stun_make_response(out, STUN_TEST_REQ, (int)sizeof STUN_TEST_REQ,
                               &ip, 54321, "abcdefghijklmnop");
    bool ok = (n == (int)sizeof STUN_TEST_EXP) &&
              memcmp(out, STUN_TEST_EXP, sizeof STUN_TEST_EXP) == 0;
    FWLOG("stun_selftest=%s len=%d", ok ? "PASS" : "FAIL", n);
    if (!ok) {
        char hx[200]; int o = 0;
        for (int i = 0; i < n && o < 190; i++) o += snprintf(hx + o, sizeof hx - o, "%02x", out[i]);
        hx[o] = 0;
        FWLOG("stun_got=%s", hx);
    }
    // Second vector: the ICE connectivity REQUEST we now send. Reference produced by an
    // independent RFC 5389 implementation (research/tmp/stun_req_ref.py) for
    //   USERNAME="zrgG:OUFR", PRIORITY=1, USE-CANDIDATE, pwd="abcdefghijklmnop",
    //   transaction id 0x11..0x1c.
    static const uint8_t STUN_REQ_EXP[] = {
        0x00, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42, 0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x00, 0x06, 0x00, 0x09,
        0x7a, 0x72, 0x67, 0x47, 0x3a, 0x4f, 0x55, 0x46, 0x52, 0x00, 0x00, 0x00,
        0x00, 0x24, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x25, 0x00, 0x00,
        0x00, 0x08, 0x00, 0x14, 0xbf, 0xbd, 0x61, 0xd7, 0x8b, 0x54, 0x19, 0xee,
        0x61, 0x07, 0x8c, 0xfb, 0x44, 0x3c, 0x7f, 0xe2, 0x04, 0x31, 0x51, 0x1b,
        0x80, 0x28, 0x00, 0x04, 0x28, 0xa3, 0xc6, 0x81 };
    static const uint8_t txn12[12] = {0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c};
    uint8_t rq[160];
    int rn = stun_make_request(rq, "zrgG", "OUFR", "abcdefghijklmnop", txn12);
    bool rok = (rn == (int)sizeof STUN_REQ_EXP) && memcmp(rq, STUN_REQ_EXP, sizeof STUN_REQ_EXP) == 0;
    FWLOG("stun_req_selftest=%s len=%d", rok ? "PASS" : "FAIL", rn);
    if (!rok) {
        char hx[200]; int o2 = 0;
        for (int i = 0; i < rn && o2 < 190; i++) o2 += snprintf(hx + o2, sizeof hx - o2, "%02x", rq[i]);
        hx[o2] = 0;
        FWLOG("stun_req_got=%s", hx);
    }
}

// ------------------------------------------------------------------ dtls link
typedef struct {
    const char *name; uint16_t port;
    struct udp_pcb *pcb;
    const char *our_pwd;
    ip4_addr_t peer; uint16_t peer_port; bool have_peer;
    mbedtls_ssl_context ssl; mbedtls_ssl_config conf;
    mbedtls_timing_delay_context timers;
    bool up; bool handshake_done;
    // Outbound DTLS record buffer.
    //
    // mbedtls 2.28 does NOT fragment DTLS handshake messages by the configured MTU
    // (ssl_msg.c:2493 "We deliberately do not check for the MTU or MFL here"); the whole
    // Certificate message is emitted as one record with frag_offset=0. Our chain is
    // ~4.1 KiB DER, so the record is ~4.2 KiB - far beyond the old 2048-byte buffer, and
    // bio_send would refuse it, killing the handshake. Size for the full chain.
    uint8_t pkt[8192]; int pkt_len;
    uint8_t rx[4096]; int rx_len;        // inbound datagram (BIO recv source)
    // The final flight (CCS+Finished) must be retransmitted when the client re-sends its
    // last flight: DTLS servers keep it buffered for exactly that (OpenSSL, which the
    // verified reference uses, does this in dtls1_retransmit_buffered_messages).
    // mbedtls 2.28 never resends after the handshake is over, so a single lost final
    // flight kills the whole session: the controller retransmits flight2, we ignore it,
    // it times out and alerts out (PLAYBOOK 9.97, every session 2026-11-03).
    uint8_t final_[192]; int final_len;
    // DTLS-SRTP exporter material, captured by the export-keys callback when the
    // handshake derives its keys (ssl_tls.c mbedtls_ssl_derive_keys -> f_export_keys_ext).
    // Only the display link (Ld) fills these: that is where speaker audio rides.
    bool exp_valid; mbedtls_tls_prf_types exp_prf;
    uint8_t exp_ms[48], exp_cr[32], exp_sr[32];
} link_t;

static int dtls_bio_recv(void *ctx, unsigned char *buf, size_t len) {
    link_t *L = (link_t *)ctx;
    if (L->rx_len <= 0) return MBEDTLS_ERR_SSL_WANT_READ;
    int n = (int)len < L->rx_len ? (int)len : L->rx_len;
    memcpy(buf, L->rx, (size_t)n);
    memmove(L->rx, L->rx + n, (size_t)(L->rx_len - n));
    L->rx_len -= n;
    return n;
}


static link_t Ld, Lg;

// game offer captured from the StartGame ProxyRequest
static sdp_offer_info_t game_offer;

static void udp_send_link(link_t *L, const uint8_t *b, int n) {
    // Every one of these used to be a silent failure. A dropped DTLS flight looks
    // exactly like "the peer never answers", so make each failure visible.
    if (!L->have_peer) { FWLOG("dtls %s: DROP %d bytes - no peer yet", L->name, n); return; }
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, n, PBUF_RAM);
    if (!p) { FWLOG("dtls %s: pbuf_alloc(%d) failed - out of RAM", L->name, n); return; }
    memcpy(p->payload, b, n);
    err_t e = udp_sendto(L->pcb, p, &L->peer, L->peer_port);
    if (e != ERR_OK) FWLOG("dtls %s: udp_sendto err=%d len=%d", L->name, (int)e, n);
    pbuf_free(p);
}

// mbedtls debug sink: the reason a DTLS handshake is refused ("no matching cipher
// suite", "bad version", ...) is only visible through this hook.
static void dtls_dbg_cb(void *ctx, int level, const char *file, int line, const char *s) {
    (void)ctx; (void)file; (void)line;
    if (level > 2) return;
    static int budget;
    if (budget > 120) return;
    budget++;
    FWLOG("mtls%d %s", level, s);
}

// Export-keys callback (MBEDTLS_SSL_EXPORT_KEYS, ssl_tls.c mbedtls_ssl_derive_keys):
// hands us the master secret, both handshake randoms and the negotiated PRF the moment
// the handshake derives its keys. That is everything the RFC 5705 DTLS-SRTP exporter
// needs ("EXTRACTOR-dtls_srtp", exactly how stadiacast dtls.py export_srtp_keys gets its
// material from pyOpenSSL). Fired per handshake attempt; the tone sender only trusts it
// once Ld.handshake_done is also true, and every session reset clears both.
static int dtls_export_keys_cb(void *ctx, const unsigned char *ms, const unsigned char *kb,
                               size_t maclen, size_t keylen, size_t ivlen,
                               const unsigned char client_random[32],
                               const unsigned char server_random[32],
                               mbedtls_tls_prf_types prf) {
    (void)kb; (void)maclen; (void)keylen; (void)ivlen;
    link_t *L = (link_t *)ctx;
    if (L != &Ld) return 0;              // speaker audio rides the display link only
    memcpy(L->exp_ms, ms, 48);
    memcpy(L->exp_cr, client_random, 32);
    memcpy(L->exp_sr, server_random, 32);
    L->exp_prf = prf;
    L->exp_valid = true;
    return 0;
}

static void dtls_drive(link_t *L);

// Display-RPC gating state (see the display RPC section below for the rationale).
static bool disp_rpc_armed;         // v1:ResolveDiscovery served (or fallback fired)
static uint32_t disp_rpc_arm_ms;    // when armed (ms since boot)
static uint32_t disp_rpc_hs_ms;     // when Ld.handshake_done turned true (fallback base)
static bool state_req_sent;         // the first GetControllerStateRequest went out
static uint32_t last_state_req_ms;  // ms since boot of the last GetControllerStateRequest
static void disp_rpc_reset(void);
static void audio_session_reset(void);   // display session died: drop SRTP keys/attach/tone

// ---- forward decls for the protocol layer ----
static void on_display_frame(uint8_t *f, int n);
static void on_game_frame(uint8_t *f, int n);


// Feed one datagram, drive handshake/appdata, flush outbound records.
static void dtls_drive(link_t *L) {
    int r;
    // Bounded: this loop used to be able to spin forever. mbedtls can keep returning
    // WANT_WRITE with nothing buffered (pkt_len == 0), and the only exit condition was
    // WANT_READ with an empty rx queue - so a controller starting a DTLS handshake could
    // wedge the whole main loop, which also kills USB servicing (the CDC port then
    // refuses to open). Cap the work per call and resume on the next poll.
    int guard = 0;
    static uint32_t lastlog; static int logcnt;
    while ((r = mbedtls_ssl_handshake(&L->ssl)) == MBEDTLS_ERR_SSL_WANT_READ ||
           r == MBEDTLS_ERR_SSL_WANT_WRITE) {
        if (L->pkt_len) {
            if (logcnt < 12) FWLOG("dtls %s: flight out %d bytes", L->name, L->pkt_len);
            udp_send_link(L, L->pkt, L->pkt_len); L->pkt_len = 0;
        }
        {   // Progress must be logged HERE: the normal WANT_READ path returns below,
            // so anything after the loop never runs while waiting for the peer.
            uint32_t now = to_ms_since_boot(get_absolute_time());
            if (logcnt < 12 && (now - lastlog) >= 400) {
                lastlog = now; logcnt++;
                FWLOG("dtls %s: state=%d r=-0x%04x rx=%d hs=%d",
                      L->name, (int)L->ssl.state, (unsigned)(-r), L->rx_len,
                      L->handshake_done ? 1 : 0);
            }
        }
        if (r == MBEDTLS_ERR_SSL_WANT_READ && L->rx_len <= 0) return;  // wait for more input
        if (++guard > 32) return;                                      // yield to the main loop
    }
    if (L->pkt_len) {
        if (r == 0 && !L->handshake_done && L->pkt_len <= (int)sizeof L->final_) {
            memcpy(L->final_, L->pkt, (size_t)L->pkt_len);
            L->final_len = L->pkt_len;
            FWLOG("dtls %s: final flight out %d bytes", L->name, L->pkt_len);
            if (L->pkt_len >= 24) {
                char hx[64]; int o = 0;
                for (int i = 0; i < 24 && o < 60; i++)
                    o += snprintf(hx + o, sizeof hx - o, "%02x", L->pkt[i]);
                hx[o] = 0;
                FWLOG("finalfl24=%s", hx);
            }
        }
        udp_send_link(L, L->pkt, L->pkt_len); L->pkt_len = 0;
        // Send the final flight twice back-to-back: the controller never accepts it and
        // we cannot yet tell loss from rejection (close_notify carries no error code).
        // A duplicate is harmless to a client that already has it (idempotent records).
        if (L == &Ld && L->final_len > 0) udp_send_link(L, L->final_, L->final_len);
    }
    if (r == 0 && !L->handshake_done) {
        FWLOG("dtls %s: HANDSHAKE DONE (cipher=%s)", L->name,
              mbedtls_ssl_get_ciphersuite(&L->ssl));
    }
    if (r != 0) {                       // fatal handshake error: reset session
        FWLOG("dtls %s: handshake FAILED rc=-0x%04x", L->name, (unsigned)(-r));
        mbedtls_ssl_session_reset(&L->ssl);
        L->handshake_done = false;
        L->final_len = 0;
        if (L == &Ld) { disp_rpc_reset(); audio_session_reset(); }
        return;
    }
    L->handshake_done = true;
    if (L == &Ld) disp_rpc_hs_ms = to_ms_since_boot(get_absolute_time());
    // P0-2 (HANDOVER 4.4): advance the display link the moment the handshake completes,
    // NOT when peer data arrives. The controller sends nothing until it sees our
    // GetControllerStateRequest, so a data-triggered advance is a bidirectional deadlock.
    // rtc_tick()'s READY driver (1.5 s) starts firing on the next tick after this.
    if (L == &Ld && cloud_state == CLOUD_REGISTERED) {
        cloud_state = CLOUD_LINK_UP;
        FWLOG("cloud: display link up -> sending GetControllerStateRequest");
    }
    // drain app data
    static uint8_t app[1400];
    int n;
    while ((n = mbedtls_ssl_read(&L->ssl, app, sizeof app)) > 0) {
        // Inbound display app data + the peer's DECRYPTED alert: ssl_read returns
        // PEER_CLOSE_NOTIFY / a fatal code for alerts - logging the rc distinguishes
        // "app chose to leave" (0x7880) from "our records broke it" (bad_record_mac
        // 0x2700, decrypt_error 0x0307, ...). Rate-limited: the error persists.
        static int app_log; static int last_rc_logged;
        if (L == &Ld && app_log < 12) { app_log++; FWLOG("disp app data in %d bytes", n); }
        if (L == &Ld) {
            on_display_frame(app, n);
        } else {
            if (cloud_state == CLOUD_READY) cloud_state = CLOUD_GAME_STARTED;
            on_game_frame(app, n);
        }
        if (L->pkt_len) { udp_send_link(L, L->pkt, L->pkt_len); L->pkt_len = 0; }
    }
    if (n < 0 && L == &Ld) {
        // The DECRYPTED alert/error from the controller, rate-limited (mbedtls keeps
        // returning the stored code): 0x7880 close_notify = app chose to leave;
        // 0x2700 bad_record_mac / 0x7780 decrypt_error = our records broke it.
        static int rc_logged;
        if (rc_logged < 8) { rc_logged++; FWLOG("disp read rc=-0x%04x", (unsigned)(-n)); }
        // D9: the controller's close/fatal alert ends THIS session for good. Without a
        // reset, every later re-registration meets a zombie link (handshake_done
        // latched, display-RPC arm stale, ICE checks silenced) and the second ICE
        // never starts. The reference drops all post-DTLS state on the next offer
        // (reset_boot_state, controller.py:163-186); the equivalent here is the same
        // session reset a fresh ClientHello triggers (see link_recv).
        if (n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || n == MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE) {
            FWLOG("dtls disp: session reset after alert");
            mbedtls_ssl_session_reset(&L->ssl);
            L->handshake_done = false;
            L->final_len = 0;
            L->rx_len = 0;
            disp_rpc_reset();
            audio_session_reset();
        }
    }
    if (L->pkt_len) { udp_send_link(L, L->pkt, L->pkt_len); L->pkt_len = 0; }
}

// --------------------------------------------------------------- send RPC
// Returns the frame length written (8+n), 0 when nothing left the link (no
// handshake / oversized / mbedtls write refused). Callers that ignore it keep the
// old behaviour; the 0x66 path logs it so a silently-dropped ACK is visible.
static int wh2_send(link_t *L, uint16_t id, const uint8_t *payload, int n) {
    if (!L->handshake_done) return 0;
    // 1500 bytes on a 2048-byte stack (PICO_STACK_SIZE default 0x800) plus the
    // mbedtls frames above it is a guaranteed overflow. Single-threaded, so static.
    static uint8_t frame[1500];
    // p3-2710: the 8-byte header is written by proto.c wh2_wrap() - the SAME function
    // tests/proto_host_test.c asserts byte for byte (R15_WH2_START/STOP), so the
    // device wire form and the host oracle can no longer drift apart.
    int total = wh2_wrap(frame, (int)sizeof frame, id, payload, n);
    if (!total) return 0;   // bounds check lives in wh2_wrap now
    for (int off = 0; off < total; ) {
        int w = mbedtls_ssl_write(&L->ssl, frame + off, (size_t)(total - off));
        if (w <= 0) return 0;                       // silent partial writes were invisible
        off += w;
        if (L->pkt_len > 0) { udp_send_link(L, L->pkt, L->pkt_len); L->pkt_len = 0; }
    }
    if (L->pkt_len > 0) { udp_send_link(L, L->pkt, L->pkt_len); L->pkt_len = 0; }
    return total;
}

// DisplayToController request out (ticket++, payload built by proto.c). The wire id is a
// parameter: everything rides WID_DISP_RPC (0x75, the live-verified stadiacast preset)
// EXCEPT the audio attach, whose channel is AUDIO_ATTACH_WID (config.h) so the PC-verified
// pc-peer variant (0x74, display-rpc.cjs muxFrame(CH)) can be tried on the device.
static void rpc_request_display(const uint8_t *payload, int n, uint16_t wid) {
    uint8_t msg[700]; pb_out_t o; pbo_init(&o, msg, sizeof msg);
    uint32_t ticket = cloud_next_ticket();
    build_rpc_request(&o, ticket, payload, n);
    // Every outbound display RPC is visible: the 1.5 s GetControllerStateRequest loop is
    // otherwise silent, and "did we keep sending" was unanswerable from the logs.
    static int req_log;
    if (req_log < 16) { req_log++; FWLOG("disp rpc out: ticket=%u len=%d id=0x%04x", ticket, o.len, wid); }
    wh2_send(&Ld, wid, o.buf, o.len);
}
static void rpc_respond_display(uint32_t ticket, int code, const uint8_t *payload, int n) {
    static uint8_t msg[760]; pb_out_t o; pbo_init(&o, msg, sizeof msg);
    build_rpc_response(&o, ticket, code, payload, n);
    wh2_send(&Ld, WID_DISP_RPC, o.buf, o.len);
}

// The RpcRequest/RpcResponse payload on the display link is NOT the bare inner message:
// it is a DisplayToController with the inner message in its oneof field. The receive side
// (on_display_rpc / handle_ctd_request) parses ControllerToDisplay the same way, and the
// live reference does the same (stadiacast controller.py:667 - "payload is a
// DisplayToController"). Sending the bare inner message makes the controller see a
// wire-type mismatch on that field and drop the whole RPC.
static void rpc_request_dtc(int field, const uint8_t *inner, int n, uint16_t wid) {
    static uint8_t dtc[700]; pb_out_t d; pbo_init(&d, dtc, sizeof dtc);
    pbo_bytes(&d, field, inner, n);
    rpc_request_display(d.buf, d.len, wid);
}
static void rpc_respond_dtc(uint32_t ticket, int code, int field, const uint8_t *inner, int n) {
    uint8_t dtc[700]; pb_out_t d; pbo_init(&d, dtc, sizeof dtc);
    pbo_bytes(&d, field, inner, n);
    rpc_respond_display(ticket, code, d.buf, d.len);
}

// --------------------------------------------------------------- audio TX
// Speaker path, ported from the PC-verified recipe (PLAYBOOK 3.6z6) and the live spec
// (stadiacast). The controller's audio playback is
//   * ATTACHED by a display RPC DisplayToController{16: SetAudioModeRequest{1:2}}
//     ("WebRTC Opus"; pc-peer.cjs audio_attach_sent / display-rpc.cjs
//     buildAudioModeRequest - a SUBmessage, not a bare varint),
//   * FED by Opus RTP (PT 111, 20 ms frames = ts step 960, stereo 48 kHz, seq+1 with no
//     gaps - the device only advances its playback pump on consecutive sequence numbers,
//     emu37) wrapped in SRTP AES128_CM_SHA1_80, sent over UDP on the DISPLAY link's own
//     5-tuple (BUNDLE: same socket as STUN/DTLS). Unprotected RTP is dropped silently.
// The Opus payload is a pre-encoded 440 Hz steady-state cycle (src/tone_frames.h,
// tools/gen-tone-frames.cjs); the firmware never runs a codec.
static struct {
    bool keys_ok;                     // SRTP TX keys derived for THIS display session
    uint8_t key[16], auth[20], salt[14];
    // SRTCP TX keys: same DTLS-SRTP master key/salt, RTCP session keys are the RFC
    // 3711 labels 3/4/5 the reference derives next to 0/1/2 (srtp.py:71-72
    // kdf(3,klen)/kdf(4,alen)/kdf(5,slen)). rtcp_index is the SRTCP packet index,
    // pre-incremented from 0 (srtp.py:183); rr_sent is the lifetime empty-RR count.
    uint8_t rtcp_key[16], rtcp_auth[20], rtcp_salt[14];
    uint32_t rtcp_index; uint32_t rr_sent;
    bool attached; uint32_t attached_ms;   // tag16 mode-2 attach state (60 s re-arm guard)
    bool usb_src;                     // p3-2700: frame source = UAC1 USB ring (true)
                                      // or nothing (false; the tone only runs while
                                      // a TONE command is active). Since p3-3500 this
                                      // is MACHINE-managed by the auto-source tick
                                      // below (USB data arriving -> true, gone >100 ms
                                      // -> false); the AUDIOSRC console command is
                                      // deleted.
    bool tone_on;
    uint32_t frames_left;             // frames still to send in the current tone
    uint32_t tone_frames;             // frames the current tone asked for (log line)
    uint32_t next_due_us;             // absolute due time of the next frame
    uint16_t seq; uint32_t ts;        // RTP stream state, CONTINUES across tones (werift
                                      // sendRtp rewrites the header the same way)
    uint32_t roc;                     // SRTP rollover counter (wraps of seq)
    uint16_t last_seq; bool have_seq;
    uint8_t frame;                    // index into the looped tone cycle
    bool marker;                      // next frame carries the RTP marker bit
    uint32_t sent_total;              // lifetime frames (heartbeat visibility)
    uint32_t last_stat_ms;            // 10 s usb-source visibility line
} audio;

static void audio_session_reset(void) {
    // A dead display session invalidates the SRTP keys (new handshake = new exporter
    // material), the attach (the controller's audio path reset with it) and any tone.
    // RTP seq/ts restart too: the receiver's SRTP state starts fresh per session.
    audio.keys_ok = false;
    audio.attached = false;
    audio.attached_ms = 0;
    audio.tone_on = false;
    audio.frames_left = 0;
    audio.seq = 1;
    audio.ts = 0;
    audio.roc = 0;
    audio.have_seq = false;
    audio.rtcp_index = 0;              // SRTCP index restarts with the new keys
    audio.frame = 0;
    audio.marker = true;
    // p3-3641: any PCM buffered for the OLD session must not be encoded into the
    // new RTP stream; drop it and let core1 clear its staging tail.
    ipc_pcm_reset();
    ipc_audio_request_flush();
}

// RFC 3711 §4.3.1 key derivation, key_derivation_rate 0 - the exact construction of the
// live spec (stadiacast srtp.py srtp_kdf): label XORed into salt byte 6, IV = salt<<16,
// keystream = AES-CTR(master_key, IV) over n zero bytes.
static void srtp_kdf(const uint8_t mkey[16], const uint8_t msalt[14], int label,
                     uint8_t *out, int n) {
    uint8_t iv[16], sb[16], zeros[20] = {0};
    memcpy(iv, msalt, 14);
    iv[14] = iv[15] = 0;
    iv[7] ^= (uint8_t)label;          // label<<48 lands on byte 7 of the 112-bit salt
                                      // (libsrtp nonce.v8[7]; byte-verified vs srtp.py)
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    if (mbedtls_aes_setkey_enc(&aes, mkey, 128) == 0) {
        size_t off = 0;
        memcpy(sb, iv, 16);
        mbedtls_aes_crypt_ctr(&aes, (size_t)n, &off, iv, sb, zeros, out);
    }
    mbedtls_aes_free(&aes);
}

// Derive the SRTP TX keys from the display DTLS handshake, lazily on first use:
// RFC 5764 §4.2 keying via the RFC 5705 exporter (label "EXTRACTOR-dtls_srtp", no
// context) over master secret + handshake randoms, then the RFC 3711 session-key KDF.
// The exporter output is client_key(16) | server_key(16) | client_salt(14) |
// server_salt(14); we are the DTLS SERVER, so our OUTBOUND stream keys the server
// halves (endpoint.py _on_dtls_complete, role "server" branch).
static bool audio_keys_derive(void) {
    if (audio.keys_ok) return true;
    if (!Ld.handshake_done) return false;
    if (!Ld.exp_valid) {
        static int l1;
        if (l1 < 3) { l1++; FWLOG("audio: no exporter material captured"); }
        return false;
    }
    mbedtls_dtls_srtp_info srtp;
    memset(&srtp, 0, sizeof srtp);
    mbedtls_ssl_get_dtls_srtp_negotiation_result(&Ld.ssl, &srtp);
    if (srtp.chosen_dtls_srtp_profile != MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_80) {
        static int l2;
        if (l2 < 3) { l2++; FWLOG("audio: srtp profile not AES128_CM_SHA1_80 (0x%04x)",
                                  (unsigned)srtp.chosen_dtls_srtp_profile); }
        return false;
    }
    // RFC 5705 seed = client_random || server_random, NOTHING ELSE. p3-2330: this used
    // to append uint16be(60) - the TLS 1.3 HKDF-Expand-Label convention, which a TLS 1.2
    // exporter must NOT use. Verified against the two stacks that interop with this
    // controller: werift prf.js exportKeyingMaterial() seeds label||clientRandom||
    // serverRandom (and werift is the stack behind the PC-verified audible tone), and
    // stadiacast delegates to pyOpenSSL's export_keying_material (RFC 5705, no length).
    // With the 2 extra bytes every derived key/salt was wrong, the controller's SRTP
    // unprotect failed on all 125 tone frames and - emu37 - it drops those silently:
    // "frames sent, no sound", keys_ok and m=n+22 all looking healthy.
    uint8_t seed[32 + 32];
    memcpy(seed, Ld.exp_cr, 32);
    memcpy(seed + 32, Ld.exp_sr, 32);
    uint8_t mat[60];
    if (mbedtls_ssl_tls_prf(Ld.exp_prf, Ld.exp_ms, 48, "EXTRACTOR-dtls_srtp",
                            seed, sizeof seed, mat, sizeof mat) != 0) {
        static int l3;
        if (l3 < 3) { l3++; FWLOG("audio: exporter PRF failed"); }
        return false;
    }
    srtp_kdf(mat + 16, mat + 46, 0, audio.key, 16);    // label 0: rtp cipher key
    srtp_kdf(mat + 16, mat + 46, 1, audio.auth, 20);   // label 1: rtp auth key (SHA1)
    srtp_kdf(mat + 16, mat + 46, 2, audio.salt, 14);   // label 2: rtp salt
    srtp_kdf(mat + 16, mat + 46, 3, audio.rtcp_key, 16);   // label 3: rtcp cipher key
    srtp_kdf(mat + 16, mat + 46, 4, audio.rtcp_auth, 20);  // label 4: rtcp auth key (SHA1)
    srtp_kdf(mat + 16, mat + 46, 5, audio.rtcp_salt, 14);  // label 5: rtcp salt
    audio.keys_ok = true;
    FWLOG("audio: srtp tx keys derived (srtp profile 0x%04x, prf %d)",
          (unsigned)srtp.chosen_dtls_srtp_profile, (int)Ld.exp_prf);
    return true;
}

// SRTP AES128_CM/HMAC-SHA1-80 protect, TX side - the C mirror of stadiacast srtp.py
// protect_rtp: AES-CTR over the payload with IV = (salt<<16)^(ssrc<<64)^(index<<16),
// then tag = HMAC-SHA1(auth, packet||roc)[0..10). pkt holds the full plain RTP packet
// and must have 10 spare bytes; returns the protected length, 0 on error.
static int audio_srtp_protect(uint8_t *pkt, int len, int cap) {
    if (len < 12 || len + 10 > cap) return 0;
    int hdr = 12 + 4 * (pkt[0] & 0x0F);            // csrcs
    if (pkt[0] & 0x10) {                           // one header extension block (RFC 8285)
        if (hdr + 4 > len) return 0;
        hdr += 4 + 4 * ((pkt[hdr + 2] << 8) | pkt[hdr + 3]);
    }
    if (hdr > len) return 0;
    uint16_t seq = (uint16_t)((pkt[2] << 8) | pkt[3]);
    uint32_t ssrc = ((uint32_t)pkt[8] << 24) | ((uint32_t)pkt[9] << 16) |
                    ((uint32_t)pkt[10] << 8) | (uint32_t)pkt[11];
    if (audio.have_seq && seq < audio.last_seq) audio.roc++;   // seq wrapped 65535 -> 0
    audio.last_seq = seq; audio.have_seq = true;
    uint8_t iv[16], sb[16];
    memcpy(iv, audio.salt, 14);
    iv[14] = iv[15] = 0;
    iv[4] ^= (uint8_t)(ssrc >> 24); iv[5] ^= (uint8_t)(ssrc >> 16);
    iv[6] ^= (uint8_t)(ssrc >> 8);  iv[7] ^= (uint8_t)ssrc;
    iv[8] ^= (uint8_t)(audio.roc >> 24); iv[9] ^= (uint8_t)(audio.roc >> 16);
    iv[10] ^= (uint8_t)(audio.roc >> 8); iv[11] ^= (uint8_t)audio.roc;
    iv[12] ^= (uint8_t)(seq >> 8);  iv[13] ^= (uint8_t)seq;
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    int rc = mbedtls_aes_setkey_enc(&aes, audio.key, 128);
    if (rc == 0) {
        size_t off = 0;
        memcpy(sb, iv, 16);
        mbedtls_aes_crypt_ctr(&aes, (size_t)(len - hdr), &off, iv, sb, pkt + hdr, pkt + hdr);
    }
    mbedtls_aes_free(&aes);
    if (rc != 0) return 0;
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    mbedtls_md_context_t mc;
    mbedtls_md_init(&mc);
    uint8_t tag[20] = {0};
    // md_setup(..., 1): the hmac flag ALLOCATES the hmac context - with 0 every
    // md_hmac_* call fails with MD_BAD_INPUT_DATA and the tag silently stays zero.
    if (mbedtls_md_setup(&mc, md, 1) == 0 && mbedtls_md_hmac_starts(&mc, audio.auth, 20) == 0) {
        mbedtls_md_hmac_update(&mc, pkt, (size_t)len);
        uint8_t r4[4] = { (uint8_t)(audio.roc >> 24), (uint8_t)(audio.roc >> 16),
                          (uint8_t)(audio.roc >> 8), (uint8_t)audio.roc };
        mbedtls_md_hmac_update(&mc, r4, 4);
        mbedtls_md_hmac_finish(&mc, tag);
    }
    mbedtls_md_free(&mc);
    memcpy(pkt + len, tag, 10);
    return len + 10;
}

// SRTCP AES128_CM/HMAC-SHA1-80 protect, TX side - the C mirror of stadiacast srtp.py
// protect_rtcp (181-192). Three differences from protect_rtp above: (1) the packet
// index is a standalone counter pre-incremented from 0 (first packet index 1), not
// roc<<16|seq; (2) the E-bit word 0x80000000|index is appended in the CLEAR after the
// (possibly empty) encrypted part - AES-CTR covers only pkt[8:], IV = _cm_iv(rtcp_salt,
// ssrc, index) with index<<16 landing on IV bytes 10-13; (3) the HMAC runs over the
// body WITHOUT any roc word. pkt holds the plain RTCP packet and must have 14 spare
// bytes (4 index + 10 tag); returns the protected length, 0 on error.
static int disp_rtcp_protect(uint8_t *pkt, int len, int cap) {
    if (len < 8 || len + 14 > cap) return 0;
    uint32_t ssrc = ((uint32_t)pkt[4] << 24) | ((uint32_t)pkt[5] << 16) |
                    ((uint32_t)pkt[6] << 8) | (uint32_t)pkt[7];
    audio.rtcp_index = (audio.rtcp_index + 1) & 0x7FFFFFFFu;
    uint32_t idx = audio.rtcp_index;
    uint8_t iv[16], sb[16];
    memcpy(iv, audio.rtcp_salt, 14);
    iv[14] = iv[15] = 0;
    iv[4] ^= (uint8_t)(ssrc >> 24); iv[5] ^= (uint8_t)(ssrc >> 16);
    iv[6] ^= (uint8_t)(ssrc >> 8);  iv[7] ^= (uint8_t)ssrc;
    iv[10] ^= (uint8_t)(idx >> 24); iv[11] ^= (uint8_t)(idx >> 16);
    iv[12] ^= (uint8_t)(idx >> 8);  iv[13] ^= (uint8_t)idx;
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    int rc = mbedtls_aes_setkey_enc(&aes, audio.rtcp_key, 128);
    if (rc == 0) {
        size_t off = 0;
        memcpy(sb, iv, 16);
        mbedtls_aes_crypt_ctr(&aes, (size_t)(len - 8), &off, iv, sb, pkt + 8, pkt + 8);
    }
    mbedtls_aes_free(&aes);
    if (rc != 0) return 0;
    pkt[len]     = (uint8_t)(0x80 | (idx >> 24));   // E-bit set: index word follows
    pkt[len + 1] = (uint8_t)(idx >> 16);
    pkt[len + 2] = (uint8_t)(idx >> 8);
    pkt[len + 3] = (uint8_t)idx;
    int body = len + 4;
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    mbedtls_md_context_t mc;
    mbedtls_md_init(&mc);
    uint8_t tag[20] = {0};
    if (mbedtls_md_setup(&mc, md, 1) == 0 && mbedtls_md_hmac_starts(&mc, audio.rtcp_auth, 20) == 0) {
        mbedtls_md_hmac_update(&mc, pkt, (size_t)body);
        mbedtls_md_hmac_finish(&mc, tag);
    }
    mbedtls_md_free(&mc);
    memcpy(pkt + body, tag, 10);
    return body + 10;
}

// Empty RTCP Receiver Report, the reference's exact 8 bytes (endpoint.py:574-585
// send_rtcp_rr): 80 C9 00 01 <ssrc> (V=2, PT=201 RR, RC=0, length 1, our local
// sender SSRC - the same AUDIO_SSRC the RTP path uses, like endpoint.local_ssrc).
// Protected with the RTCP session keys and sent raw on the display link's own
// 5-tuple (BUNDLE: same socket as STUN/DTLS/audio). "Standard WebRTC receiver
// traffic: the display is the receiver of the controller's mic-audio and input
// streams, so it reports on them" - and some controller state machines only count
// the link as live once display traffic arrives (controller.py:470-487 _rtcp_loop,
// fired every cfg.rtcp_interval=1.0 s once the display DTLS is connected).
static bool disp_rtcp_send_rr(void) {
    if (!audio_keys_derive()) return false;   // same exporter material, labels 3/4/5
    if (!Ld.have_peer || !Ld.pcb) return false;
    uint8_t rr[8 + 4 + 10];
    rr[0] = 0x80; rr[1] = 201; rr[2] = 0; rr[3] = 1;
    rr[4] = (uint8_t)(AUDIO_SSRC >> 24); rr[5] = (uint8_t)(AUDIO_SSRC >> 16);
    rr[6] = (uint8_t)(AUDIO_SSRC >> 8);  rr[7] = (uint8_t)AUDIO_SSRC;
    int m = disp_rtcp_protect(rr, 8, (int)sizeof rr);
    if (m <= 0) return false;
    udp_send_link(&Ld, rr, m);
    return true;
}

// Attach the controller's playback channel: DisplayToController{16:{1:mode}} as an
// RpcRequest payload - the exact 19-byte shape pc-peer sends (display-rpc.cjs
// buildAudioModeRequest: 00 00 <wid> 00 13 00 00 00 0a 09 08 <t> 12 05 82 01 02 08 02;
// byte-identical to ours except the ticket and the wire id), through the firmware's own
// request path on AUDIO_ATTACH_WID. p3-2300 evidence with 0x75: the controller ACKED the
// attach (pico-log-20261104-220015: "disp notif: t=1 pl=51 tag=4" AudioConfiguration-
// Changed carrying mode 2 + its IP, right after ticket-2 went out), so 0x75 is known
// good at the RPC level; AUDIO_ATTACH_WID defaults to pc-peer's 0x74 to match the only
// audibly-verified recipe end to end. Flip it back to WID_DISP_RPC if 0x74 ever stops
// producing the tag=4 acknowledgment.
// mode 2 = attach WebRTC Opus (mode 3 = UDP_PCM is REJECTED by the firmware: it logs
// "Unsupported audio mode"). 60 s re-arm guard like the pc-peer auto-attach.
static void audio_attach_send(int mode) {
    uint32_t now = to_ms_since_boot(get_absolute_time());
    if (audio.attached && now - audio.attached_ms < 60000) return;
    if (!Ld.handshake_done) return;
    uint8_t body[2] = { 0x08, (uint8_t)mode };     // SetAudioModeRequest{f1: mode}
    rpc_request_dtc(DTC_SET_AUDIO_MODE, body, 2, AUDIO_ATTACH_WID);
    audio.attached = true;
    audio.attached_ms = now;
    FWLOG("audio_attach_sent {mode:%d, wid:0x%04x}", mode, AUDIO_ATTACH_WID);
}

// One 20 ms Opus frame out as SRTP RTP over the display 5-tuple. Returns the UDP bytes
// sent, 0 when the frame did not leave. The payload comes from the selected source:
// the tone cycle, or (p3-2700/p3-3641) one frame encoded RIGHT HERE on core0 from
// the UAC1 PCM ring - the RTP/SRTP layer (header, seq/ts/marker, protect, send) is
// identical for both, which is the whole point of reusing this pump.
//
// p3-3641-core0encode: this is the on-core0 encode call (usb_audio_encode_live ->
// opus_encode with libopus's static pseudostack). It reads exactly one 3840-byte
// block per slot; a short ring is zero-filled inside ipc_pcm_read(), so the frame
// always exists and the RTP sequence never gaps.
// p3-3621 audio telemetry: real Opus frames vs silence fallback
static uint32_t tx_real, tx_sil;
// p3-3641: the ring gets one 80 ms cushion before the first live encode; until
// then (and whenever the encoder is unusable) slots carry the pre-encoded
// silence frame, keeping the RTP sequence gapless.
static bool usb_prefilled;
static int audio_send_frame(void) {
    if (!audio_keys_derive()) return 0;
    if (!Ld.have_peer || !Ld.pcb) return 0;
    static uint8_t pkt[12 + IPC_AUDIO_FRAME_MAX];
    int n;
    if (audio.usb_src) {
        n = 0;
        if (usb_prefilled) n = usb_audio_encode_live(pkt + 12, (int)sizeof pkt - 12);
        if (n <= 0) {
            int sl = 0;
            const uint8_t *s = usb_audio_silence(&sl);
            if (sl <= 0) {
                // No frame AND no silence fallback: core0's encoder never came up
                // (see usb_audio_encoder_init). Fail closed (retry next slot, no
                // seq hole) but leave a trace on the log.
                static int no_silence_logged;
                if (no_silence_logged < 3) {
                    no_silence_logged++;
                    FWLOG("audio: no encoder/silence frame (encoder failed?) - USB source stalled");
                }
                return 0;
            }
            n = sl;
            if (n > (int)sizeof pkt - 12) n = (int)sizeof pkt - 12;
            memcpy(pkt + 12, s, (size_t)n);
            tx_sil++;
        } else {
            tx_real++;
        }
    } else {
        n = tone_frame_off[audio.frame + 1] - tone_frame_off[audio.frame];
        memcpy(pkt + 12, tone_frames + tone_frame_off[audio.frame], (size_t)n);
    }
    pkt[0] = 0x80;                                  // V=2, no X/CC (emu37: X=0 accepted)
    pkt[1] = (uint8_t)((audio.marker ? 0x80 : 0) | (AUDIO_PT & 0x7F));
    pkt[2] = (uint8_t)(audio.seq >> 8); pkt[3] = (uint8_t)audio.seq;
    pkt[4] = (uint8_t)(audio.ts >> 24); pkt[5] = (uint8_t)(audio.ts >> 16);
    pkt[6] = (uint8_t)(audio.ts >> 8);  pkt[7] = (uint8_t)audio.ts;
    pkt[8] = (uint8_t)(AUDIO_SSRC >> 24); pkt[9] = (uint8_t)(AUDIO_SSRC >> 16);
    pkt[10] = (uint8_t)(AUDIO_SSRC >> 8); pkt[11] = (uint8_t)AUDIO_SSRC;
    int m = audio_srtp_protect(pkt, 12 + n, (int)sizeof pkt);
    if (m <= 0) return 0;
    udp_send_link(&Ld, pkt, m);
    {   // a couple of frame logs: proof the pump is alive without flooding the ring.
        // The destination 5-tuple is printed so "frames went to the display peer" is a
        // log fact, not an inference (BUNDLE: audio rides Ld's own socket, :40000 ->
        // the controller's display-side port).
        static int fl;
        if (fl < 6) {
            fl++;
            FWLOG("audio frame: seq=%u ts=%u n=%d m=%d -> %d.%d.%d.%d:%u",
                  audio.seq, audio.ts, n, m,
                  ip4_addr1(&Ld.peer), ip4_addr2(&Ld.peer),
                  ip4_addr3(&Ld.peer), ip4_addr4(&Ld.peer), Ld.peer_port);
        }
    }
    return m;
}

// AUDPTEST console command: ONE unencrypted RTP frame with the current tone data -
// deliberately unprotected. The controller drops SRTP-unprotectable packets silently
// (emu37), so with a healthy SRTP path this frame must NOT produce sound while TONE
// does: that contrast is the point (it pins "silence = protection wrong" vs "silence =
// transport/attach wrong" without a flash cycle). Counters (seq/ts/frame) are NOT
// advanced: the probe reuses the next unsent seq so a hypothetical acceptor would see
// a plain replay and drop it anyway.
void rtc_audio_test_raw(void) {
    if (!Ld.handshake_done || !Ld.have_peer || !Ld.pcb) {
        FWLOG("audptest_skip {reason:\"no display session\"}");
        return;
    }
    int n = tone_frame_off[audio.frame + 1] - tone_frame_off[audio.frame];
    static uint8_t pkt[12 + IPC_AUDIO_FRAME_MAX];
    pkt[0] = 0x80;
    pkt[1] = (uint8_t)((audio.marker ? 0x80 : 0) | (AUDIO_PT & 0x7F));
    pkt[2] = (uint8_t)(audio.seq >> 8); pkt[3] = (uint8_t)audio.seq;
    pkt[4] = (uint8_t)(audio.ts >> 24); pkt[5] = (uint8_t)(audio.ts >> 16);
    pkt[6] = (uint8_t)(audio.ts >> 8);  pkt[7] = (uint8_t)audio.ts;
    pkt[8] = (uint8_t)(AUDIO_SSRC >> 24); pkt[9] = (uint8_t)(AUDIO_SSRC >> 16);
    pkt[10] = (uint8_t)(AUDIO_SSRC >> 8); pkt[11] = (uint8_t)AUDIO_SSRC;
    memcpy(pkt + 12, tone_frames + tone_frame_off[audio.frame], (size_t)n);
    udp_send_link(&Ld, pkt, 12 + n);
    FWLOG("audptest: raw rtp seq=%u ts=%u n=%d (NO srtp) -> %d.%d.%d.%d:%u",
          audio.seq, audio.ts, n,
          ip4_addr1(&Ld.peer), ip4_addr2(&Ld.peer),
          ip4_addr3(&Ld.peer), ip4_addr4(&Ld.peer), Ld.peer_port);
}

// TONE console command: attach (if the guard allows) and play 440 Hz for ms.
// The PC recipe's default (3.6z6): 2500 ms = 125 frames. Implies the tone source
// (AUDIOSRC tone) - TONE always was the tone recipe and stays self-contained.
void rtc_audio_tone_start(uint32_t ms) {
    if (!Ld.handshake_done || !Ld.have_peer) {
        FWLOG("audio_tone_skip {reason:\"no display session\"}");
        return;
    }
    audio.usb_src = false;
    uint32_t frames = ms / AUDIO_FRAME_MS;
    if (!frames) frames = 1;
    audio_attach_send(2);              // attach-then-play, like /audio-attach-play
    audio.frames_left = frames;
    audio.tone_frames = frames;
    audio.next_due_us = net_infra_uptime_us();
    audio.marker = true;               // each tone starts with the marker bit (playTone)
    audio.tone_on = true;
    FWLOG("audio_tone_start {frames:%u, frameMs:%d, tsStep:%d, pt:%d, ssrc:0x%08x}",
          (unsigned)frames, AUDIO_FRAME_MS, AUDIO_TS_STEP, AUDIO_PT, (unsigned)AUDIO_SSRC);
}

// AUDIOSRC console command (p3-2700): usb = the UAC1 speaker ring (PC audio,
// continuous stream), tone = the 440 Hz recipe. Switching resets the pacing and
// arms the marker bit (first frame of the new source carries M, like each tone).
void rtc_audio_set_source(int usb) {
    audio.usb_src = usb != 0;
    audio.tone_on = false;
    audio.frames_left = 0;
    audio.next_due_us = net_infra_uptime_us();
    audio.marker = true;
    if (audio.usb_src) {
        // p3-3641: any PCM still buffered belongs to a previous source run - drop
        // it and rebuild the 80 ms cushion from live audio (fresh PCM, no stale
        // tail). core1's staging tail is cleared by the flush request.
        ipc_pcm_reset();
        ipc_audio_request_flush();
        usb_prefilled = false;
        audio_attach_send(2);          // attach if the 60 s guard allows; the pump
                                        // retries every pass while the session is up
        FWLOG("audio src=usb {opusb:%d Hz, br:%d, cpx:%d, stream:%d}",
              AUDIO_OPUS_RATE, AUDIO_OPUS_BITRATE, AUDIO_OPUS_COMPLEXITY,
              ipc_audio_stream_get() ? 1 : 0);
    } else {
        FWLOG("audio src=tone");
    }
}

int rtc_audio_frames_sent(void) { return (int)audio.sent_total; }

// --------------------------------------------------------------- rumble TX
static int send_input_message(const uint8_t *pb, int n);   // the 0x66 mirror sender below
static uint32_t rumble_left, rumble_right; static bool rumble_on;
// p3-2550: starts at 0 so the FIRST outbound series carries seq=1 exactly like the
// reference's _feedback_seq (game_session.py:133/567: 0, pre-incremented per send).
static uint32_t rumble_seq = 0;
// Set by the writers - the XInput OUT endpoint's tud_vendor_rx_cb (IRQ context, since
// p3-2340; before that tud_hid_set_report_cb), the RUMBLE pulse and its auto-off - and
// cleared by rtc_tick when it flushes: every rumble frame must leave on the NEXT
// rtc_tick (<= ~20 ms, main.c drives it at 20 ms), not wait for the 2 s keepalive
// refresh. Since p3-2640 this flag is the ONLY trigger: no writer sends directly.
static volatile bool rumble_dirty;
// Series session_id (InputMessageSeries f1) and gamepad id (GamepadMessage_V2 f1) the
// controller announced: the reference echoes both in its feedback series
// (game_session.py send_vibration: series.session_id / vib.id = g["gamepad_id"] or 0).
// p3-2550: 16 -> 64 bytes - the reference echoes the session_id string WHATEVER its
// length (input.proto: string); a longer id used to be silently dropped by the cap,
// so the feedback series went out without the echo the live session carried.
static uint8_t  series_session[64]; static uint8_t series_session_len;
static uint32_t last_gamepad_id;

// Rumble-TX visibility budgets, FILE scope on purpose (p3-2640). The 2026-11-05 00:40
// "iron evidence" round misread budget silence as "the instrumented path never runs":
// every counter below is a per-BOOT static, the verification capture opened 26.6 min
// into a session that had already run 10 RUMBLE pulses (rumble_seq=22), and all four
// budgets were drained - while the controller's ack (gameframe ...2016, twice) proved
// the path HAD run and the series HAD left. rtc_rumble_pulse() (the explicit host test
// command, the one moment a human is watching) now resets them, so a mid-session RUMBLE
// always shows its own `rumble tx:` line, wire hex and the ack line - boot-lifetime
// exhaustion can never hide a deliberate test again. HID-driven rumble keeps the plain
// budgets (a game can shake the motors continuously; visibility there is best-effort).
static int rumble_tx_log;      // `rumble tx:` lines (flush path)
static int rumble_hex_log;     // `rumble hex:` lines (0x66 TX self-certification dump)
static int rumble_ack_log;     // `game ack in:` lines (controller acking our series)
static int rumble_pbdrop_log;  // `rumble pbdrop:` lines (pbo_raw dropped a write: truncated series)

// base_timestamp_us of our feedback series. game_session.py send_vibration uses
// int(time.time() * 1e6) - WALL-CLOCK microseconds - and the live e4 session proves
// the controller runs its own series in the same domain (registration decoded with
// t_us = base + rel = 1793597554953620 = 2026-11-02T05:32:34Z). The controller's clock
// comes from OUR SNTP (= cert mid + ms since boot, net_infra.c sntp_recv), so mirror
// exactly that clock: ms resolution is what we serve anyway. The old uptime-only value
// landed in 1970 (up to 9 orders of magnitude off): the 2026-11-04 23:47 session acked
// our series (gameframe 201f = InputProtocolMessage{4:31}) but the motor never moved -
// with relative_time_us=0 the vibration is scheduled AT base_timestamp_us, and a
// decades-stale timestamp is dropped by the haptics path (acked at the session layer,
// dead at the executor - the ack proves only the series, not the message content).
static uint64_t rumble_wall_us(void) {
    return ((uint64_t)rtc_cert_time_epoch() * 1000ull
          + (uint64_t)to_ms_since_boot(get_absolute_time())) * 1000ull;
}

// Rumble state writers/reader must be IRQ-coherent since p3-2130: the XInput
// rumble OUT frame now arrives on core1 (usb_hid.c queues it with
// ipc_rumble_push()); rtc_tick drains that queue into this state through
// rumble_set(), and rtc_tick's flush is the single send point. rtc_send_rumble()
// itself is CORE0-ONLY (p3-3600 review P1-9): the core1 path never calls it.
static void rumble_set(uint16_t l, uint16_t r) {
    uint32_t save = save_and_disable_interrupts();
    rumble_left=l; rumble_right=r; rumble_on=(l||r)!=0; rumble_seq++;
    rumble_dirty=true;                       // rtc_tick: flush on the next tick
    restore_interrupts(save);
}
void rtc_send_rumble(uint16_t l, uint16_t r) {
    rumble_set(l, r);
}
void rtc_rumble_off(void) {
    uint32_t save = save_and_disable_interrupts();
    rumble_left=0; rumble_right=0; rumble_on=false; rumble_seq++;
    rumble_dirty=true;                       // the 0,0 stop frame must leave promptly too
    restore_interrupts(save);
}

// The ONE rumble sender (p3-2640): rtc_tick's flush block is the only caller. Returns
// true when the series was handed to the wire (wh2_send accepted it); false means the
// link is down or the DTLS write refused - the caller re-arms rumble_dirty so the frame
// is retried on a later tick instead of being silently dropped.
static bool rumble_flush(void) {
    if (!Lg.handshake_done) return false;
    // coherent snapshot (see the writers above)
    uint32_t save = save_and_disable_interrupts();
    uint32_t vib_l = rumble_left, vib_r = rumble_right, vib_seq = rumble_seq;
    restore_interrupts(save);
    int ovf0 = g_pb_overflow;   // pbo_raw drop counter baseline for the tripwire below
    // p3-2550: one visibility line per send (budget 16, like the game tx line): id /
    // base_ts domain / session echo are the three content fields the 23:47 post-mortem
    // could not see, and "acked series, dead motor" needs them to discriminate.
    // p3-2640: the counter is file scope and rtc_rumble_pulse() resets it - see the
    // budget comment above rumble_tx_log for why a boot-lifetime budget alone was a
    // misdiagnosis trap.
    {
        if (rumble_tx_log < 16) {
            rumble_tx_log++;
            FWLOG("rumble tx: id=%u l=%u r=%u seq=%u base=%llu sid=%u",
                  (unsigned)last_gamepad_id, (unsigned)vib_l, (unsigned)vib_r,
                  (unsigned)vib_seq, (unsigned long long)rumble_wall_us(),
                  (unsigned)series_session_len);
        }
    }
    // p3-2710: the series is built by proto.c build_rumble_series() - the ONE
    // constructor, shared byte-for-byte with tests/proto_host_test.c, so the host
    // oracle asserts the firmware's OWN output instead of a replica. The 2026-11-05
    // 01:0x start frame (27 B: `3a11 1001 18<ts> 2204 2000 520c`) came from this
    // block's old inline `pbo_init(&sl, slim, sizeof sl)`: sizeof of the pb_out_t
    // STRUCT (12 B on ARM32!) instead of the 48 B array, so after `20 00` (f4=0)
    // and `52 0c` (f10 promising 12 B) the feedback CONTENT was dropped by
    // pbo_raw's cap check - a length prefix with nothing behind it. The 35 B stop
    // frame survived because its f10 content is only 8 B (4+8 <= 12). The host test
    // never saw it: its inline REPLICA used the correct sizeof. Shared constructor
    // with NUMERIC caps (see proto.c) = host and device build identical bytes -
    // sizeof(pb_out_t) is 16 on x64 vs 12 on ARM32, so a struct-sizeof typo in
    // shared code would STILL pass on host and truncate on the device.
    uint8_t msg[160]; pb_out_t o; pbo_init(&o, msg, sizeof msg);
    build_rumble_series(&o, last_gamepad_id, vib_l, vib_r, vib_seq, rumble_wall_us(),
                        series_session, series_session_len);
    // Tripwire for any future cap regression: pbo_raw counts every dropped write in
    // g_pb_overflow. Only our own builds ran since the snapshot, so any increment
    // here is THIS series being truncated - the 27 B frame left no other trace.
    if (g_pb_overflow != ovf0 && rumble_pbdrop_log < 8) {
        rumble_pbdrop_log++;
        FWLOG("rumble pbdrop: dropped=%d - series truncated", g_pb_overflow - ovf0);
    }
    return send_input_message(o.buf, o.len) > 0;  // no f4 piggyback: the reference's series
}                                                  // messages never carry ack_sequence_number

// Host-triggered test pulse, wired to the CDC "RUMBLE" command (usb_hid.c). Mirrors the
// reference's rumble() helper (game_session.py:595-637): set the levels, hold, then
// send_vibration(0,0) at the deadline so the motors stop instead of riding the
// controller's 5000 ms haptics watchdog. Amplitude scale is 0..0xFFFF (MOTOR_MAX,
// game_session.py:56): 75% = 49151, duration 200 ms.
//
// p3-2640: the start frame is NO LONGER sent from here. There is exactly ONE send path
// now - the writers (this, rtc_send_rumble, rtc_rumble_off) only set state +
// rumble_dirty, and rtc_tick's flush block (<= 20 ms later, main.c drives it at 20 ms)
// is the sole caller of rumble_flush(). The old direct rumble_flush() here was one of
// two fork sources: it could race the tick flush into DOUBLE-sending a series (the
// 00:40 rumble-live2 capture shows the controller acking series 22 TWICE - the stop
// frame went out once from the auto-off's direct flush and once more from the next
// tick's rumble_dirty flush, same seq), and when Lg was down it no-opped silently
// while "rumble: pulse done" kept implying a send. With dirty-only, a pulse requested
// before the game session is up simply stays pending and leaves on the first tick
// after Lg's handshake completes - nothing is lost, nothing is duplicated.
// This is also the host-test entry point, so the per-pulse visibility reset lives
// here (see the rumble_tx_log comment for the mid-session budget trap).
static bool rumble_pulse_on; static absolute_time_t rumble_pulse_until;
void rtc_rumble_pulse(void) {
    uint32_t save = save_and_disable_interrupts();   // coherent with the HID-IRQ writer
    rumble_left = rumble_right = 49151;         // 75% of MOTOR_MAX
    rumble_seq++;
    rumble_on = true;
    rumble_dirty = true;                         // the tick flush sends it (single path)
    restore_interrupts(save);
    rumble_pulse_on = true;
    rumble_pulse_until = delayed_by_ms(get_absolute_time(), 200);
    rumble_tx_log = 0;      // a deliberate test must see its own lines even mid-session
    rumble_hex_log = 0;
    rumble_ack_log = 0;
}

// --------------------------------------------------------------- input decode
// Commit a decoded pad state from EITHER input path - game-link gamepad_v2 below or
// display-link message3 in on_display_rpc - and log it on any change (buttons or
// axis delta > 256). p3-2050: this used to live inline in apply_gamepad_v2, so the
// display path (the one the live session proves is THE input channel) updated `pad`
// silently and every button press was invisible. Rate-limited so a stick swirl
// cannot flood the CDC ring - which, note, also starves tud_task: the same
// starvation is the prime suspect for the host-side HID interface failing to start
// (Code 10) while CDC works. `src` names the delivering path in the log line.
static void pad_commit(const pad_state_t *p, const char *src) {
    static pad_state_t prev; static int logged;
    if (logged < 24 &&
        (p->buttons != prev.buttons || labs(p->lx - prev.lx) > 256 ||
         labs(p->ly - prev.ly) > 256 || labs(p->rx - prev.rx) > 256 ||
         labs(p->ry - prev.ry) > 256 || p->lt != prev.lt || p->rt != prev.rt)) {
        prev = *p; logged++;
        FWLOG("pad: btn=%06x lx=%d ly=%d rx=%d ry=%d lt=%u rt=%u src=%s",
              p->buttons, (int)p->lx, (int)p->ly, (int)p->rx, (int)p->ry,
              p->lt, p->rt, src);
    }
    pad = *p; pad_fresh = true;
    // p3-3600-dualcore: publish the snapshot for core1's XInput IN report. The
    // seqlock in ipc.c is what keeps core1 from reading a torn struct.
    ipc_pad_publish(p);
}

static void apply_gamepad_v2(const uint8_t *g, int gl) {
    pad_state_t p = {0};
    {   // GamepadMessage_V2.f1 = the controller's gamepad id: the reference echoes it as
        // the rumble's gamepad_vibration.id (game_session.py send_vibration).
        uint64_t gid = pb_get_u64(g, gl, 1, UINT64_MAX);
        if (gid != UINT64_MAX) last_gamepad_id = (uint32_t)gid;
    }
    p.buttons = (uint32_t)pb_get_u64(g, gl, 2, 0);
    int64_t x;
    // sint32 zigzag
    x = (int64_t)pb_get_u64(g, gl, 3, 0); p.lx = (int16_t)(((uint32_t)x >> 1) ^ (uint32_t)(-(x & 1)));
    x = (int64_t)pb_get_u64(g, gl, 4, 0); p.ly = (int16_t)(((uint32_t)x >> 1) ^ (uint32_t)(-(x & 1)));
    x = (int64_t)pb_get_u64(g, gl, 5, 0); p.rx = (int16_t)(((uint32_t)x >> 1) ^ (uint32_t)(-(x & 1)));
    x = (int64_t)pb_get_u64(g, gl, 6, 0); p.ry = (int16_t)(((uint32_t)x >> 1) ^ (uint32_t)(-(x & 1)));
    p.lt = (uint8_t)pb_get_u64(g, gl, 7, 0);
    p.rt = (uint8_t)pb_get_u64(g, gl, 8, 0);
    pad_commit(&p, "g66");
}

// --------------------------------------------- outbound 0x66: MIRROR the controller
// p3-2000-input. How the live spec sends ANYTHING on the game link is decided by
// game_session.py:528-548: cfg.game_framing="auto" (the default and the live preset)
// MIRRORS the controller's own input framing - "RTP-in-0x66 until any is seen".
// ota.282115 sends its input as the BARE InputProtocolMessage on 0x66, so the reference's
// ACKs and rumble series go out BARE too (endpoint.send_wire(0x66, payload)).
//
// Live evidence for both directions (research/e4/sc-run/server.jsonl, firmware ota.282115,
// the session behind PLAYBOOK 9.46):
//   * game_input framing=raw, ONE series (seq=1 registration, device_presence TYPE_YETI),
//     ZERO retransmissions in 25 minutes, game_wire_in={0x0066: 4} - and the controller
//     ACKED the reference's three bare rumble series (game_input ack=1,2,3), so bare
//     0x66 frames in BOTH directions are proven good.
//   * Our own p3-1725-ack (bare ACK): pico-log-20261104-183025.txt - exactly ONE
//     gameframe in 28 minutes, ZERO retransmissions. The input sender's window is ONE
//     series with PeriodicResend and NO give-up timeout (wiki 8: AppendOutgoingMessage
//     sends only at pending==0), so an unacked seq=1 MUST retransmit forever. It did
//     not: the bare ACK was accepted.
//   * Our p3-1855-rtpack (RTP-framed ACK): pico-log-20261104-185840.txt - seq=1
//     retransmitted for the whole 26-minute session. The RTP envelope is REJECTED by the
//     controller's bare-framed 0x66 reader (tests/fake_controller.py:464-469 models that
//     reader as strict: "the 0x66 reader takes the framing this session uses, nothing
//     else"). p3-1855 therefore REGRESSED the working bare ACK of p3-1725; this build
//     restores the mirror and keeps the RTP envelope only for the (never observed)
//     RTP-framed controller.
#define GF_RTP 0    // config default: RTP-in-WireHeader2 until any framing is seen
#define GF_RAW 1    // bare InputProtocolMessage in WireHeader2 (what ota.282115 uses)
static uint8_t game_tx_framing = GF_RTP;
static uint16_t rtp_tx_seq;      // seeded once per boot, pre-incremented per send
static uint32_t rtp_tx_ssrc;     // seeded once per boot, never 0
static uint8_t  input_pt = 96;   // config.py:67 default until the peer's RTP PT is seen
static int send_input_rtp(const uint8_t *pb, int n) {
    if (!rtp_tx_ssrc) {          // endpoint.py:123/143: random start, ssrc never 0
        rtp_tx_ssrc = net_infra_uptime_us() * 2654435761u;
        if (!rtp_tx_ssrc) rtp_tx_ssrc = 1;
        rtp_tx_seq = (uint16_t)(rtp_tx_ssrc >> 16);
    }
    static uint8_t pkt[192];     // ACK is 2-6B; a rumble-sized series fits with the header
    if (n <= 0 || 12 + n > (int)sizeof pkt) return 0;
    rtp_tx_seq++;                                                       // endpoint.py:609
    uint32_t ts = (uint32_t)(((uint64_t)net_infra_uptime_us() * 90u) / 1000000u); // 90 kHz
    pkt[0] = 0x80; pkt[1] = input_pt & 0x7F;                            // rtp.py:123-124
    pkt[2] = (uint8_t)(rtp_tx_seq >> 8); pkt[3] = (uint8_t)rtp_tx_seq;
    pkt[4] = (uint8_t)(ts >> 24); pkt[5] = (uint8_t)(ts >> 16);
    pkt[6] = (uint8_t)(ts >> 8);  pkt[7] = (uint8_t)ts;
    pkt[8] = (uint8_t)(rtp_tx_ssrc >> 24); pkt[9] = (uint8_t)(rtp_tx_ssrc >> 16);
    pkt[10] = (uint8_t)(rtp_tx_ssrc >> 8); pkt[11] = (uint8_t)rtp_tx_ssrc;
    memcpy(pkt + 12, pb, n);
    return wh2_send(&Lg, WID_INPUT, pkt, 12 + n);   // endpoint.py:612 send_wire(0x66, pkt)
}

// game_session.py:536-548 send_input_message: framing "raw" = the bare protobuf in
// WireHeader2 0x66 (endpoint.send_wire), otherwise the RTP envelope. TX visibility:
// the send result is logged (rate-limited) because wh2_send can refuse silently and
// "the controller ignored our ACK" was indistinguishable from "the ACK never left".
//
// p3-2640 device-side self-certification: every outbound SERIES (top-level field 7 -
// our ACKs are field 4 only, so field 7 here IS the rumble feedback series) dumps its
// full wire frame in hex BEFORE the send. The next live RUMBLE test can then diff the
// exact bytes against tests/check_rumble.py's expected R15_START/R15_STOP vectors
// straight from the device log - no more inferring content from acks. GF_RAW prints
// byte-for-byte what wh2_send puts on the wire (8B WireHeader2 + payload); GF_RTP
// prints the payload the RTP envelope will carry (that framing has never been observed
// live - ota.282115 is bare). Budget 4 lines, reset by rtc_rumble_pulse().
static int send_input_message(const uint8_t *pb, int n) {
    {
        bool is_series = false;
        {
            pb_it_t probe; pbi_init(&probe, pb, n);
            while (pbi_next(&probe)) if (probe.field == 7 && probe.wire == 2) { is_series = true; break; }
        }
        if (is_series && rumble_hex_log < 4) {
            uint8_t fr[8 + 128];
            int fl = 0;                              // <=0: dump payload-only instead
            if (game_tx_framing == GF_RAW && n <= 128) {   // exact wh2_send wire form
                int total = 8 + n;
                fr[0]=0; fr[1]=0; fr[2]=0x66; fr[3]=0;
                fr[4]=(uint8_t)total; fr[5]=(uint8_t)(total>>8); fr[6]=(uint8_t)(total>>16);
                fr[7]=0;
                memcpy(fr + 8, pb, (size_t)n);
                fl = total;
            }
            if (fl > 0) {
                for (int blk = 0; blk * 48 < fl && rumble_hex_log < 4; blk++) {
                    int from = blk * 48, to = from + 48; if (to > fl) to = fl;
                    char hx[112]; int o = 0;
                    for (int i = from; i < to; i++)
                        o += snprintf(hx + o, sizeof hx - o, "%02x", fr[i]);
                    hx[o] = 0;
                    rumble_hex_log++;
                    FWLOG("rumble hex%d/%d %s", blk + 1, fl, hx);
                }
            } else {                                // RTP framing or oversize: payload only
                char hx[112]; int o = 0;
                for (int i = 0; i < n && i < 48; i++)
                    o += snprintf(hx + o, sizeof hx - o, "%02x", pb[i]);
                hx[o] = 0;
                rumble_hex_log++;
                FWLOG("rumble hex(payload,rtp) %s", hx);
            }
        }
    }
    int w = (game_tx_framing == GF_RAW) ? wh2_send(&Lg, WID_INPUT, pb, n)
                                        : send_input_rtp(pb, n);
    static int tx_log;
    if (tx_log < 16) {
        tx_log++;
        FWLOG("game tx: framing=%s len=%d w=%d seq=%u",
              game_tx_framing == GF_RAW ? "raw" : "rtp", n, w, (unsigned)rtp_tx_seq);
    }
    return w;
}

// game link 0x66 frame -> InputProtocolMessage (game_session.py:443-460 _on_channel_input)
static void on_game_input(const uint8_t *buf, int len) {
    // RTP-in-0x66 vs the bare message, exactly the reference demux: RTP v2 means
    // len>=12 and buf[0]>>6==2 (a bare InputProtocolMessage's first tag byte is never
    // 0b10xxxxxx); PT 192..223 is RTCP (RFC 5761) and carries no input. A successful
    // RTP parse strips the header (CSRCs + one extension block, RFC 8285) and mirrors
    // the peer's PT for our own sends; a header that walks past the frame keeps the raw
    // parse, like parse_rtp's ValueError path (game_session.py:454-460) does.
    const uint8_t *pm = buf; int plen = len;   // what the protobuf parser sees
    if (len >= 12 && (buf[0] >> 6) == 2) {
        if (buf[1] >= 192 && buf[1] <= 223) return;    // RTCP on 0x66: nothing to decode
        int off = 12 + 4 * (buf[0] & 0x0F);            // skip CC csrcs
        if (buf[0] & 0x10) {                           // X: one header extension block
            if (off + 4 <= len) off += 4 + 4 * ((buf[off + 2] << 8) | buf[off + 3]);
            else off = len + 1;                        // block header runs past the frame
        }
        if (off <= len) { pm = buf + off; plen = len - off; input_pt = buf[1] & 0x7F; }
        game_tx_framing = GF_RTP;          // mirror latch (game_session.py:483-494)
    } else {
        game_tx_framing = GF_RAW;          // the bare message: ota.282115's own framing
    }
    pb_it_t it; pbi_init(&it, pm, plen);
    while (pbi_next(&it)) {
        if (it.field == 4 && it.wire == 0) {
            // The controller ACKED one of OUR outbound series (rumble): the live 9.46
            // session shows exactly this shape coming back (game_input ack=1,2,3 after
            // each rumble_sent), so this line is the positive confirmation that our
            // bare series was accepted - not just "not retransmitted".
            // p3-2640: file-scope counter (rumble_ack_log), reset by rtc_rumble_pulse -
            // the 00:40 capture had this budget silently drained and the acks were only
            // visible as raw gameframe dumps.
            if (rumble_ack_log < 8) {
                rumble_ack_log++;
                FWLOG("game ack in: controller acked our series seq=%u", (unsigned)it.v);
            }
        }
        else if (it.field == 7 && it.wire == 2) {
            uint32_t seq = (uint32_t)pb_get_u64(it.body, it.body_len, 2, 0);
            // Echo the series session_id (InputMessageSeries f1) for our feedback series.
            // p3-2710 finding: ota.282115's own series carries NO f1 - the real-device
            // capture 2026-11-05 01:00 (gameframe n=35: series = f2 seq + f3 base +
            // f4 messages, nothing else) and the live e4 session both prove it - so
            // series_session_len stays 0 and the echo is correctly OMITTED, exactly
            // like the reference (game_session.py send_vibration's `if session_id:`
            // skips; the live motor-spinning rumbles carried no echo either). sid=0
            // in `rumble tx:` is the live baseline for THIS controller, not a learning
            // failure. A controller that does announce one (any length <= 64 B) is
            // echoed through the shared, host-tested learn_series_session() (R16
            // vectors of tests/proto_host_test.c).
            {
                int sl = learn_series_session(it.body, it.body_len,
                                              series_session, (int)sizeof series_session);
                if (sl > 0) series_session_len = (uint8_t)sl;
            }
            if (seq) {
                input_seq_seen = seq;
                // ACK every input series with InputProtocolMessage{4: ack_sequence_number}
                // (game_session.py:516-521, cfg.ack_mode="rtp" config.py:66) - through
                // send_input_message, i.e. in the CONTROLLER'S OWN framing (raw for
                // ota.282115 - see the block comment above), one ACK per received
                // series - no throttle, no seq-change gate, no ack_time_us (that f5
                // lives in the sender's InputMessageSeries, input.proto:392; the ACK
                // message is f4 only). Without a processed ACK the controller
                // retransmits the same seq forever: its window is ONE series
                // (AppendOutgoingMessage only sends at pending==0) and PeriodicResend
                // never gives up (wiki chapter 8), so every later input queues behind
                // the unacked seq=1 registration and buttons produce no new frames.
                uint8_t ab[8]; pb_out_t ao; pbo_init(&ao, ab, sizeof ab);
                pbo_u64(&ao, 4, input_seq_seen);
                send_input_message(ao.buf, ao.len);
                { static int ack_log; if (ack_log < 12) { ack_log++;
                  FWLOG("game ack: framing=%s ack_seq=%u",
                        game_tx_framing == GF_RAW ? "raw" : "rtp",
                        (unsigned)input_seq_seen); } }
            }
            int ml; const uint8_t *msgsb = pb_get_bytes(it.body, it.body_len, 4, &ml);
            if (msgsb) {
                pb_it_t m; pbi_init(&m, msgsb, ml);
                while (pbi_next(&m)) {
                    if (m.field == 5 && m.wire == 2) {
                        // InputMessageSlim: gamepad_message_v2 IS field 5 (input.proto);
                        // field 1 is the legacy GamepadMessage_V1. The old code looked for
                        // V2 nested inside f1, so no press ever reached the pad state.
                        apply_gamepad_v2(m.body, m.body_len);
                    }
                    else if (m.field == 1 && m.wire == 2) {
                        // Legacy V1 registrations carry the gamepad id in the first
                        // present sub-message (register#2/button#3/joystick#4/trigger#5/
                        // vibration#6, each with #1 = id) - input_protocol.py _gamepad_v1
                        // learns the id from either shape; the reference echoes it as
                        // vib.id. The live ota.282115 registers via V2, this covers the
                        // other firmware generation (p3-2550).
                        for (int f = 2; f <= 6; f++) {
                            int sl; const uint8_t *sub = pb_get_bytes(m.body, m.body_len, f, &sl);
                            if (!sub) continue;
                            uint64_t gid = pb_get_u64(sub, sl, 1, UINT64_MAX);
                            if (gid != UINT64_MAX) last_gamepad_id = (uint32_t)gid;
                        }
                    }
                }
            }
        }
    }
}

// --------------------------------------------------------------- display RPC
static absolute_time_t last_rumble_refresh;
// Display-RPC gating, mirroring the live spec (stadiacast controller.py): the
// GetControllerStateRequest loop is ARMED by v1:ResolveDiscovery
// (on_discovery_resolved -> _start_display_rpc, controller.py:294-308). A display
// RPC sent before the controller's OnConnected registered its RPC reader is
// dropped and once stalled a live controller for good (docs/protocol.md §5.1);
// our old zero-initialised `last_state_req` fired the very first request at
// T0+0..50 ms, ~0.3-0.5 s before OnConnected. After arming, the first request
// waits display_rpc_delay (0.6 s, live preset config.py:111) and the re-sends
// follow display_rpc_interval (1.5 s). If ResolveDiscovery never arrives,
// _display_rpc_fallback (controller.py:604-615) starts the loop anyway - here
// 8 s after the handshake completed.
//
// p3-2340: the DEFAULT trigger is now dtls, not resolve (DISPLAY_RPC_TRIGGER_DTLS
// in config.h): the arm happens DISPLAY_RPC_DTLS_ARM_MS (0.5 s) after the DTLS
// handshake and the first request leaves immediately after that - stadiacast's
// other preset "--display-rpc-trigger dtls --display-rpc-delay 0.6", with 0.5 s.
// The resolve arm (https.c, rtc_display_rpc_arm) still works and can arm slightly
// earlier when ResolveDiscovery beats the 0.5 s; the 8 s fallback stays as
// belt-and-braces. Symptom fixed: boots where the controller never posts
// ResolveDiscovery used to burn the first GCSR round on the fallback timeout
// (white LED -> three yellow/red rounds before connecting).

void rtc_display_rpc_arm(void) {
    if (disp_rpc_armed) return;                  // first ResolveDiscovery only, like _resolved_at
    disp_rpc_armed = true;
    disp_rpc_arm_ms = to_ms_since_boot(get_absolute_time());
    FWLOG("disp rpc arm (resolve-discovery)");
}

static void disp_rpc_reset(void) {               // a dead session must not keep its arm
    disp_rpc_armed = false;
    disp_rpc_arm_ms = 0;
    disp_rpc_hs_ms = 0;
    state_req_sent = false;
    last_state_req_ms = 0;
}

static uint32_t startgame_ticket; static bool startgame_sent;
static uint32_t startgame_logged;   // ticket whose StartGame result line already left

// Wall-clock microseconds in the controller's own clock domain: the SNTP epoch we
// serve (rtc_cert_time_epoch, the SAME source net_infra.c sntp_recv answers with)
// plus uptime - the firmware-side equivalent of controller.py:791
// reply.current_time.display_time_us = int(self.now() * 1_000_000). The controller
// takes its clock from our SNTP replies, so display_time_us must be in that domain;
// the old answer (net_infra_uptime_us(), boot microseconds ~1e8) sat 9 orders of
// magnitude below the epoch microseconds (~1.7e15) the remote_clock compares against.
// Same class of domain error p3-2550 proved fatal on the rumble base timestamp
// ("series acked but the motor never moves").
static uint64_t rtc_wall_us(void) {
    return (uint64_t)rtc_cert_time_epoch() * 1000000ull + net_infra_uptime_us();
}

// D9 / reset_boot_state mirror (controller.py:163-186): a NEW offer from the
// controller means a new boot - the reference cancels all post-DTLS tasks,
// clears the resolved/dtls timestamps and the pending RPC tickets. Called by
// cloud.c extract_offer() whenever an offer is adopted (register or
// DiscoverDisplay). Without this, a session that died without a closing alert
// (silent abandon -> re-registration) left a zombie: handshake_done latched,
// display-RPC arm stale, StartGame sent-flag stuck - and the second ICE round
// never started. Same reset the alert path (dtls_drive) and a fresh
// ClientHello (link_recv) already perform; guarded like reset_boot_state's
// early return (controller.py:170-171) so a first boot is a no-op.
void rtc_reset_display_session(void) {
    if (!Ld.handshake_done && !Ld.final_len && !disp_rpc_armed && !startgame_sent &&
        cloud_state != CLOUD_LINK_UP)
        return;                                   // nothing stale to drop
    FWLOG("dtls disp: session reset (new offer = new boot)");
    mbedtls_ssl_session_reset(&Ld.ssl);
    Ld.handshake_done = false;
    Ld.final_len = 0;
    Ld.rx_len = 0;
    disp_rpc_reset();
    audio_session_reset();
    startgame_sent = false;                       // the next boot must be able to send it again
    startgame_logged = 0;                         // ... and to log a fresh result line
    // fresh display session (reset_boot_state): the GCSR loop gates on CLOUD_LINK_UP,
    // so READY must drop too or a Discover-path offer would leave it stuck.
    if (cloud_state == CLOUD_LINK_UP || cloud_state == CLOUD_READY)
        cloud_state = CLOUD_REGISTERED;
}

static void handle_ctd_request(uint32_t ticket, const uint8_t *pl, int n) {
    pb_it_t it; pbi_init(&it, pl, n);
    int tag = 0;
    while (pbi_next(&it)) if (it.wire == 2) { tag = it.field; break; }
    uint8_t body[80]; pb_out_t o;
    if (tag == CTD_HEARTBEAT) {
        rpc_respond_display(ticket, ST_OK, NULL, 0);
    } else if (tag == CTD_TIME_REQ) {
        int bl; const uint8_t *tr = pb_get_bytes(pl, n, CTD_TIME_REQ, &bl);
        uint64_t ctu = bl ? pb_get_u64(tr, bl, 1, 0) : 0;
        pbo_init(&o, body, sizeof body);
        // Top5 #1: display_time_us = wall clock (SNTP epoch + uptime), not uptime -
        // the controller's remote_clock treats this as the display's "now".
        build_current_time_response(&o, ctu, rtc_wall_us());
        rpc_respond_dtc(ticket, ST_OK, DTC_TIME_RESP, o.buf, o.len);
    } else if (tag == CTD_PROXY_REQ) {
        // `pl` IS the ControllerToDisplay; the proxy request is nested INSIDE it
        // (controller_message.proto: ControllerToDisplay.proxy_request = field 1).
        // Chain, byte-identical to the live reference (controller.py:706 parses the
        // RpcRequest payload AS ControllerToDisplay, _answer_request:806 passes
        // msg.proxy_request to game_session.on_proxy_request, which reads pr.body):
        //   CTD.f1  = ProxyRequest{1:flag, 2:key, 4:body}
        //   body    = inner RpcMessage.f1(request) -> .f2(payload)
        //   payload = StreamerRequest.f1(initialization) -> .f2(offer)
        // The old code read the body at CTD.f4 directly (one level missing: that is
        // audio_configuration_changed, never present) - pb_get_bytes returned NULL at
        // every layer and game_offer stayed all-zero, so our own game ICE checks
        // (gated on game_offer.offer_ufrag) never left the device while the ANSWER
        // still carried our credentials and the controller duly started checking
        // :40001 (it does not need our offer to do that).
        int pl1; const uint8_t *preq = pb_get_bytes(pl, n, CTD_PROXY_REQ, &pl1); // proxy_request
        int dl = -1, rl = -1, il = -1, ol = -1, offl = -1;
        const uint8_t *offr = NULL;
        uint32_t inner_ticket = 0;                 // Top5 #4: RpcRequest.f1, echoed in the
                                                   // inner RpcResponse (game_session.py:288
                                                   // inner_ticket / :374 rpc_response(inner_ticket)).
                                                   // The StreamingClient correlates its proxied
                                                   // request by THIS ticket; the old constant 0
                                                   // is "no ticket" (the reference refuses those
                                                   // outright, controller.py:771-772).
        if (preq) {
            const uint8_t *data = pb_get_bytes(preq, pl1, 4, &dl);               // body
            if (data) {
                const uint8_t *req = pb_get_bytes(data, dl, 1, &rl);             // request
                if (req) {
                    inner_ticket = (uint32_t)pb_get_u64(req, rl, 1, 0);
                    const uint8_t *inner = pb_get_bytes(req, rl, 2, &il);        // payload
                    if (inner) {
                        const uint8_t *infr = pb_get_bytes(inner, il, 1, &ol);   // initialization
                        if (infr) offr = pb_get_bytes(infr, ol, 2, &offl);       // offer
                    }
                }
            }
        }
        // Adopt only a credential-carrying offer (extract_offer's proven pattern): a
        // retry ProxyRequest without an offer must not wipe the game ICE credentials
        // that the whole game link (our checks, the reactive check) hangs off.
        if (offr) {
            sdp_offer_info_t tmp; memset(&tmp, 0, sizeof tmp);
            parse_rtc_sdp_offer(offr, offl, &tmp);
            if (tmp.offer_ufrag[0] && tmp.offer_pwd[0]) {
                memcpy(&game_offer, &tmp, sizeof game_offer);
            } else {
                FWLOG("proxy offer without credentials - keeping ufrag=[%s]",
                      game_offer.offer_ufrag);
            }
        }
        // One line per ProxyRequest: every nesting layer's length (-1 = field absent)
        // plus what the offer parse produced. This is the only place the 198B/324B
        // envelope contents become observable on the device log.
        FWLOG("proxy pr=%d body=%d req=%d pay=%d init=%d offer=%d t=%u uf=[%s] pwlen=%d",
              pl1, dl, rl, il, ol, offl, (unsigned)inner_ticket, game_offer.offer_ufrag,
              game_offer.offer_pwd[0] ? (int)strlen(game_offer.offer_pwd) : 0);
        static uint8_t sr[340]; pb_out_t so; pbo_init(&so, sr, sizeof sr);
        build_streamer_init_response(&so, &game_offer, &cloud_game_creds, cloud_ip_str, PORT_GAME);
        static uint8_t inner2[380]; pb_out_t i2; pbo_init(&i2, inner2, sizeof inner2);
        build_rpc_response(&i2, inner_ticket, ST_OK, so.buf, so.len);
        static uint8_t pr[420]; pb_out_t po; pbo_init(&po, pr, sizeof pr);
        pbo_bytes(&po, 1, i2.buf, i2.len);                     // ProxyResponse{data}
        rpc_respond_dtc(ticket, ST_OK, DTC_PROXY_RESP, po.buf, po.len);
    } else {
        rpc_respond_display(ticket, ST_UNIMPLEMENTED, NULL, 0);
    }
}

static void on_display_rpc(const uint8_t *buf, int len) {
    pb_it_t top; pbi_init(&top, buf, len);
    while (pbi_next(&top)) {
        if (top.field == 1 && top.wire == 2) {                  // request
            uint32_t t = (uint32_t)pb_get_u64(top.body, top.body_len, 1, 0);
            int pl; const uint8_t *payload = pb_get_bytes(top.body, top.body_len, 2, &pl);
            if (payload) handle_ctd_request(t, payload, pl);
        } else if (top.field == 2 && top.wire == 2) {           // response
            uint32_t t = (uint32_t)pb_get_u64(top.body, top.body_len, 1, 0);
            // Top5 #2: GCSR verdict ladder, verbatim from controller.py:735-756 - a
            // response is only a success when code==0 AND the payload variant is
            // controller_state (ControllerToDisplay f2). Anything else (INTERNAL 13
            // from the responder destructor while the controller sits in R/C/
            // WAITING_ACCEPT_COMMAND, a payload the parser rejected, ...) is counted
            // and IGNORED: no READY, no audio attach, no StartGame; the GCSR loop's
            // 1.5 s retry handles it (protocol.md:130-133). The old code took ANY
            // response as READY, so one error reply faked the whole handshake and
            // chained straight into the StartGame storm of Top5 #3.
            uint64_t code = pb_get_u64(top.body, top.body_len, 2, 0);
            int rpl; const uint8_t *rpay = pb_get_bytes(top.body, top.body_len, 4, &rpl);
            int sl;
            bool has_state = rpay && pb_get_bytes(rpay, rpl, CTD_STATE_RESP, &sl) != NULL;
            if (cloud_state == CLOUD_LINK_UP) {
                if (code == ST_OK && has_state) {
                    cloud_state = CLOUD_READY;
                    // Attach the speaker channel on the controller's first state
                    // response, the same moment pc-peer's auto-attach fires
                    // (pc-peer.cjs: audio_attach_sent {auto:true} after the state
                    // response, 60 s re-arm inside).
                    audio_attach_send(2);
                } else {
                    static uint32_t gcsr_errs;
                    gcsr_errs++;
                    if (gcsr_errs <= 6)
                        FWLOG("gcsr resp err: t=%u code=%llu state=%d n=%u (retry 1.5s)",
                              (unsigned)t, (unsigned long long)code, (int)has_state,
                              (unsigned)gcsr_errs);
                }
            }
            // Top5 #3: StartGame result, once per boot (game_session.py:171-231).
            // on_start_game_response only RECORDS {code, error_message} and logs
            // game_started / game_start_failed - it never re-arms the sender, and the
            // latch clears only when a new offer resets the boot
            // (rtc_reset_display_session). The old "clear startgame_sent on any
            // matching response" let a FAILED_PRECONDITION error reply re-arm the
            // 20 ms tick sender into a 50 Hz StartGame storm.
            if (startgame_sent && t == startgame_ticket && startgame_logged != t) {
                startgame_logged = t;
                FWLOG("startgame result: t=%u code=%llu (%s)", (unsigned)t,
                      (unsigned long long)code,
                      code == ST_OK ? "game_started" : "game_start_failed");
            }
        } else if (top.field == 3 && top.wire == 2) {           // notification
            // p3-2050: THE input path. The live 9.46 session (research/e4/sc-run/
            // server.jsonl) proves the controller's input is an RpcNotification
            // {message3} on THIS link (0x74) - READY only, sent on change: its
            // "type":"rpc_input" events are 1:1 with the rpc_in message3 lines and
            // rtp_input count is ZERO, while game_wire_in={0x0066:4} (one
            // registration series only) - exactly the p3-2035 observation.
            // Reference: stadiacast controller.py:731/758 (_on_rpc -> _on_input_rpc).
            uint32_t t = (uint32_t)pb_get_u64(top.body, top.body_len, 1, 0);
            int pl; const uint8_t *payload = pb_get_bytes(top.body, top.body_len, 2, &pl);
            if (payload) {
                int il; const uint8_t *in3 = pb_get_bytes(payload, pl, CTD_INPUT, &il);
                if (in3) {                                       // message3 input report
                    // Message3 (controller_message.proto:237, gamepad.py:97
                    // from_message3): f1 buttons, f2/f3 left stick x/y, f4/f5
                    // right stick x/y (sint32 zigzag), f6/f7 L2/R2 triggers
                    // 0..255. Live sample {"f1":0,"f2".."f5":0,"f6":2,"f7":0}
                    // decoded as triggers {l:2, r:0} - the map below matches.
                    pad_state_t p = {0};
                    p.buttons = (uint32_t)pb_get_u64(in3, il, 1, 0);
                    int64_t x;
                    x=(int64_t)pb_get_u64(in3,il,2,0); p.lx=(int16_t)(((uint32_t)x>>1)^(uint32_t)(-(x&1)));
                    x=(int64_t)pb_get_u64(in3,il,3,0); p.ly=(int16_t)(((uint32_t)x>>1)^(uint32_t)(-(x&1)));
                    x=(int64_t)pb_get_u64(in3,il,4,0); p.rx=(int16_t)(((uint32_t)x>>1)^(uint32_t)(-(x&1)));
                    x=(int64_t)pb_get_u64(in3,il,5,0); p.ry=(int16_t)(((uint32_t)x>>1)^(uint32_t)(-(x&1)));
                    p.lt=(uint8_t)pb_get_u64(in3,il,6,0);
                    p.rt=(uint8_t)pb_get_u64(in3,il,7,0);
                    // p3-2035 and earlier parsed this but committed pad SILENTLY -
                    // the branch has never produced a log line, so "input does not
                    // arrive" was indistinguishable from "arrives invisibly".
                    // One line per message3 (sparse by definition: on-change only).
                    static int logged;
                    if (logged < 60) {
                        logged++;
                        FWLOG("disp in3: t=%u il=%d btn=%06x l=%d,%d r=%d,%d trg=%u,%u",
                              (unsigned)t, il, p.buttons, (int)p.lx, (int)p.ly,
                              (int)p.rx, (int)p.ry, p.lt, p.rt);
                    }
                    pad_commit(&p, "disp3");
                } else {
                    // A notification that is NOT message3 (f4 audio_configuration_
                    // changed, f6 streaming_stopped, ...): tag + size so the
                    // notification surface is visible without a hex dump.
                    static int nf;
                    if (nf < 12) {
                        nf++;
                        pb_it_t vit; pbi_init(&vit, payload, pl); int vtag = 0;
                        while (pbi_next(&vit)) if (vit.wire == 2) { vtag = vit.field; break; }
                        FWLOG("disp notif: t=%u pl=%d tag=%d", (unsigned)t, pl, vtag);
                    }
                }
            }
        }
    }
}

static void on_display_frame(uint8_t *f, int n) {
    // p3-2050 content visibility: the display link used to be a black hole - any
    // record that was not a well-formed 0x74 vanished without a single log line.
    // The known chatty sizes are 16B (heartbeat tag14 request) and 19/22B (time
    // tag18 request; the controller_time_us varint makes the length), so every
    // OTHER size dumps the whole record (budget 20, two lines past 24B, like
    // on_game_frame). NOTE the size collision: a message3 input notification is
    // 16-25B (single button ~= 19B) - pico-log-20261104-201526.txt has a 23B
    // display record nobody could identify - so size alone never proves/kills
    // "input arrived"; the on_display_rpc notification lines ("disp in3:" /
    // "disp notif:") discriminate by RPC kind, this dump settles everything else.
    {
        static int dumped;
        if (n != 16 && n != 19 && n != 22 && dumped < 20) {
            dumped++;
            uint16_t wid = n >= 4 ? (uint16_t)(f[2] | (f[3] << 8)) : 0;
            char hx[64]; int o = 0;
            int nb0 = n < 24 ? n : 24;
            for (int i = 0; i < nb0; i++)
                o += snprintf(hx + o, sizeof hx - o, "%02x", f[i]);
            hx[o] = 0;
            FWLOG("dispframe n=%d id=0x%04x %s", n, wid, hx);
            if (n > 24) {
                char hx2[64]; int o2 = 0;
                int nb = n < 48 ? n : 48;
                for (int i = 24; i < nb; i++)
                    o2 += snprintf(hx2 + o2, sizeof hx2 - o2, "%02x", f[i]);
                hx2[o2] = 0;
                FWLOG("dispframe2 %s", hx2);
            }
        }
    }
    if (n < 8) return;
    // Mirror the reference parser (stadiacast/rtc/wire.py parse_wire_message):
    //   * header version nibble (byte0 >> 4) must be 0
    //   * 24-bit total length must be >= 8 and must not exceed the record we got
    // Without this a malformed/merged record would be handed to the protobuf parser.
    if ((f[0] >> 4) != 0) return;
    uint32_t total = (uint32_t)f[4] | ((uint32_t)f[5] << 8) | ((uint32_t)f[6] << 16);
    if (total < 8 || (int)total > n) return;
    uint16_t id = f[2] | (f[3] << 8);
    if (id == WID_CTRL_RPC) on_display_rpc(f + 8, (int)total - 8);
}

static void on_game_frame(uint8_t *f, int n) {
    if (n < 8) return;
    uint16_t id = f[2] | (f[3] << 8);
    // p3-2000-input dump: the whole record (two lines for >24 B), budget 30, and the
    // series sequence_number of every 0x66 frame parsed out separately - "is the
    // controller retransmitting seq=1 or is a NEW series arriving" is THE diagnostic of
    // the input stall, and the old 16-byte/10-frame dump answered neither (the budget
    // was always eaten by seq=1 dupes before anything else happened). The full bytes
    // also decide what the 32 B registration frame carries (f4 messages present or an
    // empty heartbeat series) without another flash.
    {
        static int dumped;
        int dump = 0;
        if (id == WID_INPUT) { if (dumped < 30) dump = 1; }
        else {                                     // first 3 of every other wire id
            static uint16_t seen_id[4]; static int seen_n[4]; int s = -1;
            for (int i = 0; i < 4; i++) if (seen_id[i] == id) s = i;
            if (s < 0) for (int i = 0; i < 4; i++) if (!seen_n[i]) { s = i; seen_id[s] = id; }
            if (s >= 0 && seen_n[s] < 3) { seen_n[s]++; dump = 1; }
        }
        if (dump) {
            dumped++;
            uint32_t seq = 0;
            if (id == WID_INPUT) {
                // best-effort on the WH2 payload (NOT the record: the 8-byte header
                // would derange the parse): bare InputProtocolMessage{7: series{2: seq}};
                // an RTP-wrapped frame parses as 0 - the hex dump shows the truth
                int pl; const uint8_t *body = pb_get_bytes(f + 8, n - 8, 7, &pl);
                if (body) seq = (uint32_t)pb_get_u64(body, pl, 2, 0);
            }
            char hx[64]; int o = 0;
            int nb0 = n < 24 ? n : 24;
            for (int i = 0; i < nb0; i++)
                o += snprintf(hx + o, sizeof hx - o, "%02x", f[i]);
            hx[o] = 0;
            FWLOG("gameframe n=%d id=0x%04x seq=%u %s", n, id, (unsigned)seq, hx);
            if (n > 24) {
                char hx2[64]; int o2 = 0;
                int nb = n < 48 ? n : 48;
                for (int i = 24; i < nb; i++)
                    o2 += snprintf(hx2 + o2, sizeof hx2 - o2, "%02x", f[i]);
                hx2[o2] = 0;
                FWLOG("gameframe2 %s", hx2);
            }
        }
        // A NEW sequence number is the milestone line: never rate-limited away (it can
        // only happen as often as the controller sends new input).
        if (id == WID_INPUT) {
            static uint32_t last_seq; static bool have_seq;
            int pl; const uint8_t *body = pb_get_bytes(f + 8, n - 8, 7, &pl);
            if (body) {
                uint32_t seq = (uint32_t)pb_get_u64(body, pl, 2, 0);
                if (seq && (!have_seq || seq != last_seq)) {
                    FWLOG("gseq: %u -> %u (new series)", (unsigned)(have_seq ? last_seq : 0),
                          (unsigned)seq);
                    last_seq = seq; have_seq = true;
                }
            }
        }
    }
    if (id == WID_INPUT) on_game_input(f + 8, n - 8);
    else if (id == WID_CTRL_RPC || id == WID_GAME_RPC || id == 0x0076) {       // game RPC -> empty OK
        pb_it_t top; pbi_init(&top, f + 8, n - 8);
        while (pbi_next(&top)) if (top.field == 1 && top.wire == 2) {
            uint32_t t = (uint32_t)pb_get_u64(top.body, top.body_len, 1, 0);
            uint8_t msg[80]; pb_out_t o; pbo_init(&o, msg, sizeof msg);
            build_rpc_response(&o, t, ST_OK, NULL, 0);
            // Reply id mirrors the request exactly like the reference
            // (game_session.py:746): 0x74 -> 0x75, otherwise the SAME id (0xFFFA ->
            // 0xFFFA). p3-1435 always replied on 0xFFFA, which drops the reply of any
            // request the controller sends on 0x74. (In the live 9.46 session the
            // controller never used the game RPC channel at all - game_wire_in was
            // {0x0066: 4} - so this branch is unexercised alignment, not a fix.)
            uint16_t rid = (id == WID_CTRL_RPC) ? WID_DISP_RPC : id;
            int w = wh2_send(&Lg, rid, o.buf, o.len);
            { static int rpc_log; if (rpc_log < 8) { rpc_log++;
              FWLOG("game rpc: in id=0x%04x ticket=%u -> reply id=0x%04x w=%d",
                    id, (unsigned)t, rid, w); } }
        }
    }
}

// --------------------------------------------------------------- udp recv
static void link_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port) {
    link_t *L = (link_t *)arg;
    if (p->len >= 20) {
        uint8_t *m = (uint8_t *)p->payload;
        if (!(m[0] == 0 && m[1] == 1) && !(m[0] >= 20 && m[0] <= 23)) {
            // Anything that is neither a STUN request nor a DTLS record. A binding
            // SUCCESS here would prove our own connectivity checks reach the peer.
            static int logged_other;
            if (logged_other < 6) { logged_other++; FWLOG("udp %s: other type=%02x%02x len=%u", L->name, m[0], m[1], (unsigned)p->len); }
        }
        if (m[0] == 0 && m[1] == 1) {                            // STUN request
            ip4_addr_copy(L->peer, *ip_2_ip4(addr)); L->peer_port = port; L->have_peer = true;
            uint8_t resp[96];
            {   // Decode the request's USERNAME: it must contain OUR ufrag. If it does not,
                // the SDP answer we advertised carried different ICE credentials.
                char un[48] = ""; int ul = 0;
                int off = 20;
                while (off + 4 <= (int)p->len) {
                    uint16_t at = (uint16_t)((m[off] << 8) | m[off+1]);
                    uint16_t al = (uint16_t)((m[off+2] << 8) | m[off+3]);
                    if (at == 0x0006) {
                        int n2 = al < (int)sizeof un - 1 ? al : (int)sizeof un - 1;
                        memcpy(un, m + off + 4, (size_t)n2); un[n2] = 0; ul = n2; break;
                    }
                    off += 4 + ((al + 3) & ~3);
                }
                // Everything needed to decide the MESSAGE-INTEGRITY key in one line:
                // the USERNAME the controller used, plus both credential pairs.
                // Which attributes did the controller put in its check? ICE nomination is
                // carried by USE-CANDIDATE (0x0025); the role by ICE-CONTROLLING (0x802A) /
                // ICE-CONTROLLED (0x8029). Without this we cannot tell whether it is
                // nominating us - and the controller only starts DTLS after nomination.
                int has_uc = 0, has_cl = 0, has_cd = 0, has_pr = 0;
                {
                    int o2 = 20;
                    while (o2 + 4 <= (int)p->len) {
                        uint16_t a2 = (uint16_t)((m[o2] << 8) | m[o2+1]);
                        uint16_t l2 = (uint16_t)((m[o2+2] << 8) | m[o2+3]);
                        if (a2 == 0x0025) has_uc = 1;
                        else if (a2 == 0x802A) has_cl = 1;
                        else if (a2 == 0x8029) has_cd = 1;
                        else if (a2 == 0x0024) has_pr = 1;
                        o2 += 4 + (((int)l2 + 3) & ~3);
                    }
                }
                FWLOG("stun %s: user=[%s] UC=%d CONTROLLING=%d CONTROLLED=%d PRIO=%d",
                      L->name, un, has_uc, has_cl, has_cd, has_pr);
            }
            int rl = stun_make_response(resp, m, p->len, ip_2_ip4(addr), port, L->our_pwd);
            // Reference behaviour (endpoint.py:343-344): once a peer's check verifies we
            // immediately send our own check to that address, before DTLS.
            {
                uint32_t r2 = get_rand_32();
                uint8_t tx2[12];
                for (int i = 0; i < 12; i++) tx2[i] = (uint8_t)(r2 >> ((i & 3) * 8));
                uint8_t chk[160];
                const sdp_offer_info_t *oi = (L == &Ld) ? &cloud_offer : &game_offer;
                const char *opwd = oi->offer_pwd[0] ? oi->offer_pwd : L->our_pwd;
                // USERNAME local part must be THIS link's own ufrag: the peer checks it
                // against the answer we advertised for this link. The hardcoded display
                // ufrag was fine for Ld but would send the game link's checks with the
                // WRONG local name (answer says game creds), and the controller rejects
                // those with 401. The rtc_tick driver already uses the right one per link.
                const char *lufrag = (L == &Ld) ? cloud_disp_creds.ufrag : cloud_game_creds.ufrag;
                if (oi->offer_ufrag[0]) {
                    int cn = stun_make_request(chk, oi->offer_ufrag, lufrag, opwd, tx2);
                    udp_send_link(L, chk, cn);
                }
            }
            {   // Dump the actual response bytes (two lines) - the controller rejects it and
                // the only way to see why is to look at what we put on the wire.
                static int dumped;
                if (dumped < 2) {
                    dumped++;
                    char h1[80], h2[80]; int o1 = 0, o2 = 0;
                    for (int i = 0; i < rl && i < 32 && o1 < 76; i++) o1 += snprintf(h1+o1, sizeof h1-o1, "%02x", resp[i]);
                    for (int i = 32; i < rl && o2 < 76; i++) o2 += snprintf(h2+o2, sizeof h2-o2, "%02x", resp[i]);
                    h1[o1] = 0; h2[o2] = 0;
                    FWLOG("sresp1=%s", h1);
                    FWLOG("sresp2=%s", h2);
                }
            }
            FWLOG("stun %s: req %d.%d.%d.%d:%u len=%u -> resp len=%d pwd_len=%d",
                  L->name, ip4_addr1(ip_2_ip4(addr)), ip4_addr2(ip_2_ip4(addr)),
                  ip4_addr3(ip_2_ip4(addr)), ip4_addr4(ip_2_ip4(addr)), (unsigned)port,
                  (unsigned)p->len, rl, L->our_pwd ? (int)strlen(L->our_pwd) : -1);
            struct pbuf *rp = pbuf_alloc(PBUF_TRANSPORT, rl, PBUF_RAM);
            if (!rp) {
                FWLOG("stun %s: pbuf_alloc(%d) failed", L->name, rl);
            } else {
                memcpy(rp->payload, resp, rl);
                err_t se = udp_sendto(pcb, rp, addr, port);
                if (se != ERR_OK) FWLOG("stun %s: send err=%d", L->name, (int)se);
                pbuf_free(rp);
            }
        } else if (m[0] >= 20 && m[0] <= 23) {                   // DTLS record
            // Post-handshake epoch-0 handshake records: either a retransmitted client
            // flight2 (answer: resend our buffered final flight - mbedtls never does) or
            // a fresh ClientHello from a controller restart (answer: rebuild the session).
            // Record header: type(1) ver(2) epoch(2) seq(6) len(2); m[13] = first
            // handshake message type (1 = ClientHello).
            if (L->handshake_done && m[0] == 22 && p->len >= 14 && m[3] == 0 && m[4] == 0) {
                if (m[13] == 1) {
                    FWLOG("dtls %s: new ClientHello after done - resetting session", L->name);
                    mbedtls_ssl_session_reset(&L->ssl);
                    L->handshake_done = false;
                    L->final_len = 0;
                    L->rx_len = 0;
                    if (L == &Ld) { disp_rpc_reset(); audio_session_reset(); }
                } else if (L->final_len > 0) {
                    static uint32_t last_resend;
                    uint32_t now = to_ms_since_boot(get_absolute_time());
                    FWLOG("dtls %s: dup flight2 - resending final flight %d bytes%s", L->name,
                          L->final_len, (now - last_resend) < 300 ? " (rate)" : "");
                    last_resend = now;
                    udp_send_link(L, L->final_, L->final_len);
                    pbuf_free(p);      // duplicate: do not feed the finished session
                    return;
                }
            }
            {
                static int dtls_in;
                if (dtls_in < 12) {
                    dtls_in++;
                    FWLOG("dtls %s: record type=%u ver=%02x%02x epoch=%u len=%u hs=%d",
                          L->name, m[0], m[1], m[2], (unsigned)((m[3] << 8) | m[4]), (unsigned)p->len,
                          L->handshake_done ? 1 : 0);
                    // Alerts decide the diagnosis: epoch=1 encrypted alert means the
                    // controller DID finish its handshake and is closing at the app layer;
                    // epoch=0 means it never accepted our final flight. Dump the header.
                    if (m[0] == 21 && p->len >= 16) {
                        char hx[40]; int o = 0;
                        for (int i = 0; i < 16; i++)
                            o += snprintf(hx + o, sizeof hx - o, "%02x", m[i]);
                        FWLOG("alert16=%s", hx);
                    }
                    // A ClientHello fully determines what the peer will accept: cipher
                    // suites, extensions, DTLS version. Dump it so the negotiation can be
                    // analysed offline instead of guessed at.
                    if (m[0] == 22 && p->len >= 14 && m[13] == 1) {
                        int total = (int)p->len < 156 ? (int)p->len : 156;
                        for (int blk = 0; blk < 3; blk++) {
                            int from = blk * 52;
                            if (from >= total) break;
                            int to = from + 52; if (to > total) to = total;
                            char hx[120]; int o = 0;
                            for (int i = from; i < to; i++)
                                o += snprintf(hx + o, sizeof hx - o, "%02x", m[i]);
                            hx[o] = 0;
                            FWLOG("chello%d=%s", blk, hx);
                        }
                    }
                }
            }
            ip4_addr_copy(L->peer, *ip_2_ip4(addr)); L->peer_port = port; L->have_peer = true;
            if (p->len > (int)sizeof L->rx) {
                // was silently dropped before
                FWLOG("dtls %s: datagram %d > rx buffer %d, dropped",
                      L->name, (int)p->len, (int)sizeof L->rx);
            } else {
                if (L->rx_len + p->len > (int)sizeof L->rx) {
                    // old code did memmove(...,0) (a no-op) then overwrote from the start
                    FWLOG("dtls %s: rx backlog %d + %d overflows, resetting backlog",
                          L->name, L->rx_len, (int)p->len);
                    L->rx_len = 0;
                }
                memcpy(L->rx + L->rx_len, m, p->len);
                L->rx_len += (int)p->len;
                dtls_drive(L);
            }
        }
    }
    pbuf_free(p);
}

// mbedtls BIO against our UDP pcb
static int bio_send(void *ctx, const unsigned char *buf, size_t len) {
    link_t *L = (link_t *)ctx;
    if (L->pkt_len + (int)len > (int)sizeof L->pkt) {
        // Do NOT pretend this was sent. Previously the record was dropped silently and
        // len was returned, so mbedtls believed the handshake flight went out while the
        // peer received nothing - a guaranteed stall. Our 3-certificate chain makes the
        // DTLS Certificate flight several KB, which is exactly this case unless the MTU
        // is capped (see mbedtls_ssl_set_mtu in link_setup).
        FWLOG("dtls %s: TX RECORD TOO BIG len=%u pkt_len=%d", L->name, (unsigned)len, L->pkt_len);
        return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    }
    memcpy(L->pkt + L->pkt_len, buf, len);
    L->pkt_len += (int)len;
    return (int)len;
}

// ---- DTLS self test -------------------------------------------------------------
// Runs a full client<->server handshake entirely inside the firmware, over memory
// queues, at boot. This separates "our DTLS configuration is wrong" from "the peer is
// doing something unusual" without needing a controller or a network. It also proves
// the certificate/key pair, the negotiated cipher suite and the DTLS version work.
typedef struct { uint8_t buf[4096]; int len; } mq_t;
static mq_t mq_c2s, mq_s2c;
static mbedtls_ssl_context st_s, st_c;
static mbedtls_timing_delay_context st_timers_s, st_timers_c;

static int st_send_c(void *ctx, const unsigned char *b, size_t n) {
    (void)ctx; if (mq_c2s.len + (int)n > (int)sizeof mq_c2s.buf) return MBEDTLS_ERR_SSL_WANT_WRITE;
    memcpy(mq_c2s.buf + mq_c2s.len, b, n); mq_c2s.len += (int)n; return (int)n;
}
static int st_send_s(void *ctx, const unsigned char *b, size_t n) {
    (void)ctx; if (mq_s2c.len + (int)n > (int)sizeof mq_s2c.buf) return MBEDTLS_ERR_SSL_WANT_WRITE;
    memcpy(mq_s2c.buf + mq_s2c.len, b, n); mq_s2c.len += (int)n; return (int)n;
}
static int st_recv_c(void *ctx, unsigned char *b, size_t n) {
    (void)ctx; if (mq_s2c.len <= 0) return MBEDTLS_ERR_SSL_WANT_READ;
    int k = (int)n < mq_s2c.len ? (int)n : mq_s2c.len;
    memcpy(b, mq_s2c.buf, (size_t)k); memmove(mq_s2c.buf, mq_s2c.buf + k, (size_t)(mq_s2c.len - k));
    mq_s2c.len -= k; return k;
}
static int st_recv_s(void *ctx, unsigned char *b, size_t n) {
    (void)ctx; if (mq_c2s.len <= 0) return MBEDTLS_ERR_SSL_WANT_READ;
    int k = (int)n < mq_c2s.len ? (int)n : mq_c2s.len;
    memcpy(b, mq_c2s.buf, (size_t)k); memmove(mq_c2s.buf, mq_c2s.buf + k, (size_t)(mq_c2s.len - k));
    mq_c2s.len -= k; return k;
}

// Boot logs are dropped while USB is enumerating, so the result is kept here and
// reported by the heartbeat: 0 = not run, 1 = PASS, negative = mbedtls error.
int g_dtls_selftest;
static volatile bool g_selftest_req;
void rtc_request_dtls_selftest(void) { g_selftest_req = true; }
int rtc_dtls_selftest(void) { return g_dtls_selftest; }

void dtls_self_test(void) {
    // DISABLED: the in-firmware loopback handshake floods the CDC log ring with mbedtls
    // debug lines and wedges the main loop, which also stalls the network stack. The
    // real handshake against the controller (which logs through the same debug hook)
    // gives the same information without that risk.
    FWLOG("dtlssel: disabled (use the live handshake trace)");
    g_dtls_selftest = 0;
}

static void link_setup(link_t *L, const char *name, uint16_t port, const char *pwd) {
    memset(L, 0, sizeof *L);
    L->name = name; L->port = port; L->our_pwd = pwd;
    mbedtls_ssl_init(&L->ssl);
    mbedtls_ssl_config_init(&L->conf);
    // Every one of these can fail (heap exhaustion being the realistic one with three
    // SSL contexts alive). They used to be ignored, which left the link permanently
    // unable to handshake with no trace in the log.
    int r1 = mbedtls_ssl_config_defaults(&L->conf, MBEDTLS_SSL_IS_SERVER,
                                         MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_rng(&L->conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_authmode(&L->conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_debug_set_threshold(3);
    mbedtls_ssl_conf_dbg(&L->conf, dtls_dbg_cb, NULL);
    mbedtls_ssl_conf_ca_chain(&L->conf, &chain, NULL);
    int r2 = mbedtls_ssl_conf_own_cert(&L->conf, &chain_leaf, &pkey_leaf);
    int r3 = mbedtls_ssl_setup(&L->ssl, &L->conf);
    if (r1 || r2 || r3) {
        FWLOG("dtls %s: INIT FAILED defaults=%d cert=%d setup=%d", name, r1, r2, r3);
    }
    mbedtls_ssl_set_bio(&L->ssl, L, bio_send, dtls_bio_recv, NULL);
    mbedtls_ssl_conf_dtls_cookies(&L->conf, NULL, NULL, NULL);   // LAN: no cookie exchange
    // use_srtp: the controller's ClientHello demands it (profile 0x0001) and the
    // verified reference (OpenSSL, stadiacast DEFAULT_SRTP_PROFILES) always echoes the
    // extension in its ServerHello. Without it the controller completes the handshake,
    // then silently abandons the session (close_notify, no error code - 2026-11-04
    // four rejected final flights). We do not use the SRTP keys yet (no audio), but the
    // negotiated extension is what the peer needs to accept the session.
    {
        static const uint16_t srtp_prof[] = { MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_80,
                                              MBEDTLS_TLS_SRTP_UNSET };
        int r4 = mbedtls_ssl_conf_dtls_srtp_protection_profiles(&L->conf, srtp_prof);
        if (r4) FWLOG("dtls %s: srtp profiles refused rc=%d", name, r4);
    }
    // Capture the handshake's exporter material on the display link: the speaker path
    // derives its SRTP keys from it after the handshake completes.
    if (L == &Ld) mbedtls_ssl_conf_export_keys_ext_cb(&L->conf, dtls_export_keys_cb, L);
    mbedtls_ssl_session_reset(&L->ssl);
    // Cap the DTLS record/MTU so mbedtls fragments handshake flights that exceed one
    // datagram. Without this the Certificate message carrying our 3-cert chain (~4 KB)
    // is emitted as oversized records, which bio_send would have to drop. Set AFTER
    // session_reset so the value is not overwritten.
    mbedtls_ssl_set_mtu(&L->ssl, 1200);
    // Correct mbedTLS 2.28 API. The previous line called mbedtls_ssl_set_timer(), which is
    // an INTERNAL 2-argument function declared only in ssl_internal.h:
    //     void mbedtls_ssl_set_timer(mbedtls_ssl_context *ssl, uint32_t millisecs);
    // Because that header is not included here, the implicit-declaration rule let the
    // 4-argument call through and the compiler passed &L->timers (a POINTER) where a
    // uint32_t delay belonged. The real registration entry point,
    // mbedtls_ssl_set_timer_cb(), therefore never ran, so DTLS retransmission timers
    // were never wired up at all. Register them after session_reset.
    mbedtls_ssl_set_timer_cb(&L->ssl, &L->timers, mbedtls_timing_set_delay, mbedtls_timing_get_delay);
    L->pcb = udp_new();
    if (!L->pcb) {
        // 2026-11-04 live repro (p3-1425): with MEMP_NUM_UDP_PCB=4 the game link was
        // the FIFTH udp_new() of boot and got NULL here; udp_bind/udp_recv then
        // return ERR_ARG via LWIP_ERROR whose printf is lost while the CDC port is
        // still enumerating, so a dead game endpoint looked exactly like "the
        // controller never checks us". Log it loudly AND expose it through the
        // heartbeat (rtc_pcb_mask) so a lost boot line can never hide it again.
        FWLOG("bind %s port=%u FAILED - udp_new returned NULL (UDP pcb pool exhausted)", name, port);
    } else {
        err_t be = udp_bind(L->pcb, IP_ADDR_ANY, port);
        FWLOG("bind %s port=%u err=%d", name, port, (int)be);
        udp_recv(L->pcb, link_recv, L);
    }
}

// Heartbeat-visible UDP endpoint health: bit0 = display :40000, bit1 = game :40001.
// 3 = both bound. Printed every 15 s because the one-shot bind FWLOG lines are lost
// whenever the log port opens after boot - which is how a NULL game pcb stayed
// invisible for a full day of logs.
int rtc_pcb_mask(void) { return (Ld.pcb ? 1 : 0) | (Lg.pcb ? 2 : 0); }

// SHA-256 fingerprint of the leaf certificate in the SDP wire format:
//   "sha-256 " + 32 bytes as upper-case hex joined by ':'  (103 chars + NUL)
static void make_cert_fingerprint(const mbedtls_x509_crt *crt, char *out, int cap) {
    unsigned char md[32];
    out[0] = 0;
    // NB mbedtls_sha256() is the deprecated void form in mbedTLS 2.x; use _ret.
    if (mbedtls_sha256_ret(crt->raw.p, crt->raw.len, md, 0) != 0) return;
    int n = snprintf(out, (size_t)cap, "sha-256 ");
    for (int i = 0; i < 32 && n > 0 && n < cap - 4; i++)
        n += snprintf(out + n, (size_t)(cap - n), (i ? ":%02X" : "%02X"), (unsigned)md[i]);
}

void dtls_self_test(void);

void rtc_init(void) {
    stun_selftest();          // mechanical byte-level check against the RFC reference
    mbedtls_x509_crt_init(&chain); mbedtls_x509_crt_init(&chain_leaf);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy); mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    int rc_entropy = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    int rc_cert = mbedtls_x509_crt_parse(&chain, TLS_CERT_PEM, TLS_CERT_PEM_len);
    // p3-3654: DTLS identity = THE SAME upstream GTS credential as HTTPS.
    // Rationale: the controller compares the SDP a=fingerprint against the DTLS
    // certificate and (empirically, 2026-11-08) rejects a session whose DTLS
    // identity does not share the GTS chain it just validated on :443 - the
    // handshake stops after our final flight ("final flight timer resend #2/#3")
    // and the controller goes silent with a white LED. stadiacast (the reference)
    // serves one credential for BOTH paths; we now do the same. The old
    // self-signed EC leaf (TLS_EC_*) stays compiled for the fallback build.
#if DTLS_IDENTITY_UPSTREAM
    // p3-3655: serve the LEAF ONLY on DTLS (same GTS leaf/key/fingerprint as
    // HTTPS - one identity - but a ~1.3 KB single-datagram flight). mbedTLS 2.28
    // does not fragment our DTLS handshake flight (observed: one 4344 B datagram
    // = IP fragments), and the controller just retransmits its ClientHello
    // forever instead of reassembling - the old RSA-leaf failure mode.
    // DTLS-SRTP never validates chains (identity = SDP fingerprint match), so
    // the intermediates are irrelevant to the peer; HTTPS keeps serving them.
    int rc_leaf = mbedtls_x509_crt_parse(&chain_leaf, TLS_LEAF_PEM, TLS_LEAF_PEM_len);
#else
    // DTLS uses an ECDSA P-256 certificate: DER 427 bytes instead of the RSA leaf's 1301,
    // which keeps the whole ServerHello flight (~660 B) inside ONE datagram. With the RSA
    // leaf the flight is 1876-1926 B, needs IP fragments, and the controller never
    // completes the handshake (it just retransmits its ClientHello).
    int rc_leaf = mbedtls_x509_crt_parse(&chain_leaf, TLS_EC_CERT_PEM, TLS_EC_CERT_PEM_len);
#endif
    mbedtls_pk_init(&pkey_leaf);
#if DTLS_IDENTITY_UPSTREAM
    int rc_leafkey = mbedtls_pk_parse_key(&pkey_leaf, TLS_KEY_PEM, TLS_KEY_PEM_len, NULL, 0);
#else
    int rc_leafkey = mbedtls_pk_parse_key(&pkey_leaf, TLS_EC_KEY_PEM, TLS_EC_KEY_PEM_len, NULL, 0);
#endif
    FWLOG("rtc: ec cert=%d key=%d", rc_leaf, rc_leafkey);
    FWLOG("rtc: leaf=%d", rc_leaf);
    int rc_key  = mbedtls_pk_parse_key(&pkey, TLS_KEY_PEM, TLS_KEY_PEM_len, NULL, 0);
    rtc_cert_rc = rc_cert; rtc_key_rc = rc_key;
    FWLOG("rtc: drbg=%d cert=%d key=%d", rc_entropy, rc_cert, rc_key);
    // Both parses report "invalid format", so probe the PEM layer directly: this tells us
    // whether the header is even recognised and confirms the buffer really starts with it.
    {
        mbedtls_pem_context pem; mbedtls_pem_init(&pem); size_t use_len = 0;
        int prc = mbedtls_pem_read_buffer(&pem, "-----BEGIN CERTIFICATE-----",
                                          "-----END CERTIFICATE-----", TLS_CERT_PEM, NULL, 0, &use_len);
        FWLOG("rtc: pemprobe rc=%d used=%u len=%u head=[%c%c%c%c%c%c%c%c]",
              prc, (unsigned)use_len, TLS_CERT_PEM_len,
              TLS_CERT_PEM[0], TLS_CERT_PEM[1], TLS_CERT_PEM[2], TLS_CERT_PEM[3],
              TLS_CERT_PEM[4], TLS_CERT_PEM[5], TLS_CERT_PEM[6], TLS_CERT_PEM[7]);
        mbedtls_pem_free(&pem);
    }
    // The SDP answer must carry "sha-256 XX:XX:..." of OUR leaf certificate; the
    // controller verifies the DTLS certificate against it. Previously this was never
    // filled in at all (a function "called by dtls.c" that does not exist), so the
    // answer advertised an EMPTY fingerprint and the handshake could not succeed.
    char fp[128] = "";
    if (chain.raw.len > 0) {
        make_cert_fingerprint(&chain_leaf, fp, sizeof fp);
        cloud_set_fingerprint(fp);
    }
    FWLOG("rtc: cert=%d key=%d fp=%s", rc_cert, rc_key, fp[0] ? fp : "(NONE)");
    // Pick a clock inside the leaf certificate's validity and publish it via SNTP.
    if (chain.raw.len > 0) {
        int64_t from = civil_epoch(&chain.valid_from);
        int64_t to   = civil_epoch(&chain.valid_to);
        int64_t mid  = (from + to) / 2;
        if (mid > 0) cert_time_epoch = (uint32_t)mid;
        FWLOG("rtc: sntp clock=%u (cert valid %04d-%02d-%02d .. %04d-%02d-%02d)",
              (unsigned)cert_time_epoch, chain.valid_from.year, chain.valid_from.mon,
              chain.valid_from.day, chain.valid_to.year, chain.valid_to.mon, chain.valid_to.day);
    }
    link_setup(&Ld, "disp", PORT_DISPLAY, cloud_disp_creds.pwd);
    link_setup(&Lg, "game", PORT_GAME, cloud_game_creds.pwd);
    // p3-3641: create the CORE0 Opus encoder and pre-encode the silence fallback
    // NOW, before main.c logs heap headroom. The first opus_encode() arms
    // libopus's pseudostack (p3-3646: a static 48 KiB .bss buffer, no heap) and
    // prints its measured depth, so the heap log that follows is the real pool.
    usb_audio_encoder_init();
    // Boot defaults for the audio stream state (seq=1, marker armed): static storage
    // would zero-start the first tone with seq=0 and no marker bit.
    audio_session_reset();
}

void rtc_tick(void) {
    // Run the DTLS self test when the host asks for it over the CDC port, so its log is
    // guaranteed to reach a connected terminal instead of being dropped at boot.
    if (g_selftest_req) { g_selftest_req = false; dtls_self_test(); }

    // p3-3600-dualcore: rumble frames arrive from core1's XInput OUT callback and
    // are queued in ipc.c; commit them into the rumble state here, before the flush
    // block below, so a fresh game-rumble frame leaves on THIS tick.
    { uint16_t l, r; while (ipc_rumble_pop(&l, &r)) rumble_set(l, r); }

    // Proactive final-flight retransmit, OpenSSL-style timer (endpoint.py _arm_dtls_timer):
    // the reactive resend-on-dup loses the race when the controller's retransmission
    // timeout fires before our answer crosses the wire (2026-11-04 00:0x: its encrypted
    // alert beat our resend by a hair). Three tries at 0.5/1.5/3.5 s, then stay quiet;
    // the dup-flight2 handler remains as backstop.
    {
        static uint32_t done_at; static int tries;
        if (Ld.handshake_done && Ld.final_len > 0) {
            uint32_t now = to_ms_since_boot(get_absolute_time());
            if (!done_at) { done_at = now ? now : 1; tries = 0; }
            uint32_t dt = now - done_at;
            if ((tries == 0 && dt >= 500) || (tries == 1 && dt >= 1500) ||
                (tries == 2 && dt >= 3500)) {
                tries++;
                FWLOG("dtls disp: final flight timer resend #%d (%u ms)", tries, dt);
                udp_send_link(&Ld, Ld.final_, Ld.final_len);
            }
        } else { done_at = 0; tries = 0; }
    }
    // READY driver: GetControllerStateRequest until answered, but only after the
    // display RPC is armed (see disp_rpc_armed above). Cadence mirrors _display_rpc_loop
    // (controller.py:617-643): first request display_rpc_delay (0.6 s, live preset) after
    // the arm, re-sends every display_rpc_interval (1.5 s). The old code keyed off a
    // zero-initialised `last_state_req`, so the first request left at T0+0..50 ms -
    // before the controller's OnConnected - which the live spec records as dropped
    // (protocol.md §5.1, tests/test_boot_flow.py:252 live-stall repro).
    if (cloud_state == CLOUD_LINK_UP && Ld.handshake_done) {
        uint32_t now_ms = to_ms_since_boot(get_absolute_time());
#if DISPLAY_RPC_TRIGGER_DTLS
        // p3-2340: trigger=dtls (the stadiacast LIVE preset family, docs/protocol.md
        // §5.1: OnConnected lands ~0.5 s after the handshake and a first request at
        // DTLS+0.5..0.6 s is proven safe). The old resolve-trigger waited for
        // v1:ResolveDiscovery (8 s fallback), and whenever the controller skipped or
        // delayed it the first GCSR round died on the fallback - the user-visible
        // "white LED then three yellow/red rounds before it finally connects" boot.
        // Arm base IS the handshake: the 0.5 s has already elapsed, so the first
        // request leaves on THIS tick (the display_rpc_delay check below passes
        // immediately), i.e. DTLS+0.5 s exactly like stadiacast --display-rpc-trigger
        // dtls --display-rpc-delay 0.5.
        if (!disp_rpc_armed && disp_rpc_hs_ms && now_ms - disp_rpc_hs_ms >= DISPLAY_RPC_DTLS_ARM_MS) {
            disp_rpc_armed = true;
            disp_rpc_arm_ms = disp_rpc_hs_ms;
            FWLOG("disp rpc arm (dtls+%dms)", DISPLAY_RPC_DTLS_ARM_MS);
        }
#endif
        if (!disp_rpc_armed && disp_rpc_hs_ms && now_ms - disp_rpc_hs_ms >= 600) {
            // Fallback arm (stadiacast _display_rpc_fallback, controller.py:604-615): no
            // arm at all 8 s after the handshake -> start the display RPCs anyway.
            // Harmless belt-and-braces next to the dtls trigger above (it cannot be
            // reached unless that arm somehow never fired).
            disp_rpc_armed = true;
            disp_rpc_arm_ms = now_ms;
            FWLOG("disp rpc fallback arm");
        }
        if (disp_rpc_armed) {
            // If ResolveDiscovery beat the handshake, the reference arms at
            // dtls-connected instead (controller.py:461-466): the 0.6 s delay runs from
            // the LATER of the two, never from a stale pre-handshake arm.
            uint32_t arm_base = disp_rpc_arm_ms > disp_rpc_hs_ms ? disp_rpc_arm_ms : disp_rpc_hs_ms;
            if (!state_req_sent ? now_ms - arm_base >= 600          // display_rpc_delay (live)
                                : now_ms - last_state_req_ms >= 1500) // display_rpc_interval
            {
                uint8_t b[16]; pb_out_t o; pbo_init(&o, b, sizeof b);
                build_get_controller_state_request(&o);
                rpc_request_dtc(DTC_STATE_REQ, o.buf, o.len, WID_DISP_RPC);
                state_req_sent = true;
                last_state_req_ms = now_ms;
            }
        }
    }
    // StartGame once READY (held until GAME_STARTED; controller connects game link then)
    if (cloud_state == CLOUD_READY && !startgame_sent && Ld.handshake_done) {
        uint8_t b[24]; pb_out_t o; pbo_init(&o, b, sizeof b);
        build_start_game(&o, "pico");
        uint8_t dtc[48]; pb_out_t d; pbo_init(&d, dtc, sizeof dtc);
        pbo_bytes(&d, DTC_START_GAME, o.buf, o.len);      // DisplayToController{8: StringAndInt}
        startgame_ticket = cloud_next_ticket();
        uint8_t msg[80]; pb_out_t m; pbo_init(&m, msg, sizeof msg);
        build_rpc_request(&m, startgame_ticket, d.buf, d.len);
        wh2_send(&Ld, WID_DISP_RPC, m.buf, m.len);
        startgame_sent = true;
    }
    // Rumble flush - the SINGLE send point since p3-2640 (see rtc_rumble_pulse): every
    // rumble frame on 0x66 leaves from HERE. IMMEDIATELY on a new host frame
    // (rumble_dirty, set by the XInput OUT endpoint in IRQ context, by the RUMBLE pulse
    // and by the pulse auto-off - waiting for the refresh would add up to 2 s of
    // game-rumble latency), and every 2 s while on (5 s firmware watchdog). The dirty
    // read+clear must be IRQ-coherent with the writer or a frame landing between the
    // read and the clear would be lost; a refused send re-arms dirty so a transient
    // DTLS write failure retries on the next tick instead of dropping the frame.
    if (Lg.handshake_done) {
        uint32_t save = save_and_disable_interrupts();
        bool flush_now = rumble_dirty || (rumble_on &&
            absolute_time_diff_us(last_rumble_refresh, get_absolute_time()) > 2000000);
        rumble_dirty = false;
        restore_interrupts(save);
        if (flush_now) {
            last_rumble_refresh = get_absolute_time();
            if (!rumble_flush()) {
                uint32_t s2 = save_and_disable_interrupts();
                rumble_dirty = true;
                restore_interrupts(s2);
            }
        }
    }
    // Auto-off for the host-triggered pulse (see rtc_rumble_pulse): 200 ms after the
    // request, arm the 0,0 stop series so the motors actually stop instead of riding
    // the controller's 5000 ms haptics watchdog. p3-2640: rtc_rumble_off() sets
    // rumble_dirty and the flush block ABOVE sends it - the old direct rumble_flush()
    // here was the second fork: with dirty also set, the next tick flushed the SAME
    // stop series again (the 00:40 capture's duplicated ack `2016 2016` is exactly
    // those two sends), so the controller received every stop frame twice. The log
    // line now carries hs= (game-link handshake state) because "pulse done" alone
    // never proved the frame left - with hs=0 the stop series is merely pending and
    // will leave on the first tick after the handshake completes.
    if (rumble_pulse_on &&
        absolute_time_diff_us(rumble_pulse_until, get_absolute_time()) >= 0) {
        rumble_pulse_on = false;
        rtc_rumble_off();       // amplitudes 0, bumps rumble_seq for the stop series
        FWLOG("rumble: pulse done (stop series seq=%u armed, hs=%d)",
              (unsigned)rumble_seq, Lg.handshake_done ? 1 : 0);
    }
    // ICE connectivity checks. The first one cannot be sent (the peer address is only
    // learned from its first inbound packet), but after that a check every second mirrors
    // the proven chain (ice_fast_checks = 1 s) - and on that chain the controller's DTLS
    // ClientHello FOLLOWS our check. rtc_tick()'s comment has always promised this while
    // nothing ever sent a check.
    {
        static uint32_t last_ice_ms;
        uint32_t now_ms = to_ms_since_boot(get_absolute_time());
        if (now_ms - last_ice_ms >= 1000) {
            last_ice_ms = now_ms;
            uint32_t r = get_rand_32();
            uint8_t txn[12];
            for (int i = 0; i < 12; i++) txn[i] = (uint8_t)(r >> ((i & 3) * 8));
            txn[3] ^= (uint8_t)now_ms;
            uint8_t req[160];
            if (Ld.have_peer && !Ld.handshake_done && cloud_offer.offer_ufrag[0]) {
                // RFC 8445: a binding REQUEST is keyed with the PEER's password (the one
                // the peer will use to validate it), not our own. We were using ours.
                const char *peerpwd = cloud_offer.offer_pwd[0] ? cloud_offer.offer_pwd : cloud_disp_creds.pwd;
                int n = stun_make_request(req, cloud_offer.offer_ufrag,
                                          cloud_disp_creds.ufrag, peerpwd, txn);
                {   // Are our own checks actually going out? Without the peer's Binding
                    // Success in the log, "never sent" and "sent but ignored" look alike.
                    static int chklog;
                    if (chklog < 8) {
                        chklog++;
                        FWLOG("CHECK out len=%d user=[%s:%s] pwd_len=%d peer=%d.%d.%d.%d:%u",
                              n, cloud_offer.offer_ufrag, cloud_disp_creds.ufrag,
                              peerpwd ? (int)strlen(peerpwd) : -1,
                              ip4_addr1(&Ld.peer), ip4_addr2(&Ld.peer),
                              ip4_addr3(&Ld.peer), ip4_addr4(&Ld.peer), Ld.peer_port);
                    }
                }
                udp_send_link(&Ld, req, n);
            }
            if (Lg.have_peer && !Lg.handshake_done && game_offer.offer_ufrag[0]) {
                txn[0] ^= 0x5a;
                const char *gpeerpwd = game_offer.offer_pwd[0] ? game_offer.offer_pwd : cloud_game_creds.pwd;
                int n = stun_make_request(req, game_offer.offer_ufrag,
                                          cloud_game_creds.ufrag, gpeerpwd, txn);
                udp_send_link(&Lg, req, n);
            }
        }
    }
    // Post-handshake STUN keepalive (D3): the reference NEVER stops checking after the
    // handshake - endpoint.py _keepalive (281-295) keeps sending a binding request on the
    // selected pair every _keepalive_delay() = 2.5 s once DTLS has started, and
    // docs/protocol.md:84-86 says "Our checks repeat every 2.5 s as keepalive". Same
    // stun_make_request path and CHECK log as the pre-handshake checks, ka=1 marking it.
    // Top5 #5: back to the constant 2.5 s. The previous 1 s period + 500 ms first beat
    // was self-invented compensation for having NO RTCP (audit C7) - with the SRTCP RR
    // below keeping display traffic flowing every 1 s, STUN returns to the reference
    // cadence. The timer anchors at the handshake, so the first beat is DTLS+2.5 s
    // exactly like the reference loop.
    {
        static uint32_t last_ka_ms; static bool ka_armed;
        uint32_t now_ms = to_ms_since_boot(get_absolute_time());
        if (!Ld.handshake_done) ka_armed = false;
        else if (!ka_armed) { ka_armed = true; last_ka_ms = now_ms; }
        else if (now_ms - last_ka_ms >= 2500) {
            last_ka_ms = now_ms;
            if (Ld.handshake_done && Ld.have_peer && cloud_offer.offer_ufrag[0]) {
                uint32_t r = get_rand_32();
                uint8_t txn[12];
                for (int i = 0; i < 12; i++) txn[i] = (uint8_t)(r >> ((i & 3) * 8));
                txn[7] ^= (uint8_t)now_ms;
                uint8_t req[160];
                const char *peerpwd = cloud_offer.offer_pwd[0] ? cloud_offer.offer_pwd : cloud_disp_creds.pwd;
                int n = stun_make_request(req, cloud_offer.offer_ufrag,
                                          cloud_disp_creds.ufrag, peerpwd, txn);
                {   // keepalive visibility: same format as the pre-handshake CHECK, ka=1
                    static int kalog;
                    if (kalog < 8) {
                        kalog++;
                        FWLOG("CHECK out ka=1 len=%d user=[%s:%s] pwd_len=%d peer=%d.%d.%d.%d:%u",
                              n, cloud_offer.offer_ufrag, cloud_disp_creds.ufrag,
                              peerpwd ? (int)strlen(peerpwd) : -1,
                              ip4_addr1(&Ld.peer), ip4_addr2(&Ld.peer),
                              ip4_addr3(&Ld.peer), ip4_addr4(&Ld.peer), Ld.peer_port);
                    }
                }
                udp_send_link(&Ld, req, n);
            }
            if (Lg.handshake_done && Lg.have_peer && game_offer.offer_ufrag[0]) {
                uint32_t r = get_rand_32();
                uint8_t txn[12];
                for (int i = 0; i < 12; i++) txn[i] = (uint8_t)(r >> ((i & 3) * 8));
                txn[7] ^= 0x5a;
                uint8_t req[160];
                const char *gpeerpwd = game_offer.offer_pwd[0] ? game_offer.offer_pwd : cloud_game_creds.pwd;
                int n = stun_make_request(req, game_offer.offer_ufrag,
                                          cloud_game_creds.ufrag, gpeerpwd, txn);
                udp_send_link(&Lg, req, n);
            }
        }
    }
    // SRTCP RR: an empty Receiver Report every 1 s on the display link (Top5 #5; live
    // preset rtcp_interval=1.0, config.py:103-116; controller.py:456-457 starts the
    // loop at display dtls-connected, 470-487 _rtcp_loop; endpoint.py:574-585
    // send_rtcp_rr). Mirrors the loop's timing too: the first RR lands one interval
    // after the keys exist, and a beat that cannot send still consumes its slot (the
    // Python `continue` sleeps a full interval again) - so last_rr_ms advances on
    // every fire, send or not.
    {
        static uint32_t last_rr_ms; static bool rr_armed;
        uint32_t now_ms = to_ms_since_boot(get_absolute_time());
        if (!Ld.handshake_done) rr_armed = false;
        else if (!rr_armed) { rr_armed = true; last_rr_ms = now_ms; }
        else if (now_ms - last_rr_ms >= 1000) {
            last_rr_ms = now_ms;
            if (disp_rtcp_send_rr()) {
                audio.rr_sent++;
                if (audio.rr_sent <= 3)      // first few, like rtcp_rr_sent in the spec log
                    FWLOG("rtcp_rr_sent {name:\"input\", count:%u}", (unsigned)audio.rr_sent);
            }
        }
    }
    // Audio tone pump: one SRTP Opus frame every 20 ms, drift-corrected (frame n leaves
    // at t0 + n*20 ms; falling behind drains as a short burst, like playTone's due-time
    // pacing). rtc_tick is driven at 20 ms from the main loop for exactly this cadence.
    // A dead display link or a failed send stops the tone with a reason line.
    if (audio.tone_on) {
        if (!Ld.handshake_done) {
            audio.tone_on = false;
            FWLOG("audio_tone_stop {reason:\"display link down\"}");
        } else {
            uint32_t now = net_infra_uptime_us();
            int burst = 0;
            while (audio.frames_left && (int32_t)(now - audio.next_due_us) >= 0) {
                if (!audio_send_frame()) {
                    audio.tone_on = false;
                    FWLOG("audio_tone_stop {reason:\"send failed\"}");
                    break;
                }
                audio.marker = false;                       // only the tone's first frame
                audio.seq++;
                audio.ts += AUDIO_TS_STEP;
                audio.frame = (audio.frame + 1) % TONE_FRAME_COUNT;
                audio.frames_left--;
                audio.next_due_us += AUDIO_FRAME_MS * 1000;
                audio.sent_total++;
                if (++burst >= 5) break;                    // never wedge the tick
            }
            if (!audio.frames_left && audio.tone_on) {
                audio.tone_on = false;
                FWLOG("audio_tone_done {frames:%u, sent_total:%u}",
                      (unsigned)audio.tone_frames, (unsigned)audio.sent_total);
            }
        }
    }
    // ---- automatic audio-source selection (p3-3500 plug-and-play) ----
    // The speaker frame source is no longer a console command: this tick watches
    // the USB audio data flow through ipc_audio_ms_since_data() (published by
    // core1's usb_audio_core1_tick every loop pass). Data arriving = the PC is
    // playing into the UAC1 device -> switch the source to USB (full
    // rtc_audio_set_source(1) semantics: audio attach, marker bit, pacing reset)
    // and log ONE "auto-detected" line for the plug-and-play verification. No data
    // for >100 ms (host closed the stream / device deselected) -> back to MUTE: the
    // 20 ms RTP pump simply stops (the requirement is silence, never the test tone)
    // and both the core1 ring and the queued frames are dropped so a later resume
    // starts from live audio, not the stale tail.
    // The switch-on threshold is the same 100 ms window read from the fresh
    // side (ms_since_data < 100 while streaming), so there is exactly one
    // threshold and no boundary flapping. A running manual TONE is never
    // interrupted - it owns usb_src until it finishes (data still flowing
    // flips the source on the next tick after that).
    {
        uint32_t since_ms = ipc_audio_ms_since_data(net_infra_uptime_us());
        if (!audio.usb_src) {
            if (since_ms < 100 && !audio.tone_on) {
                rtc_audio_set_source(1);
                static uint8_t budget = 4;   // proof lines, not a heartbeat
                if (budget) { budget--; FWLOG("audio: usb source auto-detected"); }
            }
        } else if (since_ms > 100) {
            audio.usb_src = false;
            audio.next_due_us = 0;          // re-arm fresh on the next switch-on
            ipc_audio_request_flush();      // core1: drop its staging tail
            ipc_pcm_reset();                // core0: drop the buffered PCM
            usb_prefilled = false;
            static uint8_t budget = 4;
            if (budget) { budget--; FWLOG("audio: usb source idle %lums -> mute",
                                          (unsigned long)since_ms); }
        }
    }
    // Tell core1 whether it should feed PCM at all (it only pumps USB audio into
    // the IPC ring while the USB speaker source is live).
    ipc_audio_set_want(audio.usb_src && Ld.handshake_done);
    // USB-source pump (p3-2700/p3-3641): a CONTINUOUS 20 ms stream. ONE 3840-byte
    // PCM block is read from the IPC ring and encoded with libopus on THIS core per
    // slot; a short ring is zero-filled inside ipc_pcm_read(), so the RTP seq never
    // gaps (the device only advances its playback pump on consecutive sequence
    // numbers, emu37). Same drift-corrected due-time pacing as the tone: frame n
    // leaves at t0 + n*20 ms, a stall beyond 200 ms re-anchors instead of bursting.
    if (audio.usb_src && !audio.tone_on) {
        if (Ld.handshake_done && Ld.have_peer) {
            audio_attach_send(2);          // no-op while the 60 s guard holds
            uint32_t now = net_infra_uptime_us();
            if (!audio.next_due_us ||
                (int32_t)(now - audio.next_due_us) > 80000) {
                audio.next_due_us = now;   // arm / re-anchor after a long stall
            }
            // p3-3641 JITTER CUSHION: core1 fills the ring at 192 kB/s while the
            // encoder consumes the same rate, so without a cushion every block is
            // short (the old core1-side prefill, now owned by the consumer). Until
            // 4 blocks (80 ms) are buffered the slots carry silence, which keeps
            // the sequence gapless while the ring fills.
            if (!usb_prefilled && ipc_pcm_level() >= IPC_PCM_PREFILL_BYTES) {
                usb_prefilled = true;
                FWLOG("audio: pcm prefill done (lvl=%u B)", (unsigned)ipc_pcm_level());
            }
            int burst = 0;
            while ((int32_t)(now - audio.next_due_us) >= 0) {
                if (!audio_send_frame()) break;   // stay due: retry next tick
                audio.marker = false;             // only the source's first frame
                audio.seq++;
                audio.ts += AUDIO_TS_STEP;
                audio.next_due_us += AUDIO_FRAME_MS * 1000;
                audio.sent_total++;
                if (++burst >= 3) break;          // never wedge the tick (p3-3630: 5 was a burst source)
            }
            // 10 s visibility: the WHOLE pipeline on one line. After the move the
            // numbers to watch are lvl (ring depth, should hover around the 80 ms
            // prefill), drop (core1 had to throw PCM away because core0/encoder was
            // too slow - the old 58% failure signature), under (core0 read past the
            // ring), and the core0 encode timing (must stay well under 20 ms).
            uint32_t ms = to_ms_since_boot(get_absolute_time());
            if (ms - audio.last_stat_ms >= 10000) {
                audio.last_stat_ms = ms ? ms : 1;
                uint32_t ok, fail, last_us, avg_us, max_us; int16_t peak;
                usb_audio_encode_stats(&ok, &fail, &last_us, &avg_us, &max_us, &peak);
                // p3-3646: split across lines. clog_ truncates at 158 chars and the
                // single-line version above was 190+ chars on real hardware, i.e. the
                // encode timing (last/avg/max) was ALWAYS cut off - exactly the number
                // that has to tell us "ms or seconds".
                FWLOG("audio usb: lvl=%u drop=%u under=%u sent=%u streaming=%d real=%u sil=%u",
                      (unsigned)ipc_pcm_level(), (unsigned)ipc_pcm_dropped(),
                      (unsigned)ipc_pcm_under(),
                      (unsigned)audio.sent_total, ipc_audio_stream_get() ? 1 : 0,
                      (unsigned)tx_real, (unsigned)tx_sil);
                FWLOG("audio enc: ok=%u fail=%u last=%lu.%02lu avg=%lu.%02lu max=%lu.%02lu ms peak=%d",
                      (unsigned)ok, (unsigned)fail,
                      (unsigned long)(last_us / 1000), (unsigned long)((last_us % 1000) / 10),
                      (unsigned long)(avg_us / 1000), (unsigned long)((avg_us % 1000) / 10),
                      (unsigned long)(max_us / 1000), (unsigned long)((max_us % 1000) / 10),
                      (int)peak);
                // p3-3646: pseudostack health. creep must stay 0; peak is the deepest
                // single call (vs 40960 requested / 49152 static); canary > 0 means a
                // REAL overrun that used to corrupt the heap silently.
                uint32_t pcr, pcm, pcp, pcc;
                usb_audio_ps_stats(&pcr, &pcm, &pcp, &pcc);
                FWLOG("audio ps: creep=%u creepmax=%u peak=%u canary=%u",
                      (unsigned)pcr, (unsigned)pcm, (unsigned)pcp, (unsigned)pcc);
            }
        }
    }
    // OPUSBENCH: now a CORE0 benchmark. usb_audio_bench_start() only queues a
    // request from core1's CDC parser; the tick is a no-op unless one is pending.
    usb_audio_bench_tick();
}

bool rtc_game_connected(void) { return cloud_state == CLOUD_GAME_STARTED; }
bool rtc_display_ready(void) { return cloud_state >= CLOUD_READY; }
