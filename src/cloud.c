#include "cloud.h"
#include "config.h"
#include "usb_hid.h"   // FWLOG
#include "rtc.h"       // rtc_reset_display_session (new offer = new boot)
#include <string.h>
#include <stdio.h>
#include "pico/rand.h"

volatile cloud_state_t cloud_state = CLOUD_BOOT;
sdp_offer_info_t cloud_offer;
rtc_creds_t cloud_disp_creds, cloud_game_creds;
char cloud_ip_str[16] = AP_IP;

static uint8_t gmsg_bundle[340]; static int gmsg_bundle_len; static bool gmsg_queued;
// PLAYBOOK 3.6y: re-delivering the answer resets the controller's GothamRtcSession state
// from 3 back to 2, and the DTLS-complete gate (==3) then silently fails. Deliver once.
static bool gmsg_delivered;
static int64_t gmsg_id = 1;       // next id to allocate
// The id actually carried by the queued message. The live capture shows the controller
// acking the FIRST push as id=1, so the first message we send must be 1, not 2.
static int64_t gmsg_sent_id = 1;
// The display id/token pair the register response carried (D7): the reference
// answers BOTH v1:RegisterController and v1:DiscoverDisplay with the SAME
// per-controller pair (controller.py:224 + 235 both use self.display_token);
// our old DiscoverDisplay reply hardcoded a different token.
static char reg_disp_id[32] = "pico-display-1";
static char reg_disp_token[48] = "";
// Tickets mirror stadiacast exactly (D5): ControllerSession.__init__ sets
// _rpc_ticket = 0 (controller.py:125), send_rpc() PRE-increments before use
// (controller.py:671-673) so the first outbound request carries ticket=1, and
// reset_boot_state() re-zeroes it on every new offer (controller.py:183).
static uint32_t ticket_seq = 0;

static void rand_alnum(char *dst, int n) {
    static const char A[] = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    for (int i = 0; i < n; i++) dst[i] = A[get_rand_32() % (sizeof A - 1)];
    dst[n] = 0;
}

// one DTLS identity for both links (fingerprint advertised in SDP matches)
static char cert_fingerprint[128];            // "sha-256 XX:XX:..." (103 chars)
const char *cloud_cert_fingerprint(void) { return cert_fingerprint; }

void cloud_encoder_dump(void) {
    // Build the exact bytes we would push on /gmsg and log them, so the encoder can be
    // verified against the live-verified sample without needing a controller.
    static uint8_t bundle[512]; pb_out_t g; pbo_init(&g, bundle, sizeof bundle);
    rtc_creds_t c; memset(&c, 0, sizeof c);
    strcpy(c.ufrag, "ABCDEF");
    strcpy(c.pwd, "abcdefghijklmnopqrstuv");
    strcpy(c.fingerprint, "sha-256 00:11:22:33");
    sdp_offer_info_t inf; memset(&inf, 0, sizeof inf); inf.raw_dtls = 1; inf.delayed_acks = 1;
    build_sdp_answer_bundle(&g, &inf, &c, "192.168.137.1", 40000);
    FWLOG("ENCDUMP bundle=%d", g.len);
    for (int blk = 0; blk < 6; blk++) {
        int from = blk * 52; if (from >= g.len) break;
        int to = from + 52; if (to > g.len) to = g.len;
        char hx[120]; int q = 0;
        for (int i = from; i < to; i++) q += snprintf(hx + q, sizeof hx - q, "%02x", bundle[i]);
        hx[q] = 0; FWLOG("bun%d=%s", blk, hx);
    }
    static uint8_t env[640]; pb_out_t e; pbo_init(&e, env, sizeof env);
    build_gmsg_envelope(&e, 1, bundle, g.len);
    FWLOG("ENCDUMP envelope=%d", e.len);
    for (int blk = 0; blk < 8; blk++) {
        int from = blk * 52; if (from >= e.len) break;
        int to = from + 52; if (to > e.len) to = e.len;
        char hx[120]; int q = 0;
        for (int i = from; i < to; i++) q += snprintf(hx + q, sizeof hx - q, "%02x", env[i]);
        hx[q] = 0; FWLOG("env%d=%s", blk, hx);
    }
}

void cloud_init(void) {
    cloud_state = CLOUD_BOOT;
    gmsg_queued = false; gmsg_bundle_len = 0; gmsg_id = 1; ticket_seq = 0;
    rand_alnum(cloud_disp_creds.ufrag, 6);
    rand_alnum(cloud_disp_creds.pwd, 22);
    rand_alnum(cloud_game_creds.ufrag, 6);
    rand_alnum(cloud_game_creds.pwd, 22);
    cert_fingerprint[0] = 0;                  // filled by dtls.c after cert load
    strcpy(cloud_disp_creds.fingerprint, "");
    strcpy(cloud_game_creds.fingerprint, "");
}

void cloud_set_fingerprint(const char *fp_nocolon_prefix) {
    // dtls.c calls with "sha-256 XX:XX:.."; store full form for SDP
    snprintf(cloud_disp_creds.fingerprint, sizeof cloud_disp_creds.fingerprint, "%s", fp_nocolon_prefix);
    snprintf(cloud_game_creds.fingerprint, sizeof cloud_game_creds.fingerprint, "%s", fp_nocolon_prefix);
    // cert_fingerprint is what cloud_cert_fingerprint() returns (heartbeat/diagnostics).
    // It was never written, so a perfectly good fingerprint always displayed as (NONE).
    snprintf(cert_fingerprint, sizeof cert_fingerprint, "%s", fp_nocolon_prefix);
}

// Returns true when a credentials-carrying offer was ADOPTED (a new boot).
static bool extract_offer(const uint8_t *body, int len) {
    // RegisterControllerRequest.discovery(5).sdp_offer_bundle(4)
    //   or DiscoverDisplayRequest.sdp_offer_bundle(4).
    // The bundle is WebRtcSdpAndIceCandidates{sdp(1){3: sdp_offer}, ice_candidate(2)}
    // and find_sdp_offer() knows the exact path (see proto.c).
    const uint8_t *disc; int dl;
    const uint8_t *bundle = NULL; int bl = 0;
    disc = pb_get_bytes(body, len, 5, &dl);
    if (disc && dl > 0) bundle = pb_get_bytes(disc, dl, 4, &bl);
    if (!bundle || bl <= 0) bundle = pb_get_bytes(body, len, 4, &bl);
    if (!bundle || bl <= 0) return false;
    const uint8_t *offer; int ol = 0;
    if (!find_sdp_offer(bundle, bl, &offer, &ol) || ol <= 0) {
        FWLOG("cloud: register request carries no sdp_offer (bundle=%d)", bl);
        return false;
    }
    // Parse into a scratch copy and only adopt it if it actually carries credentials.
    // The controller re-registers WITHOUT an offer after a failed attempt, and that empty
    // parse used to overwrite the good offer. Everything downstream - our own ICE checks in
    // particular - hangs off cloud_offer.offer_ufrag, so wiping it silenced our checks and
    // left ICE permanently one-way (the controller then gave up and never started DTLS).
    sdp_offer_info_t tmp;
    memset(&tmp, 0, sizeof tmp);
    parse_rtc_sdp_offer(offer, ol, &tmp);
    if (tmp.offer_ufrag[0] && tmp.offer_pwd[0]) {
        memcpy(&cloud_offer, &tmp, sizeof cloud_offer);
        FWLOG("cloud: offer ufrag=%s pwd_len=%d raw=%d dly=%d",
              cloud_offer.offer_ufrag, (int)strlen(cloud_offer.offer_pwd),
              cloud_offer.raw_dtls, cloud_offer.delayed_acks);
        // A new offer = a new boot (D9): the reference runs reset_boot_state() on
        // every accepted offer (controller.py:270 -> 163-186) - it cancels the
        // post-DTLS tasks, re-zeroes the RPC ticket (controller.py:183) and drops
        // the display session state. The firmware mirror: kill the (possibly
        // zombie) Ld session + display-RPC arm so the next ICE round starts clean
        // even when the controller abandoned silently, without a closing alert.
        ticket_seq = 0;
        rtc_reset_display_session();
        return true;
    }
    FWLOG("cloud: empty offer ignored (keeping ufrag=[%s])", cloud_offer.offer_ufrag);
    return false;
}

// Queue the current answer on the gmsg channel. Shared by the register path and
// the DiscoverDisplay path (the reference queues from both: controller.py:227/265
// -> _offer_from_request -> queue_gmsg, ids allocated the same way, 311-316).
static void queue_sdp_answer(void) {
    pb_out_t g; pbo_init(&g, gmsg_bundle, sizeof gmsg_bundle);
    build_sdp_answer_bundle(&g, &cloud_offer, &cloud_disp_creds, cloud_ip_str, PORT_DISPLAY);
    gmsg_bundle_len = g.len; gmsg_queued = true; gmsg_delivered = false;
#if BISECT_0826
    gmsg_id++;                       // p3-0826: allocate first, so the first push is id=2
    gmsg_sent_id = gmsg_id;
#else
    gmsg_sent_id = gmsg_id;          // send the CURRENT id first, so the first push is id=1
    gmsg_id++;
#endif
    FWLOG("answer queued=%d id=%d offer_ufrag=[%s]",
          g.len, (int)gmsg_sent_id, cloud_offer.offer_ufrag);
}

void cloud_on_register(const uint8_t *body, int len, uint8_t *out, int *out_len) {
    extract_offer(body, len);
    reg_resp_t r;
    snprintf(r.registration_id, sizeof r.registration_id, "pico-reg-%08x", (unsigned)get_rand_32());
    snprintf(r.registration_token, sizeof r.registration_token, "pico-tok-%08x", (unsigned)get_rand_32());
    snprintf(r.display_id, sizeof r.display_id, "pico-display-1");
    snprintf(r.display_token, sizeof r.display_token, "%s", r.registration_token);
    // Remember the pair so DiscoverDisplay answers with the SAME tokens (D7).
    snprintf(reg_disp_id, sizeof reg_disp_id, "%s", r.display_id);
    snprintf(reg_disp_token, sizeof reg_disp_token, "%s", r.display_token);
    pb_out_t o; pbo_init(&o, out, *out_len);
    build_register_controller_response(&o, &r);
    *out_len = o.len;
    // queue the SDP answer bundle on gmsg
    queue_sdp_answer();
    // The controller only starts ICE after it receives this answer, so both the build and
    // the hand-off must be visible: "no ICE" and "answer never delivered" look identical
    // from the outside otherwise.
    FWLOG("register: answer=%d id=%d offer_ufrag=[%s] offer_pwd_len=%d fp=%s",
          gmsg_bundle_len, (int)gmsg_sent_id, cloud_offer.offer_ufrag,
          cloud_offer.offer_pwd[0] ? (int)strlen(cloud_offer.offer_pwd) : -1,
          cloud_cert_fingerprint());
    { extern int g_pb_overflow; if (g_pb_overflow) FWLOG("PB OVERFLOW x%d - answer truncated!", g_pb_overflow); }
    cloud_state = CLOUD_REGISTERED;
}

void cloud_on_discover(const uint8_t *body, int len, uint8_t *out, int *out_len) {
    // v1:DiscoverDisplay (D7 + D9-2): the reference answers with the SAME
    // display_id/display_token as the register response (controller.py:234-235)
    // AND extracts the request's sdp_offer_bundle, re-answering with a fresh
    // answer on gmsg (controller.py:245-246 -> _offer_from_request -> 263-266).
    // Our old reply hardcoded a different token and dropped a carried offer on
    // the floor, so a re-registration whose offer arrived here never got ICE
    // credentials refreshed and the second session stalled in STUN forever.
    bool adopted = extract_offer(body, len);
    if (adopted) queue_sdp_answer();
    pb_out_t o; pbo_init(&o, out, *out_len);
    build_discover_display_response(&o, reg_disp_id, reg_disp_token[0] ? reg_disp_token : "pico-token-dd");
    *out_len = o.len;
    FWLOG("discover: adopted=%d id=%s", adopted ? 1 : 0, reg_disp_id);
}

bool cloud_gmsg_poll(const uint8_t *body, int len, uint8_t *out, int *out_len) {
    // acked? if last_message.id >= gmsg_id -> delivered
    const uint8_t *ref; int rl;
    ref = pb_get_bytes(body, len, 2, &rl);
    uint64_t acked = 0; bool has_ack = false;
    if (ref && rl > 0) {
        acked = pb_get_u64(ref, rl, 1, 0);
        has_ack = true;
        if (acked >= (uint64_t)gmsg_sent_id) gmsg_queued = false;
    }
    {   // The controller only starts ICE after it consumes the answer, so the poll's ack is
        // the acceptance signal. Without this, "answer delivered but ignored" and "answer
        // accepted" look identical.
        static int polllog;
        if (polllog < 24) {
            polllog++;
            FWLOG("gmsg poll body=%d ack=%d acked_id=%d our_id=%d queued=%d",
                  len, has_ack ? 1 : 0, (int)acked, (int)gmsg_sent_id, gmsg_queued ? 1 : 0);
        }
    }
    if (!gmsg_queued) return false;
    // PLAYBOOK 3.6y (byte-level, live-verified): re-delivering the answer resets the
    // controller's GothamRtcSession state from 3 (PERFORMING_DTLS_HANDSHAKE) back to 2,
    // and the DTLS-complete gate (== 3) then fails silently: no data channel, no UDP
    // input, no logs. The PC toolchain had to switch to "answer delivered exactly once".
    if (gmsg_delivered) return false;
    gmsg_delivered = true;
    pb_out_t o; pbo_init(&o, out, *out_len);
    build_gmsg_envelope(&o, gmsg_sent_id, gmsg_bundle, gmsg_bundle_len);
    *out_len = o.len;
    FWLOG("gmsg deliver id=%d envelope=%d", (int)gmsg_sent_id, o.len);
    {   // Dump the answer bundle itself: the controller accepts the envelope but never acks
        // it, so the payload is the remaining suspect and it must be inspectable offline.
        static int dumped;
        if (dumped < 1) {
            dumped++;
            for (int blk = 0; blk < 4; blk++) {
                int from = blk * 52;
                if (from >= gmsg_bundle_len) break;
                int to = from + 52; if (to > gmsg_bundle_len) to = gmsg_bundle_len;
                char hx[120]; int q = 0;
                for (int i = from; i < to; i++) q += snprintf(hx + q, sizeof hx - q, "%02x", gmsg_bundle[i]);
                hx[q] = 0;
                FWLOG("ans%d=%s", blk, hx);
            }
        }
    }
    return true;
}

const uint8_t *cloud_take_gmsg(int *len) { *len = gmsg_bundle_len; return gmsg_bundle; }
void cloud_reset_link(void) { cloud_state = CLOUD_BOOT; gmsg_queued = false; gmsg_delivered = false; }
uint32_t cloud_next_ticket(void) { return ++ticket_seq; }   // first call -> 1
