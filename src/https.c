// https.c - mbedTLS TLS server on :443 over lwIP RAW tcp (NO_SYS) + HTTP endpoints.
#include "https.h"
#include "config.h"
#include "cloud.h"
#include "certs.h"
#include "rtc.h"
#include "usb_hid.h"
#include "pico/stdlib.h"
#include "ipc.h"
#include "hardware/watchdog.h"
#include <string.h>
#include <stdio.h>
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "lwip/tcp.h"
#include "lwip/ip_addr.h"
#include "lwip/pbuf.h"

static mbedtls_x509_crt chain;
static mbedtls_pk_context pkey;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_ssl_config tls_conf;

// Omaha /service/update2 answer, element for element after the live spec's _omaha
// (stadiacast src/stadiacast/receiver.py:450-473, "Omaha update check: always
// 'no update'"). The reference document is
//   <?xml ...?><response protocol="3.0" server="stadia-local-receiver">   <- SERVER_NAME,
//     <daystart elapsed_seconds=".." elapsed_days=".."/>                  __init__.py:11
//     <app appid="A" status="ok"><updatecheck status="noupdate"/><ping status="ok"/></app>
//     ... one per appid parsed from the request (regex '<app\s[^>]*appid="([^"]+)"',
//     receiver.py:453; in an update2 request the attribute only occurs inside <app>
//     tags, so a flat scan for appid=" is equivalent) ...
//   </response>
// with segments joined by "" (no newlines), default appid {00000000-...} when none parse
// (receiver.py:464), daystart = seconds since UTC midnight / days since 2007-01-01
// (receiver.py:454-460 uses datetime.now(UTC); our SNTP wall clock rtc_cert_time_epoch
// is the same domain - epoch 1167609600 = 2007-01-01 = day 13514) and Content-Type
// "text/xml; charset=utf-8" (receiver.py:470). Why this matters: the previous static
// reply (appid="1"/"2", no protocol, no daystart, no ping) was POSTed against with
// body=626, then the controller went idle ~2.5 min and tore its network down for a
// second DHCP round (pico-log-20261105-010051: update2 at t=77205, next DHCP lines
// 624-626 vs the first round at lines 5-8) - the boot never finished.
// Returns the number of appids answered, or -1 if the buffer ran out (caller then
// sends OM_FALLBACK; unreachable with OM_MAX_APPS and this buffer size).
#define OM_MAX_APPS 8
static int omaha_noupdate(char *out, int cap, const uint8_t *body, int blen) {
    (void)blen;
    int o = 0;
#define OM_ADD(...) do { int w = snprintf(out + o, cap - o, __VA_ARGS__); \
                         if (w < 0 || w >= cap - o) return -1; o += w; } while (0)
    OM_ADD("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
           "<response protocol=\"3.0\" server=\"stadia-local-receiver\">");
    uint32_t epoch = rtc_cert_time_epoch();      // SNTP-sourced UTC seconds
    OM_ADD("<daystart elapsed_seconds=\"%u\" elapsed_days=\"%u\"/>",
           epoch % 86400u, epoch / 86400u - 13514u);
    int apps = 0;
    const char *p = (const char *)body;          // body may be NULL: 0 appids parsed
    while (p && apps < OM_MAX_APPS) {
        const char *a = strstr(p, "appid=\"");
        if (!a) break;
        a += 7;
        const char *e = strchr(a, '"');
        if (!e) break;
        int alen = (int)(e - a);
        if (alen > 64) alen = 64;
        OM_ADD("<app appid=\"%.*s\" status=\"ok\"><updatecheck status=\"noupdate\"/>"
               "<ping status=\"ok\"/></app>", alen, a);
        apps++;
        p = e + 1;
    }
    if (apps == 0)   // receiver.py:464: answer a placeholder app when nothing parsed
        OM_ADD("<app appid=\"{00000000-0000-0000-0000-000000000000}\" status=\"ok\">"
               "<updatecheck status=\"noupdate\"/><ping status=\"ok\"/></app>");
    OM_ADD("</response>");
#undef OM_ADD
    return apps;
}

// Same shape, single placeholder app, no request parsing - sent only if the builder
// above overflows (it cannot with OM_MAX_APPS=8 and om[1600]: worst case ~1.4 KB).
static const char OM_FALLBACK[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<response protocol=\"3.0\" server=\"stadia-local-receiver\">"
    "<app appid=\"{00000000-0000-0000-0000-000000000000}\" status=\"ok\">"
    "<updatecheck status=\"noupdate\"/><ping status=\"ok\"/></app></response>";

// The controller opens a NEW tcp connection per HTTP request (FVC -> RegisterController
// -> /gmsg arrive back to back). With a single slot the third accept was aborted and
// /gmsg never came, so the link only worked by timing luck. We now keep NSLOTS
// concurrent connections; everything request-scoped lives in conn_t so two
// connections can never stomp each other's rx ring or http buffer.
#define NSLOTS 3
#define RXRING 4096
enum { HS_HANDSHAKE, HS_DATA, HS_DEAD };
typedef struct {
    struct tcp_pcb *tpcb;
    mbedtls_ssl_context ssl;
    int state;
    // Must be able to hold one whole TLS record. Our Certificate flight carries the
    // full 3-certificate chain (fullchain.pem = 5644 bytes PEM ~= 4.1 KB DER), i.e. a
    // ~4.2 KB record. With the old tx[1400] that record was truncated and the 1400-byte
    // fragment was all that went out, so the controller could never verify us.
    uint8_t tx[6144]; int txlen;   // p3-3647: 8192->6144 to fund the RAM hot path (bio_send is WANT_WRITE-safe; max single record 4129 B)
    // Per-connection TLS RX ring (was file-scope globals: two connections sharing one
    // ring fed each other handshake ciphertext).
    uint8_t rxring[RXRING]; int rxr_head, rxr_tail;
    // Per-connection HTTP request buffer (was file-scope globals).
    // 16384 because the controller's RegisterController HEADERS alone measured 4082
    // bytes (CAST-CERT); a smaller buffer silently drops the body.
    uint8_t httpbuf[8192]; int httplen;
    int idle_rounds;    // consecutive drives with a complete header but no body
    bool closing;
    bool ssl_init;      // mbedtls_ssl_init ran; must be freed exactly once
    bool sni_done;      // ClientHello SNI scan ran for this connection
} conn_t;
static conn_t C[NSLOTS];

// One compact line for the 1 Hz heartbeat: slot:state,txlen,httplen,sslstate.
// The last heartbeat printed before a main-loop wedge shows which connection was
// stuck where (see PLAYBOOK 9.97: registration-phase wedge, cause unknown).
void https_diag(char *dst, int dstlen) {
    int o = snprintf(dst, dstlen, "https=");
    for (int i = 0; i < NSLOTS && o > 0 && o < dstlen - 28; i++) {
        o += snprintf(dst + o, dstlen - o, "%s%d:%d,%d,%d,%d",
                      i ? "|" : "", i,
                      (int)C[i].state, C[i].txlen, C[i].httplen,
                      (int)C[i].ssl.state);
    }
}

static int ring_used(conn_t *c) { return (c->rxr_head - c->rxr_tail + RXRING) % RXRING; }

// Case-insensitive substring search over the UNCONSUMED part of the TLS rx ring.
// The ClientHello (and therefore the SNI hostname) is plaintext, so this sees the
// requested server name before any handshake byte has been consumed from the ring.
static bool ring_has_str_ci(conn_t *c, const char *needle) {
    int nl = (int)strlen(needle);
    int used = ring_used(c);
    if (nl <= 0 || used < nl) return false;
    for (int i = 0; i + nl <= used; i++) {
        int j = 0;
        while (j < nl) {
            char a = (char)c->rxring[(c->rxr_tail + i + j) % RXRING];
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (a != needle[j]) break;
            j++;
        }
        if (j == nl) return true;
    }
    return false;
}
static void ring_push(conn_t *c, const uint8_t *d, int n) {
    for (int i = 0; i < n; i++) { c->rxring[c->rxr_head] = d[i]; c->rxr_head = (c->rxr_head + 1) % RXRING; }
}

// Retire a slot: release the TLS heap (~32 KB per ssl_setup) exactly once, then wipe
// the struct. state/tpcb are set so on_accept sees the slot as free. Every termination
// path (peer FIN, err callback, handshake failure, graceful close) must run through
// here, otherwise slots never recycle and the heap bleeds dry after ~10 accepts.
static void conn_reset(conn_t *c) {
    if (c->ssl_init) mbedtls_ssl_free(&c->ssl);
    memset(c, 0, sizeof *c);
    c->state = HS_DEAD;    // 0 is HS_HANDSHAKE; memset alone is not enough
    c->tpcb = NULL;
}

static int bio_send(void *ctx, const unsigned char *buf, size_t len) {
    conn_t *c = (conn_t *)ctx;
    // Never claim success for bytes we did not queue: returning `len` after truncating
    // to the buffer size makes mbedtls believe the record is on the wire while the peer
    // sees a partial handshake. Report WANT_WRITE so the caller flushes and retries.
    if (c->txlen + (int)len > (int)sizeof c->tx) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    memcpy(c->tx + c->txlen, buf, len);
    c->txlen += (int)len;
    return (int)len;
}
static int bio_recv(void *ctx, unsigned char *buf, size_t len) {
    conn_t *c = (conn_t *)ctx;
    int avail = ring_used(c);
    if (!avail) return MBEDTLS_ERR_SSL_WANT_READ;
    int n = (int)len < avail ? (int)len : avail;
    for (int i = 0; i < n; i++) buf[i] = c->rxring[(c->rxr_tail + i) % RXRING];
    c->rxr_tail = (c->rxr_tail + n) % RXRING;
    return n;
}

static void conn_flush_tx(conn_t *c) {
    while (c->txlen > 0 && c->tpcb) {
        int snd = tcp_sndbuf(c->tpcb);
        int n = c->txlen < snd ? c->txlen : snd;
        if (n <= 0) return;
        if (tcp_write(c->tpcb, c->tx, (u16_t)n, 1 /*TCP_WRITE_FLAG_COPY*/) != ERR_OK) return;
        memmove(c->tx, c->tx + n, (size_t)(c->txlen - n));
        c->txlen -= n;
        tcp_output(c->tpcb);
    }
}

static const char *ci_find(const char *h, const char *n) {
    int nl = (int)strlen(n);
    for (const char *p = h; *p; p++) if (!strncasecmp(p, n, nl)) return p;
    return NULL;
}

// IMF-fixdate for the Date header: the controller's firmware (emu10, 0x6007c7b8)
// scans the FVC response for "date", parses a 29-char IMF-fixdate, and a valid one
// posts SNTP_SKIPPED -> the app starts immediately. Without it the controller enters
// SNTP_SYNCING and burns a ~15 s NTP timeout before registering (observed in every
// cold boot; the PC reference sends Date automatically via Python's http.server).
static void http_date_str(char out[32]) {
    int64_t epoch = (int64_t)rtc_cert_time_epoch();
    if (epoch < 1000000000) epoch = 1762000000; // fallback: 2025-11-01
    int64_t days = epoch / 86400;
    int64_t secs = epoch % 86400;
    // Howard Hinnant civil_from_days
    int64_t z = days + 719468;
    int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    int64_t doe = z - era * 146097;
    int64_t yoe = (doe - doe/1460 + doe/36524 - doe/146096) / 365;
    int64_t y = yoe + era * 400;
    int64_t doy = doe - (365*yoe + yoe/4 - yoe/100);
    int64_t mp = (5*doy + 2) / 153;
    int64_t d = doy - (153*mp+2)/5 + 1;
    int64_t m = mp < 10 ? mp+3 : mp-9;
    if (m <= 2) y++;
    static const char *wd[] = { "Thu","Fri","Sat","Sun","Mon","Tue","Wed" };
    static const char *mo[] = { "Jan","Feb","Mar","Apr","May","Jun",
                                "Jul","Aug","Sep","Oct","Nov","Dec" };
    // 1970-01-01 was a Thursday (wd index 0 = Thu). (days + 4) % 7 gives Sun=0..Sat=6
    // but our wd table starts at Thu, so shift by 4 more.
    int wday = (int)(((days + 4) % 7 + 7) % 7); // 0=Thu, 1=Fri, ...
    snprintf(out, 32, "%s, %02lld %s %04lld %02lld:%02lld:%02lld GMT",
             wd[wday], (long long)d, mo[m-1], (long long)y,
             (long long)(secs/3600), (long long)((secs/60)%60), (long long)(secs%60));
}

static void send_response(conn_t *c, int status, const char *ctype,
                          const uint8_t *body, int blen, bool close_after) {
    static uint8_t out[1800];
    // Clamp the body BEFORE the header is formatted: the old order wrote
    // Content-Length with the original size and then truncated the body, so the client
    // was told to expect more bytes than ever arrived and sat there waiting.
    if (blen > (int)sizeof out - 256) blen = (int)sizeof out - 256;
    char db[32]; http_date_str(db);
    int h = snprintf((char *)out, sizeof out,
        "HTTP/1.1 %d %s\r\nDate: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n"
        "Cache-Control: no-store\r\nConnection: %s\r\n\r\n",
        status, status == 204 ? "No Content" : "OK", db, ctype, blen,
        close_after ? "close" : "keep-alive");
    int total = h + blen;
    if (total > (int)sizeof out) { total = (int)sizeof out; blen = total - h; }
    if (blen > 0) memcpy(out + h, body, (size_t)blen);
    for (int off = 0; off < total; ) {
        int w = mbedtls_ssl_write(&c->ssl, out + off, (size_t)(total - off));
        if (w > 0) { off += w; conn_flush_tx(c); continue; }
        if (w == MBEDTLS_ERR_SSL_WANT_WRITE) {
            // TX buffer full: drain into lwIP and retry a bounded number of times.
            int guard = 0;
            while (c->txlen > 0 && guard++ < 64) conn_flush_tx(c);
            if (c->txlen == 0) continue;
            FWLOG("https: response blocked (txlen=%d) - TCP send buffer full", c->txlen);
        }
        break;
    }
    conn_flush_tx(c);
    if (close_after) c->closing = true;
}

static void route(conn_t *c, const char *method, const char *path, const uint8_t *body, int blen) {
    static uint8_t out[720];
    pb_out_t o; int n;
    // Without this the log cannot tell whether the controller ever reached us: every
    // handler was silent on success, so "no /v1: requests" and "requests we didn't log"
    // looked identical.
    FWLOG("http %s %s body=%d", method, path, blen);
    {   // When a POST arrives with body=0, the framing headers decide everything. Log
        // whether they are present at all plus the parsed values, instead of dumping the
        // (huge, base64 CAST-CERT) header verbatim.
        static int dumps;
        if (blen == 0 && dumps < 6) {
            dumps++;
            int hdr_end = 0;
            for (int i = 0; i + 3 < c->httplen; i++)
                if (c->httpbuf[i] == 13 && c->httpbuf[i+1] == 10 && c->httpbuf[i+2] == 13 && c->httpbuf[i+3] == 10)
                    { hdr_end = i + 4; break; }
            c->httpbuf[c->httplen < (int)sizeof c->httpbuf - 1 ? c->httplen : (int)sizeof c->httpbuf - 1] = 0;
            const char *cl = ci_find((char *)c->httpbuf, "content-length:");
            const char *te = ci_find((char *)c->httpbuf, "transfer-encoding:");
            const char *ck = ci_find((char *)c->httpbuf, "chunked");
            const char *cc = ci_find((char *)c->httpbuf, "cast-cert:");
            FWLOG("hdr httplen=%d hdrend=%d CL=%d TE=%d chunked=%d castcert=%d rest=%d",
                  c->httplen, hdr_end,
                  cl ? atoi(cl + 15) : -1, te ? 1 : 0, ck ? 1 : 0, cc ? 1 : 0,
                  c->httplen - hdr_end);
            // The last header lines before the blank line - that is where a Content-Length
            // would appear; without them we cannot tell an absent header from a missed one.
            {
                int from = hdr_end - 110; if (from < 0) from = 0;
                char t[120]; int o = 0;
                for (int i = from; i < hdr_end && o < 112; i++)
                    t[o++] = (c->httpbuf[i] == 13 || c->httpbuf[i] == 10) ? '|' : (char)c->httpbuf[i];
                t[o] = 0;
                FWLOG("hdrtail=%s", t);
            }
        }
    }
    if (strstr(path, "/generate_204")) {
        send_response(c, 204, "text/plain", NULL, 0, false);
    } else if (strstr(path, "/stadiaconfig")) {
        // clients3.google.com boot config. receiver.py:441-448 (fallback branch of
        // _stadiaconfig): 200, b"{}", "application/json".
        FWLOG("stadiaconfig {}");
        send_response(c, 200, "application/json", (const uint8_t *)"{}", 2, false);
    } else if (strstr(path, "/update2")) {
        // update.googleapis.com Omaha update check. receiver.py:374 routes /service/update2
        // to _omaha; answer per omaha_noupdate above, Content-Type "text/xml; charset=utf-8"
        // (receiver.py:470 - NOT application/xml; copied from the verified reference).
        static char om[1600];
        int apps = omaha_noupdate(om, (int)sizeof om, body, blen);
        FWLOG("omaha apps=%d noupdate", apps);
        if (apps < 0)
            send_response(c, 200, "text/xml; charset=utf-8",
                          (const uint8_t *)OM_FALLBACK, (int)sizeof OM_FALLBACK - 1, false);
        else
            send_response(c, 200, "text/xml; charset=utf-8",
                          (const uint8_t *)om, (int)strlen(om), false);
    } else if (strstr(path, "/log/batch")) {
        // Clearcut analytics upload. This is normally unreachable: with
        // CLEARCUT_BLOCK_TLS=1 the play.googleapis.com handshake never completes. If it
        // DOES get here (block disabled, or the SNI scan missed), never confirm a
        // successful upload by reflex - §9.83/live preset: "every wake otherwise powers
        // off ~0.3 s after its first Clearcut upload", and the reference's own
        // 200 + LogResponse(30 min) answer is included in that verdict. Ladder:
        //   0 = 204 empty (soft fail; real Google never 204s Clearcut, so the uploader
        //       should requeue like any failed upload)
        //   1 = 200 empty body
        //   2 = 200 + LogResponse{next_request_wait_millis=30 min}, receiver.py _clearcut
        //       byte for byte ({08 C0 EE 6D}) - KNOWN LETHAL, experiments only.
#if CLEARCUT_REPLY == 2
        uint8_t lr[4] = { 0x08, 0xC0, 0xEE, 0x6D };
        send_response(c, 200, "application/octet-stream", lr, (int)sizeof lr, true);
#elif CLEARCUT_REPLY == 1
        send_response(c, 200, "application/octet-stream", NULL, 0, true);
#else
        send_response(c, 204, "text/plain", NULL, 0, true);
#endif
    } else if (strstr(path, "FirmwareVersionCheck")) {
        pbo_init(&o, out, sizeof out);
        pbo_tag(&o, 1, 0); pbo_varint(&o, 0);
        send_response(c, 200, "application/x-protobuf", out, o.len, false);
    } else if (strstr(path, "RegisterController")) {
        n = (int)sizeof out;
        cloud_on_register(body, blen, out, &n);
        send_response(c, 200, "application/x-protobuf", out, n, false);
    } else if (strstr(path, "DiscoverDisplay")) {
        // D7 + D9: the reference answers with the SAME display_id/display_token the
        // register response carried (controller.py:234-235) and extracts the
        // request's sdp_offer_bundle to queue a fresh answer (controller.py:245-246).
        // The old hardcoded reply mismatched the register token and dropped a
        // carried offer, so the second ICE round ran on stale credentials.
        n = (int)sizeof out;
        cloud_on_discover(body, blen, out, &n);
        send_response(c, 200, "application/x-protobuf", out, n, false);
    } else if (strstr(path, "ResolveDiscovery")) {
        // ResolveDiscovery is the display-RPC trigger (the controller posts it right
        // after OnConnected registered its RPC reader; our 200 leads to ACCEPT_COMMANDS).
        // The reference arms its GetControllerStateRequest loop at request-arrival time,
        // before the 200 goes out (receiver.py:549-558 -> controller.on_discovery_resolved
        // -> _start_display_rpc). Arm first, then answer: a display RPC sent before this
        // point is dropped and once stalled a live controller for good.
        rtc_display_rpc_arm();
        send_response(c, 200, "application/x-protobuf", NULL, 0, false);
    } else if (strstr(path, "/gmsg")) {
        n = (int)sizeof out;
        bool have = cloud_gmsg_poll(body, blen, out, &n);
        send_response(c, 200, "application/x-protobuf", have ? out : NULL, have ? n : 0, false);
    } else if (strstr(path, "/cr/report") || strstr(path, "/cr/staging_report")) {
        send_response(c, 200, "application/x-protobuf", NULL, 0, false);
    } else {
        send_response(c, 404, "text/plain", (const uint8_t *)"no", 2, false);
    }
    (void)method;
}

static bool http_have_hdr(conn_t *c, int *hdr_end, int *clen) {
    for (int i = 0; i + 3 < c->httplen; i++)
        if (c->httpbuf[i] == 13 && c->httpbuf[i+1] == 10 && c->httpbuf[i+2] == 13 && c->httpbuf[i+3] == 10) {
            *hdr_end = i + 4;
            c->httpbuf[c->httplen < (int)sizeof c->httpbuf - 1 ? c->httplen : (int)sizeof c->httpbuf - 1] = 0;
            const char *cl = ci_find((char *)c->httpbuf, "content-length:");
            *clen = cl ? atoi(cl + 15) : 0;
            return true;
        }
    return false;
}

// The controller "occasionally" uses chunked uploads (see the live spec's http_server
// docstring), and those carry NO Content-Length, so parsing them as length-delimited
// stalls forever. Decode <hex-len>CRLF<data>CRLF ... 0CRLFCRLF into out.
// returns 1 = complete, 0 = need more bytes, -1 = malformed
static int http_dechunk(conn_t *c, int off, uint8_t *out, int cap, int *out_len) {
    int p = off, o = 0;
    for (;;) {
        // need a hex size line
        int line = p;
        while (line + 1 < c->httplen && !(c->httpbuf[line] == 13 && c->httpbuf[line+1] == 10)) line++;
        if (line + 1 >= c->httplen) return 0;                    // incomplete size line
        int sz = 0, digits = 0;
        while (p < line) {
            int ch = c->httpbuf[p++];
            int v;
            if (ch >= '0' && ch <= '9') v = ch - '0';
            else if (ch >= 'a' && ch <= 'f') v = ch - 'a' + 10;
            else if (ch >= 'A' && ch <= 'F') v = ch - 'A' + 10;
            else return -1;                                   // chunk extensions unsupported
            sz = (sz << 4) | v; digits++;
        }
        if (!digits) return -1;
        p = line + 2;                                         // skip CRLF
        if (sz == 0) { *out_len = o; return 1; }              // last chunk: report length
        if (p + sz + 2 > c->httplen) return 0;                   // body not here yet
        if (o + sz > cap) return -1;                          // decoded body too large
        memcpy(out + o, c->httpbuf + p, (size_t)sz);
        o += sz;
        p += sz;
        if (p + 1 < c->httplen && c->httpbuf[p] == 13 && c->httpbuf[p+1] == 10) p += 2;
    }
}

// p3-3627: publish "where this slot is right now" into the noinit diag slot, so a
// main-loop wedge (24 s+ inside TLS) is readable after the watchdog reset. Called
// immediately BEFORE every risky mbedtls call, so the value survives the hang.
static void diag_note(conn_t *c, const char *where) {
    char b[96];
    snprintf(b, sizeof b, "%s slot=%d st=%d ssl=%d rx=%d tx=%d http=%d",
             where, (int)(c - C), (int)c->state, (int)c->ssl.state,
             (int)ring_used(c), c->txlen, c->httplen);
    ipc_prev_https_set(b);
}

static void drive(conn_t *c) {
    if (c->state == HS_DEAD) return;
    diag_note(c, "enter");
    if (c->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
#if CLEARCUT_BLOCK_TLS
        // Clearcut guard: refuse play.googleapis.com at the SNI layer, exactly like the
        // reference live preset's clearcut_block="tls". The upload MUST fail - a
        // successful one powers the controller off ~0.3 s later (PLAYBOOK §9.83, live
        // preset quote) - and a TLS-level failure is the variant proven end-to-end
        // ("a failed upload is requeued with the next tick 60 s out, letting a queued
        // v1:ResolveDiscovery reach the wire"). Scan once, on the first bytes of the
        // connection, before mbedtls consumes the ClientHello from the ring.
        if (!c->sni_done && ring_used(c) > 0) {
            c->sni_done = true;
            if (ring_has_str_ci(c, "play.googleapis.com")) {
                FWLOG("tls: refuse clearcut SNI=play.googleapis.com -> handshake_failure");
                mbedtls_ssl_send_alert_message(&c->ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                               MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
                conn_flush_tx(c);
                struct tcp_pcb *pcb = c->tpcb;
                conn_reset(c);
                if (pcb) { if (tcp_close(pcb) != ERR_OK) tcp_abort(pcb); }
                return;
            }
        }
#endif
        int r;
        // Same hazard as dtls_drive(): bound the iterations so a stalled handshake cannot
        // starve the main loop (and with it USB/CDC).
        int guard = 0;
        diag_note(c, "hs");
        while ((r = mbedtls_ssl_handshake(&c->ssl)) == MBEDTLS_ERR_SSL_WANT_READ ||
               r == MBEDTLS_ERR_SSL_WANT_WRITE) {
            diag_note(c, "hs_want");
            conn_flush_tx(c);
            if (!ring_used(c)) return;
            if (++guard > 64) return;
        }
        conn_flush_tx(c);
        if (r != 0) {
            // Retire the slot (and its pcb) instead of just flagging HS_DEAD: a dangling
            // tpcb would block slot reuse forever.
            struct tcp_pcb *pcb = c->tpcb;
            FWLOG("tcp: close slot=%d (hs r=%d)", (int)(c - C), r);
            conn_reset(c);
            if (pcb) { if (tcp_close(pcb) != ERR_OK) tcp_abort(pcb); }
            return;
        }
        c->state = HS_DATA;
    }
    // 1400 bytes on a 2048-byte stack, with route()/mbedtls_ssl_write below it.
    // This overflows the core stack as soon as a request is served. Single-threaded.
    // tmp/dec are call-scratch shared by all slots: drive() never re-enters itself and
    // nothing they hold survives past one drive() call.
    static uint8_t tmp[1400];
    int n;
    diag_note(c, "read");
    while ((n = mbedtls_ssl_read(&c->ssl, tmp, sizeof tmp)) > 0) {
        diag_note(c, "read_body");
        if (c->httplen + n <= (int)sizeof c->httpbuf) {
            memcpy(c->httpbuf + c->httplen, tmp, (size_t)n);
            c->httplen += n;
            c->idle_rounds = 0;
        } else {
            FWLOG("http: request too big (%d + %d > %d) - dropping", c->httplen, n, (int)sizeof c->httpbuf);
            c->httplen = 0;
        }
        conn_flush_tx(c);
        if (c->closing) break;
    }
    // Decide only after the read loop has drained. The controller sends its POST headers
    // and body back to back with NO Content-Length, so routing the moment the header ends
    // (cl == 0) discarded the body - which is exactly why RegisterController arrived with
    // body=0 and our SDP answer was built from an all-zero offer.
    if (!c->closing) {
        int he, cl;
        if (http_have_hdr(c, &he, &cl)) {
            char method[8] = {0}, path[96] = {0};
            sscanf((char *)c->httpbuf, "%7s %95s", method, path);
            bool chunked = ci_find((char *)c->httpbuf, "transfer-encoding:") != NULL &&
                           ci_find((char *)c->httpbuf, "chunked") != NULL;
            if (chunked) {
                static uint8_t dec[2048]; int dl = 0;
                int r2 = http_dechunk(c, he, dec, (int)sizeof dec, &dl);
                if (r2 == 1) { route(c, method, path, dec, dl); c->httplen = 0; c->idle_rounds = 0; }
                else if (r2 < 0) { FWLOG("http: bad chunked body, dropping request"); c->httplen = 0; c->idle_rounds = 0; }
            } else if (cl > 0) {
                if (c->httplen - he >= cl) { route(c, method, path, c->httpbuf + he, cl); c->httplen = 0; c->idle_rounds = 0; }
            } else if (c->httplen - he > 0) {
                // No framing header: everything past the header is the body.
                int avail = c->httplen - he;
                route(c, method, path, c->httpbuf + he, avail);
                c->httplen = 0; c->idle_rounds = 0;
            } else if (++c->idle_rounds >= 3) {
                // Header only, no body, and nothing more arrived for a few passes.
                c->idle_rounds = 0;
                route(c, method, path, NULL, 0);
                c->httplen = 0;
            }
        }
    }
    conn_flush_tx(c);
    if (c->closing && c->txlen == 0) {
        mbedtls_ssl_close_notify(&c->ssl);
        conn_flush_tx(c);
        // Close the pcb ourselves: waiting for the peer's FIN (the old behaviour) kept a
        // live pcb registered against this slot and its callbacks fired into whatever
        // connection reused the slot next.
        struct tcp_pcb *pcb = c->tpcb;
        FWLOG("tcp: close slot=%d (done)", (int)(c - C));
        conn_reset(c);
        if (pcb) { if (tcp_close(pcb) != ERR_OK) tcp_abort(pcb); }
    }
}

static err_t on_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    (void)err;
    conn_t *c = (conn_t *)arg;
    if (!c) { if (p) pbuf_free(p); tcp_abort(tpcb); return ERR_OK; }
    if (!p) {
        // Peer closed. tcp_close here; after it returns lwIP issues no further
        // callbacks for this pcb, so freeing the slot immediately is safe.
        FWLOG("tcp: close slot=%d (fin)", (int)(c - C));
        conn_reset(c);
        tcp_close(tpcb);
        return ERR_OK;
    }
    if (p->tot_len + ring_used(c) < RXRING) {
        struct pbuf *q = p;
        while (q) { ring_push(c, (const uint8_t *)q->payload, q->len); q = q->next; }
    }
    tcp_recved(tpcb, p->tot_len);
    pbuf_free(p);
    drive(c);
    return ERR_OK;
}
static err_t on_sent(void *arg, struct tcp_pcb *tpcb, u16_t len) {
    (void)len;
    // Locate the connection via arg, never via a global: with NSLOTS slots the sender
    // is whichever connection this pcb belongs to.
    conn_t *c = (conn_t *)arg;
    if (c && c->tpcb == tpcb) conn_flush_tx(c);
    return ERR_OK;
}
static void on_err(void *arg, err_t err) {
    // pcb is already gone when this fires - do not touch it, just retire the slot.
    conn_t *c = (conn_t *)arg;
    if (!c) return;
    FWLOG("tcp: abort slot=%d err=%d", (int)(c - C), (int)err);
    conn_reset(c);
}
extern void clog_(const char *fmt, ...);

// p3-3653: mbedtls debug hook for the HTTPS server (mirrors DTLS dtls_dbg_cb).
// Without it a stuck handshake is silent (the WDT fires 30 s later with only a
// t= line as evidence). Level<=2 keeps certificate/parse/key-exchange milestones;
// budget caps the ring cost. Real-machine use: EC-cert hangs during parallel
// handshakes - the last "htls" line names the stuck call.
static void tls_dbg_cb(void *ctx, int level, const char *file, int line, const char *s) {
    (void)ctx; (void)file; (void)line;
    if (level > 2) return;
    static int budget;
    if (budget > 200) return;
    budget++;
    FWLOG("htls%d %s", level, s);
}

// p3-3629: heap headroom probe. The controller opens three TLS connections at
// once and each mbedtls_ssl_setup() mallocs its record buffers from the same heap
// whose free space is (RAM end - end of bss). Every KiB added to core1's stack /
// Opus buffers comes out of this, and when it runs dry registration dies.
static uint32_t heap_free_bytes(void) {
    extern char __end__[];
    extern char __HeapLimit[];
    extern void *sbrk(int);
    uintptr_t brk = (uintptr_t)sbrk(0);
    uintptr_t lim = (uintptr_t)__HeapLimit;
    return (brk < lim) ? (uint32_t)(lim - brk) : 0u;
}

static err_t on_accept(void *arg, struct tcp_pcb *newpcb, err_t err) {
    (void)arg;
    if (err != ERR_OK || !newpcb) return ERR_VAL;
    int slot = -1;
    for (int i = 0; i < NSLOTS; i++)
        if (C[i].state == HS_DEAD && !C[i].tpcb) { slot = i; break; }
    if (slot < 0) {
        FWLOG("tcp: abort slot=-1 from port %u (all %d slots busy)",
              (unsigned)newpcb->local_port, NSLOTS);
        tcp_abort(newpcb);
        // p3-3649: MUST return ERR_ABRT after aborting. tcp_in.c falls through
        // to tcp_receive(pcb) on ERR_OK - on a freed pcb that is use-after-free
        // (real-machine: lwIP assert -> panic -> HardFault 5 ms after a 4th
        // concurrent accept; blackbox pc=panic.c _exit). lwIP skips its own
        // abort when we report ERR_ABRT ("Already aborted?").
        return ERR_ABRT;
    }
    clog_("tcp: accept slot=%d from port %u heap=%u", slot, (unsigned)newpcb->local_port,
          (unsigned)heap_free_bytes());
    // p3-3644: NEVER let a TLS accept run mbedtls_ssl_setup() on a starved heap.
    // With 4 KB records one setup needs ~12-15 KB; over three concurrent
    // connections plus lwIP churn this floor keeps a clean 2x margin. Refusing
    // with a log (the controller retries) beats a WDT reboot every time -
    // real-machine 2026-11-08: setup on 36 KB heap wedged inside mbedtls and took
    // the board down ("accept slot=0 ssl_setup heap=36864" + wdt=1).
    if (heap_free_bytes() < 24576u) {
        FWLOG("tcp: refuse slot=%d from port %u heap=%u < 24K (no TLS setup on starved heap)",
              slot, (unsigned)newpcb->local_port, (unsigned)heap_free_bytes());
        tcp_abort(newpcb);
        return ERR_ABRT;   // p3-3649: aborted pcb must not see tcp_receive (see above)
    }
    {   // diag: remember the exact accept step in NOLOAD RAM (survives a WDT reset)
        char b[80];
        snprintf(b, sizeof b, "accept slot=%d begin heap=%u", slot, (unsigned)heap_free_bytes());
        ipc_prev_https_set(b);
    }
    // NOTE: a taken slot is always clean - busy slots are never touched here. Earlier
    // code closed the previous connection inside accept and the controller's next
    // request (the GMsg poll) then hung in the TLS handshake; retiring connections in
    // their own callbacks (fin / err / close) is the working path. The memset is
    // belt-and-braces, the TLS heap is released by conn_reset() on those paths.
    conn_t *c = &C[slot];
    memset(c, 0, sizeof *c);
    c->tpcb = newpcb; c->state = HS_HANDSHAKE;
    mbedtls_ssl_init(&c->ssl);
    c->ssl_init = true;
    {
        char b[80];
        snprintf(b, sizeof b, "accept slot=%d ssl_setup heap=%u", slot, (unsigned)heap_free_bytes());
        ipc_prev_https_set(b);
    }
    int rc_setup = mbedtls_ssl_setup(&c->ssl, &tls_conf);
    if (rc_setup != 0) {
        FWLOG("https: mbedtls_ssl_setup failed rc=%d heap=%u (out of memory?)",
              rc_setup, (unsigned)heap_free_bytes());
        conn_reset(c);
        tcp_abort(newpcb);
        return ERR_ABRT;   // p3-3649: aborted pcb must not see tcp_receive (see above)
    }
    {
        char b[80];
        snprintf(b, sizeof b, "accept slot=%d ssl_setup OK heap=%u", slot, (unsigned)heap_free_bytes());
        ipc_prev_https_set(b);
    }
    mbedtls_ssl_set_bio(&c->ssl, c, bio_send, bio_recv, NULL);
    tcp_arg(newpcb, c);
    tcp_recv(newpcb, on_recv);
    tcp_sent(newpcb, on_sent);
    tcp_err(newpcb, on_err);
    tcp_nagle_disable(newpcb);
    return ERR_OK;
}

void https_poll(void) {
    for (int i = 0; i < NSLOTS; i++) {
        if (C[i].state != HS_DEAD && C[i].tpcb) {
            uint32_t t0 = to_ms_since_boot(get_absolute_time());
            drive(&C[i]);
            uint32_t dt = to_ms_since_boot(get_absolute_time()) - t0;
            if (dt >= 300)   // p3-3627: a TLS handshake pass that blocks the main loop
                FWLOG("https: slot=%d drive=%ums state=%d ssl=%d rx=%u tx=%d http=%d",
                      i, (unsigned)dt, (int)C[i].state, (int)C[i].ssl.state,
                      (unsigned)ring_used(&C[i]), C[i].txlen, C[i].httplen);
            watchdog_update();
        }
    }
}

void https_init(void) {
    mbedtls_x509_crt_init(&chain);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    int rc_cert = mbedtls_x509_crt_parse(&chain, TLS_CERT_PEM, TLS_CERT_PEM_len);
    int rc_key  = mbedtls_pk_parse_key(&pkey, TLS_KEY_PEM, TLS_KEY_PEM_len, NULL, 0);
    int rc_pair = mbedtls_pk_check_pair(&chain.pk, &pkey);
    int rc_cfg  = mbedtls_ssl_config_defaults(&tls_conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_rng(&tls_conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_authmode(&tls_conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_dbg(&tls_conf, tls_dbg_cb, NULL);   // p3-3653: name stuck handshakes
    mbedtls_ssl_conf_ca_chain(&tls_conf, &chain, NULL);
    int rc_own  = mbedtls_ssl_conf_own_cert(&tls_conf, &chain, &pkey);
    if (rc_cfg || rc_own) FWLOG("https: TLS CONFIG FAILED defaults=%d cert=%d", rc_cfg, rc_own);
    for (int i = 0; i < NSLOTS; i++) C[i].state = HS_DEAD;    // 0 is HS_HANDSHAKE
    struct tcp_pcb *l = tcp_new();
    ip_addr_t any = *IP4_ADDR_ANY;
    err_t be = tcp_bind(l, &any, PORT_HTTPS);
    l = tcp_listen(l);
    // These used to be ignored. A failed bind / NULL listen / bad cert would show up
    // only as "controller never connects", which is indistinguishable from a WiFi fault.
    FWLOG("https: cert=%d key=%d keymatch=%d bind=%d listen=%s",
          rc_cert, rc_key, rc_pair, (int)be, l ? "ok" : "NULL");
    if (!l) { FWLOG("https: LISTEN FAILED - port %d unusable", PORT_HTTPS); return; }
    tcp_accept(l, on_accept);
}
