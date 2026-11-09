// wificfg.c - flash-backed AP credentials (see wificfg.h).
//
// Layout: one 4 KiB sector, the LAST sector of flash
// (PICO_FLASH_SIZE_BYTES - FLASH_SECTOR_SIZE). The firmware image (~1.5 MB at
// the bottom) never reaches it, so UF2 reflash preserves the config and only
// WIFI RESET (or a full chip erase) clears it.
//
// Safety notes:
// - erase/program run with core1 in a multicore lockout (it must be spinning
//   in RAM, not fetching code over XIP) plus IRQs masked on core0. core1 calls
//   multicore_lockout_victim_init() at boot; without it the lockout times out
//   and we refuse to touch flash rather than risk it.
// - USB drops for ~50-100 ms during the erase; the host recovers by itself.
//   This only happens on an explicit WIFI SAVE/RESET.
// - the PSK is NEVER printed (SHOW prints lengths only).

#include "wificfg.h"
#include "config.h"        // WIFI_SSID / WIFI_PASS compiled defaults
#include "ipc.h"           // WIFI_OP_*
#include "usb_hid.h"       // FWLOG
#include "pico/cyw43_arch.h"
#include "pico/multicore.h"
#include "hardware/flash.h"
#include "hardware/sync.h"
#include "hardware/watchdog.h"
#include "hardware/regs/addressmap.h"   // XIP_BASE
#include <string.h>

#define WIFICFG_OFF   (PICO_FLASH_SIZE_BYTES - FLASH_SECTOR_SIZE)
#define WIFICFG_VER   1
#define WIFICFG_AUTH_PSK  0
#define WIFICFG_AUTH_OPEN 1

typedef struct {
    char magic[4];              // "WCFG"
    uint8_t ver;                // WIFICFG_VER
    uint8_t auth;               // PSK or OPEN
    uint8_t _rsv[2];
    char ssid[WIFICFG_SSID_MAX + 1];
    char pass[WIFICFG_PASS_MAX + 1];
    uint32_t crc;               // crc32 over everything above
} wificfg_rec_t;

static char g_ssid[WIFICFG_SSID_MAX + 1];   // active (what the AP runs now)
static char g_pass[WIFICFG_PASS_MAX + 1];
static uint8_t g_auth;
static char s_ssid[WIFICFG_SSID_MAX + 1];   // staged (what SAVE will write)
static char s_pass[WIFICFG_PASS_MAX + 1];
static uint8_t s_auth;
static bool g_stored;                       // flash holds a valid record
static bool s_dirty;                        // staged differs from active

static uint32_t wificfg_crc32(const uint8_t *p, size_t n) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        crc ^= p[i];
        for (int k = 0; k < 8; k++)
            crc = (crc & 1) ? (crc >> 1) ^ 0xEDB88320u : (crc >> 1);
    }
    return crc ^ 0xFFFFFFFFu;
}

static bool rec_valid(const wificfg_rec_t *r) {
    if (memcmp(r->magic, "WCFG", 4) != 0 || r->ver != WIFICFG_VER) return false;
    if (r->auth != WIFICFG_AUTH_PSK && r->auth != WIFICFG_AUTH_OPEN) return false;
    if (r->ssid[WIFICFG_SSID_MAX] != 0 || r->pass[WIFICFG_PASS_MAX] != 0) return false;
    if (r->ssid[0] == 0 || strlen(r->ssid) > WIFICFG_SSID_MAX) return false;
    if (r->auth == WIFICFG_AUTH_PSK) {
        size_t n = strlen(r->pass);
        if (n < 8 || n > WIFICFG_PASS_MAX) return false;
    } else if (r->pass[0] != 0) {
        return false;
    }
    uint32_t want = wificfg_crc32((const uint8_t *)r,
                                  (size_t)((const uint8_t *)&r->crc - (const uint8_t *)r));
    return want == r->crc;
}

static void use_defaults(const char *why) {
    strncpy(g_ssid, WIFI_SSID, sizeof g_ssid - 1);
    strncpy(g_pass, WIFI_PASS, sizeof g_pass - 1);
    g_auth = WIFICFG_AUTH_PSK;
    strncpy(s_ssid, g_ssid, sizeof s_ssid - 1);
    strncpy(s_pass, g_pass, sizeof s_pass - 1);
    s_auth = g_auth;
    g_stored = false;
    s_dirty = false;
    FWLOG("wifi: using compiled defaults ssid=[%s] (%s)", g_ssid, why);
}

void wificfg_load(void) {
    const wificfg_rec_t *r =
        (const wificfg_rec_t *)(XIP_BASE + WIFICFG_OFF);
    if (rec_valid(r)) {
        memcpy(g_ssid, r->ssid, sizeof g_ssid);
        memcpy(g_pass, r->pass, sizeof g_pass);
        g_auth = r->auth;
        memcpy(s_ssid, g_ssid, sizeof s_ssid);
        memcpy(s_pass, g_pass, sizeof s_pass);
        s_auth = g_auth;
        g_stored = true;
        s_dirty = false;
        FWLOG("wifi: using stored config ssid=[%s] auth=%s",
              g_ssid, g_auth == WIFICFG_AUTH_OPEN ? "OPEN" : "WPA2");
    } else {
        use_defaults("no valid flash record");
    }
}

const char *wificfg_ssid(void) { return g_ssid; }
const char *wificfg_pass(void) { return g_pass; }
uint32_t wificfg_auth(void) {
    return g_auth == WIFICFG_AUTH_OPEN ? (uint32_t)CYW43_AUTH_OPEN
                                       : (uint32_t)CYW43_AUTH_WPA2_AES_PSK;
}
bool wificfg_have_stored(void) { return g_stored; }

void wificfg_show(void) {
    FWLOG("wifi: active ssid=[%s] auth=%s src=%s",
          g_ssid, g_auth == WIFICFG_AUTH_OPEN ? "OPEN" : "WPA2",
          g_stored ? "flash" : "compiled-defaults");
    if (s_dirty) {
        FWLOG("wifi: staged ssid=[%s] auth=%s (WIFI SAVE to apply, needs reboot)",
              s_ssid, s_auth == WIFICFG_AUTH_OPEN ? "OPEN" : "WPA2");
    }
    FWLOG("wifi: pass %s",
          g_auth == WIFICFG_AUTH_OPEN ? "(open network)"
          : (g_pass[0] ? "is set (not shown)" : "(MISSING - broken config)"));
}

static bool printable_ascii(const char *s, size_t n) {
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)s[i] < 0x20 || (unsigned char)s[i] > 0x7E) return false;
    return true;
}

void wificfg_stage_ssid(const char *s) {
    size_t n = strlen(s);
    if (n < 1 || n > WIFICFG_SSID_MAX || !printable_ascii(s, n)) {
        FWLOG("wifi: bad SSID (need 1..32 printable chars)");
        return;
    }
    strncpy(s_ssid, s, sizeof s_ssid - 1);
    s_ssid[sizeof s_ssid - 1] = 0;
    s_dirty = true;
    FWLOG("wifi: staged ssid=[%s] (WIFI SAVE to apply)", s_ssid);
}

void wificfg_stage_pass(const char *p) {
    size_t n = strlen(p);
    if (n < 8 || n > WIFICFG_PASS_MAX || !printable_ascii(p, n)) {
        FWLOG("wifi: bad passphrase (need 8..63 printable chars, or WIFI OPEN)");
        return;
    }
    strncpy(s_pass, p, sizeof s_pass - 1);
    s_pass[sizeof s_pass - 1] = 0;
    s_auth = WIFICFG_AUTH_PSK;
    s_dirty = true;
    FWLOG("wifi: staged WPA2 passphrase (%u chars, not shown)", (unsigned)n);
}

void wificfg_stage_open(void) {
    s_pass[0] = 0;
    s_auth = WIFICFG_AUTH_OPEN;
    s_dirty = true;
    FWLOG("wifi: staged OPEN network (WIFI SAVE to apply)");
}

// Erase the config sector and write one page. Returns 0 on success.
static int wificfg_flash_write(const wificfg_rec_t *rec) {
    watchdog_update();
    if (!multicore_lockout_start_timeout_us(500000)) {
        FWLOG("wifi: lockout timeout, flash untouched (core1 victim missing?)");
        return -1;
    }
    uint8_t page[FLASH_PAGE_SIZE];
    memset(page, 0xFF, sizeof page);
    if (rec) memcpy(page, rec, sizeof *rec);
    uint32_t irq = save_and_disable_interrupts();
    flash_range_erase(WIFICFG_OFF, FLASH_SECTOR_SIZE);
    flash_range_program(WIFICFG_OFF, page, sizeof page);
    restore_interrupts(irq);
    multicore_lockout_end_blocking();
    if (rec) {
        const wificfg_rec_t *rb =
            (const wificfg_rec_t *)(XIP_BASE + WIFICFG_OFF);
        if (memcmp(rb, rec, sizeof *rec) != 0) {
            FWLOG("wifi: flash verify FAILED");
            return -2;
        }
    }
    return 0;
}

static void wificfg_reboot(const char *why) {
    FWLOG("wifi: %s - rebooting to apply", why);
    sleep_ms(400);              // let the line drain over CDC first
    watchdog_reboot(0, 0, 100);
    for (;;) { }                // does not return
}

void wificfg_save(void) {
    if (!s_dirty) {
        FWLOG("wifi: nothing staged (WIFI SHOW to inspect)");
        return;
    }
    wificfg_rec_t rec;
    memset(&rec, 0, sizeof rec);
    memcpy(rec.magic, "WCFG", 4);
    rec.ver = WIFICFG_VER;
    rec.auth = s_auth;
    memcpy(rec.ssid, s_ssid, sizeof rec.ssid);
    memcpy(rec.pass, s_pass, sizeof rec.pass);
    rec.crc = wificfg_crc32((const uint8_t *)&rec,
                            (size_t)((const uint8_t *)&rec.crc - (const uint8_t *)&rec));
    if (wificfg_flash_write(&rec) == 0)
        wificfg_reboot("saved");
}

void wificfg_reset(void) {
    if (!g_stored) {
        FWLOG("wifi: no stored config (already on compiled defaults)");
        return;
    }
    if (wificfg_flash_write(NULL) == 0)
        wificfg_reboot("cleared to defaults");
}

void wificfg_on_cmd(uint8_t op, const char *ssid, const char *pass) {
    switch (op) {
    case WIFI_OP_SHOW: wificfg_show(); break;
    case WIFI_OP_SSID: wificfg_stage_ssid(ssid); break;
    case WIFI_OP_PASS: wificfg_stage_pass(pass); break;
    case WIFI_OP_OPEN: wificfg_stage_open(); break;
    case WIFI_OP_SAVE: wificfg_save(); break;
    case WIFI_OP_RESET: wificfg_reset(); break;
    default: break;
    }
}
