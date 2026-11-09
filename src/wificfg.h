// wificfg.h - AP credential management: compiled defaults + flash-stored override.
//
// The AP SSID/password used to be compile-time only (WIFI_SSID/WIFI_PASS in
// config.h). The CDC console now manages them at runtime:
//
//   WIFI SHOW            active + staged + stored credentials (pass never printed)
//   WIFI SSID <1..32>    stage SSID (spaces allowed: rest of line is the value)
//   WIFI PASS <8..63>    stage WPA2 passphrase (spaces allowed)
//   WIFI OPEN            stage an open network (no password)
//   WIFI SAVE            write staged config to flash, reboot to apply
//   WIFI RESET           erase stored config, reboot back to compiled defaults
//
// The controller remembers the same credentials, so changing them here means
// re-provisioning the controller too (see README "WiFi credentials").
// Recovery is always one command away: WIFI SHOW/RESET never need the AP.
#pragma once
#include <stdbool.h>
#include <stdint.h>

#define WIFICFG_SSID_MAX 32
#define WIFICFG_PASS_MAX 63

// core0, once at boot, BEFORE net_infra_init().
void wificfg_load(void);
// Active config (stored record, or compiled defaults when none/invalid).
const char *wificfg_ssid(void);
const char *wificfg_pass(void);   // "" when the network is open
uint32_t wificfg_auth(void);      // CYW43_AUTH_* constant for enable_ap_mode()
bool wificfg_have_stored(void);   // a valid flash record exists
// Console operations (core0; results go out as FWLOG lines).
void wificfg_show(void);
void wificfg_stage_ssid(const char *s);
void wificfg_stage_pass(const char *p);
void wificfg_stage_open(void);
void wificfg_save(void);          // flash write, then reboot to apply
void wificfg_reset(void);         // flash erase, then reboot to defaults
// IPC mailbox consumer glue (op = WIFI_OP_* from ipc.h).
void wificfg_on_cmd(uint8_t op, const char *ssid, const char *pass);
