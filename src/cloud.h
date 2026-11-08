// cloud.h — the controller-facing state: discovery session + gmsg queue + session creds.
#pragma once
#include "proto.h"
#include <stdint.h>
#include <stdbool.h>

typedef enum {
    CLOUD_BOOT = 0,          // waiting for RegisterController
    CLOUD_REGISTERED,        // offer accepted; answer queued on gmsg
    CLOUD_LINK_UP,           // display-link DTLS connected
    CLOUD_READY,             // controller answered GetControllerState
    CLOUD_GAME_STARTED,      // game session DTLS connected
} cloud_state_t;

extern volatile cloud_state_t cloud_state;
extern sdp_offer_info_t cloud_offer;          // parsed display-link offer (echo source)
extern rtc_creds_t cloud_disp_creds;          // our display-link ICE creds
extern rtc_creds_t cloud_game_creds;          // our game ICE creds
extern char cloud_ip_str[16];                 // "192.168.137.1"

void cloud_init(void);                        // generates creds, resets state
void cloud_set_fingerprint(const char *fp);   // called by dtls.c after cert load ("sha-256 XX:..")
const char *cloud_cert_fingerprint(void);
void cloud_on_register(const uint8_t *body, int len, uint8_t *out, int *out_len);
void cloud_on_discover(const uint8_t *body, int len, uint8_t *out, int *out_len); // same display id/token as register + offer extraction
bool cloud_gmsg_poll(const uint8_t *body, int len, uint8_t *out, int *out_len); // true = envelope ready
const uint8_t *cloud_take_gmsg(int *len);     // the queued answer bundle (NULL until register)
void cloud_reset_link(void);                  // controller rebooted: back to BOOT
uint32_t cloud_next_ticket(void);             // our outbound RPC tickets (first=1, per-boot)
