// rtc.h — the display link and game session: STUN/ICE + DTLS + WireHeader2 RPC.
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stdint.h>

// buttons: Message3 f1 raw bit layout (see stadiacast gamepad.py) - u32 since
// p3-2340 because bit 16 (the Stadia logo button) must survive decoding: the
// XInput report maps it onto the Guide bit.
typedef struct { uint32_t buttons; int16_t lx, ly, rx, ry; uint8_t lt, rt; } pad_state_t;
extern volatile pad_state_t pad;              // latest input (fed to USB HID)
extern volatile bool pad_fresh;
extern volatile uint32_t input_seq_seen;

void rtc_init(void);                          // both UDP endpoints + timers
void rtc_display_rpc_arm(void);               // v1:ResolveDiscovery served: arm the GetControllerStateRequest loop
void rtc_reset_display_session(void);         // new offer adopted: drop zombie Ld state (reset_boot_state mirror)
void rtc_tick(void);
uint32_t rtc_cert_time_epoch(void);  // clock inside the server cert validity (SNTP source)                          // call ~every 50ms: fast ICE checks, keepalive refresh
void rtc_send_rumble(uint16_t left, uint16_t right); // -> 0x66 envelope on game link (also starts 2s refresh)
void rtc_rumble_off(void);
void rtc_rumble_pulse(void);                     // CDC "RUMBLE" cmd: 200 ms / 75% both motors, auto-off
void rtc_audio_tone_start(uint32_t ms);     // TONE console cmd: 440 Hz Opus/SRTP on the display link
void rtc_audio_set_source(int usb);         // internal speaker-source setter (p3-3500: driven by the
                                            // automatic USB-data detection in rtc_tick; the AUDIOSRC
                                            // console command is deleted - zero-config audio)
void rtc_audio_test_raw(void);              // AUDPTEST console cmd: ONE unprotected RTP frame (control experiment)
int rtc_audio_frames_sent(void);            // lifetime SRTP audio frames (heartbeat)
bool rtc_game_connected(void);
bool rtc_display_ready(void);
int rtc_pcb_mask(void);                        // hb: bit0 display pcb, bit1 game pcb (3 = both)
