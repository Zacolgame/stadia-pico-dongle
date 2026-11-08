// https.h — TLS 1.3 server on :443 with the boot/discovery/gmsg endpoints.
#pragma once
#include <stdint.h>
#include <stdbool.h>

void https_init(void);       // spawns the TLS listener (mbedTLS, thread-safe via its own thread)
void https_poll(void);       // call from core loop if single-threaded mode
void https_diag(char *dst, int dstlen);  // per-slot "state,txlen,httplen,sslstate" for the heartbeat
