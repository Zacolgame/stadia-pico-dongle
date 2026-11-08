// net_infra.h — WiFi AP + DHCP + DNS + SNTP: the Pico's own little internet.
#pragma once
#include "pico/stdlib.h"

void net_infra_init(void);
void net_infra_ap_info(char *ssid_out, int cap, int *maxstas, int *chan, int *auth);   // starts AP, DHCPD, DNS(:53), SNTP(:123)
uint32_t net_infra_uptime_us(void); // monotonic us since boot (for time echo / SNTP)
bool net_infra_client_associated(void);
bool net_infra_ap_beaconing(void);
void net_infra_diag(char *out, int cap);
// p3-3050-ipv6ra: multicast an ICMPv6 Router Advertisement with router_lifetime=0
// while the AP is up (5 s cadence + on the first Router Solicitation), so the
// controller's boot-time IPv6 init completes instead of timing out into the
// 3-round crash pattern. Call ~every 50 ms from the main loop. Frame bytes come
// from build_ipv6_ra() (proto.c), host-oracled by tests/check_ipv6_ra.py.
void net_infra_ipv6_tick(void);
