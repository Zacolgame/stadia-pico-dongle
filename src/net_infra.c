// net_infra.c — AP + DHCPD + DNS + SNTP over lwIP (raw API, one tcpip thread).
#include "net_infra.h"
#include "rtc.h"
#include "usb_hid.h"
#include "config.h"
#include "proto.h"
#include <string.h>
#include <stdio.h>
#include "pico/cyw43_arch.h"
#include "wificfg.h"
#include "hardware/gpio.h"
#include "lwip/ip_addr.h"
#include "lwip/udp.h"
#include "lwip/dns.h"
#include "dhcpserver.h"
#include "dnsserver.h"

volatile uint32_t g_eth_rx_frames = 0;
volatile uint32_t g_eth_rx_accept = 0;
// Cumulative frame counter that nothing ever resets, so "has the rx path ever worked?"
// can be answered at any time (net_infra_diag re-arms g_eth_rx_frames to 1 every second).
volatile uint32_t g_eth_rx_total = 0;
static int last_link_val = -1;
static uint32_t last_link_change_ms;
static absolute_time_t boot_t;

bool net_infra_ap_beaconing(void) {
    int st = cyw43_wifi_link_status(&cyw43_state, CYW43_ITF_AP);
    return st == CYW43_LINK_JOIN || st == CYW43_LINK_NOIP || st == CYW43_LINK_UP;
}

// ---- IPv6 RA sender (p3-3050-ipv6ra) -----------------------------------------
// Kills the controller's boot crash ritual: after associating it floods Router
// Solicitations (193 observed) because nothing on this IPv4-only AP answers
// IPv6; its init times out into the 3-round Crash pattern (kPatterns[38-45]).
// We multicast a Router Advertisement with router_lifetime=0 - "router present,
// NOT a default router" - so its IPv6 init completes at once. The frame itself
// is built by build_ipv6_ra() (proto.c), byte-exact against the host oracle
// tests/check_ipv6_ra.py. Costs one static 110 B buffer: LWIP_IPV6 stays 0.
static uint8_t ra_frame[IPV6_RA_FRAME_LEN];
static uint16_t ra_len;                       // 0 until the MAC is known + built
static uint32_t ra_sent, ra_last_ms;
static volatile uint32_t g_ipv6_rs_seen;      // every RS frame, cumulative
static volatile bool g_ipv6_rs_pending;       // hook arms, tick consumes
#define IPV6_RA_PERIOD_MS   5000   // unsolicited multicast cadence (task spec: 5 s)
#define IPV6_RA_MIN_GAP_MS  500    // RS-triggered cap: below RFC 4861's 3 s guidance
                                    // ON PURPOSE - the first RS must get its RA within
                                    // one RS retransmit (~78 ms), the storm is ~13 RS/s

static void ipv6_ra_build_once(void) {
    if (ra_len) return;
    const uint8_t *mac = cyw43_state.mac;
    if (!(mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5])) return; // not read yet
    ra_len = (uint16_t)build_ipv6_ra(ra_frame, mac);
    // Self-test the exact bytes that go on the air (see verify_ipv6_ra_checksum):
    // a checksum defect would make the controller drop every RA and the whole
    // fix would look like a no-op. The hex dump (2 lines) is Wireshark-checkable
    // from any capture - same convention as the rumble `hex1` self-certification.
    int ok = verify_ipv6_ra_checksum(ra_frame);
    FWLOG("ipv6: RA ready len=%u selftest=%s src=%02x:%02x:%02x:%02x:%02x:%02x",
          (unsigned)ra_len, ok ? "ok" : "FAIL",
          mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    char hx[IPV6_RA_FRAME_LEN + 1];
    for (int i = 0; i < 55; i++) sprintf(hx + 2 * i, "%02x", ra_frame[i]);
    FWLOG("ipv6: RA hex1=%s", hx);
    for (int i = 55; i < IPV6_RA_FRAME_LEN; i++) sprintf(hx + 2 * (i - 55), "%02x", ra_frame[i]);
    FWLOG("ipv6: RA hex2=%s", hx);
}

void net_infra_ipv6_tick(void) {
    ipv6_ra_build_once();
    if (!ra_len) return;
    // Only advertise while the AP interface is really up in the firmware
    // (bit CYW43_ITF_AP of itf_state; the optional STA experiment tears the AP
    // down and we must not keep multicasting on a dead interface).
    if (!(cyw43_state.itf_state & (1u << CYW43_ITF_AP))) return;
    uint32_t now = to_ms_since_boot(get_absolute_time());
    const char *why = NULL;
    if (g_ipv6_rs_pending && now - ra_last_ms >= IPV6_RA_MIN_GAP_MS) {
        // answer the first RS of a burst, swallow the rest for the gap window
        g_ipv6_rs_pending = false;
        why = "rs";
    } else if (ra_sent == 0 || now - ra_last_ms >= IPV6_RA_PERIOD_MS) {
        why = ra_sent ? "per" : "boot";
    }
    if (!why) return;
    // Raw ethernet send straight into the cyw43 SDPCM tx path - no netif, no
    // lwIP (LWIP_IPV6=0 stays); the driver takes the async-context lock itself.
    int rc = cyw43_send_ethernet(&cyw43_state, CYW43_ITF_AP, ra_len, ra_frame, false);
    ra_sent++; ra_last_ms = now;
    // Log budget: first 8 sends make one 90 s capture show the whole startup
    // ritual, then one line / 10 min keeps long sessions provably alive.
    if (ra_sent <= 8 || (ra_sent % 120) == 0)
        FWLOG("ipv6: RA sent (lifetime=0) n=%u rs=%u why=%s rc=%d",
              (unsigned)ra_sent, (unsigned)g_ipv6_rs_seen, why, rc);
}




// ------------------------------------------------- SNTP: answer with uptime-based clock
static struct udp_pcb *sntp_pcb;
static void sntp_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port) {
    if (p->len < 48) { pbuf_free(p); return; }
    static uint8_t out[48];
    memcpy(out, p->payload, 48);
    out[0] = 0x1c;
    memset(out + 8, 0, 32);
    // MUST land inside our certificate's validity window: the controller takes its
    // clock from here and rejects a "not yet valid" / expired server certificate.
    // It used to be a hard-coded 2025-01-01 while the cert is 2026-10 .. 2027-01.
    uint64_t secs = (uint64_t)rtc_cert_time_epoch() +
                    (uint64_t)(to_ms_since_boot(get_absolute_time()) / 1000);
    uint32_t n = (uint32_t)secs;
    out[16] = (uint8_t)(n >> 24); out[17] = (uint8_t)(n >> 16); out[18] = (uint8_t)(n >> 8); out[19] = (uint8_t)n;
    out[40] = (uint8_t)(n >> 24); out[41] = (uint8_t)(n >> 16); out[42] = (uint8_t)(n >> 8); out[43] = (uint8_t)n;
    struct pbuf *rp = pbuf_alloc(PBUF_TRANSPORT, 48, PBUF_RAM);
    if (rp) { memcpy(rp->payload, out, 48); udp_sendto(pcb, rp, addr, port); pbuf_free(rp); }
    pbuf_free(p);
}

void net_infra_init(void) {
    boot_t = get_absolute_time();
    // stadia-ap did this and we did not: WIFI_CHANNEL was defined but never used, so
    // the chip has been running the driver's default channel 3 (cyw43_ctrl.c:102,
    // consumed by cyw43_ll_wifi_ap_init at :682). Must be set before enable_ap_mode,
    // because that call runs set_up -> ap_init which consumes ap_channel.
    cyw43_wifi_ap_set_channel(&cyw43_state, WIFI_CHANNEL);
    // EXACTLY the official access_point example sequence
    cyw43_arch_enable_ap_mode(wificfg_ssid(), wificfg_pass(), wificfg_auth());
    // Diagnostics: log every async event (assoc/deauth/psk/link) and every eth TX.
    // The trace code IS compiled in even for Release (the name table is in the image),
    // so this is the cheapest way to see what the chip is really doing. ETH_RX is left
    // off on purpose: g_eth_rx_frames already counts it, and dumping frames over a
    // 115200 UART could stall the poll loop.
    cyw43_state.trace_flags |= CYW43_TRACE_ASYNC_EV | CYW43_TRACE_ETH_TX;
    // Two AP-state probes that need no client:
    //  * the WLAN MAC the chip actually uses - an all-zero or multicast MAC makes
    //    association impossible while beacons still work;
    //  * maxassoc, which only answers when the AP BSS is really up in the chip.
    {
        const uint8_t *m = cyw43_state.mac;
        int maxs = 0;
        cyw43_wifi_ap_get_max_stas(&cyw43_state, &maxs);
        FWLOG("ap mac=%02x:%02x:%02x:%02x:%02x:%02x maxassoc=%d ch=%u",
              m[0], m[1], m[2], m[3], m[4], m[5], maxs,
              (unsigned)cyw43_state.ap_channel);
    }
    struct netif *n = netif_default;
    ip4_addr_t ip, mask, gw;
    ip4addr_aton(AP_IP, &ip);
    IP4_ADDR(&mask, 255, 255, 255, 0);
    ip4_addr_set_zero(&gw);
    netif_set_addr(n, &ip, &mask, &gw);
    netif_set_up(n);
    netif_set_link_up(n);   // cyw43_lwip.c:274 drops every packet without LINK_UP
    // official pico-examples servers (MIT)
    static dhcp_server_t dhcp_server;
    static dns_server_t dns_server;
    dhcp_server_init(&dhcp_server, &ip, &mask);
    dns_server_init(&dns_server, &ip);
    sntp_pcb = udp_new();
    err_t se = udp_bind(sntp_pcb, IP_ADDR_ANY, PORT_SNTP);
    FWLOG("bind sntp port=%d err=%d", PORT_SNTP, (int)se);
    udp_recv(sntp_pcb, sntp_recv, NULL);
}
void net_infra_diag(char *out, int cap) {
    // one line: itf_state(hex) ap_link raw ap_ssid_len ap_auth ap_channel pm
    int st = cyw43_wifi_link_status(&cyw43_state, CYW43_ITF_AP);
    if (st != last_link_val) { last_link_val = st; last_link_change_ms = to_ms_since_boot(get_absolute_time()); }
    // Read FIRST, then arm. The old order armed to 1 and then read, so dxf was always 1
    // and the printed delta was always 0 - which made working reception look like rx=0.
    // The counters are ARMED to 1 and incremented by the callback, so the frames seen
    // during this interval = value - 1. (Reading before arming and subtracting the
    // previous snapshot underflows because the value is reset every call.)
    uint32_t dxf = g_eth_rx_frames ? g_eth_rx_frames - 1 : 0;
    uint32_t dxa = g_eth_rx_accept ? g_eth_rx_accept - 1 : 0;
    g_eth_rx_frames = 1; g_eth_rx_accept = 1;   // re-arm for the next interval
    // driver-side probes: did the poll worker / IRQ ever run, and did the chip ever
    // advertise a packet on gSPI?  (deltas since the previous diag call)
    extern volatile uint32_t g_cyw43_poll_runs, g_cyw43_irq_count;
    extern volatile uint32_t g_cyw43_polldev, g_cyw43_nopin, g_cyw43_pktavail;
    static uint32_t ppo, pirq, ppd, pnp, ppa;
    uint32_t dpo = g_cyw43_poll_runs - ppo, dirq = g_cyw43_irq_count - pirq;
    uint32_t dpd = g_cyw43_polldev - ppd, dnp = g_cyw43_nopin - pnp, dpa = g_cyw43_pktavail - ppa;
    ppo = g_cyw43_poll_runs; pirq = g_cyw43_irq_count;
    ppd = g_cyw43_polldev; pnp = g_cyw43_nopin; ppa = g_cyw43_pktavail;
    // RP2350-E9 (excess Bank-0 pad leakage) can make GPIO24 latch high; log the raw
    // level so a stuck/false-high IRQ line is visible in the same line.
    static uint32_t pin_hi, pin_total;
    int pin = gpio_get(CYW43_PIN_WL_HOST_WAKE);
    pin_total++;
    if (pin) pin_hi++;
    // RX dispatch census: if the chip advertises packets (pa>0) but rx stays 0, these
    // say which branch swallowed them: d=data(ok) a=async w=wrong-payload-type o=other.
    extern volatile uint32_t g_rx_nopkt, g_rx_flow, g_rx_async, g_rx_data,
                             g_rx_wrongtype, g_rx_other;
    static uint32_t pnop, pfl, pas, pda, pwt, pot;
    uint32_t dda = g_rx_data - pda, das = g_rx_async - pas;
    uint32_t dwt = g_rx_wrongtype - pwt, dot = g_rx_other - pot;
    // nopkt/flow were tracked but never shown. When the chip reports a packet as
    // available (pa>0) yet nothing becomes DATA or ASYNC, it lands in one of these two:
    // nk = poll returned -1 (the "available" bit was stale or the frame was consumed
    // already), fl = flow-control (-4) i.e. the chip is NOT ready to hand us a frame.
    uint32_t dnk = g_rx_nopkt - pnop, dfl = g_rx_flow - pfl;
    pnop = g_rx_nopkt; pfl = g_rx_flow; pas = g_rx_async;
    pda = g_rx_data; pwt = g_rx_wrongtype; pot = g_rx_other;
    // associated-station count: distinguishes "client never associated" from
    // "associated but the chip forwards nothing". NB cyw43_wifi_ap_get_stas() leaves
    // *num untouched on an early error return, so seed it with 0 (not 8).
    int nsta = 0;
    uint8_t macs[8][6];
    cyw43_wifi_ap_get_stas(&cyw43_state, &nsta, (uint8_t *)macs);
    snprintf(out, cap,
             "itf=%02x sta=%d sst=%d pin=%d rx=%u/%u rxr=%u po=%u irq=%u pd=%u np=%u pa=%u nk=%u fl=%u d=%u a=%u w=%u o=%u",
             (unsigned)cyw43_state.itf_state, nsta,
             cyw43_wifi_link_status(&cyw43_state, CYW43_ITF_STA), pin,
             (unsigned)dxf, (unsigned)dxa, (unsigned)g_eth_rx_total,
             (unsigned)dpo, (unsigned)dirq, (unsigned)dpd, (unsigned)dnp, (unsigned)dpa,
             (unsigned)dnk, (unsigned)dfl,
             (unsigned)dda, (unsigned)das, (unsigned)dwt, (unsigned)dot);
}

uint32_t net_infra_uptime_us(void) { return (uint32_t)to_us_since_boot(get_absolute_time()); }
bool net_infra_client_associated(void) {
    uint8_t macs[8][6];
    // NB: cyw43_wifi_ap_get_stas() returns EARLY without touching *num_stas when the
    // chip is not up yet, so a pre-seeded value makes sta= look permanently true.
    int num = 0;
    cyw43_wifi_ap_get_stas(&cyw43_state, &num, (uint8_t *)macs);
    return num > 0;
}

// Read back what we asked the chip to advertise, plus maxassoc (which only answers when
// the AP BSS is really up). Used by the periodic heartbeat so a late-opened serial port
// still shows whether the AP is genuinely configured.
void net_infra_ap_info(char *ssid_out, int cap, int *maxstas, int *chan, int *auth) {
    int n = cyw43_state.ap_ssid_len;
    if (n > 31) n = 31;
    for (int i = 0; i < n && i < cap - 1; i++) ssid_out[i] = (char)cyw43_state.ap_ssid[i];
    ssid_out[n < cap - 1 ? n : cap - 1] = 0;
    int m = 0; cyw43_wifi_ap_get_max_stas(&cyw43_state, &m);
    if (maxstas) *maxstas = m;
    if (chan) *chan = (int)cyw43_state.ap_channel;
    if (auth) *auth = (int)cyw43_state.ap_auth;
}

// Called by the cyw43 driver glue for every ethernet frame it hands to lwIP. Logs the
// first few so we can see WHO is actually transmitting to us (the AP station list ioctl
// may itself be failing, which would make sta=0 a false negative).
void fw_rx_frame_hook(const uint8_t *b, size_t n) {
    // IPv6 Router Solicitation detect (p3-3050-ipv6ra): must run on EVERY frame,
    // so it sits ABOVE the 1/s logging gate below. RS = ethertype 0x86dd, IPv6
    // next header 58 (ICMPv6), type 133 (dst ff02::2 arrives as eth dst
    // 33:33:00:00:00:02, but only the L3/L4 fields matter here). We only arm the
    // flag - the RA goes out from net_infra_ipv6_tick() in the main loop, never
    // from inside cyw43_poll() (no re-entrant driver/bus access).
    if (n >= 14 + 40 + 8 && b[12] == 0x86 && b[13] == 0xdd &&
        (b[14] & 0xf0) == 0x60 && b[20] == 58 && b[54] == 133) {
        g_ipv6_rs_seen++;
        g_ipv6_rs_pending = true;
    }
    // One frame per second, fully decoded at L3/L4. Knowing only the ethertype was not
    // enough: we saw a real client sending IPv4 unicast to our AP MAC and could not tell
    // whether it was DHCP, DNS, TCP/443, STUN or DTLS.
    static uint32_t last_ms;
    uint32_t now = to_ms_since_boot(get_absolute_time());
    if (now - last_ms < 1000) return;
    last_ms = now;
    if (n < 14) return;
    uint16_t et = (uint16_t)((b[12] << 8) | b[13]);
    if (et != 0x0800 || n < 34) {
        FWLOG("RXF et=0x%04x n=%u src=%02x:%02x:%02x:%02x:%02x:%02x",
              (unsigned)et, (unsigned)n, b[6], b[7], b[8], b[9], b[10], b[11]);
        return;
    }
    const uint8_t *ip = b + 14;
    int ihl = (ip[0] & 0x0f) * 4;
    uint8_t proto = ip[9];
    const char *pn = proto == 6 ? "TCP" : proto == 17 ? "UDP" : proto == 1 ? "ICMP" : "?";
    uint16_t sp = 0, dp = 0;
    if ((proto == 6 || proto == 17) && ihl >= 20 && (int)n >= 14 + ihl + 4) {
        sp = (uint16_t)((ip[ihl] << 8) | ip[ihl + 1]);
        dp = (uint16_t)((ip[ihl + 2] << 8) | ip[ihl + 3]);
    }
    FWLOG("RXF %s %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u n=%u smac=%02x:%02x:%02x:%02x:%02x:%02x",
          pn, ip[12], ip[13], ip[14], ip[15], (unsigned)sp,
          ip[16], ip[17], ip[18], ip[19], (unsigned)dp, (unsigned)n,
          b[6], b[7], b[8], b[9], b[10], b[11]);
}
