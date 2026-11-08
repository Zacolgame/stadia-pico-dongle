/**
 * Copyright (c) 2022 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>

#include "dnsserver.h"
#include "config.h"    // CLEARCUT_DNS_NXDOMAIN
#include "usb_hid.h"   // FWLOG
#include "lwip/udp.h"

#define PORT_DNS_SERVER 53
#define DUMP_DATA 0

#define DEBUG_printf(...)
#define ERROR_printf printf

typedef struct dns_header_t_ {
    uint16_t id;
    uint16_t flags;
    uint16_t question_count;
    uint16_t answer_record_count;
    uint16_t authority_record_count;
    uint16_t additional_record_count;
} dns_header_t;

#define MAX_DNS_MSG_SIZE 300

static int dns_socket_new_dgram(struct udp_pcb **udp, void *cb_data, udp_recv_fn cb_udp_recv) {
    *udp = udp_new();
    if (*udp == NULL) {
        return -ENOMEM;
    }
    udp_recv(*udp, cb_udp_recv, (void *)cb_data);
    return ERR_OK;
}

static void dns_socket_free(struct udp_pcb **udp) {
    if (*udp != NULL) {
        udp_remove(*udp);
        *udp = NULL;
    }
}

static int dns_socket_bind(struct udp_pcb **udp, uint32_t ip, uint16_t port) {
    ip_addr_t addr;
    IP4_ADDR(&addr, ip >> 24 & 0xff, ip >> 16 & 0xff, ip >> 8 & 0xff, ip & 0xff);
    err_t err = udp_bind(*udp, &addr, port);
    if (err != ERR_OK) {
        ERROR_printf("dns failed to bind to port %u: %d", port, err);
        assert(false);
    }
    return err;
}

#if DUMP_DATA
static void dump_bytes(const uint8_t *bptr, uint32_t len) {
    unsigned int i = 0;

    for (i = 0; i < len;) {
        if ((i & 0x0f) == 0) {
            printf("\n");
        } else if ((i & 0x07) == 0) {
            printf(" ");
        }
        printf("%02x ", bptr[i++]);
    }
    printf("\n");
}
#endif

// Reply with the source address the query was addressed to. A device with a hard-coded
// resolver (the Stadia controller uses 8.8.8.8) discards answers arriving from any other
// IP, so a plain udp_sendto reply from 192.168.137.1 would be silently ignored.
static const ip_addr_t *g_reply_src;
static struct netif *g_reply_netif;

static int dns_socket_sendto(struct udp_pcb **udp, const void *buf, size_t len, const ip_addr_t *dest, uint16_t port) {
    if (len > 0xffff) {
        len = 0xffff;
    }

    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
    if (p == NULL) {
        ERROR_printf("DNS: Failed to send message out of memory\n");
        return -ENOMEM;
    }

    memcpy(p->payload, buf, len);
    err_t err;
    if (g_reply_src != NULL && g_reply_netif != NULL && IP_IS_V4(g_reply_src)) {
        err = udp_sendto_if_src(*udp, p, dest, port, g_reply_netif, g_reply_src);
    } else {
        err = udp_sendto(*udp, p, dest, port);
    }

    pbuf_free(p);

    if (err != ERR_OK) {
        ERROR_printf("DNS: Failed to send message %d\n", err);
        return err;
    }

#if DUMP_DATA
    dump_bytes(buf, len);
#endif
    return len;
}

static void dns_server_process(void *arg, struct udp_pcb *upcb, struct pbuf *p, const ip_addr_t *src_addr, u16_t src_port) {
    // Where was this query sent? Answer FROM that address (see g_reply_src above).
    g_reply_src = ip_current_dest_addr();
    g_reply_netif = ip_current_input_netif();
    dns_server_t *d = arg;
    DEBUG_printf("dns_server_process %u\n", p->tot_len);

    uint8_t dns_msg[MAX_DNS_MSG_SIZE];
    dns_header_t *dns_hdr = (dns_header_t*)dns_msg;

    size_t msg_len = pbuf_copy_partial(p, dns_msg, sizeof(dns_msg), 0);
    if (msg_len < sizeof(dns_header_t)) {
        goto ignore_request;
    }

#if DUMP_DATA
    dump_bytes(dns_msg, msg_len);
#endif

    uint16_t flags = lwip_ntohs(dns_hdr->flags);
    uint16_t question_count = lwip_ntohs(dns_hdr->question_count);

    DEBUG_printf("len %d\n", msg_len);
    DEBUG_printf("dns flags 0x%x\n", flags);
    DEBUG_printf("dns question count 0x%x\n", question_count);

    // flags from rfc1035
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    // Check QR indicates a query
    if (((flags >> 15) & 0x1) != 0) {
        DEBUG_printf("Ignoring non-query\n");
        goto ignore_request;
    }

    // Check for standard query
    if (((flags >> 11) & 0xf) != 0) {
        DEBUG_printf("Ignoring non-standard query\n");
        goto ignore_request;
    }

    // Check question count
    if (question_count < 1) {
        DEBUG_printf("Invalid question count\n");
        goto ignore_request;
    }

    // Print the question
    DEBUG_printf("question: ");
    const uint8_t *question_ptr_start = dns_msg + sizeof(dns_header_t);
    const uint8_t *question_ptr_end = dns_msg + msg_len;
    const uint8_t *question_ptr = question_ptr_start;
    char qname[128]; int qn = 0;
    while(question_ptr < question_ptr_end) {
        if (*question_ptr == 0) {
            question_ptr++;
            break;
        } else {
            int label_len = *question_ptr++;
            if (label_len > 63) {
                DEBUG_printf("Invalid label\n");
                goto ignore_request;
            }
            if (qn + label_len + 2 < (int)sizeof qname) {
                if (qn) qname[qn++] = '.';
                for (int li = 0; li < label_len; li++) {
                    char ch = (char)question_ptr[li];
                    qname[qn++] = (ch >= 'A' && ch <= 'Z') ? (char)(ch - 'A' + 'a') : ch;
                }
            }
            question_ptr += label_len;
        }
    }
    qname[qn] = 0;
    DEBUG_printf("%s\n", qname);
    {   // Log every query and what we answer. Without this the only DNS evidence was the
        // NXDOMAIN rule, so "the resolver never asked for the FVC host" and "we answered
        // the wrong thing" looked identical from the log.
        static int dnslog;
        if (dnslog < 40) { dnslog++; FWLOG("dns q=[%s] from %d.%d.%d.%d", qname,
            ip4_addr1(ip_2_ip4(src_addr)), ip4_addr2(ip_2_ip4(src_addr)),
            ip4_addr3(ip_2_ip4(src_addr)), ip4_addr4(ip_2_ip4(src_addr))); }
    }

    // play.googleapis.com is the controller's boot "internet self-check" name AND the
    // Clearcut analytics host. §9.83: a Clearcut upload that SUCCEEDS powers the
    // controller off ~0.3 s later, so the upload must keep failing - but failing it at
    // DNS level also fails the boot check, and the controller then walks a 3-round
    // discovery ritual before ever contacting cloudcast-pa (pico-log-20261104-232650:
    // 4x NXDOMAIN, cloudcast-pa only ~13 s after association; with real DNS in the
    // PC era the check passed instantly). The reference "live" preset resolves
    // *.googleapis.com to the receiver (dns_sink DEFAULT_REDIRECTS) and blocks the
    // upload at the TLS layer instead (clearcut_block="tls"). We mirror that: answer
    // our IP here, refuse the SNI in https.c (CLEARCUT_BLOCK_TLS). The queries aimed
    // at the hard-coded 8.8.8.8 also land here (the reply source is spoofed via
    // g_reply_src), so all four boot lookups now succeed.
#if CLEARCUT_DNS_NXDOMAIN
    if (strstr(qname, "play.googleapis.com") != NULL) {
        dns_hdr->flags = lwip_htons(
                    0x1 << 15 |  // QR = response
                    0x1 << 10 |  // AA = authoritative
                    0x1 << 7  |  // RA = recursion available
                    3);          // RCODE = NXDOMAIN
        dns_hdr->question_count = lwip_htons(1);
        dns_hdr->answer_record_count = 0;
        dns_hdr->authority_record_count = 0;
        dns_hdr->additional_record_count = 0;
        dns_socket_sendto(&d->udp, &dns_msg, (question_ptr - dns_msg) + 4, src_addr, src_port);
        FWLOG("dns: NXDOMAIN for %s (keep Clearcut from going through)", qname);
        goto ignore_request;
    }
#else
    if (strstr(qname, "play.googleapis.com") != NULL)
        FWLOG("dns: %s -> us (fastboot selfcheck; Clearcut blocked at TLS)", qname);
#endif

    // Boot-finishing endpoints (stadiacast docs/protocol.md §1 boot table): stadiaconfig
    // on clients3.google.com, Omaha /service/update2 on update.googleapis.com. Both
    // queries are answered with our IP by the catch-all A reply below; these lines make
    // the two boot-critical lookups explicit, mirroring the play.googleapis.com note
    // above. Evidence they must land on us AND be answered with the reference templates:
    // pico-log-20261105-010051 - POST /service/update2 body=626 answered by the old
    // static XML at t=77205, then ~2.5 min of idle heartbeats and a second full DHCP
    // round (lines 624-626 vs the first at lines 5-8) = the boot ritual residue.
    if (strstr(qname, "clients3.google.com") != NULL)
        FWLOG("dns: %s -> us (boot endpoint: stadiaconfig)", qname);
    if (strstr(qname, "update.googleapis.com") != NULL)
        FWLOG("dns: %s -> us (boot endpoint: omaha /service/update2)", qname);

    // Check question length
    if (question_ptr - question_ptr_start > 255) {
        DEBUG_printf("Invalid question length\n");
        goto ignore_request;
    }

    // Skip QNAME and QTYPE
    question_ptr += 4;

    // Generate answer
    uint8_t *answer_ptr = dns_msg + (question_ptr - dns_msg);
    *answer_ptr++ = 0xc0; // pointer
    *answer_ptr++ = question_ptr_start - dns_msg; // pointer to question
    
    *answer_ptr++ = 0;
    *answer_ptr++ = 1; // host address

    *answer_ptr++ = 0;
    *answer_ptr++ = 1; // Internet class

    *answer_ptr++ = 0;
    *answer_ptr++ = 0;
    *answer_ptr++ = 0;
    *answer_ptr++ = 60; // ttl 60s

    *answer_ptr++ = 0;
    *answer_ptr++ = 4; // length
    memcpy(answer_ptr, &d->ip.addr, 4); // use our address
    answer_ptr += 4;

    dns_hdr->flags = lwip_htons(
                0x1 << 15 | // QR = response
                0x1 << 10 | // AA = authoritative
                0x1 << 7);   // RA = authenticated
    dns_hdr->question_count = lwip_htons(1);
    dns_hdr->answer_record_count = lwip_htons(1);
    dns_hdr->authority_record_count = 0;
    dns_hdr->additional_record_count = 0;

    // Send the reply
    DEBUG_printf("Sending %d byte reply to %s:%d\n", answer_ptr - dns_msg, ipaddr_ntoa(src_addr), src_port);
    dns_socket_sendto(&d->udp, &dns_msg, answer_ptr - dns_msg, src_addr, src_port);

ignore_request:
    pbuf_free(p);
}

void dns_server_init(dns_server_t *d, ip_addr_t *ip) {
    if (dns_socket_new_dgram(&d->udp, d, dns_server_process) != ERR_OK) {
        DEBUG_printf("dns server failed to start\n");
        return;
    }
    if (dns_socket_bind(&d->udp, 0, PORT_DNS_SERVER) != ERR_OK) {
        DEBUG_printf("dns server failed to bind\n");
        return;
    }
    ip_addr_copy(d->ip, *ip);
    DEBUG_printf("dns server listening on port %d\n", PORT_DNS_SERVER);
}

void dns_server_deinit(dns_server_t *d) {
    dns_socket_free(&d->udp);
}
