/*
 * lwipopts.h -- stadia-ap 的 lwIP 配置（NO_SYS raw API，两个 netif：
 * CYW43 SoftAP + TinyUSB RNDIS/ECM）。本文件在 include 路径上先于 SDK 的
 * lwip/src/include，会被编译进本目标的所有 lwIP 源文件（INTERFACE sources
 * 挂在应用目标上编译）一并生效。
 *
 * 基线拷自 research/pico2w/firmware/include/lwipopts.h（在本 SDK 上编译/审查过）。
 * 差异：无 webserver/CLI/BLE → 内存略增（NAT 的 PBUF_RAM 拷贝）。
 */
#ifndef _LWIPOPTS_H
#define _LWIPOPTS_H

/* ---------- core ---------- */
#define NO_SYS                      1
#define SYS_LIGHTWEIGHT_PROT        1
#define MEM_ALIGNMENT               4

#define LWIP_SINGLE_NETIF           0        /* AP + USB 两个 netif */
#define LWIP_NETIF_HOSTNAME         1
#define LWIP_NETIF_STATUS_CALLBACK  1
#define LWIP_NETIF_LINK_CALLBACK    1
#define LWIP_NETIF_REMOVE_CALLBACK  1

/* ---------- protocols ---------- */
#define LWIP_IPV4                   1
#define LWIP_IPV6                   0
#define LWIP_ARP                    1
#define LWIP_ETHERNET               1
#define LWIP_ICMP                   1        /* 回 ping（调试用） */
#define LWIP_RAW                    0
#define LWIP_UDP                    1        /* DHCP server */
#define LWIP_TCP                    1        /* TLS:443 server */
#define MEMP_NUM_TCP_PCB             4
#define MEMP_NUM_TCP_PCB_LISTEN      2
#define MEMP_NUM_TCP_SEG             32
#define TCP_SND_BUF                  4096
#define TCP_MSS                      1280
#define TCP_WND                      4096
#define TCP_SND_QUEUELEN             16
#define LWIP_DISABLE_TCP_SANITY_CHECKS 1
#define LWIP_TCP_KEEPALIVE           1
#define LWIP_DNS                    0        /* 我们是 DHCP server，不是 DNS 客户端 */
#define LWIP_DHCP                   0        /* 我们自己跑 DHCP server */
#define LWIP_AUTOIP                 0
#define LWIP_IGMP                   0
/* --- 广播丢弃 workaround（pico-examples#783 / 论坛 p=2386705）-------------------
 * lwIP 2.1 的 ip4_input() 里：
 *     #if LWIP_IGMP || IP_ACCEPT_LINK_LAYER_ADDRESSING
 *       if (check_ip_src && !ip4_addr_isany_val(src))
 *     #endif
 *       { if (broadcast||multicast) { 丢弃 } }     ← 花括号在 #if 之外
 * 当 LWIP_IGMP=0 且 LWIP_DHCP=0 时，守卫被预处理掉、但它的**函数体保留**，
 * 于是所有广播/多播 IP 包被无条件丢弃 —— 包括 DHCP DISCOVER
 * （源 0.0.0.0、目的 255.255.255.255），客户端永远拿不到 IP。
 * 定义 LWIP_IP_ACCEPT_UDP_PORT（哪怕值就是 0）即可强制
 * IP_ACCEPT_LINK_LAYER_ADDRESSING=1、恢复正确守卫，且**不会**引入 DHCP 客户端代码。
 * 不要删这行。 */
// Accept UDP datagrams sent to a DNS server IP that is not ours (e.g. the controller's
// hard-coded 8.8.8.8). Without this lwIP drops them at ip4_input and the device can never
// resolve a name, so it never reaches our HTTPS server. The DNS responder answers with a
// source address equal to the query's destination (udp_sendto_if_src), so the client sees
// a reply from the server it asked.
#define LWIP_IP_ACCEPT_UDP_PORT(port) ((port) == PP_NTOHS(53))
#define LWIP_SNMP                   0
#define LWIP_MDNS_RESPONDER         0

/* 无 socket/netconn 层（纯 raw API） */
#define LWIP_NETCONN                0
#define LWIP_SOCKET                 0
#define LWIP_COMPAT_SOCKETS         0
#define LWIP_POSIX_SOCKETS_IO_NAMES 0

/* 转发在应用层（nat.c），不开 lwIP IP_FORWARD */
#define IP_FORWARD                  0

/* ---------- memory ---------- */
#define MEM_LIBC_MALLOC             0
#define MEMP_MEM_MALLOC             0
#define MEM_SIZE                    (48 * 1024)
#define MEMP_NUM_PBUF               16
/* 2026-11-04 (p3-1435): the boot census of udp_new() is FIVE, not four -
 * dhcpserver.c(67), dnsserver.c(53), net_infra.c SNTP(95), rtc.c Ld :40000,
 * rtc.c Lg :40001. With 4 slots the GAME link's udp_new() returned NULL;
 * udp_bind(NULL,...) then returns ERR_ARG via LWIP_ERROR (a printf that is lost
 * because the CDC log port opens seconds after boot) and NOTHING listens on
 * 40001: the controller's game ICE checks arrive (RXF proves it) and lwIP drops
 * every one - "0 stun game: lines, source port rebinds" (pico-log-20261104-142004).
 * 6 = 5 users + 1 spare; each element is 32 bytes. */
#define MEMP_NUM_UDP_PCB            6
#define MEMP_NUM_TCP_PCB            4
#define MEMP_NUM_TCP_PCB_LISTEN     2
#define MEMP_NUM_TCP_SEG            32
#define MEMP_NUM_ARP_QUEUE          8
#define MEMP_NUM_NETBUF             0
#define MEMP_NUM_SYS_TIMEOUT        (LWIP_NUM_SYS_TIMEOUT_INTERNAL + 4)

#define PBUF_POOL_SIZE              24
#define PBUF_POOL_BUFSIZE           1528

/* ---------- misc ---------- */
#define ETH_PAD_SIZE                0
#define ETHARP_SUPPORT_STATIC_ENTRIES 1
#define LWIP_NETIF_TX_SINGLE_PBUF   1
#define LWIP_CHKSUM_ALGORITHM       3
#define LWIP_CHECKSUM_CTRL_PER_NETIF 1
#define SYS_STATS                   0
#define MEM_STATS                   0
#define LWIP_STATS                  0
#define LWIP_DEBUG                  0

#endif /* _LWIPOPTS_H */
