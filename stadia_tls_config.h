// TLS/DTLS server config for the SDK's mbedtls 2.28 (TLS 1.2 + DTLS 1.2).
#ifndef __STADIA_TLS_CONFIG_H
#define __STADIA_TLS_CONFIG_H

#define MBEDTLS_CONFIG_VERSION 0x02280000

#define MBEDTLS_PLATFORM_C
#define MBEDTLS_NO_PLATFORM_ENTROPY     // pico_mbedtls.c provides hardware feed
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_HARDWARE_ALT
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_RSA_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_OID_C
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_MD_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA256_C 1
#define MBEDTLS_SHA256_C 1
#define MBEDTLS_SHA512_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21
#define MBEDTLS_MD5_C
#define MBEDTLS_HMAC_DRBG_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED
#define MBEDTLS_ECDH_C
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CCM_C
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_POLY1305_C
#define MBEDTLS_CHACHAPOLY_C
#define MBEDTLS_CIPHER_C
// AES-CTR: the SRTP AES128_CM protect/KDF for the speaker-audio path needs
// mbedtls_aes_crypt_ctr (rtc.c audio section).
#define MBEDTLS_CIPHER_MODE_CTR
// Needed for mbedtls_ssl_conf_dbg: without it a rejected handshake is completely silent.
#define MBEDTLS_DEBUG_C
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_SRV_C
#define MBEDTLS_SSL_CLI_C
// DTLS 1.0 is TLS 1.1 underneath: without TLS1_1 mbedtls refuses a peer whose
// ClientHello only offers DTLS 1.0 (the controller's record version is FEFF).
#define MBEDTLS_SSL_PROTO_TLS1_1
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_PROTO_DTLS
#define MBEDTLS_SSL_DTLS_HELLO_VERIFY
#define MBEDTLS_SSL_DTLS_ANTI_REPLAY
// use_srtp negotiation: the controller's ClientHello offers SRTP_AES128_CM_SHA1_80 and
// the verified reference (stadiacast/OpenSSL) echoes it; without the echo the controller
// abandons the session right after the handshake (see rtc.c link_setup).
#define MBEDTLS_SSL_DTLS_SRTP
#define MBEDTLS_SSL_EXPORT_KEYS 0
#define MBEDTLS_SSL_COOKIE_C
#define MBEDTLS_SSL_CACHE_C
#define MBEDTLS_SSL_SERVER_NAME_INDICATION
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
#define MBEDTLS_SSL_EXPORT_KEYS

// p3-3644: per-connection TLS/DTLS record buffers are malloc'd from the heap by
// mbedtls_ssl_setup(). The controller opens THREE concurrent TLS connections on
// top of TWO DTLS contexts, and with the default 16 KB records each context
// needs ~33-45 KB - the heap died at the first TLS accept (real-machine
// PREVRESET: "accept slot=0 ssl_setup heap=36864" then WDT). Our messages are
// small - the largest outbound record is the 4.1 KB DER certificate chain,
// which TLS fragments - so 4 KB records are plenty and cut the per-connection
// need to ~12 KB. NOTE (p3-3632 lesson): THIS is the live config file - the SDK
// consumes it via PICO_MBEDTLS_CONFIG_FILE. A lookalike mbedtls_config.h in the
// repo root is NOT referenced by the build; editing it is a silent no-op.
#define MBEDTLS_SSL_IN_CONTENT_LEN  4096
#define MBEDTLS_SSL_OUT_CONTENT_LEN 4096



#define MBEDTLS_TIMING_ALT
#include "mbedtls/check_config.h"
#endif
