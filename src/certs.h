// generated certificate material (do not commit)
#ifndef CERTS_H
#define CERTS_H

extern const unsigned char TLS_CERT_PEM[];
extern const unsigned int TLS_CERT_PEM_len;
extern const unsigned char TLS_KEY_PEM[];
extern const unsigned int TLS_KEY_PEM_len;

extern const unsigned char TLS_LEAF_PEM[];     // RSA leaf, used by DTLS
extern const unsigned int TLS_LEAF_PEM_len;
extern const unsigned char TLS_EC_CERT_PEM[];  // ECDSA alternative (unused by default)
extern const unsigned int TLS_EC_CERT_PEM_len;
extern const unsigned char TLS_EC_KEY_PEM[];
extern const unsigned int TLS_EC_KEY_PEM_len;

#endif
