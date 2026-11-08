#!/usr/bin/env python3
"""gen-dtls-cert.py -- (re)generate the throwaway DTLS lab identity.

Usage (from repo root):  python tools/gen-dtls-cert.py
Writes vendor/selfsigned-dtls/{leaf,privkey}.pem, then run
tools/gen-certs.py to compile them into src/certs.c.

The DTLS path pins the leaf by its SHA-256 fingerprint carried in the SDP
answer and never validates a chain, so a minimal self-signed ECDSA P-256
certificate is correct here by design. The important property is SIZE: the
leaf must stay small enough that the ServerHello flight fits ONE UDP
datagram (~660 B total). Keep extensions minimal (SAN only).

Requires: python -m pip install cryptography
"""
import datetime
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, 'vendor', 'selfsigned-dtls')


def main():
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError:
        print('need: python -m pip install cryptography')
        return 1
    os.makedirs(OUT, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'StadiaDev-Lab'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'stadia-dtls.local'),
    ])
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName('stadia-dtls.local')]),
                critical=False)
            .sign(key, hashes.SHA256()))
    leaf = cert.public_bytes(serialization.Encoding.PEM)
    priv = key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption())
    with open(os.path.join(OUT, 'leaf.pem'), 'wb') as fh:
        fh.write(leaf)
    with open(os.path.join(OUT, 'privkey.pem'), 'wb') as fh:
        fh.write(priv)
    der_len = len(cert.public_bytes(serialization.Encoding.DER))
    print('wrote vendor/selfsigned-dtls/{leaf,privkey}.pem (leaf DER %d B)' % der_len)
    if der_len > 600:
        print('WARNING: leaf grew past the single-datagram budget!')
        return 2
    print('next: python tools/gen-certs.py')
    return 0


if __name__ == '__main__':
    sys.exit(main())
