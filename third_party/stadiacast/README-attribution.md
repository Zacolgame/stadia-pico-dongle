Third-party attribution -- stadiacast
=====================================

This firmware reuses the built-in TLS credential that the stadiacast project
(https://github.com/jkfran/stadiacast) ships so its receiver needs no
user-supplied certificate. Nothing else of stadiacast is copied into the
firmware; the protocol implementation here is independent.

Upstream project: Stadiacast
Copyright (c) 2026 Francisco Jimenez Cabrera and the Stadiacast contributors
License: MIT (see LICENSE.txt), with the exception described in NOTICE.txt.

What was reused and where it lives
----------------------------------
  credential  vendor/upstream-credential/{fullchain,privkey,leaf}.pem
              -> compiled into src/certs.c by tools/gen-certs.py
  provenance  vendor/upstream-credential/PROVENANCE.txt
  docs        NOTICE.txt / LICENSE.txt in this directory

Why a revoked certificate is safe here
--------------------------------------
The credential is a Google Trust Services chain issued for stadiacast.lol; the
upstream authors revoked it at their own request BEFORE publishing the private
key. Ordinary TLS clients (which check revocation) reject it, so it is useless
as an impersonation tool; the Stadia controller, which validates only that the
chain terminates in its built-in GTS roots (no hostname, date or revocation
check), accepts it. This is exactly how the upstream project distributes it,
and the same caveat applies: treat this credential as a test/interop artifact,
not as a secret.

Trademark / affiliation
-----------------------
Stadiacast and this firmware are independent interoperability projects. They
are not affiliated with, endorsed by or supported by Google. Stadia is a
trademark of Google LLC.
