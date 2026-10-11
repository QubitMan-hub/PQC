# Changelog

## Unreleased

- Revoking a client now also closes its open connections, within about a second of the CRL changing; before, only new connections were refused, so a stolen device holding a long-lived connection (a database pool, MQTT, a tunnel) stayed in until it reconnected.
- The edge sends data without Nagle delays (TCP_NODELAY) and keeps the GIL on its short OpenSSL data-path calls: 40-55% more requests per second per process, and lower latency for request/response protocols.
- `tests/interop`: Node and curl on OpenSSL 3.5 (ML-DSA, mutual TLS), Go (post-quantum key exchange with a classical fallback certificate) and revocation against a running edge, and pqc's client against public post-quantum servers; run by the new `interop` workflow.

- `pqc console`: a local web page for the CA and the edges. Issue, download (key only on request), renew and revoke certificates; watch each edge's connections and its share of quantum-safe handshakes; test any host:port to see what it negotiates, or why it was refused and what it offers instead; copy client settings for pqc, curl, Python, nginx and anything else through an originate edge. Bearer token, a lockout after 10 wrong tokens, a strict CSP and an audit log of every action.

- First release of the TLS product: the post-quantum TLS 1.3 edge (terminate and originate), mutual TLS with CRLs, `strict`, `transition` and `cnsa2` policies, and the certificate authority with EST, ACME, renewal and KMS/HSM keys.
