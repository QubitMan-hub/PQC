# Changelog

## Unreleased

- `pqc console`: a local web page for the CA and the edges. Issue, download (key only on request), renew and revoke certificates; watch each edge's connections and its share of quantum-safe handshakes; test any host:port to see what it negotiates, or why it was refused and what it offers instead; copy client settings for pqc, curl, Python, nginx and anything else through an originate edge. Bearer token, a lockout after 10 wrong tokens, a strict CSP and an audit log of every action.

- First release of the TLS product: the post-quantum TLS 1.3 edge (terminate and originate), mutual TLS with CRLs, `strict`, `transition` and `cnsa2` policies, and the certificate authority with EST, ACME, renewal and KMS/HSM keys.
