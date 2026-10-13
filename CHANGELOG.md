# Changelog

## Unreleased

- CRLs carry persistent, increasing numbers; downloads reject rollback, numbering downgrades and same-second loss of legacy revocations. Include `crl-number` in CA backups.
- Native ACME HTTPS handshakes run in bounded workers with deadlines; issuance rechecks authorization expiry and deactivation, and asynchronous validation cannot reactivate a deactivated authorization.
- The OpenSSL bridge rejects calls after connection closure, frees SSL objects after shutdown errors, handles BIO/digest allocation failures, preserves configured Windows library precedence, and uses the encoded exporter-label length.
- Certificate chains retain self-issued CA key-rollover certificates unless their self-signature verifies.
- Transition edges with a classical fallback prefer it for dual-capability clients, including browsers that advertise ML-DSA but trust only the fallback CA. Strict PQC clients still receive ML-DSA certificates; hybrid key exchange remains preferred.
- Development, CI and container dependencies use reviewed version pins. Weekly CI audits the frozen pins as well as allowed library ranges; compatibility and independent-review requirements are documented.

- The edge and clients no longer send the self-signed root in their certificate chain (the peer already has it): the edge's first handshake reply shrinks from 19 KB to 12 KB, inside TCP's initial window, which saves a round trip on every new connection over a real network. OpenSSL's automatic chain building, which put the root back when a client-CA file was loaded, is off; chain files on disk are unchanged.

- On Windows, connecting to `localhost` took two seconds when the server listened on 127.0.0.1 (Windows tries ::1 first and waits after the refusal). pqc's client now tries 127.0.0.1 first for `localhost`, and the edge, `ca serve` and ACME listen on every interface for both IPv4 and IPv6 by default (`[::]`), falling back to IPv4 where there is no IPv6.

- The edge, the console, ACME and the metrics page can listen on IPv6 (`--listen "[::]:443"` also takes IPv4 clients where the system allows); they failed with "address family not supported" before.

- Mutual-TLS edges failed every resumed session ("session id context uninitialized"), and TLS clients resume automatically when they reconnect. Sessions now resume, a session from an edge that trusts other clients or another policy never does, and a revoked client is still refused when it resumes.

- Facing the internet: one address may open at most 50 new connections a second (`max_rate_per_client`; bursts of twice that; this machine's own connections are exempt) and, once the edge is half full, hold at most an eighth of its connections (`max_per_client`). Before, one machine could take every connection slot by completing handshakes and then idling, or slow everyone else's new connections from 4 ms to 180 ms by reconnecting as fast as it could. Refusals and failed handshakes are logged once per address every 10 seconds, so a flood cannot fill the disk. The accept backlog is 1,024 (was 128).
- The edge warns when its metrics port listens beyond this machine: `/status` lists every route and upstream without a login.

- Revocation lists are verified once per change instead of on every connection: with 20,000 revoked certificates a mutual-TLS handshake no longer spends 26 ms re-checking the list (35 handshakes a second before, 150 after, the same as with an empty list). A list with a damaged version field is now refused with a clear message instead of an unhandled error.
- The edge raises its open-file limit at start (systemd's default of 1,024 allowed only about 340 connections) and warns when `max_connections` still cannot fit; each connection now holds two file descriptors instead of three. The systemd unit sets `LimitNOFILE=65536`. `--max-connections` sets the limit without a config file. Measured: 9,000 open connections in one process, about 105 KB each.
- The refusal hint for clients without a matching key exchange names what the policy needs (cnsa2: ML-KEM-1024).
- `tests/interop/bench.py` measures the edge on any machine; CI now runs the TLS tests on Windows with OpenSSL 3.5 instead of skipping them.

- Revoking a client now also closes its open connections, within about a second of the CRL changing; before, only new connections were refused, so a stolen device holding a long-lived connection (a database pool, MQTT, a tunnel) stayed in until it reconnected.
- The edge sends data without Nagle delays (TCP_NODELAY) and keeps the GIL on its short OpenSSL data-path calls: 40-55% more requests per second per process, and lower latency for request/response protocols.
- `tests/interop`: Node and curl on OpenSSL 3.5 (ML-DSA, mutual TLS), Go (post-quantum key exchange with a classical fallback certificate) and revocation against a running edge, and pqc's client against public post-quantum servers; run by the new `interop` workflow.

- `pqc console`: a local web page for the CA and the edges. Issue, download (key only on request), renew and revoke certificates; watch each edge's connections and its share of quantum-safe handshakes; test any host:port to see what it negotiates, or why it was refused and what it offers instead; copy client settings for pqc, curl, Python, nginx and anything else through an originate edge. Bearer token, a lockout after 10 wrong tokens, a strict CSP and an audit log of every action.

- First release of the TLS product: the post-quantum TLS 1.3 edge (terminate and originate), mutual TLS with CRLs, `strict`, `transition` and `cnsa2` policies, and the certificate authority with EST, ACME, renewal and KMS/HSM keys.
