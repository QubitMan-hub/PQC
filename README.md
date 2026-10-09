# Acxelin PQC: TLS 1.3 + mTLS

Post-quantum TLS in front of any TCP service, mutual TLS between services, and your own certificate authority, in Python.

- **TLS edge:** TLS 1.3 with X25519MLKEM768 key exchange and ML-DSA certificates, in front of a service that does not change.
- **Mutual TLS:** only clients with a certificate from your CA get in; a revoked one is refused at its next connection.
- **Certificate authority:** ML-DSA or SLH-DSA roots and issuing CAs, revocation lists, renewal, EST and ACME enrollment, AWS KMS or HSM keys.

The diagram in [site/how-it-works/tls.html](site/how-it-works/tls.html) shows the whole flow; working on the code itself is in [CONTRIBUTING.md](CONTRIBUTING.md).

## Try it in one minute

With [Docker Desktop](https://www.docker.com/products/docker-desktop/) running:

```
docker build -t pqc https://github.com/QubitMan-hub/PQC.git#main
docker run --rm pqc
```

It creates a certificate authority, puts the post-quantum edge in front of an ordinary web server, fetches a page through it with X25519MLKEM768 and an ML-DSA certificate, and shows a classical-only client being refused. Nothing is left behind.

## Install

Python 3.11+, on Windows, macOS or Linux, from a clone of this repository:

```
pip install .                  # AWS KMS keys: pip install ".[kms]"
pqc                            # every command, and where to start
pqc doctor                     # what works on this machine
pqc try                        # the one-minute tour, without Docker
pqc doctor --ca pki --config edge.toml   # preflight: CA key protection, CRL freshness, expiring certificates, risky settings
```

Every command explains itself with `--help`, and most show an example (`pqc ca issue --help`).

The CA works everywhere. The TLS edge needs **OpenSSL 3.5 or newer**:

| Platform | How to get it |
|---|---|
| Debian 13, Ubuntu 25.04+ | Already the system OpenSSL |
| Docker | `docker build -t pqc .` then `docker run --rm pqc` (Debian 13 base) |
| Windows | Install OpenSSL 3.5+ and put its `bin` on `PATH`, or set `PQC_OPENSSL` to that folder |
| macOS | `brew install openssl@3`, then set `PQC_OPENSSL` to `$(brew --prefix openssl@3)/lib` if it is not found |
| Older Linux | Build OpenSSL 3.5 and run with `LD_LIBRARY_PATH=/path/to/openssl/lib` |

Config files can be written with any editor, Notepad and PowerShell included: UTF-8 with or without a byte-order mark, or UTF-16.

## TLS 1.3 + mTLS

```
pqc ca init --name "Acme PQC Root"                        # ML-DSA-87 root, key encrypted; scripts set PQC_CA_PASSPHRASE
pqc ca issue server app.acme.example --out certs/edge
pqc tls edge --target 127.0.0.1:8080 --cert certs/edge/chain.pem --key certs/edge/key.pem --metrics 127.0.0.1:9100
```

Clients now reach the app on port 8443 over TLS 1.3 with X25519MLKEM768 and an ML-DSA certificate. `examples/edge.toml` documents routes, mutual TLS, CRLs and tunnels (`pqc tls edge --config examples/edge.toml`).

- **Edge modes:** `terminate` puts PQC TLS in front of a service. `originate` lets a plain local client reach a remote edge, so two edges make a post-quantum tunnel for any TCP protocol.
- **Mutual TLS:** `require_client_cert` plus a CRL. Revoked clients are refused at the next handshake. A forged or expired CRL refuses everyone (fail closed). When the CA runs on another machine, `pqc ca publish` serves its CRL and `crl_url` makes edges fetch it every minute (`crl_every`), so a revocation reaches them without copying files.
- **Policies:** `strict` (post-quantum only, the default), `transition` (also serves classical clients) and `cnsa2` (ML-KEM-1024, ML-DSA-87, AES-256 only).
- **Browsers:** they negotiate X25519MLKEM768 but cannot verify ML-DSA yet. Under `transition`, `fallback_cert`/`fallback_key` (or `--fallback-cert`/`--fallback-key`) give them an ECDSA or RSA certificate, while post-quantum clients get ML-DSA on the same port.
- **Operations:** certificates and `edge.toml` reload without a restart, `/metrics` for Prometheus, JSON logs, graceful shutdown, connection limits and deadlines on every socket.
- **Bundles:** `pqc tls bundle nginx|postgres|pgvector|mqtt --host NAME` writes a Compose project with the service behind the edge.

Which clients connect (tested against the edge):

| Client | `strict` | `transition` with an ECDSA fallback |
|---|---|---|
| OpenSSL 3.5 command line, Node 22 | X25519MLKEM768, ML-DSA verified | X25519MLKEM768, ML-DSA |
| Chrome/Chromium, Go 1.24 | refused (cannot verify ML-DSA) | X25519MLKEM768, ECDSA certificate |
| Java 21, Python and curl on OpenSSL 3.0 | refused | X25519 (classical), ECDSA certificate |

Check a connection:

```
pqc tls connect app.acme.example:8443 --ca pki/ca.crt --send hello
       version  TLSv1.3
        cipher  TLS_AES_256_GCM_SHA384
         group  X25519MLKEM768
      peer_key  ML-DSA-65
```

### What listens where

| Command | Listens on by default | Serves |
|---|---|---|
| `tls edge`, `tls serve` | every interface, port 8443 | post-quantum TLS; mutual TLS where configured |
| `ca serve` (EST) | every interface, port 9443 | enrollment over post-quantum TLS: a one-time token, or the current certificate to renew |
| `ca publish` | every interface, port 8080 | the CRL and the CA certificate over plain HTTP: both are public by design |
| `ca acme` | this machine only, 127.0.0.1:14000 | ACME; put it behind the edge or set `--listen` |

To narrow what can connect, give `--listen` one address (`--listen 10.0.0.5:8443`, or `127.0.0.1:8443` for this machine only) and firewall the ports.

### Certificate authority

- **Hierarchy:** ML-DSA or SLH-DSA (FIPS 205) roots, and issuing CAs under them (`ca init --parent`). SLH-DSA needs OpenSSL 3.5+.
- **Keys:** encrypted PKCS#8 files, AWS KMS ML-DSA keys (`--kms`), or any HSM with a command-line signer (`--signer-command`). KMS is tested against a stand-in for its API, not AWS itself.
- **Lifecycle:** issue, sign CSRs, revoke, CRLs. `pqc ca maintain` (daily) renews what expires within 30 days in place and re-signs the CRL. Listing reads the CA without its passphrase; only signing needs it.
- **External signers are checked:** a signature from KMS or an HSM command is verified against the CA's public key before anything is issued.
- **EST (RFC 7030):** `ca serve` on post-quantum TLS; `ca token` makes one-time tokens bound to a name. Machines run `ca enroll` with the token in `PQC_ENROLL_TOKEN` (the key never leaves them) and renew over mutual TLS.
- **ACME (RFC 8555):** `ca acme` with http-01, external account binding and an allow-list. The CSR must carry an ML-DSA key (`ca csr`, then `certbot --csr`).

## Deploy

- **Docker:** `Dockerfile` builds the edge and the CA tools on Debian 13 (OpenSSL 3.5).
- **Kubernetes:** `deploy/helm/pqc` runs the CA (EST, ACME, daily maintenance) and edge gateways; `deploy/k8s/sidecar.yaml` shows the edge as a sidecar. Both expect the image `ghcr.io/qubitman-hub/pqc`, published from the first release; until then build it and set `image.repository`.
- **systemd:** `deploy/systemd` runs the edge and the daily CA maintenance.

## Limits

- The edge uses one thread per connection (512 by default) and forwards TCP bytes; it does not parse HTTP. One process handles about 500 new TLS connections a second; on Linux, `--workers N` runs N processes on the same port.
- Revocation uses CRL files; there is no OCSP responder. The CA keeps its index in one JSON file, fine for thousands of devices.
- Algorithms come from OpenSSL and pyca/cryptography. Nothing here is FIPS 140-3 validated, and no independent security review has been done yet.
