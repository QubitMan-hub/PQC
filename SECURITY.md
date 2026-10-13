# Security

## Reporting a vulnerability

Email info@acxelinquantum.com with "security" in the subject. Please do not open a public issue.

## Classical cryptography in this repository, and why

| Where | What | Why |
|---|---|---|
| `pki/acme.py` | RSA, ECDSA, Ed25519 | Verifying ACME clients' account keys (RFC 8555). Certificates it issues are ML-DSA only. |
| `pki/acme.py` | Python's TLS 1.3 defaults | The ACME server's HTTPS listener (`--tls-cert`) does not enforce strict PQC policy. Key exchange depends on its OpenSSL defaults; use a classical listener certificate for client compatibility. Issued certificates are ML-DSA. |
| `pki/signers.py` | SHA-1 | The RFC 5280 subject key identifier, a lookup label, not a security function. |
| `tls` policy `transition` | X25519, ECDSA/RSA fallback certificate | Only when a customer enables it for browsers; `strict` (the default) and `cnsa2` refuse classical key exchange. |
| `tests/` | RSA, ECDSA, P-256 | Classical peers the tests expect to be refused. |

TLS 1.3 prefers AES-256-GCM and also allows ChaCha20-Poly1305 and AES-128-GCM, except under `cnsa2`, which allows only AES-256-GCM.

## How the repository is protected

- CI runs with a read-only token (`permissions: contents: read`) and every third-party action is pinned to a commit.
- No secrets in the repository or its history. Test keys are generated at test time.
- Command-line tools never overwrite a private key or a CA by accident; a certificate key is replaced only by `ca renew` or `ca maintain`.

CRLs carry increasing numbers, persisted in the CA's `crl-number` file before signing.
Back up this file with the CA; restoring an older CA snapshot must not reuse numbers
already published. Edges reject decreasing numbers and a return to unnumbered CRLs.
Older, unnumbered CRLs remain supported: equal-timestamp updates cannot remove
revocations, and the next CA update introduces numbering automatically.

The native ACME HTTP(S) listener accepts at most 128 concurrent connections and gives
TLS handshakes 10 seconds. Its worker threads perform handshakes, so a stalled peer
does not block the accept loop. Internet deployments should still use the documented
network protections against distributed floods.

## Assumptions about the host

- On Windows, pqc loads OpenSSL from `PQC_OPENSSL`, then from the folders on `PATH` (newest `libssl-*.dll` first). Anyone who can write to one of those folders can make pqc load their library, so set `PQC_OPENSSL` and keep `PATH` to folders only administrators can write. On Linux and macOS the system loader decides.
- Private keys are files with owner-only permissions, or live in AWS KMS or an HSM. Python cannot wipe keys from memory, so the host running the CA or an edge must be trusted like any server that holds keys.

Each TLS `Connection` belongs to one worker. Do not read, write or free its OpenSSL
object concurrently. To interrupt a worker, shut down its underlying socket and let
the owning worker close the connection, as the revocation sweeper does. Closing a
`Context` does not invalidate existing connections; OpenSSL retains their context
reference. New connections through a closed context are refused.

The [security review guide](docs/security-review.md) records review scope, compatibility
limits, and reproducible checks. CI runs weekly and audits both frozen dependency
versions and the library's allowed ranges. These checks do not constitute an
independent security audit or FIPS validation.
