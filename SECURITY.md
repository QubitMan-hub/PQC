# Security

## Reporting a vulnerability

Email info@acxelinquantum.com with "security" in the subject. Please do not open a public issue.

## Classical cryptography in this repository, and why

| Where | What | Why |
|---|---|---|
| `pki/acme.py` | RSA, ECDSA, Ed25519 | Verifying ACME clients' account keys (RFC 8555). Certificates it issues are ML-DSA only. |
| `pki/acme.py` | TLS 1.3 (classical key exchange) | The ACME server's own HTTPS listener (`--tls-cert`). Python's `ssl` cannot offer ML-KEM; the certificates it issues are ML-DSA. |
| `pki/signers.py` | SHA-1 | The RFC 5280 subject key identifier, a lookup label, not a security function. |
| `tls` policy `transition` | X25519, ECDSA/RSA fallback certificate | Only when a customer enables it for browsers; `strict` (the default) and `cnsa2` refuse classical key exchange. |
| `tests/` | RSA, ECDSA, P-256 | Classical peers the tests expect to be refused. |

TLS 1.3 prefers AES-256-GCM and also allows ChaCha20-Poly1305 and AES-128-GCM, except under `cnsa2`, which allows only AES-256-GCM.

## How the repository is protected

- CI runs with a read-only token (`permissions: contents: read`) and every third-party action is pinned to a commit.
- No secrets in the repository or its history. Test keys are generated at test time.
- Command-line tools never overwrite a private key or a CA by accident; a certificate key is replaced only by `ca renew` or `ca maintain`.

## Assumptions about the host

- On Windows, pqc loads OpenSSL from `PQC_OPENSSL`, then from the folders on `PATH` (newest `libssl-*.dll` first). Anyone who can write to one of those folders can make pqc load their library, so set `PQC_OPENSSL` and keep `PATH` to folders only administrators can write. On Linux and macOS the system loader decides.
- Private keys are files with owner-only permissions, or live in AWS KMS or an HSM. Python cannot wipe keys from memory, so the host running the CA or an edge must be trusted like any server that holds keys.
