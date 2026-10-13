# Compatibility and security review

PQC's edge requires Python 3.11+, cryptography 49+, and system OpenSSL 3.5+
with the configured groups and signature algorithms available. `pqc doctor`
checks the loaded library and whether it can construct a strict TLS context.
The cryptography wheel's private OpenSSL is separate from the edge's system
library. A successful CA operation alone does not establish TLS readiness.

## Client compatibility

| Client or use | Configuration | What is protected |
| --- | --- | --- |
| PQC-aware clients with ML-DSA support | `strict`, trusted PQC CA | Post-quantum hybrid key exchange and ML-DSA authentication; classical key exchange is refused |
| Browser/public-CA clients | `transition`, a classical fallback certificate and key trusted by the client | Post-quantum exchange when offered; classical authentication is preferred for clients offering both signature families; classical exchange remains allowed |
| Legacy application that needs strict protection | Local `originate` edge connected to a remote strict edge | Strict protection between edges; local plain TCP must stay on a trusted interface/network |
| Clients requesting the `cnsa2` policy | ML-DSA-87 certificates and compatible ML-KEM-1024 groups | The configured algorithms are enforced; this is not a compliance certification |

For a browser-facing edge, use the documented `--fallback-cert` and
`--fallback-key` with `--policy transition`. Issue the fallback certificate
through a CA the browser trusts and include its proper chain. Do not disable
certificate verification to work around compatibility. ML-DSA certificates
and the classical fallback key are separate credentials.

Clients that offer both signature families receive the classical fallback even
if they list ML-DSA first. A transition client must trust that fallback's CA;
use `strict` with the PQC CA when ML-DSA authentication is required. Advertising
ML-DSA signature support does not imply that a browser trusts the private PQC CA.

The `/status` and `/metrics` endpoints count negotiated groups. An
`X25519MLKEM768` connection using a classical certificate has hybrid key
exchange, but does not have post-quantum certificate authentication. Place
metrics behind network access controls; the endpoint has no login. TLS
inspection proxies terminate the protection at the proxy.

## Reproducible checks

Follow `CONTRIBUTING.md` for the pinned development installation, then run:

```
pqc doctor
pqc try
python -m pytest -q -ra
ruff check .
pip-audit --strict --no-deps -r constraints.txt
```

Install the audit command with `pip install -c constraints.txt pip-audit`.
`tests/interop/run.sh` exercises real Node/curl clients with OpenSSL 3.5+
and Go 1.24+ against strict and transition edges, including mTLS, a 20 MB
payload and revocation. Run it in the documented Debian 13 toolchain from
the interoperability workflow. The test suite also verifies the policy
matrix, hostname checks, certificate roles, session resumption, and refusal
of invalid authorizations and replayed CRLs.

`tests/test_openssl_lifecycle.py` covers closed-object calls in isolated
subprocesses, shutdown cleanup, allocation failure boundaries, exporter
labels, Windows library precedence and CA key rollover. CI runs the tests
on Linux, Windows and macOS, and checks frozen dependency pins and fresh
library-range resolutions weekly. Scheduled checks provide evidence at
their run time; they do not guarantee future compatibility or security.

## Scope for an independent reviewer

The code uses established cryptography and OpenSSL implementations, but
the integration and surrounding authorization logic need independent review.
Review these boundaries against the exact commit under consideration:

- `pqc/tls/openssl.py`: ABI prototypes, buffer lengths, native object
  ownership, error queues, nonblocking retry semantics, shutdown and library
  loading. Connections have one owning worker; concurrent free/read/write
  is unsupported. Check native behavior with sanitizers or a suitable memory
  checker in addition to the Python regressions.
- `pqc/tls/server.py` and `edge.py`: admission limits, certificate reload,
  session trust boundaries, revocation and worker lifecycle. Revocation
  interrupts sockets; the owning worker frees its SSL object.
- `pqc/pki`: signer output verification, DER reconstruction for external
  signers, issuance permissions, crash consistency and monotonically
  numbered CRLs. Backups must retain `crl-number`; restoring stale CA state
  must not reuse published numbers.
- EST and ACME: token/account binding, CSR identity restrictions,
  authorization expiry/deactivation, validation destination controls,
  request limits and replay resistance.
- Console and deployment: authenticated administration, private-key
  downloads, local transport, metrics exposure and host trust assumptions.

Report findings privately through `SECURITY.md`, with a reproduction,
affected configurations and commit. Record the reviewer's identity, scope,
date, exclusions and unresolved findings before describing a review as
independent. Current tests and internal code reviews do not provide that
certification; the project remains not independently audited or FIPS validated.
