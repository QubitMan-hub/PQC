# CLAUDE.md

Acxelin PQC, product 1: post-quantum TLS 1.3 + mTLS and its certificate authority. Pure Python; the one runtime dependency is `cryptography` (49+). TLS uses the system's OpenSSL 3.5+ through ctypes (`pqc/tls/openssl.py`). Never shell out to the openssl command line in product code.

## Commands

```
pip install -e ".[test,integration]"
python -m pytest -q          # must stay green
ruff check .
pqc doctor && pqc try
```

## Layout

`pqc/pki` (CA, EST, ACME, signers), `pqc/tls` (OpenSSL binding, server, edge, bundles), `pqc/cli` (commands), `pqc/checks.py` (doctor), `pqc/storage.py` (atomic, locked files).

## Rules

- Every security behaviour has a test.
- Minimal code, few comments; prefer a small, well-tested change over a framework.
- Must run on Windows, macOS and Linux (pathlib, utf-8, no shell-specific behaviour).
- Never overclaim: say what is tested and what is not.
- Commit as `git -c user.name="Qubit Man" -c user.email="qubitmen@gmail.com"`.
