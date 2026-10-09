# Contributing

How to work on the code itself. Using the product is in the [README](README.md).

## Repository map

| Folder | Purpose |
|---|---|
| `pqc/pki/` | The certificate authority, EST, ACME and KMS/HSM signers |
| `pqc/tls/` | The OpenSSL 3.5 binding, the TLS server, the edge and bundles |
| `pqc/cli/` | The `pqc` command |
| `tests/` | Regression tests |
| `site/` | The product page and its diagram |
| `examples/`, `deploy/` | Edge configuration, Helm chart, Kubernetes sidecar, systemd units |
| `docs/how-it-works/` | The diagram's source (archify workflow JSON) |

## Development install

Python 3.11+, from a clone:

```
pip install -e ".[test,integration]"   # [integration]: certbot and acme, for the ACME tests
pqc doctor
```

## Tests

```
python -m pytest -q
```

The TLS tests run when OpenSSL 3.5+ is available and are skipped otherwise; `pqc doctor` says which you have. The code needs `cryptography` 49 or newer (for ML-KEM and ML-DSA). CI also lints with `ruff check .` and builds the Docker image.

## Website

`site/index.html` is the product page; `site/how-it-works/tls.html` is the interactive diagram, built with the archify skill in `.claude/skills/archify` from `docs/how-it-works/tls.workflow.json`.

`pqc` is a working name: `NAME` in `pqc/__init__.py`.
