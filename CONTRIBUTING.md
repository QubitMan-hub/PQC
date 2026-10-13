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
pip install -c constraints.txt setuptools
pip install --no-build-isolation -c constraints.txt -e ".[test,integration]" ruff
pqc doctor
```

`integration` installs certbot and acme for the ACME tests. `constraints.txt` pins the
dependencies for development, CI and the container, including optional KMS dependencies
when requested. The library's dependency ranges stay in `pyproject.toml`. Install the
pinned setuptools first; `--no-build-isolation` then uses that version for the build.

To deliberately refresh the pins with uv 0.12.23, then run the tests:

```
uv pip compile --universal --all-extras --python-version 3.11 --no-python-downloads pyproject.toml requirements-tools.in --upgrade --output-file constraints.txt
```

Review dependency updates before committing the regenerated file. CI's separate audit
job also checks the latest versions allowed by the library's ranges.

## Tests

```
python -m pytest -q
```

The TLS tests run when OpenSSL 3.5+ is available and are skipped otherwise; `pqc doctor` says which you have. The code needs `cryptography` 49 or newer (for ML-KEM and ML-DSA). CI also lints with `ruff check .` and builds the Docker image.

## Website

`site/index.html` is the product page; `site/how-it-works/tls.html` is the interactive diagram, built with the archify skill in `.claude/skills/archify` from `docs/how-it-works/tls.workflow.json`.

`pqc` is a working name: `NAME` in `pqc/__init__.py`.
