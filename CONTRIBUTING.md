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

The public website is published at **https://qubitman-hub.github.io/PQC/** by
`.github/workflows/pages.yml`. The workflow uploads only `site/`, preserving the
existing relative links, fonts, images and diagram. No build or backend is needed.
Pull requests check and package the site without deploying it; changes to `site/`
or the workflow on `main` publish automatically. **Run workflow** on `main` also
publishes manually.

Repository owner setup (after merging the workflow):

1. In **Settings → Pages → Build and deployment**, set **Source** to **GitHub Actions**.
2. Allow GitHub Actions and the pinned `actions/*` actions in repository settings.
   If the `github-pages` environment has deployment rules, permit `main` and approve
   any required deployment review.
3. In **Actions → Deploy website → Run workflow**, select `main`. Check that the
   deployment succeeds and that the website, guide and diagram open.
4. On the repository's **About** panel, click the gear and set **Website** to
   `https://qubitman-hub.github.io/PQC/` (or select **Use your GitHub Pages website**).

No personal access token, hosting credentials or custom secrets are required:
deployment uses GitHub's automatic `GITHUB_TOKEN` and OIDC token. Before the first
successful deployment, the website links may return 404.

GitHub Pages hosts static documentation only. `pqc console` needs a running Python
backend, OpenSSL 3.5+, CA files and its bearer token. Remote console access needs
a separately managed server and a TLS edge with a browser-trusted certificate,
as described in the guide. Do not upload CA private keys, console tokens or the
console backend to the Pages artifact. The Docker, Helm and systemd files deploy
the PQC services separately; GitHub Pages does not run them.

`pqc` is a working name: `NAME` in `pqc/__init__.py`.
