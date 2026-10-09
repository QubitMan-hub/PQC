# Debian 13 ships OpenSSL 3.5, so the system libssl negotiates ML-KEM and ML-DSA.
# pinned by digest so a rebuild uses the same base; Dependabot proposes updates (tests/test_release.py keeps CI on it too)
ARG BASE=python:3.13-slim-trixie@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b
FROM ${BASE}
# Apply distribution security updates even when the pinned base predates their publication.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --home /srv pqc
WORKDIR /app
COPY pyproject.toml README.md ./
COPY pqc ./pqc
# pip is not needed at run time and carries its own vendored packages, so it leaves the image.
RUN pip install --no-cache-dir . && pip uninstall -y pip && pqc doctor
USER pqc
WORKDIR /srv
EXPOSE 8443 9100
ENTRYPOINT ["pqc"]
# with no arguments, the one-minute tour; deployments name their command (tls edge --config ..., as the Helm chart does)
CMD ["try"]
