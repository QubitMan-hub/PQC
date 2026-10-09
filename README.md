# Acxelin PQC: TLS 1.3 + mTLS

Puts quantum-safe encryption in front of the services you already run, without changing them.

- **Quantum-safe connections:** TLS 1.3 with post-quantum key exchange (X25519MLKEM768) and certificates (ML-DSA).
- **Only trusted clients get in:** with mutual TLS, a client must show a certificate you issued. Revoke it and it is refused from its next connection.
- **Your own certificate authority:** you issue, renew and revoke every certificate yourself.

## See it in one minute

With [Docker Desktop](https://www.docker.com/products/docker-desktop/) running:

```
docker build -t pqc https://github.com/QubitMan-hub/PQC.git#main
docker run --rm pqc
```

You will see a web page fetched over a quantum-safe connection, and an old-style client refused.

## Install

You need Python 3.11+ and OpenSSL 3.5+ ([how to get OpenSSL 3.5](site/manual.html#install) on Windows and macOS; recent Linux already has it).

```
git clone https://github.com/QubitMan-hub/PQC
cd PQC
pip install .
pqc doctor
```

`pqc doctor` should say `TLS edge: ready`.

## Use it

```
pqc ca init --name "My Root"                               # 1. create your certificate authority
pqc ca issue server localhost --out server                 # 2. give your server a certificate
pqc tls edge --target 127.0.0.1:8080 --cert server/chain.pem --key server/key.pem   # 3. protect the app on port 8080
pqc tls connect localhost:8443 --ca pki/ca.crt             # 4. check: shows X25519MLKEM768 and ML-DSA-65
```

Your app now answers on port 8443, quantum-safe. To let in only clients with a certificate, and to cut one off, follow the guide.

## Learn more

- **Step-by-step guide:** [site/manual.html](site/manual.html) (open it in a browser). Every step shows what you should see.
- **How it works:** [site/how-it-works/tls.html](site/how-it-works/tls.html), an interactive diagram.
- **Every option:** `pqc --help`, then `pqc COMMAND --help`.
- **Every edge setting:** [examples/edge.toml](examples/edge.toml).
- **Deploying:** `Dockerfile`, `deploy/helm/pqc` (Kubernetes) and `deploy/systemd`.

## Good to know

- Browsers cannot check ML-DSA certificates yet. For websites, run the edge with `--policy transition` and a classical fallback certificate (`--fallback-cert`, `--fallback-key`).
- Not FIPS 140-3 validated, and not yet independently security reviewed.

Working on the code: [CONTRIBUTING.md](CONTRIBUTING.md). Security: [SECURITY.md](SECURITY.md).
