"""Bundles: a common service behind the post-quantum edge, generated as a Docker Compose project in one command."""
import os
import shutil
from pathlib import Path

from .. import __version__
from ..pki import CA, CAError, general_names, write

EDGE_UID = 10001
SERVICES = {
    "nginx": {"image": "nginx:stable", "port": 80, "public": 443, "volume": None,
              "use": "https://{host}/ with a client that verifies ML-DSA (OpenSSL 3.5+, `pqc tls connect`). Browsers cannot verify "
                     "ML-DSA yet: for them use policy = \"transition\" with fallback_cert and fallback_key (an ECDSA or RSA certificate)"},
    "postgres": {"image": "postgres:17", "port": 5432, "public": 5433, "volume": "/var/lib/postgresql/data",
                 "env": {"POSTGRES_PASSWORD": "${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD}"},
                 "use": "psql \"host={host} port=5433 sslmode=verify-full sslrootcert=pki/ca.crt sslnegotiation=direct\" "
                        "(libpq 17+; the client's OpenSSL must be 3.5+ to negotiate ML-KEM, or connect through `pqc tls edge --mode originate`)"},
    "pgvector": {"image": "pgvector/pgvector:pg17", "port": 5432, "public": 5433, "volume": "/var/lib/postgresql/data",
                 "env": {"POSTGRES_PASSWORD": "${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD}"},
                 "use": "as postgres; then CREATE EXTENSION vector;"},
    "mqtt": {"image": "eclipse-mosquitto:2", "port": 1883, "public": 8883, "volume": "/mosquitto/data",
             "config": "listener 1883\nallow_anonymous false\npassword_file /mosquitto/config/passwd\npersistence true\npersistence_location /mosquitto/data/\n",
             "use": "mosquitto_pub -h {host} -p 8883 --cafile pki/ca.crt -t test -m hi -u USER -P PASS (clients need OpenSSL 3.5+ for ML-KEM)"},
}


def create(service, out, host, ca_dir=None, require_client_cert=False, policy="strict", passphrase=None):
    """Write docker-compose.yml, edge.toml and a certificate for `host` into `out`. Reuses the CA in `ca_dir` when given."""
    if service not in SERVICES:
        raise CAError(f"unknown service {service}; choose from {', '.join(SERVICES)}")
    s, out = SERVICES[service], Path(out)
    if (out / "docker-compose.yml").exists():
        raise CAError(f"{out} already has a bundle")
    taken = [n for n in ("edge.toml", "README.txt", "ca.key.KEEP-OFFLINE", "mosquitto.conf", "passwd", "edge", *([] if ca_dir else ["pki"]))
             if (out / n).exists()]
    if taken:
        raise CAError(f"{out} already has {', '.join(taken)}; give the bundle a new folder (--out) so nothing there is replaced")
    general_names([host])
    ca = CA(ca_dir, passphrase) if ca_dir else None
    fresh = not out.exists()
    try:
        return _create(service, s, out, host, ca, ca_dir, require_client_cert, policy)
    except BaseException:
        if fresh:
            shutil.rmtree(out, ignore_errors=True)
        raise


def _create(service, s, out, host, ca, ca_dir, require_client_cert, policy):
    pki = Path(ca_dir) if ca_dir else out / "pki"
    ca = ca or CA.init(pki, f"{host} bundle root")
    ca.issue(host, "server", out=out / "edge")
    ca.crl(days=30)
    if hasattr(os, "chown") and os.geteuid() == 0:
        os.chown(out / "edge" / "key.pem", EDGE_UID, EDGE_UID)
    if not ca_dir:
        (pki / "ca.key").rename(out / "ca.key.KEEP-OFFLINE")
    mtls = 'require_client_cert = true\ncrl = "/pki/crl.pem"\n' if require_client_cert else ""
    write(out / "edge.toml", (f'[metrics]\nlisten = "0.0.0.0:9100"\n\n[[edge]]\nname = "{service}"\nmode = "terminate"\n'
                              f'listen = "0.0.0.0:{s["public"]}"\ntarget = "{service}:{s["port"]}"\npolicy = "{policy}"\n'
                              f'cert = "/edge/chain.pem"\nkey = "/edge/key.pem"\nca = "/pki/ca.crt"\n{mtls}').encode())
    lines = ["# " + service + " behind the post-quantum edge. Only the edge is published; the service is not reachable from outside.",
             "services:",
             f"  {service}:", f"    image: {s['image']}", "    restart: unless-stopped"]
    if s.get("env"):
        lines += ["    environment:"] + [f'      {k}: "{v}"' for k, v in s["env"].items()]
    volumes = [f"      - data:{s['volume']}"] if s["volume"] else []
    if "config" in s:
        write(out / "mosquitto.conf", s["config"].encode())
        write(out / "passwd", b"")
        volumes += ["      - ./mosquitto.conf:/mosquitto/config/mosquitto.conf:ro", "      - ./passwd:/mosquitto/config/passwd:ro"]
    if volumes:
        lines += ["    volumes:"] + volumes
    lines += ["  edge:", f"    image: ghcr.io/qubitman-hub/pqc:{__version__}", '    command: ["tls", "edge", "--config", "/etc/pqc/edge.toml"]',
              "    restart: unless-stopped", f"    depends_on: [{service}]", f'    ports: ["{s["public"]}:{s["public"]}"]', "    volumes:",
              "      - ./edge.toml:/etc/pqc/edge.toml:ro", "      - ./edge:/edge:ro",
              f"      - {Path(ca_dir).resolve().as_posix() if ca_dir else './pki'}:/pki:ro"]
    if s["volume"]:
        lines += ["volumes:", "  data:"]
    write(out / "docker-compose.yml", ("\n".join(lines) + "\n").encode())
    notes = [] if hasattr(os, "chown") and os.geteuid() == 0 else [
        "", f"The edge runs as uid {EDGE_UID}: on Linux run `sudo chown {EDGE_UID} edge/key.pem` before starting."]
    if require_client_cert:
        notes += ["", "Mutual TLS checks pki/crl.pem, and an expired CRL locks everyone out (fail closed).",
                  "Keep it fresh: run `pqc ca maintain --dir <ca dir>` daily (cron or a scheduled task)."]
    notes += ["", "Create MQTT users first: docker run --rm -v $PWD:/w eclipse-mosquitto:2 mosquitto_passwd -b /w/passwd USER PASS"] if service == "mqtt" else []
    notes += ["", "The CA private key is in ca.key.KEEP-OFFLINE. Move it off this machine; you need it to renew or revoke."] if not ca_dir else []
    write(out / "README.txt", "\n".join([
        f"{service} behind post-quantum TLS ({policy} policy{', mutual TLS' if require_client_cert else ''})", "",
        "1. docker compose up -d", f"2. Connect: {s['use'].format(host=host)}", f"3. Check:   pqc tls connect {host}:{s['public']} --ca pki/ca.crt", "",
        "Certificates: edge/ (the edge's), pki/ca.crt (give this to clients).",
        "Renew: pqc ca renew <serial> --dir <ca dir> --out edge   (the edge picks it up without a restart)", *notes, ""]).encode())
    return out
