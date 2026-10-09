"""Run inside the CA pod: a post-quantum HTTPS request through the edge, then the ACME directory. Exits non-zero on failure."""
import json
import sys
import time
import urllib.request

from pqc import tls
from pqc.tls.http import HTTPError, request

release, namespace = sys.argv[1], sys.argv[2]
edge = f"{release}-edge.{namespace}.svc"
ctx = tls.client_context("/data/pki/root.crt")
deadline = time.monotonic() + 60
while True:
    try:
        with tls.connect(edge, 8443, ctx, edge, timeout=15) as conn:
            status, _, body = request(conn, "GET", "/", edge)
            info = conn.info()
        break
    except (OSError, tls.TLSError, HTTPError) as e:
        if time.monotonic() > deadline:
            raise
        print(f"edge not reachable yet ({e}); the Service may still be catching up with the new pods")
        time.sleep(2)
print(f"edge: HTTP {status}, {info['group']}, {info['cipher']}, peer {info['peer']} ({info['peer_key']})")
assert status == 200 and info["group"] == "X25519MLKEM768" and info["peer_key"].startswith("ML-DSA"), info
with urllib.request.urlopen(f"http://{release}-ca.{namespace}.svc:14000/directory", timeout=10) as r:
    d = json.loads(r.read())
print(f"acme: {d['newOrder']} (EAB required: {d['meta']['externalAccountRequired']})")
