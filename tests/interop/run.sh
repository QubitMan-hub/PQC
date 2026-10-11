#!/bin/bash
# Real clients against the edge: Node and curl on OpenSSL 3.5 (full post-quantum: X25519MLKEM768 and ML-DSA, with mutual TLS),
# Go (post-quantum key exchange, classical fallback certificate), and what each must be refused. Needs pqc, go, node, curl.
set -u
here=$(cd "$(dirname "$0")" && pwd); work=$(mktemp -d); cd "$work"; failed=0
check() { local want=$1 name=$2; shift 2; out=$("$@" 2>&1); got=$([ $? -eq 0 ] && echo pass || echo refused)
  if [ "$got" = "$want" ]; then echo "ok    $name ($got)"; else echo "FAIL  $name: expected $want, got $got: $out"; failed=1; fi; }
same() { [ "$(echo "$out" | cut -d' ' -f2)" = "$sum" ] || { echo "FAIL  $1: body differs"; failed=1; }; }

pqc ca init --dir pki --name "Interop Root" --no-encrypt >/dev/null
pqc ca issue server localhost --dir pki --san 127.0.0.1 --out srv >/dev/null
pqc ca issue client partner --dir pki --out partner >/dev/null
python3 - <<'PY'
import datetime as dt
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
now, k = dt.datetime.now(dt.timezone.utc), ec.generate_private_key(ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key()).serial_number(1)
     .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=7))
     .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False).sign(k, hashes.SHA256()))
open("fb.pem", "wb").write(c.public_bytes(serialization.Encoding.PEM))
open("fb.key", "wb").write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
PY
mkdir www && head -c 20000000 /dev/urandom > www/data.bin && sum=$(sha256sum www/data.bin | cut -d' ' -f1)
python3 -m http.server 18080 --bind 127.0.0.1 --directory www >/dev/null 2>&1 &
pqc tls edge --listen 127.0.0.1:18443 --target 127.0.0.1:18080 --cert srv/chain.pem --key srv/key.pem --ca pki/ca.crt \
  --require-client-cert --crl pki/crl.pem --metrics 127.0.0.1:19100 >strict.log 2>&1 &
pqc tls edge --listen 127.0.0.1:18444 --target 127.0.0.1:18080 --policy transition --cert srv/chain.pem --key srv/key.pem \
  --fallback-cert fb.pem --fallback-key fb.key --metrics 127.0.0.1:19101 >transition.log 2>&1 &
trap 'kill $(jobs -p) 2>/dev/null' EXIT
sleep 3
(cd "$here" && go build -o "$work/goclient" client.go)

check pass    "node, mutual TLS, ML-DSA, 20 MB"      node "$here/client.js" https://localhost:18443/data.bin pki/ca.crt partner/chain.pem partner/key.pem; same node
check refused "node without a client certificate"    node "$here/client.js" https://localhost:18443/data.bin pki/ca.crt
check pass    "curl, mutual TLS, ML-DSA, 20 MB"      curl -sSf --cacert pki/ca.crt --cert partner/chain.pem --key partner/key.pem https://localhost:18443/data.bin -o got.bin
[ "$(sha256sum got.bin | cut -d' ' -f1)" = "$sum" ] || { echo "FAIL  curl: body differs"; failed=1; }
check refused "go on the strict edge (cannot verify ML-DSA)" ./goclient https://localhost:18443/data.bin pki/ca.crt
check pass    "go through the transition edge, 20 MB" ./goclient https://localhost:18444/data.bin fb.pem; same go
pqc ca revoke "$(pqc ca list --dir pki | awk '/ partner/ {print $1}')" --dir pki >/dev/null; sleep 1
check refused "node after its certificate was revoked" node "$here/client.js" https://localhost:18443/ pki/ca.crt partner/chain.pem partner/key.pem

for port in 19100 19101; do
  groups=$(curl -s 127.0.0.1:$port/status | python3 -c "import json,sys; print(json.dumps([v['groups'] for v in json.load(sys.stdin).values()]))")
  echo "      edge :$port key exchanges: $groups"
  echo "$groups" | grep -q X25519MLKEM768 || { echo "FAIL  no X25519MLKEM768 handshake on :$port"; failed=1; }
done
exit $failed
