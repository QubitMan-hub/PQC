#!/bin/bash
# pqc's client against public servers that offer post-quantum key exchange today, verified with the system's root CAs.
# The web still uses RSA and ECDSA certificates, so the transition policy is the one that connects; strict must refuse clearly.
set -u
roots=${ROOTS:-/etc/ssl/certs/ca-certificates.crt}; failed=0
for host in cloudflare.com www.google.com pq.cloudflareresearch.com; do
  out=$(pqc tls connect "$host:443" --ca "$roots" --policy transition --json --timeout 15 2>&1)
  group=$(echo "$out" | python3 -c "import json,sys; print(json.load(sys.stdin)['group'])" 2>/dev/null)
  if [ "$group" = X25519MLKEM768 ]; then echo "ok    $host: X25519MLKEM768, certificate verified"; else echo "FAIL  $host: $out"; failed=1; fi
done
out=$(pqc tls connect cloudflare.com:443 --ca "$roots" --policy strict --timeout 15 2>&1) && { echo "FAIL  strict accepted a classical certificate"; failed=1; } \
  || echo "ok    strict policy refuses the web's classical certificates: ${out:0:120}"
exit $failed
