// A Node HTTPS client; with Node built on OpenSSL 3.5+ it verifies ML-DSA certificates and offers X25519MLKEM768.
// usage: node client.js URL CA [CERT KEY] -> prints the body's size and SHA-256, exits 1 on failure
const https = require("https"), fs = require("fs"), crypto = require("crypto");
const [url, ca, cert, key] = process.argv.slice(2);
https.get(url, { ca: fs.readFileSync(ca), ...(cert && { cert: fs.readFileSync(cert), key: fs.readFileSync(key) }) }, r => {
  const h = crypto.createHash("sha256"); let n = 0;
  r.on("data", d => { n += d.length; h.update(d); }).on("end", () => console.log(n, h.digest("hex")));
}).on("error", e => { console.log("error:", e.message); process.exit(1); });
