// A Go HTTPS client (Go 1.24+ offers X25519MLKEM768 by default but cannot verify ML-DSA certificates).
// usage: client URL CA_FILE -> prints the body's size and SHA-256, exits 1 on failure
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	pool := x509.NewCertPool()
	b, _ := os.ReadFile(os.Args[2])
	pool.AppendCertsFromPEM(b)
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}}
	r, err := c.Get(os.Args[1])
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	h := sha256.New()
	n, _ := io.Copy(h, r.Body)
	fmt.Printf("%d %x\n", n, h.Sum(nil))
}
