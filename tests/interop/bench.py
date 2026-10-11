"""How fast is the edge on this machine? Starts a small web server, an edge in front of it, and clients built on pqc's own
TLS (so it runs anywhere pqc does, Windows included). Prints new handshakes per second and requests per second on kept-alive
connections. The clients share the machine with the edge, so the numbers are a floor, not a ceiling.

    python tests/interop/bench.py [seconds]
"""
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from pqc import tls
from pqc.pki import CA


class Hello(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):  # one write: headers and body sent separately stall ~40 ms each on Nagle and delayed ACKs
        self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nhello\n")

    def log_message(self, *a):
        pass


def run(seconds, ctx, port, fresh):
    done, end = [], time.monotonic() + seconds

    def client():
        n, conn = 0, None
        while time.monotonic() < end:
            if conn is None:
                conn = tls.connect("127.0.0.1", port, ctx, "localhost", 10)
            conn.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            reply = b""
            while not reply.endswith(b"hello\n"):
                reply += conn.recv(timeout=10)
            n += 1
            if fresh:
                conn.close()
                conn = None
        done.append(n)
    threads = [threading.Thread(target=client) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return sum(done) / seconds


def main():
    seconds = float(sys.argv[1]) if len(sys.argv) > 1 else 5
    with tempfile.TemporaryDirectory() as d:
        ca = CA.init(Path(d) / "pki", "Bench Root")
        srv, _ = ca.issue("localhost", "server", ["127.0.0.1"])
        web = ThreadingHTTPServer(("127.0.0.1", 0), Hello)
        threading.Thread(target=web.serve_forever, daemon=True).start()
        edge = subprocess.Popen([sys.executable, "-m", "pqc", "tls", "edge", "--listen", "127.0.0.1:18555",
                                 "--target", f"127.0.0.1:{web.server_address[1]}", "--cert", str(srv / "chain.pem"),
                                 "--key", str(srv / "key.pem")], stderr=subprocess.DEVNULL)
        try:
            ctx = tls.client_context(str(Path(d) / "pki" / "ca.crt"))
            for _ in range(50):
                try:
                    tls.connect("127.0.0.1", 18555, ctx, "localhost", 2).close()
                    break
                except (tls.TLSError, OSError):
                    time.sleep(0.2)
            print(f"{tls.lib().version}, Python {sys.version.split()[0]} on {sys.platform}")
            print(f"new connections (X25519MLKEM768 + ML-DSA-65): {run(seconds, ctx, 18555, True):6.0f} per second")
            print(f"requests on kept-alive connections:           {run(seconds, ctx, 18555, False):6.0f} per second")
        finally:
            edge.terminate()
            web.shutdown()


if __name__ == "__main__":
    main()
