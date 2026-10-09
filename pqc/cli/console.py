"""pqc console: the web page for the CA, its certificates, the edges and a connection test."""
import threading
import webbrowser
from pathlib import Path

from .common import ca_passphrase, run_until_signal


def cmd_console(a):
    from ..console import App, Settings, serve
    from ..pki import CA
    s = Settings.load(a.config) if a.config else Settings()
    s.listen = a.listen or s.listen
    s.ca = a.ca or s.ca or "pki"
    s.edges += a.edge
    s.check_updates = s.check_updates or a.check_updates
    if not (Path(s.ca) / "ca.crt").exists():
        raise ValueError(f"no CA in {s.ca}; create one with 'pqc ca init --dir {s.ca}', or point --ca at yours")
    pw = ca_passphrase(s.ca)
    CA(s.ca, pw)
    app = App(s, passphrase=pw)
    httpd = serve(app)
    host, port = httpd.server_address[:2]
    url = f"http://{'localhost' if host == '127.0.0.1' else host}:{port}/"
    print(f"console on {url}\n  open:  {url}#token={app.token}\n  token: {app.token}\nCtrl+C stops it.")
    if host not in ("127.0.0.1", "::1", "localhost"):
        print("warning: listening beyond localhost over plain HTTP; put `pqc tls edge --policy transition` in front of it")
    elif not a.no_browser:
        webbrowser.open(f"{url}#token={app.token}")
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    stop = threading.Event()
    run_until_signal(stop.wait, lambda: (httpd.shutdown(), stop.set()))
    return 0


def add(sub):
    p = sub.add_parser("console", help="web page to issue, revoke and test certificates and watch the edges",
                       epilog="example: pqc console --ca pki --edge http://127.0.0.1:9100")
    p.set_defaults(func=cmd_console)
    p.add_argument("--config", help="TOML with a [console] section")
    p.add_argument("--listen", help="host:port (default 127.0.0.1:8900, this machine only)")
    p.add_argument("--ca", help="CA folder (default: pki)")
    p.add_argument("--edge", action="append", default=[], help="an edge's --metrics address, e.g. http://127.0.0.1:9100 (repeatable)")
    p.add_argument("--check-updates", action="store_true", help="show when a newer release is out (asks GitHub once a day)")
    p.add_argument("--no-browser", action="store_true", help="do not open the page in a browser")
