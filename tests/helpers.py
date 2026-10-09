"""Shared by the tests."""
import time

from pqc import tls

try:
    tls.lib()
    REASON = None  # why the tests that need OpenSSL 3.5 are skipped, when they are
except tls.OpenSSLUnavailable as e:
    REASON = str(e)


def wait(check, seconds=5.0):
    """Poll `check` until it is true or `seconds` pass; its last answer."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if check():
            return True
        time.sleep(0.05)
    return check()
