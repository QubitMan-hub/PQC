"""Shared private file writes and process/thread locking, independent of cryptographic protocols."""
import contextlib
import errno
import os
import secrets
import threading
import time
from pathlib import Path

_THREAD_LOCKS: dict[str, threading.Lock] = {}
_HELD = threading.local()


@contextlib.contextmanager
def locked(root, filename=".lock"):
    """Serialize file-backed state across threads/processes; allow nested updates in one thread."""
    root = Path(root).resolve()
    if Path(filename).name != filename or filename in {".", ".."}:
        raise ValueError("Lock filename must be a single file name")
    key = str(root / filename)
    held = _HELD.__dict__.setdefault("roots", set())
    if key in held:
        yield
        return
    tl = _THREAD_LOCKS.setdefault(key, threading.Lock())
    with tl, os.fdopen(os.open(root / filename, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600), "a+b") as f:
        if os.name == "nt":
            import msvcrt
            f.seek(0)
            while True:
                try:
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError as e:
                    if e.errno not in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                        raise
                    time.sleep(0.05)
        else:
            import fcntl
            fcntl.flock(f, fcntl.LOCK_EX)
        held.add(key)
        try:
            yield
        finally:
            held.discard(key)
            if os.name == "nt":
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)


def shared(action, tries=40):
    """Windows refuses to open or replace a file while another thread has it open (a CRL being read while its new copy is
    swapped in); such a clash lasts milliseconds, so try again briefly. Elsewhere this runs `action` once."""
    for n in range(tries):
        try:
            return action()
        except PermissionError:
            if os.name != "nt" or n == tries - 1:
                raise
            time.sleep(0.025)


def write(path, data, secret=False):
    """Write atomically; secret files are created owner-only."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(12)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600 if secret else 0o644)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        shared(lambda: os.replace(tmp, path))
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def append(path, line):
    """Add one line to a log that only its owner can read (audit logs name identities and administrative actions)."""
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "ab") as f:
        f.write(line.encode() + b"\n")


