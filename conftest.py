"""On GitHub Actions, each failing test becomes an annotation, so a failure can be read from the checks API without the log."""
import os


def escape(text, prop=False):
    text = str(text).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return text.replace(":", "%3A").replace(",", "%2C") if prop else text


def pytest_runtest_logreport(report):
    if os.environ.get("GITHUB_ACTIONS") != "true" or not report.failed:
        return
    path, line = report.location[0], (report.location[1] or 0) + 1
    crash = getattr(report.longrepr, "reprcrash", None)
    message = crash.message if crash else (str(report.longrepr or "").strip().splitlines() or ["failed"])[-1]
    print(f"\n::error file={escape(path, True)},line={line},title={escape(report.nodeid, True)}::{escape(message[:500])}", flush=True)
