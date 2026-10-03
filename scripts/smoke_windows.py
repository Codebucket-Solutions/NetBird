"""Start the built client on this Windows machine and check that it runs.

    python smoke_windows.py --expected-version 0.80.0+codebuckets.1 --directory <dir with netbird.exe and netbird-ui.exe>
    python smoke_windows.py --expected-version 0.80.0+codebuckets.1 --installer <netbird-enterprise-windows-amd64.exe>

With --directory the daemon is installed as a service from that directory; with
--installer the NSIS installer is run silently and the installed files are
tested, then uninstalled. Either way: the daemon must answer "status" and report
the expected version, and the UI must still be running after a grace period.
Failures are reported as workflow annotations with the relevant log, because
the job log of this public repository is not readable without a login.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

INSTALL_DIRECTORY = Path(r"C:\Program Files\Netbird")
DAEMON_LOG = Path(r"C:\ProgramData\Netbird\client.log")
UI_GRACE_SECONDS = 20
DAEMON_READY_SECONDS = 30


def annotate(title: str, message: str) -> None:
    print(f"::error title={title}::{message.strip().replace(chr(13), '')[-1500:].replace(chr(10), '%0A')}", flush=True)


def run(command: list[str], timeout: int = 120, check: bool = True) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(command), flush=True)
    completed = subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=timeout)
    print(completed.stdout + completed.stderr, flush=True)
    if check and completed.returncode != 0:
        raise RuntimeError(f"{command[0]} exited {completed.returncode}: {completed.stdout}{completed.stderr}")
    return completed


def tail(path: Path, lines: int = 60) -> str:
    if not path.is_file():
        return f"{path} does not exist"
    return "\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:])


def wait_for_daemon(netbird: Path) -> str:
    deadline = time.time() + DAEMON_READY_SECONDS
    last = ""
    while time.time() < deadline:
        completed = run([str(netbird), "status"], timeout=30, check=False)
        last = completed.stdout + completed.stderr
        if completed.returncode == 0 and "Daemon version" in completed.stdout:
            return completed.stdout
        time.sleep(3)
    raise RuntimeError("the daemon did not answer 'status' in time:\n" + last + "\n--- client.log ---\n" + tail(DAEMON_LOG))


def check_version(netbird: Path, expected: str) -> None:
    reported = run([str(netbird), "version"], timeout=30).stdout.strip()
    if reported != expected:
        raise RuntimeError(f"netbird.exe version is {reported!r}, expected {expected!r}")


def check_ui(ui: Path) -> None:
    log = Path(tempfile.gettempdir()) / "netbird-ui-smoke.log"
    console = Path(tempfile.gettempdir()) / "netbird-ui-smoke.console"
    for path in (log, console):
        if path.exists():
            path.unlink()
    print(f"+ {ui} --log-file {log} --log-level debug", flush=True)
    # A GUI-subsystem process still writes to handles its parent hands it, which is where the Wails
    # runtime reports a fatal error; logrus output goes to the log file.
    with console.open("wb") as handle:
        process = subprocess.Popen([str(ui), "--log-file", str(log), "--log-level", "debug"], stdout=handle, stderr=subprocess.STDOUT)
        time.sleep(UI_GRACE_SECONDS)
        exited = process.poll()
    output = "--- ui log ---\n" + tail(log, 60) + "\n--- ui console ---\n" + tail(console, 40)
    print(output, flush=True)
    if exited is not None:
        raise RuntimeError(f"netbird-ui.exe exited with {exited} within {UI_GRACE_SECONDS}s\n{output}")
    if "tray applyIcon" not in output:
        process.kill()
        raise RuntimeError("netbird-ui.exe is running but never set up its tray icon\n" + output)
    process.kill()
    process.wait(timeout=30)
    print(f"netbird-ui.exe ran for {UI_GRACE_SECONDS}s and set up its tray icon")


def smoke(directory: Path, expected: str) -> None:
    netbird, ui = directory / "netbird.exe", directory / "netbird-ui.exe"
    for executable in (netbird, ui):
        if not executable.is_file():
            raise RuntimeError(f"{executable} is missing")
    check_version(netbird, expected)
    print(wait_for_daemon(netbird))
    check_ui(ui)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-version", required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--directory", help="run the daemon from these built files")
    source.add_argument("--installer", help="install this NSIS installer silently and test the installation")
    args = parser.parse_args()
    if os.name != "nt":
        raise SystemExit("the smoke test runs on Windows only")

    installer = Path(args.installer).resolve() if args.installer else None
    directory = INSTALL_DIRECTORY if installer else Path(args.directory).resolve()
    netbird = directory / "netbird.exe"
    try:
        if installer:
            run([str(installer), "/S"], timeout=600)
            time.sleep(5)
        else:
            run([str(netbird), "service", "install"], timeout=120)
            run([str(netbird), "service", "start"], timeout=120)
        smoke(directory, args.expected_version)
    except Exception as error:  # noqa: BLE001 - every failure is reported the same way
        annotate("Windows smoke test failed", str(error))
        return 1
    finally:
        try:
            if installer:
                uninstaller = INSTALL_DIRECTORY / "netbird_uninstall.exe"
                if uninstaller.is_file():
                    run([str(uninstaller), "/S"], timeout=600, check=False)
            elif netbird.is_file():
                run([str(netbird), "service", "stop"], timeout=120, check=False)
                run([str(netbird), "service", "uninstall"], timeout=120, check=False)
        except Exception as cleanup:  # noqa: BLE001
            print(f"cleanup failed: {cleanup}", flush=True)
    print("Windows smoke test passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
