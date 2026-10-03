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


def notice(title: str, message: str) -> None:
    print(f"::notice title={title}::{message.strip().replace(chr(13), '')[-1500:].replace(chr(10), '%0A')}", flush=True)


def check_ui(ui: Path) -> None:
    """Start the UI the ways it is started in practice and require it to stay up.

    Explorer and the installer start a windowsgui binary with no console and no
    standard handles; a console starts it with inherited handles. Each variant
    is run on its own, with the UI log read after it, and one variant keeps
    its console output in a file, because the Wails runtime reports a fatal
    error on stderr rather than through the log file.
    """
    log = Path(tempfile.gettempdir()) / "netbird-ui-smoke.log"
    console = Path(tempfile.gettempdir()) / "netbird-ui-smoke.console"
    # Where the enterprise UI sends stderr when it has no standard handles (enterprise_stderr_windows.go).
    stderr_log = Path(os.environ.get("LOCALAPPDATA", tempfile.gettempdir())) / "netbird" / "netbird-ui.stderr.log"
    command = [str(ui), "--log-file", str(log), "--log-level", "debug"]
    detached = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    report = []
    failures = []
    for name, kwargs in (
        ("detached, no standard handles", {"creationflags": detached, "close_fds": True}),
        ("detached, output to a file", {"creationflags": detached, "close_fds": True, "capture": True}),
        ("inherited handles", {}),
    ):
        for path in (log, console, stderr_log):
            if path.exists():
                path.unlink()
        capture = kwargs.pop("capture", False)
        print(f"+ {' '.join(command)}  ({name})", flush=True)
        handle = console.open("wb") if capture else None
        try:
            process = subprocess.Popen(command, stdout=handle, stderr=subprocess.STDOUT if capture else None, **kwargs)
            time.sleep(UI_GRACE_SECONDS)
            exited = process.poll()
        finally:
            if handle:
                handle.close()
        if exited is None:
            process.kill()
            process.wait(timeout=30)
        output = "--- ui log ---\n" + tail(log, 40)
        if capture:
            output += "\n--- ui console ---\n" + tail(console, 40)
        else:
            output += "\n--- ui stderr log ---\n" + tail(stderr_log, 40)
        state = "still running" if exited is None else f"exited with {exited}"
        print(f"{name}: {state}\n{output}", flush=True)
        report.append(f"{name}: {state}")
        if exited is not None:
            failures.append(f"{name}: exited with {exited}\n{output}")
        elif "tray applyIcon" not in output:
            failures.append(f"{name}: running but never set up its tray icon\n{output}")
        time.sleep(3)
    notice("UI launch variants", "\n".join(report) + "\n--- ui stderr log (last variant) ---\n" + tail(stderr_log, 40))
    if failures:
        raise RuntimeError("netbird-ui.exe did not stay up for every launch variant\n" + "\n\n".join(failures))
    print(f"netbird-ui.exe ran for {UI_GRACE_SECONDS}s in every launch variant and set up its tray icon")


def run_diagnostic_ui(ui: Path) -> None:
    """Run a console-subsystem, non-production build with its output captured and report it."""
    console = Path(tempfile.gettempdir()) / "netbird-ui-diagnostic.console"
    if console.exists():
        console.unlink()
    print(f"+ {ui} --log-level debug  (diagnostic build, output captured)", flush=True)
    with console.open("wb") as handle:
        process = subprocess.Popen([str(ui), "--log-level", "debug"], stdout=handle, stderr=subprocess.STDOUT)
        time.sleep(UI_GRACE_SECONDS)
        exited = process.poll()
    if exited is None:
        process.kill()
        process.wait(timeout=30)
    output = tail(console, 60)
    state = "still running" if exited is None else f"exited with {exited}"
    print(f"diagnostic build: {state}\n{output}", flush=True)
    notice("Diagnostic UI output", f"{state}\n{output}")


def smoke(directory: Path, expected: str, diagnostic_ui: Path | None) -> None:
    netbird, ui = directory / "netbird.exe", directory / "netbird-ui.exe"
    for executable in (netbird, ui):
        if not executable.is_file():
            raise RuntimeError(f"{executable} is missing")
    check_version(netbird, expected)
    print(wait_for_daemon(netbird))
    try:
        check_ui(ui)
    finally:
        if diagnostic_ui and diagnostic_ui.is_file():
            run_diagnostic_ui(diagnostic_ui)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-version", required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--directory", help="run the daemon from these built files")
    source.add_argument("--installer", help="install this NSIS installer silently and test the installation")
    parser.add_argument("--diagnostic-ui", help="a console-subsystem UI build to run with its output captured after the checks")
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
        smoke(directory, args.expected_version, Path(args.diagnostic_ui) if args.diagnostic_ui else None)
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
