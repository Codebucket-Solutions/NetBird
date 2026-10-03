"""Build upstream's NSIS and MSI installers over the staged, signed binaries.

    python build_installers.py --source <materialized upstream> --arch amd64|arm64 --output <directory>

The source tree must hold dist/netbird_windows_<arch>/ with netbird.exe,
netbird-ui.exe and wintun.dll, and client/MicrosoftEdgeWebview2Setup.exe.
A failing tool is reported as a workflow annotation with the end of its output,
because the job log of this public repository is not readable without a login.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import overlay  # noqa: E402

MAKENSIS = Path(r"C:\Program Files (x86)\NSIS\makensis.exe")
WIX_VERSION = "6.0.2"


def fail(title: str, output: str) -> None:
    tail = output.strip().replace("\r", "")[-1500:]
    print(f"::error title={title}::{tail.replace(chr(10), '%0A')}", flush=True)
    raise SystemExit(1)


def run(title: str, command: list[str], cwd: Path, env: dict[str, str] | None = None) -> str:
    print("+", " ".join(command), flush=True)
    completed = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, errors="replace")
    output = completed.stdout + completed.stderr
    print(output, flush=True)
    if completed.returncode != 0:
        fail(title, output)
    return output


def find_wix() -> Path:
    for candidate in [shutil.which("wix"), Path(os.environ.get("USERPROFILE", "")) / ".dotnet" / "tools" / "wix.exe"]:
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    run("WiX install failed", ["dotnet", "tool", "install", "--global", "wix", "--version", WIX_VERSION], Path.cwd())
    candidate = Path(os.environ.get("USERPROFILE", "")) / ".dotnet" / "tools" / "wix.exe"
    if not candidate.is_file():
        fail("WiX install failed", f"{candidate} does not exist after installation")
    return candidate


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--arch", required=True, choices=["amd64", "arm64"])
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    source = Path(args.source).resolve()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)

    staged = source / "dist" / f"netbird_windows_{args.arch}"
    missing = [name for name in ("netbird.exe", "netbird-ui.exe", "wintun.dll") if not (staged / name).is_file()]
    if missing or not (source / "client" / "MicrosoftEdgeWebview2Setup.exe").is_file():
        fail("Installer inputs missing", f"staged={staged} missing={missing} webview2={(source / 'client' / 'MicrosoftEdgeWebview2Setup.exe').is_file()}")
    if not MAKENSIS.is_file():
        fail("NSIS missing", f"{MAKENSIS} does not exist on this runner")

    version, _ = overlay.release_identity(Path(__file__).resolve().parent.parent)
    upstream, revision = version.split("+codebuckets.")

    # NSIS wants a four-part file version; the enterprise revision is the fourth.
    nsis_env = dict(os.environ, APPVER=f"{upstream}.{revision}")
    run("NSIS installer build failed", [str(MAKENSIS), "/V4", f"/DARCH={args.arch}", r"client\installer.nsis"], source, nsis_env)
    built = source / "netbird-installer.exe"
    if not built.is_file():
        fail("NSIS installer build failed", f"{built} was not produced")
    exe = output / f"netbird-enterprise-windows-{args.arch}.exe"
    shutil.move(str(built), exe)

    # The MSI carries the upstream version; upstream allows same-version upgrades, so a new
    # enterprise revision of the same upstream still installs over the previous one.
    wix = find_wix()
    run("WiX extension install failed", [str(wix), "extension", "add", f"WixToolset.Util.wixext/{WIX_VERSION}"], source)
    wix_arch = "x64" if args.arch == "amd64" else "arm64"
    msi = output / f"netbird-enterprise-windows-{args.arch}.msi"
    run("MSI installer build failed", [
        str(wix), "build", "-arch", wix_arch, "-ext", "WixToolset.Util.wixext", "-o", str(msi), r".\client\netbird.wxs",
        "-d", f"ProcessorArchitecture={wix_arch}", "-d", f"ArchSuffix={args.arch}",
    ], source, dict(os.environ, NETBIRD_VERSION=upstream))
    if not msi.is_file():
        fail("MSI installer build failed", f"{msi} was not produced")

    for installer in (exe, msi):
        print(f"Built {installer.name}: {installer.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
