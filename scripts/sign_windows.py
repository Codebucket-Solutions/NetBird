#!/usr/bin/env python3
"""Authenticode-sign a qualified Windows candidate without persisting key material."""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath


CERTIFICATE_PATTERN = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL
)
EXPECTED_EXECUTABLES = {"netbird.exe", "netbird-ui.exe"}
EXPECTED_COMMON_NAME = "netbird.internal.codebuckets.in"
TIMESTAMP_URLS = (
    "http://timestamp.digicert.com",
    "http://timestamp.globalsign.com/tsa/r45standard",
)
SIGNTOOL_TIMEOUT_SECONDS = 60
X509_ASN_ENCODING = 0x00000001
PKCS_7_ASN_ENCODING = 0x00010000
CERT_STORE_ADD_REPLACE_EXISTING = 3


def run(
    command: list[str],
    *,
    input_bytes: bytes | None = None,
    check: bool = True,
    env: dict[str, str] | None = None,
    timeout_seconds: int | None = None,
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            command,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=env,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(
            f"{Path(command[0]).name} exceeded its {timeout_seconds}-second timeout"
        ) from error
    if check and result.returncode != 0:
        diagnostics = b"\n".join(
            part.strip() for part in (result.stdout, result.stderr) if part.strip()
        ).decode("utf-8", errors="replace")
        raise RuntimeError(f"{Path(command[0]).name} failed\n{diagnostics}")
    return result


def find_openssl() -> Path:
    discovered = shutil.which("openssl")
    candidates = [
        Path(discovered) if discovered else None,
        Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        / "Git"
        / "usr"
        / "bin"
        / "openssl.exe",
    ]
    for candidate in candidates:
        if candidate and candidate.is_file():
            return candidate
    raise RuntimeError("OpenSSL was not found on the Windows runner")


def version_key(path: Path) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in path.parents[1].name.split("."))
    except ValueError:
        return (0,)


def find_signtool() -> Path:
    kits = (
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
        / "Windows Kits"
        / "10"
        / "bin"
    )
    candidates = sorted(kits.glob("*/x64/signtool.exe"), key=version_key, reverse=True)
    if not candidates:
        raise RuntimeError("Windows SDK SignTool was not found")
    return candidates[0]


def openssl_text(openssl: Path, *arguments: str) -> str:
    return run([str(openssl), *arguments]).stdout.decode("utf-8", errors="replace").strip()


def certificate_names(openssl: Path, certificate: Path) -> tuple[str, str]:
    output = openssl_text(
        openssl,
        "x509",
        "-in",
        str(certificate),
        "-noout",
        "-subject",
        "-issuer",
        "-nameopt",
        "RFC2253",
    )
    values: dict[str, str] = {}
    for line in output.splitlines():
        name, separator, value = line.partition("=")
        if separator:
            values[name.strip()] = value.strip()
    if "subject" not in values or "issuer" not in values:
        raise RuntimeError("Unable to read certificate subject and issuer")
    return values["subject"], values["issuer"]


def certificate_thumbprint(openssl: Path, certificate: Path) -> str:
    output = openssl_text(
        openssl, "x509", "-in", str(certificate), "-noout", "-fingerprint", "-sha1"
    )
    _, separator, value = output.partition("=")
    if not separator:
        raise RuntimeError("Unable to read certificate thumbprint")
    return value.replace(":", "").strip().upper()


def certificate_der(certificate: Path) -> bytes:
    value = certificate.read_text(encoding="ascii")
    body = re.sub(r"-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s", "", value)
    return base64.b64decode(body, validate=True)


def install_certificate(store_name: str, certificate: Path) -> tuple[int, int]:
    from ctypes import wintypes

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    crypt32.CertOpenSystemStoreW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR]
    crypt32.CertOpenSystemStoreW.restype = wintypes.HANDLE
    crypt32.CertAddEncodedCertificateToStore.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_ubyte),
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    crypt32.CertAddEncodedCertificateToStore.restype = wintypes.BOOL
    crypt32.CertCloseStore.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    crypt32.CertCloseStore.restype = wintypes.BOOL

    store = crypt32.CertOpenSystemStoreW(None, store_name)
    if not store:
        raise ctypes.WinError(ctypes.get_last_error())
    encoded = certificate_der(certificate)
    buffer = (ctypes.c_ubyte * len(encoded)).from_buffer_copy(encoded)
    context = ctypes.c_void_p()
    if not crypt32.CertAddEncodedCertificateToStore(
        store,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        buffer,
        len(encoded),
        CERT_STORE_ADD_REPLACE_EXISTING,
        ctypes.byref(context),
    ):
        error = ctypes.get_last_error()
        crypt32.CertCloseStore(store, 0)
        raise ctypes.WinError(error)
    return int(store), int(context.value)


def remove_certificates(installed: list[tuple[int, int]]) -> None:
    from ctypes import wintypes

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    crypt32.CertDeleteCertificateFromStore.argtypes = [ctypes.c_void_p]
    crypt32.CertDeleteCertificateFromStore.restype = wintypes.BOOL
    crypt32.CertCloseStore.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    crypt32.CertCloseStore.restype = wintypes.BOOL
    for store, context in reversed(installed):
        crypt32.CertDeleteCertificateFromStore(ctypes.c_void_p(context))
        crypt32.CertCloseStore(wintypes.HANDLE(store), 0)


def validate_signing_identity(
    openssl: Path,
    key_path: Path,
    leaf_path: Path,
    intermediate_paths: list[Path],
    root_path: Path,
) -> str:
    key_public = run(
        [str(openssl), "pkey", "-in", str(key_path), "-pubout", "-outform", "DER"]
    ).stdout
    certificate_public_pem = run(
        [str(openssl), "x509", "-in", str(leaf_path), "-pubkey", "-noout"]
    ).stdout
    certificate_public = run(
        [str(openssl), "pkey", "-pubin", "-outform", "DER"],
        input_bytes=certificate_public_pem,
    ).stdout
    if not key_public or key_public != certificate_public:
        raise RuntimeError("CSCA1_KEY does not match CSCA1_CERT")

    public_description = run(
        [str(openssl), "pkey", "-pubin", "-text", "-noout"], input_bytes=certificate_public_pem
    ).stdout.decode("utf-8", errors="replace")
    if "384 bit" not in public_description or "secp384r1" not in public_description:
        raise RuntimeError("Signing key must use ECDSA P-384 (secp384r1)")

    subject, _ = certificate_names(openssl, leaf_path)
    if not subject.startswith(f"CN={EXPECTED_COMMON_NAME},"):
        raise RuntimeError(f"Signing certificate CN must be {EXPECTED_COMMON_NAME}")

    eku = openssl_text(
        openssl, "x509", "-in", str(leaf_path), "-noout", "-ext", "extendedKeyUsage"
    )
    usages = [part.strip() for part in eku.splitlines()[-1].split(",")]
    if usages != ["Code Signing"]:
        raise RuntimeError("Signing certificate must contain only the Code Signing EKU")

    run([str(openssl), "x509", "-in", str(leaf_path), "-noout", "-checkend", "0"])
    verify = [str(openssl), "verify", "-CAfile", str(root_path)]
    if intermediate_paths:
        intermediate_bundle = intermediate_paths[0].parent / "intermediates.pem"
        intermediate_bundle.write_text(
            "\n".join(path.read_text(encoding="ascii").strip() for path in intermediate_paths)
            + "\n",
            encoding="ascii",
            newline="\n",
        )
        verify.extend(["-untrusted", str(intermediate_bundle)])
    verify.append(str(leaf_path))
    run(verify)
    return certificate_thumbprint(openssl, leaf_path)


def safe_extract(archive: Path, destination: Path) -> None:
    with zipfile.ZipFile(archive) as source:
        for member in source.infolist():
            normalized = PurePosixPath(member.filename.replace("\\", "/"))
            if normalized.is_absolute() or ".." in normalized.parts:
                raise RuntimeError(f"Unsafe archive member: {member.filename}")
        source.extractall(destination)


def write_archive(source: Path, destination: Path) -> None:
    if destination.exists():
        raise RuntimeError(f"Refusing to overwrite output archive: {destination}")
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(source).as_posix())


def sign_executable(
    signtool: Path, pfx_path: Path, pfx_password: str, executable: Path
) -> None:
    failures: list[str] = []
    for timestamp_url in TIMESTAMP_URLS:
        print(f"Signing {executable.name} via {timestamp_url}", flush=True)
        try:
            run(
                [
                    str(signtool),
                    "sign",
                    "/f",
                    str(pfx_path),
                    "/p",
                    pfx_password,
                    "/fd",
                    "SHA256",
                    "/tr",
                    timestamp_url,
                    "/td",
                    "SHA256",
                    str(executable),
                ],
                timeout_seconds=SIGNTOOL_TIMEOUT_SECONDS,
            )
            return
        except RuntimeError as error:
            failures.append(f"{timestamp_url}: {error}")
            print(
                f"Timestamp attempt failed for {timestamp_url}; trying fallback",
                flush=True,
            )
    raise RuntimeError(
        f"All timestamp services failed while signing {executable.name}\n"
        + "\n".join(failures)
    )


def sign(args: argparse.Namespace) -> None:
    if os.name != "nt":
        raise RuntimeError("Authenticode signing must run on Windows")

    certificate_bundle = os.environ.pop("CSCA1_CERT", "")
    private_key = os.environ.pop("CSCA1_KEY", "")
    if not certificate_bundle.strip() or not private_key.strip():
        raise RuntimeError("CSCA1_CERT and CSCA1_KEY repository secrets are required")

    input_directory = Path(args.input_directory).resolve()
    output_directory = Path(args.output_directory).resolve()
    archives = list(input_directory.glob("*.zip"))
    if len(archives) != 1:
        raise RuntimeError(f"Expected one Windows candidate archive, found {len(archives)}")
    output_directory.mkdir(parents=True, exist_ok=True)

    certificate_blocks = [match.strip() for match in CERTIFICATE_PATTERN.findall(certificate_bundle)]
    if len(certificate_blocks) < 3:
        raise RuntimeError("CSCA1_CERT must contain leaf, intermediate, and root certificates")

    openssl = find_openssl()
    signtool = find_signtool()
    installed: list[tuple[int, int]] = []
    with tempfile.TemporaryDirectory(prefix="netbird-authenticode-") as temporary:
        temporary_path = Path(temporary)
        key_path = temporary_path / "key.pem"
        key_path.write_text(private_key.strip() + "\n", encoding="ascii", newline="\n")
        certificate_paths: list[Path] = []
        for index, certificate in enumerate(certificate_blocks):
            path = temporary_path / f"certificate-{index}.pem"
            path.write_text(certificate + "\n", encoding="ascii", newline="\n")
            certificate_paths.append(path)

        leaf_path = certificate_paths[0]
        roots: list[Path] = []
        intermediates: list[Path] = []
        for path in certificate_paths[1:]:
            subject, issuer = certificate_names(openssl, path)
            (roots if subject == issuer else intermediates).append(path)
        if len(roots) != 1 or not intermediates:
            raise RuntimeError("CSCA1_CERT does not contain one root and an intermediate chain")

        print(
            "Validating certificate, key, chain, EKU, and P-384 requirements",
            flush=True,
        )
        leaf_thumbprint = validate_signing_identity(
            openssl, key_path, leaf_path, intermediates, roots[0]
        )
        chain_path = temporary_path / "chain.pem"
        chain_path.write_text(
            "\n".join(
                path.read_text(encoding="ascii").strip()
                for path in [*intermediates, roots[0]]
            )
            + "\n",
            encoding="ascii",
            newline="\n",
        )

        pfx_path = temporary_path / "signing.pfx"
        pfx_password = secrets.token_urlsafe(32)
        openssl_environment = os.environ.copy()
        openssl_environment["NETBIRD_PFX_PASSWORD"] = pfx_password
        run(
            [
                str(openssl),
                "pkcs12",
                "-export",
                "-inkey",
                str(key_path),
                "-in",
                str(leaf_path),
                "-certfile",
                str(chain_path),
                "-out",
                str(pfx_path),
                "-passout",
                "env:NETBIRD_PFX_PASSWORD",
            ],
            env=openssl_environment,
        )

        expanded = temporary_path / "expanded"
        expanded.mkdir()
        safe_extract(archives[0], expanded)
        executables = {path.name: path for path in expanded.glob("*.exe")}
        if set(executables) != EXPECTED_EXECUTABLES:
            raise RuntimeError(
                "Unexpected Windows executable set: " + ", ".join(sorted(executables))
            )

        try:
            print("Installing the temporary verification trust chain", flush=True)
            for store, path in [("Root", roots[0]), *[("CA", item) for item in intermediates]]:
                installed.append(install_certificate(store, path))

            for executable in sorted(executables.values()):
                sign_executable(signtool, pfx_path, pfx_password, executable)
                print(f"Verifying {executable.name}", flush=True)
                run(
                    [str(signtool), "verify", "/pa", "/all", str(executable)],
                    timeout_seconds=SIGNTOOL_TIMEOUT_SECONDS,
                )

            signed_archive = output_directory / archives[0].name
            write_archive(expanded, signed_archive)
            digest = hashlib.sha256(signed_archive.read_bytes()).hexdigest()
            checksum = signed_archive.with_suffix(signed_archive.suffix + ".sha256")
            checksum.write_text(
                f"{digest}  {signed_archive.name}\n", encoding="ascii", newline="\n"
            )
        finally:
            remove_certificates(installed)

    print(f"Signed and verified {len(EXPECTED_EXECUTABLES)} executables")
    print(f"Signing certificate SHA-1: {leaf_thumbprint}")
    print(f"Created {signed_archive.name}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-directory", required=True)
    parser.add_argument("--output-directory", required=True)
    return parser.parse_args()


if __name__ == "__main__":
    sign(parse_args())
