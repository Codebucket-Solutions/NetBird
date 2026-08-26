#!/usr/bin/env python3
"""Reconstruct and qualify the CodeBuckets NetBird enterprise overlay."""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Any


STABLE_TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
PATCH_HASH = re.compile(r"^([0-9a-fA-F]{64})  (.+)$")
PATCH_DIFF = re.compile(r"^diff --git a/(.+) b/(.+)$", re.MULTILINE)
ENTERPRISE_HOOK_PATHS = {
    "client/cmd/service_controller.go",
    "client/ui/tray.go",
}
CUSTOM_SOURCE_PATTERNS = (
    "client/enterprise/**",
    "client/ui/enterprise_*.go",
    "client/ui/services/enterprise_*.go",
)


def run(
    *command: str,
    cwd: Path | None = None,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    if env:
        environment.update(env)
    result = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and result.returncode != 0:
        rendered = " ".join(command)
        diagnostics = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip())
        raise RuntimeError(f"command failed ({rendered})\n{diagnostics}")
    return result


def read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"required JSON file does not exist: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"expected a JSON object: {path}")
    return value


def atomic_json_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="\n",
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        delete=False,
    ) as temporary:
        json.dump(value, temporary, indent=2)
        temporary.write("\n")
        temporary_path = Path(temporary.name)
    os.replace(temporary_path, path)


def github_output(name: str, value: object) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    with Path(output_path).open("a", encoding="utf-8", newline="\n") as output:
        output.write(f"{name}={str(value).lower() if isinstance(value, bool) else value}\n")


def print_result(value: dict[str, Any]) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def require_schema(lock: dict[str, Any], config: dict[str, Any]) -> None:
    if lock.get("schema_version") != 1 or config.get("schema_version") != 1:
        raise RuntimeError("unsupported overlay or lock schema version")


def verify_policy_contract(source: Path, overlay_root: Path, enterprise_text: str) -> None:
    config = read_json(overlay_root / "overlay.config.json")
    schema = read_json(overlay_root / "policy" / "client-policy.schema.json")
    schema_version = schema.get("properties", {}).get("schema_version", {}).get("const")
    if schema_version != config.get("policy_schema_version"):
        raise RuntimeError("policy JSON schema version does not match overlay.config.json")

    catalog = schema.get("x-netbird-mdm-catalog")
    if not isinstance(catalog, list) or not catalog:
        raise RuntimeError("policy JSON schema has no MDM capability catalog")
    catalog_keys = [str(item.get("key", "")) for item in catalog if isinstance(item, dict)]
    if not all(catalog_keys) or len(catalog_keys) != len(set(catalog_keys)):
        raise RuntimeError("policy MDM capability catalog contains empty or duplicate keys")

    native_catalog_keys = {
        str(item["key"])
        for item in catalog
        if isinstance(item, dict) and item.get("support") != "enterprise"
    }
    mdm_source = (source / "client" / "mdm" / "policy.go").read_text(encoding="utf-8")
    native_source_constants = dict(
        re.findall(r'(Key[A-Za-z0-9]+)\s*=\s*"([^"]+)"', mdm_source)
    )
    native_source_keys = set(native_source_constants.values())
    if native_catalog_keys != native_source_keys:
        missing = sorted(native_source_keys - native_catalog_keys)
        stale = sorted(native_catalog_keys - native_source_keys)
        raise RuntimeError(
            "policy MDM catalog drifted from locked upstream "
            f"(missing={missing}, stale={stale})"
        )

    registry_match = re.search(
        r"var supportedNetBirdControls = map\[string\]struct\{\}\{(.*?)\n\}",
        enterprise_text,
        re.DOTALL,
    )
    if not registry_match:
        raise RuntimeError("enterprise native-control registry is missing")
    registry_constants = set(re.findall(r"mdm\.(Key[A-Za-z0-9]+):", registry_match.group(1)))
    unknown_constants = sorted(registry_constants - set(native_source_constants))
    if unknown_constants:
        raise RuntimeError(f"enterprise native-control registry has unknown constants: {unknown_constants}")
    registry_keys = {native_source_constants[name] for name in registry_constants}
    schema_control_keys = set(
        schema.get("properties", {})
        .get("netBirdControls", {})
        .get("propertyNames", {})
        .get("enum", [])
    )
    if registry_keys != schema_control_keys:
        raise RuntimeError(
            "policy schema and enterprise native-control registry differ "
            f"(Go={sorted(registry_keys)}, JSON={sorted(schema_control_keys)})"
        )

    required_literals = (
        f"SchemaVersion:         {schema_version}",
        f'enterpriseRevision   = "codebuckets.{config["enterprise_revision"]}"',
        'json:"netBirdControls"',
        'json:"exit_node"',
        'exitNodePinned         exitNodeMode = "PINNED"',
    )
    for required in required_literals:
        if required not in enterprise_text:
            raise RuntimeError(f"enterprise implementation is missing policy contract invariant: {required}")


def series_entries(path: Path) -> list[str]:
    if not path.is_file():
        raise RuntimeError(f"patch series does not exist: {path}")
    entries = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if len(entries) != len(set(entries)):
        raise RuntimeError("patch series contains duplicate entries")
    for entry in entries:
        if Path(entry).name != entry or not entry.lower().endswith(".patch"):
            raise RuntimeError(f"patch series entry must be a plain .patch filename: {entry}")
    return entries


def github_json(url: str) -> dict[str, Any]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "codebuckets-netbird-enterprise-overlay",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=15) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise RuntimeError(f"GitHub returned an unexpected response for {url}")
    return value


def discover(args: argparse.Namespace, overlay_root: Path) -> None:
    repository = args.repository
    release = github_json(f"https://api.github.com/repos/{repository}/releases/latest")
    tag = str(release.get("tag_name", ""))
    if release.get("draft") or release.get("prerelease") or not STABLE_TAG.fullmatch(tag):
        raise RuntimeError(f"GitHub latest release is not a stable semantic version: {tag}")

    clone_url = f"https://github.com/{repository}.git"
    tag_ref = f"refs/tags/{tag}"
    peeled_ref = f"{tag_ref}^{{}}"
    remote = run("git", "ls-remote", "--tags", clone_url, tag_ref, peeled_ref)
    resolved: dict[str, str] = {}
    for line in remote.stdout.splitlines():
        fields = line.split()
        if len(fields) == 2 and GIT_SHA.fullmatch(fields[0]):
            resolved[fields[1]] = fields[0]
    if tag_ref not in resolved or peeled_ref not in resolved:
        raise RuntimeError(f"stable annotated tag could not be resolved and peeled: {tag}")

    tag_object_sha = resolved[tag_ref]
    commit_sha = resolved[peeled_ref]
    commit = github_json(f"https://api.github.com/repos/{repository}/commits/{commit_sha}")
    verification = commit.get("commit", {}).get("verification", {})
    verified = bool(verification.get("verified"))
    verification_reason = str(verification.get("reason", ""))
    if not verified and not args.allow_unverified_commit:
        raise RuntimeError(f"upstream release commit is not verified: {commit_sha} ({verification_reason})")

    lock_path = Path(args.lock_path).resolve() if args.lock_path else overlay_root / "upstream.lock.json"
    existing = read_json(lock_path) if lock_path.is_file() else None
    changed = existing is None or any(
        existing.get(key) != value
        for key, value in {
            "release_tag": tag,
            "tag_object_sha": tag_object_sha,
            "commit_sha": commit_sha,
        }.items()
    )
    published_at = dt.datetime.fromisoformat(str(release["published_at"]).replace("Z", "+00:00"))
    lock = {
        "schema_version": 1,
        "repository": repository,
        "clone_url": clone_url,
        "release_tag": tag,
        "tag_object_sha": tag_object_sha,
        "commit_sha": commit_sha,
        "commit_verified": verified,
        "commit_verification_reason": verification_reason,
        "release_url": str(release["html_url"]),
        "release_published_at": published_at.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "locked_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if args.write_lock and changed:
        atomic_json_write(lock_path, lock)

    for name, value in {
        "changed": changed,
        "release_tag": tag,
        "tag_object_sha": tag_object_sha,
        "commit_sha": commit_sha,
        "release_url": release["html_url"],
    }.items():
        github_output(name, value)
    print_result(
        {
            "changed": changed,
            "release_tag": tag,
            "tag_object_sha": tag_object_sha,
            "commit_sha": commit_sha,
            "commit_verified": verified,
            "verification_reason": verification_reason,
            "lock_written": bool(args.write_lock and changed),
        }
    )


def verify_source(source: Path, overlay_root: Path, require_hook: bool) -> dict[str, Any]:
    source = source.resolve()
    if not source.is_dir():
        raise RuntimeError(f"materialized source does not exist: {source}")
    lock = read_json(overlay_root / "upstream.lock.json")
    config = read_json(overlay_root / "overlay.config.json")
    require_schema(lock, config)
    if run("git", "rev-parse", "--is-inside-work-tree", cwd=source).stdout.strip() != "true":
        raise RuntimeError(f"source path is not a Git worktree: {source}")

    base = str(lock["commit_sha"])
    run("git", "merge-base", "--is-ancestor", base, "HEAD", cwd=source)
    changed_paths = [
        path.strip().replace("\\", "/")
        for path in run("git", "diff", "--name-only", f"{base}..HEAD", cwd=source).stdout.splitlines()
        if path.strip()
    ]
    allowed_patterns = allowed_source_patterns(config)
    unexpected = [
        path
        for path in changed_paths
        if not any(fnmatch.fnmatchcase(path, pattern) for pattern in allowed_patterns)
    ]
    if unexpected:
        raise RuntimeError("patches modified paths outside the allow-list:\n" + "\n".join(unexpected))

    run("git", "diff", "--check", f"{base}..HEAD", cwd=source)
    conflicts = run("git", "grep", "-n", "-E", r"^(<<<<<<<|>>>>>>>)", "--", ".", cwd=source, check=False)
    if conflicts.returncode == 0 and conflicts.stdout.strip():
        raise RuntimeError("conflict markers found:\n" + conflicts.stdout.strip())
    if conflicts.returncode not in (0, 1):
        raise RuntimeError("unable to scan source for conflict markers")

    hook_required = bool(config.get("require_enterprise_hook")) or require_hook
    if hook_required:
        enterprise = source / "client" / "enterprise"
        if not enterprise.is_dir():
            raise RuntimeError("enterprise hook is required but client/enterprise does not exist")
        controller = (source / "client" / "cmd" / "service_controller.go").read_text(encoding="utf-8")
        hook_count = len(re.findall(r"enterprise\.Wrap\s*\(", controller))
        if hook_count != 1:
            raise RuntimeError(f"expected exactly one enterprise.Wrap call; found {hook_count}")
        tray = (source / "client" / "ui" / "tray.go").read_text(encoding="utf-8")
        quit_hook_count = len(re.findall(r"t\.enterpriseQuitDisabled\s*\(", tray))
        if quit_hook_count != 1:
            raise RuntimeError(
                f"expected exactly one enterprise quit guard; found {quit_hook_count}"
            )
        enterprise_text = "\n".join(path.read_text(encoding="utf-8") for path in enterprise.rglob("*.go"))
        for required in (config["management_url"], config["policy_url"], "system_serial_number"):
            if str(required) not in enterprise_text:
                raise RuntimeError(f"enterprise implementation is missing invariant: {required}")
        if config["policy_poll_interval_seconds"] != 15:
            raise RuntimeError("enterprise policy poll interval must be 15 seconds")
        verify_policy_contract(source, overlay_root, enterprise_text)

    result = {
        "base_commit": base,
        "source_head": run("git", "rev-parse", "HEAD", cwd=source).stdout.strip(),
        "source_tree": run("git", "rev-parse", "HEAD^{tree}", cwd=source).stdout.strip(),
        "changed_path_count": len(changed_paths),
        "enterprise_hook_required": hook_required,
        "enterprise_hook_verified": hook_required,
    }
    github_output("source_head", result["source_head"])
    github_output("source_tree", result["source_tree"])
    github_output("changed_path_count", result["changed_path_count"])
    return result


def verify(args: argparse.Namespace, overlay_root: Path) -> None:
    print_result(verify_source(Path(args.source), overlay_root, args.require_enterprise_hook))


def verify_patch_stack(patch_dir: Path) -> list[str]:
    entries = series_entries(patch_dir / "series")
    patch_files = sorted(path.name for path in patch_dir.glob("*.patch") if path.is_file())
    if patch_files != sorted(entries):
        raise RuntimeError("patch directory and patches/series differ")

    manifest: dict[str, str] = {}
    manifest_path = patch_dir / "manifest.sha256"
    if not manifest_path.is_file():
        raise RuntimeError(f"patch manifest does not exist: {manifest_path}")
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = PATCH_HASH.fullmatch(stripped)
        if not match:
            raise RuntimeError(f"invalid patch manifest line: {line}")
        digest, name = match.groups()
        if Path(name).name != name or name in manifest:
            raise RuntimeError(f"invalid or duplicate patch manifest entry: {name}")
        manifest[name] = digest.lower()
    if sorted(manifest) != sorted(entries):
        raise RuntimeError("patch manifest entries do not exactly match patches/series")
    for name in entries:
        content = (patch_dir / name).read_bytes()
        actual = hashlib.sha256(content).hexdigest()
        if actual != manifest[name]:
            raise RuntimeError(f"patch hash mismatch: {name}")
        diff_paths = PATCH_DIFF.findall(content.decode("utf-8"))
        if not diff_paths:
            raise RuntimeError(f"patch contains no file diff: {name}")
        for before, after in diff_paths:
            if before != after or before not in ENTERPRISE_HOOK_PATHS:
                raise RuntimeError(
                    f"patch modifies a path other than an approved enterprise hook: "
                    f"{name}: {before} -> {after}"
                )
    return entries


def allowed_source_patterns(config: dict[str, Any]) -> list[str]:
    patterns = [str(pattern) for pattern in config["allowed_upstream_path_patterns"]]
    if config.get("allow_ui_patch"):
        patterns.append("client/ui/**")
    return patterns


def custom_source_inventory(
    custom_root: Path,
    allowed_patterns: list[str],
) -> tuple[list[tuple[Path, Path]], str]:
    if not custom_root.is_dir():
        raise RuntimeError(f"custom source root does not exist: {custom_root}")
    inventory: list[tuple[Path, Path]] = []
    digest = hashlib.sha256()
    for source in sorted(custom_root.rglob("*")):
        if source.is_symlink():
            raise RuntimeError(f"custom source must not contain symlinks: {source}")
        if not source.is_file():
            continue
        relative = source.relative_to(custom_root)
        normalized = relative.as_posix()
        if not any(fnmatch.fnmatchcase(normalized, pattern) for pattern in CUSTOM_SOURCE_PATTERNS):
            raise RuntimeError(f"custom source path is not enterprise-owned: {normalized}")
        if not any(fnmatch.fnmatchcase(normalized, pattern) for pattern in allowed_patterns):
            raise RuntimeError(f"custom source path is outside the allow-list: {normalized}")
        content = source.read_bytes()
        digest.update(normalized.encode("utf-8"))
        digest.update(b"\0")
        digest.update(content)
        digest.update(b"\0")
        inventory.append((source, relative))
    if not inventory:
        raise RuntimeError("custom source root is empty")
    return inventory, digest.hexdigest()


def install_custom_sources(
    destination: Path,
    inventory: list[tuple[Path, Path]],
) -> None:
    for source, relative in inventory:
        target = destination / relative
        if target.exists():
            raise RuntimeError(f"custom source collides with upstream: {relative.as_posix()}")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def materialize(args: argparse.Namespace, overlay_root: Path) -> None:
    destination = Path(args.destination).resolve()
    if destination.exists():
        raise RuntimeError(f"destination already exists; use a clean path: {destination}")
    lock = read_json(overlay_root / "upstream.lock.json")
    config = read_json(overlay_root / "overlay.config.json")
    require_schema(lock, config)
    if not STABLE_TAG.fullmatch(str(lock.get("release_tag", ""))):
        raise RuntimeError("locked tag is not a stable semantic version")
    for key in ("tag_object_sha", "commit_sha"):
        if not GIT_SHA.fullmatch(str(lock.get(key, ""))):
            raise RuntimeError(f"lock property {key} is not a full Git SHA")
    if not lock.get("commit_verified"):
        raise RuntimeError("locked upstream commit is not marked verified")
    patch_entries = verify_patch_stack(overlay_root / "patches")
    custom_inventory, custom_source_sha256 = custom_source_inventory(
        overlay_root / "custom",
        allowed_source_patterns(config),
    )

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir()
    run("git", "init", cwd=destination)
    run("git", "remote", "add", "upstream", str(lock["clone_url"]), cwd=destination)
    tag = str(lock["release_tag"])
    run("git", "fetch", "--depth=1", "upstream", f"refs/tags/{tag}:refs/tags/{tag}", cwd=destination)
    actual_tag = run("git", "rev-parse", f"{tag}^{{tag}}", cwd=destination).stdout.strip()
    actual_commit = run("git", "rev-parse", f"{tag}^{{commit}}", cwd=destination).stdout.strip()
    if actual_tag != lock["tag_object_sha"] or actual_commit != lock["commit_sha"]:
        raise RuntimeError("fetched upstream provenance does not match the lock")
    run("git", "checkout", "--detach", str(lock["commit_sha"]), cwd=destination)
    run("git", "config", "user.name", "working-max", cwd=destination)
    run("git", "config", "user.email", "administrator@thecodebucket.com", cwd=destination)
    run("git", "config", "commit.gpgsign", "false", cwd=destination)
    run("git", "config", "tag.gpgSign", "false", cwd=destination)
    if run("git", "status", "--porcelain", cwd=destination).stdout.strip():
        raise RuntimeError("materialized upstream tree is dirty before patching")

    for patch_name in patch_entries:
        patch_path = (overlay_root / "patches" / patch_name).resolve()
        result = run("git", "apply", "--3way", "--", str(patch_path), cwd=destination, check=False)
        if result.returncode != 0:
            raise RuntimeError(f"patch failed: {patch_name}\n{result.stdout}\n{result.stderr}")

    install_custom_sources(destination, custom_inventory)
    run("git", "add", "--all", cwd=destination)
    run("git", "diff", "--cached", "--check", cwd=destination)
    if not run("git", "diff", "--cached", "--name-only", cwd=destination).stdout.strip():
        raise RuntimeError("enterprise overlay produced no source changes")
    commit_date = str(lock["release_published_at"])
    run(
        "git",
        "commit",
        "--no-gpg-sign",
        "-m",
        "enterprise: apply CodeBuckets managed client overlay",
        cwd=destination,
        env={"GIT_AUTHOR_DATE": commit_date, "GIT_COMMITTER_DATE": commit_date},
    )

    if not args.skip_verification:
        print_result(verify_source(destination, overlay_root, args.require_enterprise_hook))

    manifest_path = overlay_root / "patches" / "manifest.sha256"
    policy_contract_path = overlay_root / "policy" / "client-policy.schema.json"
    overlay_head = run("git", "rev-parse", "--verify", "HEAD", cwd=overlay_root, check=False)
    provenance = {
        "schema_version": 1,
        "upstream_tag": tag,
        "tag_object_sha": lock["tag_object_sha"],
        "upstream_commit": lock["commit_sha"],
        "overlay_commit": overlay_head.stdout.strip() if overlay_head.returncode == 0 else "uncommitted",
        "patch_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "patch_count": len(patch_entries),
        "custom_source_sha256": custom_source_sha256,
        "custom_file_count": len(custom_inventory),
        "policy_contract_sha256": hashlib.sha256(policy_contract_path.read_bytes()).hexdigest(),
        "source_head": run("git", "rev-parse", "HEAD", cwd=destination).stdout.strip(),
        "source_tree": run("git", "rev-parse", "HEAD^{tree}", cwd=destination).stdout.strip(),
        "materialized_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    provenance_path = Path(f"{destination}.provenance.json")
    atomic_json_write(provenance_path, provenance)
    for name, value in {
        "source_path": destination,
        "provenance_path": provenance_path,
        "upstream_tag": tag,
        "upstream_commit": lock["commit_sha"],
        "source_tree": provenance["source_tree"],
    }.items():
        github_output(name, value)
    print_result({"source_path": str(destination), "provenance_path": str(provenance_path), **provenance})


def export_overlay(args: argparse.Namespace, overlay_root: Path) -> None:
    source = Path(args.source).resolve()
    output = Path(args.output).resolve()
    if not source.is_dir() or output.exists():
        raise RuntimeError("source must exist and output must be a new directory")
    base = str(read_json(overlay_root / "upstream.lock.json")["commit_sha"])
    run("git", "merge-base", "--is-ancestor", base, "HEAD", cwd=source)
    if run("git", "status", "--porcelain", cwd=source).stdout.strip():
        raise RuntimeError("development source must be clean before exporting patches")
    verify_source(source, overlay_root, True)

    custom_source = source / "client" / "enterprise"
    if not custom_source.is_dir():
        raise RuntimeError("development source is missing client/enterprise")
    custom_output = output / "custom"
    custom_files = [
        path
        for path in source.rglob("*")
        if path.is_file()
        and any(
            fnmatch.fnmatchcase(path.relative_to(source).as_posix(), pattern)
            for pattern in CUSTOM_SOURCE_PATTERNS
        )
    ]
    for custom_file in sorted(custom_files):
        relative = custom_file.relative_to(source)
        target = custom_output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(custom_file, target)

    patch_output = output / "patches"
    patch_output.mkdir(parents=True)
    patch_specs = (
        ("0001-enterprise-enforce-managed-client-policy.patch", "client/cmd/service_controller.go"),
        ("0002-enterprise-guard-ui-quit.patch", "client/ui/tray.go"),
    )
    manifest_lines: list[str] = []
    for patch_name, hook_path in patch_specs:
        hook_diff = run(
            "git",
            "diff",
            "--binary",
            "--full-index",
            f"{base}..HEAD",
            "--",
            hook_path,
            cwd=source,
        ).stdout
        if not hook_diff.strip():
            raise RuntimeError(f"development source has no enterprise hook change: {hook_path}")
        patch_path = patch_output / patch_name
        patch_path.write_text(hook_diff, encoding="utf-8", newline="\n")
        manifest_lines.append(f"{hashlib.sha256(patch_path.read_bytes()).hexdigest()}  {patch_name}")
    (patch_output / "series").write_text(
        "\n".join(name for name, _ in patch_specs) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (patch_output / "manifest.sha256").write_text(
        "\n".join(manifest_lines) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print_result(
        {
            "source_path": str(source),
            "base_commit": base,
            "source_head": run("git", "rev-parse", "HEAD", cwd=source).stdout.strip(),
            "output_directory": str(output),
            "patch_files": [name for name, _ in patch_specs],
            "custom_file_count": len([path for path in custom_output.rglob("*") if path.is_file()]),
        }
    )


def release_preflight(args: argparse.Namespace, overlay_root: Path) -> None:
    if not re.fullmatch(r"[1-9][0-9]*", args.enterprise_revision):
        raise RuntimeError("enterprise revision must be a positive integer")
    config = read_json(overlay_root / "overlay.config.json")
    lock = read_json(overlay_root / "upstream.lock.json")
    require_schema(lock, config)
    if not config.get("release_enabled") and not args.allow_release_disabled:
        raise RuntimeError("production release is disabled in overlay.config.json")
    if not config.get("require_enterprise_hook"):
        raise RuntimeError("production release requires require_enterprise_hook=true")
    if int(args.enterprise_revision) != int(config["enterprise_revision"]):
        raise RuntimeError("requested revision does not match overlay.config.json")
    upstream_tag = str(lock["release_tag"])
    if not STABLE_TAG.fullmatch(upstream_tag):
        raise RuntimeError("locked upstream tag is not stable")
    release_tag = f"{upstream_tag}-enterprise.{args.enterprise_revision}"
    github_output("release_tag", release_tag)
    github_output("upstream_tag", upstream_tag)
    print_result({"release_tag": release_tag, "upstream_tag": upstream_tag})


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--overlay-root", help="overlay repository root; defaults to the script parent")
    commands = root.add_subparsers(dest="command", required=True)

    discover_parser = commands.add_parser("discover", help="resolve the latest stable upstream release")
    discover_parser.add_argument("--repository", default="netbirdio/netbird")
    discover_parser.add_argument("--lock-path")
    discover_parser.add_argument("--write-lock", action="store_true")
    discover_parser.add_argument("--allow-unverified-commit", action="store_true")
    discover_parser.set_defaults(handler=discover)

    materialize_parser = commands.add_parser("materialize", help="clone locked upstream and apply the patch stack")
    materialize_parser.add_argument("--destination", required=True)
    materialize_parser.add_argument("--require-enterprise-hook", action="store_true")
    materialize_parser.add_argument("--skip-verification", action="store_true")
    materialize_parser.set_defaults(handler=materialize)

    verify_parser = commands.add_parser("verify", help="verify a reconstructed source tree")
    verify_parser.add_argument("--source", required=True)
    verify_parser.add_argument("--require-enterprise-hook", action="store_true")
    verify_parser.set_defaults(handler=verify)

    export_parser = commands.add_parser("export", help="export custom sources and the tiny hook patch")
    export_parser.add_argument("--source", required=True)
    export_parser.add_argument("--output", required=True)
    export_parser.set_defaults(handler=export_overlay)

    release_parser = commands.add_parser("release-preflight", help="enforce protected release gates")
    release_parser.add_argument("--enterprise-revision", required=True)
    release_parser.add_argument(
        "--allow-release-disabled",
        action="store_true",
        help="validate signing in CI without allowing release publication",
    )
    release_parser.set_defaults(handler=release_preflight)
    return root


def main() -> int:
    args = parser().parse_args()
    overlay_root = Path(args.overlay_root).resolve() if args.overlay_root else Path(__file__).resolve().parents[1]
    try:
        args.handler(args, overlay_root)
    except Exception as error:  # concise failure boundary for local use and CI
        print(f"overlay: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
