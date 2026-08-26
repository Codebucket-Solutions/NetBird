# CodeBuckets NetBird Enterprise Overlay

This repository contains the enterprise overlay for the upstream
[`netbirdio/netbird`](https://github.com/netbirdio/netbird) client. It does not
vendor the upstream source tree.

Every build is reconstructed from four immutable inputs:

1. `upstream.lock.json`, which pins the upstream annotated tag and commit;
2. the ordered patches listed in `patches/series`; and
3. the enterprise Go sources under `custom/`; and
4. the overlay Git commit containing the scripts and workflows.

The upstream checkout under the parent workspace (`../netbird-original`) is a
developer reference only. CI never trusts or packages it. CI creates a fresh
checkout from the lock and applies the patch series.

## Current implementation status

There are two deliberately tiny upstream touchpoints: the daemon composition
hook in `client/cmd/service_controller.go`, and one guard call at the start of
the desktop tray's Quit handler. All policy, enforcement, polling, and UI guard
logic is maintained as ordinary Go source under `custom/client`, outside the
patches. Production publication remains disabled in `overlay.config.json`.

The machine-readable API contract and complete v0.77.1 native MDM capability
inventory live in `policy/client-policy.schema.json`. Policy schema v4 uses a
sparse `netBirdControls` object whose keys exactly match native MDM names, plus
`enterpriseControls` and exit-node policy. Exit nodes
support `PINNED`, `DISABLED`, and `USER_CONTROLLED`; strict behavior is used when
no valid policy is available. Qualification compares the JSON key allow-list,
the Go enforcement registry, and upstream MDM constants so they cannot drift.

## Local materialization

From Windows, macOS, or Linux:

```shell
python scripts/overlay.py materialize --destination build/source
```

The command verifies upstream provenance and the patch manifest, applies the
two tiny hook patches, copies the custom source tree, creates one deterministic overlay
commit, and runs the invariants. It refuses to reuse an existing destination.

## Patch development

Normally, edit the enterprise-owned files under `custom/client` directly. If developing against a
materialized checkout, export both the custom source tree and regenerated hook
patch to a new directory:

```shell
python scripts/overlay.py export \
  --source build/development-source \
  --output build/exported-overlay
```

The export contains `custom/` and `patches/`. Review both before replacing the
canonical overlay payload. Patches are restricted to the daemon composition
block and the one tray Quit guard; custom policy code must never be embedded in
either patch.

## GitHub Actions

- `discover-upstream.yml` discovers a newer stable release and opens a draft
  lock-update PR. It never releases.
- `qualify.yml` reconstructs, verifies, tests, and builds Windows amd64/arm64
  candidates entirely on Windows runners. There is no Linux or macOS job.
- `release.yml` supports a signing-only CI test that cannot publish a release.
  Normal release dispatches Authenticode-sign Windows candidates and creates a
  Windows-only draft release.

See [`../PLAN.md`](../PLAN.md) for architecture, security, signing, rollout, and
long-term upgrade requirements.
