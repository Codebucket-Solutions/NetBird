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

The only upstream touchpoint is a small patch to
`client/cmd/service_controller.go`: one import and one `enterprise.Wrap(...)`
composition hook. Enterprise policy logic is maintained as ordinary Go source
under `custom/client/enterprise`, outside the patch. Production publication
remains disabled in `overlay.config.json` until every platform signing gate is
ready.

The machine-readable API contract and complete v0.77.1 native MDM capability
inventory live in `policy/client-policy.schema.json`. Policy schema v3 uses a
sparse `netBirdControls` object whose keys exactly match native MDM names, plus
connection-state and exit-node policy. Exit nodes
support `PINNED`, `DISABLED`, and `USER_CONTROLLED`; strict behavior is used when
no valid policy is available. Qualification compares the JSON key allow-list,
the Go enforcement registry, and upstream MDM constants so they cannot drift.

## Local materialization

From Windows, macOS, or Linux:

```shell
python scripts/overlay.py materialize --destination build/source
```

The command verifies upstream provenance and the patch manifest, applies the
tiny hook patch, copies the custom source tree, creates one deterministic overlay
commit, and runs the invariants. It refuses to reuse an existing destination.

## Patch development

Normally, edit `custom/client/enterprise` directly. If developing against a
materialized checkout, export both the custom source tree and regenerated hook
patch to a new directory:

```shell
python scripts/overlay.py export \
  --source build/development-source \
  --output build/exported-overlay
```

The export contains `custom/` and `patches/`. Review both before replacing the
canonical overlay payload. The hook patch must remain limited to
`client/cmd/service_controller.go`; custom policy code must never be embedded
inside it.

## GitHub Actions

- `discover-upstream.yml` discovers a newer stable release and opens a draft
  lock-update PR. It never releases.
- `qualify.yml` reconstructs, verifies, tests, and builds Windows and macOS
  candidates from the locked source. Its Ubuntu job is orchestration and Go
  testing only; it does not produce a Linux client.
- `release.yml` supports a signing-only CI test that cannot publish a release.
  Normal release dispatches Authenticode-sign Windows candidates and keep the
  release as a draft until macOS Developer ID signing and notarization finish.

See [`../PLAN.md`](../PLAN.md) for architecture, security, signing, rollout, and
long-term upgrade requirements.
