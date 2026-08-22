# CodeBuckets NetBird Enterprise Overlay

This repository contains the enterprise overlay for the upstream
[`netbirdio/netbird`](https://github.com/netbirdio/netbird) client. It does not
vendor the upstream source tree.

Every build is reconstructed from three immutable inputs:

1. `upstream.lock.json`, which pins the upstream annotated tag and commit;
2. the ordered patches listed in `patches/series`; and
3. the overlay Git commit containing the scripts and workflows.

The upstream checkout under the parent workspace (`../netbird-original`) is a
developer reference only. CI never trusts or packages it. CI creates a fresh
checkout from the lock and applies the patch series.

## Current implementation status

The enterprise wrapper is maintained as one patch that changes one upstream
composition file, `client/cmd/service_controller.go`. All policy logic lives in
new `client/enterprise` files. Production release remains deliberately disabled
in `overlay.config.json` until Windows and Apple signing identities exist. This
prevents accidentally distributing unsigned enterprise clients.

## Local materialization

From Windows, macOS, or Linux:

```shell
python scripts/overlay.py materialize --destination build/source
```

The command verifies upstream provenance and the patch manifest, applies every
patch with `git am --3way`, and runs the overlay invariant checks. It refuses to
reuse an existing destination.

## Patch development

Develop enterprise changes as linear commits on a temporary checkout based on
the commit in `upstream.lock.json`, then export them to a new directory:

```shell
python scripts/overlay.py export \
  --source build/development-source \
  --output build/exported-patches
```

Review the generated patches, `series`, and `manifest.sha256` before replacing
the canonical `patches/` directory through a pull request. Do not hand-edit the
derived source and canonical patches independently.

## GitHub Actions

- `discover-upstream.yml` discovers a newer stable release and opens a draft
  lock-update PR. It never releases.
- `qualify.yml` reconstructs, verifies, tests, and builds Windows and macOS
  candidates from the locked source. Its Ubuntu job is orchestration and Go
  testing only; it does not produce a Linux client.
- `release.yml` creates a draft release candidate only after the enterprise
  hook and release gate are enabled. Production signing remains a protected
  follow-up stage and must not be bypassed.

See [`../PLAN.md`](../PLAN.md) for architecture, security, signing, rollout, and
long-term upgrade requirements.
