# CodeBuckets NetBird Enterprise Overlay

This repository contains the enterprise overlay for the upstream
[`netbirdio/netbird`](https://github.com/netbirdio/netbird) client. It does not
vendor the upstream source tree.

Every build is reconstructed from four immutable inputs:

1. `upstream.lock.json`, which pins the upstream annotated tag and commit;
2. the one patch listed in `patches/series`; and
3. the enterprise Go sources under `custom/`; and
4. the overlay Git commit containing the scripts and workflows.

The upstream checkout under the parent workspace (`../netbird-original`) is a
developer reference only. CI never trusts or packages it. CI creates a fresh
checkout from the lock and applies the patch.

## Current implementation status

The overlay carries exactly one patch,
`patches/0001-enterprise-enforce-managed-client-policy.patch`. It makes two
deliberately tiny changes to upstream: the daemon composition hook in
`client/cmd/service_controller.go`, and one guard call at the start of the
desktop tray's Quit handler. All policy, enforcement, polling, and UI guard
logic is maintained as ordinary Go source under `custom/client`, outside the
patch.

The machine-readable API contract lives in `policy/client-policy.schema.json`.
A policy response carries a `policyId`, a `validUntil` lease, one flat
`controls` object of booleans (`keepConnected`, `disableQuit`, and five keys
that exactly match native MDM names), and an `exitNode` policy. Exit nodes
support `PINNED`, `DISABLED`, and `USER_CONTROLLED`. The client ignores unknown
fields and unknown control keys and applies the strict default to any known
control a response omits, so the server can add controls without breaking
deployed clients; strict behavior is also used when no valid policy is
available. There is no schema version and no policy revision: a newly accepted
response replaces the previous one, and replay is bounded by `validUntil`.
Qualification compares the control keys in the JSON schema, the Go enforcement
registry, and upstream MDM constants so they cannot drift.

Peer admission is implemented in Engineering Fabric and is switched off there
until rollout. Two NetBird groups define the
population: `netbird-users`, whose peer list Engineering Fabric maintains from
this client's polls and Intune compliance, and `netbird-bypass`, maintained by
administrators for the people and machines that may run the official client.
NetBird default-deny policies sourced from those groups enforce it; no
management-server code changes. The client identifies itself by its NetBird
IP and serial number only, never by WireGuard keys; Engineering Fabric derives
the user, hostname, OS, and client version from the NetBird management API peer
record. See [`docs/peer-admission.md`](docs/peer-admission.md).

The NetBird management plane remains fixed at
`https://api.netbird.internal.codebuckets.in`. The independent enterprise
policy plane is fixed at `https://api.engineering-fabric.codebuckets.in`, using
`POST /api/v1/netbird/client/policy` for polling. The client sends no shutdown
notification; a peer that stops polling loses admission after five minutes.

## Fleet token and version stamp

Two values are set when the daemon is linked, not in source:

- **Version.** `python scripts/overlay.py build-version` prints the version the
  daemon reports, for example `0.80.0+codebuckets.0`: the locked upstream
  version followed by the enterprise revision. CI passes it with
  `-X github.com/netbirdio/netbird/version.version=...`. Engineering Fabric
  admits only peers whose version carries the `+codebuckets.` stamp.
- **Fleet token.** The policy server accepts polls only with the fleet token.
  A production build sets it with
  `-X github.com/netbirdio/netbird/client/enterprise.policyToken=...`. It is
  never committed. Only the release workflow links it, and only when the
  repository secret `NB_ENTERPRISE_POLICY_TOKEN` exists. Releases are served
  from a public download host, so a token linked into them is readable by
  anyone who downloads a build; it identifies the build, not a device.
  Candidates built on a push or pull request never carry it and are answered
  401 by the policy server. A build without a linked token reads the
  `NB_ENTERPRISE_POLICY_TOKEN` environment variable, which is meant for
  development.

Because the stamped version is a release version, keep automatic client
updates disabled in the NetBird management settings; an automatic update would
replace this build with the official client.

## Local materialization

From Windows, macOS, or Linux:

```shell
python scripts/overlay.py materialize --destination build/source
```

The command verifies upstream provenance and the patch manifest, applies the
hook patch, copies the custom source tree, creates one deterministic overlay
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
canonical overlay payload. The patch is restricted to the daemon composition
block and the one tray Quit guard; custom policy code must never be embedded in
it.

## GitHub Actions

- `discover-upstream.yml` discovers a newer stable release and opens a draft
  lock-update PR. It never releases.
- `qualify.yml` reconstructs, verifies, tests, and builds Windows amd64/arm64
  candidates entirely on Windows runners. There is no Linux or macOS job.
- `release.yml` rebuilds the candidates, Authenticode-signs them, uploads them
  to the release bucket, and then switches `latest.json` to the new version.
  It starts from the Actions tab or by pushing the release tag, for example
  `v0.80.0-enterprise.0`. It creates no GitHub release. A signing-only test
  run publishes nothing.

## Releases and forced updates

Releases are served from `https://netbird-client.download.codebuckets.in`:

- `latest.json` names the only version that is allowed to connect, with the
  download URL and SHA-256 of each archive.
- `releases/<tag>/` holds the signed archives of one release and is never
  overwritten.

Publishing a release makes every older build stop working. Engineering Fabric
reads `latest.json` and is the only authority the client listens to:

- Engineering Fabric answers the policy poll of an older build with HTTP 426.
  The answer names the required version and the download link for the
  device's platform. The daemon then disconnects and refuses to connect or log
  in; the error shows the user the version to install and the link. It keeps
  polling, so it notices when the server accepts it again.
- Engineering Fabric also stops admitting an outdated peer to the network, so
  a build that never asks is cut off as well.
- People get the link from Engineering Fabric (`GET /api/v1/netbird/download`,
  any signed-in user). The daemon reads no manifest of its own.

A release must be newer than the published one; `scripts/overlay.py
release-manifest` refuses anything else.

The server side of the contract, including admission and rollout, is described
in `NETBIRD.md` and `docs/NETBIRD_OPERATIONS.md` in the Engineering Fabric
repository.
