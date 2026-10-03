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
`patches/0001-enterprise-enforce-managed-client-policy.patch`. It makes three
deliberately small changes to upstream: the daemon composition hook in
`client/cmd/service_controller.go`, one guard call at the start of the
desktop tray's Quit handler, and a fix in `client/ui/services/theme.go` so a
theme change tints only windows whose webview has loaded (upstream v0.80.0
tints a window still being created, which dereferences the missing WebView2
controller and exits the UI; this is a startup race on Windows). All policy,
enforcement, polling, and UI guard logic is maintained as ordinary Go source
under `custom/client`, outside the patch.

The wire contract is owned by Engineering Fabric (`docs/API_REFERENCE.md` and
`NETBIRD.md` there); the client side of it is `custom/client/enterprise`.
A policy response carries a `policyId`, a `validUntil` lease, one flat
`controls` object of booleans (`keepConnected`, `disableQuit`, and five keys
that exactly match native MDM names), and an `exitNode` policy. Exit nodes
support `PINNED`, `DISABLED`, and `USER_CONTROLLED`. The client ignores unknown
fields and unknown control keys and applies the strict default to any known
control a response omits, so the server can add controls without breaking
deployed clients; strict behavior is also used when no valid policy is
available. There is no schema version and no policy revision: a newly accepted
response replaces the previous one, and replay is bounded by `validUntil`.
Qualification checks the Go enforcement registry against the upstream MDM
constants, so an upstream rename cannot go unnoticed.

Peer admission is implemented in Engineering Fabric and is switched off there
until rollout. Engineering Fabric keeps NetBird groups equal to Entra groups,
and a group marked admitted-only holds only devices that pass admission: this
client polling, an enterprise build, and Intune compliance. NetBird
default-deny policies built on those groups enforce it; no management-server
code changes. The client identifies itself by its NetBird
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
  candidates entirely on Windows runners, then throws them away. There is no
  Linux or macOS job.
- `release.yml` builds each architecture again with the fleet token,
  Authenticode-signs the executables, packages them with upstream's
  `client/installer.nsis` and `client/netbird.wxs`, signs the installers and
  uploads them to the release bucket, all inside one job, and then switches
  `latest.json` to the new version. It starts from the
  Actions tab or by pushing the release tag, for example
  `v0.80.0-enterprise.0`. It creates no GitHub release. A signing-only test
  run uploads nothing.

Both use `.github/actions/build-windows`. No workflow stores a build as an
Actions artifact: the repository is public, and the bucket is the only place a
release exists.

## Releases and forced updates

Releases are served from `https://netbird-client.download.codebuckets.in`:

- `latest.json` names the only version that is allowed to connect, with the
  download URL and SHA-256 of each installer: `netbird-enterprise-windows-<arch>.exe`
  (upstream's NSIS installer, listed under the platform `windows-<arch>`) and
  `netbird-enterprise-windows-<arch>.msi` (for Intune or other managed
  deployment, listed as `windows-<arch>-msi`). Both carry the signed
  `netbird.exe`, `netbird-ui.exe` and `wintun.dll`, install the service, and
  replace an official client in place: same install directory, service name,
  and MSI upgrade code.
- `releases/<tag>/` holds the signed installers of one release and is never
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
release-preflight` refuses anything else before building, and
`release-manifest` checks again against the bucket before switching
`latest.json`. The manifest is built from the installers read back from the
bucket, each checked against the SHA-256 written when it was signed.

The server side of the contract, including admission and rollout, is described
in `NETBIRD.md` and `docs/NETBIRD_OPERATIONS.md` in the Engineering Fabric
repository.
