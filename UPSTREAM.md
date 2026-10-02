# Upstream qualification record

## Current lock

- Repository: `netbirdio/netbird`
- Stable release: `v0.78.0`
- Annotated tag object: `e3d9198023f9a6106ddd2c28c773b9f6bc7f3f6b`
- Peeled commit: `7c1253004b1c1f95d343c0db8a9971680e0687f4`
- GitHub commit verification: verified (`valid`)
- Published: 2026-09-03 19:25:58 UTC
- Locked: 2026-09-06 (previous lock `v0.77.1` at `79a06720b684768b421f0a54f3bb14f22704994f`, locked 2026-08-22)

The tag and commit were resolved from the official GitHub release and the exact
`https://github.com/netbirdio/netbird.git` remote. The annotated release tag is
not assumed to be signed; the full tag object and peeled commit are both pinned.

## Upgrade review template

For every proposed lock change, record:

- upstream release notes and security fixes reviewed;
- daemon RPC and service-construction changes;
- profile/config/MDM precedence changes;
- tray/Wails and session/logout changes;
- Windows/macOS build, packaging, signing, and updater changes;
- serial collection and management metadata changes;
- patch application result and `git range-diff`;
- Windows/macOS qualification results;
- approved exceptions, owners, and rollback version.

## Upgrade record: v0.77.1 to v0.78.0 (reviewed and locked 2026-09-06)

The local reference clone was moved to `main` at `76ea722` (`v0.78.0-11`). The
stable release locked is `v0.78.0`; commits after it on `main` are not
release candidates. Qualification on the Windows CI runners is still required;
the local review had no Go toolchain and validated only materialization, patch
application, and the policy contract.

- Annotated tag object: `e3d9198023f9a6106ddd2c28c773b9f6bc7f3f6b`
- Peeled commit: `7c1253004b1c1f95d343c0db8a9971680e0687f4`
- GitHub commit verification: verified (`valid`)
- Published: 2026-09-03 19:25:58 UTC; not a draft, not a prerelease
- Commits since `v0.77.1`: 59

### Patch application

Both patches apply cleanly with `git apply --check` against `v0.78.0`.
`client/cmd/service_controller.go` changed only two log messages;
`client/ui/tray.go` gained window-management helpers and did not touch
`handleQuit`.

### Daemon RPC surface

No new RPCs. `LoginRequest`, `SetConfigRequest`, and `GetConfigResponse` gain
`enable_local_metrics`, `local_metrics_address`, and `remoteJobsAllowed`. The
wrapper's `SetConfig` denial under `disableUpdateSettings` covers them; the RPC
classification test needs no change.

### Native MDM keys: 19 to 23

`client/mdm/policy.go` adds `enableLocalMetrics`, `localMetricsAddress`,
`allowRemoteJobs`, and `debugBundleUploadURL` (listed in `SecretKeys`).
`scripts/overlay.py verify_policy_contract` compares the schema catalog with the
locked source, so the lock bump and these four catalog entries in
`policy/client-policy.schema.json` must land in the same change, with
`api_mapping: null` and notes that local metrics and remote jobs stay disabled
and that the upload URL is a secret never returned by the policy API.

### Behavior changes to review with the bump

- #7360 allows logging out of the active profile when profiles are disabled;
  the wrapper denies `Logout` regardless, and the bypass test covers it.
- #7378 binds the cached SSH JWT to the local caller; `WaitSSOLogin` now takes
  a caller context, which the planned override passes through unchanged.
- #7384 changes `netbird login` to stay connected.
- #7238 resolves profiles for the sudo invoking user on Linux; no Windows effect.
- #6689 adds a local Prometheus metrics endpoint on the client, off by default;
  the enterprise build keeps it off.
- #6322 unifies peer and route ACL filtering inside the engine; no wrapper
  contact.

### Identity paths used by the admission design

All hold at `v0.78.0`: `WaitSSOLogin` returns the account email and the CLI and
UI persist it to the profile state file; `LocalPeerState.IP` is still the
WireGuard interface address in CIDR form; `GET /api/peers?ip=` is still a
substring filter; `Peer` still exposes `user_id` and `serial_number`; group
`PUT` still takes a peer list; `ConfigInput.ManagementURL`,
`ConfigInput.DisableAutoConnect`, `UpdateOrCreateConfig`, and the
`ServiceManager` methods the wrapper calls are unchanged; `AuthUserIDClaim`,
`GroupsPropagationEnabled`, and the JWT email extractor are unchanged.

### Toolchain

`go.mod` requires `go 1.26.0` with `toolchain go1.26.7` (was 1.25.5 / 1.25.12).
`qualify.yml` reads the version from the materialized `go.mod`, so CI adapts;
a local Go install must be 1.26. pnpm stays `11.4.0`; Wails v3 beta.3 via the
`netbirdio/wails` replace, installed from the module graph as before.

### Change set

`upstream.lock.json` (tag object, commit, release date, verification), this file,
the four catalog entries in `policy/client-policy.schema.json`, the provenance
block in `policy/peer-admission.schema.json` (both since removed, see below),
and the version mentions in the plans and README. `qualify.yml` must pass on
Windows runners before this lock is used for a release.

## Policy contract change (2026-10-02, still on v0.78.0)

The client policy contract was replaced by a smaller one; nothing in the lock
changed. This supersedes the contract details in the upgrade record above.

- The client posts only `netbirdIp` and `serialNumber` to
  `POST /api/v1/netbird/client/policy`. Schema versions, policy revisions, the
  `/force-disconnect` notification, and the user email, hostname, OS, version,
  and exit-node state fields are gone; Engineering Fabric reads user, hostname,
  OS, and client version from the NetBird management API peer record.
- Of the identity paths listed above, the client now relies only on
  `LocalPeerState.IP`, which the daemon returns from `Status` only when
  `GetFullPeerStatus` is set, and on the system serial. It no longer reads the
  SSO email from the profile state file or the WireGuard key.
- `policy/client-policy.schema.json` no longer carries the native MDM
  capability catalog, and `policy/peer-admission.schema.json` was deleted.
  `scripts/overlay.py verify_policy_contract` now checks that the control keys
  in the schema equal the Go registry plus `keepConnected` and `disableQuit`,
  and that every `mdm.Key*` constant in the registry exists in the locked
  source. It no longer fails when upstream adds an MDM key, so review
  `client/mdm/policy.go` by hand under "profile/config/MDM precedence changes"
  in every upgrade.
