# Peer admission: enterprise client required

Status: implemented in Engineering Fabric and switched off there until
rollout; admission starts read-only. Decision 2026-09-04 (two groups), revised
2026-09-06 (no WireGuard keys, no device enrollment, admission decided by
Engineering Fabric, no management-server fork) and 2026-10-02 (the client sends
only its NetBird IP and serial; no policy revisions; no force-disconnect
notification). The server side is described in `NETBIRD.md` in the Engineering
Fabric repository; the client wire contract is
[`../policy/client-policy.schema.json`](../policy/client-policy.schema.json).

## Decision

Every NetBird user must run the CodeBuckets enterprise client, except users in
the bypass group who may run the official NetBird client. Two NetBird groups
define the population, and NetBird's own default-deny access control enforces
it. Nothing in the management server is patched or replaced.

| Group | Who belongs | Client allowed | Who maintains it |
| --- | --- | --- | --- |
| `netbird-users` | peers of every person who may use NetBird | enterprise client only | Engineering Fabric, one peer at a time, automatically |
| `netbird-bypass` | people explicitly allowed to use the official client, plus machines: exit-node gateways, routing peers, servers, CI runners | official or enterprise client | administrators, in the dashboard or through an Entra group claim; setup keys for machines |

A peer in neither group authenticates and appears in the dashboard, but no
access policy, route, or DNS applies to it, so nothing is reachable.

## How a peer gets into `netbird-users`

The enterprise client polls Engineering Fabric every 15 seconds. Each poll
carries the compiled fleet token, the peer's NetBird IP, and the device serial
number, and nothing else. No WireGuard key is read or sent. Engineering Fabric
derives the user, hostname, OS, and client version from the NetBird management
API peer record for that IP, and then decides:

```text
admitted  = the peer exists in NetBird (looked up by NetBird IP)
        and the enterprise client polled within the last 5 minutes
        and the polled serial equals the serial NetBird recorded for that peer
        and the peer's NetBird user can be resolved
        and the version the client reported to NetBird carries the enterprise stamp (+codebuckets.)
        and no other currently polling peer of the same user reports the same serial
        and Intune reports the device compliant for that user, matched by serial, with the same OS
```

Admitted peers are written to `netbird-users` through the NetBird API. A peer
leaves the group when polling stops for five minutes, when Intune reports it
non-compliant, or when it disappears from NetBird. Unknown is never treated as
non-compliant: if Intune or the NetBird API is unreachable, memberships stay
as they are and an alert fires.

Every peer in the Engineering Fabric device list carries one admission reason:

| Reason | Meaning |
| --- | --- |
| `ADMITTED` | every condition above holds |
| `BYPASS_GROUP` | the peer's access comes from `netbird-bypass` |
| `NOT_POLLING` | no poll from the enterprise client within the last five minutes |
| `USER_UNRESOLVED` | the peer's NetBird user could not be resolved |
| `VERSION_NOT_ENTERPRISE` | the version NetBird recorded lacks the `+codebuckets.` stamp |
| `UNIDENTIFIABLE_SERIAL` | the serial is blank or unusable as a device identifier |
| `DUPLICATE_SERIAL` | another currently polling peer of the same user reports the same serial |
| `INTUNE_NOT_FOUND` | no Intune managed device matches the serial for that user |
| `PLATFORM_MISMATCH` | the Intune device's OS differs from the peer's OS in NetBird |
| `INTUNE_NONCOMPLIANT` | Intune reports the device non-compliant |
| `INTUNE_UNKNOWN_KEPT_PREVIOUS` | Intune was unreachable; the previous membership was kept |

Duplicate serials are judged only among peers of the same user that are
currently polling, so a re-enrolled device recovers on its own once its old
peer stops polling.

The identifiers in the poll are lookup keys, not proof. The decision rests on
two systems the fleet already trusts: the NetBird API for which user owns the
peer and which client version it reported, and Intune for whether the device
is compliant. A forged poll admits nothing unless both agree. Residual risk: a
user who owns a compliant corporate device could clone its serial onto a
personal machine registered under their own account; the version stamp,
per-user duplicate-serial handling, and the OS check push that to a modified
client plus firmware spoofing.

## One-time setup

1. Create the groups `netbird-users` and `netbird-bypass` in the dashboard.
   Nothing else may ever add peers to `netbird-users`: no user auto-group, no
   JWT claim, no setup key.
2. Keep user group propagation enabled (Settings, Groups). It is on by default
   for new accounts.
3. `netbird-bypass` people are managed in the dashboard as auto-assigned groups.
   Do not map an Entra claim to it: NetBird's JWT sync manages only groups it
   created itself, so a dashboard group and a claim would fight.
4. Make sure the Entra application registration NetBird uses emits the `email`
   claim in ID tokens; NetBird's user emails come from it. The client itself
   never sends an email. For a new NetBird account set `AuthUserIDClaim` to `oid`; for
   the existing account leave the claim alone, because changing it re-keys
   every user and orphans their peers, and let Engineering Fabric map users to
   Entra through their email.
5. Remove the default all-to-all policy. Delete the `Default` policy under
   Access Control for the existing account; set `DisableDefaultPolicy` for
   accounts created later.
6. Source every access policy, route distribution group, and nameserver group
   from `netbird-users`, `netbird-bypass`, or narrower groups. Never use `All`.
   Engineering Fabric audits this and alerts.
7. Create machine setup keys with the auto-assigned group `netbird-bypass`,
   one-off or with a usage limit and a short expiry. Treat them as admission
   credentials and never bake them into images.
8. Create a NetBird service user with a personal access token for Engineering
   Fabric, and grant Engineering Fabric's Entra application permission to read
   Intune managed devices. Note the two group IDs; Engineering Fabric is
   configured by group ID because NetBird allows duplicate group names.
9. Run the Engineering Fabric reconciler read-only once, review its device
   list, then enable writes.

## Day-to-day operations

| Task | Action | Effect |
| --- | --- | --- |
| onboard a normal user | install the enterprise client; the user signs in | the peer is admitted within about a minute of the first poll (one reconcile interval plus the Intune lookup), once Intune shows the device compliant |
| allow a person to use the official client | add the user to `netbird-bypass` | every existing and future device of that user is admitted immediately |
| temporary bypass | add to `netbird-bypass`, set a reminder, remove later | both changes are recorded as NetBird activity events |
| end a bypass | remove the user from `netbird-bypass` | the user's official-client peers lose access at once; enterprise-client peers stay admitted through `netbird-users` |
| enroll a gateway or server | register with a `netbird-bypass` setup key | admitted for as long as the membership exists |
| offboard a user | delete the user in NetBird or disable them in Entra | their peers stop being admitted; normal offboarding removes them |
| see why a device has no access | Engineering Fabric device list | shows peer, user, serial, compliance, last poll, and the admission reason |
| a laptop wakes after sleeping longer than five minutes | nothing to do | it was removed while asleep and is readmitted within about a minute of its first poll after waking |

## What the client sends

`POST https://api.engineering-fabric.codebuckets.in/api/v1/netbird/client/policy`
with exactly two fields:

```json
{
  "netbirdIp": "100.64.12.7",
  "serialNumber": "C02EXAMPLE1234"
}
```

- `netbirdIp` comes from the daemon's `Status` RPC (full peer status), which
  reports it as CIDR; the wrapper sends the bare address. Until the peer has
  logged in there is no address, and the wrapper sends no request at all and
  stays on strict defaults. A disconnected daemon also reports no address, so
  the wrapper keeps polling with the last address it saw; otherwise a policy
  that allows disconnecting would expire while disconnected.
- `serialNumber` is the trimmed system serial. It must equal the serial the
  NetBird management server recorded for that peer; otherwise Engineering
  Fabric answers 403. An IP that matches no NetBird peer is also answered 403.
- The client sends no user, hostname, OS, or version. Engineering Fabric reads
  them from the NetBird management API peer record.
- The `Authorization` header carries the fleet token compiled into the build.
  It identifies the build, not the device; rotation is a client release, and
  Engineering Fabric accepts two values during a rollover.

## What the client receives

HTTP 200 with a policy; the full contract is
[`../policy/client-policy.schema.json`](../policy/client-policy.schema.json):

```json
{
  "policyId": "engineering-always-on:v7",
  "validUntil": "2026-10-02T10:05:00Z",
  "controls": {
    "keepConnected": true,
    "disableQuit": true,
    "disableUpdateSettings": true,
    "disableProfiles": true,
    "disableNetworks": true,
    "disableAdvancedView": true,
    "disableAutoConnect": false
  },
  "exitNode": { "mode": "DISABLED", "networkId": "" }
}
```

- `controls` is one flat object of booleans. The client ignores top-level
  fields it does not know and control keys it does not know, whatever their
  type, and applies its strict default to a known control the response omits,
  so the server can add controls without breaking deployed clients.
- There is no schema version and no per-device revision. A newly accepted
  response replaces the previous one. Replay of an old response is bounded by
  its `validUntil`: the server issues five-minute leases and the client refuses
  a lease that has passed or reaches more than 15 minutes ahead. The lease is
  measured against the `Date` header of the response, so a wrong clock on the
  device neither rejects a valid policy nor stretches its lease.
- Any other status carries `{"error":"CODE"}`; the client reads only the status
  code, keeps its last accepted policy until that lease ends, and then enforces
  strict defaults.
- There is no shutdown notification. A peer that stops polling is treated as
  `NOT_POLLING` after five minutes.

## Failure behavior

| Situation | Behavior |
| --- | --- |
| official client on a personal device | registers, gets nothing, visible as not admitted |
| official client installed over the enterprise client on a corporate device | polling stops; removed from `netbird-users` after five minutes; a script that keeps polling still fails the version check |
| device non-compliant in Intune | removed on the next reconcile; readmitted automatically when compliant |
| blank or placeholder serial number | a blank serial cannot poll and stays `NOT_POLLING`; a placeholder such as `To be filled by O.E.M.` is listed as `UNIDENTIFIABLE_SERIAL`; either needs a real serial or a bypass entry |
| same serial on two polling peers of one user | listed as `DUPLICATE_SERIAL`; a re-enrolled device recovers on its own once its old peer stops polling |
| polled serial differs from the serial NetBird recorded, or the IP is unknown | the poll is answered 403; the client stays on strict defaults |
| Intune or Graph unreachable | affected peers keep their membership; alert |
| NetBird API unreachable | the admission run fails and writes nothing; alert |
| Engineering Fabric down | memberships unchanged; clients keep their last valid policy, then strict defaults |
| fleet token leaked | rotate in the next release; the token alone admits nothing |

## Troubleshooting

| Symptom | Check | Fix |
| --- | --- | --- |
| connected but nothing reachable, corporate device | Engineering Fabric device list: last poll and compliance | not polling means the enterprise client is not running; non-compliant means fix the device in Intune |
| connected but nothing reachable, personal device | device list shows no Intune match | expected; add the user to `netbird-bypass` only if that is intended |
| device listed as unidentifiable | serial number blank | give the machine a real serial or use a bypass setup key |
| device listed with a duplicate serial | another polling peer of the same user reports the same serial, usually the old registration of a re-enrolled device | nothing to do once the old peer stops polling; delete the old peer in NetBird to speed it up |
| a whole group of peers lost access at once | policies for `All` usage, Fabric audit alert, group membership | restore the policy sources; Fabric never removes peers when its inputs are unreachable |
| a device is stuck strict after a fresh install | the peer has no NetBird IP yet so the client does not poll, or the poll is answered 403 because the IP is unknown or the serial differs from the one NetBird recorded | sign in first; then compare the device serial with the peer's serial in NetBird |
| gateway or server has no access | its group membership | its setup key lacked `netbird-bypass`, or the membership was removed |

## Optional hardening kept on file

An admission validator injected into an enterprise management binary through
upstream extension points could refuse network maps to peers outside the two
groups regardless of policy configuration. It is not part of phase one: it
duplicates default-deny, adds a Linux build and a linked AGPL binary, and the
`All` audit covers the misconfiguration it would guard against.
