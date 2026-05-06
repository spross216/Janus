```
   ╔════════════════════════════════════════════════╗
   ║                                                ║
   ║   IT  ←══════ ••  J A N U S  •• ══════→  OT    ║
   ║                                                ║
   ║             Zero Trust OT Gateway              ║
   ║                                                ║
   ╚════════════════════════════════════════════════╝
```

# Janus — Zero Trust OT Gateway

Identity-based admission control for accessing Operational Technology (OT) devices —
CNC machines, welding robots, SCADA HMIs — from the IT side of a manufacturing network.

The gateway answers exactly one question, every time someone wants to talk to an OT
device:

> *Is this user, on this device, allowed to reach that machine right now?*

A request is admitted only if **all three** gates pass:

1. The OT device is in the registry the gateway knows about.
2. The requesting user is a member of the Entra ID group required for that specific device.
3. The user has at least one Intune-managed device that is currently reporting `compliant`.

If all three pass, the gateway issues an 8-hour session ID and (in production) opens a
tunnel to the OT device's IP. If any gate fails, access is denied. **Every decision —
admit or deny — is written to an append-only audit log.**

---

## Who this is for

This PoC is aimed at **smaller machine shops** that need to bring legacy operational
infrastructure into a Zero Trust posture in order to meet **CMMC 2.0** requirements
without ripping out the OT equipment they already own.

The compliance story this design supports:

- **MFA without retrofitting OT.** Authentication happens at the gateway against the
  user's Entra-joined thin client. With **TPM-backed Windows Hello for Business**, the
  thin client itself satisfies the multi-factor requirement (something-you-have: the TPM;
  something-you-are: the biometric or PIN tied to it). The CNC, welding robot, or HMI
  never has to know what MFA is.
- **Continuous device-health enforcement.** Intune compliance state is checked on every
  admission decision, not at enrollment time. A machine that falls out of compliance
  loses access on its next session.
- **Identity-bound, time-bound sessions.** Every session has a UPN, a session ID, and an
  8-hour expiry. There is no shared service account into the OT subnet.
- **Audit-friendly by construction.** Every admit and every deny appends one JSON Lines
  entry to an immutable log: timestamp, decision, UPN, device, reason. That log is the
  evidence artifact assessors are looking for.

The point is not to replace the existing network segmentation; it is to put a Zero Trust
identity boundary in front of it so that the legacy gear behind the firewall can stay
exactly where it is.

---

## Architecture

![Zero Trust OT Gateway — Architecture and Admission](architecture.png)

### How a request flows

1. **The user scans a QR code** on the OT device with their thin client. The QR encodes
   the device ID; the client already knows the user's UPN.
2. **The thin client calls the gateway** with `(upn, deviceId)`.
3. **Gate 1 — device lookup.** The gateway looks `deviceId` up in its local registry.
   If the device is not in the registry, the gateway denies with `Device not in registry`,
   writes an audit entry, and returns. *No Graph calls are made for unknown devices.*
4. **Gate 2 — group membership.** The gateway calls `Get-MgUserMemberOf` against Entra
   ID and checks whether the user is a member of the `requiredGroup` for that specific
   device (e.g. `OT-CNC-Operators` for a CNC machine, `OT-SCADA-Admins` for a SCADA HMI).
   If not, deny with `Not a member of <group>`.
5. **Gate 3 — device compliance.** The gateway calls
   `Get-MgDeviceManagementManagedDevice` filtered by UPN and verifies that **at least
   one** of the user's managed devices is reporting `compliant`. If none are compliant,
   deny with `No compliant Intune-managed device found for user`.
6. **Admit.** The gateway mints a session ID (GUID), records an expiry 8 hours out, writes
   the audit entry, and (in production) opens a tunnel from the IT subnet to the OT
   device's IP through the firewall. The thin client gets back the session ID and expiry;
   the user operates the OT device until the session expires.

Every path through the function — including all three deny branches — writes exactly one
audit entry before returning. There is no way to reach the tunnel-open step without an
admit entry already on disk.

---

## Why this PoC exists

OT networks have historically been protected by air gaps and network segmentation alone.
That model is breaking down: vendors need remote support, technicians use mobile thin
clients, and IT/OT convergence means IT-side identity now matters on the plant floor —
and CMMC 2.0 expects controls that segmentation alone cannot demonstrate.

A Zero Trust gateway flips the question from *"is this packet on the right VLAN?"* to
*"who is this human, what device are they on, and is that device healthy?"* — and it does
that check on **every** session, against the live state in Entra ID and Intune, not against
a static ACL.

This PowerShell PoC exists to:

- **Prove the admission logic** end to end against real Microsoft Graph endpoints
  (`Get-MgUserMemberOf`, `Get-MgDeviceManagementManagedDevice`) before committing to a
  production implementation language.
- **Pin down the data contracts** — the device registry shape, the admit/deny result
  shape, the audit entry shape — so a port to another language is a translation, not a
  redesign.
- **Demonstrate the functional-core / imperative-shell split** that the production
  version should preserve: pure decision logic that is trivially testable, surrounded by
  a thin shell that does the I/O.
- Give stakeholders something runnable to poke at while the production language and
  deployment story are still being decided.

The PoC is **not** a production gateway. It does not actually open a network tunnel — the
admit path stops at issuing a session ID and writing the audit entry. The transport layer
(TCP proxy, WireGuard, SSH forward, etc.) is the obvious next thing a software engineer
extending this would wire up; the comment in `Request-OtAccess.ps1` marks the exact spot.

---

## Repository contents

| File | Purpose |
|---|---|
| `Request-OtAccess.ps1`       | The admission engine. Functional core (`Find-OtDevice`, `Test-GroupMembership`, `Test-IntuneCompliance`, `New-AdmitResult`, `New-DenyResult`, `New-AuditEntry`) plus the imperative shell (`Get-DeviceRegistry`, `Write-AuditLog`, `New-GraphClient`, `Request-OtAccess`). |
| `Request-OtAccess.Tests.ps1` | Pester tests covering every pure function in the core. No Graph calls, no I/O. |
| `devices.json`               | The device registry: deviceId, displayName, requiredGroup, location, protocol, ipAddress. |
| `audit.log` *(generated)*    | Append-only JSON Lines audit log. One line per admission decision. |

### Running the PoC

```powershell
.\Request-OtAccess.ps1 -DeviceId 'ot-cnc-01' -Upn 'jsmith@contoso.com'
```

This will prompt you to sign in to Microsoft Graph (scopes: `User.Read.All`,
`GroupMember.Read.All`, `DeviceManagementManagedDevices.Read.All`), run the three gates,
print the result, and append a line to `audit.log`.

### Running the tests

```powershell
Invoke-Pester .\Request-OtAccess.Tests.ps1
```

Tests are pure-function only — they run offline and require no Graph tenant.

---

## Production target language

PowerShell got us here because it has the most ergonomic Microsoft Graph SDK and lets us
stand up the whole admission flow in a single file. It is the wrong language to actually
**deploy** as a long-running gateway service: it has no first-class HTTP server story,
weak concurrency primitives, and a startup cost that hurts on every cold path.

The candidates below are roughly ordered by how strong a fit they are for this specific
workload — a stateful, long-running, identity-aware network gateway that lives on a Linux
host (likely in a container) and talks to Microsoft Graph constantly.

### .NET languages (preferred)

#### C# — primary candidate
- **Microsoft Graph SDK is first-class.** `Microsoft.Graph` and `Microsoft.Graph.Beta`
  are authored by the same team that owns the API; new endpoints land here first. Auth
  via `Azure.Identity` integrates cleanly with managed identity, workload identity, and
  certificate-based service principals — the auth modes a real deployment will need.
- **ASP.NET Core / Kestrel / YARP** give us a credible HTTP front end and a battle-tested
  reverse-proxy substrate for the actual tunnel-opening step the PoC stubs out. YARP in
  particular was built for exactly this shape of problem.
- **Mature observability story.** OpenTelemetry, structured logging via `ILogger`, and
  health-check middleware are baseline; the audit log can become a structured sink
  without extra ceremony — and structured logs are exactly what a CMMC assessor will ask
  to see.
- **Runs natively on Linux containers**, AOT-compiles for faster startup, and has the
  largest pool of engineers inside most Microsoft-shop organizations who can maintain it.
- **Trade-off:** the functional-core split we have in the PoC has to be enforced by
  discipline; C# does not push you toward immutability the way F# does.

#### F# — strong fit for the core, especially if we keep the split
- **The functional-core / imperative-shell architecture is F#'s native idiom.** The pure
  decision functions (`Find-OtDevice`, `Test-GroupMembership`, `Test-IntuneCompliance`,
  result/audit constructors) translate almost line-for-line into F# with discriminated
  unions for `Decision = Admit of Session | Deny of Reason` and records for the rest.
  That makes illegal states unrepresentable in a way C# cannot match without a lot of
  boilerplate.
- **Same SDK access as C#.** F# consumes `Microsoft.Graph` and `Azure.Identity` directly;
  no second ecosystem to maintain.
- **Pragmatic option:** F# core (decision logic + types) + C# shell (ASP.NET host,
  middleware, hosting) in a single solution. We get the type safety where it matters and
  the broader ecosystem where it doesn't.
- **Trade-off:** smaller hiring pool. If the team maintaining this won't have an F#
  speaker on it long-term, that is a real operational risk.

### Non-.NET candidates (lower priority, listed for completeness)

#### Go
- Static single binary, tiny container image, predictable runtime — attractive for a
  gateway. Strong concurrency primitives.
- The Microsoft Graph SDK for Go (`microsoftgraph/msgraph-sdk-go`) exists and is
  supported, but it lags the .NET SDK on new endpoints and the ergonomics are noticeably
  heavier (Kiota-generated builders, more ceremony per call).
- No discriminated unions, weaker type system for modeling the admit/deny decision
  cleanly.

#### Rust
- Best-in-class for a security-critical, long-running network service: memory safety,
  great async story, predictable performance.
- **Graph ecosystem is sparse.** No first-party SDK; community crates exist but are
  partial and not Microsoft-supported. We would be hand-rolling a non-trivial portion of
  the auth and Graph-call surface, which is exactly the part of the system we want to be
  boring.
- Reasonable choice if Graph access is wrapped in a thin C# sidecar and Rust handles only
  the tunnel transport, but that is two services to operate instead of one.

### Recommendation

Port the PoC to **C# on ASP.NET Core**, with the admission core in **F#** if we have at
least one engineer who will own that code path long-term. Keep the functional-core /
imperative-shell split that the PowerShell version already has — it is the single most
important piece of design to carry forward, because it is what makes the admission logic
testable without a Graph tenant and what makes the audit trail trivial to reason about
during an assessment.

---

## Contributing

This PoC is intended as a starting point for collaborators to build out a
production gateway. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for what kinds of
contributions are wanted and how the inbound license grant works.

## License

Licensed under the [Apache License 2.0](LICENSE). The Apache 2.0 patent grant
is intentional: it ensures that anyone who contributes code also grants users a
patent license covering that contribution, which closes the door on
"submarine patent" claims from past contributors.
