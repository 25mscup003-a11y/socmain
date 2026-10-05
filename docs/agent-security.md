# Agent Security control center

`/superadmin/agent-security` separates desired policy from current endpoint evidence.
Only an active superadmin session can change policy or queue security actions.

A policy change creates a **queued** audit record. The next authenticated heartbeat
carries the full policy; a later report must contain all 12 controls and the exact
policy version before the audit becomes **success**. Persistence errors become
**failed**. Older policies overtaken by a newer version become **superseded**.
Reports older than three minutes are **stale**, independently of the ten-minute
connection window shared with the system inventory. Old agents without runtime
evidence show **pending**, never an assumed 100% score.

| Control | Actual behavior |
| --- | --- |
| Self Protection | Master switch for runtime integrity and analysis monitoring. Existing manual lockdown remains until authorized unlock. |
| Tamper Protection | Checks package files, symlinks and writable permissions during integrity scans. Requires Integrity Verification. Does not stop a privileged OS administrator. |
| Anti-Debugging | Detects Python tracing and OS debugger attachment (Linux and Windows). |
| Anti-Reverse Engineering | Detects known analysis-tool processes. Does not prevent extracting Python source. |
| Anti-Dump Protection | Linux disables process dumpability and core dumps. Other POSIX systems disable core dumps only; Windows reports unsupported. |
| Integrity Verification | Verifies package SHA-256 inventory; the backend checks the report against its package baseline. Explicit Verify integrity runs even if periodic checks are disabled. |
| Secure Communication | Required AES-256-GCM API encryption, signed requests and request-bound response authentication. HTTP uses encrypted API polling; plaintext Socket.IO is disabled. |
| Configuration Encryption | Required AES-256-GCM on-disk configuration. Policy persistence errors cannot be acknowledged as success. |
| Certificate Validation | Required chain/hostname verification for HTTPS. HTTP reports not applicable. Certificate pinning and mTLS are reported separately. |
| Code Integrity Monitoring | Periodic package scans on heartbeats, requiring Self Protection and Integrity Verification. |
| Lockdown Mode | Enables automatic evidence-preserving containment on findings. Manual lockdown persists across restarts and guards heartbeat, socket and automatic response commands. |
| Maintenance Mode | Pauses ordinary telemetry delivery and response commands; security heartbeats, recovery and policy changes remain available. Existing firewall rules remain installed. |

Security actions have durable IDs. Update success requires the installed target
version and request ID after restart. Recovery completion is reported by the new
process, and duplicate completed commands are not executed again. Unlock refuses
unresolved findings unless authorized maintenance is active.

The audit table supports endpoint/result filters, ten records per page, endpoint
names and expandable before/after values, agent results and completion times.
Legacy source IPs are left unknown where they were never captured.

Validation covers policy authorization and version matching, all runtime controls,
real Linux anti-dump flags in an isolated subprocess, disk-write failure, lockdown
dispatch paths, recovery acknowledgements, encrypted transport and browser flows.
Desktop runtime report v2 ships in agent 0.1.12. Offline devices need to reconnect
and install the current package before their enforcement can be confirmed.

## Optional source clearing (desktop release 0.1.13)

Self Protection includes **Clear source on external open**, off by default. Normal
Self Protection and existing policies do not arm it. A superadmin must confirm the
destructive action for the selected endpoint, after a fresh runtime report confirms
Linux fanotify support. Resuming a suspended destructive policy also requires this
acknowledgement. Desired state and the endpoint's actual state remain separate.

On a supported Linux host with `CAP_SYS_ADMIN`, the agent uses `FAN_OPEN_PERM` to
identify the opening process before deciding the request. Agent-process reads are
allowed. An external process opening a manifested `.py` source file causes that
exact inode to be truncated to zero length and the triggering open to be denied.
Symlinks, hardlinks, writable/unowned paths, changed inodes and unidentified readers
are never destructive targets. Configuration, logs, dependencies and files outside
the package manifest are not targeted. Errors are reported; there is no inotify or
process-name fallback and no claim of secure disk erasure.

**Any external reader can trigger this**, including an editor, antivirus, backup,
or a second local invocation of `agent.py`. The agent can break and require a fresh
installation. Use Maintenance Mode and wait for the agent's suspended-state report
before inspection, backup or local diagnostics. Authorized OTA updates suspend the
listener before invoking the installer; a new process revalidates the new manifest.
If launching the installer fails, rearming validates the original inventory again.
An installer that never completes can leave protection suspended, visibly reported.

Clearing is reported as `source_cleared_on_open` in the existing security findings,
tamper audit and optional automatic lockdown. The integrity mismatch persists on
disk even if the process exits before delivering its next heartbeat. There is no
guarantee that a broken or disconnected agent can deliver its final event.

This does not cover Windows/macOS, preexisting file descriptors or mappings,
compiled bytecode, copies, snapshots, offline disk access, or privileged OS
administrators. Fatal listener failures release pending kernel requests and report
an error; they do not guarantee ongoing access denial. Unit tests exercise actual
truncation only on temporary fixtures. The separate real-kernel integration test
requires `CAP_SYS_ADMIN` and is skipped when that capability is unavailable.
