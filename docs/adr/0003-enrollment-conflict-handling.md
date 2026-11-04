# ADR-0003: Enrollment Certificate Conflict Handling and Security Guidance

> We enforce atomic local key verification before declaring enrollment success, detect upstream certificate conflicts, and guide users to contact the Security Team when an active certificate already exists.

## Metadata

| Field             | Value                                                          |
| :---------------- | :------------------------------------------------------------- |
| **Document ID**   | ADR-0003                                                       |
| **Status**        | `Proposed`                                                     |
| **Date**          | 2026-11-04                                                     |
| **Deciders**      | Wazuh maintainers                                              |
| **Governs**       | `src/main.ts`, `src-tauri/src/lib.rs`, `index.html`             |
| **Amends**        | N/A                                                            |
| **Amended by**    | N/A                                                            |
| **Supersedes**    | N/A                                                            |
| **Superseded by** | N/A                                                            |

## Context

The Wazuh Agent Installer is a cross-platform desktop application built with Tauri (Rust backend) and TypeScript (frontend). During the onboarding process, the application triggers endpoint enrollment by launching the `wazuh-cert-oauth2-client` binary as a child process.

When an employee who previously enrolled an endpoint attempts to enroll on a new or replaced machine (where no `/Library/Ossec/etc/client.keys` or equivalent platform path exists locally), the upstream certificate authority rejects the CSR with an HTTP 409 Conflict:
```
[ERROR wazuh_cert_oauth2_client] An error occurred during execution: Upstream error: Conflict: User already has an active certificate. Use the --overwrite flag to re-enroll and replace it.
```

Previously, the desktop installer suffered from two critical shortcomings during this flow:
1. **Contradictory UI State**: The child process exited without signaling an error code to the caller. The installer backend captured exit code 0 and reported success, prompting the frontend to optimistically display a green banner (`✓ ✓ Agent enrolled successfully!`). Shortly after, background polling checked for local keys, discovered none, and flipped the sidebar badge to a red failure icon (`✗`), severely confusing users.
2. **Missing Security Guidance and Deadlock**: Because the installer determined whether to show the "Re-enroll / Overwrite" button solely by checking if `client.keys` existed on the local disk, a fresh machine without local keys offered no overwrite option. Users were left in an unrecoverable loop with no guidance on what had happened or what action to take.

Organizational security policy dictates that an active certificate conflict is an expected security boundary: an existing certificate should not be blindly replaced without user awareness, and employees replacing machines should contact the Security Team to retrieve their existing keys or authorize a re-enrollment.

The deciding forces are:
- The user interface must never present a success state unless `client.keys` has been verified on the endpoint filesystem.
- When an upstream certificate conflict occurs, the installer must clearly explain the condition and direct the user to the Security Team.
- The solution must operate seamlessly across Linux, macOS, and Windows endpoints.

## Decision

We will implement post-execution key verification and upstream conflict intercept handling inside `wazuh-agent-installer`:

1. **Conflict Intercept and Asynchronous Key Delivery**:
   During enrollment, `wazuh-cert-oauth2-client` negotiates certificates (`sslagent.cert` and `sslagent.key`) with the CA and restarts the local agent. The agent then connects to the Wazuh manager using mutual TLS, and the manager delivers `client.keys` to the endpoint. If the upstream CA rejects enrollment due to an active certificate conflict, the installer log listener intercepts the conflict signature (`hasCertConflict = true`) and prevents success banners from displaying. Following a clean process exit without conflicts, the installer polls asynchronously for `client.keys` to be populated by the manager.

2. **Conflict Signature Detection**:
   The installer log reader (`enroll-log` listener) will inspect log lines for the upstream conflict signature: `Conflict: User already has an active certificate`. When detected, a dedicated state flag is activated.

3. **Security Guidance and User-Confirmed Overwrite Option**:
   When a certificate conflict is identified:
   - Suppress generic exit-code failure messages.
   - Display a prominent, styled notification banner and conflict card informing the user:
     - **Contact Security Team (Recommended)**: Request existing client keys so the previous certificate remains valid.
     - **Overwrite and Replace**: Re-enroll with overwrite enabled to generate new keys for this machine, with an explicit warning that the previous certificate will be invalidated.
   - Provide an explicit `⚠️ Overwrite and Re-enroll` action button so authorized users can re-enroll directly without terminal commands.

4. **Banner Typography Fix**:
   Remove the redundant hardcoded `"✓ "` from the message text in `src/main.ts` so `showStatusBanner()` renders a single checkmark cleanly.

## Options considered

| Option                                                                 | Verdict  | Why (one line)                                                                                       |
| :--------------------------------------------------------------------- | :------- | :--------------------------------------------------------------------------------------------------- |
| Rely solely on process exit code (status quo)                          | Rejected | Upstream CLI bugs or silent zero exits result in false-positive success banners.                     |
| Automatically pass `--overwrite` on conflict                           | Rejected | Violates security policy by silently invalidating active certificates without human authorization.    |
| Atomic key verification + Security guidance + explicit overwrite action| Adopted  | Prevents false success states, upholds security policies, and empowers users to re-enroll securely.   |

## Consequences

**Not part of this decision:** Modifying the exit code in `wazuh-cert-oauth2-client` is tracked separately under issue #386 in that repository; this decision ensures the desktop installer handles failures reliably regardless of CLI exit code behavior.

### Impact

**Benefits**

- Eliminates contradictory UI states where errors and success banners appear simultaneously.
- Gives non-technical users clear, empathetic guidance when a machine swap occurs.
- Guarantees that the green success indicator strictly correlates with real, working keys on disk.
- Operates reliably across Linux, macOS, and Windows.

**Costs**

- Adds log-string inspection logic and state-checking in the enrollment UI pipeline.

**Risks**

- If the upstream error string changes significantly, string-based conflict detection could fail to match (mitigated: the fallback will cleanly report enrollment failure due to missing keys, preventing any false success state).

### Accepted limits

- Users without access to their old keys must wait for Security Team intervention to complete enrollment.

### Done when

- [ ] `startEnrollment` confirms valid `client.keys` presence before rendering success.
- [ ] Log stream intercepts `Conflict: User already has an active certificate` and flags conflict state.
- [ ] UI displays explicit notice directing users to contact the Security Team.
- [ ] Double checkmark (`✓ ✓`) formatting glitch is eliminated.
- [ ] Build and unit tests pass across all platforms.

### Revisit when

- The server introduces self-service multi-device key management or automated device migration in the OAuth2 flow.

## Rollback

To roll back this decision, revert the log inspection and verification guards in `src/main.ts` and `src-tauri/src/lib.rs`.

## Evidence

| Claim                                                                 | Where                                                          |
| :-------------------------------------------------------------------- | :------------------------------------------------------------- |
| Upstream conflict error emitted by cert client                        | Terminal output in `wazuh-agent-installer` issue #50           |
| Missing `std::process::exit(1)` in cert client                        | `crates/wazuh-cert-oauth2-client/src/main.rs` (issue #386)    |
| Key verification and conflict notice implementation                   | `src/main.ts` and `src-tauri/src/lib.rs` in this repo          |

## References

- [ADR template](https://github.com/ADORSYS-GIS/wazuh/blob/main/docs/adr/template.md)
- [ADR writing guide](https://github.com/ADORSYS-GIS/wazuh/blob/main/docs/adr/GUIDE.md)
- [wazuh-cert-oauth2 Issue #386](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/issues/386)

## Solution implementation

| Kind   | Tracking                                                                                                        | Status   | What it covers                                                          |
| :----- | :-------------------------------------------------------------------------------------------------------------- | :------- | :---------------------------------------------------------------------- |
| Issue  | [ADORSYS-GIS/wazuh-agent-installer#50](https://github.com/ADORSYS-GIS/wazuh-agent-installer/issues/50)          | Open     | Handle active certificate conflict and guide user to security team     |
