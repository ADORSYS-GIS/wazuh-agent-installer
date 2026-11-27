# ADR-0004: Compatible Bash Selection for macOS Installation

> We will bootstrap macOS installations with `/bin/bash` and prioritize system Bash in the child `PATH` so Apple Silicon does not select an incompatible Intel-only Homebrew Bash.

## Metadata

| Field | Value |
| :--- | :--- |
| **Document ID** | ADR-0004 |
| **Status** | `Proposed` |
| **Date** | 2026-11-27 |
| **Deciders** | Wazuh maintainers |
| **Governs** | `src-tauri/src/lib.rs` |
| **Amends** | N/A |
| **Amended by** | N/A |
| **Supersedes** | N/A |
| **Superseded by** | N/A |

## Context

The Wazuh Agent Installer launches a shell to run the macOS installation script. On Apple Silicon, an Intel-only Bash at `/usr/local/bin/bash` can be selected when ARM Homebrew Bash at `/opt/homebrew/bin/bash` is absent. The process then fails with `Bad CPU type in executable` before the setup script runs.

Changing only the initial shell selection would not address nested script invocations of `bash`, which resolve through the child process's `PATH`. The installer must start with a known-compatible shell, preserve access to ARM Homebrew tools, and ensure nested invocations prefer macOS system Bash over an incompatible `/usr/local/bin/bash`. Linux and Windows behavior must remain unchanged. These compatibility requirements and the need to cover nested invocations decide the approach.

## Decision

We will use the absolute `/bin/bash` path to start macOS installations. For the macOS child process, we will construct `PATH` in this order: `/opt/homebrew/bin`, `/usr/bin`, `/bin`, `/usr/sbin`, `/sbin`, `/usr/local/bin`, then the remaining non-empty entries from the existing `PATH`, preserving their order and removing duplicates. This keeps ARM Homebrew tools available while causing nested `bash` commands to resolve to system Bash before an Intel-only `/usr/local/bin/bash`. Other operating systems will retain their existing shell and environment behavior.

## Options considered

| Option | Verdict | Why (one line) |
| :--- | :--- | :--- |
| Resolve the initial `bash` from the existing `PATH` | Rejected | On the affected configuration this can select the Intel-only `/usr/local/bin/bash` and fail before setup starts. |
| Use `/bin/bash` only for the initial process | Rejected | Bundled and downloaded scripts invoke `bash` again through `PATH`. |
| Use `/bin/bash` initially and order macOS child `PATH` to prefer compatible Bash | Adopted | Covers both the initial process and nested shell invocations while keeping ARM Homebrew tools available. |

## Consequences

**Not part of this decision:** Installing Bash through Homebrew, installing Rosetta 2, or changing Linux and Windows shell behavior.

### Impact

**Benefits**
- Avoids selecting an Intel-only Bash for the initial install process or nested invocations on Apple Silicon.
- Keeps `/opt/homebrew/bin` first so ARM Homebrew tools remain available.
- Preserves custom non-empty `PATH` entries while removing duplicates.

**Costs**
- macOS child-process command resolution changes: system directories are searched before `/usr/local/bin` and the remaining existing `PATH` entries.

**Risks**
- A macOS installation that relies on a custom executable shadowing a system command may resolve the system executable instead; the original non-empty `PATH` entries remain available after the standard directories.
- This ordering avoids the known Intel-only Bash selection but does not inspect executable architectures or guarantee compatibility for unrelated tools.

### Accepted limits

- The installer does not validate the architecture of every executable in the inherited `PATH`; this decision addresses Bash selection for installation.

### Revisit when

- The macOS installation scripts stop invoking Bash through `PATH`, or the supported macOS/Homebrew shell layout changes.

## Rollback

**When.** Roll back if the new macOS shell or `PATH` selection causes installation failures that were not present before this change.

**How, in order.**

1. Revert the PR #98 implementation through a reviewed change, including its implementation and regression tests; do not make a one-off edit to an installed application.
2. Build and distribute the reverted installer through the normal release process.
3. Keep the existing system Bash and Homebrew installations unchanged; do not leave a partial change that restores `/usr/local/bin` ahead of system directories in the child `PATH`.
4. The revert restores the prior shell-selection behavior and therefore does not fix the reported Apple Silicon failure; users on the affected configuration may need the existing workaround of installing ARM64 Bash with Apple Silicon Homebrew.

## Evidence

| Claim | Where |
| :--- | :--- |
| The reported failure occurs on Apple Silicon when `/usr/local/bin/bash` is Intel-only and ARM Homebrew Bash is absent. | [Issue #97](https://github.com/ADORSYS-GIS/wazuh-agent-installer/issues/97) |
| The proposed implementation selects `/bin/bash` initially and sets the macOS child `PATH` order. | [PR #98 source commit](https://github.com/ADORSYS-GIS/wazuh-agent-installer/commit/2a9f349c4df04b0207f8d8ce6a65c5dbb4f1b150) (`src-tauri/src/lib.rs`) |
| Regression tests cover shell selection, path ordering, deduplication, custom entries, and empty `PATH`. | [PR #98 source commit](https://github.com/ADORSYS-GIS/wazuh-agent-installer/commit/2a9f349c4df04b0207f8d8ce6a65c5dbb4f1b150) (`src-tauri/src/tests.rs`) |
| The pull request reports passing Rust, frontend, CI, and diff checks; Apple Silicon hardware validation remains outstanding. | [PR #98 verification and manual validation](https://github.com/ADORSYS-GIS/wazuh-agent-installer/pull/98) |

## References

- [ADR template](https://github.com/ADORSYS-GIS/wazuh/blob/main/docs/adr/template.md)
- [ADR writing guide](https://github.com/ADORSYS-GIS/wazuh/blob/main/docs/adr/GUIDE.md)
- [Issue #97: macOS ARM installation fails with Intel-only Bash](https://github.com/ADORSYS-GIS/wazuh-agent-installer/issues/97)

## Solution implementation

| Kind | Tracking | Status | What it covers |
| :--- | :--- | :--- | :--- |
| Issue | [ADORSYS-GIS/wazuh-agent-installer#97](https://github.com/ADORSYS-GIS/wazuh-agent-installer/issues/97) | Open | Report and acceptance criteria for the Apple Silicon Bash selection failure |
| PR | [ADORSYS-GIS/wazuh-agent-installer#98](https://github.com/ADORSYS-GIS/wazuh-agent-installer/pull/98) | Open | Select a compatible macOS shell, order child `PATH`, and add regression tests |
| Commit | [2a9f349](https://github.com/ADORSYS-GIS/wazuh-agent-installer/commit/2a9f349c4df04b0207f8d8ce6a65c5dbb4f1b150) | 2026-11-26 | Implements shell selection and macOS `PATH` ordering with tests |
