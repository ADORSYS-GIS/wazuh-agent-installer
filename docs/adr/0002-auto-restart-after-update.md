# ADR-0002: Automatic Application Restart After Update

> We automatically restart the desktop installer process using Tauri's native restart API upon successful update completion so that the application immediately runs the new binary and syncs local state.

## Metadata

| Field             | Value                                                          |
| :---------------- | :------------------------------------------------------------- |
| **Document ID**   | ADR-0002                                                       |
| **Status**        | `Accepted`                                                     |
| **Date**          | 2026-11-03                                                     |
| **Deciders**      | Wazuh maintainers                                              |
| **Governs**       | `src/main.ts`, `src-tauri/src/lib.rs`                          |
| **Amends**        | N/A                                                            |
| **Amended by**    | N/A                                                            |
| **Supersedes**    | N/A                                                            |
| **Superseded by** | N/A                                                            |

## Context

This project is a cross-platform desktop installer built with Tauri (Rust backend) and TypeScript (frontend). It packages self-update capabilities via platform-specific shell scripts (`macos.sh`, `ubuntu.sh`, and `windows.ps1`) that download the latest release asset and replace the installed binary on disk (`/Applications/Wazuh Agent Installer.app`, `/usr/bin/wazuh-agent-installer`, or Program Files).

When an update script finishes executing, the newly installed files exist on disk, but the operating system keeps the existing executable running in memory. Previously, the application prompted the user to manually close the window and scheduled a delayed close after 5 seconds. If the user did not notice or left the app open, the running instance remained on the old version, continued showing the "Update available" banner, and failed to reflect the upgrade.

The deciding forces were: the update transition must be automatic and seamless, the newly installed binary must launch immediately to execute its startup logic and synchronize `version.txt`, and the mechanism must work reliably across macOS, Linux, and Windows without manual user intervention.

## Decision

We will expose a dedicated `restart_app` command in the Tauri backend invoking `tauri::process::restart(&app.env())`. Upon successful return from `run_app_update`, the frontend will display a clear confirmation message in the terminal log and trigger `restart_app` after a 1.5-second timeout, with a fallback to window close.

On launch, the newly spawned binary automatically runs `init_config_dir`, which compares its internal package version against `version.txt`, writes the updated version number to disk, and evaluates update status against GitHub releases, presenting a refreshed UI with no stale update prompts.

## Options considered

| Option                                              | Verdict  | Why (one line)                                                                                                              |
| :-------------------------------------------------- | :------- | :-------------------------------------------------------------------------------------------------------------------------- |
| Manual user close and re-launch (status quo)        | Rejected | Users leave the app open or get confused by repeated update notifications.                                                  |
| Webview reload (`location.reload()`)                | Rejected | Only reloads web assets; leaves old native binary running in memory and misses newly installed native code and version.     |
| Native process restart via `tauri::process::restart`| Adopted  | Cleanly terminates the old process and spawns the new executable in a cross-platform manner.                                 |

## Consequences

**Not part of this decision:** Background system services managed by the installer (such as Wazuh agent or Suricata) are not restarted by this flow; this decision strictly governs the installer desktop application self-update lifecycle.

### Impact

**Benefits**

- Immediate user feedback and automatic transition to the newly installed binary.
- The new binary automatically synchronizes `version.txt` on startup.
- Eliminates user confusion from stale "Update available" banners after completing an update.
- Consistent cross-platform behavior handled natively by Tauri.

**Costs**

- The running application window closes and re-opens automatically after update completion.

**Risks**

- If the updater script fails to write the new binary or corrupts the disk asset, restarting could trigger a crash on restart (mitigated: restart is only invoked if `run_app_update` completes with exit status code 0).
- If OS elevation or anti-virus scans delay the new binary launch, there could be a brief delay before the new window renders (mitigated: `tauri::process::restart` handles the child spawn before terminating the parent).

### Accepted limits

- Automatic restart applies to the GUI desktop application; headless CLI executions are unaffected.
- A 1.5-second delay is introduced before restart so the user can read the success message in the terminal log.

### Done when

- [x] Backend exposes `restart_app` command calling `tauri::process::restart(&app.env())`.
- [x] Backend registers `restart_app` in `tauri::generate_handler!`.
- [x] Frontend updates `triggerUpdate` to log success and invoke `restart_app`.
- [x] All automated tests pass (`cargo test`, `npm run build`, `./run-ci.sh`).
- [x] Newly spawned binary synchronizes `version.txt` and clears update banners.

### Revisit when

- Tauri introduces in-place hot-reloading for native desktop binaries.
- The installer architecture adopts an external background updater service.

## Rollback

To roll back this decision, revert the frontend call in `src/main.ts` from `restart_app` back to `getCurrentWindow().close()`, and remove `restart_app` from `src-tauri/src/lib.rs`.

## Evidence

| Claim                                                                 | Where                                                          |
| :-------------------------------------------------------------------- | :------------------------------------------------------------- |
| Backend exposes and registers `restart_app` via process restart       | `src-tauri/src/lib.rs` in this repo                            |
| Frontend invokes `restart_app` upon successful update completion      | `src/main.ts` in this repo                                     |
| Startup routine writes upgraded package version into `version.txt`    | `src-tauri/src/lib.rs` (`init_config_dir_at_path`) in this repo |
| All verification checks pass cleanly                                  | `./run-ci.sh` in this repo                                     |

## References

- [ADR template](https://github.com/ADORSYS-GIS/wazuh/blob/main/docs/adr/template.md)
- [ADR writing guide](https://github.com/ADORSYS-GIS/wazuh/blob/main/docs/adr/GUIDE.md)
- [Tauri Process API](https://docs.rs/tauri/latest/tauri/process/fn.restart.html)

## Solution implementation

| Kind   | Tracking                                                                                                        | Status            | What it covers                                     |
| :----- | :-------------------------------------------------------------------------------------------------------------- | :---------------- | :------------------------------------------------- |
| Issue  | [ADORSYS-GIS/wazuh-agent-installer#45](https://github.com/ADORSYS-GIS/wazuh-agent-installer/issues/45)          | Closed            | Feature request for automatic restart after update |
| PR     | [ADORSYS-GIS/wazuh-agent-installer#46](https://github.com/ADORSYS-GIS/wazuh-agent-installer/pull/46)            | Merged 2026-11-03 | Implements auto-restart, bumps v1.3.1, adds ADR    |
| PR     | [ADORSYS-GIS/wazuh-agent-installer#47](https://github.com/ADORSYS-GIS/wazuh-agent-installer/pull/47)            | Merged 2026-11-03 | Merges feature and release bump to `main`          |
| Commit | [3b48d7d](https://github.com/ADORSYS-GIS/wazuh-agent-installer/commit/3b48d7d)                                 | 2026-11-03        | Implements restart command, UI flow, and draft ADR |
| Commit | [3b8b6d9](https://github.com/ADORSYS-GIS/wazuh-agent-installer/commit/3b8b6d9)                                 | 2026-11-03        | Version bump to 1.3.1                              |
| Commit | [343d4c6](https://github.com/ADORSYS-GIS/wazuh-agent-installer/commit/343d4c6)                                 | 2026-11-03        | Merge PR #46 into `develop`                        |
| Commit | [9116301](https://github.com/ADORSYS-GIS/wazuh-agent-installer/commit/9116301)                                 | 2026-11-03        | Merge PR #47 into `main`                           |
