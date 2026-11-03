# ADR-0002: Automatic Application Restart After Update

> We automatically restart the desktop installer process using `tauri::process::restart` upon successful completion of the update script so that the new binary immediately runs and updates local state.

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

When the in-app updater completes running the OS-specific update script (`macos.sh`, `ubuntu.sh`, or `windows.ps1`), the newly installed package is placed on disk (`/Applications/Wazuh Agent Installer.app`, `/usr/bin/wazuh-agent-installer`, or Program Files). However, the currently running application process remains in memory on the old version. Previously, the UI prompted the user to manually close the application and scheduled a window close after 5 seconds. If the user did not notice or re-opened the app later, they continued to see stale update notifications.

## Decision

We will expose a dedicated `restart_app` command in the Tauri backend invoking `tauri::process::restart(&app.env())`. Upon successful return from `run_app_update`, the frontend will log a clear confirmation message and trigger `restart_app` after a 1.5-second delay.

On launch, the newly spawned binary automatically runs `init_config_dir`, which writes its current package version to `version.txt` and evaluates updates against GitHub releases, loading a refreshed UI with no stale update prompts.

## Options considered

| Option                                              | Verdict  | Why (one line)                                                                                                              |
| :-------------------------------------------------- | :------- | :-------------------------------------------------------------------------------------------------------------------------- |
| Manual user close and re-launch (status quo)        | Rejected | Users leave the app open or get confused by repeated update notifications.                                                  |
| Webview reload (`location.reload()`)                | Rejected | Only reloads the web assets; leaves old native binary running in memory and misses newly installed native code and version. |
| Native process restart via `tauri::process::restart`| Adopted  | Cleanly terminates the old process and spawns the new executable in a cross-platform manner.                                 |

## Consequences

### Impact

**Benefits**

- Immediate user feedback with no manual restart required.
- The new binary immediately initializes `version.txt` with the upgraded version number.
- Stale update banners and pills disappear automatically upon restart.

**Costs**

- The running application window closes and re-opens automatically after the update finishes.
