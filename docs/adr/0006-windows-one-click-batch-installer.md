# ADR-0006: Windows 1-Click Bootstrap Batch Installer

> We introduce a 1-click Windows batch installer (`install-scripts/windows.bat`) that self-elevates with native UAC, downloads the latest release MSI package using curl, and removes Mark of the Web quarantine attributes to eliminate non-technical user friction and SmartScreen malware warnings.

## Metadata

| Field             | Value                                                |
| :---------------- | :--------------------------------------------------- |
| **Document ID**   | ADR-0006                                             |
| **Status**        | `Accepted`                                           |
| **Date**          | 2026-11-11                                           |
| **Deciders**      | Wazuh maintainers                                    |
| **Governs**       | `install-scripts/windows.bat`                         |
| **Amends**        | N/A                                                  |
| **Amended by**    | N/A                                                  |
| **Supersedes**    | N/A                                                  |
| **Superseded by** | N/A                                                  |

## Context

The Wazuh Agent Installer supports Linux, macOS, and Windows. On Windows, the application is packaged as an MSI installer (`Wazuh.Agent.Installer_<version>_x64_en-US.msi`) published to GitHub Releases alongside an automated PowerShell installation script (`install-scripts/windows.ps1`).

In practice, non-technical users experience significant friction with the existing Windows enrollment workflow:
1. **PowerShell barrier**: The enrollment guide instructs users to open PowerShell as Administrator and run `irm ... | iex`. Non-technical employees frequently do not know how to find PowerShell, run it with elevated privileges, or navigate execution policy prompts.
2. **Direct browser download warnings (SmartScreen)**: When non-technical users navigate directly to GitHub Releases in their browser, they face decision paralysis among dozens of platform assets. Furthermore, executables downloaded via web browsers (Edge, Chrome) receive the Windows "Mark of the Web" (`Zone.Identifier` alternate data stream). Because the MSI package is not signed with an enterprise EV code-signing certificate, Microsoft Defender SmartScreen displays a warning ("Windows protected your PC - Unknown Publisher"), which users misinterpret as malware.
3. **Support overhead**: This barrier generates avoidable support tickets during company-wide rollouts and delays fleet security enrollment.

The deciding forces are:
- Eliminate terminal and command-line prerequisites for non-technical Windows users.
- Prevent Windows Defender SmartScreen "unrecognized app / malware" warnings without recurring commercial certificate costs.
- Provide a zero-cost, self-contained mechanism that runs natively on standard Windows 10 and Windows 11 systems.
- Preserve backward compatibility for existing PowerShell automated pipelines and direct MSI installations.

## Decision

We introduce `install-scripts/windows.bat`, a self-contained Windows batch file that provides a native double-click installation experience:

1. **Automatic UAC Self-Elevation**:
   - The script checks for administrative privileges using `net session`.
   - If unprivileged, it automatically re-executes itself with elevated privileges via `Start-Process -Verb RunAs`, presenting the standard Windows User Account Control (UAC) prompt ("Do you want to allow this app to make changes to your device?").
   - Users simply click "Yes" without touching PowerShell or administrative submenus.

2. **Native Asset Resolution and Download**:
   - The script queries the official GitHub Releases endpoint (`ADORSYS-GIS/wazuh-agent-installer/releases/latest`) to determine the target release tag and MSI asset filename.
   - It downloads the MSI package directly using Windows native `curl.exe` (standard in Windows 10 build 17063+ and Windows 11) with a fallback to `Invoke-WebRequest`.
   - It places the installer in `%USERPROFILE%\Downloads` so users can locate the downloaded package.

3. **SmartScreen Mark of the Web Removal**:
   - The script invokes `Unblock-File` on the downloaded `.msi` file.
   - This strips the browser-appended `Zone.Identifier` quarantine stream before launching `msiexec.exe`.
   - As a result, the MSI package launches cleanly in the foreground without the blue SmartScreen warning screen.

## Options considered

| Option                                                     | Verdict  | Why (one line)                                                                    |
| :--------------------------------------------------------- | :------- | :-------------------------------------------------------------------------------- |
| PowerShell one-liner only (`windows.ps1`)                  | Rejected | High user friction; non-technical users struggle with elevated terminal usage.    |
| Commercial EV Code Signing Certificate                     | Rejected | High annual subscription costs and hardware token management overhead.           |
| Enterprise MDM (Microsoft Intune)                          | Rejected | Infeasible for unmanaged or BYOD endpoints and carries cloud subscription costs.  |
| 1-Click Batch Installer with UAC Elevation and Unblock     | Adopted  | Zero financial cost, zero terminal usage for users, and eliminates SmartScreen.   |

## Consequences

**Not part of this decision:** Replacing the PowerShell script or Linux/macOS installation scripts. The existing `install-scripts/windows.ps1`, `macos.sh`, and `ubuntu.sh` remain intact for automated pipelines and advanced users.

### Impact

**Benefits**
- Non-technical users install the agent by double-clicking a single file and confirming the standard Windows UAC dialog.
- SmartScreen "unrecognized app" popups are prevented by unblocking the downloaded file.
- The MSI installer is saved to the user's `Downloads` directory for visibility.
- Zero financial or cloud infrastructure cost.

**Costs**
- Adds `install-scripts/windows.bat` to repository maintenance.

### Done when

- [x] `install-scripts/windows.bat` is created and executable on Windows 10/11.
- [x] UAC self-elevation and Mark of the Web unblocking are implemented.
- [x] Documentation in `README.md` and `docs/operations/packaging.md` updated.
- [x] ADR-0006 is documented and indexed in `docs/adr/README.md`.
- [x] Pull request is opened and linked to tracking issue.

### Revisit when

- The organization acquires an enterprise EV Code Signing Certificate or Microsoft Azure Trusted Signing infrastructure.
- Windows changes default `.bat` execution policies or removes built-in `curl.exe`.

## Rollback

To roll back, remove `install-scripts/windows.bat` and revert documentation changes. The application and packaging pipeline remain unchanged.

## Evidence

| Claim                                                    | Where                                                                  |
| :------------------------------------------------------- | :--------------------------------------------------------------------- |
| User friction and SmartScreen issue                      | Issue [#76](https://github.com/ADORSYS-GIS/wazuh-agent-installer/issues/76) |
| Script implementation                                    | `install-scripts/windows.bat`                                           |
| Canonical enrollment documentation                       | Confluence [Windows - Enrollment Guide](https://adorsys.atlassian.net/wiki/spaces/Wazuh/pages/1414070436/Windows+-+Enrollment+Guide) |

## References

- [Microsoft Unblock-File Documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/unblock-file)
- [Microsoft Defender SmartScreen Overview](https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/)
- [ADR template](https://github.com/ADORSYS-GIS/wazuh/blob/main/docs/adr/template.md)
- [ADR writing guide](https://github.com/ADORSYS-GIS/wazuh/blob/main/docs/adr/GUIDE.md)

## Solution implementation

| Kind   | Tracking                                                                                                        | Status | What it covers                                              |
| :----- | :-------------------------------------------------------------------------------------------------------------- | :----- | :---------------------------------------------------------- |
| Issue  | [ADORSYS-GIS/wazuh-agent-installer#76](https://github.com/ADORSYS-GIS/wazuh-agent-installer/issues/76)          | Open   | Provide 1-click batch installer for non-technical users     |
| PR     | [ADORSYS-GIS/wazuh-agent-installer](https://github.com/ADORSYS-GIS/wazuh-agent-installer/pulls)                | Open   | Adds install-scripts/windows.bat, docs, and ADR-0006        |
