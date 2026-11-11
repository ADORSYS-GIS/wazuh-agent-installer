@echo off
setlocal
title Wazuh Agent Installer Setup
set "BAT_PATH=%~f0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$content = [System.IO.File]::ReadAllText($env:BAT_PATH); Invoke-Expression ($content -split (':::PS' + '_PAYLOAD:::'))[-1]"
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Installation failed or was cancelled.
    pause
)
exit /b %errorlevel%

:::PS_PAYLOAD:::
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Repo = "ADORSYS-GIS/wazuh-agent-installer"

Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "  Wazuh Agent Installer - 1-Click Windows Setup" -ForegroundColor Cyan
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[INFO] Resolving latest release version from GitHub..."
try {
    $Response = Invoke-WebRequest -Uri "https://github.com/$Repo/releases/latest" -MaximumRedirection 0 -ErrorAction Ignore -UseBasicParsing
    if ($Response.StatusCode -in 301, 302) {
        $Tag = ($Response.Headers.Location -split '/')[-1]
    } else {
        $Tag = (Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest").tag_name
    }
} catch {
    $Tag = "v1.3.2"
}

if (-not $Tag) { $Tag = "v1.3.2" }
$Ver = $Tag.TrimStart('v')
$Tag = "v$Ver"

Write-Host "[INFO] Target release: $Tag (Version: $Ver)"

$MsiName = "Wazuh.Agent.Installer_${Ver}_x64_en-US.msi"
$DownloadUrl = "https://github.com/$Repo/releases/download/$Tag/$MsiName"
$TempPath = Join-Path $env:TEMP "WazuhInstaller_$Ver.msi"
$UserDownloads = Join-Path $env:USERPROFILE "Downloads"
$SavedCopy = Join-Path $UserDownloads $MsiName

Write-Host "[INFO] Downloading $MsiName..."
Write-Host "[INFO] URL: $DownloadUrl"

# Download to temp directory
Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempPath -UseBasicParsing

# Verify file size (must be >= 1 MB)
$fileItem = Get-Item -LiteralPath $TempPath
if ($fileItem.Length -lt 1000000) {
    Write-Host "[ERROR] Downloaded file appears incomplete ($($fileItem.Length) bytes)." -ForegroundColor Red
    exit 1
}

Write-Host "[INFO] Package size verified: $($fileItem.Length) bytes."

# Unblock file to eliminate SmartScreen warnings
Write-Host "[INFO] Removing browser download quarantine (Mark of the Web)..."
if (Test-Path $TempPath) { Unblock-File -LiteralPath $TempPath -ErrorAction SilentlyContinue }

# Close running instances so files are not locked during upgrade
Get-Process -Name "Wazuh Agent Installer" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "  Installing Wazuh Agent Installer..." -ForegroundColor Cyan
Write-Host "  Please click 'Yes' when Windows prompts for Administrator permission (UAC)" -ForegroundColor Cyan
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host ""

try {
    $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$TempPath`" /passive /norestart" -Verb RunAs -Wait -PassThru
    if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) {
        Write-Host ""
        Write-Host "============================================================================" -ForegroundColor Green
        Write-Host "  Installation completed successfully!" -ForegroundColor Green
        Write-Host "============================================================================" -ForegroundColor Green
        Write-Host ""
    } else {
        Write-Host "[WARN] Passive install finished with exit code $($proc.ExitCode). Launching installer..." -ForegroundColor Yellow
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$TempPath`"" -Verb RunAs
    }
} catch {
    Write-Host "[ERROR] Administrator elevation was cancelled or failed." -ForegroundColor Red
    exit 1602
}

# Clean up temporary installer MSI
Remove-Item -Path $TempPath -Force -ErrorAction SilentlyContinue

# Clean up any leftover installer files in Downloads
if (Test-Path $UserDownloads) {
    Get-ChildItem -Path $UserDownloads -Filter "*Wazuh*Installer*.msi" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
}

# Auto-launch the installed application
$InstalledExe = Join-Path $env:ProgramFiles "Wazuh Agent Installer\Wazuh Agent Installer.exe"
if (-not (Test-Path $InstalledExe) -and ${env:ProgramFiles(x86)}) {
    $InstalledExe = Join-Path ${env:ProgramFiles(x86)} "Wazuh Agent Installer\Wazuh Agent Installer.exe"
}

if (Test-Path $InstalledExe) {
    Write-Host "[INFO] Launching Wazuh Agent Installer..."
    Start-Process -FilePath $InstalledExe
} else {
    Write-Host "[INFO] You can now launch Wazuh Agent Installer from your Start Menu."
}

# Self-delete this batch installer from Downloads so no residual files remain
Write-Host "[INFO] Cleaning up installer..."
if ($env:BAT_PATH -and (Test-Path -LiteralPath $env:BAT_PATH)) {
    Start-Process cmd.exe -ArgumentList "/c timeout /t 3 >nul & del /f /q `"$env:BAT_PATH`"" -WindowStyle Hidden
}

Write-Host ""
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "  Setup complete! Window will close automatically in 3 seconds..." -ForegroundColor Cyan
Write-Host "============================================================================" -ForegroundColor Cyan
Start-Sleep -Seconds 3
