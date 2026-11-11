@echo off
setlocal EnableDelayedExpansion

title Wazuh Agent Installer Setup

echo ============================================================================
echo   Wazuh Agent Installer - 1-Click Windows Setup
echo ============================================================================
echo.

:: ============================================================================
:: 1. Configuration & Parameter Parsing
:: ============================================================================
set "REPO=ADORSYS-GIS/wazuh-agent-installer"
set "VERSION=%~1"
if "%VERSION%"=="" set "VERSION=latest"

:: ============================================================================
:: 2. Resolve Target Release Tag
:: ============================================================================
if /i "%VERSION%"=="latest" (
    echo [INFO] Resolving latest release version from GitHub...
    for /f "usebackq delims=" %%I in (`powershell -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue'; try { (Invoke-WebRequest -Uri 'https://github.com/%REPO%/releases/latest' -MaximumRedirection 0 -ErrorAction Ignore -UseBasicParsing).Headers.Location -split '/' | Select-Object -Last 1 } catch { '' }"`) do (
        set "TAG=%%I"
    )
    if not defined TAG (
        for /f "usebackq delims=" %%I in (`powershell -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue'; try { (Invoke-RestMethod -Uri 'https://api.github.com/repos/%REPO%/releases/latest').tag_name } catch { '' }"`) do (
            set "TAG=%%I"
        )
    )
    if not defined TAG (
        echo [WARN] Unable to resolve latest tag online. Using default release v1.3.2...
        set "TAG=v1.3.2"
    )
) else (
    set "TAG=%VERSION%"
)

:: Normalize version strings (ensure tag starts with v, VER is digits only)
if not "!TAG:~0,1!"=="v" set "TAG=v!TAG!"
set "VER=!TAG:~1!"

echo [INFO] Target release: !TAG! (Version: !VER!)

:: ============================================================================
:: 3. Build Asset URLs & Destination Paths
:: ============================================================================
set "MSI_NAME=Wazuh.Agent.Installer_!VER!_x64_en-US.msi"
set "DOWNLOAD_URL=https://github.com/%REPO%/releases/download/!TAG!/!MSI_NAME!"

:: Save to user's Downloads directory for visibility
if defined USERPROFILE (
    set "TARGET_DIR=%USERPROFILE%\Downloads"
) else (
    set "TARGET_DIR=%TEMP%"
)
if not exist "!TARGET_DIR!" mkdir "!TARGET_DIR!" >nul 2>&1
set "DEST=!TARGET_DIR!\!MSI_NAME!"

echo [INFO] Target package: !MSI_NAME!
echo [INFO] Saving to:      !DEST!
echo.

:: ============================================================================
:: 4. Download the MSI Package
:: ============================================================================
echo [INFO] Downloading package from GitHub Releases...
echo [INFO] URL: !DOWNLOAD_URL!

where curl.exe >nul 2>&1
if %errorlevel% equ 0 (
    curl.exe -fL -# -o "!DEST!" "!DOWNLOAD_URL!"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue'; [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '!DOWNLOAD_URL!' -OutFile '!DEST!' -UseBasicParsing"
)

if not exist "!DEST!" (
    echo.
    echo [ERROR] Download failed. The installer package was not found.
    echo Please verify release assets at: https://github.com/%REPO%/releases/tag/!TAG!
    echo.
    pause
    exit /b 1
)

:: ============================================================================
:: 5. Strip Mark of the Web (Zone.Identifier)
:: ============================================================================
echo.
echo [INFO] Removing browser download quarantine flag (Mark of the Web)...
powershell -NoProfile -ExecutionPolicy Bypass -Command "if (Test-Path -LiteralPath '!DEST!') { Unblock-File -LiteralPath '!DEST!' }" >nul 2>&1

:: ============================================================================
:: 6. Launch the Windows Installer (with UAC elevation prompt)
:: ============================================================================
echo [SUCCESS] Package downloaded and unblocked successfully!
echo [INFO] Location: "!DEST!"
echo [INFO] Launching Wazuh Agent Installer...
echo.

:: Launch msiexec with RunAs verb so Windows prompts for administrator permission natively
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Start-Process -FilePath 'msiexec.exe' -ArgumentList '/i `"`"!DEST!`"`"' -Verb RunAs } catch { Start-Process -FilePath 'msiexec.exe' -ArgumentList '/i `"`"!DEST!`"`"' }"

echo ============================================================================
echo Setup initiated. Follow the on-screen installer wizard to finish.
echo You can also re-run the installer anytime from your Downloads folder.
echo ============================================================================
timeout /t 5 >nul 2>&1
exit /b 0
