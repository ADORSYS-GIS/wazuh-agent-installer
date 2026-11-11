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
:: Prefer the standalone .exe installer; fallback to .msi if needed
:: ============================================================================
set "INSTALLER_NAME=Wazuh.Agent.Installer_!VER!_x64-setup.exe"
set "DOWNLOAD_URL=https://github.com/%REPO%/releases/download/!TAG!/!INSTALLER_NAME!"

:: Save to user's Downloads directory for visibility
if defined USERPROFILE (
    set "TARGET_DIR=%USERPROFILE%\Downloads"
) else (
    set "TARGET_DIR=%TEMP%"
)
if not exist "!TARGET_DIR!" mkdir "!TARGET_DIR!" >nul 2>&1
set "DEST=!TARGET_DIR!\!INSTALLER_NAME!"

echo [INFO] Target package: !INSTALLER_NAME!
echo [INFO] Saving to:      !DEST!
echo.

:: ============================================================================
:: 4. Download the Installer Package
:: ============================================================================
echo [INFO] Downloading package from GitHub Releases...
echo [INFO] URL: !DOWNLOAD_URL!

where curl.exe >nul 2>&1
if %errorlevel% equ 0 (
    curl.exe -fL -# -o "!DEST!" "!DOWNLOAD_URL!"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue'; [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '!DOWNLOAD_URL!' -OutFile '!DEST!' -UseBasicParsing"
)

:: Fallback to .msi if .exe is not found on the release
if not exist "!DEST!" (
    echo [WARN] .exe package not found. Attempting .msi fallback...
    set "INSTALLER_NAME=Wazuh.Agent.Installer_!VER!_x64_en-US.msi"
    set "DOWNLOAD_URL=https://github.com/%REPO%/releases/download/!TAG!/!INSTALLER_NAME!"
    set "DEST=!TARGET_DIR!\!INSTALLER_NAME!"

    if %errorlevel% equ 0 (
        curl.exe -fL -# -o "!DEST!" "!DOWNLOAD_URL!"
    ) else (
        powershell -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue'; [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '!DOWNLOAD_URL!' -OutFile '!DEST!' -UseBasicParsing"
    )
)

if not exist "!DEST!" (
    echo.
    echo [ERROR] Download failed. The installer package was not found.
    echo Please verify release assets at: https://github.com/%REPO%/releases/tag/!TAG!
    echo.
    pause
    exit /b 1
)

:: Verify file size (installer must be valid binary, >= 1 MB)
for %%A in ("!DEST!") do set "FILESIZE=%%~zA"
if not defined FILESIZE set "FILESIZE=0"
if !FILESIZE! LSS 1000000 (
    echo.
    echo [ERROR] Downloaded file is too small or incomplete (!FILESIZE! bytes).
    echo Please check your network connection and try again.
    echo Direct download link: !DOWNLOAD_URL!
    echo.
    pause
    exit /b 1
)

echo [INFO] Package size verified: !FILESIZE! bytes.

:: ============================================================================
:: 5. Strip Mark of the Web (Zone.Identifier)
:: ============================================================================
echo.
echo [INFO] Removing browser download quarantine flag (Mark of the Web)...
powershell -NoProfile -ExecutionPolicy Bypass -Command "if (Test-Path -LiteralPath '!DEST!') { Unblock-File -LiteralPath '!DEST!' }" >nul 2>&1

:: ============================================================================
:: 6. Launch the Windows Installer
:: ============================================================================
echo [SUCCESS] Package downloaded and unblocked successfully!
echo [INFO] Location: "!DEST!"
echo [INFO] Launching Wazuh Agent Installer...
echo.

:: Launch .exe directly or via msiexec if .msi was downloaded
if /i "!DEST:~-4!"==".msi" (
    start "" msiexec.exe /i "!DEST!"
) else (
    start "" "!DEST!"
)

echo ============================================================================
echo Setup initiated. Follow the on-screen installer wizard to finish.
echo You can also re-run the installer anytime from your Downloads folder.
echo ============================================================================
timeout /t 5 >nul 2>&1
exit /b 0
