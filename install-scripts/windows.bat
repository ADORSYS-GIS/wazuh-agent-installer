@echo off
setlocal EnableDelayedExpansion

title Wazuh Agent Installer Setup

:: ============================================================================
:: 1. UAC Elevation Check & Automatic Self-Elevation
:: ============================================================================
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Administrator permissions are required to install system services.
    echo [INFO] Requesting elevation...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
    exit /b %errorlevel%
)

:: ============================================================================
:: 2. Configuration & Parameter Parsing
:: ============================================================================
set "REPO=ADORSYS-GIS/wazuh-agent-installer"
set "VERSION=%~1"
if "%VERSION%"=="" set "VERSION=latest"

echo ============================================================================
echo   Wazuh Agent Installer - 1-Click Windows Setup
echo ============================================================================
echo.

:: ============================================================================
:: 3. Resolve Target Release Tag
:: ============================================================================
if /i "%VERSION%"=="latest" (
    echo [INFO] Resolving latest release version from GitHub...
    for /f "usebackq delims=" %%I in (`powershell -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue'; try { (Invoke-WebRequest -Uri 'https://github.com/%REPO%/releases/latest' -MaximumRedirection 0 -ErrorAction Ignore -UseBasicParsing).Headers.Location -split '/' | Select-Object -Last 1 } catch { '' }"`) do (
        set "TAG=%%I"
    )
    if not defined TAG (
        echo [WARN] Direct redirect query failed. Attempting fallback query...
        for /f "usebackq delims=" %%I in (`powershell -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue'; try { (Invoke-RestMethod -Uri 'https://api.github.com/repos/%REPO%/releases/latest').tag_name } catch { '' }"`) do (
            set "TAG=%%I"
        )
    )
    if not defined TAG (
        echo [ERROR] Could not determine latest release version.
        echo Please ensure you are connected to the internet and try again.
        pause
        exit /b 1
    )
) else (
    set "TAG=%VERSION%"
)

:: Normalize version strings
if not "!TAG:~0,1!"=="v" set "TAG=v!TAG!"
set "VER=!TAG:~1!"

echo [INFO] Selected release: !TAG! (Version: !VER!)

:: ============================================================================
:: 4. Build Asset URLs & Destination Paths
:: ============================================================================
set "MSI_NAME=Wazuh.Agent.Installer_!VER!_x64_en-US.msi"
set "DOWNLOAD_URL=https://github.com/%REPO%/releases/download/!TAG!/!MSI_NAME!"

:: Target the user's Downloads directory if available, otherwise Temp
if defined USERPROFILE (
    set "TARGET_DIR=%USERPROFILE%\Downloads"
) else (
    set "TARGET_DIR=%TEMP%"
)
if not exist "!TARGET_DIR!" mkdir "!TARGET_DIR!" >nul 2>&1
set "DEST=!TARGET_DIR!\!MSI_NAME!"

echo [INFO] Target package: !MSI_NAME!
echo [INFO] Destination:    !DEST!
echo.

:: ============================================================================
:: 5. Download the MSI Package (using curl or fallback to PowerShell)
:: ============================================================================
echo [INFO] Downloading package from GitHub Releases...
where curl.exe >nul 2>&1
if %errorlevel% equ 0 (
    curl.exe -fL -# -o "!DEST!" "!DOWNLOAD_URL!"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue'; [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '!DOWNLOAD_URL!' -OutFile '!DEST!' -UseBasicParsing"
)

if not exist "!DEST!" (
    echo.
    echo [ERROR] Download failed. The release package was not found.
    echo Please verify release assets at: https://github.com/%REPO%/releases/tag/!TAG!
    pause
    exit /b 1
)

:: ============================================================================
:: 6. Strip Mark of the Web (Zone.Identifier)
:: ============================================================================
echo [INFO] Unblocking file to prevent Windows Defender SmartScreen warnings...
powershell -NoProfile -ExecutionPolicy Bypass -Command "if (Test-Path -LiteralPath '!DEST!') { Unblock-File -LiteralPath '!DEST!' }" >nul 2>&1

:: ============================================================================
:: 7. Launch the Windows Installer
:: ============================================================================
echo.
echo [SUCCESS] Package downloaded and unblocked successfully!
echo [INFO] Saved to: "!DEST!"
echo [INFO] Launching Wazuh Agent Installer...
echo.

start "" msiexec.exe /i "!DEST!"

echo ============================================================================
echo Setup initiated. Follow the on-screen installer wizard to finish.
echo This window will close automatically in 5 seconds.
echo ============================================================================
timeout /t 5 >nul 2>&1
exit /b 0
