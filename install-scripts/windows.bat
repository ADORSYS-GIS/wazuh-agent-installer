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
:: Use the official .msi package matching windows.ps1
:: ============================================================================
set "MSI_NAME=Wazuh.Agent.Installer_!VER!_x64_en-US.msi"
set "DOWNLOAD_URL=https://github.com/%REPO%/releases/download/!TAG!/!MSI_NAME!"
set "TEMP_MSI=%TEMP%\WazuhInstaller_!VER!.msi"

if defined USERPROFILE (
    set "USER_DOWNLOADS=%USERPROFILE%\Downloads"
) else (
    set "USER_DOWNLOADS=%TEMP%"
)
set "SAVED_COPY=!USER_DOWNLOADS!\!MSI_NAME!"

echo [INFO] Target package: !MSI_NAME!
echo [INFO] Download URL:   !DOWNLOAD_URL!
echo [INFO] Staging path:   !TEMP_MSI!
echo.

:: ============================================================================
:: 4. Download the MSI Package
:: ============================================================================
echo [INFO] Downloading package from GitHub Releases...

where curl.exe >nul 2>&1
if %errorlevel% equ 0 (
    curl.exe -fL -# -o "!TEMP_MSI!" "!DOWNLOAD_URL!"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue'; [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '!DOWNLOAD_URL!' -OutFile '!TEMP_MSI!' -UseBasicParsing"
)

if not exist "!TEMP_MSI!" (
    echo.
    echo [ERROR] Download failed. The installer package was not found.
    echo Please verify release assets at: https://github.com/%REPO%/releases/tag/!TAG!
    echo.
    pause
    exit /b 1
)

:: Verify file size (MSI must be valid binary, >= 1 MB)
for %%A in ("!TEMP_MSI!") do set "FILESIZE=%%~zA"
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

:: Save a copy into the user's Downloads folder for convenience
if not exist "!USER_DOWNLOADS!" mkdir "!USER_DOWNLOADS!" >nul 2>&1
copy /y "!TEMP_MSI!" "!SAVED_COPY!" >nul 2>&1
echo [INFO] A copy of the installer was saved to:
echo        "!SAVED_COPY!"

:: ============================================================================
:: 5. Strip Mark of the Web (Zone.Identifier)
:: ============================================================================
echo.
echo [INFO] Removing browser download quarantine flag (Mark of the Web)...
powershell -NoProfile -ExecutionPolicy Bypass -Command "if (Test-Path -LiteralPath '!TEMP_MSI!') { Unblock-File -LiteralPath '!TEMP_MSI!' }; if (Test-Path -LiteralPath '!SAVED_COPY!') { Unblock-File -LiteralPath '!SAVED_COPY!' }" >nul 2>&1

:: ============================================================================
:: 6. Execute the Installation (Matching windows.ps1 behavior)
:: ============================================================================
echo.
echo ============================================================================
echo   Installing Wazuh Agent Installer...
echo   Please click 'Yes' if Windows prompts for Administrator permission (UAC)
echo ============================================================================
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command "try { $p = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', '!TEMP_MSI!', '/passive', '/norestart') -Verb RunAs -Wait -PassThru; exit $p.ExitCode } catch { exit 1602 }"
set "INSTALL_STATUS=%errorlevel%"

if %INSTALL_STATUS% neq 0 if %INSTALL_STATUS% neq 3010 (
    echo [WARN] Elevated passive install returned exit code %INSTALL_STATUS%.
    echo [INFO] Launching interactive installer as fallback...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', '!TEMP_MSI!') -Verb RunAs"
)

echo.
echo ============================================================================
echo   Installation complete!
echo ============================================================================
echo.

:: Launch the updated installed application
set "INSTALLED_EXE=%ProgramFiles%\Wazuh Agent Installer\Wazuh Agent Installer.exe"
if exist "!INSTALLED_EXE!" (
    echo [INFO] Launching updated Wazuh Agent Installer...
    start "" "!INSTALLED_EXE!"
) else (
    echo [INFO] You can now launch Wazuh Agent Installer from your Start Menu.
)

timeout /t 5 >nul 2>&1
exit /b 0
