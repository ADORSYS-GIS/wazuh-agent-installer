param(
    [string]$Version = "latest"
)

$Repo = "ADORSYS-GIS/wazuh-agent-installer"
Write-Host "📥 Downloading Wazuh Agent Installer for Windows..." -ForegroundColor Cyan

if ($Version -eq "latest") {
    $Response = Invoke-WebRequest -Uri "https://github.com/$Repo/releases/latest" -MaximumRedirection 0 -ErrorAction Ignore
    if ($Response.StatusCode -in 301, 302) {
        $Tag = ($Response.Headers.Location -split '/')[-1]
    } else {
        Write-Error "❌ Could not determine latest version tag."
        exit 1
    }
} else {
    $Tag = $Version
}

if (-not $Tag) {
    Write-Error "❌ Could not determine version tag."
    exit 1
}

$Ver = $Tag.TrimStart('v')
$Tag = "v$Ver"

$DownloadUrl = "https://github.com/$Repo/releases/download/$Tag/wazuh-agent-installer-dev_${Ver}_x64_en-US.msi"

try {
    Invoke-WebRequest -Uri $DownloadUrl -Method Head -ErrorAction Stop > $null
} catch {
    Write-Error "❌ Could not find Windows .msi package ($DownloadUrl) in release"
    Write-Host "   Visit https://github.com/$Repo/releases to check available assets"
    exit 1
}
$TempPath = Join-Path $env:TEMP "WazuhInstaller_$Version.msi"

Write-Host "Downloading from: $DownloadUrl"
Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempPath

Write-Host "📦 Installing package..." -ForegroundColor Cyan
$process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$TempPath`" /passive /norestart" -Wait -NoNewWindow -PassThru

if ($process.ExitCode -eq 0) {
    Write-Host "✅ Wazuh Agent Installer installed successfully! You can find it in your Start Menu." -ForegroundColor Green
} else {
    Write-Host "❌ Installation failed with exit code: $($process.ExitCode). Please try running PowerShell as Administrator." -ForegroundColor Red
}
