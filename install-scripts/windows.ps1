param(
    [string]$Version = "latest"
)

$Repo = "ADORSYS-GIS/wazuh-agent-installer"
Write-Host "📥 Downloading Wazuh Agent Installer for Windows..." -ForegroundColor Cyan

$ReleaseUrl = if ($Version -eq "latest") {
    "https://api.github.com/repos/$Repo/releases/latest"
} else {
    "https://api.github.com/repos/$Repo/releases/tags/$Version"
}

try {
    $ReleaseInfo = Invoke-RestMethod -Uri $ReleaseUrl -ErrorAction Stop
} catch {
    Write-Error "❌ Failed to fetch release information. Check your internet connection or the version tag."
    exit 1
}

$Asset = $ReleaseInfo.assets | Where-Object { $_.name -match '\.msi$' } | Select-Object -First 1

if (-not $Asset) {
    Write-Error "❌ Could not find Windows .msi package in release"
    Write-Host "   Visit https://github.com/$Repo/releases to check available assets"
    exit 1
}

$DownloadUrl = $Asset.browser_download_url
$TempPath = Join-Path $env:TEMP "WazuhInstaller_$Version.msi"

Write-Host "Downloading from: $DownloadUrl"
Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempPath

Write-Host "📦 Installing package..." -ForegroundColor Cyan
Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$TempPath`" /quiet /norestart" -Wait -NoNewWindow

Write-Host "✅ Wazuh Agent Installer installed successfully! You can find it in your Start Menu." -ForegroundColor Green
