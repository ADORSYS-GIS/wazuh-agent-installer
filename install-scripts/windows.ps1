param(
    [string]$Version = "latest"
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Repo = "ADORSYS-GIS/wazuh-agent-installer"
Write-Output "📥 Downloading Wazuh Agent Installer for Windows..."

if ($Version -eq "latest") {
    $Response = Invoke-WebRequest -Uri "https://github.com/$Repo/releases/latest" -MaximumRedirection 0 -ErrorAction Ignore -UseBasicParsing
    if ($Response.StatusCode -in 301, 302) {
        $Tag = ($Response.Headers.Location -split '/')[-1]
    } else {
        Write-Output "❌ Could not determine latest version tag."
        exit 1
    }
} else {
    $Tag = $Version
}

if (-not $Tag) {
    Write-Output "❌ Could not determine version tag."
    exit 1
}

$Ver = $Tag.TrimStart('v')
$Tag = "v$Ver"

$DownloadUrl = "https://github.com/$Repo/releases/download/$Tag/Wazuh.Agent.Installer_${Ver}_x64_en-US.msi"

try {
    Invoke-WebRequest -Uri $DownloadUrl -Method Head -ErrorAction Stop -UseBasicParsing > $null
} catch {
    Write-Output "❌ Could not find Windows .msi package ($DownloadUrl) in release"
    Write-Output "   Visit https://github.com/$Repo/releases to check available assets"
    exit 1
}
$TempPath = Join-Path $env:TEMP "WazuhInstaller_$Version.msi"

Write-Output "Downloading from: $DownloadUrl"
Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempPath -UseBasicParsing

Write-Output "📦 Installing package..."
$process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$TempPath`" /passive /norestart" -Wait -NoNewWindow -PassThru

if ($process.ExitCode -eq 0) {
    Write-Output "✅ Wazuh Agent Installer installed successfully! You can find it in your Start Menu."
} else {
    Write-Output "❌ Installation failed with exit code: $($process.ExitCode). Please try running PowerShell as Administrator."
    exit $($process.ExitCode)
}
