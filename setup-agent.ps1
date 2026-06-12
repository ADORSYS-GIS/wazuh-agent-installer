param(
    [string]$RepoUrl = "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-agent",
    [string]$Ref = $(
        if ($env:WAZUH_AGENT_REPO_REF) { $env:WAZUH_AGENT_REPO_REF } else { 'main' }
    )
)

$env:WAZUH_AGENT_VERSION = "4.14.4-1"
$env:WAZUH_AGENT_STATUS_VERSION = "v0.5.0-skyengpro"
$env:WAZUH_AGENT_STATUS_REPO_REF = "v0.5.0-skyengpro"
$env:APP_VERSION = "0.5.0-skyengpro"

$ScriptRoot = Split-Path -Path $MyInvocation.MyCommand.Path -Parent

# Decide remote path depending on OS
$remotePath = 'scripts/windows/setup-agent.ps1'

# Create a temporary folder
$tmp = Join-Path -Path $env:TEMP -ChildPath "wazuh_setup_$([guid]::NewGuid())"
New-Item -ItemType Directory -Path $tmp -Force | Out-Null

try {
    $checksumsUrl = "$RepoUrl/$Ref/checksums.sha256"
    $scriptUrl = "$RepoUrl/$Ref/$remotePath"
    $checksumsPath = Join-Path $tmp 'checksums.sha256'
    $scriptPath = Join-Path $tmp 'remote_setup.ps1'

    # Download files
    Invoke-WebRequest -Uri $checksumsUrl -OutFile $checksumsPath -UseBasicParsing -ErrorAction Stop
    Invoke-WebRequest -Uri $scriptUrl -OutFile $scriptPath -UseBasicParsing -ErrorAction Stop

    # Verify checksum
    $match = Select-String -Path $checksumsPath -Pattern $remotePath -SimpleMatch

    if ($null -eq $match) {
        Write-Error "Could not find checksum entry for $remotePath"
        exit 1
    }

    $expected = (
        $match | Select-Object -First 1
    ).Line -split '\s+' | Select-Object -First 1
    $expected = $expected.ToLower()

    $actual = (Get-FileHash -Path $scriptPath -Algorithm SHA256).Hash.ToLower()

    Write-Host "Expected: $expected"
    Write-Host "Actual:   $actual"

    if ($expected -ne $actual) {
        Write-Error "Checksum verification failed for $remotePath"
        exit 1
    }

    # --- INJECTED HOTFIX FOR CERT AUTH ---
    if ($env:INSTALL_CERT_AUTH -eq "FALSE") {
        $scriptContent = Get-Content -Path $scriptPath -Raw
        $scriptContent = $scriptContent -replace 'SectionSeparator "Installing OAuth2Client"\s+Install-OAuth2Client', ''
        Set-Content -Path $scriptPath -Value $scriptContent
    }
    # -------------------------------------

    # Execute the downloaded script
    & $scriptPath @args
} finally {
    # Clean up temporary folder
    Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue
}
