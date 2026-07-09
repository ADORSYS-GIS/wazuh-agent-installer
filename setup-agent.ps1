param(
    [switch]$InstallSnort,
    [switch]$InstallSuricata,
    [switch]$InstallNetBird,
    [switch]$InstallVelociraptor,
    [string]$VelociraptorConfig,
    [switch]$CaptureDockerLogs,
    [switch]$Help
)

$env:WAZUH_AGENT_REPO_REF = if ($env:WAZUH_AGENT_REPO_REF) { $env:WAZUH_AGENT_REPO_REF } else { "develop" }

# Download the real setup-agent.ps1 to a temp file so we can forward
# all command-line switches (Invoke-Expression drops them).
$tmpScript = Join-Path $env:TEMP "wazuh-setup-agent-real_$((Get-Date).Ticks).ps1"
try {
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-agent/$env:WAZUH_AGENT_REPO_REF/scripts/setup-agent.ps1" -OutFile $tmpScript -UseBasicParsing

    # Rebuild the argument list to forward to the downloaded script
    $forwardArgs = @()
    if ($InstallSnort)       { $forwardArgs += "-InstallSnort" }
    if ($InstallSuricata)    { $forwardArgs += "-InstallSuricata" }
    if ($InstallNetBird)     { $forwardArgs += "-InstallNetBird" }
    if ($InstallVelociraptor){ $forwardArgs += "-InstallVelociraptor" }
    if ($VelociraptorConfig) { $forwardArgs += "-VelociraptorConfig"; $forwardArgs += $VelociraptorConfig }
    if ($CaptureDockerLogs)  { $forwardArgs += "-CaptureDockerLogs" }
    if ($Help)               { $forwardArgs += "-Help" }

    & $tmpScript @forwardArgs
}
finally {
    Remove-Item $tmpScript -ErrorAction SilentlyContinue
}