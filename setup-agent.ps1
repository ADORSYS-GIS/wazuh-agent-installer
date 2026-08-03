$env:WAZUH_AGENT_REPO_REF = if ($env:WAZUH_AGENT_REPO_REF) { $env:WAZUH_AGENT_REPO_REF } else { "develop" }
$tmpScript = Join-Path $env:TEMP "wazuh-setup-agent-real_$((Get-Date).Ticks).ps1"
try {
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-agent/$env:WAZUH_AGENT_REPO_REF/scripts/setup-agent.ps1" -OutFile $tmpScript -UseBasicParsing
    & $tmpScript @args
}
finally {
    Remove-Item $tmpScript -ErrorAction SilentlyContinue
}
