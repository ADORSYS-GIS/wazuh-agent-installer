param(
    [string]$RepoUrl = "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-agent",
    [string]$Ref = $(
        if ($env:WAZUH_AGENT_REPO_REF) { $env:WAZUH_AGENT_REPO_REF } else { 'fix/error-message-helper-function' }
    )
)

$env:WAZUH_AGENT_REPO_REF = $Ref
$env:WAZUH_AGENT_STATUS_REPO_REF = "user-main"
$env:INSTALL_CERT_AUTH = "TRUE"

Invoke-Expression (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-agent/refs/heads/${Ref}/scripts/setup-agent.ps1" -UseBasicParsing).Content
