$env:WAZUH_AGENT_REPO_REF = if ($env:WAZUH_AGENT_REPO_REF) { $env:WAZUH_AGENT_REPO_REF } else { "develop" }

Invoke-Expression (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-agent/develop/scripts/setup-agent.ps1" -UseBasicParsing).Content
