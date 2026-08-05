export WAZUH_AGENT_REPO_REF="${WAZUH_AGENT_REPO_REF:-v1.8.1-rc.1}"

curl -s "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-agent/${WAZUH_AGENT_REPO_REF}/scripts/setup-agent.sh?t=$(date +%s)" | bash -s -- "$@"
