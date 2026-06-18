#!/bin/sh
set -eu

export WAZUH_AGENT_REPO_REF="${WAZUH_AGENT_REPO_REF:-fix/error-message-helper-function}"
export WAZUH_AGENT_STATUS_REPO_REF="user-main"
export INSTALL_CERT_AUTH="TRUE"

curl -s "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-agent/refs/heads/${WAZUH_AGENT_REPO_REF}/scripts/setup-agent.sh" | bash -s -- "$@"