#!/bin/sh
set -eu

# Default to the develop branch so inner scripts resolve correctly;
# users can override by setting WAZUH_AGENT_REPO_REF themselves.
export WAZUH_AGENT_REPO_REF="${WAZUH_AGENT_REPO_REF:-v1.8.1-rc.1}"

curl -s "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-agent/${WAZUH_AGENT_REPO_REF}/scripts/setup-agent.sh" | bash -s -- "$@"
