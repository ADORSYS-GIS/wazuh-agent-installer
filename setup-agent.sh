#!/bin/sh
set -eu

curl -s "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-agent/refs/heads/fix/error-message-helper-function/scripts/setup-agent.sh" | bash -s -- "$@"