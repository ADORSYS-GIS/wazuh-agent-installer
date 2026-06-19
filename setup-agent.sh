#!/bin/sh
set -eu

curl -s "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-agent/refs/heads/main/scripts/setup-agent.sh" | bash -s -- "$@"