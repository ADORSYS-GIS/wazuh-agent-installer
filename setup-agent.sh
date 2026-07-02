#!/bin/sh
set -eu

curl -s "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-agent/refs/tags/v1.8.0/scripts/setup-agent.sh" | bash -s -- "$@"
