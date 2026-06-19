#!/bin/sh
set -eu

curl -s "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-agent/refs/tags/v1.8.1-rc.2/scripts/setup-agent.sh" | bash -s -- "$@"