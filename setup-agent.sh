#!/bin/sh
set -eu

curl -s "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-agent/refs/tags/v1.9.0-rc.5/scripts/setup-agent.sh" | bash -s -- "$@"