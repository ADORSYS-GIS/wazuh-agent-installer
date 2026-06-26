#!/bin/sh
set -eu

curl -s "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-agent/develop/scripts/setup-agent.sh" | bash -s -- "$@"