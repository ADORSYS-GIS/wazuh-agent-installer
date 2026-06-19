#!/bin/sh
set -eu

curl -s "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-agent/refs/heads/chore/release-v1.8.1/scripts/setup-agent.sh" | bash -s -- "$@"