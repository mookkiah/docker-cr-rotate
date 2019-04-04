#!/bin/sh

set -e

cat << LICENSE_ACK

# ========================================================================================= #
# Gluu License Agreement: https://github.com/GluuFederation/gluu-docker/blob/3.1.4/LICENSE. #
# The use of Gluu Server Docker Edition is subject to the Gluu Support License.             #
# ========================================================================================= #

LICENSE_ACK

if [ "$GLUU_CONTAINER_METADATA" != "docker" ] && [ "$GLUU_CONTAINER_METADATA" != "kubernetes" ]; then
    echo "Warning: invalid value for GLUU_CONTAINER_METADATA environment variable; fallback to Docker metadata"
    echo ""
    GLUU_CONTAINER_METADATA=docker
fi

if [ "$GLUU_CONTAINER_METADATA" = "docker" ]; then
	if [ -f /etc/redhat-release ]; then
		source scl_source enable python27 && python /opt/cr-rotate/scripts/cr_rotating_de.py
	else
		python /opt/cr-rotate/scripts/cr_rotating_de.py
	fi
fi

if [ "$GLUU_CONTAINER_METADATA" = "kubernetes" ]; then
	if [ -f /etc/redhat-release ]; then
		source scl_source enable python27 && python /opt/cr-rotate/scripts/cr_rotating_k8.py
	else
		python /opt/cr-rotate/scripts/cr_rotating_k8.py
	fi
fi
