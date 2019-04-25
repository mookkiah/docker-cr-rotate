#!/bin/sh

set -e

cat << LICENSE_ACK

# ========================================================================================= #
# Gluu License Agreement: https://github.com/GluuFederation/gluu-docker/blob/3.1.5/LICENSE. #
# The use of Gluu Server Docker Edition is subject to the Gluu Support License.             #
# ========================================================================================= #

LICENSE_ACK

if [ "$GLUU_CONTAINER_METADATA" != "docker" ] && [ "$GLUU_CONTAINER_METADATA" != "kubernetes" ]; then
    echo "Warning: invalid value for GLUU_CONTAINER_METADATA environment variable; fallback to Docker metadata"
    echo ""
    GLUU_CONTAINER_METADATA="docker"
fi

case $GLUU_CONTAINER_METADATA in
    "docker")
        ENTRYPOINT="/opt/cr-rotate/scripts/cr_rotating_docker.py"
        ;;
    "kubernetes")
        ENTRYPOINT="/opt/cr-rotate/scripts/cr_rotating_k8.py"
        ;;
esac

if [ -f /etc/redhat-release ]; then
    source scl_source enable python27 && python /opt/cr-rotate/scripts/wait_for.py --deps config,secret,ldap
    source scl_source enable python27 && python $ENTRYPOINT
else
    python /opt/cr-rotate/scripts/wait_for.py --deps config,secret,ldap
    python $ENTRYPOINT
fi
