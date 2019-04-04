#!/bin/sh

set -e

if [ "$GLUU_CONTAINER_METADATA" != "docker" ] || [ "$GLUU_CONTAINER_METADATA" != "kubernetes" ];then
	printf "Setting enviornment choice to default docker.\n
	If you are running Kubernetes please change stop and run with GLUU_CONTAINER_METADATA kubernetes "
fi

if [ "$GLUU_CONTAINER_METADATA" = "docker" ];then
	if [ -f /etc/redhat-release ]; then
		source scl_source enable python27 && python /opt/cr-rotate/scripts/cr_rotating_de.py
	else
		python /opt/cr-rotate/scripts/cr_rotating_de.py
	fi
fi

if [ "$GLUU_CONTAINER_METADATA" = "kubernetes" ];then
	if [ -f /etc/redhat-release ]; then
		source scl_source enable python27 && python /opt/cr-rotate/scripts/cr_rotating_k8.py
	else
		python /opt/cr-rotate/scripts/cr_rotating_k8.py
	fi
fi
