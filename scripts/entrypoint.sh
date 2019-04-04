#!/bin/sh

set -e

<<<<<<< HEAD
if [ "$GLUU_CONTAINER_METADATA" != "docker" ] || [ "$GLUU_CONTAINER_METADATA" != "kubernetes" ];then
	printf "Setting enviornment choice to default docker.\nIf you are running Kubernetes please change stop and run with GLUU_CONTAINER_METADATA kubernetes "
=======
if [ "$GLUU_CONTAINER_METADATA" = "" ];then
	printf "Setting enviornment choice to default docker.\nIf you are running Kubernetes please change. Stop now and run with GLUU_CONTAINER_METADATA kubernetes "
>>>>>>> 6d4fba31237f650959e40fe275cef3ae7755f367
	"$GLUU_CONTAINER_METADATA" = "docker"
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
