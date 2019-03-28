#!/bin/sh

set -e

if [ -f /etc/redhat-release ]; then
    source scl_source enable python27 && python /opt/cr-rotate/scripts/cr_rotating_de.py
else
    python /opt/cr-rotate/scripts/cr_rotating_de.py
fi
