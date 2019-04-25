#!/usr/bin/env python
# ------------------------------------
"""
updating cache refresh in gluu server
Author : Mohammad Abudayyeh
"""
# ------------------------------------
import base64
import logging
import os
import sys
import time

import pyDes
from kubernetes import client, config
from kubernetes.stream import stream
from ldap3 import Server, Connection, MODIFY_REPLACE

from gluulib import get_manager

logger = logging.getLogger("cr_rotate")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
fmt = logging.Formatter('%(levelname)s - %(asctime)s - %(message)s')
ch.setFormatter(fmt)
logger.addHandler(ch)

signal_ip = '999.888.999.777'
default_ip = '255.255.255.255'


# Function to decrypt encoded password
def decrypt_text(encrypted_text, key):
    cipher = pyDes.triple_des(b"{}".format(key), pyDes.ECB,
                              padmode=pyDes.PAD_PKCS5)
    encrypted_text = b"{}".format(base64.b64decode(encrypted_text))
    return cipher.decrypt(encrypted_text)


def get_pod_ip(pod):
    return pod.status.pod_ip


def clean_snapshot(pod, ip, connector):
    logger.info("Cleaning cache folders for {} with IP {}".format(pod.metadata.name, ip))
    stream(connector, pod.metadata.name, pod.metadata.namespace,
           command=['/bin/sh', '-c', 'rm -rf /var/ox/identity/cr-snapshots'],
           stderr=True, stdin=True,
           stdout=True, tty=False)
    stream(connector, pod.metadata.name, pod.metadata.namespace,
           command=['/bin/sh', '-c', 'mkdir -p /var/ox/identity/cr-snapshots'],
           stderr=True, stdin=True,
           stdout=True, tty=False)
    # pod doesn't have `jetty` user/group
    # stream(cli.connect_get_namespaced_pod_exec, pod.metadata.name, pod.metadata.namespace,
    #       command=['/bin/sh', '-c', 'chown -R jetty:jetty /var/ox/identity/cr-snapshots'],
    #       stderr=True, stdin=True,
    #       stdout=True, tty=False)


def get_appliance(conn_ldap, inum):
    conn_ldap.search(
        'inum={},ou=appliances,o=gluu'.format(inum),
        '(objectclass=gluuAppliance)',
        attributes=['oxTrustCacheRefreshServerIpAddress',
                    'gluuVdsCacheRefreshEnabled'],
    )
    return conn_ldap.entries[0]


def update_appliance(conn_ldap, appliance, pod, ip):
    try:
        logger.info("Updating oxTrustCacheRefreshServerIpAddress to {} with IP {}".format(pod.metadata.name, ip))
        conn_ldap.modify(appliance.entry_dn,
                         {'oxTrustCacheRefreshServerIpAddress': [(MODIFY_REPLACE, [ip])]})
        result = conn_ldap.result
        if result["description"] == "success":
            logger.info("CacheRefresh config has been updated")
        else:
            logger.warn("Unable to update CacheRefresh config; reason={}".format(result["message"]))
    except Exception as e:
        logger.warn("Unable to update CacheRefresh config; reason={}".format(e))


def write_master_ip(ip):
    with open('/cr/ip_file.txt', 'w+') as ip_file:
        ip_file.write(str(ip))


def check_master_ip(ip):
    with open('/cr/ip_file.txt', 'a+') as ip_file:
        ip_master = ip_file.read().strip()
    if str(ip) in ip_master:
        return True
    return False


def send_signal(conn_ldap, inum):
    try:
        appliance = get_appliance(conn_ldap, inum)
        logger.info("No oxtrust pods found on this node. Provisioning other oxtrust pods at other nodes...")
        conn_ldap.modify(appliance.entry_dn,
                         {'oxTrustCacheRefreshServerIpAddress': [(MODIFY_REPLACE, [signal_ip])]})
        result = conn_ldap.result
        if result["description"] == "success":
            logger.info("Signal has been sent")
            logger.info("Waiting for response...It may take up to 5 mins")
            check_ip = appliance["oxTrustCacheRefreshServerIpAddress"]
            process_time = 0
            check = False
            starttime = time.time()
            while not check:
                check_ip = appliance["oxTrustCacheRefreshServerIpAddress"]
                logger.info("CHECK IP: {}".format(check_ip))
                endtime = time.time()
                process_time = endtime - starttime
                if check_ip != signal_ip or round(process_time) > 300.0:
                    check = True
                time.sleep(5)
            if check_ip == signal_ip:
                # No nodes found . Reset to default
                conn_ldap.modify(appliance.entry_dn,
                                 {'oxTrustCacheRefreshServerIpAddress': [(MODIFY_REPLACE, [default_ip])]})
                result = conn_ldap.result
                if result["description"] == "success":
                    logger.info("No nodes found.Cache Refresh updated ip to default. Please add oxtrust pods")
                else:
                    logger.warn("Unable to update CacheRefresh to defaults; reason={}".format(result["message"]))
            else:
                logger.info("Oxtrust pods found at other nodes. Cache Refresh has been updated")
        else:
            logger.warn("Unable to send signal; reason={}".format(result["message"]))
    except Exception as e:
        logger.warn("Unable to update CacheRefresh config; reason={}".format(e))


def get_kube_conf():
    config_loaded = False

    try:
        config.load_incluster_config()
        config_loaded = True
    except config.config_exception.ConfigException:
        logger.warn("Unable to load in-cluster configuration; trying to load from Kube config file")
        try:
            config.load_kube_config()
            config_loaded = True
        except (IOError, config.config_exception.ConfigException) as exc:
            logger.warn("Unable to load Kube config; reason={}".format(exc))

    if not config_loaded:
        logger.error("Unable to load in-cluster or Kube config")
        sys.exit(1)

    cli = client.CoreV1Api()
    cli.api_client.configuration.assert_hostname = False
    return cli


def main():
    # check interval (by default per 5 mins)
    GLUU_CR_ROTATION_CHECK = os.environ.get("GLUU_CR_ROTATION_CHECK", 60 * 5)

    try:
        check_interval = int(GLUU_CR_ROTATION_CHECK)
    except ValueError:
        check_interval = 60 * 5

    manager = get_manager()

    cli = get_kube_conf()

    # Get URL of LDAP
    GLUU_LDAP_URL = os.environ.get("GLUU_LDAP_URL", "localhost:1636")

    bind_dn = manager.config.get("ldap_binddn")
    bind_password = decrypt_text(manager.secret.get("encoded_ox_ldap_pw"), manager.secret.get("encoded_salt"))

    ldap_server = Server(GLUU_LDAP_URL, port=1636, use_ssl=True)

    inum = manager.config.get("inumAppliance")

    try:
        while True:
            # Get a list of oxtrust pods
            oxtrust_pods = cli.list_pod_for_all_namespaces(label_selector='APP_NAME=oxtrust').items
            oxtrust_ip_pool = [get_pod_ip(pod) for pod in oxtrust_pods]
            signalon = False

            with Connection(ldap_server, bind_dn, bind_password) as conn_ldap:
                appliance = get_appliance(conn_ldap, inum)
                current_ip_in_ldap = appliance["oxTrustCacheRefreshServerIpAddress"]
                is_cr_enabled = bool(appliance["gluuVdsCacheRefreshEnabled"] == "enabled")

                if current_ip_in_ldap in oxtrust_ip_pool and is_cr_enabled:
                    write_master_ip(current_ip_in_ldap)

                if check_master_ip(current_ip_in_ldap) and oxtrust_pods:
                    signalon = True

                if current_ip_in_ldap == signal_ip:
                    logger.info("Signal received. Setting new oxtrust pod at this node to CacheRefresh ")
                    signalon = True

                if not oxtrust_pods and is_cr_enabled:
                    send_signal(conn_ldap, inum)

                if current_ip_in_ldap == default_ip and is_cr_enabled and oxtrust_pods:
                    logger.info("Oxtrust pods found after resetting to defaults.")
                    signalon = True

                for pod in oxtrust_pods:
                    ip = get_pod_ip(pod)

                    # The user has disabled the CR or CR is not active
                    if not is_cr_enabled:
                        # TODO: should we bail since CR is disabled?
                        logger.warn('Cache refresh is found to be disabled.')

                    appliance = get_appliance(conn_ldap, inum)
                    current_ip_in_ldap = appliance["oxTrustCacheRefreshServerIpAddress"]
                    is_cr_enabled = bool(appliance["gluuVdsCacheRefreshEnabled"] == "enabled")
                    # Check  the pod has not been setup previously, the CR is enabled
                    if ip != current_ip_in_ldap and is_cr_enabled and current_ip_in_ldap not in oxtrust_ip_pool \
                            and signalon:
                        logger.info("Current oxTrustCacheRefreshServerIpAddress: {}".format(current_ip_in_ldap))

                        # Clean cache folder at oxtrust pod
                        clean_snapshot(pod, ip, cli.connect_get_namespaced_pod_exec)
                        update_appliance(conn_ldap, appliance, pod, ip)
            # delay
            time.sleep(check_interval)
    except KeyboardInterrupt:
        logger.warn("Canceled by user; exiting ...")


if __name__ == "__main__":
    main()
