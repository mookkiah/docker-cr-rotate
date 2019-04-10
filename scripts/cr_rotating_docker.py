#!/usr/bin/env python
# ------------------------------------
"""
updating cache refresh in gluu server
Author : Mohammad Abudayyeh
"""
import base64
import logging
import os

import time
import docker
import pyDes

from ldap3 import Server, Connection, MODIFY_REPLACE
from gluu_config import ConfigManager


logger = logging.getLogger("cr_rotate")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
fmt = logging.Formatter('%(levelname)s - %(asctime)s - %(message)s')
ch.setFormatter(fmt)
logger.addHandler(ch)

signal_ip = '999.888.999.777'


# Function to decrypt encoded password
def decrypt_text(encrypted_text, key):
    cipher = pyDes.triple_des(b"{}".format(key), pyDes.ECB,
                              padmode=pyDes.PAD_PKCS5)
    encrypted_text = b"{}".format(base64.b64decode(encrypted_text))
    return cipher.decrypt(encrypted_text)


def get_container_ip(container):
    network_dict = container.attrs['NetworkSettings']['Networks']
    first_default_network_name = network_dict.keys()[0]
    return container.attrs['NetworkSettings']['Networks'][first_default_network_name]['IPAddress']


def clean_snapshot(container, ip):
    logger.info("Cleaning cache folders for {} holding ID of {} "
                "with IP {}".format(container.name, container.id, ip))
    container.exec_run('rm -rf /var/ox/identity/cr-snapshots/')
    container.exec_run('mkdir /var/ox/identity/cr-snapshots/')
    # container doesn't have `jetty` user/group
    # container.exec_run('chown -R jetty:jetty /var/ox/identity/cr-snapshots/')


def get_appliance(conn_ldap, inum):
    conn_ldap.search(
        'inum={},ou=appliances,o=gluu'.format(inum),
        '(objectclass=gluuAppliance)',
        attributes=['oxTrustCacheRefreshServerIpAddress',
                    'gluuVdsCacheRefreshEnabled'],
    )
    return conn_ldap.entries[0]


def update_appliance(conn_ldap, appliance, container, ip):
    try:
        logger.info("Updating oxTrustCacheRefreshServerIpAddress to {} "
                    "holding ID of {} with IP {}".format(container.name, container.id, ip))
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


def send_signal(conn_ldap, appliance):
    default_ip = '255.255.255.255'
    try:
        logger.info("No oxtrust containers found on this node. Provisioning other oxtrust containers at other nodes...")
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
                if check_ip != signal_ip or round(process_time) > 300.0:
                    check = True
                check_ip = appliance["oxTrustCacheRefreshServerIpAddress"]
                endtime = time.time()
                process_time = endtime - starttime

            if check_ip == signal_ip:
                # No nodes found . Reset to default
                conn_ldap.modify(appliance.entry_dn,
                                 {'oxTrustCacheRefreshServerIpAddress': [(MODIFY_REPLACE, [default_ip])]})
                result = conn_ldap.result

                if result["description"] == "success":
                    logger.info("No nodes found.Cache Refresh updated ip to default. Please add oxtrust containers")

                else:
                    logger.warn("Unable to update CacheRefresh to defaults; reason={}".format(result["message"]))

            else:
                logger.info("Oxtrust containers found at other nodes. Cache Refresh has been updated")

        else:
            logger.warn("Unable to send signal; reason={}".format(result["message"]))

    except Exception as e:
        logger.warn("Unable to update CacheRefresh config; reason={}".format(e))


def main():
    # check interval (by default per 10 mins)
    GLUU_CR_ROTATION_CHECK = os.environ.get("GLUU_CR_ROTATION_CHECK", 60 * 5)

    try:
        check_interval = int(GLUU_CR_ROTATION_CHECK)
    except ValueError:
        check_interval = 60 * 5

    config_manager = ConfigManager()

    # Docker URL
    docker_url = 'unix://var/run/docker.sock'

    # Docker Client
    client = docker.DockerClient(base_url=docker_url)

    # Get URL of LDAP
    GLUU_LDAP_URL = os.environ.get("GLUU_LDAP_URL", "localhost:1636")

    # Get creds for LDAP access
    bind_dn = config_manager.get("ldap_binddn")
    bind_password = decrypt_text(config_manager.get("encoded_ox_ldap_pw"), config_manager.get("encoded_salt"))

    ldap_server = Server(GLUU_LDAP_URL, port=1636, use_ssl=True)

    inum = config_manager.get("inumAppliance")

    try:
        while True:
            oxtrust_containers = client.containers.list(filters={'label': 'APP_NAME=oxtrust'})
            oxtrust_ip_pool = [get_container_ip(container) for container in oxtrust_containers]
            signalon = False

            with Connection(ldap_server, bind_dn, bind_password) as conn_ldap:
                appliance = get_appliance(conn_ldap, inum)
                current_ip_in_ldap = appliance["oxTrustCacheRefreshServerIpAddress"]
                is_cr_enabled = bool(appliance["gluuVdsCacheRefreshEnabled"] == "enabled")

                if current_ip_in_ldap in oxtrust_ip_pool and is_cr_enabled:
                    write_master_ip(current_ip_in_ldap)

                if check_master_ip(current_ip_in_ldap) and oxtrust_containers:
                    signalon = True

                if current_ip_in_ldap == signal_ip:
                    logger.info("Signal received. Setting new oxtrust container at this node to CacheRefresh ")
                    signalon = True

                if not oxtrust_containers and is_cr_enabled:
                    send_signal(conn_ldap, appliance)

                for container in oxtrust_containers:
                    ip = get_container_ip(container)

                    # The user has disabled the CR or CR is not active
                    if not is_cr_enabled:
                        # TODO: should we bail since CR is disabled?
                        logger.warn('Cache refresh is found to be disabled.')

                    # Check  the container has not been setup previously, the CR is enabled
                    if ip != current_ip_in_ldap and is_cr_enabled and current_ip_in_ldap not in oxtrust_ip_pool \
                            and signalon:
                        logger.info("Current oxTrustCacheRefreshServerIpAddress: {}".format(current_ip_in_ldap))

                        # Clean cache folder at oxtrust container
                        clean_snapshot(container, ip)
                        update_appliance(conn_ldap, appliance, container, ip)

            # delay
            time.sleep(check_interval)
    except KeyboardInterrupt:
        logger.warn("Canceled by user; exiting ...")


if __name__ == "__main__":
    main()
