"""
updating cache refresh in gluu server
Author : Mohammad Abudayyeh
"""
import base64
import logging
import os
import sys
import time

import docker
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


def decrypt_text(encrypted_text, key):
    """Decodes encoded text.
    """
    cipher = pyDes.triple_des(b"{}".format(key), pyDes.ECB,
                              padmode=pyDes.PAD_PKCS5)
    encrypted_text = b"{}".format(base64.b64decode(encrypted_text))
    return cipher.decrypt(encrypted_text)


class BaseClient(object):
    def get_oxtrust_containers(self):
        """Gets oxTrust containers.

        Subclass __MUST__ implement this method.
        """
        raise NotImplementedError

    def get_container_ip(self, container):
        """Gets container's IP address.

        Subclass __MUST__ implement this method.
        """
        raise NotImplementedError

    def clean_snapshot(self, container):
        """Cleanups cache refresh snapshots directory.

        Subclass __MUST__ implement this method.
        """
        raise NotImplementedError


class DockerClient(BaseClient):
    def __init__(self, base_url="unix://var/run/docker.sock"):
        self.client = docker.DockerClient(base_url=base_url)

    def get_oxtrust_containers(self):
        return self.client.containers.list(filters={'label': 'APP_NAME=oxtrust'})

    def get_container_ip(self, container):
        # networks = container.attrs["NetworkSettings"]
        # network = container.attrs["NetworkSettings"]["Networks"].keys()[0]
        # return network["IPAddress"]
        for _, network in container.attrs["NetworkSettings"]["Networks"].iteritems():
            return network["IPAddress"]

    def clean_snapshot(self, container):
        logger.info(
            "Cleaning cache folders for {} with IP {}".format(
                container.name, self.get_container_ip(container),
            )
        )
        container.exec_run("rm -rf /var/ox/identity/cr-snapshots/")
        container.exec_run("mkdir -p /var/ox/identity/cr-snapshots")


class KubernetesClient(BaseClient):
    def __init__(self):
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
        self.client = cli

    def get_oxtrust_containers(self):
        return self.client.list_pod_for_all_namespaces(
            label_selector='APP_NAME=oxtrust'
        ).items

    def get_container_ip(self, container):
        return container.status.pod_ip

    def clean_snapshot(self, container):
        logger.info(
            "Cleaning cache folders for {} with IP {}".format(
                container.metadata.name, self.get_container_ip(container)
            )
        )

        stream(
            self.client.connect_get_namespaced_pod_exec,
            container.metadata.name,
            container.metadata.namespace,
            command=['/bin/sh', '-c', 'rm -rf /var/ox/identity/cr-snapshots'],
            stderr=True,
            stdin=True,
            stdout=True,
            tty=False,
        )

        stream(
            self.client.connect_get_namespaced_pod_exec,
            container.metadata.name,
            container.metadata.namespace,
            command=['/bin/sh', '-c', 'mkdir -p /var/ox/identity/cr-snapshots'],
            stderr=True,
            stdin=True,
            stdout=True,
            tty=False,
        )


def get_configuration(conn_ldap):
    conn_ldap.search(
        "ou=configuration,o=gluu",
        '(objectclass=gluuConfiguration)',
        attributes=['oxTrustCacheRefreshServerIpAddress',
                    'gluuVdsCacheRefreshEnabled'],
    )
    return conn_ldap.entries[0]


def update_configuration(conn_ldap, configuration, ip):
    try:
        conn_ldap.modify(
            configuration.entry_dn,
            {'oxTrustCacheRefreshServerIpAddress': [(MODIFY_REPLACE, [ip])]}
        )
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


def send_signal(conn_ldap):
    try:
        config = get_configuration(conn_ldap)
        logger.info("No oxtrust containers found on this node. Provisioning other oxtrust containers at other nodes...")
        conn_ldap.modify(config.entry_dn,
                         {'oxTrustCacheRefreshServerIpAddress': [(MODIFY_REPLACE, [signal_ip])]})
        result = conn_ldap.result

        if result["description"] == "success":
            check_ip = config["oxTrustCacheRefreshServerIpAddress"]
            logger.info("Signal has been sent")
            logger.info("Waiting for response...It may take up to 5 mins")
            process_time = 0
            check = False
            starttime = time.time()

            while not check:
                config = get_configuration(conn_ldap)
                check_ip = config["oxTrustCacheRefreshServerIpAddress"]
                endtime = time.time()
                process_time = endtime - starttime

                if check_ip != signal_ip or round(process_time) > 300.0:
                    check = True

                time.sleep(5)

            if check_ip == signal_ip:
                # No nodes found . Reset to default
                conn_ldap.modify(config.entry_dn,
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
    GLUU_CONTAINER_METADATA = os.environ.get("GLUU_CONTAINER_METADATA", "docker")

    # check interval (by default per 5 mins)
    GLUU_CR_ROTATION_CHECK = os.environ.get("GLUU_CR_ROTATION_CHECK", 60 * 5)

    try:
        check_interval = int(GLUU_CR_ROTATION_CHECK)
    except ValueError:
        check_interval = 60 * 5

    manager = get_manager()

    # Get creds for LDAP access
    bind_dn = manager.config.get("ldap_binddn")
    bind_password = decrypt_text(manager.secret.get("encoded_ox_ldap_pw"), manager.secret.get("encoded_salt"))

    if GLUU_CONTAINER_METADATA == "kubernetes":
        client = KubernetesClient()
    else:
        client = DockerClient()

    # Get URL of LDAP
    GLUU_LDAP_URL = os.environ.get("GLUU_LDAP_URL", "localhost:1636")
    ldap_server = Server(GLUU_LDAP_URL, port=1636, use_ssl=True)

    try:
        while True:
            oxtrust_containers = client.get_oxtrust_containers()
            oxtrust_ip_pool = [client.get_container_ip(container) for container in oxtrust_containers]
            signalon = False

            with Connection(ldap_server, bind_dn, bind_password) as conn_ldap:
                config = get_configuration(conn_ldap)
                current_ip_in_ldap = config["oxTrustCacheRefreshServerIpAddress"]
                is_cr_enabled = config["gluuVdsCacheRefreshEnabled"] in ("enabled", True)

                if current_ip_in_ldap in oxtrust_ip_pool and is_cr_enabled:
                    write_master_ip(current_ip_in_ldap)

                if check_master_ip(current_ip_in_ldap) and oxtrust_containers:
                    signalon = True

                if current_ip_in_ldap == signal_ip:
                    logger.info("Signal received. Setting new oxtrust container at this node to CacheRefresh ")
                    signalon = True

                if not oxtrust_containers and is_cr_enabled:
                    send_signal(conn_ldap)

                # If no oxtrust was found the previous would set ip to default. If later oxtrust was found
                if current_ip_in_ldap == default_ip and is_cr_enabled and oxtrust_containers:
                    logger.info("Oxtrust containers found after resetting to defaults.")
                    signalon = True

                for container in oxtrust_containers:
                    ip = client.get_container_ip(container)

                    # The user has disabled the CR or CR is not active
                    if not is_cr_enabled:
                        logger.warn('Cache refresh is found to be disabled.')

                    config = get_configuration(conn_ldap)
                    current_ip_in_ldap = config["oxTrustCacheRefreshServerIpAddress"]
                    is_cr_enabled = config["gluuVdsCacheRefreshEnabled"] in ("enabled", True)

                    # Check  the container has not been setup previously, the CR is enabled
                    if ip != current_ip_in_ldap and is_cr_enabled and current_ip_in_ldap not in oxtrust_ip_pool \
                            and signalon:
                        logger.info("Current oxTrustCacheRefreshServerIpAddress: {}".format(current_ip_in_ldap))

                        # Clean cache folder at oxtrust container
                        client.clean_snapshot(container)

                        logger.info("Updating oxTrustCacheRefreshServerIpAddress to {} with IP {}".format(container.name, ip))
                        update_configuration(conn_ldap, config, ip)

            # delay
            time.sleep(check_interval)
    except KeyboardInterrupt:
        logger.warn("Canceled by user; exiting ...")


if __name__ == "__main__":
    main()
