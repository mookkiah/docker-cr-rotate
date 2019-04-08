#!/usr/bin/env python
# ------------------------------------
"""
updating cache refresh in gluu server
Author : Mohammad Abudayyeh
Email : mo@gluu.org
"""
# ------------------------------------
import base64
import os
import pyDes
import shutil
from kubernetes import client, config
from kubernetes.client import Configuration
from kubernetes.client.apis import core_v1_api
from kubernetes.client.rest import ApiException
from kubernetes.stream import stream
from ldap3 import Server, Connection, MODIFY_REPLACE, MODIFY_ADD, MODIFY_DELETE, SUBTREE, ALL, BASE, LEVEL
from gluu_config import ConfigManager
import datetime


# Function to decrypt encoded password
def decrypt_text(encrypted_text, key):
    cipher = pyDes.triple_des(b"{}".format(key), pyDes.ECB,
                              padmode=pyDes.PAD_PKCS5)
    encrypted_text = b"{}".format(base64.b64decode(encrypted_text))
    return cipher.decrypt(encrypted_text)


def get_kube():
    cli = None
    # XXX: is there a better way to check if we are inside a cluster or not?
    if "KUBERNETES_SERVICE_HOST" in os.environ:
        config.load_incluster_config()
        cli = client.CoreV1Api()
    else:
        try:
            # Load Kubernetes Configuration
            config.load_kube_config()
            c = Configuration()
            c.assert_hostname = False
            Configuration.set_default(c)
            # Set Kubernetes Client
            cli = core_v1_api.CoreV1Api()
        except FileNotFoundError:
            cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' +
                                  str('Creating directory : /cr/logs/') + '\n')

    return cli


def main():
    error = None
    if not os.path.isdir('/cr/logs'):
        try:
            os.makedirs('/cr/logs')
        except Exception as e:
            error = e
    cr_rotating_log = open("/cr/logs/cr_rotating.log", "a+")
    cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' +
                          str('Creating directory : /cr/logs/') + str(error) + '\n')
    config_manager = ConfigManager()
    cli = get_kube()
    # Get a list of all available pods

    pods = cli.list_pod_for_all_namespaces().items
    # Empty list to hold oxtrust pods
    #oxtrust_pods = cli.list_namespaced_pod(label_selector='APP_NAME=oxtrust')
    oxtrust_pods = []
    # Empty list to hold LDAP containers . Usually and almost always will only have one
    ldap_pods = []
    #ldap_pods = cli.list_namespaced_pod(label_selector='APP_NAME=opendj')
    bind_password_encoded = ''
    salt_code = ''
    bind_password = ''
    # Empty list to hold oxtrust pods IPs
    oxtrust_ip_pool = []
    #-------Method 2 LDAP ------------
    # Get URL of LDAP
    GLUU_LDAP_URL = os.environ.get("GLUU_LDAP_URL", "localhost:1636")
    # -------END_Method 2 LDAP ------------
    # Open cache refresh log file
    # Get Oxtrust and OpenDJ pods associated with APP_NAME label
    for pod in pods:
        try:
            if "opendj" in pod.metadata.labels['APP_NAME']:
                ldap_pods.append(pod)
            if "oxtrust" in pod.metadata.labels['APP_NAME']:
                oxtrust_pods.append(pod)
                # Get IP of pod and send it to IP pool lost
                ip = pod.status.pod_ip
                oxtrust_ip_pool.append(ip)
        except Exception as e:
            cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' + str(e) + '\n')
    # No LDAP pods found
    if not ldap_pods:
        cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' + str('No LDAP found') + '\n')
    # Get bind password
    try:
        bind_dn = config_manager.get("ldap_binddn")
        bind_password = decrypt_text(config_manager.get("encoded_ox_ldap_pw"), config_manager.get("encoded_salt"))
        ldap_server = Server(GLUU_LDAP_URL, port=1636, use_ssl=True)
        conn_ldap = Connection(ldap_server, bind_dn, bind_password)
        conn_ldap.bind()
    except Exception as e:
        cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' + str(e) + '\n')
    # ------- END_Method 2 using consul ----------
    if bind_password:
        try:
            # Same structure as above but using LDAP
            conn_ldap.search('ou=appliances,o=gluu', '(objectclass=gluuAppliance)', attributes='inum')
            server_dn_LDAP = str(conn_ldap.entries[0]).strip()
            server_dn_ldap = server_dn_LDAP[server_dn_LDAP.find("inum: "):].strip("\n")
            server_dn = "inum=" + server_dn_ldap[server_dn_ldap.find("m:") + 3:]
            conn_ldap.search('ou=appliances,o=gluu', '(objectclass=gluuAppliance)',
                             attributes='oxTrustCacheRefreshServerIpAddress')
            current_ip_in_ldap_LDAP = str(conn_ldap.entries[0]).strip()
            current_ip_in_ldap = current_ip_in_ldap_LDAP[
                                      current_ip_in_ldap_LDAP.find("oxTrustCacheRefreshServerIpAddress: ") + len(
                                          "oxTrustCacheRefreshServerIpAddress: "):].strip("\n")
            conn_ldap.search('ou=appliances,o=gluu', '(objectclass=gluuAppliance)',
                             attributes=['gluuVdsCacheRefreshEnabled'])
            is_cr_enabled_ldap_LDAP = str(conn_ldap.entries[0]).strip()
            is_cr_enabled = is_cr_enabled_ldap_LDAP[
                                 is_cr_enabled_ldap_LDAP.find("gluuVdsCacheRefreshEnabled: "):].strip(
                "\n").find("enabled")
        except Exception as e:
            cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' + str(e) + '\n')
        for oxtrust_pod in oxtrust_pods:
            ip = oxtrust_pod.status.pod_ip
            # The user has disabled the CR or CR is not active
            if is_cr_enabled < 0:
                cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' +
                                        str('Cache refresh is found to be disabled. Cleaning files...') + '\n')

            # Check  is the current ip of oxtrust pod is not the same as the one in oxTrustCacheRefreshServerIpAddress
            # Check is CR is Enabled
            # Check that the oxTrustCacheRefreshServerIpAddress is not in the oxtrust_ip_pool
            if ip != current_ip_in_ldap and is_cr_enabled >= 0 and current_ip_in_ldap not in oxtrust_ip_pool:
                cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' +
                                      str("Current oxTrustCacheRefreshServerIpAddress :  ") +
                                      str(current_ip_in_ldap) + '\n')
                cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' +
                                      str("Updating oxTrustCacheRefreshServerIpAddress to ") +
                                      str(oxtrust_pod.metadata.name) + ' with ip : ' + str(ip) + '\n')


                # Clean cache folder at oxtrust pod
                stream(cli.connect_get_namespaced_pod_exec, oxtrust_pod.metadata.name, oxtrust_pod.metadata.namespace,
                       command=['/bin/sh','-c','rm -rf /var/ox/identity/cr-snapshots'],
                       stderr=True, stdin=True,
                       stdout=True, tty=False)
                stream(cli.connect_get_namespaced_pod_exec, oxtrust_pod.metadata.name, oxtrust_pod.metadata.namespace,
                       command=['/bin/sh','-c','mkdir -p /var/ox/identity/cr-snapshots'],
                       stderr=True, stdin=True,
                       stdout=True, tty=False)
                stream(cli.connect_get_namespaced_pod_exec, oxtrust_pod.metadata.name, oxtrust_pod.metadata.namespace,
                       command=['/bin/sh','-c','chown -R jetty:jetty /var/ox/identity/cr-snapshots'],
                       stderr=True, stdin=True,
                       stdout=True, tty=False)

                try:
                    conn_ldap.modify(server_dn + ',ou=appliances,o=gluu',
                                {'oxTrustCacheRefreshServerIpAddress': [(MODIFY_REPLACE, [ip])]})
                    cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' + str(conn_ldap.result) + '\n')
                except Exception as e:
                    cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' + str(e) + '\n')
# ------------------------------------


if __name__ == "__main__":
    main()

