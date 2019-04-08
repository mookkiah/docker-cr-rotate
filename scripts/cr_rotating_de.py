#!/usr/bin/env python
# ------------------------------------
"""
updating cache refresh in gluu server
Author : Mohammad Abudayyeh
Email : mo@gluu.org
"""
import base64
import docker
import os
import pyDes
import shutil
from ldap3 import Server, Connection, MODIFY_REPLACE, MODIFY_ADD, MODIFY_DELETE, SUBTREE, ALL, BASE, LEVEL
from gluu_config import ConfigManager
import datetime


# Function to decrypt encoded password
def decrypt_text(encrypted_text, key):
    cipher = pyDes.triple_des(b"{}".format(key), pyDes.ECB,
                              padmode=pyDes.PAD_PKCS5)
    encrypted_text = b"{}".format(base64.b64decode(encrypted_text))
    return cipher.decrypt(encrypted_text)


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
    # Directory of Cache Refresh LDIF
    directory = "/cr/ldif"
    # Filename of Cache Refresh LDIF
    filename = "/crldif"
    # Docker URL
    docker_url = 'unix://var/run/docker.sock'
    # Docker Client
    client = docker.DockerClient(base_url=docker_url)
    # Empty list to hold oxtrust containers
    oxtrust_containers = client.containers.list(filters={'label': 'APP_NAME=oxtrust'})
    # Empty list to hold LDAP containers . Usually and almost always will only have one
    ldap_containers = client.containers.list(filters={'label': 'APP_NAME=opendj'})
    # Empty list to hold oxtrust containers IPs
    oxtrust_ip_pool = []
    bind_password_encoded = ''
    salt_code = ''
    bind_password = ''
    Label = ''
    #-------Method 2 LDAP ------------
    # Get URL of LDAP
    GLUU_LDAP_URL = os.environ.get("GLUU_LDAP_URL", "localhost:1636")
    # -------END_Method 2 LDAP ------------
    # Get Oxtrust and OpenDJ containers associated with APP_NAME label
    for container in oxtrust_containers:
            # Get IP of conatiner and send it to IP pool lost
            network_dict = container.attrs['NetworkSettings']['Networks']
            first_default_network_name = str(network_dict.keys()[0])
            ip = container.attrs['NetworkSettings']['Networks'][first_default_network_name]['IPAddress'].strip()
            oxtrust_ip_pool.append(ip)
    # No LDAP containers found
    if not ldap_containers:
        cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : '
                                + str('No LDAP found') + '\n')
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
                                 current_ip_in_ldap_LDAP.find("oxTrustCacheRefreshServerIpAddress: ") +
                                 len("oxTrustCacheRefreshServerIpAddress: "):].strip("\n")
            conn_ldap.search('ou=appliances,o=gluu', '(objectclass=gluuAppliance)',
                             attributes=['gluuVdsCacheRefreshEnabled'])
            is_cr_enabled_ldap_LDAP = str(conn_ldap.entries[0]).strip()
            is_cr_enabled = is_cr_enabled_ldap_LDAP[
                            is_cr_enabled_ldap_LDAP.find("gluuVdsCacheRefreshEnabled: "):].strip("\n").find("enabled")
        except Exception as e:
            cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' + str(e) + '\n')
        # ------- END_Method 2 LDAP -------
        for container in oxtrust_containers:
            network_dict = container.attrs['NetworkSettings']['Networks']
            first_default_network_name = str(network_dict.keys()[0])
            ip = container.attrs['NetworkSettings']['Networks'][first_default_network_name]['IPAddress'].strip()
            # The user has disabled the CR or CR is not active
            if is_cr_enabled < 0:
                cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' +
                                      str('Cache refresh is found to be disabled. Cleaning files...') + '\n')
                # Check if the path for the LDIF exists and if so remove it
                if os.path.isdir(directory):
                    try:
                        shutil.rmtree(directory)
                    except Exception as e:
                        cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' + str(e) + '\n')
            # Check  the container has not been setup previously, the CR is enabled
            if ip != current_ip_in_ldap and is_cr_enabled >= 0 and current_ip_in_ldap not in oxtrust_ip_pool:
                cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' +
                                      str("Current oxTrustCacheRefreshServerIpAddress :  ") +
                                      str(current_ip_in_ldap) + '\n')
                cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' +
                                      str("Updating oxTrustCacheRefreshServerIpAddress to ") + str(container.name)
                                      + ' holding id of ' + str(container.id) + ' with ip : ' + str(ip) + '\n')
                cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' +
                                      str("Cleaning cache folderes for  ") + str(container.name)
                                      + ' holding id of ' + str(container.id) + ' with ip : ' + str(ip) + '\n')
                # Clean cache folder at oxtrust container
                container.exec_run('rm -rf /var/ox/identity/cr-snapshots/')
                container.exec_run('mkdir /var/ox/identity/cr-snapshots/')
                container.exec_run('chown -R jetty:jetty /var/ox/identity/cr-snapshots/')
                try:
                    conn_ldap.modify(server_dn + ',ou=appliances,o=gluu',
                                     {'oxTrustCacheRefreshServerIpAddress': [(MODIFY_REPLACE, [ip])]})
                    cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' + str(conn_ldap.result) + '\n')
                except Exception as e:
                    cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' + str(e) + '\n')
# ------------------------------------
if __name__ == "__main__":
    main()
