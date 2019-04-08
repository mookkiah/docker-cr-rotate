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
import tarfile
import shutil
from ldap3 import Server, Connection, MODIFY_REPLACE, MODIFY_ADD, MODIFY_DELETE, SUBTREE, ALL, BASE, LEVEL
from gluu_config import ConfigManager
import datetime


# Function to copy files from source to destination
def copy_to(src, container, dst):
    os.chdir(os.path.dirname(src))
    srcname = os.path.basename(src)
    tar = tarfile.open(src + '.tar', mode='w')
    try:
        tar.add(srcname)
    finally:
        tar.close()
    data = open(src + '.tar', 'rb').read()
    container.put_archive(os.path.dirname(dst), data)


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
            # Return oxtrust server DN
            server_dn = ldap_containers[0].exec_run(
                '/opt/opendj/bin/ldapsearch -h localhost -p 1636 -Z -X -D "cn=directory manager" -w ' + str(
                    bind_password) + ' -b "ou=appliances,o=gluu"  "inum=*" | grep dn').output.strip()
            # Return oxtrust conf cache refresh
            oxtrust_conf_cache_refresh = ldap_containers[0].exec_run('/opt/opendj/bin/ldapsearch -h localhost -p 1636 '
                                                                     '-Z -X -D "cn=directory manager" -w ' +
                                                                     str(bind_password) +
                                                                     ' -b "o=gluu" '
                                                                     '-T "objectClass=oxTrustConfiguration"'
                                                                     ' oxTrustCacheRefreshServerIpAddress \ | '
                                                                     'grep "^oxTrustCacheRefreshServerIpAddress"')\
                .output.strip()
            # Get the currently set ip in ldap oxTrustCacheRefreshServerIpAddress
            current_ip_in_ldap = ldap_containers[0].exec_run('/opt/opendj/bin/ldapsearch -h localhost -p 1636 -Z -X -D '
                                                             '"cn=directory manager" -w ' + str(bind_password)
                                                             + ' -b "ou=appliances,o=gluu"  "inum=*" | '
                                                               'grep "^oxTrustCacheRefreshServerIpAddress"')\
                .output.strip()
            current_ip_in_ldap = current_ip_in_ldap[current_ip_in_ldap.find("oxTrustCacheRefreshServerIpAddress: ") +
                                                    len("oxTrustCacheRefreshServerIpAddress: "):].strip("\n")
            # From the oxtrust conf cache refresh extract cache refresh conf
            cache_refresh_conf = oxtrust_conf_cache_refresh[oxtrust_conf_cache_refresh.find("oxTrustConf"
                                                                                            "CacheRefresh: {"):].strip()
            # From the oxtrust conf cache refresh extract oxtrust conf cache refresh DN
            conf_dn = oxtrust_conf_cache_refresh[oxtrust_conf_cache_refresh.find("dn:"):
                                                 oxtrust_conf_cache_refresh.find("oxTrustConfCacheRefresh")].strip()
            # Returns an index number if -1 disabled and if => 0 enabled
            is_cr_enabled = ldap_containers[0].exec_run('/opt/opendj/bin/ldapsearch -h localhost -p 1636 -Z -X -D'
                                                        ' "cn=directory manager" -w ' + str(bind_password) +
                                                        ' -b "ou=appliances,o=gluu" "gluuVdsCacheRefreshEnabled=*" '
                                                        'gluuVdsCacheRefreshEnabled \ | grep -Pzo "enabled"')\
                .output.find("enabled")
        except Exception as e:
            cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' + str(e) + '\n')
        # ------- Method 2 LDAP -------
        try:
            # Same structure as above but using LDAP
            conn_ldap.search('o=gluu', '(objectclass=oxTrustConfiguration)', attributes='oxTrustConfCacheRefresh')
            oxtrust_conf_cache_refresh_LDAP = str(conn_ldap.entries[0]).strip()
            cache_refresh_conf_ldap = oxtrust_conf_cache_refresh_LDAP[
                                 oxtrust_conf_cache_refresh_LDAP.find("oxTrustConfCacheRefresh: "):].strip("\n")
            conn_ldap.search('ou=appliances,o=gluu', '(objectclass=gluuAppliance)', attributes='inum')
            server_dn_LDAP = str(conn_ldap.entries[0]).strip()
            server_dn_ldap = server_dn_LDAP[server_dn_LDAP.find("inum: "):].strip("\n")
            server_dn_ldap = "inum=" + server_dn_ldap[server_dn_ldap.find("m:") + 3:]
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
            # Check  the container has not been setup previosly, the CR is enabled
            if ip != current_ip_in_ldap and is_cr_enabled >= 0 and current_ip_in_ldap not in oxtrust_ip_pool:
                cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' +
                                      str("Current oxTrustCacheRefreshServerIpAddress :  ") +
                                      str(current_ip_in_ldap) + '\n')
                cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' +
                                      str("Updating oxTrustCacheRefreshServerIpAddress to ") + str(container.name)
                                      + ' holding id of ' + str(container.id) + ' with ip : ' + str(ip) + '\n')
                if not os.path.isdir(directory):
                    try:
                        os.makedirs(directory)
                        cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' +
                                              str('Creating directory : ') + directory + '\n')
                    except Exception as e:
                        cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' + str(e) + '\n')
                # Clear contents of file at CR rotate container
                open(directory + filename, 'w+').close()
                cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' +
                                      str('Writing LDIF to  : ') + directory + filename + '\n')
                # Format and concatenate ldifdata
                ldifdata = str(
                    server_dn) + "\nchangetype: modify\nreplace: oxTrustCacheRefreshServerIpAddress\n" \
                                 "oxTrustCacheRefreshServerIpAddress: " + str(
                    ip) + "\n\n" + str(conf_dn) + "\nchangetype: modify\nreplace: oxTrustConfCacheRefresh\n" + str(
                    cache_refresh_conf)
                ldif = open(directory + filename, "w+")
                ldif.write(ldifdata)
                ldif.close()
                cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' +
                                      str("Cleaning cache folderes for  ") + str(container.name)
                                      + ' holding id of ' + str(container.id) + ' with ip : ' + str(ip) + '\n')
                # Clean cache folder at oxtrust container
                container.exec_run('rm -rf /var/ox/identity/cr-snapshots/')
                container.exec_run('mkdir /var/ox/identity/cr-snapshots/')
                container.exec_run('chown -R jetty:jetty /var/ox/identity/cr-snapshots/')
                cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' +
                                      str('Creating file  : ') + directory + filename + ' at ' +
                                      str(ldap_containers[0].name) + ' holding id of ' +
                                      str(ldap_containers[0].id) + '\n')
                ldap_containers[0].exec_run(' mkdir -p ' + directory)
                cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' +
                                      str('Copying LDIF to  : ') + str(ldap_pods[0].name) + '\n')
                copy_to(directory + filename, ldap_containers[0], directory + filename)
                ldap_modify_status = ldap_containers[0].exec_run(
                    '/opt/opendj/bin/ldapmodify -D "cn=directory manager" -w ' + bind_password +
                    ' -h localhost -p 1636 --useSSL --trustAll -f ' + directory + filename).output
                cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' + str(ldap_modify_status) + '\n')
                # Clean up files
                cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' +
                                      str('Cleaning files at  : ') + str(ldap_pods[0].name) + '\n')
                ldap_containers[0].exec_run('rm -rf ' + directory + filename)
                # ------- Method 2 LDAP -------
                try:
                    conn_ldap.modify(server_dn_ldap + ',ou=appliances,o=gluu',
                                     {'oxTrustCacheRefreshServerIpAddress': [(MODIFY_REPLACE, [ip])]})
                    cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' + str(conn_ldap.result) + '\n')
                    conn_ldap.modify('ou=oxtrust,ou=configuration,' + server_dn_ldap + ',ou=appliances,o=gluu',
                                     {'oxTrustConfCacheRefresh': [(MODIFY_REPLACE, [cache_refresh_conf_ldap])]})
                    cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' + str(conn_ldap.result) + '\n')
                except Exception as e:
                    cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' + str(e) + '\n')
                # ------- END_Method 2 LDAP -------
# ------------------------------------
if __name__ == "__main__":
    main()
