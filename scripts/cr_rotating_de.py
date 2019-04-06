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
    config_manager = ConfigManager()
    # Directory of Cache Refresh LDIF
    directory = "/cr/ldif"
    # Filename of Cache Refresh LDIF
    filename = "/crldif"
    cr_rotating_log = open("/cr/logs/cr_rotating.log", "a+")
    # Docker URL
    docker_url = 'unix://var/run/docker.sock'
    # Docker Client
    client = docker.DockerClient(base_url=docker_url)
    # Low level API client
    low_client = docker.APIClient(base_url=docker_url)
    # Empty list to hold oxtrust containers
    oxtrust_containers = []
    # Empty list to hold LDAP containers . Usually and almost always will only have one
    ldap_containers = []
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
    for container in client.containers.list():
        try:
            Label = low_client.inspect_container(container.id)['Config']['Labels']['APP_NAME']
        except Exception as e:
            cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' + str(e) + '\n')
        if len(Label) > 0:
            if "oxtrust" in Label:
                oxtrust_containers.append(container)
            elif "opendj" in Label:
                ldap_containers.append(container)
    # No LDAP containers found
    if len(ldap_containers) == 0:
        cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : '
                                + str('No LDAP found') + '\n')
    # Get bind password
    for oxtrust_container in oxtrust_containers:
        oxldap_prop_list = None
        salt_list = None
        # Get IP of conatiner and send it to IP pool lost
        network_dict = low_client.inspect_container(oxtrust_container.id)['NetworkSettings']['Networks']
        first_default_network_name = str(network_dict.keys()[0])
        ip = low_client.inspect_container(oxtrust_container.id)['NetworkSettings']['Networks'][first_default_network_name][
            'IPAddress'].strip()
        oxtrust_ip_pool.append(ip)
        # Return the ox-ldap.properties file as a list
        oxldap_prop_list = oxtrust_container.exec_run('cat /etc/gluu/conf/ox-ldap.properties').output.split()
        # Return the salt file as a list
        salt_list = oxtrust_container.exec_run('cat /etc/gluu/conf/salt').output.split()
        # Check if there exists a salt code in the salt list, if so set salt_code to it
        if ''.join(salt_list).find('=') >= 0:
            salt_code = salt_list[salt_list.index('=') + 1]
        else:
            cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : '
                                    + str('Encoded salt cannot be found') + '\n')
        # Check if there exists a an encoded bind password in the ox-ldap.properties, if so set encoded password to it
        if ''.join(oxldap_prop_list).find('bindPassword') >= 0:
            bind_password_encoded = oxldap_prop_list[oxldap_prop_list.index('bindPassword:') + 1]
            # decode the bind password
            bind_password = decrypt_text(bind_password_encoded, salt_code)
        else:
            cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : '
                                    + str('Bind Password cannot be found') + '\n')
    # ------- Method 2 using consul and LDAP ----------
    try:
        bind_dn_ldap = config_manager.get("ldap_binddn")
        bind_password_ldap = decrypt_text(config_manager.get("encoded_ox_ldap_pw"), config_manager.get("encoded_salt"))
        ldap_server_ldap = Server(GLUU_LDAP_URL, port=1636, use_ssl=True)
        conn_ldap = Connection(ldap_server_ldap, bind_dn_ldap, bind_password_ldap)
        conn_ldap.bind()
    except Exception as e:
        cr_rotating_log.write('[' + str(datetime.datetime.now()) + '] : ' + str(e) + '\n')
    # ------- END_Method 2 using consul ----------
    if len(bind_password) > 0:
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
            network_dict = low_client.inspect_container(container.id)['NetworkSettings']['Networks']
            first_default_network_name = str(network_dict.keys()[0])
            ip = low_client.inspect_container(container.id)['NetworkSettings']['Networks']
            [first_default_network_name]['IPAddress'].strip()
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
