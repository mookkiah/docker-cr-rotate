#!/usr/bin/env python
# ------------------------------------
"""
updating cache refresh in gluu server
Author : Mohammad Abudayyeh
Email : mo@gluu.org
"""
import base64
import os
import pyDes
# import signal
# ------------------------------------
# import string
import tarfile
import shutil
from kubernetes import client, config
from kubernetes.client import Configuration
from kubernetes.client.apis import core_v1_api
from kubernetes.client.rest import ApiException
from kubernetes.stream import stream
from ldap3 import Server, Connection, MODIFY_REPLACE, MODIFY_ADD, MODIFY_DELETE, SUBTREE, ALL, BASE, LEVEL
from gluulib import get_manager
# Function to decrypt encoded password
def decrypt_text(encrypted_text, key):
    cipher = pyDes.triple_des(b"{}".format(key), pyDes.ECB,
                              padmode=pyDes.PAD_PKCS5)
    encrypted_text = b"{}".format(base64.b64decode(encrypted_text))
    return cipher.decrypt(encrypted_text)


def main():
    config.load_kube_config()
    c = Configuration()
    c.assert_hostname = False
    Configuration.set_default(c)
    cli = core_v1_api.CoreV1Api()
    pods = cli.list_pod_for_all_namespaces().items
    # Directory of Cache Refresh LDIF
    directory = "/cr/ldif"
    # Filename of Cache Refresh LDIF
    filename = "/crldif"
    # Salt file location
    # salt_location = '/etc/gluu/conf/salt'
    # Empty list to hold oxtrust containers
    oxtrust_pods = []
    # Empty list to hold LDAP containers . Usually and almost always will only have one
    ldap_pods = []
    bind_password_encoded = ''
    salt_code = ''
    bind_password = ''
    #-------Method 2 LDAP ------------
    manager = get_manager()
    GLUU_LDAP_URL = os.environ.get("GLUU_LDAP_URL", "localhost:1636")
    # -------END_Method 2 LDAP ------------
    for pod in pods:
        try:
            if "opendj" in pod.metadata.labels['APP_NAME']:
                ldap_pods.append(pod)
            elif "oxtrust" in pod.metadata.labels['APP_NAME']:
                oxtrust_pods.append(pod)
        except ApiException as e:
            if e.status != 404:
                print("Unknown error: %s" % e)
                exit(1)
    if len(ldap_pods) == 0: print "No LDAP found"

    # Get encoded password
    for oxtrust_pod in oxtrust_pods:
        # Return the ox-ldap.properties file as a list
        oxldap_prop_list = None
        oxldap_prop_list = stream(cli.connect_get_namespaced_pod_exec, oxtrust_pod.metadata.name, oxtrust_pod.metadata.namespace,
                      command=['cat', '/etc/gluu/conf/ox-ldap.properties'],
                      stderr=True, stdin=True,
                      stdout=True, tty=False).split()
        # Return the salt file as a list
        salt_list = None
        salt_list = stream(cli.connect_get_namespaced_pod_exec, oxtrust_pod.metadata.name, oxtrust_pod.metadata.namespace,
                                  command=['cat', '/etc/gluu/conf/salt'],
                                  stderr=True, stdin=True,
                                  stdout=True, tty=False).split()
        # Check if there exists a salt code in the salt list, if so set salt_code to it
        if ''.join(salt_list).find('=') >= 0:
            salt_code = salt_list[salt_list.index('=') + 1]
        # Currently print but needs to be appended  to the oxtrust log file
        else:
            print " Encoded salt cannot be found"

        # Check if there exists a an encoded bind password in the ox-ldap.properties, if so set encoded password to it
        if ''.join(oxldap_prop_list).find('bindPassword') >= 0:
            bind_password_encoded = oxldap_prop_list[oxldap_prop_list.index('bindPassword:') + 1]
            # decode the bind password
            bind_password = decrypt_text(bind_password_encoded, salt_code)
        # Currently print but needs to be appended to the oxtrust log file
        else:
            print "Bind Password cannot be found"
    # if bind pass is empty using the method above try
    # ------- Method 2 using consul ----------
    try:
        bind_dn_ldap = manager.config.get("ldap_binddn")
        bind_password_ldap = decrypt_text(manager.secret.get("encoded_ox_ldap_pw"),manager.secret.get("encoded_salt"))
        ldap_server_ldap = Server(GLUU_LDAP_URL, port=1636, use_ssl=True)
        conn_ldap = Connection(ldap_server, bind_dn, bind_password)
        conn_ldap.bind()
    except Exception as err:
        print err
    # ------- END_Method 2 using consul ----------
    if len(bind_password) > 0:
        # Return oxtrust server DN
        server_dn = stream(cli.connect_get_namespaced_pod_exec, ldap_pods[0].metadata.name, ldap_pods[0].metadata.namespace,
                                  command=['/opt/opendj/bin/ldapsearch -h localhost -p 1636 -Z -X -D "cn=directory manager" -w ' + str(
                bind_password) + ' -b "ou=appliances,o=gluu"  "inum=*" | grep dn)'],
                                  stderr=True, stdin=True,
                                  stdout=True, tty=False).split()
        # Return oxtrust conf cache refresh
        oxtrust_conf_cache_refresh = stream(cli.connect_get_namespaced_pod_exec, ldap_pods[0].metadata.name, ldap_pods[0].metadata.namespace,
                                  command=['/opt/opendj/bin/ldapsearch -h localhost -p 1636 -Z -X -D "cn=directory manager" -w ' + str(
                bind_password) + ' -b "o=gluu" -T "objectClass=oxTrustConfiguration" oxTrustConfCacheRefresh \ | '
                                 'grep "^oxTrustConfCacheRefresh"'],
                                  stderr=True, stdin=True,
                                  stdout=True, tty=False).split()
        # Get the currently set ip in ldap
        # get current ip in ldap
        current_ip_in_ldap = None
        # From the oxtrust conf cache refresh extract cache refresh conf
        cache_refresh_conf = oxtrust_conf_cache_refresh[oxtrust_conf_cache_refresh.find("oxTrustConfCacheRefresh: {"):].strip()
        # From the oxtrust conf cache refresh extract oxtrust conf cache refresh DN
        conf_dn = oxtrust_conf_cache_refresh[oxtrust_conf_cache_refresh.find("dn:"):oxtrust_conf_cache_refresh.find(
            "oxTrustConfCacheRefresh")].strip()
        # Returns an index number if -1 disabled and if => 0 enabled
        is_cr_enabled = stream(cli.connect_get_namespaced_pod_exec, ldap_pods[0].metadata.name, ldap_pods[0].metadata.namespace,
                                  command=['/opt/opendj/bin/ldapsearch -h localhost -p 1636 -Z -X -D "cn=directory manager" -w ' + str(
                bind_password) + ' -b "ou=appliances,o=gluu" "gluuVdsCacheRefreshEnabled=*" '
                                 'gluuVdsCacheRefreshEnabled \ | grep -Pzo "enabled"'],
                                  stderr=True, stdin=True,
                                  stdout=True, tty=False).find("enabled")
        # ------- Method 2 LDAP -------
        # Return oxtrust conf cache refresh
        conn_ldap.search('o=gluu', '(objectclass=oxTrustConfiguration)', attributes='oxTrustConfCacheRefresh')
        oxtrust_conf_cache_refresh_LDAP = str(conn.entries[0]).strip()
        cache_refresh_conf_ldap = oxtrust_conf_cache_refresh_LDAP[
                             oxtrust_conf_cache_refresh_LDAP.find("oxTrustConfCacheRefresh: {"):].strip("\n")
        conn.search_ldap('ou=appliances,o=gluu', '(objectclass=gluuAppliance)', attributes='inum')
        server_dn_LDAP = str(conn.entries[0]).strip()
        server_dn_ldap = server_dn_LDAP[server_dn_LDAP.find("inum: "):].strip("\n")
        server_dn_ldap = "inum=" + server_dn[server_dn.find("m:") + 3:]
        conn_ldap.search('ou=appliances,o=gluu', '(objectclass=gluuAppliance)', attributes=['gluuIpAddress'])
        current_ip_in_ldap_LDAP = str(conn.entries[0]).strip()
        # Change this
        current_ip_in_ldap_ldap = current_ip_in_ldap_LDAP[current_ip_in_ldap_LDAP.find("gluuIpAddress: "):].strip("\n")
        conn_ldap.search('ou=appliances,o=gluu', '(objectclass=gluuAppliance)', attributes=['gluuVdsCacheRefreshEnabled'])
        is_cr_enabled_ldap_LDAP = str(conn.entries[0]).strip()
        is_cr_enabled_ldap = is_cr_enabled_ldap_LDAP[is_cr_enabled_ldap_LDAP.find("gluuVdsCacheRefreshEnabled: "):].strip(
            "\n")
        conn_ldap.search('o=gluu', '(objectclass=gluuOrganization)', attributes=['o'])
        # ------- END_Method 2 LDAP -------
        for oxtrust_pod in oxtrust_pods:
            ip = oxtrust_pod.status.pod_ip
            if is_cr_enabled < 0:
                # The user has disabled the CR
                # Check if the path for the LDIF exists and if so remove it
                if os.path.isdir(directory):
                    shutil.rmtree(directory)
            # Check  the container has not been setup previosly, the CR is enabled
            elif ip != current_ip_in_ldap and is_cr_enabled >= 0:
                if not os.path.isdir(directory):
                    os.makedirs(directory)

                # Clear contents of file at CR rotate container
                open(directory + filename, 'w').close()
                # Format and concatenate ldifdata
                ldifdata = str(
                    server_dn) + "\nchangetype: modify\nreplace: oxTrustCacheRefreshServerIpAddress\n" \
                                 "oxTrustCacheRefreshServerIpAddress: " + str(
                    ip) + "\n\n" + str(conf_dn) + "\nchangetype: modify\nreplace: oxTrustConfCacheRefresh\n" + str(
                    cache_refresh_conf)

                ldif = open(directory + filename, "w+")
                ldif.write(ldifdata)
                ldif.close()
                # Clean cache folder at oxtrust container
                stream(client.connect_get_namespaced_pod_exec, oxtrust_pod.metadata.name, oxtrust_pod.metadata.namespace,
                       command=['rm', '-rf' '/var/ox/identity/cr-snapshots/'],
                       stderr=True, stdin=True,
                       stdout=True, tty=False)
                stream(client.connect_get_namespaced_pod_exec, oxtrust_pod.metadata.name, oxtrust_pod.metadata.namespace,
                       command=['mkdir', '/var/ox/identity/cr-snapshots/'],
                       stderr=True, stdin=True,
                       stdout=True, tty=False)
                stream(client.connect_get_namespaced_pod_exec, oxtrust_pod.metadata.name, oxtrust_pod.metadata.namespace,
                       command=['chown', '-R', 'jetty:jetty', '/var/ox/identity/cr-snapshots/'],
                       stderr=True, stdin=True,
                       stdout=True, tty=False)
                stream(client.connect_get_namespaced_pod_exec, ldap_pods[0].metadata.name, ldap_pods[0].metadata.namespace,
                       command=[' mkdir', '-p', directory],
                       stderr=True, stdin=True,
                       stdout=True, tty=False)
                writetoldif_command = [
                    '/bin/sh',
                    '-c',
                    'echo', ldifdata, '>>', directory+filename]
                stream(api.connect_get_namespaced_pod_exec, ldap_pods[0].metadata.name, ldap_pods[0].metadata.namespace,
                              command=writetoldif_command,
                              stderr=True, stdin=False,
                              stdout=True, tty=False)
                ldap_modify_status = stream(client.connect_get_namespaced_pod_exec, ldap_pods[0].metadata.name, ldap_pods[0].metadata.namespace,
                       command=['/opt/opendj/bin/ldapmodify -D "cn=directory manager" -w ' + bind_password +
                    ' -h localhost -p 1636 --useSSL --trustAll -f ' + directory + filename + directory],
                       stderr=True, stdin=True,
                       stdout=True, tty=False)
                # Currently print but needs to be appended to the oxtrust log file
                print ldap_modify_status
                # Clean up files
                stream(cli.connect_get_namespaced_pod_exec, ldap_pods[0].metadata.name, ldap_pods[0].metadata.namespace,
                                            command=['rm', '-rf ', directory + filename],
                                            stderr=True, stdin=True,
                                            stdout=True, tty=False)
                # ------- Method 2 LDAP -------
                conn.modify(server_dn + ',ou=appliances,o=gluu',
                            {'oxTrustCacheRefreshServerIpAddress': [(MODIFY_REPLACE, [ip])]})
                print "OxtrustCacheRefreshServerIpAddress was modified : output to oxtrust.log"
                print conn.result
                conn.modify('ou=oxtrust,ou=configuration,' + server_dn + ',ou=appliances,o=gluu',
                            {'oxTrustConfCacheRefresh': [(MODIFY_REPLACE, [cache_refresh_conf])]})
                print "oxTrustConfCacheRefresh was modified : output to oxtrust.log"
                # ------- END_Method 2 LDAP -------

# ------------------------------------
if __name__ == "__main__":
    main()
