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
# import signal
# ------------------------------------
# import string
import tarfile
import shutil


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
    # Directory of Cache Refresh LDIF
    directory = "/cr/ldif"
    # Filename of Cache Refresh LDIF
    filename = "/crldif"
    # Docker URL
    docker_url = 'unix://var/run/docker.sock'
    # Salt file location
    # salt_location = '/etc/gluu/conf/salt'
    # Docker Client
    client = docker.DockerClient(base_url=docker_url)
    # Low level API client
    low_client = docker.APIClient(base_url=docker_url)
    # Empty list to hold oxtrust containers
    oxtrust_containers = []
    # Empty list to hold LDAP containers . Usually and almost always will only have one
    ldap_containers = []
    bind_password_encoded = ''
    salt_code = ''
    bind_password = ''

    for container in client.containers.list():
        try:
            Label = low_client.inspect_container(container.id)['Config']['Labels']['com.docker.swarm.service.name']
        except:
            print 'No Labelss found for ' + str(container.name)
            Label = ''
        if len(Label) > 0:
            if "gluu_oxtrust" in Label:
                oxtrust_containers.append(container)
            elif "gluu_ldap" in Label:
                ldap_containers.append(container)
    if len(ldap_containers) == 0: print "No LDAP found"
    # Get encoded password
    for oxtrust_container in oxtrust_containers:
        # Return the ox-ldap.properties file as a list
        oxldap_prop_list = oxtrust_container.exec_run('cat /etc/gluu/conf/ox-ldap.properties').output.split()
        # Return the salt file as a list
        salt_list = oxtrust_container.exec_run('cat /etc/gluu/conf/salt').output.split()

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

    if len(bind_password)>0:
        # Return oxtrust server DN
        server_dn = ldap_containers[0].exec_run(
            '/opt/opendj/bin/ldapsearch -h localhost -p 1636 -Z -X -D "cn=directory manager" -w ' + str(
                bind_password) + ' -b "ou=appliances,o=gluu"  "inum=*" | grep dn)').output.strip()
        # Return oxtrust conf cache refresh
        oxtrust_conf_cache_refresh = ldap_containers[0].exec_run(
            '/opt/opendj/bin/ldapsearch -h localhost -p 1636 -Z -X -D "cn=directory manager" -w ' + str(
                bind_password) + ' -b "o=gluu" -T "objectClass=oxTrustConfiguration" oxTrustConfCacheRefresh \ | '
                                 'grep "^oxTrustConfCacheRefresh"').output.strip()
        # Get the currently set ip in ldap
        current_ip_in_ldap = ldap_containers[0].exec_run(
            '/opt/opendj/bin/ldapsearch -h localhost -p 1636 -Z -X -D "cn=directory manager" -w ' + str(
                bind_password) + ' -b "ou=appliances,o=gluu"  "gluuIpAddress=*" gluuIpAddress \ | '
                                 'grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"').output.strip()
        # From the oxtrust conf cache refresh extract cache refresh conf
        cache_refresh_conf = oxtrust_conf_cache_refresh[oxtrust_conf_cache_refresh.find("oxTrustConfCacheRefresh: {"):].strip()
        # From the oxtrust conf cache refresh extract oxtrust conf cache refresh DN
        conf_dn = oxtrust_conf_cache_refresh[oxtrust_conf_cache_refresh.find("dn:"):oxtrust_conf_cache_refresh.find(
            "oxTrustConfCacheRefresh")].strip()
        # Returns an index number if -1 disabled and if => 0 enabled
        is_cr_enabled = ldap_containers[0].exec_run(
            '/opt/opendj/bin/ldapsearch -h localhost -p 1636 -Z -X -D "cn=directory manager" -w ' + str(
                bind_password) + ' -b "ou=appliances,o=gluu" "gluuVdsCacheRefreshEnabled=*" '
                                 'gluuVdsCacheRefreshEnabled \ | grep -Pzo "enabled"').output.find(
            "enabled")

        # container_setup_boolean = False
        for container in oxtrust_containers:
            network_dict = low_client.inspect_container(container.id)['NetworkSettings']['Networks']
            first_default_network_name = str(network_dict.keys()[0])
            ip = low_client.inspect_container(container.id)['NetworkSettings']['Networks'][first_default_network_name][
                'IPAddress'].strip()

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
                container.exec_run('rm -rf /var/ox/identity/cr-snapshots/')
                container.exec_run('mkdir /var/ox/identity/cr-snapshots/')
                container.exec_run('chown -R jetty:jetty /var/ox/identity/cr-snapshots/')
                ldap_containers[0].exec_run(' mkdir -p ' + directory)
                copy_to(directory + filename, ldap_containers[0], directory + filename)
                ldap_modify_status = ldap_containers[0].exec_run(
                    '/opt/opendj/bin/ldapmodify -D "cn=directory manager" -w ' + bind_password +
                    ' -h localhost -p 1636 --useSSL --trustAll -f ' + directory + filename).output
                # Currently print but needs to be appended to the oxtrust log file
                print ldap_modify_status
                # Clean up files
                ldap_containers[0].exec_run('rm -rf ' + directory + filename)


# ------------------------------------
if __name__ == "__main__":
    main()
