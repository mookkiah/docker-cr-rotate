## Overview

CacheRefreshRotation is a special container to monitor cache refresh on a specific oxTrust container.

## Versions

See [Releases](https://github.com/GluuFederation/docker-cr-rotate/releases) for stable versions.
For bleeding-edge/unstable version, use `gluufederation/cr-rotate:4.3.0_dev`.

## Environment Variables

The following environment variables are supported by the container:

- `GLUU_CONFIG_ADAPTER`: The config backend adapter, can be `consul` (default) or `kubernetes`.
- `GLUU_CONFIG_CONSUL_HOST`: hostname or IP of Consul (default to `localhost`).
- `GLUU_CONFIG_CONSUL_PORT`: port of Consul (default to `8500`).
- `GLUU_CONFIG_CONSUL_CONSISTENCY`: Consul consistency mode (choose one of `default`, `consistent`, or `stale`). Default to `stale` mode.
- `GLUU_CONFIG_CONSUL_SCHEME`: supported Consul scheme (`http` or `https`).
- `GLUU_CONFIG_CONSUL_VERIFY`: whether to verify cert or not (default to `false`).
- `GLUU_CONFIG_CONSUL_CACERT_FILE`: path to Consul CA cert file (default to `/etc/certs/consul_ca.crt`). This file will be used if it exists and `GLUU_CONFIG_CONSUL_VERIFY` set to `true`.
- `GLUU_CONFIG_CONSUL_CERT_FILE`: path to Consul cert file (default to `/etc/certs/consul_client.crt`).
- `GLUU_CONFIG_CONSUL_KEY_FILE`: path to Consul key file (default to `/etc/certs/consul_client.key`).
- `GLUU_CONFIG_CONSUL_TOKEN_FILE`: path to file contains ACL token (default to `/etc/certs/consul_token`).
- `GLUU_CONFIG_KUBERNETES_NAMESPACE`: Kubernetes namespace (default to `default`).
- `GLUU_CONFIG_KUBERNETES_CONFIGMAP`: Kubernetes configmaps name (default to `gluu`).
- `GLUU_CONFIG_KUBERNETES_USE_KUBE_CONFIG`: Load credentials from `$HOME/.kube/config`, only useful for non-container environment (default to `false`).
- `GLUU_SECRET_ADAPTER`: The secrets adapter, can be `vault` or `kubernetes`.
- `GLUU_SECRET_VAULT_SCHEME`: supported Vault scheme (`http` or `https`).
- `GLUU_SECRET_VAULT_HOST`: hostname or IP of Vault (default to `localhost`).
- `GLUU_SECRET_VAULT_PORT`: port of Vault (default to `8200`).
- `GLUU_SECRET_VAULT_VERIFY`: whether to verify cert or not (default to `false`).
- `GLUU_SECRET_VAULT_ROLE_ID_FILE`: path to file contains Vault AppRole role ID (default to `/etc/certs/vault_role_id`).
- `GLUU_SECRET_VAULT_SECRET_ID_FILE`: path to file contains Vault AppRole secret ID (default to `/etc/certs/vault_secret_id`).
- `GLUU_SECRET_VAULT_CERT_FILE`: path to Vault cert file (default to `/etc/certs/vault_client.crt`).
- `GLUU_SECRET_VAULT_KEY_FILE`: path to Vault key file (default to `/etc/certs/vault_client.key`).
- `GLUU_SECRET_VAULT_CACERT_FILE`: path to Vault CA cert file (default to `/etc/certs/vault_ca.crt`). This file will be used if it exists and `GLUU_SECRET_VAULT_VERIFY` set to `true`.
- `GLUU_SECRET_KUBERNETES_NAMESPACE`: Kubernetes namespace (default to `default`).
- `GLUU_SECRET_KUBERNETES_CONFIGMAP`: Kubernetes secrets name (default to `gluu`).
- `GLUU_SECRET_KUBERNETES_USE_KUBE_CONFIG`: Load credentials from `$HOME/.kube/config`, only useful for non-container environment (default to `false`).
- `GLUU_WAIT_MAX_TIME`: How long the startup "health checks" should run (default to `300` seconds).
- `GLUU_WAIT_SLEEP_DURATION`: Delay between startup "health checks" (default to `10` seconds).
- `GLUU_PERSISTENCE_TYPE`: Persistence backend being used (one of `ldap`, `couchbase`, or `hybrid`; default to `ldap`).
- `GLUU_PERSISTENCE_LDAP_MAPPING`: Specify data that should be saved in LDAP (one of `default`, `user`, `cache`, `site`, or `token`; default to `default`). Note this environment only takes effect when `GLUU_PERSISTENCE_TYPE` is set to `hybrid`.
- `GLUU_LDAP_URL`: Address and port of LDAP server (default to `localhost:1636`); required if `GLUU_PERSISTENCE_TYPE` is set to `ldap` or `hybrid`.
- `GLUU_LDAP_USE_SSL`: Whether to use SSL connection to LDAP server (default to `true`).
- `GLUU_COUCHBASE_URL`: Address of Couchbase server (default to `localhost`); required if `GLUU_PERSISTENCE_TYPE` is set to `couchbase` or `hybrid`.
- `GLUU_COUCHBASE_USER`: Username of Couchbase server (default to `admin`); required if `GLUU_PERSISTENCE_TYPE` is set to `couchbase` or `hybrid`.
- `GLUU_COUCHBASE_CERT_FILE`: Couchbase root certificate location (default to `/etc/certs/couchbase.crt`); required if `GLUU_PERSISTENCE_TYPE` is set to `couchbase` or `hybrid`.
- `GLUU_COUCHBASE_PASSWORD_FILE`: Path to file contains Couchbase password (default to `/etc/gluu/conf/couchbase_password`); required if `GLUU_PERSISTENCE_TYPE` is set to `couchbase` or `hybrid`.
- `GLUU_COUCHBASE_BUCKET_PREFIX`: Prefix for Couchbase buckets (default to `gluu`).
- `GLUU_COUCHBASE_TRUSTSTORE_ENABLE`: Enable truststore for encrypted Couchbase connection (default to `true`).
- `GLUU_CR_ROTATION_CHECK`: The interval between IP rotation check (default to `300` seconds).
- `GLUU_CONTAINER_METADATA`: The name of scheduler to pull container metadata (one of `docker` or `kubernetes`; default to `docker`).
- `GLUU_SQL_DB_DIALECT`: Dialect name of SQL backend (one of `mysql`, `pgsql`; default to `mysql`).
- `GLUU_SQL_DB_HOST`: Host of SQL backend (default to `localhost`).
- `GLUU_SQL_DB_PORT`: Port of SQL backend (default to `3306`).
- `GLUU_SQL_DB_NAME`: Database name (default to `gluu`)
- `GLUU_SQL_DB_USER`: User name to interact with SQL backend (default to `gluu`).
- `GLUU_SQL_PASSWORD_FILE`: Path to file contains password for SQL backend (default to `/etc/gluu/conf/sql_password`).
- `GLUU_GOOGLE_SPANNER_INSTANCE_ID`: Instance ID of Google Spanner (default to empty string).
- `GLUU_GOOGLE_SPANNER_DATABASE_ID`: Database ID of Google Spanner (default to empty string).
- `GOOGLE_APPLICATION_CREDENTIALS`: Path to Google credentials JSON file (default to `/etc/gluu/conf/google-credentials.json`).
- `GOOGLE_PROJECT_ID`: Google Project ID (default to empty string).

## Getting Metadata

!!! Note
    Since the metadata scope is per node, this container must be deployed in each node. Use `mode=global` in Swarm Mode services or `DaemonSet` in Kubernetes.

1.  Set a predefined label on oxTrust container.

    **Docker:**

    ```sh
    docker run \
        --label APP_NAME=oxtrust \
        gluufederation/oxtrust:4.3.0_dev
    ```

    **Kubernetes:**

    ```yaml
    # oxtrust.yaml
    apiVersion: apps/v1
    kind: StatefulSet
    metadata:
      name: oxtrust
      labels:
        app: oxtrust
        APP_NAME: oxtrust
    spec:
      serviceName: oxtrust
      template:
        metadata:
          labels:
            app: oxtrust
            APP_NAME: oxtrust
    ```

1.  Set the appropriate `GLUU_CONTAINER_METADATA` environment variable.
    If the container is running on the Docker scheduler, the `docker.sock` file must be mounted into container.

    **Docker:**

    ```sh
    docker run \
      -e GLUU_CONTAINER_METADATA=docker \
      -v /var/run/docker.sock:/var/run/docker.sock \
      gluufederation/cr-rotate:4.3.0_dev
    ```

    **Kubernetes:**

    Set the environment variable `GLUU_CONTAINER_METADATA=kubernetes`.
