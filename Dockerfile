FROM alpine

LABEL maintainer="Gluu Inc. <support@gluu.org>"

# ===============
# Alpine packages
# ===============
RUN apk update && apk add --no-cache \
    py-pip \
    wget

# ====
# Tini
# ====

ENV TINI_VERSION v0.18.0
RUN wget -q https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-static -O /usr/bin/tini \
    && chmod +x /usr/bin/tini

# ======
# Python
# ======
RUN pip install -U pip
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# ===
# ENV
# ===
ENV GLUU_CONFIG_ADAPTER consul
ENV GLUU_CONSUL_HOST localhost
ENV GLUU_CONSUL_PORT 8500
ENV GLUU_CONSUL_CONSISTENCY stale
ENV GLUU_CONSUL_SCHEME http
ENV GLUU_CONSUL_VERIFY false
ENV GLUU_CONSUL_CACERT_FILE /etc/certs/consul_ca.crt
ENV GLUU_CONSUL_CERT_FILE /etc/certs/consul_client.crt
ENV GLUU_CONSUL_KEY_FILE /etc/certs/consul_client.key
ENV GLUU_CONSUL_TOKEN_FILE /etc/certs/consul_token
ENV GLUU_KUBERNETES_NAMESPACE default
ENV GLUU_KUBERNETES_CONFIGMAP gluu
ENV GLUU_LDAP_URL localhost:1636
ENV GLUU_CONTAINER_METADATA docker

# ==========
# misc stuff
# ==========
WORKDIR /opt/cr-rotate
RUN mkdir -p /etc/certs /cr/logs /cr/ldif

COPY scripts /opt/cr-rotate/scripts
RUN chmod +x /opt/cr-rotate/scripts/entrypoint.sh

ENTRYPOINT ["tini", "-g", "--"]
CMD ["/opt/cr-rotate/scripts/entrypoint.sh"]
