# docker-cr-rotate

Docker Cache Refresh script and components

## Documentation

The official documentation can be found at https://gluu.org/docs/de/3.1.6.

### Example on Docker Single host and Swarm:

Run this command:

```bash
docker run \
    -d \
    --restart=unless-stopped \
    --network container:consul \
    --name cr_rotates \
    -e GLUU_CONFIG_ADAPTER=consul \
    -e GLUU_CONFIG_CONSUL_HOST=consul \
    -e GLUU_SECRET_ADAPTER=vault \
    -e GLUU_SECRET_VAULT_HOST=vault \
    -e GLUU_CONTAINER_METADATA=docker \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /path/to/vault_role_id.txt:/etc/certs/vault_role_id \
    -v /path/to/vault_secret_id.txt:/etc/certs/vault_secret_id \
    gluufederation/cr-rotate:4.0.0_dev
```
