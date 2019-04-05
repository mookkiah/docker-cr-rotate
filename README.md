# docker-cr-rotate

Docker Cache Refresh script and components

### Docker Single host and Swarm:

Run this command:

```bash
docker run -d --restart=unless-stopped -e GLUU_CONTAINER_METADATA=docker --name cr_rotates -v /var/run/docker.sock:/var/run/docker.sock -v ./volumes/cr/ldif/:/cr/ldif/ gluufederation/cr-rotate:3.1.4_dev
```
