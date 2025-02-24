# Kea Dhcp4 + Kea Control Agent Test Setup

> Note: This setup works under the assumption that the Docker `bridge` network driver creates a new broadcast domain
  for its containers, isolated from any of the Docker host's physical interfaces' broadcast domains. Otherwise, the
  Kea Dhcp4 server could cause ip-assignment issues in the physical network!

```sh
# Set up 5 dhcp clients and a kea-dhcp4 server with kea-ctrl-agent on its own bridge network
docker compose up -d
```


