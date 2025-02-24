# Kea Dhcp4 + Kea Control Agent Test Setup

> Note: This setup works under the assumption that the Docker `bridge` network driver creates a new broadcast domain
  for its containers, isolated from any of the Docker host's physical interfaces' broadcast domains. Otherwise, the
  Kea Dhcp4 server could cause ip-assignment issues in the physical network!

## How To Use

1. Get NAV development containers up and running:

   ```sh
   git clone "https://github.com/Uninett/nav.git" 
   cd nav
   docker compose up -d
   ```

2. Get the containers for this test setup up and running:

   ```sh
   # Sets up 5 dhcp clients and a kea-dhcp4 server with kea-ctrl-agent on its own bridge network:
   docker compose up -d
   ```

3. Connect the `nav-web` container to the test setup's network:

   ```sh
   ```
