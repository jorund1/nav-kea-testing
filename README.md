# Set Up a Local Kea API Server for Testing with NAV

> Disclaimer: This setup works under the assumption that the Docker `bridge` network driver creates a new broadcast domain
  for its containers, isolated from any of the Docker host's physical interfaces' broadcast domains. Otherwise, the
  Kea Dhcp4 server could cause serious ip-assignment troubles on the physical network!


## How To Use

Get NAV containers up and running the usual way, making sure to be checked out in the `kea-metrics` branch of my NAV fork[^0]:

[^0]: Should any oddities occur when building images, try removing old NAV images (browse `docker image ls -a`),
or just build using `docker compose build --no-cache` (this will over time create lots of images you have to
clean up manually).

```sh
git clone -o jorund1 -b kea-metrics "https://github.com/jorund1/nav.git"
cd nav
docker compose up -d
```

*After* NAV containers are up, get the containers from this very repo up and running[^1]:

[^1]: We will connect the Kea server to the NAV network, so NAV containers must go up first. We assume the NAV network is called 'nav_default'. This is the default case when the NAV repository's root directory is called 'nav' (the default name when cloning the NAV repository).
If this is the case for you, continue on. However, if your local NAV repository's root directory is not called 'nav',
then set the environment variable NAV_NETWORK to '*dir*_default', where *dir*
is the name of your NAV repository's root directory *before* applying this step to make sure that the Kea server is connected to the correct NAV network.


```sh
# Sets up 5 dhcp clients and a kea server (kea-dhcp4 server and kea-ctrl-agent) on its
# own bridge network and also adds a route from the kea server to the NAV network
git clone "https://github.com/jorund1/nav-kea-testing.git"
cd nav-kea-testing
docker compose up -d
./acquire 4 # This script can be ran with numbers between 1 and 5 to
            # clear all leases in the Kea DHCP lease database and then
            # have between 1 and 5 dhcp clients acquire an address
```

Now NAV should be able to reach the Kea API at `http://kea:8000/`. To test this, add the following entry to
the `dhcpmetrics.conf` NAV configuration file[^2]:

[^2]: for example by editing it in the NAV source tree under `python/nav/etc/dhcpmetrics.conf`and then running `docker compose exec nav nav config install --overwrite /etc/nav`

```sh
[http://kea:8000/]
dhcp_version=4
service=Kea Management API
```

Then, run `docker compose exec nav dhcpmetrics` to check if the Kea API server is found.

Lastly, check if the user-interface works as expected. In the NAV web interface at `http://localhost/`, create a VLAN in 'seeddb' with subnet
containing the subnet '172.31.255.0/24' and afterwards go to the VLAN's web page. ~Here you should see DHCP stats for that VLAN in
the form of timeseries graphs~. (The functionality described in this last paragraph is part of another branch that is not included in
the branch we are using now.)
