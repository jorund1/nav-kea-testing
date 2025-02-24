#!/bin/sh
sudo docker build -t jorund1/kea-dhcp4 .
#sudo docker network create -d macvlan -o parent=kea-br0-veth0 --subnet 172.31.255.0/24 --ip-range 172.31.255.128/25 kea-net
