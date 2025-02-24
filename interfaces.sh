#!/bin/sh

N_CLIENTS=1

up() {
    # Set up bridge
    sudo ip link add kea-br0 type bridge
    sudo ip link set kea-br0 up
    
    # Set up veth pair for docker to attach
    sudo ip link add kea-veth0 type veth peer kea-br0-veth0
    sudo ip link set kea-br0-veth0 master kea-br0
    sudo ip link set kea-br0-veth0 up
    sudo ip link set kea-veth0 up
    
    # Set up veth pairs for dhclient
    for i in $(seq 1 $N_CLIENTS); do
        sudo ip link add "kea-veth$i" type veth peer "kea-br0-veth$i"
        sudo ip link set "kea-br0-veth$i" master kea-br0
        sudo ip link set "kea-br0-veth$i" up
        sudo ip link set "kea-veth$i" up
    done
}

down() {
    # Tear down
    sudo ip link delete kea-br0
    sudo ip link delete kea-br0-veth0
    for i in $(seq 1 $N_CLIENTS); do
        sudo ip link delete "kea-br0-veth$i"
    done
}

case $1 in
    up)
        up
        ;;
    down)
        down
        ;;
    *)
        echo "Usage: $0 { up | down }" >&2
        exit 1
        ;;
esac
