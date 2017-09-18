#!/bin/bash

# module installation
sudo apt-get update -y
sudo apt-get install openvswitch-switch -y
sudo apt-get install openvswitch-common -y
sudo apt-get install openvswitch-controller -y

/sbin/ifconfig eth1 up
/sbin/ifconfig eth2 up
/sbin/ifconfig eth3 up


#ovs configuration
ovs-vsctl add-br br0
ovs-vsctl add-port br0 eth1
ovs-vsctl add-port br0 eth2
ovs-vsctl add-port br0 eth3


ovs-ofctl add-flow br0 actions=NORMAL

ovs-ofctl dump-flows br0
