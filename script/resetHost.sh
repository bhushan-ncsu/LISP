#!/bin/sh

ssh root@$h1 -t 'ifconfig eth1 0 up'
ssh root@$h2 -t 'ifconfig eth1 0 up'
ssh root@$h3 -t 'ifconfig eth1 0 up'
ssh root@$h4 -t 'ifconfig eth1 0 up'
ssh root@$h5 -t 'ifconfig eth1 0 up'
ssh root@$h6 -t 'ifconfig eth1 0 up'
ssh root@$h7 -t 'ifconfig eth1 0 up'
ssh root@$h8 -t 'ifconfig eth1 0 up'
