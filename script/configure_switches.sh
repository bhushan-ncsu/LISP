#!/bin/bash
ssh root@$sw1 'bash -s' < ./configure_individual_switch.sh
ssh root@$sw2 'bash -s' < ./configure_individual_switch.sh
ssh root@$sw3 'bash -s' < ./configure_individual_switch.sh
ssh root@$sw4 'bash -s' < ./configure_individual_switch.sh
