# !/bin/sh

OLD=$1
NEW=$2
IP=$3
DEF_GW=$4

IP_FIRST_OCTET=`echo $IP | grep -o -E '[0-9]+' | head -1 | sed -e 's/^0\+//'`
DEF_GW_FIRST_OCTET=`echo $DEF_GW | grep -o -E '[0-9]+' | head -1 | sed -e 's/^0\+//'`

CMD='ifconfig eth1 0 up'
ssh $OLD -t $CMD

CMD='ifconfig eth1 '
CMD+=$IP 
CMD+=' up '

ssh $NEW -t $CMD

if [ "$IP_FIRST_OCTET" == "$DEF_GW_FIRST_OCTET" ]
then
    if [ "$IP_FIRST_OCTET" == "20" ]
    then
        ssh -t $NEW << EOF
        route add -net 30.0.0.0 netmask 255.0.0.0 gw 20.0.0.1
        route add -net 40.0.0.0 netmask 255.0.0.0 gw 20.0.0.1
        route add -net 50.0.0.0 netmask 255.0.0.0 gw 20.0.0.1 
        ping $DEF_GW -c 1
EOF
    elif [ "$IP_FIRST_OCTET" == "30" ]
    then
        ssh -t $NEW << EOF
        route add -net 20.0.0.0 netmask 255.0.0.0 gw 30.0.0.1
        route add -net 40.0.0.0 netmask 255.0.0.0 gw 30.0.0.1
        route add -net 50.0.0.0 netmask 255.0.0.0 gw 30.0.0.1
        ping $DEF_GW -c 1
EOF
    elif [ "$IP_FIRST_OCTET" == "40" ]
    then
        ssh -t $NEW << EOF
        route add -net 20.0.0.0 netmask 255.0.0.0 gw 40.0.0.1
        route add -net 30.0.0.0 netmask 255.0.0.0 gw 40.0.0.1
        route add -net 50.0.0.0 netmask 255.0.0.0 gw 40.0.0.1
        ping $DEF_GW -c 1
EOF
    elif [ "$IP_FIRST_OCTET" == "50" ]
    then
        ssh -t $NEW << EOF
        route add -net 20.0.0.0 netmask 255.0.0.0 gw 50.0.0.1
        route add -net 30.0.0.0 netmask 255.0.0.0 gw 50.0.0.1
        route add -net 40.0.0.0 netmask 255.0.0.0 gw 50.0.0.1
        ping $DEF_GW -c 1
EOF
    fi
else
    if [ "$DEF_GW_FIRST_OCTET" == "20" ]
    then
        ssh -t $NEW << EOF
        route add -host 20.0.0.1 dev eth1
        route add -net 20.0.0.0 netmask 255.0.0.0 gw $DEF_GW
        route add -net 30.0.0.0 netmask 255.0.0.0 gw $DEF_GW
        route add -net 40.0.0.0 netmask 255.0.0.0 gw $DEF_GW
        route add -net 50.0.0.0 netmask 255.0.0.0 gw $DEF_GW
        ping $DEF_GW -c 1
EOF
    elif [ "$DEF_GW_FIRST_OCTET" == "30" ]
    then
        ssh -t $NEW << EOF
        route add -host 30.0.0.1 dev eth1
        route add -net 20.0.0.0 netmask 255.0.0.0 gw $DEF_GW
        route add -net 30.0.0.0 netmask 255.0.0.0 gw $DEF_GW
        route add -net 40.0.0.0 netmask 255.0.0.0 gw $DEF_GW
        route add -net 50.0.0.0 netmask 255.0.0.0 gw $DEF_GW
        ping $DEF_GW -c 1
EOF
    elif [ "$DEF_GW_FIRST_OCTET" == "40" ]
    then
        ssh -t $NEW << EOF
        route add -host 40.0.0.1 dev eth1
        route add -net 20.0.0.0 netmask 255.0.0.0 gw $DEF_GW
        route add -net 30.0.0.0 netmask 255.0.0.0 gw $DEF_GW
        route add -net 40.0.0.0 netmask 255.0.0.0 gw $DEF_GW
        route add -net 50.0.0.0 netmask 255.0.0.0 gw $DEF_GW
        ping $DEF_GW -c 1
EOF
    elif [ "$DEF_GW_FIRST_OCTET" == "50" ]
    then
        ssh -t $NEW << EOF
        route add -host 50.0.0.1 dev eth1
        route add -net 20.0.0.0 netmask 255.0.0.0 gw $DEF_GW
        route add -net 30.0.0.0 netmask 255.0.0.0 gw $DEF_GW
        route add -net 40.0.0.0 netmask 255.0.0.0 gw $DEF_GW
        route add -net 50.0.0.0 netmask 255.0.0.0 gw $DEF_GW
        ping $DEF_GW -c 1
EOF
    fi
fi
