# !/bin/sh

ssh -t root@$h1 << EOF
ifconfig eth1 20.0.0.2 up
route add -net 30.0.0.0 netmask 255.0.0.0 dev eth1
route add -net 40.0.0.0 netmask 255.0.0.0 dev eth1
route add -net 50.0.0.0 netmask 255.0.0.0 dev eth1
arping 20.0.0.1 -c 1 -i eth1
EOF

ssh -t root@$h2 << EOF
ifconfig eth1 20.0.0.3 up
route add -net 30.0.0.0 netmask 255.0.0.0 dev eth1
route add -net 40.0.0.0 netmask 255.0.0.0 dev eth1
route add -net 50.0.0.0 netmask 255.0.0.0 dev eth1
arping 20.0.0.1 -c 1 -i eth1
EOF

ssh -t root@$h3 << EOF
ifconfig eth1 30.0.0.2 up
route add -net 20.0.0.0 netmask 255.0.0.0 dev eth1
route add -net 40.0.0.0 netmask 255.0.0.0 dev eth1
route add -net 50.0.0.0 netmask 255.0.0.0 dev eth1
arping 30.0.0.1 -c 1 -i eth1
EOF

ssh -t root@$h4 << EOF
ifconfig eth1 30.0.0.3 up
route add -net 20.0.0.0 netmask 255.0.0.0 dev eth1
route add -net 40.0.0.0 netmask 255.0.0.0 dev eth1
route add -net 50.0.0.0 netmask 255.0.0.0 dev eth1
arping 30.0.0.1 -c 1 -i eth1
EOF

ssh -t root@$h5 << EOF
ifconfig eth1 40.0.0.2 up
route add -net 20.0.0.0 netmask 255.0.0.0 dev eth1
route add -net 30.0.0.0 netmask 255.0.0.0 dev eth1
route add -net 50.0.0.0 netmask 255.0.0.0 dev eth1
arping 40.0.0.1 -c 1 -i eth1
EOF

ssh -t root@$h6 << EOF 
ifconfig eth1 40.0.0.3 up
route add -net 20.0.0.0 netmask 255.0.0.0 dev eth1
route add -net 30.0.0.0 netmask 255.0.0.0 dev eth1
route add -net 50.0.0.0 netmask 255.0.0.0 dev eth1
arping 40.0.0.1 -c 1 -i eth1
EOF

ssh -t root@$h7 << EOF 
ifconfig eth1 50.0.0.2 up
route add -net 20.0.0.0 netmask 255.0.0.0 dev eth1
route add -net 30.0.0.0 netmask 255.0.0.0 dev eth1
route add -net 40.0.0.0 netmask 255.0.0.0 dev eth1
arping 50.0.0.1 -c 1 -i eth1
EOF

ssh -t root@$h8 << EOF 
ifconfig eth1 50.0.0.3 up
route add -net 20.0.0.0 netmask 255.0.0.0 dev eth1
route add -net 30.0.0.0 netmask 255.0.0.0 dev eth1
route add -net 40.0.0.0 netmask 255.0.0.0 dev eth1
arping 50.0.0.1 -c 1 -i eth1
EOF
