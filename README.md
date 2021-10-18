# Securing-Systems-IP-Tables-

#!/bin/sh
# IPtables Rules to harden security, written/compiled from various sources on the internet and tweaked by UniDoX
# Updated March 2020

#Debian based distros use package iptables-persistent
#iptables-save > /etc/iptables/rules.v4
dpkg-reconfigure iptables-persistent
