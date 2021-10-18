#!/bin/sh
# IPtables Rules to harden security, written/compiled from various sources on the internet and tweaked by UniDoX#0101
# Updated March 2020

## Set your WAN based Interface here, for example eth0 or enp2s0
INTERFACE=eth0

#Clear any existing rules, comment out to disable

#Flush!
iptables -F

#Initial Rules
iptables -A INPUT -p tcp --dport 22 -j ACCEPT #Keep SSH Alive, Important!
iptables -A INPUT -i lo -j ACCEPT #Allow Localhost connections for sanity.
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT #Permit related connections to  something whitelisted

# Block ports (Blacklist  mode only, Not reccomended)
#iptables -A INPUT -p tcp -i $INTERFACE --destination-port 80 -j DROP
#iptables -A INPUT -p tcp -i $INTERFACE --destination-port 8080 -j DROP

#explicit bans
#iptables -I INPUT -s 1.2.3.4 -j DROP

#whitelist rules (ports to open)
iptables -A INPUT -p tcp -i $INTERFACE --destination-port 80 -j ACCEPT             #HTTP
iptables -A INPUT -p tcp -i $INTERFACE --destination-port 443 -j ACCEPT             #HTTPS

#### Blacklist or whitelist mode, alturnate the following 2 lines to change
#iptables -P INPUT ACCEPT  #Blacklist mode (permissive)
iptables -P INPUT DROP	   #Whitelist mode (restrictive)

iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

#Whitelist/trusted IP's and subnets (Admins) 
## Add any IP Addresses in here you to not wish to be locked out
iptables -A INPUT -s 127.0.0.1/8 -j ACCEPT                  #Localhost
iptables -A INPUT -s 123.45.67.8 -j ACCEPT            		 # Example, Add your own

            

# NAT Settings - Only needed if using VPN such as PPTPD, remember to enable ipv4.forwarding
#iptables --table nat --append POSTROUTING --out-interface ppp0 -j MASQUERADE
#iptables --append FORWARD --in-interface eth1 -j ACCEPT

#Block Cracker
iptables -A INPUT -s 123.1.2.3 -i $INTERFACE -p udp -m state --state NEW -m udp --dport 161 -j DROP

# Reject spoofed packets
iptables -A INPUT -s 10.0.0.0/8 -j DROP
iptables -A INPUT -s 169.254.0.0/16 -j DROP
iptables -A INPUT -s 172.16.0.0/12 -j DROP
iptables -A INPUT -s 127.0.0.0/8 -j DROP

iptables -A INPUT -s 224.0.0.0/4 -j DROP
iptables -A INPUT -d 224.0.0.0/4 -j DROP
iptables -A INPUT -s 240.0.0.0/5 -j DROP
iptables -A INPUT -d 240.0.0.0/5 -j DROP
iptables -A INPUT -s 0.0.0.0/8 -j DROP
iptables -A INPUT -d 0.0.0.0/8 -j DROP
iptables -A INPUT -d 239.255.255.0/24 -j DROP
iptables -A INPUT -d 255.255.255.255 -j DROP

# Stop smurf attacks
iptables -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP
iptables -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP

# Drop all invalid packets
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP
iptables -A OUTPUT -m state --state INVALID -j DROP

# Drop excessive RST packets to avoid smurf attacks
iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT

# Attempt to block portscans
# Anyone who tried to portscan us is locked out for an entire day.
iptables -A INPUT   -m recent --name portscan --rcheck --seconds 86400 -j DROP
iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j DROP 
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP 

iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP 
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP 
iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP 

iptables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP 
iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP 
iptables -A INPUT -p tcp --tcp-flags ACK,PSH PSH -j DROP 
iptables -A INPUT -p tcp --tcp-flags ACK,URG URG -j DROP 

# Once the day has passed, remove them from the portscan list
iptables -A INPUT   -m recent --name portscan --remove
iptables -A FORWARD -m recent --name portscan --remove

# These rules add scanners to the portscan list, and log the attempt.
iptables -A INPUT   -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
iptables -A INPUT   -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP

iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP

# Block Brute Force attempts to SSH
iptables -A INPUT -i $INTERFACE -p tcp -m tcp --dport 22 -m state --state NEW -m recent --set --name SSH --rsource
iptables -A INPUT -i $INTERFACE -p tcp -m tcp --dport 22 -m recent --rcheck --seconds 30 --hitcount 4 --rttl --name SSH --rsource -j REJECT --reject-with tcp-reset
iptables -A INPUT -i $INTERFACE -p tcp -m tcp --dport 22 -m recent --rcheck --seconds 30 --hitcount 3 --rttl --name SSH --rsource -j LOG --log-prefix "SSH brute force "
iptables -A INPUT -i $INTERFACE -p tcp -m tcp --dport 22 -m recent --update --seconds 30 --hitcount 3 --rttl --name SSH --rsource -j REJECT --reject-with tcp-reset
iptables -A INPUT -i $INTERFACE -p tcp -m tcp --dport 22 -j ACCEPT
# Block RDESKTOP Brute Force Attempts
iptables -A INPUT -i $INTERFACE -p tcp -m tcp --dport 3389 -m state --state NEW -m recent --set --name RDESKTOP --rsource
iptables -A INPUT -i $INTERFACE -p tcp -m tcp --dport 3389 -m recent --rcheck --seconds 30 --hitcount 4 --rttl --name RDESKTOP --rsource -j REJECT --reject-with tcp-reset
iptables -A INPUT -i $INTERFACE -p tcp -m tcp --dport 3389 -m recent --rcheck --seconds 30 --hitcount 3 --rttl --name RDESKTOP --rsource -j LOG --log-prefix "RDESKTOP brute force "
iptables -A INPUT -i $INTERFACE -p tcp -m tcp --dport 3389 -m recent --update --seconds 30 --hitcount 3 --rttl --name RDESKTOP --rsource -j REJECT --reject-with tcp-reset
iptables -A INPUT -i $INTERFACE -p tcp -m tcp --dport 3389 -j ACCEPT

#CentOS 
service iptables save
service iptables restart

#Debian based distros use package iptables-persistent
#iptables-save > /etc/iptables/rules.v4
dpkg-reconfigure iptables-persistent
