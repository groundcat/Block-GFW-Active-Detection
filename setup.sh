#!/bin/bash
umask 027
script_path="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
echo "Installing at the directory: ${script_path}"
apt update && apt upgrade -y
apt install -y python3 python3-pip iptables-persistent
pip3 install -r ${script_path}/requirements.txt
grep "bash ${script_path}/update.sh" /etc/crontab || echo "0 * * * * bash ${script_path}/update.sh ">> /etc/crontab
echo "Installed at the directory: ${script_path}"

# Disable IPv6 (remove below lines if you want to keep IPv6, however it may cause some issues since the script only generates IPv4 rules)
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
sysctl -w net.ipv6.conf.lo.disable_ipv6=1
echo "net.ipv6.conf.all.disable_ipv6=1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6=1" >> /etc/sysctl.conf
echo "net.ipv6.conf.lo.disable_ipv6=1" >> /etc/sysctl.conf
