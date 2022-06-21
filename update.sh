#!/bin/bash
umask 027
script_path="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
python3 "${script_path}/main.py"
cp "${script_path}/rules/rules.v4" "/etc/iptables/rules.v4"
iptables-restore < "/etc/iptables/rules.v4"
