# Block-GFW-Active-Detection

This is a script that generates an iptables rule set to limit the IP addresses that are allowed to connect to your server.

The default configuration to be used to protect the [OutlineVPN Shadowsocks server](https://getoutline.org/) against China's Great Firewall (GFW). 
GFW identifies servers running Shadowsocks proxy/VPN by active detection. 
This has been verified through [experiments](https://web.archive.org/web/20210304224724/https://blog.hiaoxui.com/blog/post/hiaoxui/whitelist-tech), and we have provided a simple and effective countermeasure: 
setting up a whitelist firewall on the server side. 
Our strategy proved to be effective in prolonging the survival time of the server without affecting the user experience.
Nevertheless, it is highly recommended to set up your Shadowsocks servers with [OutlineVPN](https://getoutline.org/) or follow the best practices: [How to Deploy a Censorship Resistant Shadowsocks-libev Server](https://gfw.report/blog/ss_tutorial/en/).

## Features

✅  Generates an iptables rule set to limit the IP addresses that are allowed to connect to your server via TCP/UDP.

✅  Supports multiple IP addresses and ports.

✅  Updates the rule set automatically every hour based on the IP addresses resolved from your DDNS domains.

✅  Protects your SSH service (disabled by default, enable in `config.ini`).

## Prerequisites

- A DDNS domain set up at your home computer or router.
- A remote server running Shadowsocks or VPN that requires protection. This server is where this script will be installed. Root access is required.
- Install iptables-persistent with `apt install -y iptables-persistent`. During installation, it will ask you if you want to keep current rules–decline.
- Run `setup.sh` described below to install the remaining dependencies.

## Configure

Create a `config.ini` file to your liking. Use `config.example.ini` as a template.

```bash
cp config.example.ini config.ini
vi config.ini
```

Make sure `SSH_PORT` is the same port number you set in `sshd_config` and `SSH_ALLOWED_HOST` is properly configured, otherwise you might be blocked from accessing SSH by the firewall.

## Install

This setup script works for Ubuntu and Debian based Linux distributions.

The setup script will

- install dependencies and required Python packages
- install cronjob to run the script `update.sh` every hour
- disable IPv6 given that the script does not support IPv6 yet

You only need to run this script once, however you may run it for multiple times if necessary.

```bash
chmod -x ./setup.sh
/bin/bash ./setup.sh
```

## Update iptables rules manually

The update script will

- query the domains or DDNS domains with DNS-over-HTTPS to resolve IP addresses
- update the iptables rule set to allow the IP addresses to connect to your server
- if any one of the domains fails to be successfully resolved, the script will exit to avoid blocking the existing IP addresses

```bash
chmod -x ./update.sh
/bin/bash ./update.sh
```
