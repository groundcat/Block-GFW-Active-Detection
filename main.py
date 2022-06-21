import requests
import re
import configparser
import datetime
from dns_over_https import SecureDNS


def main():
    # Load the config file config.ini
    config = configparser.ConfigParser()
    config.read('config.ini')
    config.sections()

    # Get config
    whitelist_ports = config['TCP_UDP']['WHITELIST_POSTS']
    ssh_port = config['SSH']['SSH_PORT']
    ssh_allowed_ip = resolve_ip(config['SSH']['SSH_ALLOWED_HOST'].strip())
    resolver = config['DNS_RESOLVER']['RESOLVER']
    if config['SSH']['SSH_PROTECTED'] == 'yes':
        ssh_protected = True
    else:
        ssh_protected = False

    # Build list of hosts to check
    whitelist_ips = []
    whitelist_hosts = config['TCP_UDP']['WHITELIST_HOSTS'].split(',')

    for host in whitelist_hosts:
        host = host.strip()
        ip = resolve_ip(host=host, resolver=resolver)
        if ip is not None and ip not in whitelist_ips:
            whitelist_ips.append(ip)

    if len(whitelist_hosts) == 0:
        print("No hosts in whitelist")
        exit(1)

    # Append to rules file
    with open('rules/rules.v4', 'w') as rules_v4:

        # Add a timestamp
        rules_v4.write(f'# Generated at {datetime.datetime.now()}\n')

        # Common header
        rules_v4.write('*filter\n')

        #  Allow all loopback (lo0) traffic and drop all traffic to 127/8 that doesn't use lo0
        rules_v4.write('-A INPUT -i lo -j ACCEPT\n')
        rules_v4.write('-A INPUT ! -i lo -d 127.0.0.0/8 -j REJECT\n')

        #  Accept all established inbound connections
        rules_v4.write('-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n')

        #  Allow all outbound traffic - you can modify this to only allow certain traffic
        rules_v4.write('-A OUTPUT -j ACCEPT\n')

        #  Allow connections from only certain sources
        for whitelist_ip in whitelist_ips:
            rules_v4.write(f'-A INPUT -s {whitelist_ip} -p tcp --dport {whitelist_ports} -j ACCEPT\n')
            rules_v4.write(f'-A INPUT -s {whitelist_ip} -p UDP --dport {whitelist_ports} -j ACCEPT\n')

        rules_v4.write(f'-A INPUT -p tcp --dport {whitelist_ports} -j DROP\n')
        rules_v4.write(f'-A INPUT -p udp --dport {whitelist_ports} -j DROP\n')

        #  Allow SSH connections
        if ssh_protected:
            rules_v4.write(f'-A INPUT -s {ssh_allowed_ip} -p tcp --dport {ssh_port} -j ACCEPT\n')
            rules_v4.write(f'-A INPUT -p tcp --dport {ssh_port} -j DROP\n')
        else:
            rules_v4.write(f'-A INPUT -p tcp -m state --state NEW --dport 22 -j ACCEPT\n')

        #  Deny ping
        rules_v4.write('-A INPUT -p icmp -m icmp --icmp-type 8 -j DROP\n')

        #  Log iptables denied calls
        rules_v4.write('-A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7\n')

        #  Reject all the other inbound - default deny unless explicitly allowed policy
        rules_v4.write('-A INPUT -j REJECT\n')
        rules_v4.write('-A FORWARD -j REJECT\n')
        rules_v4.write('COMMIT\n')


def resolve_ip(host, resolver='doh'):
    """
    Detects the IP of a domain with ip-api.com API
    """
    # See if the domain is an ip address
    regex = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    if regex.match(host):
        print(f"{host} is an IP address, no need to resolve")
        return host

    if resolver == 'api':
        # Use ip-api.com API
        api_endpoint = f"http://ip-api.com/json/{host}"
        api_response = requests.get(api_endpoint)
        if api_response.status_code == 200:
            api_response_json = api_response.json()
            ip = api_response_json['query']
            print(f"{host} successfully resolved to {ip}")
            return ip
        else:
            print(f"{host} could not be resolved")
            exit(1)

    else:
        # Use DNS-over-HTTPS
        ip = dns_over_https(domain=host, query_type='A')
        return ip


def dns_over_https(domain, query_type='A'):
    """
    Resolves a domain name to an IP address using DNS-over-HTTPS
    """
    r = SecureDNS(query_type=query_type)
    try:
        host = r.resolve(domain)[0]
    except:
        print(f"{domain} could not be resolved through DoH")
        exit(1)  # if any one of the domains fails to be successfully resolved,
        # the script will exit to avoid blocking the existing IP addresses
    else:
        print(f"{domain} resolved to {host}")
        return host


if __name__ == '__main__':
    main()
