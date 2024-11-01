#!/usr/bin/env python

import ipaddress

import re
import netifaces

def validate_ports_format(csv_string):
    # Format must be a CSV that contains values like "<integer>[-<integer>][-tcp|-udp]"
    pattern = r"^(\d+(-\d+)?(-tcp|-udp)?)(,\d+(-\d+)?(-tcp|-udp)?)*$"
    return bool(re.match(pattern, csv_string))

def expand_port_ranges(str):
    str = str.replace(";", ",") # In case it comes from DB

    tcp_ports = []
    udp_ports = []

    for entry in str.split(","):
        entry_split = entry.split("-")
        if entry_split[-1] == "tcp":
            if len(entry_split) > 2:
                start, end = map(int, entry_split[:2])
                tcp_ports.extend(range(start, end + 1))
            else:
                tcp_ports.append(int(entry_split[0]))
        elif entry_split[-1] == "udp":
            if len(entry_split) > 2:
                start, end = map(int, entry_split[:2])
                udp_ports.extend(range(start, end + 1))
            else:
                udp_ports.append(int(entry_split[0]))
        elif len(entry_split) > 1:
            start, end = map(int, entry_split[:2])
            tcp_ports.extend(range(start, end + 1))
        else:
            tcp_ports.append(int(entry_split[0]))
    
    return tcp_ports, udp_ports


# Function to detect the local network range dynamically
def get_local_ip_range():
    """Get the local IP address range dynamically using the system network interfaces."""
    for interface in netifaces.interfaces():
        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addresses:
            ipv4_info = addresses[netifaces.AF_INET][0]
            ip_address = ipv4_info['addr']
            netmask = ipv4_info['netmask']

            # Skip the loopback interface (127.x.x.x)
            if not ip_address.startswith("127."):
                network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
                return str(network)
    
    raise RuntimeError("Could not find a valid non-loopback IP address")