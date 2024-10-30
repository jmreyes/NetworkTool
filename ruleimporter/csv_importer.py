#!/usr/bin/env python

import argparse
import csv
import re

from ipaddress import ip_network

# Assuming the networktool is two directory levels higher...
import os, sys; sys.path.append(os.path.abspath(os.path.realpath(__file__) + "/../../"))

from networktool import db

def parse_and_import_csv(file_path):
    with open(file_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile, delimiter=',')
        for row in reader:
            ruleid = row['ID']
            src_zone = row['Source Zone']
            src_addr = row['Source Address']
            src_addr_text = row['Source Address (expanded)']
            src_addr_ips = extract_ips(src_addr_text)
            dst_zone = row['Dest. Zone']
            dst_addr = row['Dest. Address']
            dst_addr_text = row['Dest. Address (expanded)']
            dst_addr_ips = extract_ips(dst_addr_text)
            application = row['Application']
            service = row['Service']
            service_text = row['Service (expanded)']
            service_ports = extract_ports(service_text)
            action = row['Action']

            name = f"{src_addr} -> {dst_addr} [{service}]"
        
            rule = db.SqlHandler.Rule(
                id=ruleid,
                name=name,
                src_zone=src_zone,
                src_addr=src_addr,
                src_addr_text=src_addr_text,
                src_addr_ips=src_addr_ips,
                dst_zone=dst_zone,
                dst_addr=dst_addr,
                dst_addr_text=dst_addr_text,
                dst_addr_ips=dst_addr_ips,
                application=application,
                service=service,
                service_text=service_text,
                service_ports=service_ports,
                action=action
            )

            try:
                db.sqlhandler.insert(rule)
                print(f"[+] Rule {ruleid} imported.")
            except:
                print(f"[!] ERROR: Could not import rule {ruleid}. Check manually in DB if it already exists.")

def extract_ips(addr_text):
    # Reusing the regular expression to match IP ranges in CIDR notation
    ip_ranges = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}\b', addr_text)

    # Convert each CIDR range to an ip_network object and sort them
    sorted_ip_ranges = sorted(ip_ranges, key=lambda x: ip_network(x))

    # Join sorted IP ranges into a comma-separated list
    return ";".join(sorted_ip_ranges)
    
def extract_ports(service_text):
    # Regular expression to match port ranges or individual ports with TCP
    port_ranges = re.findall(r'\b\d{1,5}(?:-\d{1,5})?-tcp\b', service_text)

    # Extract start and end of ranges or individual ports and sort them
    sorted_ports = sorted(port_ranges, key=lambda x: int(x.split('-')[0]))
    
    # Join sorted port ranges into a comma-separated list
    return ";".join(sorted_ports)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse a CSV file containing rules from the command line, importing its contents in the network-tool DB.")
    parser.add_argument("csv_file", type=str, help="Path to the CSV file to parse")
    parser.add_argument("sqlite_file", type=str, help="Path to the sqlite DB")

    args = parser.parse_args()

    db.sqlhandler = db.SqlHandler(url=f"sqlite:///{args.sqlite_file}", echo=False)

    parse_and_import_csv(args.csv_file)