#!/usr/bin/env python3

import os

def set_static_ip(service_name, ip_address, subnet_mask, router_address):
    # Turn off Wi-Fi
    os.system(f"networksetup -setnetworkserviceenabled {service_name} off")
    
    # Set static IP
    os.system(f"networksetup -setmanual {service_name} {ip_address} {subnet_mask} {router_address}")
    
    # Turn on Wi-Fi
    os.system(f"networksetup -setnetworkserviceenabled {service_name} on")


def enable_dhcp(service_name):
    # Turn off Wi-Fi
    os.system(f"networksetup -setnetworkserviceenabled {service_name} off")
    
    # Enable DHCP
    os.system(f"networksetup -setdhcp {service_name}")
    
    # Turn on Wi-Fi
    os.system(f"networksetup -setnetworkserviceenabled {service_name} on")


# Example usage
service_name = "Wi-Fi"  # Change to your network service name - cannot contain spaces (e.g., "Wi-Fi" or "Ethernet")
ip_address = "192.168.1.10"  # Change to your desired IP address
subnet_mask = "255.255.255.0"  # Change to your subnet mask
router_address = "192.168.1.1"  # Change to your router (gateway) address



# set_static_ip(service_name, ip_address, subnet_mask, router_address)

enable_dhcp(service_name)

