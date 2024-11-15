from scapy.all import ARP,sniff

import time

# Dictionary to store legitimate IP-to-MAC address mappings
ip_mac_add= {}

def detect_arp_spoofing(packet):
    if packet.haslayer(ARP):
        # check if the packet is an ARP response(op = 2)
        if packet[ARP].op == 2:
            sender_ip = packet[ARP].psrc
            sender_mac = packet[ARP].hwsrc
            # check if the sender IP is already in out IP-MAC dictionary
            if sender_ip in ip_mac_add:
                if ip_mac_add[sender_ip] != sender_mac:
                    print("ALERT! Possible arp spoofing atack detected!")
                    print(f"IP: {sender_ip} is being  claimed by multiple MACs: ")
                    print(f" -Original MAC address is {ip_mac_add[sender_ip]}")
                    print(f" -New MAC: {sender_mac}")
                else:
                    #add the IP-to-MAC mapping in the dicionary
                    ip_mac_add[sender_ip] = sender_mac


print("Starting ARP spoof detection..........")
sniff(filter="arp",prn=detect_arp_spoofing,store=False)
                