from scapy.all import sniff, IP, TCP, Raw
from collections import defaultdict
import time
import re

ldap_time_window = 1
ldap_query_threshold = 5
ldap_ports = [389,636]


# dictionary to track LDAP queries per IP

ldap_requests = defaultdict(lambda: {"count": 0, "timestamp" : []})

def detect_ldap_enumetation(packet):
    if packet.haslayer(IP) and packet.haslayer[TCP].dport in ldap_ports:
        src_ip = packet[IP].src
        current_time = time.time()

        ldap_requests[src_ip]["timestamp"].append(current_time)

        ldap_requests[src_ip]["timestamp"] = [
            ts for ts in ldap_requests[src_ip]["timestamp"] if current_time - ts <= ldap_time_window
        ]

        ldap_requests[src_ip]["count"] = len(ldap_requests[src_ip]["tiemstamp"])


        if ldap_requests[src_ip]["count"] > ldap_query_threshold:
            print(f"Alart! Potential LDAP enumeration detected from {src_ip}")


print("Our detection is starting>>>>>>>>>>>>>>>>>")
sniff(filter= "tcp port 389 or tcp port 636", prn= detect_ldap_enumetation, store = 0)