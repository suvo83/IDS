from scapy.all import sniff,DNS, DNSQR, IP 
from collections import defaultdict



def dns_poisoning_detection(packet):
    if packet.haslayer(DNS) and packet[DNS].qr == 1:
        query = packet[DNSQR].qname.decode()
        src_ip = packet[IP].src

        if src_ip not in dns_query_request:
            dns_query_request[query].append(src_ip)

        if len(dns_query_request[query]) > 1:
            print(f"Alert!!! Potential DNS Poisoning detected for query {query} \n from {', '.join(dns_query_request[query])}")

print("starting dns poisoning scanning...........")
sniff(filter = "tcp",prn=dns_poisoning_detection,store=0)