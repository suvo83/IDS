from scapy.all import DNS, IP, sniff
from collections import deque
import time

DNS_threshold = 50  # Threshold of DNS requests per second
monitor_interval = 1  # Monitoring interval in seconds
dns_packet_timestamp = deque()

def detect_dns_flood(packet):
    if not packet.haslayer(DNS):
        return  # Skip non-DNS packets

    current_time = time.time()
    dns_packet_timestamp.append(current_time)

    # Remove outdated packets from deque
    while dns_packet_timestamp and dns_packet_timestamp[0] < current_time - monitor_interval:
        dns_packet_timestamp.popleft()

    packet_rate = len(dns_packet_timestamp) / monitor_interval

    if packet_rate > DNS_threshold:
        source_ip = packet[IP].src  # Correctly access the source IP
        print(f"Alert! Potential DNS flood detected from {source_ip} at {current_time:.2f}")
        print(f"Packet rate: {packet_rate:.2f} packets/second")

print("DNS flood detection is starting...")
sniff(filter='ip', prn=detect_dns_flood, store=0)

