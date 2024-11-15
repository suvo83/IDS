from scapy.all import ICMP, sniff
from collections import deque
import time

# Configuration for detection
icmp_threshold = 50  # Set the ICMP packets per second threshold
monitor_interval = 1  # Check traffic every 1 second

# Store timestamps of recent ICMP packets
packet_timestamp = deque()

def detect_icmp_flood(packet):
    if packet.haslayer(ICMP):
        print("ICMP packet detected:", packet.summary())
        
        # Get the current timestamp
        current_time = time.time()
        packet_timestamp.append(current_time)

        # Remove old packets from the deque that fall outside the monitoring interval
        while packet_timestamp and packet_timestamp[0] < current_time - monitor_interval:
            packet_timestamp.popleft()
        
        # Calculate the ICMP packet rate
        icmp_packet_rate = len(packet_timestamp) / monitor_interval

        # If packet rate exceeds threshold, flag as potential ICMP flood
        if icmp_packet_rate > icmp_threshold:
            print(f"ALERT: Potential ICMP flood detected! Rate: {icmp_packet_rate:.2f} packets/sec")
        else:
            print(f"ICMP Packet Rate: {icmp_packet_rate:.2f} packets/sec")  # Optional monitoring output

# Start the sniffing process and apply the detection function
print("Starting ICMP flood detection...")
sniff(filter="icmp", prn=detect_icmp_flood, store=0)
