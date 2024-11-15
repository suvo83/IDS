from scapy.all import DNS,sniff
from collections import deque
import time

monitor_interval = 10    # monitor over a 10-second interval
dns_threshould = 50      # set a threshould (ex: 50 DNS responses per second)
dns_packet_timestamp = deque()

def dns_amplification_detect(packet):
    if packet.haslayer(DNS) and packet[DNS].qr  == 1: #qr == 1 stands for dns response
        response_size = len(packet)
        current_time = time.time()
        dns_packet_timestamp.append((current_time, response_size))

        # removeing outdated packet
        while dns_packet_timestamp and dns_packet_timestamp[0][0] < current_time - monitor_interval:
            dns_packet_timestamp.popleft()

        # calculate dns response rate and average size
        response_rate = len(dns_packet_timestamp)/monitor_interval
        dns_average_size = sum(size for _,size in dns_packet_timestamp)/len(dns_packet_timestamp)

        # checking conditions
        if response_rate > dns_threshould and dns_average_size > 500:
            print("ALERT: DNS amplification detected!")
            print(f"Response rate{response_rate:.2f} response/sec, avg size: {dns_average_size:.2f} bytes")

sniff(filter="port 53",prn=dns_amplification_detect,store = 0)