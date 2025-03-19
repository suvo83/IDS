from scapy.all import IP,sniff, TCP
from collections import defaultdict, deque
import time

request_counts = defaultdict(lambda: {"count":0, "timestamp" : deque()})
time_window = 1
request_thershold = 100

def detect_HTTP_flood(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        dest_port = packet[TCP].dport
        src_ip = packet[IP].src
        if dest_port in (443,80):
            current_time = time.time()
            protocol = "HTTPS" if dest_port == 433 else "HTTP"

            request_data = request_counts[src_ip]
            request_data["timestamp"].append(current_time)

            while request_data["timestamp"] and current_time - request_data["timestamp"][0] > time_window:
                request_data["timestamp"].popleft()

            request_data["count"] = len(request_data["timestamp"])

            if request_data["count"] > request_thershold:
                print(f"Alert Potential {protocol} Flood detected from {src_ip}")

print("Our detection is startig......")
sniff(filter= "ip",prn=detect_HTTP_flood,store=0)