import time
from collections import defaultdict

# Set thresholds and time window
time_window = 10
syn_threshold = 5
incomplete_threshold = 4

# Track SYN and incomplete counts for each IP
connections = defaultdict(lambda: {"syn_count": 0, "incomplete_count": 0, "timestamps": []})

def detect_syn_flood(ip, packet_type, timestamp):
    current_time = time.time()

    # Remove old timestamps for each IP
    for ip_addr in list(connections.keys()):
        connections[ip_addr]["timestamps"] = [t for t in connections[ip_addr]["timestamps"] if current_time - t < time_window]
        if not connections[ip_addr]["timestamps"]:
            del connections[ip_addr]
    
    # Update counts based on packet type
    if packet_type == "SYN":
        connections[ip]["syn_count"] += 1
        connections[ip]["timestamps"].append(current_time)
    if packet_type == "SYN-ACK":
        connections[ip]["incomplete_count"] += 1
    
    # Check if thresholds are exceeded
    if (connections[ip]["syn_count"] > syn_threshold and connections[ip]["incomplete_count"] > incomplete_threshold):
        print(f"Possible SYN attack detected from {ip}")

