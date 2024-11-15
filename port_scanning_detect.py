from scapy.all import sniff, IP, TCP

# Dictionary to track unique destination ports for each source IP
scan_tracker = {}

def detect_port_scan(packet):
    # Get source IP and destination port
    src_ip = packet[IP].src
    dst_port = packet[IP].dport
    
    # Initialize tracker for new IPs
    if src_ip not in scan_tracker:
        scan_tracker[src_ip] = set()
    
    # Add the destination port to the set of ports for this IP
    scan_tracker[src_ip].add(dst_port)
    
    # If an IP has scanned more than 10 ports, trigger an alert
    if len(scan_tracker[src_ip]) > 10:
        print(f"Alert: port scan detected from {src_ip}")

# Sniff IP and TCP packets, applying the port scan detection function
sniff(filter="ip and tcp", prn=detect_port_scan)
