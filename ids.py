from scapy.all import sniff, IP, TCP, ICMP, DNS, ARP, Raw, DNSQR
import time
from collections import defaultdict,deque
from datetime import timedelta,datetime
from scapy.layers.http import HTTPRequest



# for port scan detection
scan_tracker = {}

# for syn flood detection
time_window = 10
syn_threshold = 5
incomplete_threshold = 4
connections = defaultdict(lambda: {"syn_count": 0, "incomplete_count": 0, "timestamps": []})

# for icmp flood detection
icmp_threshold = 50  # Set the ICMP packets per second threshold
monitor_interval = 1  # Check traffic every 1 second
packet_timestamp = deque() # Store timestamps of recent ICMP packets

# for dns amplification
monitor_interval = 10    # monitor over a 10-second interval
dns_threshould = 50      # set a threshould (ex: 50 DNS responses per second)
dns_packet_timestamp = deque()

# for brute force detection
attempt_thershould = 5 # number of attempt from a single IP within the timeframe
time_window = 60 # timeframe in which attempts are counted

connections_attemps = defaultdict(lambda: defaultdict(list)) # scr ip list with timestamp
alerted_list = set() #track IPs we have already alearted on


def detect_port_scan(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        # Get source IP and destination port
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        
        # Initialize tracker for new IPs
        if src_ip not in scan_tracker:
            scan_tracker[src_ip] = set()
        
        # Add the destination port to the set of ports for this IP
        scan_tracker[src_ip].add(dst_port)
        
        # If an IP has scanned more than 10 ports, trigger an alert
        if len(scan_tracker[src_ip]) > 10:
            print(f"Alert: port scan detected from {src_ip}")

def detect_syn_flood(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        current_time = time.time()

        # Clean up old timestamps for each IP
        for ip_addr in list(connections.keys()):
            connections[ip_addr]["timestamps"] = [t for t in connections[ip_addr]["timestamps"] if current_time - t < time_window]
            if not connections[ip_addr]["timestamps"]:
                del connections[ip_addr]

        # Update counts based on packet flags
        if packet[TCP].flags == 'S':  # SYN packet
            connections[src_ip]["syn_count"] += 1
            connections[src_ip]["timestamps"].append(current_time)
        elif packet[TCP].flags == 'SA':  # SYN-ACK packet
            connections[src_ip]["incomplete_count"] += 1

        # Check if thresholds are exceeded
        if (connections[src_ip]["syn_count"] > syn_threshold and connections[src_ip]["incomplete_count"] > incomplete_threshold):
            print(f"Alert: Possible SYN flood detected from {src_ip}")

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
    
def detect_brute_force(packet):
    timestamp = time.time()

    # Detect SSH brute force attack
    if packet.haslayer(TCP) and packet[TCP].dport == 22:
        src_ip = packet[IP].src
        service = "SSH"

        # Log the connection attempt
        connections_attemps[service][src_ip].append(timestamp)

        # Remove outdated attempts from the log
        connections_attemps[service][src_ip] = [
            time for time in connections_attemps[service][src_ip]
            if (timestamp - time).total_seconds() <= time_window
        ]

        # Check if the number of attempts exceeds the threshold
        if len(connections_attemps[service][src_ip]) >= attempt_thershould:
            # Only alert once per IP within the detection period
            if src_ip not in alerted_list:
                print(f"ALERT: Brute force attack detected! from {src_ip}")
                alerted_list.add(src_ip)

    # Repeat similar logic for FTP, RDP, SMTP, and HTTP
    # Detect RDP brute force attack
    elif packet.haslayer(TCP) and packet[TCP].dport == 3389:
        src_ip = packet[IP].src
        service = "RDP"

        # Log the connection attempt
        connections_attemps[service][src_ip].append(timestamp)

        # Remove outdated attempts from the log
        connections_attemps[service][src_ip] = [
            time for time in connections_attemps[service][src_ip]
            if (timestamp - time).total_seconds() <= time_window
        ]

        # Check if the number of attempts exceeds the threshold
        if len(connections_attemps[service][src_ip]) >= attempt_thershould:
            # Only alert once per IP within the detection period
            if src_ip not in alerted_list:
                print(f"ALERT: Brute force attack detected! from {src_ip}")
                alerted_list.add(src_ip)
    
    # detect ftp brute force
    elif packet.haslayer(TCP) and packet[TCP].dport == 21:
        src_ip = packet[IP].src
        service = "FTP"

        # Log the connection attempt
        connections_attemps[service][src_ip].append(timestamp)

        # Remove outdated attempts from the log
        connections_attemps[service][src_ip] = [
            time for time in connections_attemps[service][src_ip]
            if (timestamp - time).total_seconds() <= time_window
        ]

        # Check if the number of attempts exceeds the threshold
        if len(connections_attemps[service][src_ip]) >= attempt_thershould:
            # Only alert once per IP within the detection period
            if src_ip not in alerted_list:
                print(f"ALERT: Brute force attack detected! from {src_ip}")
                alerted_list.add(src_ip)
    
    # detect http brute force
    elif packet.haslayer(TCP) and packet[TCP].dport == 80:
        src_ip = packet[IP].src
        service = "HTTP"

        # Log the connection attempt
        connections_attemps[service][src_ip].append(timestamp)

        # Remove outdated attempts from the log
        connections_attemps[service][src_ip] = [
            time for time in connections_attemps[service][src_ip]
            if (timestamp - time).total_seconds() <= time_window
        ]

        # Check if the number of attempts exceeds the threshold
        if len(connections_attemps[service][src_ip]) >= attempt_thershould:
            # Only alert once per IP within the detection period
            if src_ip not in alerted_list:
                print(f"ALERT: Brute force attack detected! from {src_ip}")
                alerted_list.add(src_ip)
    
    
    # DETECT SMTP brute force
    elif packet.haslayer(TCP) and packet[TCP].dport == 25:
        src_ip = packet[IP].src
        service = "SMTP"

        # Log the connection attempt
        connections_attemps[service][src_ip].append(timestamp)

        # Remove outdated attempts from the log
        connections_attemps[service][src_ip] = [
            time for time in connections_attemps[service][src_ip]
            if (timestamp - time).total_seconds() <= time_window
        ]

        # Check if the number of attempts exceeds the threshold
        if len(connections_attemps[service][src_ip]) >= attempt_thershould:
            # Only alert once per IP within the detection period
            if src_ip not in alerted_list:
                print(f"ALERT: Brute force attack detected! from {src_ip}")
                alerted_list.add(src_ip)
    
    


# for arp spoofing detection
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

#for sql_injection_detect.py
sql_injection_patterns = [
    r"(?i)\bUNION\b",  # UNION SELECT
    r"(?i)SELECT\b",   # SELECT keyword
    r"(?i)INSERT\b",   # insert keyword 
    r"(?i)UPDATE\b",   # update keyword
    r"(?i)DELETE\b",   # delete keyword
    r"(?i)DROP\b",     # drop table keyword
    r"(?i)OR\s*1\s*=\s*1",  # or 1=1
    r"(?i)'--",        # sql comment
    r"(?i)#",          # another sql comment
    r"(?i)SLEEP\(",    # time-based sqli
    r"(?i)BENCHMARK\(" # time-based sqli
]

def is_sql_injections(payload):
    for pattern in sql_injection_patterns:
        if re.search(pattern, payload):
            return True
    return False

import re

def detect_sql_injection(packet):
    if packet.haslayer(HTTPRequest):
        http_layer = packet[HTTPRequest]
        url = http_layer.Host.decode() + http_layer.Path.decode()

        if http_layer.Method == b"GET":
            payload = http_layer.Path.decode()
        elif http_layer.Method == b"POST":
            payload = packet[Raw].load.decode(errors = "ignore")
        else:
            payload = ""
    
        if is_sql_injections(payload):
            print(f"SQL Injectin detected!: {url}")
            print(f"Payload: {payload}")

# for unauthorized acess detection
import logging

# configure logging to store detectd unatuthorized protocols events
logging.basicConfig(filename="Unathorized_protocols.log",level=logging.INFO, format = "%(asctime)s - %(message)s")

unauthorinze_port = {
    21: "FTP",
    23: "Telnet"
}

def detect_unathorized_protocols(packet):
    if packet.haslayer(TCP):
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

        # check if source or destionation port mathes unathorized protocols
        if source_port in unauthorinze_port or destination_port in unauthorinze_port:
            protocol = unauthorinze_port.get(source_port, unauthorinze_port.get(destination_port))
            logging.info(f"Unathorized protocol detected: {protocol} | soruce IP: {packet[0][1].src} | destination IP: {packet[0][1].dst}")


from collections import Counter
import math
# parameter to define thresholds for suspicious activity 
max_query_length = 50 # maximum length for normal dns queries
entropy_threshold = 3.8 # threshold for entropy to detect randomness
max_query_rate = 10  # maximum queries per second from single source

dns_query_counter = Counter() # track query rate per ip

def entropty_calculate(data):
    counter = Counter(data)
    entropy = -sum((count/len(data))*math.log2(count/len(data)) for count in counter.values())
    return entropy

def detect_dns_tunneling(packet):
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        domain = packet[DNSQR].qname.decode('utf-8')
        src_ip = packet[IP].src

        #check for long length of domain queries
        if len(domain)>max_query_length:
            print(f"Suspected long domain: {domain} from IP: {src_ip}")

        #check for entropy of domain queries 
        entropy = entropty_calculate(domain)
        if entropy > entropy_threshold:
            print(f"High entropy in domain {domain} from IP: {src_ip} (entropy = {entropy})")
        
        # check for max queries rate 
        dns_query_counter[src_ip] += 1
        if dns_query_counter[src_ip] > max_query_rate:
            print(f"High DNS query rate from IP: {src_ip}")
            dns_query_counter[src_ip] = 0 # reset count after flagging

# Detect SMB traffic
def detect_smb(packet):
    if packet.haslayer(TCP) and packet[TCP].dport in [445, 139]:
        print(f"[SMB Traffic Detected] From IP: {packet[IP].src} -> To IP: {packet[IP].dst}")

# Detect RDP traffic
def detect_rdp(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 3389:
        print(f"[RDP Traffic Detected] From IP: {packet[IP].src} -> To IP: {packet[IP].dst}")


    
def packet_handler(packet):
    detect_icmp_flood(packet)
    detect_port_scan(packet)
    detect_syn_flood(packet)
    dns_amplification_detect(packet)
    detect_brute_force(packet)
    detect_arp_spoofing(packet)
    detect_sql_injection(packet)
    detect_unathorized_protocols(packet)
    detect_dns_tunneling(packet)
    detect_rdp(packet)
    detect_smb(packet)

print("Our ids is starting......")
sniff(filter="ip",prn = packet_handler, store = 0)