from scapy.all import sniff, IP, TCP, ICMP, DNS, ARP, Raw, DNSQR, Ether
import time
from collections import defaultdict,deque
from datetime import timedelta,datetime
from scapy.layers.http import HTTPRequest

##################
whitelisted_ips = {"0.0.0.0", "11.11.11.11", "4.4.4.4"} # whitelist you ip address to avoid false positive

# for port scan detection
scan_tracker = {}

# for syn flood detection
time_window = 1
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

        if src_ip in whitelisted_ips:
           return  # Ignore queries from the IDS itself
        
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
        connections[src_ip]["timestamps"] = [t for t in connections[src_ip]["timestamps"] if current_time - t < time_window]

        # Remove IP if no recent activity
        if not connections[src_ip]["timestamps"]:
            del connections[src_ip]
            return

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


# DNS flood detection

DNS_threshold = 50  # Threshold of DNS requests per second
monitor_interval = 1  # Monitoring interval in seconds
dns_packet_timestamp = deque()

def detect_dns_flood(packet):
    src_ip = packet[IP].src
    if src_ip in whitelisted_ips:
           return  # Ignore queries from the IDS itself
    
    if not packet.haslayer(DNS):
        return  # Skip non-DNS packets

    current_time = time.time()
    dns_packet_timestamp.append(current_time)

    # Remove outdated packets from deque
    while dns_packet_timestamp and dns_packet_timestamp[0] < current_time - monitor_interval:
        dns_packet_timestamp.popleft()

    packet_rate = len(dns_packet_timestamp) / monitor_interval

    if packet_rate > DNS_threshold:
        source_ip = packet[IP].src 
        print(f"Alert! Potential DNS flood detected from {source_ip} at {current_time:.2f}")
        print(f"Packet rate: {packet_rate:.2f} packets/second")




# DNS amplification detection

def dns_amplification_detect(packet):
    src_ip = packet[IP].src
    if src_ip in whitelisted_ips:
           return  # Ignore queries from the IDS itself
    
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
    
    src_ip = packet[IP].src
    if src_ip in whitelisted_ips:
        return  # Ignore queries from the IDS itself

    # Detect SSH brute force attack
    if packet.haslayer(TCP) and packet[TCP].dport == 22:
        src_ip = packet[IP].src
        service = "SSH"

        # Log the connection attempt
        connections_attemps[service][src_ip].append(timestamp)

        # Remove outdated attempts from the log
        connections_attemps[service][src_ip] = [
            time for time in connections_attemps[service][src_ip]
            if (timestamp - time) <= time_window
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
            if (timestamp - time) <= time_window
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
            if (timestamp - time) <= time_window
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
            if (timestamp - time) <= time_window
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
            if (timestamp - time) <= time_window
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

        if src_ip in whitelisted_ips:
            return
        
        
        #check for long length of domain queries
        if len(domain)>max_query_length:
            print(f"Suspected long domain: {domain} from IP: {src_ip}")
        
        if src_ip in whitelisted_ips:
           return  # Ignore queries from the IDS itself

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


# Detect DNS Poisoning attack

dns_query_request = defaultdict(set)  # Use a set to store unique IPs

def detect_dns_poisoning(packet):
    if packet.haslayer(DNS) and packet[DNS].qr == 1:
        # Check if DNSQR layer exists before accessing it
        if packet.haslayer(DNSQR):
            query = packet[DNSQR].qname.decode()
            src_ip = packet[IP].src
            
            if src_ip in whitelisted_ips:
                return  # Ignore queries from the IDS itself

            # Add the source IP to the set for the DNS query
            dns_query_request[query].add(src_ip)

            # If more than one unique IP is found for the same query, alert
            if len(dns_query_request[query]) > 1:
                print(f"Alert!!! Potential DNS Poisoning detected for query {query} \n from {', '.join(dns_query_request[query])}")


# Detect XSS attack
def detect_xss(packet):
    if packet.haslayer(Raw):
        payload = packet.getlayer(Raw).load.decode(errors="ignore")

        xss_patterns = [
            r"<script.*?>.*?</script>",  # Script tag with content
            r"javascript:",             # Javascript pseudo-protocol
            r"eval\s*\(",               # Javascript eval() function
            r"document\.cookie",       # Accessing document cookies (common in XSS)
            r"onmouseover\s*=",         # Event handler for mouseover
            r"alert\s*\(",              # alert() function in Javascript
            r"window\.location",       # Accessing window location (URL redirection)
            r"onload\s*=", 
        ]


        for pattern in xss_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                print(f"XSS Attack Detected! Payload : {payload}")
                return True
            

# detect fragmentation attack 

# Dictionary to store fragments by IP ID
fragments = defaultdict(list)
# Set to track alerted fragments (src, dst, id)
alerted_fragments = set()

def detect_fragmentaion_attack(packet):
    if Ether in packet:
        # Strip Ethernet layer to focus on the payload (IP layer)
        packet = packet[Ether].payload

    if IP in packet:
        ip = packet[IP]
        unique_fragment = (ip.src, ip.dst, ip.id)

        # Check if the packet is fragmented (More Fragments or Fragment Offset > 0)
        if ip.flags & 1 or ip.frag > 0:
            # Only alert once for a unique fragmented packet
            if unique_fragment not in alerted_fragments:
                print(f"Alert: Potential Fragmentation attack detected! from {ip.src} -> {ip.dst}")
                alerted_fragments.add(unique_fragment)

            # Add the fragment to the list by its ID
            fragments[ip.id].append(ip)

            # Reassembly check - sum the payload lengths to estimate if we've seen all fragments
            total_payload = sum(len(frag.payload) for frag in fragments[ip.id])
            if total_payload >= ip.len:
                print(f"Reassembled packet from {ip.src} -> {ip.dst}")
                # Reset the fragments after reassembly
                fragments[ip.id].clear()


# detect HTTP flood attacks

request_counts = defaultdict(lambda: {"count":0, "timestamp" : deque()})
time_window = 1
request_thershold = 100

def detect_HTTP_flood(packet):
    src_ip = packet[IP].src
    if src_ip in whitelisted_ips:
        return


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
    
def packet_handler(packet):
    detect_icmp_flood(packet)
    #detect_port_scan(packet)
    detect_syn_flood(packet)
    #detect_dns_flood(packet)
    dns_amplification_detect(packet)
    detect_brute_force(packet)
    detect_arp_spoofing(packet)
    detect_sql_injection(packet)
    detect_unathorized_protocols(packet)
    detect_dns_tunneling(packet)
    detect_rdp(packet)
    detect_smb(packet)
    detect_dns_poisoning(packet)
    detect_xss(packet)
    detect_fragmentaion_attack(packet)
    detect_HTTP_flood(packet)

    

import pyfiglet
from rich.console import Console

# Create a console object for rich text rendering
console = Console()

# Generate ASCII art with pyfiglet
ascii_art = pyfiglet.figlet_format("NIDS", font="starwars")

# Print the ASCII art with color
console.print(ascii_art, style="green")


from rich.progress import track
from time import sleep

# Create a console object
console = Console()

# Main app
def cool_app():
    console.print("\n[bold cyan]Initializing your Network Intrusion Detection System (NIDS)...[/bold cyan]\n")
    
    # Simulate loading with a progress bar
    for step in track(range(10), description="[green]Activating..."):
        sleep(0.5)
    
    console.print("\n[bold cyan][Activated][/bold cyan] [bold]Your NIDS is ready to use![/bold]")
    console.print("[yellow]Enjoy your experience![/yellow]")
    console.print("[bold green]Starts monitoring.....")

# Run the app
if __name__ == "__main__":
    cool_app()


sniff(filter="ip",prn = packet_handler, store = 0)

