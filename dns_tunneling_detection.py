from scapy.all import DNS,DNSQR,IP,sniff
import string
from collections import Counter
import math

# parameter to define thresholds for suspicious activity 
max_query_length = 50 # maximum length for normal dns queries
entropy_threshold = 3.8 # threshold for entropy to detect randomness
max_query_rate = 10  # maximum queries per second from single source

query_counter = Counter() # track query rate per ip

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
        query_counter[src_ip] += 1
        if query_counter[src_ip] > max_query_rate:
            print(f"High DNS query rate from IP: {src_ip}")
            query_counter[src_ip] = 0 # reset count after flagging


print("Starting DNS Tunneling Detection....")
sniff(filter="udp port 53",prn= detect_dns_tunneling,store = False)