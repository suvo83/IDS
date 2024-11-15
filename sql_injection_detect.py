import re
from scapy.all import sniff,Raw
from scapy.layers.http import HTTPRequest

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

print("Starting SQL Injection detection...........")
sniff(filter = "tcp port 80",prn=detect_sql_injection,store = False)