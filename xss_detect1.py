import re
from scapy.all import sniff, Raw

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
            

print("starting sniffing for xss detection...")
sniff(filter="ip", prn = detect_xss, store=0)