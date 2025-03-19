from scapy.all import sniff, IP, TCP, Raw
import re

# Define patterns for CRLF and suspicous headers

CRLF_pattern = r"%0D%0A|(\r\n)"
duplicate_header_pattern = r"Set-Cookie: | Location: | Conternt-Length: "


def detect_HTTP_response_spliting(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        if packet[TCP].dport == 80 and packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors="ignore")

            if re.search(CRLF_pattern, payload):
                print(f"Alert Potential HTTP response splitting attempt detected from {packet[IP].src}")

            header_count = len(re.findall(duplicate_header_pattern, payload))
            if len(header_count) > 1:
                print(f"Alert! suspicious http header detected in response from {packet[IP].src}")

print("Out detection is starting>>>>>")

sniff(filter="tcp port 80", prn = detect_HTTP_response_spliting, store = 0)