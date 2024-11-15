from scapy.all import sniff, IP, TCP

# Detect SMB traffic
def detect_smb(packet):
    if packet.haslayer(TCP) and packet[TCP].dport in [445, 139]:
        print(f"[SMB Traffic Detected] From IP: {packet[IP].src} -> To IP: {packet[IP].dst}")

# Detect RDP traffic
def detect_rdp(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 3389:
        print(f"[RDP Traffic Detected] From IP: {packet[IP].src} -> To IP: {packet[IP].dst}")

# Main detection function
def detect(packet):
    detect_rdp(packet)
    detect_smb(packet)

print("Starting packet detection...")
sniff(prn=detect, store=0)
