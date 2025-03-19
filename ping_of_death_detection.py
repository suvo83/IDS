from scapy.all import sniff, ICMP, IP

total_icmp_packet = 0
icmp_ping_of_death_thershould = 65535

def detect_ping_of_detah(packet):
    src_ip = packet[IP].src
    global total_icmp_packet
    if packet.haslayer(ICMP):
        total_icmp_packet += len(packet)
        if total_icmp_packet > icmp_ping_of_death_thershould:
            print(f"Ping of death detected! form IP: {src_ip}")

print("Starting icmp ping of death detection....")
sniff(filter="icmp",prn=detect_ping_of_detah,store=0)