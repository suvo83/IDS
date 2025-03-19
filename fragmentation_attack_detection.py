from scapy.all import sniff, IP, Ether
from collections import defaultdict

# Dictionary to store fragments by IP ID
fragments = defaultdict(list)
# Set to track alerted fragments (src, dst, id)
alerted_fragments = set()

def detect_fragmentation(packet):
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

print("Fragmentation attack detection is starting...")
sniff(filter="ip", prn=detect_fragmentation, store=0)


