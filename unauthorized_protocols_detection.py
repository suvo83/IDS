from scapy.all import sniff
from scapy.layers.inet import TCP
import logging

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


print ("Monitoring network traffic for unauthorized protocols....")
sniff(filter="tcp", prn=detect_unathorized_protocols,store = 0)