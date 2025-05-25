from scapy.all import sniff
from analyzer.parser import parse_packet

def packet_callback(packet):
    parsed = parse_packet(packet)
    if parsed:
        print(parsed)

def start_sniffing(iface):
    print(f"[INFO] Starting packet capture on {iface}...")
    sniff(iface=iface, prn=packet_callback, store=False)