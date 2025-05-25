from scapy.layers.inet import IP, TCP, UDP

def parse_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        summary = {'src': ip_src, 'dst': ip_dst, 'proto': proto}

        if TCP in packet:
            summary['sport'] = packet[TCP].sport
            summary['dport'] = packet[TCP].dport
            summary['type'] = 'TCP'
        elif UDP in packet:
            summary['sport'] = packet[UDP].sport
            summary['dport'] = packet[UDP].dport
            summary['type'] = 'UDP'
        else:
            summary['type'] = 'IP'

        return summary
    return None