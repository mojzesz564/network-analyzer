from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import time
import argparse

client = InfluxDBClient(
    url="http://localhost:8086",
    token="wDX6R3P7WvR-vgdtuJTUBRLfFGprSztFdZse9sv9Dx7JdyZfVr0J4FbaUFeQN_NuRX-JarZQEpr0SPd1rBaTvA==",
    org="my-org"
)
write_api = client.write_api(write_options=SYNCHRONOUS)

def start_sniffing(iface):
    print(f"[INFO] Starting pkt capture on {iface}...")
    sniff(iface=iface, prn=pkt_callback, store=False)

def pkt_callback(pkt):
    parsed = parse_pkt(pkt)
    try:
        point = (
            Point("packet")
            .tag("src_ip", parsed["src_ip"])
            .tag("dst_ip", parsed["dst_ip"])
            .tag("protocol", parsed["protocol"])
            .field("src_port", parsed.get("src_port", 0))
            .field("dst_port", parsed.get("dst_port", 0))
            .field("protocol", parsed["protocol"])
            .time(time.time_ns())
        )
        write_api.write(bucket="network", record=point)
    except Exception as e:
        print(f"[!] Error logging pkt: {e}")

def parse_pkt(pkt):
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        protocol = pkt[IP].proto
        summary = {'src_ip': ip_src, 'dst_ip': ip_dst, 'protocol': protocol}

        if TCP in pkt:
            summary['src_port'] = pkt[TCP].sport
            summary['dst_port'] = pkt[TCP].dport
        elif UDP in pkt:
            summary['src_port'] = pkt[UDP].sport
            summary['dst_port'] = pkt[UDP].dport


        return summary
    return None

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--iface', default='eth0')
    args = parser.parse_args()

    start_sniffing(args.iface)