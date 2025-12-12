import pyshark
import argparse

def capture_packets(interface: str, packet_count: int = 10):
    print(f"Starting live capture on {interface}, first {packet_count} packets")
    
    capture = pyshark.LiveCapture(interface=interface)

    for i, packet in enumerate(capture.sniff_continuously(packet_count=packet_count)):
        try:
            src_ip = packet.ip.src if hasattr(packet, 'ip') else "-"
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else "-"
            protocol = packet.highest_layer
            length = int(packet.length)
            ts = packet.sniff_time.isoformat()
            src_port = packet[packet.transport_layer].srcport if hasattr(packet, 'transport_layer') else "-"
            dst_port = packet[packet.transport_layer].dstport if hasattr(packet, 'transport_layer') else "-"
            tcp_flags = packet.tcp.flags if hasattr(packet, 'tcp') else "-"
            http_host = packet.http.host if hasattr(packet, 'http') else "-"
            http_path = packet.http.request_uri if hasattr(packet, 'http') else ""
            dns_query = packet.dns.qry_name if hasattr(packet, 'dns') else ""
            
            print(f"{i+1}: {ts} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | {protocol} | length={length} | flags={tcp_flags} | http={http_host}{http_path} | dns={dns_query}")
        except Exception as e:
            print(f"[!] Packet parse error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Flow Capture for Hybrid IDS")
    parser.add_argument("--iface", required=True, help="Network interface to capture packets from")
    parser.add_argument("--count", type=int, default=10, help="Number of packets to capture for test")
    args = parser.parse_args()

    capture_packets(args.iface, args.count)
