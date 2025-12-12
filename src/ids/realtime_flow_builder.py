import os
import time
import json
import pyshark
from flow_aggregator import FlowAggregator


def packet_to_dict(packet):
    try:
        src_ip = packet.ip.src if hasattr(packet, "ip") else "-"
        dst_ip = packet.ip.dst if hasattr(packet, "ip") else "-"
        protocol = packet.highest_layer
        length = int(packet.length)
        ts = packet.sniff_time.timestamp()

        try:
            src_port = packet[packet.transport_layer].srcport
            dst_port = packet[packet.transport_layer].dstport
        except Exception:
            src_port = "-"
            dst_port = "-"

        tcp_flags = packet.tcp.flags if hasattr(packet, "tcp") else "-"

        http_host = packet.http.host if hasattr(packet, "http") else None
        http_uri = packet.http.request_uri if hasattr(packet, "http") else None
        dns_query = packet.dns.qry_name if hasattr(packet, "dns") else None

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "timestamp": ts,
            "length": length,
            "tcp_flags": tcp_flags,
            "http_host": http_host,
            "http_path": http_uri,
            "dns_query": dns_query,
        }

    except Exception as e:
        print(f"[!] packet_to_dict error: {e}")
        return None



def save_flows(flow_list):
    os.makedirs("flows", exist_ok=True)

    with open("flows/flows_capture.jsonl", "a", encoding="utf-8") as f:
        for flow in flow_list:
            f.write(json.dumps(flow) + "\n")


def run_realtime_flow_builder(interface: str, timeout: int = 60, export_interval: int = 5):
    print(f"[*] Starting real-time flow builder on interface: {interface}")
    print(f"[*] Flow timeout: {timeout}s | Export interval: {export_interval}s")

    aggregator = FlowAggregator(timeout=timeout)

    try:
        capture = pyshark.LiveCapture(interface=interface)
    except Exception as e:
        print(f"[!] Failed to initialize capture on {interface}: {e}")
        return

    last_export = time.time()

    for packet in capture.sniff_continuously():
        pkt_dict = packet_to_dict(packet)
        if pkt_dict:
            aggregator.add_packet(pkt_dict)

        now = time.time()
        if now - last_export >= export_interval:
            flows = aggregator.export_timeout_flows()

            if flows:
                save_flows(flows)
                print(f"[+] Exported {len(flows)} flows")

            last_export = now

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Realtime Flow Builder for IDS")
    parser.add_argument("--interface", required=True, help="Network interface to sniff")
    parser.add_argument("--timeout", type=int, default=60, help="Flow timeout in seconds")
    parser.add_argument("--interval", type=int, default=5, help="Interval between flow exports")

    args = parser.parse_args()

    run_realtime_flow_builder(
        interface=args.interface,
        timeout=args.timeout,
        export_interval=args.interval
    )
