import json
import os
import time
from datetime import datetime

import pyshark

from correlation_engine import CorrelationEngine
from detection_engine import DetectionEngine
from flow_aggregator import FlowAggregator
from honeypot_tail import HoneypotTail
from ml_runtime_detector import MLRuntimeDetector
from scan_heuristic import ScanHeuristicDetector

EVENTS_DIR = "logs"
HONEYPOT_EVENTS_FILE = os.path.join(EVENTS_DIR, "honeypot_events.jsonl")


def packet_to_dict(packet):
    try:
        if not hasattr(packet, "ip"):
            return None
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        protocol = packet.highest_layer
        length = int(packet.length)
        ts = packet.sniff_time.timestamp()

        src_port = 0
        dst_port = 0
        if hasattr(packet, "transport_layer") and packet.transport_layer:
            try:
                src_port = int(packet[packet.transport_layer].srcport)
                dst_port = int(packet[packet.transport_layer].dstport)
            except Exception:
                pass

        # TCP flags
        tcp_flags = "-"
        if hasattr(packet, "tcp"):
            tcp_flags = getattr(packet.tcp, "flags", "-")

        # HTTP
        http_host = None
        http_uri = None
        if hasattr(packet, "http"):
            http_host = getattr(packet.http, "host", None)
            http_uri = getattr(packet.http, "request_uri", None)

        # DNS
        dns_query = None
        if hasattr(packet, "dns"):
            dns_query = getattr(packet.dns, "qry_name", None)

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
        print(f"[!] packet_to_dict error (ignored): {type(e).__name__}")
        return None


def save_flows(flow_list):
    os.makedirs("flows", exist_ok=True)
    path = "flows/flows_capture.jsonl"

    with open(path, "a", encoding="utf-8") as f:
        for flow in flow_list:
            f.write(json.dumps(flow) + "\n")


def run_realtime_flow_builder(interface: str, timeout: int = 60, export_interval: int = 5, ml_threshold: float = -0.20):
    print(f"[*] Starting real-time flow builder on interface: {interface}")
    print(f"[*] Flow timeout: {timeout}s | Export interval: {export_interval}s")
    print(f"[*] ML anomaly threshold: {ml_threshold}")

    aggregator = FlowAggregator(timeout=timeout)
    ml_detector = MLRuntimeDetector(threshold=ml_threshold)
    scan_detector = ScanHeuristicDetector(
        window_seconds=10,
        port_threshold=20,
    )
    detection_engine = DetectionEngine(
        ml_detector=ml_detector,
        scan_detector=scan_detector,
    )

    correlator = CorrelationEngine(window_seconds=300)
    honeypot_tail = HoneypotTail(HONEYPOT_EVENTS_FILE)

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

        for hp_event in honeypot_tail.poll():
            correlator.ingest_honeypot_event(hp_event)
            hp_alert = correlator.honeypot_alert(hp_event)
            print("\n[HONEYPOT ALERT]")
            print(json.dumps(hp_alert, indent=2))

        if now - last_export >= export_interval:
            flows = aggregator.export_timeout_flows()

            if flows:
                save_flows(flows)

                for flow in flows:
                    alerts = detection_engine.process_flow(flow)

                    for alert in alerts:
                        alert["timestamp"] = datetime.utcnow().isoformat() + "Z"

                        enriched = correlator.correlate(alert)

                        if enriched.get("correlated"):
                            print("\n[CORRELATED ALERT]")
                        else:
                            print("\n[IDS ALERT]")

                        print(json.dumps(enriched, indent=2))

                print(f"[+] Exported {len(flows)} flows")

            last_export = now


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Realtime Flow Builder for IDS"
    )
    parser.add_argument(
        "--interface",
        required=True,
        help="Network interface to sniff"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Flow timeout in seconds"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=5,
        help="Interval between flow exports"
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=-0.20,
        help="ML anomaly score threshold",
    )
    args = parser.parse_args()

    run_realtime_flow_builder(
        interface=args.interface,
        timeout=args.timeout,
        export_interval=args.interval,
        ml_threshold=args.threshold,
    )
