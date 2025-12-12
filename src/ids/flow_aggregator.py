import time
import json
from datetime import datetime
from collections import defaultdict

class FlowAggregator:
    def __init__(self, timeout=60):
        self.timeout = timeout
        self.flows = {}

    @staticmethod
    def _flow_key(packet):
        return (
            packet["src_ip"],
            packet["dst_ip"],
            packet["src_port"],
            packet["dst_port"],
            packet["protocol"]
        )

    def add_packet(self, packet):
        key = FlowAggregator._flow_key(packet)

        if key not in self.flows:
            self.flows[key] = {
                "src_ip": packet["src_ip"],
                "dst_ip": packet["dst_ip"],
                "src_port": packet["src_port"],
                "dst_port": packet["dst_port"],
                "protocol": packet["protocol"],
                "start_ts": packet["timestamp"],
                "end_ts": packet["timestamp"],
                "packet_count": 0,
                "total_bytes": 0,
                "sizes": [],
                "times": [],
                "tcp_flags": defaultdict(int),
                "dns_query_count": 0,
                "http_request_count": 0,
                "unique_http_hosts": set(),
            }

        flow = self.flows[key]

        flow["packet_count"] += 1
        flow["total_bytes"] += packet["length"]
        flow["sizes"].append(packet["length"])
        flow["end_ts"] = packet["timestamp"]

        if flow["times"]:
            flow["times"].append(packet["timestamp"] - flow["times"][-1])
        else:
            flow["times"].append(0)

        if packet["tcp_flags"] != "-":
            flow["tcp_flags"][packet["tcp_flags"]] += 1

        if packet.get("dns_query") not in (None, ""):
            flow["dns_query_count"] += 1

        if packet.get("http_host"):
            flow["http_request_count"] += 1
            flow["unique_http_hosts"].add(packet.get("http_host"))


    def export_timeout_flows(self):
        now = time.time()
        exported = []

        remove_keys = []
        for key, flow in self.flows.items():
            if now - flow["end_ts"] > self.timeout:
                exported.append(FlowAggregator._finalize_flow(flow))
                remove_keys.append(key)

        for k in remove_keys:
            del self.flows[k]

        return exported

    @staticmethod
    def _finalize_flow(flow):
        duration = flow["end_ts"] - flow["start_ts"]
        avg_size = sum(flow["sizes"]) / len(flow["sizes"]) if flow["sizes"] else 0
        avg_inter = sum(flow["times"]) / len(flow["times"]) if flow["times"] else 0

        return {
            "src_ip": flow["src_ip"],
            "dst_ip": flow["dst_ip"],
            "src_port": flow["src_port"],
            "dst_port": flow["dst_port"],
            "protocol": flow["protocol"],
            "packet_count": flow["packet_count"],
            "total_bytes": flow["total_bytes"],
            "avg_packet_size": avg_size,
            "duration": duration,
            "avg_interarrival_time": avg_inter,
            "tcp_flag_syn": flow["tcp_flags"].get("S", 0),
            "tcp_flag_fin": flow["tcp_flags"].get("F", 0),
            "tcp_flag_rst": flow["tcp_flags"].get("R", 0),
            "tcp_flag_ack": flow["tcp_flags"].get("A", 0),
            "dns_query_count": flow["dns_query_count"],
            "http_request_count": flow["http_request_count"],
            "unique_http_hosts": list(flow["unique_http_hosts"]),
            "timestamp_end": flow["end_ts"],
        }

if __name__ == "__main__":
    import os
    aggregator = FlowAggregator()
    flows = aggregator.export_timeout_flows()
    os.makedirs("flows", exist_ok=True)
    with open("flows/flows_sample.jsonl", "a") as f:
        for fl in flows:
            f.write(json.dumps(fl) + "\n")
