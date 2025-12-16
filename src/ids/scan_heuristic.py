import time
from collections import defaultdict

class ScanHeuristicDetector:
    def __init__(self, window_seconds=10, port_threshold=20):
        self.window = window_seconds
        self.port_threshold = port_threshold
        self.events = defaultdict(list)

    def process_flow(self, flow: dict):
        if flow.get("src_ip") in ("-", None):
            return None
        key = (flow["src_ip"], flow["dst_ip"])
        now = flow["timestamp_end"]

        dst_port = flow.get("dst_port", 0)
        if dst_port == 0:
            return None

        self.events[key].append((now, dst_port))

        self.events[key] = [
            (ts, port) for ts, port in self.events[key]
            if now - ts <= self.window
        ]

        unique_ports = {port for _, port in self.events[key]}

        if len(unique_ports) >= self.port_threshold:
            return {
                "type": "PORT_SCAN",
                "src_ip": flow["src_ip"],
                "dst_ip": flow["dst_ip"],
                "ports": sorted(unique_ports),
                "window": self.window,
                "severity": 4,
            }

        return None
