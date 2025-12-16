from datetime import datetime, timedelta
from collections import defaultdict

class CorrelationEngine:

    def __init__(self, window_seconds: int = 300):
        self.window = timedelta(seconds=window_seconds)
        self.honeypot_events = defaultdict(list)

    def ingest_honeypot_event(self, event: dict):
        try:
            ts = self._parse_ts(event["timestamp"])
            src_ip = event.get("source")

            if not src_ip:
                return

            self.honeypot_events[src_ip].append({
                "timestamp": ts,
                "attack_type": event.get("attack_type"),
                "route": event.get("route"),
            })

            self._cleanup(src_ip)

        except Exception:
            pass

    def correlate(self, ids_alert: dict) -> dict:
        src_ip = ids_alert.get("src_ip")
        if not src_ip:
            return ids_alert

        now = self._parse_ts(ids_alert.get("timestamp"))
        matches = []

        for ev in self.honeypot_events.get(src_ip, []):
            if now - ev["timestamp"] <= self.window:
                matches.append(ev)

        if matches:
            ids_alert["correlated"] = True
            ids_alert["confidence"] = "HIGH"
            ids_alert["severity"] = min(ids_alert.get("severity", 3) + 2, 10)
            ids_alert["honeypot_evidence"] = matches
        else:
            ids_alert["correlated"] = False
            ids_alert["confidence"] = "LOW"

        return ids_alert

    def _cleanup(self, src_ip: str):
        now = datetime.now()
        self.honeypot_events[src_ip] = [
            e for e in self.honeypot_events[src_ip]
            if now - e["timestamp"] <= self.window
        ]

    @staticmethod
    def _parse_ts(ts: str) -> datetime:
        return datetime.fromisoformat(ts.replace("Z", ""))

    def honeypot_alert(self, event: dict) -> dict:
        return {
            "type": "HONEYPOT_ATTACK",
            "timestamp": event["timestamp"],
            "src_ip": event["source"],
            "severity": 7,
            "confidence": "VERY_HIGH",
            "attack_type": event["attack_type"],
            "route": event.get("route"),
        }
