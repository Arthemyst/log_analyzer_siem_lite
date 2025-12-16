from mitre_mapping import MITRE_MAP

class DetectionEngine:
    def __init__(self, ml_detector, scan_detector):
        self.ml = ml_detector
        self.scan = scan_detector

    def _enrich_with_mitre(self, alert: dict) -> dict:
        mapping = MITRE_MAP.get(alert["type"])
        if mapping:
            alert["mitre"] = mapping
        return alert

    def process_flow(self, flow: dict):
        alerts = []

        ml_alert = self.ml.score_flow(flow)
        if ml_alert and ml_alert.get("anomaly"):
            alerts.append(ml_alert)

        scan_alert = self.scan.process_flow(flow)
        if scan_alert:
            alerts.append(scan_alert)

        return alerts
