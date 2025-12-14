import json
from datetime import datetime

import joblib
import numpy as np

ARTIFACTS_DIR = "src/ids/ml/artifacts"


class MLRuntimeDetector:
    def __init__(self, threshold: float = -0.20):
        self.model = joblib.load(f"{ARTIFACTS_DIR}/isolation_forest.joblib")
        self.scaler = joblib.load(f"{ARTIFACTS_DIR}/scaler.joblib")

        with open(f"{ARTIFACTS_DIR}/features.json", "r") as f:
            self.features = json.load(f)

        self.threshold = threshold

    def _vectorize(self, flow: dict) -> np.ndarray:
        row = []
        for col in self.features:
            row.append(float(flow.get(col, 0)))
        X = np.array([row])
        return self.scaler.transform(X)

    def score_flow(self, flow: dict) -> dict:
        X = self._vectorize(flow)

        score = float(self.model.decision_function(X)[0])
        anomaly = score < self.threshold

        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "src_ip": flow.get("src_ip"),
            "dst_ip": flow.get("dst_ip"),
            "src_port": flow.get("src_port"),
            "dst_port": flow.get("dst_port"),
            "protocol": flow.get("protocol"),
            "score": score,
            "anomaly": anomaly,
        }
