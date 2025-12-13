import json
import os
import numpy as np
import joblib

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from feature_config import FEATURE_COLUMNS


FLOWS_FILE = "flows/flows_capture.jsonl"
ARTIFACTS_DIR = "src/ids/ml/artifacts"


def load_flows(path: str) -> list:
    flows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            flows.append(json.loads(line))
    return flows


def build_feature_matrix(flows: list) -> np.ndarray:
    X = []
    for flow in flows:
        row = []
        for col in FEATURE_COLUMNS:
            row.append(float(flow.get(col, 0)))
        X.append(row)
    return np.array(X)
