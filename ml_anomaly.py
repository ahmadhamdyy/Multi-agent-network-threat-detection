from __future__ import annotations

import csv
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction import DictVectorizer


def _parse_bool(v: str) -> int:
    v = (v or "").strip().lower()
    return 1 if v in {"true", "1", "yes", "y", "t"} else 0


def _parse_float(v: str, default: float = 0.0) -> float:
    v = (v or "").strip()
    if not v:
        return default
    try:
        return float(v)
    except ValueError:
        return default


def _parse_ts_parts(dt_str: str) -> Tuple[int, int]:
    """
    Parse dataset timestamps like `2020-02-03 12:43:30.772`.
    Returns (hour, weekday) with best-effort defaults.
    """
    dt_str = (dt_str or "").strip()
    if not dt_str:
        return (0, 0)
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            d = datetime.strptime(dt_str, fmt)
            return (int(d.hour), int(d.weekday()))
        except ValueError:
            continue
    return (0, 0)


def row_to_features(row: Dict[str, str]) -> Dict[str, object]:
    """
    Convert an RBA CSV row into a small, cheap feature dict.
    Keep this intentionally lightweight (no heavy NLP, no external calls).
    """
    hour, weekday = _parse_ts_parts(row.get("Login Timestamp", ""))
    rtt = _parse_float(row.get("Round-Trip Time [ms]"), default=0.0)

    country = (row.get("Country") or "").strip().lower() or "unknown"
    device = (row.get("Device Type") or "").strip().lower() or "unknown"

    # Keep UA very coarse to avoid huge cardinality.
    ua = (row.get("User Agent String") or "").strip().lower()
    ua_family = "other"
    for kw in ("chrome", "safari", "firefox", "edge", "curl", "python"):
        if kw in ua:
            ua_family = kw
            break

    feats: Dict[str, object] = {
        "country": country,
        "device": device,
        "ua_family": ua_family,
        "hour": hour,
        "weekday": weekday,
        "rtt_ms": float(rtt),
        # Including this can help spot “successful but weird” vs “failed but common”.
        "login_success": int(_parse_bool(row.get("Login Successful", "False"))),
    }
    return feats


@dataclass(frozen=True)
class AnomalyDetector:
    vectorizer: DictVectorizer
    model: IsolationForest

    def score_features(self, feats: Dict[str, object]) -> float:
        """
        Return anomaly score where **higher => more anomalous**.
        IsolationForest uses +1 (inlier) / -1 (outlier) and decision_function where higher is *more normal*.
        We invert decision_function so higher is more anomalous.
        """
        X = self.vectorizer.transform([feats])
        normality = float(self.model.decision_function(X)[0])  # higher => more normal
        return -normality

    def score_event(self, event: Dict[str, object]) -> float:
        feats = {
            "country": str(event.get("country", "unknown") or "unknown").strip().lower(),
            "device": str(event.get("device", "unknown") or "unknown").strip().lower(),
            "ua_family": "other",
            "hour": 0,
            "weekday": 0,
            "rtt_ms": float(event.get("rtt_ms", 0) or 0),
            "login_success": int(bool(event.get("login_success"))),
        }
        return self.score_features(feats)


def train_from_csv(
    csv_path: str,
    *,
    sample_size: int = 200_000,
    max_rows: Optional[int] = None,
    random_seed: int = 42,
    contamination: float = 0.02,
) -> AnomalyDetector:
    """
    Train a lightweight IsolationForest on a uniform sample of rows.

    Notes:
    - We sample to keep memory/time reasonable on 1M+ rows.
    - This is unsupervised; we intentionally do NOT use dataset labels like "Is Attack IP".
    """
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Training CSV not found: {csv_path}")

    rng = np.random.default_rng(random_seed)
    reservoir: List[Dict[str, object]] = []
    seen = 0

    with open(csv_path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if max_rows is not None and seen >= max_rows:
                break
            feats = row_to_features(row)
            seen += 1

            if len(reservoir) < sample_size:
                reservoir.append(feats)
                continue

            # Reservoir sampling.
            j = int(rng.integers(0, seen))
            if j < sample_size:
                reservoir[j] = feats

    if not reservoir:
        raise ValueError("No rows read from training CSV.")

    vec = DictVectorizer(sparse=True)
    X = vec.fit_transform(reservoir)

    model = IsolationForest(
        n_estimators=200,
        random_state=random_seed,
        contamination=contamination,
        n_jobs=-1,
    )
    model.fit(X)
    return AnomalyDetector(vectorizer=vec, model=model)


def save(detector: AnomalyDetector, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    joblib.dump({"vectorizer": detector.vectorizer, "model": detector.model}, path)


def load(path: str) -> AnomalyDetector:
    obj = joblib.load(path)
    return AnomalyDetector(vectorizer=obj["vectorizer"], model=obj["model"])

