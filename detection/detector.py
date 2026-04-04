import numpy as np
from sklearn.ensemble import IsolationForest

FEATURES = [
    "duration",
    "packet_count",
    "total_bytes",
    "avg_packet_size",
    "avg_inter_arrival",
    "unique_dst_ports",
    "syn_count",
]


def train_baseline(flows):
    """Train an Isolation Forest on stored flows."""
    X = np.array([[f[feat] for feat in FEATURES] for f in flows])

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42
    )
    model.fit(X)
    print(f"[*] Baseline trained on {len(flows)} flows")
    return model


def score_flows(model, flows):
    """Score flows and flag anomalies. Returns flows with anomaly scores."""
    X = np.array([[f[feat] for feat in FEATURES] for f in flows])

    scores = model.decision_function(X)
    predictions = model.predict(X)

    results = []
    for i, flow in enumerate(flows):
        result = flow.copy()
        result["anomaly_score"] = round(float(scores[i]), 4)
        result["is_anomaly"] = predictions[i] == -1
        results.append(result)

    anomaly_count = sum(1 for r in results if r["is_anomaly"])
    print(f"[*] Scored {len(results)} flows - {anomaly_count} anomalies detected")
    return results


def print_anomalies(results, limit=10):
    """Print flagged anomalous flows."""
    anomalies = [r for r in results if r["is_anomaly"]]
    anomalies.sort(key=lambda x: x["anomaly_score"])

    print(f"\n{'='*70}")
    print(f"  ANOMALIES DETECTED ({len(anomalies)} total, showing {min(limit, len(anomalies))})")
    print(f"{'='*70}")

    if not anomalies:
        print("  No anomalies detected.")
    else:
        for i, a in enumerate(anomalies[:limit]):
            print(f" [{i+1:03}] {a['src_ip']:<18} -> {a['dst_ip']:<18} {a['protocol']:<5}")
            print(f"        score={a['anomaly_score']:<8} pkts={a['packet_count']:<5} "
                  f"bytes={a['total_bytes']:<8} duration={a['duration']}s")

    print(f"{'='*70}\n")
