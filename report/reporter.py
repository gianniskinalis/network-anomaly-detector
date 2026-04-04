import json
import os
from datetime import datetime


def generate_report(enriched_results, output_dir="reports"):
    """Generate a JSON report of all anomalous flows."""
    os.makedirs(output_dir, exist_ok=True)

    anomalies = [f for f in enriched_results if f["is_anomaly"]]

    report = {
        "report_generated": datetime.now().isoformat(),
        "total_flows_analysed": len(enriched_results),
        "total_anomalies": len(anomalies),
        "anomalies": []
    }

    for a in anomalies:
        report["anomalies"].append({
            "src_ip":        a["src_ip"],
            "dst_ip":        a["dst_ip"],
            "src_port":      a["src_port"],
            "dst_port":      a["dst_port"],
            "protocol":      a["protocol"],
            "anomaly_score": a["anomaly_score"],
            "features": {
                "duration":          a["duration"],
                "packet_count":      a["packet_count"],
                "total_bytes":       a["total_bytes"],
                "avg_packet_size":   a["avg_packet_size"],
                "avg_inter_arrival": a["avg_inter_arrival"],
                "syn_count":         a["syn_count"],
            },
            "mitre_tags": a["mitre_tags"]
        })

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/report_{timestamp}.json"

    with open(filename, "w") as f:
        json.dump(report, f, indent=2)

    print(f"[*] Report saved to {filename}")
    return filename


def print_report_summary(enriched_results):
    """Print a human readable summary of the report."""
    anomalies = [f for f in enriched_results if f["is_anomaly"]]

    print(f"\n{'='*70}")
    print("  THREAT REPORT SUMMARY")
    print(f"{'='*70}")
    print(f"  Total flows analysed : {len(enriched_results)}")
    print(f"  Anomalies detected  : {len(anomalies)}")
    print(f"{'='*70}")

    for i, a in enumerate(anomalies):
        print(f"\n [{i+1:03}] {a['src_ip']} -> {a['dst_ip']} (score: {a['anomaly_score']})")
        for tag in a["mitre_tags"]:
            print(f"         [!] {tag['tactic']} | {tag['technique']}")
            print(f"             {tag['reason']}")

    print(f"\n{'='*70}\n")
