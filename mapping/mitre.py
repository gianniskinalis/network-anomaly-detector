def map_to_mitre(flow):
    """
    Map an anomalous flow to the moast likely MITRE ATT&CK tactic
    based on its behavioral features.
    """
    tags = []

    # T1071 - Application Layer Protocol (C2 beaconing)
    # Short, regular, small packets at consistent intervals
    if (flow["avg_inter_arrival"] < 1.0 and
            flow["avg_packet_size"] < 100 and
            flow["packet_count"] >= 4):
        tags.append({
            "tactic":    "Command & Control",
            "technique": "T1071 - Application Layer Protocol",
            "reason":    "Small regular packets suggesting beaconing behavior"
        })

    # T1048 - Exfiltraton over alternative protocol
    # Large total bytes outbound
    if flow["total_bytes"] > 2000 and flow["duration"] < 5.0:
        tags.append({
            "tactic":    "Exfiltration",
            "technique": "T1048 - Application Layer Protocol",
            "reason":    f"Large data transfer ({flow['total_bytes']}B) in short duration"
        })

    # T1046 - Network Service Scanning
    # Many unique destination ports from same source
    if flow["unique_dst_ports"] > 5:
        tags.append({
            "tactic":    "Discovery",
            "technique": "T1046 - Network Scanning Service",
            "reason":    f"High unique destination port count ({flow['unique_dst_ports']})"
        })

    # T1110 - Brute Force
    # Many SYN packets indicating repeated connection attempts
    if flow["syn_count"] > 5:
        tags.append({
            "tactic":    "Credential Access",
            "technique": "T1110 - Brute Force",
            "reason":    f"High SYN count ({flow['syn_count']}) suggesting repeated attempts"
        })

    # T1571 - Non-Standard Port
    # Traffic on uncommon ports (not 80, 443, 22, 53)
    common_ports = {80, 443, 22, 53}
    dst_port = flow.get("dst_port")
    if dst_port and dst_port not in common_ports and dst_port < 1024:
        tags.append({
            "tactic":    "Command & Control",
            "technique": "T1571 - Non-Standard Port",
            "reason":    f"Traffic on uncommon port {dst_port}"
        })

    if not tags:
        tags.append({
            "tactic":    "Unknown",
            "technique": "Unclassified anomaly",
            "reason":    "Anomalous behavior detected but no specific technique matched"
        })

    return tags


def enrich_anomalies(results):
    """Add MITRE tags to all anomalous flows."""
    enriched = []
    for flow in results:
        if flow["is_anomaly"]:
            flow["mitre_tags"] = map_to_mitre(flow)
        else:
            flow["mitre_tags"] = []
        enriched.append(flow)
    return enriched
