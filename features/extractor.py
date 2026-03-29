from collections import defaultdict

def group_into_flows(records):
    """Group individual packet records into flows."""
    flows = defaultdict(list)

    for record in records:
        key = (
            record["src_ip"],
            record["dst_ip"],
            record["src_port"],
            record["dst_port"],
            record["protocol"],
        )
        flows[key].append(record)

    print(f"[*] Grouped {len(records)} packets into {len(flows)} flows")
    return flows

def extract_features(flows):
    """Extract numerical features from each flow."""
    feature_records = []

    for flow_key, packets in flows.items():
        src_ip, dst_ip, src_port, dst_port, protocol = flow_key

        timestamps = [p["timestamp"] for p in packets]
        lengths = [p["length"] for p in packets]

        duration = max(timestamps) - min(timestamps)
        total_bytes = sum(lengths)
        packet_count = len(packets)
        avg_packet_size = total_bytes / packet_count
        avg_inter_arrival = duration / packet_count if packet_count > 1 else 0

        unique_dst_ports = len(set(p["dst_port"] for p in packets if p["dst_port"]))

        flag_counts = {}
        for p in packets:
            if p["flags"]:
                flag_counts[p["flags"]] = flag_counts.get(p["flags"], 0) + 1
        syn_count = flag_counts.get("S", 0)

        feature_records.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "duration": round(duration, 6),
            "packet_count": packet_count,
            "total_bytes": total_bytes,
            "avg_packet_size": round(avg_packet_size, 2),
            "avg_inter_arrival": round(avg_inter_arrival, 6),
            "unique_dst_ports": unique_dst_ports,
            "syn_count": syn_count,
        })

    return feature_records

def print_flow_summary(feature_records, limit=10):
    """Print a summary of extracted flows."""
    print(f"\n{'='*70}")
    print(f"  FLOW SUMMARY (first {limit})")
    print(f"{'='*70}")

    for i, f in enumerate(feature_records[:limit]):
        print(f" [{i+1:03}] {f['src_ip']:<18} -> {f['dst_ip']:<18} {f['protocol']:<5}")
        print(f"       pkts={f['packet_count']:<5} bytes={f['total_bytes']:<8} "
              f"duration={f['duration']}s avg_size={f['avg_packet_size']}B")
        
    print(f"{'='*70}\n")