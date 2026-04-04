import sys
from capture.capture import read_pcap, parse_packets, print_summary
from features.extractor import group_into_flows, extract_features, print_flow_summary
from baseline.profiler import init_db, store_flows, load_flows
from detection.detector import train_baseline, score_flows, print_anomalies
from mapping.mitre import enrich_anomalies
from report.reporter import generate_report, print_report_summary


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 main.py <path_to_pcap>")
        sys.exit(1)

    pcap_path = sys.argv[1]

    # Phase 1: read and parse
    packets = read_pcap(pcap_path)
    records = parse_packets(packets)
    print_summary(records)

    # Phase 2: flow extraction
    flows = group_into_flows(records)
    features = extract_features(flows)
    print_flow_summary(features)

    # Phase 3: store and detect
    init_db()
    store_flows(features)
    all_flows = load_flows()
    model = train_baseline(all_flows)
    results = score_flows(model, all_flows)
    print_anomalies(results)

    # Phase 4: MITRE mapping and reporting
    enriched = enrich_anomalies(results)
    print_report_summary(enriched)
    generate_report(enriched)


if __name__ == "__main__":
    main()
