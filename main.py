import sys
from capture.capture import read_pcap, parse_packets, print_summary
from features.extractor import group_into_flows, extract_features, print_flow_summary

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
     

if __name__ == "__main__":
    main()