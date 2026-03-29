from scapy.all import rdpcap, sniff, IP, TCP, UDP, ICMP
from datetime import datetime

def read_pcap(filepath):
    """Read packets from a PCAP file."""
    print(f"[*] Reading PCAP: {filepath}")
    packets = rdpcap(filepath)
    print(f"[*] Loaded {len(packets)} packets")
    return packets

def capture_live(interface="eth0", packet_count=100, timeout=30):
    """Capture live traffic from a network interface."""
    print(f"[*] Capturing {packet_count} packets on {interface} (timeout: {timeout}s)")
    packets = sniff(iface=interface, count=packet_count, timeout=timeout)
    print(f"[*] Captured {len(packets)} packets")
    return packets

def parse_packet(packet):
    """Extract key fields from a single packet. Returns a dict or None."""
    if not packet.haslayer(IP):
        return None
    record = {
        "timestamp": float(packet.time),
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "protocol": packet[IP].proto,
        "length": len(packet),
        "src_port": None,
        "dst_port": None,
        "flags": None,
    }

    if packet.haslayer(TCP):
        record["src_port"] = packet[TCP].sport
        record["dst_port"] = packet[TCP].dport
        record["flags"] = str(packet[TCP].flags)
        record["protocol"] = "TCP"

    elif packet.haslayer(UDP):
        record["src_port"] = packet[UDP].sport
        record["dst_port"] = packet[UDP].dport
        record["protocol"] = "TCP"

    elif packet.haslayer(ICMP):
        record["protocol"] = "ICMP"

    return record

def parse_packets(packets):
    """Parse a list of packets into a list of records."""
    records = []
    skipped = 0

    for packet in packets:
        record = parse_packet(packet)
        if record:
            records.append(record)
        else:
            skipped += 1

    print(f"[*] Parsed {len(records)} IP packets ({skipped} non-IP skipped)")
    return records

def print_summary(records, limit=10):
    """Print a human-readable summary of the first N records."""
    print(f"\n{'='*60}")
    print(f"  PACKET SUMMARY (first {limit})")
    print(f"{'='*60}")

    for i, r in enumerate(records[:limit]):
        ts = datetime.fromtimestamp(r["timestamp"]).strftime("%H:%M:%S.%f")[:-3]
        src = f"{r['src_ip']}:{r['src_port']}" if r["src_port"] else r["src_ip"]
        dst = f"{r['dst_ip']}:{r['dst_port']}" if r["dst_port"] else r["dst_ip"]
        flags = f" [{r['flags']}]" if r["flags"] else ""
        print(f" [{i+1:03}] {ts}  {r['protocol']:<5} {src:<25} -> {dst:<25} {r['length']}B{flags}")

    print(f"{'='*60}\n")