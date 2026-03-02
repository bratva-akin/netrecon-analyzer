#!/usr/bin/env python3
"""
Scapy Packet Analyzer - Ethical Packet Capture & Analysis
Only capture on networks/interfaces you own or have permission for.
"""

from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP, DNS, Raw, wrpcap
import argparse
from datetime import datetime
import sys

def packet_callback(packet):
    """Callback function to process each captured packet."""
    timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto  # 6=TCP, 17=UDP, 1=ICMP

        summary = f"[{timestamp}] {src} → {dst} | "

        if TCP in packet:
            flags = packet[TCP].flags
            summary += f"TCP {packet[TCP].sport} → {packet[TCP].dport} | Flags: {flags}"
        elif UDP in packet:
            summary += f"UDP {packet[UDP].sport} → {packet[UDP].dport}"
        elif ICMP in packet:
            summary += f"ICMP Type: {packet[ICMP].type} Code: {packet[ICMP].code}"
        else:
            summary += f"IP Protocol {proto}"

        print(summary)

        # Show payload if present (first 80 chars, ignore binary)
        if packet.haslayer(Raw) and len(packet[Raw].load) > 0:
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore').strip()
                if payload:
                    print(f"   Payload: {payload[:80]}{'...' if len(payload) > 80 else ''}")
            except:
                print("   [Binary or non-UTF8 payload]")
        print("-" * 70)

def start_live_capture(interface="eth0", count=0, bpf_filter=None, output_pcap=None, stop_event=None):
    print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting live capture on {interface}")
    print(f"Filter: {bpf_filter or 'None'} | Count: {'unlimited' if count == 0 else count}")
    print("Press Ctrl+C to stop...\n")

    packets = []

    def stop_sniff(pkt):
        return stop_event.is_set() if stop_event else False

    try:
        packets = sniff(
            iface=interface,
            prn=packet_callback,
            filter=bpf_filter,
            count=count,
            store=bool(output_pcap),
            stop_filter=stop_sniff
        )

        if output_pcap and packets:
            wrpcap(output_pcap, packets)
            print(f"\n[+] Captured {len(packets)} packets saved to {output_pcap}")
    except KeyboardInterrupt:
        print("\n[!] Capture stopped by user.")
    except Exception as e:
        print(f"[ERROR] {e}")

def analyze_pcap_file(pcap_file):
    """Analyze an existing .pcap file."""
    print(f"\nAnalyzing file: {pcap_file}")
    try:
        packets = rdpcap(pcap_file)
        print(f"Loaded {len(packets)} packets\n")
        for pkt in packets:
            packet_callback(pkt)

       #add animaly check
        detect_anomalies(pcap_file)

    except Exception as e:
        print(f"[ERROR] Failed to read pcap: {e}")

def detect_anomalies(pcap_file):
    """Very basic anomaly detection example."""
    from collections import Counter
    print("\n=== Basic Anomaly Detection ===")
    try:
        packets = rdpcap(pcap_file)
        src_ips = Counter()
        dst_ports = Counter()
        syn_count = 0

        for pkt in packets:
            if IP in pkt:
                src_ips[pkt[IP].src] += 1
            if TCP in pkt and pkt[TCP].flags & 0x02:  # SYN flag
                syn_count += 1
                if TCP in pkt:
                    dst_ports[pkt[TCP].dport] += 1

        print(f"Total SYN packets (possible port scan): {syn_count}")
        if syn_count > 20:
            print("[ALERT] High SYN count → possible port scanning activity detected")

        print("\nTop source IPs:")
        for ip, cnt in src_ips.most_common(5):
            print(f"  {ip}: {cnt} packets")

        print("\nTop destination ports:")
        for port, cnt in dst_ports.most_common(5):
            print(f"  Port {port}: {cnt} packets")

    except Exception as e:
        print(f"[ERROR] Anomaly detection failed: {e}")


import matplotlib.pyplot as plt
from collections import Counter
from scapy.all import rdpcap, TCP, UDP

def plot_open_ports(pcap_file=None, nmap_output=None):
    """
    Simple bar chart of open ports.
    - If nmap_output provided: parse from Nmap text
    - If pcap_file: count unique open ports from TCP/UDP packets (less accurate)
    """
    ports = []
    services = []

    # Option 1: Parse from Nmap output (best if available)
    if nmap_output:
        lines = nmap_output.splitlines()
        for line in lines:
            if '/tcp' in line or '/udp' in line:
                if 'open' in line:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        port_proto = parts[0]  # e.g. 80/tcp
                        port = port_proto.split('/')[0]
                        service = parts[2] if len(parts) > 2 else "unknown"
                        ports.append(port)
                        services.append(service)

    # Option 2: Fallback to pcap (count unique destination ports)
    elif pcap_file:
        try:
            packets = rdpcap(pcap_file)
            dst_ports = []
            for pkt in packets:
                if TCP in pkt:
                    dst_ports.append(pkt[TCP].dport)
                elif UDP in pkt:
                    dst_ports.append(pkt[UDP].dport)
            port_counts = Counter(dst_ports)
            ports = list(port_counts.keys())
            services = [str(p) for p in ports]  # fallback label
        except Exception as e:
            print(f"[Chart] Failed to read pcap: {e}")
            return

    if not ports:
        print("[Chart] No open ports detected to plot.")
        return

    # Create bar chart
    plt.figure(figsize=(10, 6))
    plt.bar(services, [1] * len(services), color='skyblue', edgecolor='black')
    plt.xlabel('Service / Port')
    plt.ylabel('Open (count)')
    plt.title('Open Ports Detected')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()

    # Save chart
    chart_file = f"open_ports_chart_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
    plt.savefig(chart_file)
    plt.close()
    print(f"[+] Open ports chart saved to: {chart_file}")

# ---------------- CLI ----------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="NetRecon Analyzer - Scapy Packet Sniffer & Analyzer",
        epilog="Requires sudo for live capture. Use only on authorized networks."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--live", action="store_true", help="Start live capture")
    group.add_argument("--pcap", help="Analyze existing .pcap file (e.g. capture.pcap)")

    parser.add_argument("--iface", default="eth0", help="Interface for live capture (run 'ip link' to list)")
    parser.add_argument("--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("--filter", help="BPF filter, e.g. 'tcp port 80' or 'host 192.168.1.100'")
    parser.add_argument("--save", help="Save live capture to .pcap file (e.g. capture.pcap)")

    args = parser.parse_args()

    if args.live:
        start_live_capture(args.iface, args.count, args.filter, args.save)
    elif args.pcap:
        analyze_pcap_file(args.pcap)
