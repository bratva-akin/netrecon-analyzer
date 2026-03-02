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

def start_live_capture(interface="eth0", count=0, bpf_filter=None, output_pcap=None):
    """
    Start live sniffing.
    count=0 means unlimited (stop with Ctrl+C)
    """
    print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting live capture on {interface}")
    print(f"Filter: {bpf_filter or 'None'} | Count: {'unlimited' if count == 0 else count}")
    print("Press Ctrl+C to stop...\n")

    try:
        packets = sniff(
            iface=interface,
            prn=packet_callback,
            filter=bpf_filter,
            count=count,
            store=bool(output_pcap)  # only store if saving to pcap
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
    except Exception as e:
        print(f"[ERROR] Failed to read pcap: {e}")

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
