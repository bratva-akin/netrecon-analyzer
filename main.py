#!/usr/bin/env python3
"""
NetRecon Analyzer - Main Entry Point
Combines Nmap scanning + Scapy packet analysis
Ethical use only on authorized lab targets!
"""

import time
from datetime import datetime
import threading
import sys
from scanner import run_nmap_scan, save_results
from analyzer import start_live_capture, analyze_pcap_file

def sniffer_thread(interface, filter_str, output_pcap, stop_event):
    print("[Sniffer] Background capture started...")
    start_live_capture(
        interface=interface,
        count=0,
        bpf_filter=filter_str,
        output_pcap=output_pcap,
        stop_event=stop_event
    )
    print("[Sniffer] Capture thread finished.")

def combined_workflow(target, scan_type="syn", ports="1-1000", interface="eth0", save_scan=None, save_pcap=None):
    print(f"\n=== Combined Recon Workflow Started at {datetime.now()} ===")
    print(f"Target: {target} | Scan type: {scan_type} | Ports: {ports}")
    print(f"Interface for capture: {interface}\n")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = save_pcap or f"capture_{timestamp}.pcap"
    scan_file = save_scan or f"scan_{timestamp}.txt"

    stop_event = threading.Event()
    sniffer = threading.Thread(
        target=sniffer_thread,
        args=(interface, f"host {target}", pcap_file, stop_event)
    )
    sniffer.daemon = True
    sniffer.start()

    time.sleep(1.5)  # Give sniffer time to start

    try:
        scan_output = run_nmap_scan(
            target=target,
            scan_type=scan_type,
            ports=ports,
            version=True,
            os_detect=True if scan_type in ["syn", "udp"] else False,
            aggressive=False,
            verbose=True
        )

        if scan_output and save_scan:
            save_results(scan_output, scan_file)

        time.sleep(4)  # Wait for trailing packets
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C detected during scan/wait. Stopping gracefully...")
    finally:
        stop_event.set()
        print("[Workflow] Stopping capture...")
        sniffer.join(timeout=8)

        if sniffer.is_alive():
            print("[Warning] Sniffer did not stop within timeout — exiting anyway.")

        print("\n=== Basic Report ===")
        print(f"Scan results: {'Saved to ' + scan_file if save_scan else 'Displayed above'}")
        print(f"Packet capture saved to: {pcap_file}")
        print("\nQuick traffic summary:")
        analyze_pcap_file(pcap_file)
        print("\nWorkflow finished.\n")

# ---------------- CLI Menu ----------------
def show_menu():
    print("\n=== NetRecon Analyzer Menu ===")
    print("1. Run Nmap Scan Only")
    print("2. Run Packet Capture Only (Live)")
    print("3. Run Packet Analysis on Existing .pcap")
    print("4. Combined: Scan + Capture + Quick Report")
    print("5. Exit")
    return input("Choose option (1-5): ").strip()

if __name__ == "__main__":
    print("Welcome to NetRecon Analyzer - Ethical Recon Tool")
    print("Use only on authorized lab targets!\n")

    try:
        while True:
            choice = show_menu()

            if choice == "1":
                target = input("Target IP/range: ")
                scan_type = input("Scan type (syn/connect/udp/version) [default syn]: ") or "syn"
                ports = input("Ports [default 1-1000]: ") or "1-1000"
                save_file = input("Save scan to file? (filename or Enter to skip): ").strip() or None

                output = run_nmap_scan(target, scan_type, ports, version=True, os_detect=True, verbose=True)
                if output and save_file:
                    save_results(output, save_file)

            elif choice == "2":
                interface = input("Interface [default eth0]: ") or "eth0"
                count = int(input("Packet count (0=unlimited): ") or "0")
                filt = input("BPF filter (e.g. tcp port 80) or Enter for none: ").strip() or None
                save_pcap = input("Save to .pcap? (filename or Enter to skip): ").strip() or None
                start_live_capture(interface, count, filt, save_pcap)

            elif choice == "3":
                pcap = input("Path to .pcap file: ").strip()
                if pcap:
                    analyze_pcap_file(pcap)

            elif choice == "4":
                target = input("Target IP/range: ")
                scan_type = input("Scan type (syn/connect/udp) [default syn]: ") or "syn"
                ports = input("Ports [default 1-1000]: ") or "1-1000"
                interface = input("Capture interface [default eth0]: ") or "eth0"
                save_scan = input("Save scan results? (filename or Enter skip): ").strip() or None
                save_pcap = input("Save capture to .pcap? (filename or Enter auto): ").strip() or None

                combined_workflow(target, scan_type, ports, interface, save_scan, save_pcap)

            elif choice == "5":
                print("Exiting NetRecon Analyzer. Stay ethical!")
                sys.exit(0)

            else:
                print("Invalid choice. Try again.")

    except KeyboardInterrupt:
        print("\n\n[!] Ctrl+C pressed. Exiting cleanly...")
        sys.exit(0)
