#!/usr/bin/env python3
"""
Nmap Port Scanner Wrapper - Ethical & Safe Usage Only
Only scan targets you own or have explicit permission for.
"""

import subprocess
import argparse
import sys
import re
from datetime import datetime

def is_valid_target(target):
    """Basic validation for IP, hostname, or CIDR range."""
    # Simple regex for IP or CIDR (improve later if needed)
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
    hostname_pattern = r'^[a-zA-Z0-9.-]+$'
    if re.match(ip_pattern, target) or re.match(hostname_pattern, target):
        return True
    return False

def run_nmap_scan(target, scan_type="syn", ports="1-1024", version=False, os_detect=False, aggressive=False, verbose=False):
    """
    Run Nmap scan with selected options.
    Returns the output string or None on error.
    """
    if not is_valid_target(target):
        print(f"[!] Invalid target: {target}")
        return None

    cmd = ["nmap"]

    # Scan type selection
    if scan_type == "syn":
        cmd += ["-sS"]          # TCP SYN (stealth, fast, requires root)
    elif scan_type == "connect":
        cmd += ["-sT"]          # TCP Connect (no root needed, more detectable)
    elif scan_type == "udp":
        cmd += ["-sU"]          # UDP scan (slow)
    elif scan_type == "version":
        cmd += ["-sV"]          # Service version detection only
    else:
        print(f"[!] Unknown scan type: {scan_type}")
        return None

    # Ports
    if ports:
        cmd += ["-p", ports]

    # Additional options
    if version and scan_type != "version":
        cmd += ["-sV"]
    if os_detect:
        cmd += ["-O"]           # OS detection (requires root)
    if aggressive:
        cmd += ["-A"]           # Aggressive: OS + version + script + traceroute
    if verbose:
        cmd += ["-v"]

    # Always add these safe/recommended flags
    cmd += ["--reason", "--open"]  # Show reasons & only open ports
    cmd += ["-T4"]                 # Faster timing template

    cmd.append(target)

    print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting scan...")
    print(f"Command: {' '.join(cmd)}\n")

    try:
        # Run nmap with sudo if needed (SYN/OS usually require root)
        result = subprocess.run(
            ["sudo"] + cmd if scan_type in ["syn", "udp", "connect"] and os_detect else cmd,
            capture_output=True,
            text=True,
            check=True
        )
        output = result.stdout
        print(output)
        return output
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Nmap failed (code {e.returncode}):")
        print(e.stderr)
        return None
    except FileNotFoundError:
        print("[ERROR] Nmap not found. Install it: sudo apt install nmap")
        sys.exit(1)

def save_results(output, filename=None):
    """Save scan results to file if requested."""
    if not output:
        return
    if not filename:
        filename = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, "w") as f:
        f.write(output)
    print(f"[+] Results saved to: {filename}")

# ---------------- CLI Interface ----------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="NetRecon Analyzer - Safe Nmap Port Scanner",
        epilog="WARNING: Only use on authorized targets! Ethical hacking only."
    )
    parser.add_argument("target", help="Target IP, hostname or range (e.g. 192.168.1.100, 192.168.1.0/24)")
    parser.add_argument("--type", choices=["syn", "connect", "udp", "version"], default="syn",
                        help="Scan type (syn requires sudo)")
    parser.add_argument("--ports", default="1-1024", help="Ports to scan (e.g. 80,443 or 1-1000)")
    parser.add_argument("--version", action="store_true", help="Enable service version detection")
    parser.add_argument("--os", action="store_true", help="Enable OS detection (requires sudo)")
    parser.add_argument("--aggressive", action="store_true", help="Aggressive scan (-A)")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--save", help="Save output to file (optional filename)")

    args = parser.parse_args()

    # Run the scan
    scan_output = run_nmap_scan(
        args.target,
        args.type,
        args.ports,
        args.version,
        args.os,
        args.aggressive,
        args.verbose
    )

    # Save if requested
    if scan_output and args.save:
        save_results(scan_output, args.save)
