#!/usr/bin/env python3
"""NDETECT - a safe, beginner-friendly local network detective."""

from __future__ import annotations

import csv
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

APP_NAME = "NETWORK DETECTIVE"
VERSION = "1.0.0"
REPORT_DIR = Path(__file__).resolve().parent / "reports"
COMMON_PORTS = {
    22: "SSH", 53: "DNS", 80: "HTTP", 443: "HTTPS",
    445: "SMB", 3389: "RDP", 8080: "HTTP-ALT",
}


def paint(text: str, color: str = "cyan") -> str:
    colors = {"cyan": "36", "green": "32", "yellow": "33", "red": "31", "blue": "34", "dim": "2"}
    if not sys.stdout.isatty():
        return text
    return f"\033[{colors.get(color, '36')}m{text}\033[0m"


def banner() -> None:
    print(paint("\n╔══════════════════════════════════════════════════════╗", "cyan"))
    print(paint("║              N E T W O R K   D E T E C T I V E      ║", "cyan"))
    print(paint(f"║                     NDETECT v{VERSION}                   ║", "cyan"))
    print(paint("╚══════════════════════════════════════════════════════╝", "cyan"))
    print("  Your local network. Under your investigation.\n")


def run_command(args: list[str], timeout: int = 4) -> str:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                                errors="replace", creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return (result.stdout or "") + (result.stderr or "")
    except (OSError, subprocess.TimeoutExpired):
        return ""


def get_local_ip() -> str | None:
    # UDP connect selects the outgoing interface; it does not send application data.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 80))
        return sock.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return None
    finally:
        sock.close()


def get_gateway() -> str | None:
    system = platform.system().lower()
    if system == "windows":
        output = run_command(["ipconfig"], 5)
        match = re.search(r"Default Gateway[^\n]*\n\s*([0-9.]+)", output, re.I)
        if match:
            return match.group(1)
        match = re.search(r"Default Gateway[ .]*: *([0-9.]+)", output, re.I)
        return match.group(1) if match else None
    output = run_command(["ip", "route"], 3) if system == "linux" else run_command(["route", "-n", "get", "default"], 3)
    match = re.search(r"default via ([0-9.]+)", output)
    if match:
        return match.group(1)
    match = re.search(r"gateway: ([0-9.]+)", output, re.I)
    return match.group(1) if match else None


def get_arp_table() -> dict[str, str]:
    output = run_command(["arp", "-a"], 5)
    table: dict[str, str] = {}
    for line in output.splitlines():
        match = re.search(r"\(?([0-9]{1,3}(?:\.[0-9]{1,3}){3})\)?\s+([0-9a-f-]{17})", line, re.I)
        if match:
            table[match.group(1)] = match.group(2).replace("-", ":").upper()
    return table


def ping_host(ip: str) -> bool:
    flag = "-n" if platform.system().lower() == "windows" else "-c"
    wait_flag = "-w" if platform.system().lower() == "windows" else "-W"
    wait_value = "900" if platform.system().lower() == "windows" else "1"
    output = run_command(["ping", flag, "1", wait_flag, wait_value, ip], 3)
    return "ttl=" in output.lower() or "bytes from" in output.lower()


def discover_devices(local_ip: str) -> list[dict[str, str]]:
    address = ipaddress.ip_address(local_ip)
    if address.version != 4 or address.is_loopback or address.is_link_local:
        raise ValueError("A usable local IPv4 address could not be detected.")
    network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    print(paint(f"\n[*] Discovering responsive devices in {network} ...", "yellow"))
    print("[*] This sends one ping request per address in your local /24 network.")
    found: list[dict[str, str]] = []
    hosts = [str(host) for host in network.hosts() if str(host) != local_ip]
    started = time.time()
    with ThreadPoolExecutor(max_workers=64) as pool:
        jobs = {pool.submit(ping_host, ip): ip for ip in hosts}
        for job in as_completed(jobs):
            ip = jobs[job]
            try:
                if job.result():
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except (socket.herror, socket.gaierror, OSError):
                        hostname = "Unknown"
                    found.append({"ip": ip, "hostname": hostname, "mac": ""})
                    print(paint(f"  [+] {ip:<15} {hostname}", "green"))
            except Exception:
                continue
    arp = get_arp_table()
    for device in found:
        device["mac"] = arp.get(device["ip"], "Not in ARP cache")
    found.sort(key=lambda item: ipaddress.ip_address(item["ip"]))
    print(paint(f"\n[✓] Found {len(found)} responsive device(s) in {time.time()-started:.1f}s.", "green"))
    return found


def check_ports(target: str) -> list[dict[str, str | int]]:
    ip = ipaddress.ip_address(target)
    if ip.version != 4:
        raise ValueError("Please enter an IPv4 address.")
    print(paint(f"\n[*] Checking a small set of common TCP ports on {target}", "yellow"))
    results = []
    for port, service in COMMON_PORTS.items():
        status = "Closed or filtered"
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.7)
        try:
            if sock.connect_ex((target, port)) == 0:
                status = "Open"
                print(paint(f"  [OPEN]   {port:<5} {service}", "green"))
            else:
                print(f"  [----]   {port:<5} {service}  {status}")
        except OSError:
            print(f"  [----]   {port:<5} {service}  Unreachable")
            status = "Unreachable"
        finally:
            sock.close()
        results.append({"ip": target, "port": port, "service": service, "status": status})
    return results


def dns_lookup(hostname: str) -> list[str]:
    if not hostname or len(hostname) > 253 or any(c.isspace() for c in hostname):
        raise ValueError("Enter a valid hostname, for example example.com.")
    print(paint(f"\n[*] Looking up {hostname} ...", "yellow"))
    results = sorted({item[4][0] for item in socket.getaddrinfo(hostname, None, socket.AF_INET)})
    for address in results:
        print(paint(f"  [+] {hostname} -> {address}", "green"))
    return results


def connectivity_test() -> dict[str, str]:
    result = {"dns": "Not tested", "internet": "Not tested"}
    try:
        socket.gethostbyname("example.com")
        result["dns"] = "Working"
    except socket.gaierror:
        result["dns"] = "Failed"
    try:
        conn = socket.create_connection(("1.1.1.1", 443), timeout=3)
        conn.close()
        result["internet"] = "Reachable"
    except OSError:
        result["internet"] = "Not reachable"
    print(f"  DNS resolution: {paint(result['dns'], 'green' if result['dns']=='Working' else 'red')}")
    print(f"  Internet TCP:   {paint(result['internet'], 'green' if result['internet']=='Reachable' else 'red')}")
    return result


def save_report(data: dict) -> None:
    REPORT_DIR.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = REPORT_DIR / f"ndetect_report_{stamp}.json"
    csv_path = REPORT_DIR / f"ndetect_devices_{stamp}.csv"
    json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        rows = data.get("devices", [])
        writer = csv.DictWriter(handle, fieldnames=["ip", "hostname", "mac"])
        writer.writeheader()
        writer.writerows(rows)
    print(paint(f"\n[✓] JSON report: {json_path}", "green"))
    print(paint(f"[✓] CSV device list: {csv_path}", "green"))


def ask_ip(prompt: str) -> str | None:
    value = input(prompt).strip()
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        print(paint("Invalid IP address.", "red"))
        return None


def main() -> None:
    banner()
    local_ip = get_local_ip()
    gateway = get_gateway()
    print(paint(" SYSTEM SNAPSHOT", "blue"))
    print(f"  Operating system : {platform.system()} {platform.release()}")
    print(f"  Computer name    : {socket.gethostname()}")
    print(f"  Local IPv4       : {local_ip or 'Not detected'}")
    print(f"  Default gateway  : {gateway or 'Not detected'}")
    print("\n  Only investigate networks and devices you own or are authorized to assess.")
    report: dict = {"tool": APP_NAME, "version": VERSION, "timestamp": datetime.now().astimezone().isoformat(),
                    "system": platform.platform(), "hostname": socket.gethostname(), "local_ip": local_ip,
                    "gateway": gateway, "devices": [], "port_checks": [], "dns": {}, "connectivity": {}}
    while True:
        print(paint("\n  ┌────────────── INVESTIGATION MENU ──────────────┐", "cyan"))
        print("  │  1. Discover devices on my local /24 network  │")
        print("  │  2. Check common TCP ports on one IP          │")
        print("  │  3. DNS lookup                                │")
        print("  │  4. Test DNS and internet connectivity        │")
        print("  │  5. Save investigation report                 │")
        print("  │  6. Exit                                      │")
        print(paint("  └───────────────────────────────────────────────┘", "cyan"))
        choice = input("  NDETECT > ").strip()
        try:
            if choice == "1":
                if not local_ip:
                    print(paint("Could not detect local IPv4.", "red"))
                else:
                    report["devices"] = discover_devices(local_ip)
            elif choice == "2":
                target = ask_ip("  Target IPv4 (authorized host only): ")
                if target:
                    report["port_checks"].extend(check_ports(target))
            elif choice == "3":
                host = input("  Hostname (e.g. example.com): ").strip()
                try:
                    report["dns"][host] = dns_lookup(host)
                except socket.gaierror:
                    print(paint("DNS lookup failed. Check the hostname or DNS connection.", "red"))
            elif choice == "4":
                report["connectivity"] = connectivity_test()
            elif choice == "5":
                save_report(report)
            elif choice == "6":
                print(paint("\n  Investigation closed. Stay curious, stay ethical. 🕵️\n", "green"))
                break
            else:
                print(paint("Choose a number from 1 to 6.", "red"))
        except (ValueError, OSError) as error:
            print(paint(f"Operation could not be completed: {error}", "red"))
        except KeyboardInterrupt:
            print("\nOperation cancelled.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nNDETECT closed.")
