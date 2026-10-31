# Network Detective (NDETECT)

A beginner-friendly, permission-based network diagnostics and discovery tool built with Python's standard library.

## Features
- Local IPv4 interface and default gateway information
- Optional discovery of responsive devices on your own local subnet
- ARP cache lookup for discovered devices
- Limited TCP connectivity checks against a selected host and a small, predefined port list
- DNS resolution and basic internet connectivity diagnostics
- JSON and CSV reports

## Requirements
- Python 3.10 or newer
- Windows, Linux, or macOS
- No third-party packages required

## Run on Windows
```powershell
git clone https://github.com/emmaderidetekno-debug/network-detective.git
cd network-detective
py ndetect.py
```

If `py` is unavailable, try `python ndetect.py`.

## Run on Linux/macOS
```bash
git clone https://github.com/emmaderidetekno-debug/network-detective.git
cd network-detective
python3 ndetect.py
```

## Safe-use notes
Use discovery only on a local network you own or are explicitly authorized to assess. Host discovery sends ICMP echo requests to addresses in the detected local IPv4 /24 network. TCP checks use a small fixed list of common ports and a short timeout. This tool does not exploit services, bypass authentication, or perform stealth scanning.

Some devices block ping, so a device may be online but not appear in discovery. MAC addresses are read from the operating system's ARP cache and may be unavailable.

## Project structure
- `ndetect.py` — application
- `reports/` — generated reports (created automatically)
- `.gitignore` — excludes generated files and Python cache

## Learning roadmap
1. Understand interface and gateway detection.
2. Study ICMP discovery and why ping can be blocked.
3. Learn how ARP maps local IPv4 addresses to MAC addresses.
4. Explore TCP connection handshakes through safe connectivity checks.
5. Inspect the JSON/CSV reports.

Educational project. Not a replacement for a professional network monitoring or vulnerability assessment platform.
