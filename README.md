# ST. DERRICKS — Network Intelligence Console

Nmap-inspired educational desktop network investigation tool built with Python's standard library.

## Features
- Local Network Radar: checks responsive hosts in the detected private IPv4 /24.
- TCP Port Intelligence: checks seven common TCP ports (22, 53, 80, 443, 445, 3389, 8080) on private or loopback IPv4 targets.
- DNS Recon: resolves a hostname to IPv4 addresses.
- Connectivity Test: checks DNS and TCP reachability to 1.1.1.1:443.
- Local Listeners: inspects listening TCP sockets using Windows netstat or Linux ss.
- Export Report: saves JSON findings and a CSV of port checks in reports/.

## Windows
Run `py stderricks.py` or double-click `START_ST_DERRICKS.bat`. Requires Python 3.10+ and Tkinter. No pip packages.

## Linux/macOS
Run `python3 stderricks.py`. Tkinter must be installed.

## Safety
Only assess devices and networks you own or have explicit permission to test. Local discovery checks the detected private /24. Port checks are limited to seven fixed ports and private/loopback IPv4 targets. Closed / filtered cannot distinguish a closed port from firewall filtering. An open port is not automatically a vulnerability. This is an educational tool, not a replacement for Nmap or a vulnerability scanner.

The original command-line edition remains available as `ndetect.py`.
