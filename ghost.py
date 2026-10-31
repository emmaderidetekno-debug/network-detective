#!/usr/bin/env python3
"""GHOST // Local Network Operations Terminal. Windows-first, stdlib only."""
from __future__ import annotations
import concurrent.futures, csv, datetime as dt, ipaddress, json, os, platform, re
import socket, subprocess, sys, time, webbrowser
from pathlib import Path

ROOT=Path(__file__).resolve().parent
REPORTS=ROOT/"reports"; REPORTS.mkdir(exist_ok=True)
DB=REPORTS/"ghost_devices.json"
PORTS=[22,53,80,443,445,3389,8080,8443]

def run(args,timeout=8):
    try:
        p=subprocess.run(args,capture_output=True,text=True,errors="replace",timeout=timeout,shell=False)
        return p.returncode,(p.stdout or "")+(p.stderr or "")
    except (OSError,subprocess.TimeoutExpired) as e: return 1,str(e)

def info():
    try: ip=socket.gethostbyname(socket.gethostname())
    except OSError: ip="unknown"
    gw="unknown"
    if os.name=="nt":
        _,s=run(["ipconfig"]); m=re.search(r"Default Gateway[ .:]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)",s,re.I)
    else:
        _,s=run(["ip","route","show","default"]); m=re.search(r"default via ([0-9.]+)",s)
    if m: gw=m.group(1)
    return {"host":socket.gethostname(),"ip":ip,"gateway":gw,"system":platform.platform()}

def say(tag,msg,color="96"): print(f"\033[{color}m[{tag}]\033[0m {msg}")
def banner():
    os.system("cls" if os.name=="nt" else "clear")
    print("\033[96m  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗\n ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝\n ██║  ███╗███████║██║   ██║███████╗   ██║   \n ██║   ██║██╔══██║██║   ██║╚════██║   ██║   \n ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   \n  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝\033[0m")
    print("\033[92m GHOST // NETWORK OPERATIONS TERMINAL\033[0m")
    print("\033[90m LOCAL NETWORK INTELLIGENCE • AUTHORISED ADMINISTRATION\033[0m")
    print("─"*72)

def ping(ip,seconds=1):
    args=["ping","-n","1","-w",str(int(seconds*1000)),ip] if os.name=="nt" else ["ping","-c","1","-W",str(max(1,int(seconds))),ip]
    return run(args,seconds+2)[0]==0

def arp():
    _,out=run(["arp","-a"] if os.name=="nt" else ["ip","neigh"])
    found={}
    for line in out.splitlines():
        m=re.search(r"(\d{1,3}(?:\.\d{1,3}){3}).*?(([0-9a-f]{2}[:-]){5}[0-9a-f]{2})",line,re.I)
        if m: found[m.group(1)]=m.group(2).replace("-",":").lower()
    return found

def hostname(ip):
    try:return socket.gethostbyaddr(ip)[0]
    except OSError:return "unknown"

def save(devices):
    try: old={x["ip"]:x for x in json.loads(DB.read_text(encoding="utf-8"))}
    except Exception: old={}
    now=dt.datetime.now().astimezone().isoformat(timespec="seconds")
    for d in devices: d["first_seen"]=old.get(d["ip"],{}).get("first_seen",now)
    old.update({d["ip"]:d for d in devices})
    DB.write_text(json.dumps(list(old.values()),indent=2),encoding="utf-8")

def scan(cidr=None):
    if not cidr:
        me=info()["ip"]
        try:
            a=ipaddress.ip_address(me)
            if not a.is_private: raise ValueError()
            cidr=str(ipaddress.ip_network(f"{a}/24",strict=False))
        except ValueError:
            say("ERROR","Cannot infer LAN. Try: scan 192.168.0.0/24","91"); return []
    try:
        net=ipaddress.ip_network(cidr,strict=False)
        if net.version!=4 or not net.is_private or net.num_addresses>256: raise ValueError("Use a private IPv4 network of at most 256 addresses.")
    except ValueError as e: say("ERROR",str(e),"91"); return []
    say("SCAN",f"Checking {net}; this is a ping-based discovery, not a guarantee of every Wi-Fi client.")
    hosts=[str(x) for x in net.hosts()]
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex: alive=[h for h,ok in zip(hosts,ex.map(ping,hosts)) if ok]
    macs=arp(); now=dt.datetime.now().astimezone().isoformat(timespec="seconds")
    devices=[{"ip":h,"mac":macs.get(h,"not in ARP cache"),"hostname":hostname(h),"last_seen":now} for h in alive]
    devices.sort(key=lambda x:tuple(map(int,x["ip"].split("."))))
    save(devices); return devices

def show(devs):
    if not devs: say("INFO","No ping responses. Some phones/clients block ping; use router's client list as the authoritative view.","93"); return
    print(f"\n{'IP':<17}{'MAC':<21}HOSTNAME\n"+"-"*70)
    for d in devs: print(f"{d['ip']:<17}{d['mac']:<21}{d['hostname']}")
    say("RESULT",f"{len(devs)} responsive host(s).")

def private_ip(s):
    try:
        a=ipaddress.ip_address(s)
        return a.version==4 and (a.is_private or a.is_loopback)
    except ValueError:return False

def wifi():
    if os.name!="nt": say("INFO","Detailed Wi-Fi info currently uses Windows netsh."); return
    _,out=run(["netsh","wlan","show","interfaces"]); print(out or "No Wi-Fi interface data.")

def router():
    gw=info()["gateway"]
    if gw=="unknown": gw="192.168.0.1"
    say("ROUTER",f"Opening local admin page at http://{gw}")
    say("GUIDE","Sign in on the router itself; inspect Connected Devices / DHCP Client List.")
    say("SAFETY","Block only a device you own/manage, verify its MAC address, and confirm in the router UI.")
    say("LIMIT","Router controls differ by F3 hardware/firmware. GHOST will not guess private API endpoints or store your password.")
    webbrowser.open("http://"+gw)

def ports(ip):
    if not private_ip(ip): say("BLOCKED","Port checks limited to private/loopback IPv4 targets.","91"); return
    for p in PORTS:
        try:
            with socket.create_connection((ip,p),timeout=.7): say("OPEN",f"{ip}:{p}","92")
        except OSError: print(f"\033[90m[CLOSED/FILTERED] {ip}:{p}\033[0m")
    say("NOTE","Open ports are not proof of a vulnerability.","93")

def watch(cidr=None):
    say("WATCH","Polling every 15 seconds. Ctrl+C to stop.")
    prev=set()
    try:
        while True:
            now={d["ip"] for d in scan(cidr)}
            for x in sorted(now-prev): say("NEW DEVICE",x,"93")
            for x in sorted(prev-now): say("DEVICE LEFT",x,"93")
            prev=now; time.sleep(15)
    except KeyboardInterrupt: say("STOP","Watch stopped.")

def help_cmd():
    print("""help | status | scan [192.168.0.0/24] | devices | ping <IP>
ports <private-IP> | dns <hostname> | wifi | connections
watch [private-CIDR] | router | export | clear | exit

Scans are limited to private IPv4 LANs (max /24-sized range).
Router changes are made in the authenticated router admin page.
""")

def main():
    banner(); i=info()
    say("HOST",f"{i['host']} | IP {i['ip']} | Gateway {i['gateway']}")
    say("READY","Type help. Only inspect networks you own or are authorised to administer.","92")
    latest=[]
    while True:
        try: raw=input("\n\033[92mGHOST@\033[96mLOCAL-NET\033[0m> ").strip()
        except (EOFError,KeyboardInterrupt): print(); break
        if not raw: continue
        p=raw.split(); c=p[0].lower(); a=p[1:]
        if c in ("exit","quit"): break
        elif c=="help": help_cmd()
        elif c=="clear": banner()
        elif c=="status":
            for k,v in info().items(): print(f"{k:<10}: {v}")
        elif c=="scan": latest=scan(a[0] if a else None); show(latest)
        elif c=="devices":
            try: show(json.loads(DB.read_text(encoding="utf-8")))
            except Exception: say("INFO","No inventory yet; run scan.")
        elif c=="ping":
            if a:
                ok=ping(a[0],2); say("PING",f"{a[0]} responded." if ok else f"{a[0]} did not respond (or blocks ICMP).","92" if ok else "93")
            else: say("USAGE","ping 192.168.0.1")
        elif c=="ports":
            if a: ports(a[0])
            else: say("USAGE","ports 192.168.0.1")
        elif c=="dns":
            if a:
                try:
                    for x in sorted({r[4][0] for r in socket.getaddrinfo(a[0],None,socket.AF_INET)}): say("DNS",f"{a[0]} -> {x}","92")
                except OSError as e: say("DNS FAIL",str(e),"91")
            else: say("USAGE","dns example.com")
        elif c=="wifi": wifi()
        elif c=="connections":
            cmd=["netstat","-ano","-p","tcp"] if os.name=="nt" else ["ss","-ant"]
            print(run(cmd)[1])
        elif c=="watch": watch(a[0] if a else None)
        elif c=="router": router()
        elif c=="export":
            if not latest: say("INFO","Run scan first.")
            else:
                f=REPORTS/f"ghost_scan_{dt.datetime.now():%Y%m%d_%H%M%S}.csv"
                with f.open("w",newline="",encoding="utf-8") as h:
                    w=csv.DictWriter(h,fieldnames=list(latest[0])); w.writeheader(); w.writerows(latest)
                say("SAVED",str(f),"92")
        else: say("UNKNOWN",f"{c}. Type help.","91")

if __name__=="__main__":
    try: main()
    except Exception as e: say("FATAL",f"{type(e).__name__}: {e}","91"); sys.exit(1)
