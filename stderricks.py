import tkinter as tk
from tkinter import messagebox
import socket, ipaddress, threading, queue, json, csv, subprocess, platform, time, re, os, random, sqlite3, shutil, tempfile, webbrowser
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

APP_NAME = "ST. DERRICKS"
VERSION = "4.0"
BG = "#070b12"
PANEL = "#101827"
PANEL2 = "#0b1320"
EDGE = "#203448"
GREEN = "#39ff9c"
CYAN = "#37d7ff"
AMBER = "#ffc857"
RED = "#ff5577"
WHITE = "#e8f2f7"
MUTED = "#8297aa"
PORTS = {22:"SSH", 53:"DNS", 80:"HTTP", 443:"HTTPS", 445:"SMB", 3389:"RDP", 8080:"HTTP-ALT"}

def run_command(args, timeout=5):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                           errors="replace", creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return (p.stdout or "") + (p.stderr or "")
    except Exception:
        return ""

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 80))
        return s.getsockname()[0]
    except OSError:
        return "Not detected"
    finally:
        s.close()

def get_gateway():
    if platform.system() == "Windows":
        out = run_command(["ipconfig"])
        m = re.search(r"Default Gateway[^\n]*\n\s*([0-9.]+)", out, re.I)
        return m.group(1) if m else "Not detected"
    out = run_command(["ip", "route"])
    m = re.search(r"default via ([0-9.]+)", out)
    return m.group(1) if m else "Not detected"

def ping_host(host):
    win = platform.system() == "Windows"
    args = ["ping", "-n", "1", "-w", "900", host] if win else ["ping", "-c", "1", "-W", "1", host]
    out = run_command(args, 3).lower()
    return "ttl=" in out or "bytes from" in out

def parse_netstat():
    if platform.system() == "Windows":
        out = run_command(["netstat", "-ano", "-p", "tcp"])
        rows = []
        for line in out.splitlines():
            p = line.split()
            if len(p) >= 5 and p[0].upper() == "TCP":
                rows.append({"protocol":"TCP", "local":p[1], "remote":p[2], "state":p[3].upper(), "pid":p[4]})
        return rows
    out = run_command(["ss", "-ant"])
    rows = []
    for line in out.splitlines()[1:]:
        p = line.split()
        if len(p) >= 5:
            rows.append({"protocol":"TCP", "local":p[3], "remote":p[4], "state":p[0].upper(), "pid":"?"})
    return rows

class StDerricks:
    def __init__(self, root):
        self.root = root
        self.local_ip = get_local_ip()
        self.gateway = get_gateway()
        self.events = queue.Queue()
        self.watch_stop = threading.Event()
        self.watch_active = False
        self.data = {"devices":[], "ports":[], "dns":[], "listeners":[], "connections":[], "connectivity":{}}
        self.job_count = 0
        self.device_count = 0
        self.connection_count = 0
        self.activity = [0] * 48
        self.build_ui()
        self.log("CORE SYSTEM INITIALIZED // ST. DERRICKS v" + VERSION, "cyan")
        self.log("ANALYST MODE // authorized systems and networks only", "amber")
        self.log("LOCAL NODE // " + socket.gethostname() + " // " + self.local_ip)
        self.log("GATEWAY // " + self.gateway)
        self.tick()
        self.animate()
        self.poll_events()

    def build_ui(self):
        r = self.root
        r.title("ST. DERRICKS // CYBER DEFENCE OPERATIONS")
        r.geometry("1540x960")
        r.minsize(1180, 760)
        r.configure(bg=BG)

        header = tk.Frame(r, bg=BG)
        header.pack(fill="x", padx=18, pady=(14, 8))
        brand = tk.Frame(header, bg=BG)
        brand.pack(side="left", fill="x", expand=True)
        tk.Label(brand, text="ST. DERRICKS", bg=BG, fg=GREEN, font=("Consolas", 26, "bold")).pack(anchor="w")
        tk.Label(brand, text="CYBER DEFENCE OPERATIONS  //  NETWORK THREAT INTELLIGENCE", bg=BG, fg=CYAN,
                 font=("Consolas", 9, "bold")).pack(anchor="w")
        tk.Label(brand, text="COMMAND // MONITOR // INVESTIGATE // DOCUMENT", bg=BG, fg=MUTED,
                 font=("Consolas", 8)).pack(anchor="w", pady=(4, 0))
        tk.Button(header, text="OPEN GHOST TERMINAL  >", command=self.open_ghost_terminal,
                  bg="#12352c", fg=GREEN, activebackground="#1b5944", activeforeground=WHITE,
                  relief="flat", font=("Consolas", 9, "bold"), padx=14, pady=10,
                  cursor="hand2").pack(side="right", padx=(12, 0))
        self.clock = tk.Label(header, text="00:00:00", bg=BG, fg=GREEN, font=("Consolas", 23, "bold"))
        self.clock.pack(side="right", padx=14)
        self.date_label = tk.Label(header, text="", bg=BG, fg=MUTED, font=("Consolas", 9))
        self.date_label.pack(side="right", padx=12)

        strip = tk.Frame(r, bg=EDGE, padx=1, pady=1)
        strip.pack(fill="x", padx=18, pady=(0, 10))
        inner = tk.Frame(strip, bg=PANEL)
        inner.pack(fill="x")
        self.status_labels = {}
        for key, val in [("SYSTEM","ONLINE"),("NETWORK",self.local_ip),("GATEWAY",self.gateway),("SECURITY POSTURE","OBSERVING"),("ACTIVE TASKS","0")]:
            cell = tk.Frame(inner, bg=PANEL)
            cell.pack(side="left", fill="x", expand=True, padx=10, pady=8)
            tk.Label(cell, text=key, bg=PANEL, fg=MUTED, font=("Consolas", 8, "bold")).pack(anchor="w")
            lab = tk.Label(cell, text=val, bg=PANEL, fg=GREEN, font=("Consolas", 10, "bold"))
            lab.pack(anchor="w")
            self.status_labels[key] = lab

        main = tk.Frame(r, bg=BG)
        main.pack(fill="both", expand=True, padx=18, pady=4)
        left = tk.Frame(main, bg=PANEL, width=245)
        left.pack(side="left", fill="y", padx=(0, 9))
        left.pack_propagate(False)
        center = tk.Frame(main, bg=BG)
        center.pack(side="left", fill="both", expand=True, padx=(0, 9))
        right = tk.Frame(main, bg=BG, width=300)
        right.pack(side="right", fill="y")
        right.pack_propagate(False)

        tk.Label(left, text="MISSION CONTROL", bg=PANEL, fg=CYAN, font=("Consolas", 11, "bold")).pack(anchor="w", padx=13, pady=(14, 9))
        tk.Label(left, text="TARGET IPv4 / HOSTNAME", bg=PANEL, fg=MUTED, font=("Consolas", 8)).pack(anchor="w", padx=13)
        self.target = tk.Entry(left, bg="#050a10", fg=WHITE, insertbackground=GREEN, relief="flat", font=("Consolas", 11))
        self.target.pack(fill="x", padx=12, pady=(5, 12), ipady=8)
        self.target.insert(0, self.local_ip if self.local_ip != "Not detected" else "")
        actions = [
            ("01  NETWORK RADAR", self.discover),
            ("02  PORT INTELLIGENCE", self.scan_ports),
            ("03  DNS RECON", self.dns_lookup),
            ("04  CONNECTIVITY TEST", self.connectivity),
            ("05  LISTENING SERVICES", self.listeners),
            ("06  ACTIVE CONNECTIONS", self.connections),
            ("07  INTRUSION WATCH  [ON/OFF]", self.toggle_watch),
            ("08  EXPORT EVIDENCE", self.export_report),
            ("09  GHOST TERMINAL", self.open_ghost_terminal),
            ("10  WEB ACTIVITY", self.show_web_history),
        ]
        for label, fn in actions:
            tk.Button(left, text=label, command=fn, anchor="w", bg="#152536", fg=GREEN,
                      activebackground="#24483e", activeforeground=WHITE, relief="flat",
                      font=("Consolas", 8, "bold"), padx=10, pady=10, cursor="hand2").pack(fill="x", padx=8, pady=3)
        tk.Button(left, text="CLEAR EVENT FEED", command=self.clear_feed, bg="#2a1b27", fg=AMBER,
                  activebackground="#513040", relief="flat", font=("Consolas", 8, "bold"),
                  pady=8, cursor="hand2").pack(fill="x", padx=8, pady=(12, 4))
        tk.Label(left, text="LAB SCOPE: PRIVATE / LOOPBACK\nSCANS: FIXED COMMON TCP PORTS\nWEB HISTORY: LOCAL PROFILE ONLY", bg=PANEL, fg=MUTED,
                 font=("Consolas", 7), justify="left").pack(anchor="w", padx=13, pady=10)

        # Center: event stream and command/task console
        feed_box = tk.Frame(center, bg=PANEL, highlightbackground=EDGE, highlightthickness=1)
        feed_box.pack(fill="both", expand=True)
        feed_head = tk.Frame(feed_box, bg=PANEL)
        feed_head.pack(fill="x", padx=10, pady=8)
        tk.Label(feed_head, text="LIVE OPERATIONS FEED", bg=PANEL, fg=CYAN, font=("Consolas", 10, "bold")).pack(side="left")
        self.feed_state = tk.Label(feed_head, text="● MONITORING", bg=PANEL, fg=GREEN, font=("Consolas", 8, "bold"))
        self.feed_state.pack(side="right")
        self.feed = tk.Text(feed_box, bg="#04080e", fg=GREEN, insertbackground=GREEN, relief="flat",
                            font=("Consolas", 9), wrap="word", padx=10, pady=9)
        self.feed.pack(fill="both", expand=True, padx=7, pady=(0, 7))
        self.feed.tag_config("cyan", foreground=CYAN)
        self.feed.tag_config("amber", foreground=AMBER)
        self.feed.tag_config("red", foreground=RED)
        self.feed.tag_config("muted", foreground=MUTED)

        bottom = tk.Frame(center, bg=PANEL, highlightbackground=EDGE, highlightthickness=1)
        bottom.pack(fill="x", pady=(9, 0))
        tk.Label(bottom, text="TASK QUEUE / ANALYST CONSOLE", bg=PANEL, fg=CYAN, font=("Consolas", 9, "bold")).pack(anchor="w", padx=10, pady=(8, 3))
        self.task_text = tk.Text(bottom, height=5, bg="#04080e", fg=AMBER, relief="flat", font=("Consolas", 8), padx=9, pady=6)
        self.task_text.pack(fill="x", padx=7, pady=(0, 7))
        self.task_text.insert("end", "READY // Awaiting analyst command\n")

        # Right: threat summary, network topology, telemetry
        self.panel(right, "THREAT MONITOR")
        self.threat = tk.Label(right, text="NO ACTIVE ALERTS", bg=PANEL, fg=GREEN, font=("Consolas", 11, "bold"))
        self.threat.pack(fill="x", padx=10, pady=(0, 10))
        self.panel(right, "NETWORK TOPOLOGY")
        self.map = tk.Canvas(right, height=190, bg="#050a10", highlightthickness=1, highlightbackground=EDGE)
        self.map.pack(fill="x", padx=7, pady=(0, 10))
        self.draw_map()
        self.panel(right, "LIVE TELEMETRY")
        self.graph = tk.Canvas(right, height=105, bg="#050a10", highlightthickness=1, highlightbackground=EDGE)
        self.graph.pack(fill="x", padx=7, pady=(0, 7))
        self.panel(right, "FIELD STATISTICS")
        self.stats = {}
        for key, value in [("DISCOVERED HOSTS","0"),("OPEN PORTS","0"),("OBSERVED CONNECTIONS","0"),("REPORTS EXPORTED","0")]:
            row = tk.Frame(right, bg=PANEL)
            row.pack(fill="x", padx=10, pady=3)
            tk.Label(row, text=key, bg=PANEL, fg=MUTED, font=("Consolas", 8)).pack(side="left")
            lab = tk.Label(row, text=value, bg=PANEL, fg=GREEN, font=("Consolas", 9, "bold"))
            lab.pack(side="right")
            self.stats[key] = lab

        footer = tk.Frame(r, bg=BG)
        footer.pack(fill="x", padx=18, pady=(7, 10))
        tk.Label(footer, text="ST. DERRICKS v" + VERSION + "  //  EDUCATIONAL WHITE-HAT TOOL  //  AUTHORIZED SYSTEMS ONLY",
                 bg=BG, fg=MUTED, font=("Consolas", 8)).pack(side="left")
        tk.Label(footer, text="LOCAL ANALYSIS • NO EXPLOITS • NO STEALTH", bg=BG, fg=CYAN,
                 font=("Consolas", 8, "bold")).pack(side="right")

    def panel(self, parent, title):
        tk.Label(parent, text=title, bg=PANEL, fg=CYAN, font=("Consolas", 9, "bold")).pack(anchor="w", padx=10, pady=(10, 5))

    def log(self, text, tag=None):
        stamp = datetime.now().strftime("%H:%M:%S")
        self.feed.insert("end", "[" + stamp + "] " + text + "\n", tag or "")
        self.feed.see("end")
        self.activity[-1] = min(100, self.activity[-1] + 14)

    def task_log(self, text):
        self.task_text.insert("end", "[" + datetime.now().strftime("%H:%M:%S") + "] " + text + "\n")
        self.task_text.see("end")

    def start_job(self, label, fn):
        self.job_count += 1
        job_id = self.job_count
        self.status_labels["ACTIVE TASKS"].config(text=str(self.active_jobs + 1), fg=AMBER)
        self.active_jobs += 1
        self.log("TASK DISPATCHED // " + label + " // JOB-" + str(job_id), "cyan")
        self.task_log("RUNNING // JOB-" + str(job_id) + " // " + label)
        def worker():
            try:
                result = fn()
                self.events.put(("done", job_id, label, result))
            except Exception as exc:
                self.events.put(("error", job_id, label, str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    @property
    def active_jobs(self):
        return getattr(self, "_active_jobs", 0)

    @active_jobs.setter
    def active_jobs(self, value):
        self._active_jobs = max(0, value)

    def valid_private_target(self):
        host = self.target.get().strip()
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            raise ValueError("Enter a valid IPv4 address for port checks.")
        if not (addr.is_private or addr.is_loopback):
            raise ValueError("Port checks are restricted to private or loopback IPv4 addresses.")
        return str(addr)

    def discover(self):
        if self.local_ip == "Not detected":
            messagebox.showerror(APP_NAME, "No local IPv4 address was detected.")
            return
        def work():
            addr = ipaddress.ip_address(self.local_ip)
            if not addr.is_private:
                raise ValueError("Detected address is not private; local radar stopped.")
            net = ipaddress.ip_network(str(addr) + "/24", strict=False)
            hosts = [str(h) for h in net.hosts() if str(h) != self.local_ip]
            found = []
            self.events.put(("log", "RADAR SWEEP START // " + str(net), "cyan"))
            with ThreadPoolExecutor(max_workers=64) as pool:
                futures = {pool.submit(ping_host, h): h for h in hosts}
                for future in as_completed(futures):
                    host = futures[future]
                    try:
                        if future.result():
                            try: name = socket.gethostbyaddr(host)[0]
                            except OSError: name = "Unknown"
                            found.append({"ip":host, "hostname":name})
                            self.events.put(("log", "HOST RESPONDED // " + host + " // " + name, "green"))
                    except Exception:
                        pass
            self.data["devices"] = found
            return found
        self.start_job("LOCAL NETWORK RADAR", work)

    def scan_ports(self):
        try:
            host = self.valid_private_target()
        except ValueError as exc:
            messagebox.showwarning(APP_NAME, str(exc)); return
        def work():
            rows = []
            self.events.put(("log", "TCP SERVICE CHECK // " + host, "cyan"))
            for port, service in PORTS.items():
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(0.8)
                try: state = "OPEN" if s.connect_ex((host, port)) == 0 else "CLOSED / FILTERED"
                finally: s.close()
                row = {"ip":host, "port":port, "service":service, "status":state}
                rows.append(row)
                self.events.put(("log", str(port) + "/" + service + " // " + state,
                                 "amber" if state == "OPEN" else "muted"))
            self.data["ports"].extend(rows)
            return rows
        self.start_job("TCP PORT INTELLIGENCE", work)

    def dns_lookup(self):
        host = self.target.get().strip()
        if not host:
            messagebox.showwarning(APP_NAME, "Enter a hostname in the target field."); return
        def work():
            if len(host) > 253 or any(c.isspace() for c in host):
                raise ValueError("Invalid hostname.")
            answers = sorted({item[4][0] for item in socket.getaddrinfo(host, None, socket.AF_INET)})
            self.data["dns"].append({"hostname":host, "addresses":answers})
            for answer in answers: self.events.put(("log", "DNS ANSWER // " + host + " -> " + answer, "cyan"))
            return answers
        self.start_job("DNS RECON", work)

    def connectivity(self):
        def work():
            try: socket.gethostbyname("example.com"); dns = "WORKING"
            except OSError: dns = "FAILED"
            try:
                conn = socket.create_connection(("1.1.1.1", 443), 3); conn.close(); internet = "REACHABLE"
            except OSError: internet = "NOT REACHABLE"
            result = {"dns":dns, "internet_tcp":internet}
            self.data["connectivity"] = result
            return result
        self.start_job("CONNECTIVITY DIAGNOSTICS", work)

    def listeners(self):
        def work():
            rows = parse_netstat()
            listening = [x for x in rows if x["state"] in ("LISTENING", "LISTEN")]
            self.data["listeners"] = listening
            for row in listening:
                self.events.put(("log", "LOCAL LISTENER // " + row["local"] + " // PID " + row["pid"], "amber"))
            return listening
        self.start_job("LOCAL LISTENING SERVICES", work)

    def connections(self):
        def work():
            rows = parse_netstat()
            active = [x for x in rows if x["state"] in ("ESTABLISHED", "SYN_SENT", "SYN_RECEIVED")]
            self.data["connections"] = active
            for row in active:
                self.events.put(("log", "CONNECTION // " + row["local"] + " -> " + row["remote"] + " // " + row["state"], "cyan"))
            return active
        self.start_job("ACTIVE CONNECTION SNAPSHOT", work)

    def toggle_watch(self):
        if self.watch_active:
            self.watch_stop.set()
            self.watch_active = False
            self.status_labels["SECURITY POSTURE"].config(text="OBSERVING", fg=AMBER)
            self.log("INTRUSION WATCH STOPPED // monitoring paused", "amber")
            return
        self.watch_stop.clear()
        self.watch_active = True
        self.status_labels["SECURITY POSTURE"].config(text="WATCH ACTIVE", fg=GREEN)
        self.log("INTRUSION WATCH STARTED // local TCP connection changes are being observed", "cyan")
        def monitor():
            previous = set()
            while not self.watch_stop.is_set():
                rows = parse_netstat()
                current = {(x["local"], x["remote"], x["state"]) for x in rows if x["state"] == "ESTABLISHED"}
                for item in sorted(current - previous):
                    self.events.put(("log", "NEW ESTABLISHED CONNECTION OBSERVED // " + item[0] + " -> " + item[1], "amber"))
                previous = current
                self.events.put(("watch_count", len(current)))
                self.watch_stop.wait(5)
            self.events.put(("watch_stopped",))
        threading.Thread(target=monitor, daemon=True).start()

    def export_report(self):
        def work():
            folder = Path(__file__).resolve().parent / "reports"
            folder.mkdir(exist_ok=True)
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report = {"tool":APP_NAME, "version":VERSION, "generated":datetime.now().astimezone().isoformat(),
                      "host":socket.gethostname(), "local_ipv4":self.local_ip, "gateway":self.gateway,
                      **self.data, "note":"An observed connection or open port is not, by itself, proof of malicious activity."}
            json_path = folder / ("st_derricks_" + stamp + ".json")
            json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
            csv_path = folder / ("st_derricks_ports_" + stamp + ".csv")
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["ip","port","service","status"])
                writer.writeheader()
                writer.writerows(self.data["ports"])
            return {"json":str(json_path), "csv":str(csv_path)}
        self.start_job("EVIDENCE EXPORT", work)


    def open_ghost_terminal(self):
        win = tk.Toplevel(self.root)
        win.title("GHOST // INTEGRATED OPERATIONS TERMINAL")
        win.geometry("900x620")
        win.configure(bg="#03070c")
        top = tk.Frame(win, bg="#071522", padx=14, pady=12)
        top.pack(fill="x")
        tk.Label(top, text="GHOST // COMMAND INTERFACE", bg="#071522", fg=GREEN,
                 font=("Consolas", 16, "bold")).pack(side="left")
        tk.Label(top, text="LOCAL NODE • AUTHORISED OPERATIONS", bg="#071522", fg=CYAN,
                 font=("Consolas", 8, "bold")).pack(side="right")
        output = tk.Text(win, bg="#02060a", fg=GREEN, insertbackground=GREEN,
                         font=("Consolas", 10), relief="flat", wrap="word", padx=14, pady=12)
        output.pack(fill="both", expand=True, padx=10, pady=(10, 6))
        output.tag_config("cyan", foreground=CYAN)
        output.tag_config("amber", foreground=AMBER)
        output.tag_config("red", foreground=RED)
        output.insert("end", "GHOST // INTEGRATED TERMINAL v4.0\\nType help to list commands.\\n\\n", "cyan")
        row = tk.Frame(win, bg="#03070c")
        row.pack(fill="x", padx=10, pady=(0, 10))
        tk.Label(row, text="GHOST@LOCAL-NET >", bg="#03070c", fg=GREEN, font=("Consolas", 10, "bold")).pack(side="left", padx=(4, 8))
        command = tk.Entry(row, bg="#0b1722", fg=WHITE, insertbackground=GREEN, relief="flat", font=("Consolas", 11))
        command.pack(side="left", fill="x", expand=True, ipady=9)
        def write(value, tag=None):
            output.insert("end", value + "\\n", tag or "")
            output.see("end")
        def execute(event=None):
            raw = command.get().strip()
            command.delete(0, "end")
            if not raw: return
            write("GHOST@LOCAL-NET > " + raw, "cyan")
            parts = raw.split()
            cmd, args = parts[0].lower(), parts[1:]
            if cmd in ("exit", "close"): win.destroy()
            elif cmd == "help":
                write("help | status | ping <IP> | scan | ports <private-IP>")
                write("dns <hostname> | wifi | connections | router | webhistory | clear")
                write("Only scan networks you own/manage. Port checks are private/loopback only.", "amber")
            elif cmd == "clear": output.delete("1.0", "end")
            elif cmd == "status":
                for k,v in {"HOST":socket.gethostname(),"LOCAL IPv4":self.local_ip,"GATEWAY":self.gateway,"PLATFORM":platform.platform()}.items(): write(f"{k}: {v}")
            elif cmd == "ping":
                if not args: write("Usage: ping 192.168.0.1", "amber")
                else:
                    try: ipaddress.ip_address(args[0])
                    except ValueError: write("Enter a valid IP address.", "red"); return
                    out = run_command(["ping","-n","1","-w","1500",args[0]] if platform.system()=="Windows" else ["ping","-c","1","-W","2",args[0]],4)
                    ok = "ttl=" in out.lower() or "bytes from" in out.lower()
                    write(("HOST RESPONDED // " if ok else "NO ICMP RESPONSE // ")+args[0], "cyan" if ok else "amber")
            elif cmd == "scan":
                self.discover()
                write("Network Radar dispatched. Results appear in the dashboard feed.", "amber")
            elif cmd == "ports":
                try: host = str(ipaddress.ip_address(args[0]))
                except Exception: write("Usage: ports 192.168.0.1", "amber"); return
                addr = ipaddress.ip_address(host)
                if not (addr.is_private or addr.is_loopback): write("BLOCKED // private/loopback target only.", "red"); return
                for port,service in PORTS.items():
                    s=socket.socket(); s.settimeout(.55)
                    try: state="OPEN" if s.connect_ex((host,port))==0 else "CLOSED/FILTERED"
                    finally: s.close()
                    write(f"{host}:{port} {service} // {state}", "amber" if state=="OPEN" else None)
                write("Open ports do not prove vulnerabilities.", "amber")
            elif cmd == "dns":
                if not args: write("Usage: dns example.com", "amber")
                else:
                    try:
                        for ip in sorted({x[4][0] for x in socket.getaddrinfo(args[0],None,socket.AF_INET)}): write(args[0]+" -> "+ip,"cyan")
                    except OSError as exc: write("DNS ERROR // "+str(exc),"red")
            elif cmd == "wifi":
                write(run_command(["netsh","wlan","show","interfaces"]) if platform.system()=="Windows" else "Detailed Wi-Fi information currently uses Windows netsh.")
            elif cmd == "connections": write(run_command(["netstat","-ano","-p","tcp"] if platform.system()=="Windows" else ["ss","-ant"]))
            elif cmd == "router":
                gw=self.gateway if self.gateway!="Not detected" else "192.168.0.1"
                write("Opening local router page: http://"+gw,"cyan")
                write("Authenticate locally. Settings depend on firmware; no credentials are stored.","amber")
                webbrowser.open("http://"+gw)
            elif cmd == "webhistory":
                self.show_web_history()
                write("Local browser history viewer opened for this Windows profile.","amber")
            else: write("Unknown command. Type help.","red")
        command.bind("<Return>", execute)
        command.focus_set()

    def show_web_history(self):
        win = tk.Toplevel(self.root)
        win.title("ST. DERRICKS // LOCAL WEB ACTIVITY")
        win.geometry("1040x650")
        win.configure(bg=BG)
        head=tk.Frame(win,bg=PANEL,padx=14,pady=12); head.pack(fill="x",padx=12,pady=12)
        tk.Label(head,text="LOCAL WEB ACTIVITY // BROWSER HISTORY",bg=PANEL,fg=CYAN,font=("Consolas",13,"bold")).pack(anchor="w")
        tk.Label(head,text="Reads recent Chrome / Edge history from this Windows user profile. Nothing is uploaded.",bg=PANEL,fg=MUTED,font=("Consolas",8)).pack(anchor="w",pady=(5,0))
        body=tk.Frame(win,bg="#03070c"); body.pack(fill="both",expand=True,padx=12,pady=(0,12))
        text=tk.Text(body,bg="#03070c",fg=GREEN,font=("Consolas",9),relief="flat",wrap="none",padx=12,pady=10)
        text.pack(fill="both",expand=True)
        text.tag_config("cyan",foreground=CYAN); text.tag_config("amber",foreground=AMBER)
        def refresh():
            text.delete("1.0","end")
            base=Path(os.environ.get("LOCALAPPDATA",""))
            profiles=[("Chrome",base/"Google/Chrome/User Data/Default/History"),("Edge",base/"Microsoft/Edge/User Data/Default/History")]
            rows=[]
            for browser,db in profiles:
                if not db.exists(): continue
                temp=None
                try:
                    fd,temp=tempfile.mkstemp(prefix="ghost_history_",suffix=".db"); os.close(fd); shutil.copy2(db,temp)
                    con=sqlite3.connect(temp); cur=con.cursor()
                    cur.execute("SELECT url,title,last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 60")
                    for url,title,visit in cur.fetchall():
                        try: when=datetime.fromtimestamp(visit/1000000-11644473600).strftime("%Y-%m-%d %H:%M:%S")
                        except Exception: when="time unavailable"
                        rows.append((when,browser,title or "(untitled)",url))
                    con.close()
                except Exception as exc: rows.append(("",browser,"Could not read history: "+str(exc),""))
                finally:
                    if temp:
                        try: os.remove(temp)
                        except OSError: pass
            if not rows: text.insert("end","No Chrome or Edge history found in this Windows profile.\\n","amber"); return
            for when,browser,title,url in sorted(rows,reverse=True)[:100]:
                text.insert("end",f"{when} | {browser}\\n{title}\\n{url}\\n"+"-"*100+"\\n")
            text.insert("end","LOCAL ONLY // Private/incognito browsing is not recorded in ordinary browser history.\\n","amber")
        tk.Button(head,text="REFRESH HISTORY",command=refresh,bg="#12352c",fg=GREEN,relief="flat",font=("Consolas",9,"bold"),padx=12,pady=7).pack(anchor="e",pady=(8,0))
        refresh()

    def clear_feed(self):
        self.feed.delete("1.0", "end")
        self.log("EVENT FEED CLEARED BY ANALYST", "muted")

    def draw_map(self):
        c = self.map
        c.delete("all")
        w = max(c.winfo_width(), 270); h = 190
        cx, cy = w // 2, 90
        c.create_oval(cx-28, cy-28, cx+28, cy+28, outline=CYAN, width=2)
        c.create_text(cx, cy, text="YOU", fill=GREEN, font=("Consolas", 9, "bold"))
        c.create_text(cx, 160, text=self.local_ip, fill=MUTED, font=("Consolas", 8))
        for i in range(8):
            x = 25 + i * ((w-50)/7); y = 35 if i%2==0 else 135
            c.create_line(cx, cy, x, y, fill="#1b3b4b", dash=(2,4))
            c.create_oval(x-5,y-5,x+5,y+5,outline=GREEN if i < min(self.device_count,8) else "#385064",fill="#12352c" if i < min(self.device_count,8) else "")
        c.create_text(8, 8, anchor="nw", text="LOCAL SEGMENT // DEVICE RADAR", fill=CYAN, font=("Consolas", 7))

    def update_graph(self):
        c = self.graph; c.delete("all")
        w = max(c.winfo_width(), 270); h = 105
        c.create_text(7, 7, anchor="nw", text="EVENT ACTIVITY // RECENT UI EVENTS", fill=MUTED, font=("Consolas", 7))
        vals = self.activity[-40:]
        points = []
        for i, value in enumerate(vals):
            x = 5 + i * (w-10) / max(1, len(vals)-1)
            y = h-8 - (value/100)*(h-28)
            points.extend([x,y])
        if len(points) >= 4: c.create_line(*points, fill=GREEN, width=2, smooth=True)
        self.activity = [max(0, v-2) for v in self.activity]
        self.activity.append(0)
        self.activity = self.activity[-48:]

    def tick(self):
        now = datetime.now()
        self.clock.config(text=now.strftime("%H:%M:%S"))
        self.date_label.config(text=now.strftime("%A  %d %b %Y"))
        self.root.after(500, self.tick)

    def animate(self):
        self.update_graph()
        self.draw_map()
        self.root.after(1200, self.animate)

    def poll_events(self):
        try:
            while True:
                event = self.events.get_nowait()
                kind = event[0]
                if kind == "log":
                    _, text, color = event
                    self.log(text, {"green":"", "cyan":"cyan", "amber":"amber", "red":"red", "muted":"muted"}.get(color, ""))
                elif kind == "done":
                    _, job_id, label, result = event
                    self.active_jobs -= 1
                    self.status_labels["ACTIVE TASKS"].config(text=str(self.active_jobs), fg=GREEN if self.active_jobs == 0 else AMBER)
                    self.task_log("COMPLETE // JOB-" + str(job_id) + " // " + label)
                    self.log("TASK COMPLETE // " + label, "cyan")
                    if label == "LOCAL NETWORK RADAR":
                        self.device_count = len(result); self.stats["DISCOVERED HOSTS"].config(text=str(len(result)))
                    elif label == "TCP PORT INTELLIGENCE":
                        opened = sum(1 for x in result if x["status"] == "OPEN")
                        self.stats["OPEN PORTS"].config(text=str(sum(1 for x in self.data["ports"] if x["status"] == "OPEN")))
                        if opened: self.threat.config(text=str(opened) + " OPEN PORT(S) TO REVIEW", fg=AMBER)
                    elif label == "ACTIVE CONNECTION SNAPSHOT":
                        self.connection_count = len(result); self.stats["OBSERVED CONNECTIONS"].config(text=str(len(result)))
                    elif label == "EVIDENCE EXPORT":
                        self.stats["REPORTS EXPORTED"].config(text=str(int(self.stats["REPORTS EXPORTED"].cget("text"))+1))
                        self.log("JSON // " + result["json"], "cyan")
                        self.log("CSV // " + result["csv"], "cyan")
                        messagebox.showinfo(APP_NAME, "Evidence reports saved in the reports folder.")
                    elif label == "CONNECTIVITY DIAGNOSTICS":
                        self.log("DNS // " + result["dns"] + " // INTERNET TCP // " + result["internet_tcp"], "cyan")
                    elif label == "DNS RECON":
                        self.log("DNS LOOKUP RETURNED // " + str(len(result)) + " IPv4 address(es)", "cyan")
                    elif label == "LOCAL LISTENING SERVICES":
                        self.log("LISTENER SNAPSHOT // " + str(len(result)) + " listening socket(s)", "amber")
                elif kind == "error":
                    _, job_id, label, error = event
                    self.active_jobs -= 1
                    self.status_labels["ACTIVE TASKS"].config(text=str(self.active_jobs), fg=GREEN if self.active_jobs == 0 else AMBER)
                    self.task_log("FAILED // JOB-" + str(job_id) + " // " + label + " // " + error)
                    self.log("TASK ERROR // " + label + " // " + error, "red")
                elif kind == "watch_count":
                    self.connection_count = event[1]
                    self.stats["OBSERVED CONNECTIONS"].config(text=str(event[1]))
                elif kind == "watch_stopped":
                    self.log("INTRUSION WATCH OFFLINE", "amber")
        except queue.Empty:
            pass
        self.root.after(120, self.poll_events)

def main():
    root = tk.Tk()
    StDerricks(root)
    root.mainloop()

if __name__ == "__main__":
    main()
