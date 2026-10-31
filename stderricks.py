import tkinter as tk
from tkinter import messagebox
import socket, ipaddress, threading, queue, json, csv
from pathlib import Path
from datetime import datetime

BG="#080d12"
GREEN="#39ff9c"
CYAN="#37d7ff"
PORTS={22:"SSH",53:"DNS",80:"HTTP",443:"HTTPS",445:"SMB",3389:"RDP",8080:"HTTP-ALT"}

def main():
    root=tk.Tk()
    root.title("ST. DERRICKS // NETWORK INTELLIGENCE")
    root.geometry("1050x700")
    root.configure(bg=BG)
    tk.Label(root,text="ST. DERRICKS",bg=BG,fg=GREEN,font=("Consolas",30,"bold")).pack(anchor="w",padx=24,pady=(24,0))
    tk.Label(root,text="N E T W O R K   I N T E L L I G E N C E   //   NMAP-INSPIRED CONSOLE",bg=BG,fg=CYAN,font=("Consolas",10,"bold")).pack(anchor="w",padx=24)
    ipbox=tk.Frame(root,bg="#101a22")
    ipbox.pack(fill="x",padx=24,pady=18)
    ip=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    try:
        ip.connect(("192.0.2.1",80)); local=ip.getsockname()[0]
    except OSError: local="Not detected"
    finally: ip.close()
    tk.Label(ipbox,text="HOST  "+socket.gethostname()+"     LOCAL IPv4  "+local,bg="#101a22",fg=GREEN,font=("Consolas",11)).pack(anchor="w",padx=14,pady=14)
    body=tk.Frame(root,bg=BG); body.pack(fill="both",expand=True,padx=24,pady=8)
    side=tk.Frame(body,bg="#101a22",width=250); side.pack(side="left",fill="y",padx=(0,12)); side.pack_propagate(False)
    tk.Label(side,text="OPERATIONS",bg="#101a22",fg=CYAN,font=("Consolas",12,"bold")).pack(anchor="w",padx=14,pady=14)
    target=tk.Entry(side,bg="#050a0e",fg="white",insertbackground=GREEN,font=("Consolas",11),relief="flat")
    target.pack(fill="x",padx=12,pady=8,ipady=8); target.insert(0,local)
    feed=tk.Text(body,bg="#050a0e",fg=GREEN,font=("Consolas",10),relief="flat",wrap="word")
    feed.pack(side="left",fill="both",expand=True)
    events=queue.Queue(); busy=[False]
    def log(s): feed.insert("end","[ "+datetime.now().strftime("%H:%M:%S")+" ] "+s+"\\n"); feed.see("end")
    def job(label,fn):
        if busy[0]: return
        busy[0]=True; log("START // "+label)
        def work():
            try: events.put(("ok",label,fn()))
            except Exception as e: events.put(("error",str(e)))
        threading.Thread(target=work,daemon=True).start()
    def ping(ip):
        import subprocess,platform
        flag="-n" if platform.system()=="Windows" else "-c"
        try:
            p=subprocess.run(["ping",flag,"1",ip],capture_output=True,text=True,timeout=3)
            return "ttl=" in p.stdout.lower() or "bytes from" in p.stdout.lower()
        except Exception: return False
    def discover():
        net=ipaddress.ip_network(local+"/24",strict=False)
        found=[]
        hosts=[str(h) for h in net.hosts() if str(h)!=local]
        with ThreadPoolExecutor(max_workers=64) as pool:
            jobs={pool.submit(ping,h):h for h in hosts}
            for future in as_completed(jobs):
                h=jobs[future]
                try:
                    if future.result():
                        found.append(h); events.put(("log","DEVICE ONLINE // "+h))
                except Exception: pass
        self.data["devices"]=found
        return "RADAR COMPLETE // "+str(len(found))+" responsive devices"
    def ports():
        host=target.get().strip(); addr=ipaddress.ip_address(host)
        if not (addr.is_private or addr.is_loopback): raise ValueError("Private or loopback IPv4 only.")
        rows=[]
        for port,name in PORTS.items():
            s=socket.socket(); s.settimeout(.8)
            try: state="OPEN" if s.connect_ex((host,port))==0 else "CLOSED / FILTERED"
            finally: s.close()
            rows.append({"ip":host,"port":port,"service":name,"status":state})
            events.put(("log",str(port)+" "+name+" // "+state))
        self.data["ports"].extend(rows)
        return rows
    def dns():
        host=target.get().strip()
        result=sorted({x[4][0] for x in socket.getaddrinfo(host,None,socket.AF_INET)})
        self.data["dns"].append({"hostname":host,"addresses":result})
        return result
    def connect():
        try: socket.gethostbyname("example.com"); d="DNS WORKING"
        except OSError: d="DNS FAILED"
        try: s=socket.create_connection(("1.1.1.1",443),3); s.close(); n="INTERNET REACHABLE"
        except OSError: n="INTERNET NOT REACHABLE"
        self.data["connectivity"]={"dns":d,"internet":n}
        return d+" // "+n
    def listeners():
        import subprocess,platform
        if platform.system()=="Windows":
            p=subprocess.run(["netstat","-ano"],capture_output=True,text=True)
            lines=[x.strip() for x in p.stdout.splitlines() if "LISTENING" in x]
            self.data["listeners"]=lines
            return lines
        p=subprocess.run(["ss","-lntp"],capture_output=True,text=True)
        return p.stdout.splitlines()
    def export():
        folder=Path(__file__).resolve().parent/"reports"; folder.mkdir(exist_ok=True)
        data={"tool":"ST. DERRICKS","version":"2.0","timestamp":datetime.now().astimezone().isoformat(),"host":socket.gethostname(),"local_ip":self.ip,**self.data}
        path=folder/("report_"+datetime.now().strftime("%Y%m%d_%H%M%S")+".json")
        path.write_text(json.dumps(data,indent=2),encoding="utf-8")
        csvpath=folder/("port_results_"+datetime.now().strftime("%Y%m%d_%H%M%S")+".csv")
        with csvpath.open("w",newline="",encoding="utf-8") as f:
            writer=csv.DictWriter(f,fieldnames=["ip","port","service","status"])
            writer.writeheader()
            writer.writerows(self.data["ports"])
        return "REPORT SAVED // "+str(path)
    def button(label,fn):
        tk.Button(side,text=label,command=lambda:job(label,fn),anchor="w",bg="#14232d",fg=GREEN,activebackground="#1c443d",relief="flat",font=("Consolas",9,"bold"),padx=12,pady=12).pack(fill="x",padx=10,pady=4)
    button("01  LOCAL NETWORK RADAR",discover)
    button("02  TCP PORT INTELLIGENCE",ports)
    button("03  DNS RECON",dns)
    button("04  CONNECTIVITY TEST",connect)
    button("05  LOCAL LISTENERS",listeners)
    button("06  EXPORT REPORT",export)
    tk.Label(side,text="AUTHORIZED LAB ONLY",bg="#101a22",fg=CYAN,font=("Consolas",8)).pack(pady=20)
    def poll():
        try:
            while True:
                e=events.get_nowait()
                if e[0]=="log": log(e[1])
                elif e[0]=="error": busy[0]=False; log("ERROR // "+e[1])
                else: busy[0]=False; log("COMPLETE // "+e[1]+" // "+str(e[2]))
        except queue.Empty: pass
        root.after(100,poll)
    log("SYSTEM ONLINE // ST. DERRICKS v2.0")
    log("AUTHORIZED USE // only investigate devices and networks you own or have permission to assess")
    root.after(100,poll)
    root.mainloop()

if __name__=="__main__":
    main()
