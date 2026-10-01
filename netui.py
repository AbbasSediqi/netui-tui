#!/usr/bin/env python3
"""NETUI: interactive network discovery TUI."""
import curses
import ipaddress
import concurrent.futures
import subprocess
import shutil
import socket
import time
import re
import urllib.request
import urllib.error
import csv
import os
import sys
import termios
import pathlib
from dataclasses import dataclass, field
from threading import Lock

COMMON_PORTS = [21,22,23,25,53,80,110,139,143,443,445,3306,3389,5900,8080,8443,9100]
WEB_PORTS = [80,443,8000,8080,8081,8443,8888]
PRINTER_PORTS = [515,631,9100]
# Common UDP services. UDP scans cannot always distinguish an open port from
# a filtered one without a protocol-specific response, so results are labeled
# OPEN or OPEN|FILTERED rather than claiming certainty.
COMMON_UDP_PORTS = [53,67,68,69,123,137,138,161,162,500,514,520,1900,4500,5353]

@dataclass
class Host:
    ip: str
    hostname: str = "-"
    mac: str = "-"
    vendor: str = "-"
    ping: str = "-"
    status: str = "PENDING"
    shares: str = "-"
    web: str = "-"
    printer: str = "-"
    ports: list = field(default_factory=list)

def run_cmd(args, timeout=2):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None

def ping_host(ip):
    # Linux iputils
    r = run_cmd(["ping", "-n", "-c", "1", "-W", "1", ip], timeout=2)
    if not r or r.returncode != 0:
        return None
    m = re.search(r'time[=<]([\d.]+)\s*ms', r.stdout)
    return (m.group(1) + "ms") if m else "<1ms"

def get_hostname(ip):
    try:
        name = socket.gethostbyaddr(ip)[0]
        return name.split(".")[0]
    except (socket.herror, socket.gaierror, OSError):
        return "-"

def get_mac(ip):
    # Neighbor cache may already contain the MAC after ping.
    r = run_cmd(["ip", "neigh", "show", ip], timeout=1)
    if r is None:
        r = run_cmd(["ip", "neigh", "show", ip], timeout=1)
    if r and r.stdout:
        m = re.search(r'lladdr\s+([0-9a-fA-F:]{17})', r.stdout)
        if m:
            return m.group(1).upper()
    return "-"

def tcp_open(ip, port, timeout=0.35):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False

def udp_probe(ip, port, timeout=0.6):
    """Return OPEN, CLOSED, or OPEN|FILTERED for a UDP port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            # A small DNS query elicits a response from DNS servers; for other
            # services an empty datagram is a conservative discovery probe.
            if port == 53:
                payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01"
            else:
                payload = b""
            sock.sendto(payload, (ip, port))
            try:
                data, _ = sock.recvfrom(2048)
                return "OPEN"
            except socket.timeout:
                return "OPEN|FILTERED"
    except ConnectionRefusedError:
        return "CLOSED"
    except OSError as exc:
        # Linux may report ICMP port-unreachable asynchronously.
        if getattr(exc, "errno", None) in (111, 113):
            return "CLOSED"
        return "OPEN|FILTERED"

def http_title(ip, port):
    scheme = "https" if port in (443,8443) else "http"
    url = f"{scheme}://{ip}:{port}/"
    try:
        req = urllib.request.Request(url, headers={"User-Agent":"NETUI/1.0"})
        with urllib.request.urlopen(req, timeout=1.4, context=None) as resp:
            data = resp.read(65536).decode("utf-8", "ignore")
        m = re.search(r"<title[^>]*>(.*?)</title\s*>", data, re.I|re.S)
        if m:
            return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", m.group(1))).strip()[:38] or f"HTTP:{port}"
        return f"HTTP:{port}"
    except Exception:
        # Some HTTPS appliances have self-signed certificates; retry with unverified TLS.
        if scheme == "https":
            import ssl
            try:
                req = urllib.request.Request(url, headers={"User-Agent":"NETUI/1.0"})
                with urllib.request.urlopen(req, timeout=1.4, context=ssl._create_unverified_context()) as resp:
                    data = resp.read(65536).decode("utf-8", "ignore")
                m = re.search(r"<title[^>]*>(.*?)</title\s*>", data, re.I|re.S)
                return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", m.group(1))).strip()[:38] if m else f"HTTPS:{port}"
            except Exception:
                pass
    return "-"

def scan_services(host):
    ip=host.ip
    open_ports=[]
    for p in (445,139,80,443,8000,8080,8081,8443,8888,515,631,9100):
        if tcp_open(ip,p):
            open_ports.append(p)
    host.ports=open_ports
    if 445 in open_ports or 139 in open_ports:
        if shutil_which("smbclient"):
            r=run_cmd(["smbclient","-g","-L",f"//{ip}","-N"],timeout=3)
            if r and r.returncode == 0:
                names=[]
                for line in r.stdout.splitlines():
                    parts=line.split("|")
                    if len(parts)>1 and parts[0].lower()=="disk":
                        names.append(parts[1])
                host.shares=", ".join(names[:3]) if names else "SMB"
            else:
                host.shares="SMB (auth)"
        else:
            host.shares="SMB"
    web=[]
    for p in WEB_PORTS:
        if p in open_ports:
            title=http_title(ip,p)
            if title != "-":
                web.append(title)
    host.web=", ".join(dict.fromkeys(web)) if web else "-"
    host.printer="Yes" if any(p in open_ports for p in PRINTER_PORTS) else "No"

def shutil_which(name):
    from shutil import which
    return which(name) is not None

def open_host_webpage(host):
    """Open the first detected web service for a host in the default browser."""
    for port in WEB_PORTS:
        if port in host.ports:
            scheme = "https" if port in (443, 8443) else "http"
            url = f"{scheme}://{host.ip}/" if port in (80, 443) else f"{scheme}://{host.ip}:{port}/"
            try:
                subprocess.Popen(["xdg-open", url], stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, start_new_session=True)
                return f"Opening {url} in default browser..."
            except OSError as exc:
                return f"Could not open browser: {exc}"
    return f"No detected web service on {host.ip}. Run a scan first."

def scan_one(ip):
    h=Host(ip=ip)
    latency=ping_host(ip)
    if latency is None:
        h.status="OFFLINE"
        return h
    h.status="ONLINE"
    h.ping=latency
    h.hostname=get_hostname(ip)
    h.mac=get_mac(ip)
    scan_services(h)
    return h

def parse_range(value):
    value=value.strip()
    if "-" in value and "/" not in value:
        a,b=[x.strip() for x in value.split("-",1)]
        start,end=ipaddress.ip_address(a),ipaddress.ip_address(b)
        if start.version != 4 or end.version != 4 or int(end)<int(start):
            raise ValueError("Invalid IPv4 range")
        if int(end)-int(start)>4095:
            raise ValueError("Maximum range is 4096 addresses")
        return [str(ipaddress.IPv4Address(n)) for n in range(int(start),int(end)+1)]
    # Accept shorthand IPv4 networks such as 192.168.0/24.
    if "/" in value:
        addr, prefix = value.rsplit("/", 1)
        if "." in addr and len(addr.split(".")) == 3:
            value = addr + ".0/" + prefix
    net=ipaddress.ip_network(value, strict=False)
    if net.version != 4:
        raise ValueError("IPv4 only")
    if net.num_addresses>4096:
        raise ValueError("Maximum range is 4096 addresses")
    return [str(x) for x in net.hosts()] if net.num_addresses>2 else [str(x) for x in net]

def draw_box(stdscr, y, x, h, w, title=None, color=1):
    if h<2 or w<2: return
    try:
        win=stdscr.derwin(h,w,y,x)
        win.attron(curses.color_pair(color))
        win.box()
        if title:
            win.addnstr(0,2,f" {title} ",max(0,w-4),curses.color_pair(color)|curses.A_BOLD)
        win.attroff(curses.color_pair(color))
    except curses.error:
        pass

def safe_add(win,y,x,text,attr=0,width=None):
    try:
        if width is None: width=max(0,win.getmaxyx()[1]-x-1)
        if width>0: win.addnstr(y,x,str(text),width,attr)
    except curses.error:
        pass

def get_local_network():
    """Return the primary local IPv4 address and its CIDR network."""
    route = run_cmd(["ip", "-4", "route", "get", "1.1.1.1"], timeout=1)
    if route and route.returncode == 0 and route.stdout:
        dev_match = re.search(r"\bdev\s+(\S+)", route.stdout)
        src_match = re.search(r"\bsrc\s+(\d+(?:\.\d+){3})", route.stdout)
        if dev_match:
            dev = dev_match.group(1)
            addr = run_cmd(["ip", "-o", "-4", "addr", "show", "dev", dev], timeout=1)
            if addr and addr.stdout:
                match = re.search(r"\binet\s+(\d+(?:\.\d+){3}/\d+)", addr.stdout)
                if match:
                    interface = ipaddress.ip_interface(match.group(1))
                    return str(interface.ip), str(interface.network)
        if src_match:
            return src_match.group(1), "Network unavailable"
    return "Unavailable", "Unavailable"

def main(stdscr):
    # Ctrl+S is XOFF on many terminals; disable software flow control so
    # curses receives it as a key instead of freezing terminal output.
    try:
        fd = sys.stdin.fileno()
        tty_attrs = termios.tcgetattr(fd)
        tty_attrs[0] &= ~termios.IXON
        termios.tcsetattr(fd, termios.TCSANOW, tty_attrs)
    except (OSError, termios.error):
        pass
    local_ip, local_network = get_local_network()
    curses.curs_set(0)
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1,curses.COLOR_CYAN,-1)
    curses.init_pair(2,curses.COLOR_GREEN,-1)
    curses.init_pair(3,curses.COLOR_RED,-1)
    curses.init_pair(4,curses.COLOR_YELLOW,-1)
    curses.init_pair(5,curses.COLOR_WHITE,-1)
    curses.init_pair(6,curses.COLOR_BLUE,-1)
    stdscr.keypad(True)
    stdscr.timeout(100)
    hosts=[]
    hostmap={}
    selected=0
    offset=0
    sorted_online=False
    query=""
    searching=False
    command=""
    command_mode=False
    command_menu=False
    command_menu_index=0
    help_visible=False
    command_options=[("range", ":range ", "Scan an IP range / CIDR"), ("ports", ":ports ", "Scan TCP ports on one IP"), ("portsUDP", ":portsUDP ", "Scan common UDP ports on one IP"), ("monitor", ":monitor", "Open Shoal live network monitor"), ("help", ":help", "Show command help"), ("clear", ":clear", "Clear results"), ("quit", ":q", "Exit NETUI") ]
    message="Ready. Press : for commands, / to search."
    scanning=False
    scan_total=scan_done=0
    scan_started=0
    scan_lock=Lock()
    pool=None
    futures={}
    mode="idle"
    port_target=""
    port_results=[]
    port_progress=0
    port_done=False
    pending_g=False
    pending_g_time=0.0

    def visible_hosts():
        rows=sorted(hosts, key=lambda h: int(ipaddress.IPv4Address(h.ip)))
        if sorted_online:
            rows.sort(key=lambda h:(h.status!="ONLINE", int(ipaddress.IPv4Address(h.ip))))
        if query:
            q=query.lower()
            rows=[h for h in rows if any(q in str(value).lower() for value in (
                h.ip, h.hostname, h.mac, h.vendor, h.ping, h.status,
                h.shares, h.web, h.printer, " ".join(map(str, h.ports))
            ))]
        return rows

    def start_scan(rng):
        nonlocal hosts,hostmap,scanning,scan_total,scan_done,scan_started,pool,futures,mode,message,selected,offset
        try: ips=parse_range(rng)
        except Exception as e:
            message=f"Invalid range: {e}"; return
        if scanning and pool:
            pool.shutdown(wait=False,cancel_futures=True)
        hosts=[]; hostmap={}; futures={}
        scan_total=len(ips); scan_done=0; scan_started=time.time()
        scanning=True; mode="scan"; selected=offset=0
        pool=concurrent.futures.ThreadPoolExecutor(max_workers=min(128,max(16,len(ips))))
        for ip in ips:
            futures[pool.submit(scan_one,ip)]=ip
        message=f"Scanning {rng} ({len(ips)} addresses)..."

    def start_ports(ip):
        nonlocal pool,futures,mode,port_target,port_results,port_progress,port_done,message
        try: ip=str(ipaddress.ip_address(ip.strip()))
        except ValueError:
            message="Invalid IPv4 address"; return
        if pool: pool.shutdown(wait=False,cancel_futures=True)
        port_target=ip; port_results=[]; port_progress=0; port_done=False
        mode="ports"; message=f"Port scan: {ip}"
        pool=concurrent.futures.ThreadPoolExecutor(max_workers=64)
        futures={pool.submit(tcp_open,ip,p,0.5):p for p in range(1,1025)}
        # Include common high ports as well.
        for p in [3306,3389,5900,8000,8080,8443,8888,9100]:
            futures[pool.submit(tcp_open,ip,p,0.5)]=p

    def start_udp_ports(ip):
        nonlocal pool,futures,mode,port_target,port_results,port_progress,port_done,message
        try: ip=str(ipaddress.ip_address(ip.strip()))
        except ValueError:
            message="Invalid IPv4 address"; return
        if pool: pool.shutdown(wait=False,cancel_futures=True)
        port_target=ip; port_results=[]; port_progress=0; port_done=False
        mode="portsudp"; message=f"UDP port scan: {ip}"
        pool=concurrent.futures.ThreadPoolExecutor(max_workers=32)
        futures={pool.submit(udp_probe,ip,p):p for p in COMMON_UDP_PORTS}

    def launch_monitor():
        """Temporarily hand the terminal to Shoal, then return to NETUI."""
        nonlocal message
        executable = shutil.which("shoal")
        if not executable:
            message = "Shoal not found. Install Shoal and ensure its executable is on PATH."
            return
        try:
            curses.def_prog_mode()
            curses.endwin()
            result = subprocess.run([executable], check=False)
            message = "Returned from Shoal monitor." if result.returncode == 0 else f"Shoal exited with status {result.returncode}."
        except OSError as exc:
            message = f"Could not launch Shoal: {exc}"
        finally:
            try:
                curses.reset_prog_mode()
                curses.curs_set(0)
                stdscr.clear()
                stdscr.refresh()
            except curses.error:
                pass

    def execute_command(cmd):
        nonlocal command_mode,command,message
        parts=cmd.strip().split()
        if not parts: return
        name=parts[0].lower()
        if name in (":q",":quit",":exit"):
            raise KeyboardInterrupt
        if name==":range":
            if len(parts)<2: message="Usage: :range 192.168.1.0/24"
            else: start_scan(parts[1])
        elif name==":ports":
            if len(parts)<2: message="Usage: :ports 192.168.1.1"
            else: start_ports(parts[1])
        elif name==":portsudp":
            if len(parts)<2: message="Usage: :portsUDP 192.168.1.1"
            else: start_udp_ports(parts[1])
        elif name==":monitor":
            launch_monitor()
        elif name==":help":
            nonlocal help_visible
            help_visible=True
            message=""
        elif name==":clear":
            hosts.clear(); message="Results cleared."
        else:
            message=f"Unknown command: {name}. Type :help"

    while True:
        try:
            h,w=stdscr.getmaxyx()
            stdscr.erase()
            if h<16 or w<70:
                safe_add(stdscr,0,0,"Terminal too small (need at least 70x16).",curses.color_pair(3)); stdscr.refresh()
                stdscr.getch(); continue
            # Outer frame and panels
            draw_box(stdscr,0,0,h,w,"NETUI — Network Scanner",1)
            safe_add(stdscr,3,2,f"Local IP: {local_ip}  |  Network: {local_network}",curses.color_pair(2),w-4)
            if scanning:
                pct=int(100*scan_done/max(1,scan_total))
                safe_add(stdscr,4,2,f"Range: {scan_total} addresses  |  Scanning...",curses.color_pair(5),w//2)
                barw=max(10,min(30,w//4))
                bar="█"*int(barw*pct/100)+"░"*(barw-int(barw*pct/100))
                safe_add(stdscr,4,w//2,f"[{bar}] {pct}%  {scan_done}/{scan_total}",curses.color_pair(2),w//2-3)
            else:
                safe_add(stdscr,4,2,f"Mode: {mode.upper()}  |  {message}",curses.color_pair(5),w-4)

            # Key bindings are available on demand through the ? help overlay.
            result_y=5
            footer_h=3
            input_active=command_mode or searching
            command_h=3 if input_active else 0
            result_h=h-result_y-command_h-footer_h-1
            draw_box(stdscr,result_y,1,result_h,w-2,"Scan Results" if mode not in ("ports", "portsudp") else f"{'UDP' if mode=='portsudp' else 'TCP'} Port Scan — {port_target}",1)
            inner_y=result_y+1
            if mode in ("ports", "portsudp"):
                safe_add(stdscr,inner_y,3,"PORT       STATE",curses.color_pair(1)|curses.A_BOLD,w-6)
                safe_add(stdscr,inner_y+1,3,"-"*(w-6),curses.color_pair(6),w-6)
                for i,item in enumerate(port_results[:max(0,result_h-4)]):
                    p, state = item if mode=="portsudp" else (item, "OPEN")
                    safe_add(stdscr,inner_y+2+i,3,f"{p:<10} {state}",curses.color_pair(2) if state == "OPEN" else curses.color_pair(4),w-6)
                if not port_done:
                    safe_add(stdscr,result_y+result_h-2,3,f"Checking {'UDP' if mode=='portsudp' else 'TCP'} ports... {port_progress} / {len(COMMON_UDP_PORTS) if mode=='portsudp' else 1033}",curses.color_pair(4),w-6)
                elif not port_results:
                    safe_add(stdscr,inner_y+2,3,"No responsive UDP ports found (silent ports may be filtered or open)." if mode=="portsudp" else "No open ports found in scanned range.",curses.color_pair(4),w-6)
            else:
                columns=[("IP",16),("HOSTNAME",16),("MAC",18),("VENDOR",12),("PING",8),("STATUS",10),("SHARES",16),("WEB PAGE",22),("PRINTER",9)]
                # Scale widths to terminal
                available=w-8
                base=sum(c[1] for c in columns)
                widths=[max(6,int(c[1]*available/base)) for c in columns]
                while sum(widths)>available: widths[widths.index(max(widths))]-=1
                while sum(widths)<available: widths[0]+=1
                x=3
                for (name,_),cw in zip(columns,widths):
                    safe_add(stdscr,inner_y,x,name,curses.color_pair(1)|curses.A_BOLD,cw)
                    x+=cw
                safe_add(stdscr,inner_y+1,3,"─"*available,curses.color_pair(6),available)
                rows=visible_hosts()
                maxrows=max(0,result_h-4)
                if selected>=len(rows): selected=max(0,len(rows)-1)
                if selected<offset: offset=selected
                if selected>=offset+maxrows: offset=max(0,selected-maxrows+1)
                for ri,host in enumerate(rows[offset:offset+maxrows]):
                    idx=offset+ri
                    vals=[host.ip,host.hostname,host.mac,host.vendor,host.ping,host.status,host.shares,host.web,host.printer]
                    x=3
                    attr=curses.color_pair(6) if idx==selected else curses.color_pair(5)
                    if idx==selected:
                        try: stdscr.addstr(inner_y+2+ri,2,"›",curses.color_pair(1)|curses.A_BOLD)
                        except curses.error: pass
                    for ci,(val,cw) in enumerate(zip(vals,widths)):
                        if ci==5:
                            col=curses.color_pair(2) if val=="ONLINE" else (curses.color_pair(3) if val=="OFFLINE" else curses.color_pair(4))
                        else: col=attr
                        safe_add(stdscr,inner_y+2+ri,x,val,col,cw)
                        x+=cw
                if not rows:
                    safe_add(stdscr,inner_y+3,3,"No results yet. Use :range 192.168.1.0/24 to start scanning.",curses.color_pair(4),w-8)
                safe_add(stdscr,result_y+result_h-2,3,f"Hosts: {len(rows)} shown / {len(hosts)} discovered",curses.color_pair(1),w-8)

            # Vim-like command line: hidden until ':' or '/' is pressed.
            bottom_y=h-command_h-footer_h-1
            if input_active:
                draw_box(stdscr,bottom_y,1,command_h,w-2,None,1)
                if command_mode:
                    safe_add(stdscr,bottom_y+1,3,command,curses.color_pair(2)|curses.A_BOLD,w-6)
                    if command_menu and len(command.strip().split()) <= 1:
                        typed=command[1:].strip().split(" ",1)[0].lower() if command.startswith(":") else ""
                        filtered=[opt for opt in command_options if not typed or opt[0].lower().startswith(typed)]
                        if filtered:
                            command_menu_index=min(command_menu_index,len(filtered)-1)
                            menu_h=min(len(filtered)+2, h-12)
                            menu_w=min(64,w-4)
                            menu_y=max(6,bottom_y-menu_h)
                            draw_box(stdscr,menu_y,2,menu_h,menu_w,"Commands — Tab/↑↓ select",1)
                            for mi,(name,syntax,desc) in enumerate(filtered):
                                marker="›" if mi==command_menu_index else " "
                                attr=(curses.color_pair(2)|curses.A_BOLD) if mi==command_menu_index else curses.color_pair(5)
                                safe_add(stdscr,menu_y+1+mi,4,f"{marker} {syntax:<12} {desc}",attr,menu_w-4)
                        else:
                            safe_add(stdscr,bottom_y+2,3,"No matching commands",curses.color_pair(5),w-6)
                elif searching:
                    safe_add(stdscr,bottom_y+1,3,"/"+query+"_",curses.color_pair(2)|curses.A_BOLD,w-6)
            if help_visible:
                help_lines=[
                    "KEY BINDINGS",
                    "↑ / ↓ or j / k   Navigate results",
                    "Enter             Open selected web page",
                    "gg                Jump to first result",
                    "G                 Jump to last result",
                    "Ctrl+S            Toggle online-first sorting",
                    "/                 Search results",
                    ":                 Open command menu",
                    ":monitor          Open Shoal live network monitor",
                    "?                 Show this help",
                    "q                 Return to initial screen",
                    ":q                Exit NETUI",
                    "",
                    "Press q to close this menu",
                ]
                panel_w=min(58,w-8); panel_h=min(len(help_lines)+2,h-4)
                panel_y=max(1,(h-panel_h)//2); panel_x=max(1,(w-panel_w)//2)
                draw_box(stdscr,panel_y,panel_x,panel_h,panel_w,"Help",1)
                for hi,line in enumerate(help_lines[:panel_h-2]):
                    attr=curses.color_pair(2)|curses.A_BOLD if hi==0 else curses.color_pair(5)
                    safe_add(stdscr,panel_y+1+hi,panel_x+2,line,attr,panel_w-4)
            draw_box(stdscr,h-footer_h,w-2,footer_h,w-2,None,1)
            safe_add(stdscr,h-2,2,f"NETUI v1.0  |  {'Scanning...' if scanning else 'Ready'}",curses.color_pair(1),w-4)
            stdscr.refresh()

            # collect worker results
            if mode=="scan" and futures:
                done=[f for f in futures if f.done()]
                for f in done:
                    ip=futures.pop(f)
                    try: host=f.result()
                    except Exception: host=Host(ip=ip,status="OFFLINE")
                    hosts.append(host); hostmap[ip]=host; scan_done+=1
                if scan_done>=scan_total:
                    scanning=False
                    if pool: pool.shutdown(wait=False)
                    message=f"Scan complete: {len(hosts)} hosts checked."
            elif mode in ("ports", "portsudp") and futures:
                done=[f for f in futures if f.done()]
                for f in done:
                    p=futures.pop(f)
                    try:
                        result=f.result()
                        if mode=="portsudp":
                            if result != "CLOSED": port_results.append((p,result))
                        elif result:
                            port_results.append(p)
                    except Exception: pass
                    port_progress+=1
                if not futures:
                    port_done=True; port_results.sort(key=lambda item: item[0] if isinstance(item, tuple) else item)
                    message=f"{'UDP' if mode=='portsudp' else 'TCP'} scan complete: {len(port_results)} responsive/open ports."

            key=stdscr.getch()
            if key==-1: continue
            if help_visible:
                if key in (ord('q'),ord('Q')):
                    help_visible=False
                continue
            if command_mode:
                typed=command[1:].strip().split(" ",1)[0].lower() if command.startswith(":") else ""
                filtered=[opt for opt in command_options if not typed or opt[0].lower().startswith(typed)]
                if key==27:
                    command_mode=False; command_menu=False; command=""
                elif key in (10,13):
                    # Once an argument is present, Enter executes the command instead
                    # of selecting an autocomplete suggestion. This is important for
                    # :range CIDR, :ports IP, and :portsUDP IP.
                    has_argument = len(command.strip().split()) > 1
                    if command_menu and filtered and not has_argument:
                        name,syntax,_=filtered[min(command_menu_index,len(filtered)-1)]
                        if name in ("help","clear","quit","monitor"):
                            command_mode=False; command_menu=False; command=""
                            execute_command(syntax)
                        else:
                            command=syntax; command_menu=False
                    else:
                        c=command; command_mode=False; command_menu=False; command=""
                        execute_command(c)
                elif key in (curses.KEY_BACKSPACE,127,8):
                    command=command[:-1]; command_menu=True; command_menu_index=0
                elif key in (9,curses.KEY_DOWN,ord('j')) and command_menu and filtered:
                    command_menu_index=(command_menu_index+1)%len(filtered)
                elif key in (curses.KEY_UP,ord('k')) and command_menu and filtered:
                    command_menu_index=(command_menu_index-1)%len(filtered)
                elif 0<=key<256 and chr(key).isprintable():
                    command+=chr(key); command_menu=True; command_menu_index=0
                continue
            if searching:
                if key==27: searching=False; query=""
                elif key in (10,13): query=query.strip(); searching=False; selected=offset=0
                elif key in (curses.KEY_BACKSPACE,127,8): query=query[:-1]; selected=offset=0
                elif 0<=key<256 and chr(key).isprintable(): query+=chr(key); selected=offset=0
                continue
            rows=visible_hosts()
            if pending_g and time.monotonic()-pending_g_time > 0.8:
                pending_g=False
            if key==ord('?'):
                help_visible=True
            elif key==ord(':'):
                command_mode=True; command=":"; command_menu=True; command_menu_index=0
            elif key==ord('/'):
                searching=True; query=""
            elif key==19: # Ctrl-S
                sorted_online=not sorted_online; selected=offset=0
                message="Online-first sort enabled" if sorted_online else "Original order restored"
            elif key in (curses.KEY_DOWN,ord('j')):
                selected=min(max(0,len(rows)-1),selected+1)
            elif key in (curses.KEY_UP,ord('k')):
                selected=max(0,selected-1)
            elif key==ord('G'):
                selected=max(0,len(rows)-1)
            elif key==ord('g'):
                if pending_g:
                    selected=0
                    pending_g=False
                else:
                    pending_g=True
                    pending_g_time=time.monotonic()
            elif key in (10,13):
                if rows:
                    message=open_host_webpage(rows[selected])
            elif key in (ord('q'), ord('Q')):
                # q returns to the clean initial view; only :q exits NETUI.
                if pool:
                    pool.shutdown(wait=False, cancel_futures=True)
                    pool = None
                futures.clear()
                hosts.clear()
                hostmap.clear()
                port_results.clear()
                scanning = False
                scan_total = scan_done = 0
                port_progress = 0
                port_done = False
                mode = "idle"
                query = ""
                searching = False
                selected = offset = 0
                sorted_online = False
                message = "Ready. Press : for commands, / to search."
        except KeyboardInterrupt:
            break
    if pool:
        pool.shutdown(wait=False,cancel_futures=True)

def uninstall():
    """Remove the installed NETUI launcher (the script currently being run)."""
    target = pathlib.Path(sys.argv[0]).expanduser().resolve()
    print(f"NETUI launcher: {target}")
    if not target.is_file():
        print("Installed launcher was not found.")
        return 1
    try:
        target.unlink()
    except OSError as exc:
        print(f"Could not remove NETUI: {exc}")
        if "permission" in str(exc).lower() or getattr(exc, "errno", None) == 13:
            print("If installed system-wide, run: sudo netui uninstall")
        return 1
    print("NETUI has been uninstalled. Your scan data and configuration (if any) were not touched.")
    return 0

if __name__=="__main__":
    if len(sys.argv) > 1 and sys.argv[1].lower() == "uninstall":
        raise SystemExit(uninstall())
    try: curses.wrapper(main)
    except KeyboardInterrupt: pass
