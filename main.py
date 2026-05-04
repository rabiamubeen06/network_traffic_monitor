import csv
import os
import random
import threading
import time
from collections import defaultdict
from datetime import datetime
from flask import Flask, jsonify, request, render_template


_BASE = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(_BASE, "templates"),
    static_folder=os.path.join(_BASE, "static"),
)


DATA_FILE = os.path.join(_BASE, "traffic_log.csv")   
LOG_FILE  = os.path.join(_BASE, "session_log.csv")    #

COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "packet_size", "service", "status"
]


for _f in [DATA_FILE, LOG_FILE]:
    if os.path.exists(_f):
        os.remove(_f)


monitoring   = False
thread       = None


SERVICE_MAP = {
    "192.168.1.1":  "DNS",
    "192.168.1.2":  "WEB",
    "192.168.1.3":  "MAIL",
    "192.168.1.10": "GW",
    "192.168.1.50": "DB",
}

SERVICE_IP = {v: k for k, v in SERVICE_MAP.items()}


STUDENT_IPS = [f"192.168.2.{i}" for i in range(1,   141)]  
STAFF_IPS   = [f"192.168.2.{i}" for i in range(141, 191)]  
ADMIN_IPS   = [f"192.168.2.{i}" for i in range(191, 201)]  



ROLE_POOLS = {
    "student": STUDENT_IPS,
    "staff":   STAFF_IPS,
    "admin":   ADMIN_IPS,
}


ROLES        = ["student", "staff", "admin"]
ROLE_WEIGHTS = [0.70,       0.25,    0.05]


session_roles: dict[str, str] = {}

def get_role(ip: str) -> str:
    
    if ip in SERVICE_MAP:
        return SERVICE_MAP[ip]          
    return session_roles.get(ip, "")


PORT_SERVICE = {
    80:   "HTTP",
    443:  "HTTPS",
    53:   "DNS",
    25:   "SMTP",
    22:   "SSH",
    21:   "FTP",
    3306: "MySQL",
    5432: "PostgreSQL",
    143:  "IMAP",
    993:  "IMAPS",
    123:  "NTP",
    161:  "SNMP",
    3389: "RDP",
    8080: "HTTP-Alt",
}

def get_service(port) -> str:
    if port is None or port == 0:
        return "ICMP"
    return PORT_SERVICE.get(port, "Unknown")


def get_device_display(ip: str, show_name: bool = True) -> str:
   
    if not show_name:
        return ip
    tag = get_device_type(ip)
    return f"{tag} {ip}" if tag else ip

def get_device_type(ip: str) -> str:
   
    if ip in SERVICE_MAP:
        return f"[{SERVICE_MAP[ip]}]"
    role = session_roles.get(ip, "")
    if role == "student":
        return "[STU]"
    if role == "staff":
        return "[STAFF]"
    if role == "admin":
        return "[ADMIN]"
    return "[SERVER]"




STUDENT_BEHAVIOURS = [
        
    (45,      "WEB",        [80, 443],            "TCP",   (200,  800)),   
    (30,      "DNS",        [53],                 "UDP",   (50,   120)),   
    (12,      "WEB",        [80, 8080],           "TCP",   (900,  1500)),  
    (8,       "MAIL",       [143, 993],           "TCP",   (100,  500)),   
    (5,       "DB",         [22, 25, 3306],       "TCP",   (100,  600)),   
]

STAFF_BEHAVIOURS = [
    (35,      "WEB",        [80, 443],            "TCP",   (200,  900)),   
    (30,      "DB",         [3306, 5432],         "TCP",   (150,  700)),   
    (20,      "DNS",        [53],                 "UDP",   (50,   120)),   
    (15,      "MAIL",       [25, 143, 993],       "TCP",   (100,  600)),  
]

ADMIN_BEHAVIOURS = [
    (30,      "DB",         [3306, 5432],         "TCP",   (200,  800)),   
    (20,      "WEB",        [80, 443, 8080],      "TCP",   (200,  700)),   
    (20,      "DNS",        [53, 161, 123],       "UDP",   (60,   200)),   
    (20,      "GW",         [22],                 "TCP",   (100,  400)),   
    (10,      "MAIL",       [25, 143],            "TCP",   (100,  500)),  
]

BEHAVIOUR_MAP = {
    "student": STUDENT_BEHAVIOURS,
    "staff":   STAFF_BEHAVIOURS,
    "admin":   ADMIN_BEHAVIOURS,
}

def _pick_behaviour(role: str):
    
    behaviours = BEHAVIOUR_MAP[role]
    weights    = [b[0] for b in behaviours]
    return random.choices(behaviours, weights=weights, k=1)[0]


def generate_packet() -> dict:
   
    
    role = random.choices(ROLES, weights=ROLE_WEIGHTS, k=1)[0]

    
    src_ip = random.choice(ROLE_POOLS[role])

   
    session_roles[src_ip] = role

   
    _, dst_service, dst_ports, protocol_hint, size_range = _pick_behaviour(role)

   
    if random.random() < 0.2:
        dst_ip = f"192.168.3.{random.randint(1, 254)}"
    else:
        dst_ip = SERVICE_IP[dst_service]

  
    src_port = random.randint(1024, 65535)

   
    dst_port = random.choice(dst_ports)

   
    if protocol_hint == "TCP":
        protocol = "TCP"
    elif protocol_hint == "UDP":
        protocol = "UDP"
    elif protocol_hint == "ICMP":
        protocol = "ICMP"
    else:
       
        protocol = random.choices(["TCP", "UDP", "ICMP"], weights=[0.6, 0.3, 0.1], k=1)[0]

    
    if random.random() < 0.10:
        protocol = "ICMP"

    
    packet_size = random.randint(*size_range)

    
    if protocol == "ICMP":
        src_port    = None
        dst_port    = None
        packet_size = random.randint(28, 84)

    service   = get_service(dst_port)
    timestamp = datetime.now().strftime("%H:%M:%S")

    return {
        "timestamp":   timestamp,
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
        "src_port":    src_port if src_port is not None else "N/A",
        "dst_port":    dst_port if dst_port is not None else "N/A",
        "protocol":    protocol,
        "packet_size": packet_size,
        "service":     service,
        "status":      "PENDING",
    }



def save_packet(packet: dict) -> None:
    
    for filepath in [DATA_FILE, LOG_FILE]:
        file_exists = os.path.isfile(filepath)
        with open(filepath, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=COLUMNS)
            if not file_exists:
                writer.writeheader()
            writer.writerow(packet)



def monitor_loop() -> None:
    global monitoring
    packets_per_second = 3

    while monitoring:
        for _ in range(packets_per_second):

           
            packet1 = generate_packet()
            save_packet(packet1)

           
            packet2 = packet1.copy()

            packet2["src_ip"], packet2["dst_ip"] = (
                packet1["dst_ip"],
                packet1["src_ip"]
            )

            if packet1["protocol"] != "ICMP":
                packet2["src_port"], packet2["dst_port"] = (
                    packet1["dst_port"],
                    packet1["src_port"]
                )
            else:
                packet2["src_port"] = "N/A"
                packet2["dst_port"] = "N/A"

            packet2["timestamp"] = packet1["timestamp"]
            packet2["protocol"]  = packet1["protocol"]
            packet2["service"]   = packet1["service"]
            packet2["status"]    = "PENDING"

            if packet2["protocol"] != "ICMP":
                try:
                    size = int(packet2["packet_size"])
                    packet2["packet_size"] = max(28, size - random.randint(5, 50))
                except:
                    pass

            save_packet(packet2)

        time.sleep(1)


def read_data(protocol="", src_ip="", dst_ip="", status="") -> list:
   
    if not os.path.exists(DATA_FILE):
        return []

    with open(DATA_FILE, "r") as f:
        rows = list(csv.DictReader(f))

    result = []
    for row in rows:
        if protocol and protocol != "ALL" and row["protocol"] != protocol:
            continue
        if src_ip and src_ip not in row["src_ip"]:
            continue
        if dst_ip and dst_ip not in row["dst_ip"]:
            continue
        if status and status != "ALL" and row["status"] != status:
            continue
        result.append(row)

    return result



def calculate_statistics(rows: list) -> dict:
   
    total = len(rows)

    if total == 0:
        return {
            "total_packets":    0,
            "avg_packet_size":  0,
            "protocol_counts":  {"TCP": 0, "UDP": 0, "ICMP": 0},
            "top_services":     [],
            "top_src_ips":      [],
            "top_dst_ips":      [],
            "top_ports":        [],
            "malicious_count":  0,
            "suspicious_count": 0,
            "pending_count":    0,
        }

    protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0}
    total_size      = 0
    service_counts  = {}
    src_counts      = {}
    dst_counts      = {}
    port_counts     = {}
    malicious = suspicious = pending = 0

    for row in rows:
        p = row["protocol"]
        if p in protocol_counts:
            protocol_counts[p] += 1

        total_size += int(row["packet_size"])

        svc = row["service"]
        service_counts[svc] = service_counts.get(svc, 0) + 1

        src = row["src_ip"]
        src_counts[src] = src_counts.get(src, 0) + 1

        dst = row["dst_ip"]
        dst_counts[dst] = dst_counts.get(dst, 0) + 1

        try:
            port = int(row["dst_port"])
            if port > 0:
                port_counts[port] = port_counts.get(port, 0) + 1
        except Exception:
            pass

        st = row["status"]
        if st == "MALICIOUS":
            malicious += 1
        elif st == "SUSPICIOUS":
            suspicious += 1
        elif st == "PENDING":
            pending += 1

    def top5(count_dict):
        items = sorted(count_dict.items(), key=lambda x: x[1], reverse=True)[:5]
        return [{"name": k, "count": v} for k, v in items]

    def top5_ips(count_dict):
        items = sorted(count_dict.items(), key=lambda x: x[1], reverse=True)[:5]
        return [{"ip": k, "type": get_device_type(k), "count": v} for k, v in items]

    def top5_ports(port_dict):
        items = sorted(port_dict.items(), key=lambda x: x[1], reverse=True)[:5]
        return [{"port": k, "service": get_service(k), "count": v} for k, v in items]

    return {
        "total_packets":    total,
        "avg_packet_size":  round(total_size / total, 2),
        "protocol_counts":  protocol_counts,
        "top_services":     top5(service_counts),
        "top_src_ips":      top5_ips(src_counts),
        "top_dst_ips":      top5_ips(dst_counts),
        "top_ports":        top5_ports(port_counts),
        "malicious_count":  malicious,
        "suspicious_count": suspicious,
        "pending_count":    pending,
    }

THRESHOLD = 60


_WEB_IP = SERVICE_IP.get("WEB")   

def _build_ddos_targets(rows: list) -> set:
    
    buckets: dict[tuple, set] = defaultdict(set)

    for row in rows:
        
        if row["dst_ip"] == _WEB_IP:
            continue

        ts = row["timestamp"]         
        minute_key = ts[:5]           
        key = (row["dst_ip"], minute_key)
        buckets[key].add(row["src_ip"])

    ddos_targets = set()
    for (dst_ip, _minute), src_set in buckets.items():
        if len(src_set) >= THRESHOLD:
            ddos_targets.add(dst_ip)

    return ddos_targets



@app.route("/")
def home():
    return render_template("index.html")

@app.route("/api/status")
def status():
    return jsonify({"active": monitoring})

@app.route("/api/start", methods=["POST"])
def start():
    global monitoring, thread, session_roles

    if monitoring:
        return jsonify({"status": "already running"})

    session_roles = {}         
    monitoring    = True
    thread = threading.Thread(target=monitor_loop, daemon=True)
    thread.start()

    return jsonify({"status": "started"})

@app.route("/api/stop", methods=["POST"])
def stop():
    global monitoring
    monitoring = False
    return jsonify({"status": "stopped"})

@app.route("/api/data", methods=["GET"])
def get_data():
   
    protocol      = request.args.get("protocol",   "ALL")
    src_ip        = request.args.get("src_ip",      "")
    dst_ip        = request.args.get("dst_ip",      "")
    status_filter = request.args.get("status",      "ALL")
    show_names    = request.args.get("show_names",  "false").lower() == "true"

    rows = read_data(protocol, src_ip, dst_ip, status_filter)

    for row in rows:
        if show_names:
            row["src_ip_display"] = get_device_display(row["src_ip"], True)
            row["dst_ip_display"] = get_device_display(row["dst_ip"], True)
        else:
            row["src_ip_display"] = row["src_ip"]
            row["dst_ip_display"] = row["dst_ip"]

    stats = calculate_statistics(rows)

    return jsonify({
        "logs":       list(reversed(rows[-100:])),
        "statistics": stats,
        "count":      len(rows),
    })

@app.route("/api/logs", methods=["GET"])
def get_logs():
   
    if not os.path.exists(LOG_FILE):
        return jsonify({"logs": [], "count": 0})

    with open(LOG_FILE, "r") as f:
        rows = list(csv.DictReader(f))

    for row in rows:
        row["src_ip_display"] = get_device_display(row["src_ip"], True)
        row["dst_ip_display"] = get_device_display(row["dst_ip"], True)

    return jsonify({
        "logs":  list(reversed(rows)),
        "count": len(rows),
    })

@app.route("/api/clear", methods=["POST"])
def clear():
    
    if os.path.exists(DATA_FILE):
        os.remove(DATA_FILE)
    return jsonify({"status": "cleared"})

@app.route("/api/analyze", methods=["POST"])
def analyze():
   
    if not os.path.exists(DATA_FILE):
        return jsonify({"status": "no data"})

    with open(DATA_FILE, "r") as f:
        rows = list(csv.DictReader(f))

    ddos_targets = _build_ddos_targets(rows)

   
    MALICIOUS_PORTS = {22, 25, 3306}  

    for row in rows:
        if row["status"] != "PENDING":
            continue

       
        if row["dst_ip"] in ddos_targets:
            row["status"] = "DDOS DETECTED"
            continue

        src_ip = row["src_ip"]
        role   = session_roles.get(src_ip, "")

        try:
            dst_port = int(row["dst_port"])
        except Exception:
            dst_port = 0

        
        if role == "student" and dst_port in MALICIOUS_PORTS:
            row["status"] = "MALICIOUS"
            continue

       
        if int(row["packet_size"]) > 1400:
            row["status"] = "SUSPICIOUS"
            continue

       
        row["status"] = "NORMAL"

    with open(DATA_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    return jsonify({"status": "analyzed", "count": len(rows)})


if __name__ == "__main__":
    app.run(debug=True, port=5001, use_reloader=False, threaded=True)