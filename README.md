
  NETWORK TRAFFIC MONITOR — README

PROJECT OVERVIEW
----------------
A browser-based network traffic monitoring platform designed for a university
LAN environment. It simulates realistic packet traffic across a two-subnet
architecture (infrastructure servers on 192.168.1.x, user devices on
192.168.2.x), provides real-time filtering and statistics, and detects
anomalous or malicious activity using a rule-based analysis engine.

The system is built with a Python/Flask backend and a vanilla HTML + CSS + JS
frontend. No external JavaScript frameworks are used.

FILE STRUCTURE:

  main.py          — Flask backend: packet simulation, analysis engine, REST API
  index.html       — Single-page frontend (served via Flask template)
  style.css        — Dark-theme stylesheet (purple/cyan colour palette)
  script.js        — Frontend logic: polling, table rendering, filter handling
  traffic_log.csv  — Live captured-packets file (auto-created, clearable)
  session_log.csv  — Persistent session log (auto-created, NOT clearable)

ARCHITECTURE:
SUBNETS
  192.168.1.x  — Infrastructure / Destination servers (5 fixed nodes)
  192.168.2.x  — User devices / Source clients (200 dynamic IPs)

SERVERS (192.168.1.x)
  192.168.1.1   → DNS server
  192.168.1.2   → WEB server
  192.168.1.3   → MAIL server
  192.168.1.10  → Gateway (GW)
  192.168.1.50  → Database (DB)

USER DEVICE POOLS (192.168.2.x)
  .1  – .140   → Students  (STU)   — 140 IPs, ~70% of traffic weight
  .141 – .190  → Staff     (STAFF) — 50 IPs,  ~25% of traffic weight
  .191 – .200  → Admins    (ADMIN) — 10 IPs,  ~5%  of traffic weight

Each IP is permanently bound to a role for the duration of a monitoring
session. Role assignments are re-generated fresh on every new Start.

BACKEND — main.py

PACKET GENERATION PIPELINE
  Every second the background thread generates 3 packets plus their bidirectional
  mirror packets (6 total writes per second to CSV). The pipeline:

    1. Pick role by weight  (student 70% / staff 25% / admin 5%)
    2. Pick source IP from that role's dedicated subnet pool
    3. Pick a behaviour profile (weighted per role — see table below)
    4. Resolve destination IP from the behaviour's target service
    5. Assign ephemeral source port (1024–65535)
    6. Assign destination port from the behaviour's allowed port list
    7. Override to ICMP with 10% probability (no ports, 28–84 bytes)
    8. Write packet to traffic_log.csv AND session_log.csv

BEHAVIOUR PROFILES
  Students:  web browsing (45%), DNS lookups (30%), streaming/large HTTP (12%),
             mail (8%), suspicious DB/SSH/SMTP access (5%)
  Staff:     web (35%), authorised DB access (30%), DNS (20%), email (15%)
  Admins:    DB management (30%), web admin (20%), DNS/SNMP/NTP (20%),
             SSH to gateway (20%), misc internal mail (10%)

PORT → SERVICE MAPPING
  22   SSH      25   SMTP     53   DNS      80   HTTP
  143  IMAP     161  SNMP     443  HTTPS    993  IMAPS
  3306 MySQL    3389 RDP      5432 PostgreSQL    8080 HTTP-Alt

STORAGE — TWO-FILE DESIGN
  traffic_log.csv   Captured packets. Cleared by the Clear button.
                    This is the primary working dataset for the live table
                    and statistics panel.
  session_log.csv   Persistent log. Written alongside traffic_log.csv but
                    NEVER touched by Clear. Survives clear operations and
                    accumulates all packets for the session. Shown in the
                    Logs panel.

  Both files are deleted and recreated clean on every application startup.

ANALYSIS ENGINE  (/api/analyze)
  Processes all PENDING packets in priority order:

    Priority 1 — DDOS DETECTED
      Sliding 60-second window (keyed on HH:MM of timestamp).
      If ≥ 100 unique source IPs hit the same destination in one window,
      that destination is flagged. All packets destined for it become
      "DDOS DETECTED". WEB server (192.168.1.2) is intentionally excluded
      from DDoS analysis — high concurrent web traffic is normal behaviour.

    Priority 2 — MALICIOUS
      Student-role source IP accessing restricted ports: SSH (22), SMTP (25),
      or MySQL (3306). Students have no business accessing these services.

    Priority 3 — SUSPICIOUS
      Any packet with packet_size > 1400 bytes. May indicate data exfiltration
      or unusual payload sizes regardless of role.

    Priority 4 — NORMAL
      All other packets that pass the above checks.

  Analysis results are written back to traffic_log.csv only. session_log.csv
  retains the original PENDING statuses (it is an immutable audit trail).

STATISTICS  (/api/data)
  Computed on every data fetch from the filtered row set:
  - Total packet count
  - Average packet size (bytes)
  - Protocol breakdown: TCP / UDP / ICMP counts
  - Top 5 services by packet count
  - Top 5 source IPs by packet count
  - Top 5 destination IPs by packet count
  - Malicious / Suspicious / Pending counts


--------------------------------------------------------------------------------
REST API ENDPOINTS
--------------------------------------------------------------------------------

  GET  /                    Serves the frontend HTML page
  GET  /api/status          Returns {"active": true/false}
  POST /api/start           Starts background monitoring thread
  POST /api/stop            Stops monitoring thread
  POST /api/clear           Deletes traffic_log.csv (session_log.csv unaffected)
  POST /api/analyze         Runs analysis engine on all PENDING packets
  GET  /api/data            Returns filtered packets + statistics
        Query params: protocol, src_ip, dst_ip, status, show_names
  GET  /api/logs            Returns all records from session_log.csv


--------------------------------------------------------------------------------
FRONTEND — index.html + style.css + script.js

UI LAYOUT
  Header          Application title bar
  Controls bar    Start / Stop / Clear / Analyze / Show Logs buttons
  Filters bar     Protocol dropdown, Source IP, Destination IP text inputs
  Status bar      Animated dot + text (IDLE / MONITORING...)
  Live Traffic    Scrollable table, last 100 packets, newest-first
  Statistics      6 stat cards + full-width OSI layer reference panel
  Logs panel      Collapsible, loads from session_log.csv, paginated (100/page)

POLLING STRATEGY
  - While monitoring:  loadData() every 2 seconds, loadLogs() every 2 seconds
  - While idle:        loadData() every 5 seconds (passive refresh)
  - Logs panel only polls when it is open (visible)

DISPLAY TAGS
  Each IP address in the tables is prefixed with a colour-coded role tag:
  [DNS]   purple     [WEB]   blue        [MAIL]  green
  [GW]    amber      [DB]    pink        [STU]   cyan
  [STAFF] light-green   [ADMIN]  yellow   [SERVER] grey
  Tags can be toggled on/off with the "Show Names / Hide Names" button.

STATUS COLOUR CODING
  NORMAL         green
  SUSPICIOUS     amber / bold
  MALICIOUS      red / bold
  DDOS DETECTED  orange-red / uppercase
  PENDING        purple / italic

FILTER BEHAVIOUR
  - Filters apply to the live traffic table and statistics only.
  - The Logs panel always shows the full unfiltered session log.
  - Reset button clears filter inputs and reloads the table view only;
    it does NOT delete any data.

OSI REFERENCE PANEL
  A static reference card at the bottom of the Statistics section lists all
  7 OSI layers with the protocols relevant to this platform highlighted in bold.

DATA FILE — traffic_log.csv

CSV columns (9 fields):
  timestamp    HH:MM:SS of packet capture
  src_ip       Source IP address (192.168.1.x or 192.168.2.x)
  dst_ip       Destination IP address
  src_port     Ephemeral source port (integer or "N/A" for ICMP)
  dst_port     Destination port (integer or "N/A" for ICMP)
  protocol     TCP | UDP | ICMP
  packet_size  Payload size in bytes
  service      Service name resolved from destination port (e.g. HTTP, DNS)
  status       PENDING | NORMAL | SUSPICIOUS | MALICIOUS | DDOS DETECTED

Example row:
  11:02:49,192.168.1.44,192.168.1.138,20545,21,TCP,1275,FTP,NORMAL


--------------------------------------------------------------------------------
HOW TO RUN
--------------------------------------------------------------------------------

Requirements:
  Python 3.9+
  Flask  (pip install flask)

Steps:
  1. Place all files in the same directory with the following structure:
       project/
         main.py
         templates/
           index.html
         static/
           style.css
           script.js

  2. Run the server:
       python main.py

  3. Open a browser and navigate to:
       http://localhost:5001

  4. Click "Start Monitoring" to begin packet simulation.
     Click "Analyze" at any time to classify captured packets.
     Click "Show Logs" to view the persistent session log.

Notes:
  - The server runs on port 5001 by default (configurable at bottom of main.py).
  - Both CSV files are wiped on every startup — no stale data is shown.
  - Root-level network access is NOT required; all traffic is simulated.
  - The app is single-user and not designed for concurrent sessions.


--------------------------------------------------------------------------------
KNOWN DESIGN DECISIONS & NOTES
--------------------------------------------------------------------------------

- DDoS threshold is 100 unique sources per 60-second window. This is tuned
  for a simulation environment and may need adjustment for production use.

- The WEB server is excluded from DDoS flagging by design because the student
  behaviour profile creates legitimately high fan-in to it.

- Bidirectional mirroring means each real packet generates a reply packet,
  so raw packet counts are approximately 2x the number of user actions.

- The Clear button does NOT stop monitoring. Packet generation continues
  uninterrupted; the display simply resets to zero.

- Filtering is done server-side on each /api/data request. Large datasets
  (thousands of packets) may cause slight latency in the filter response.

================================================================================
  END OF README
================================================================================
