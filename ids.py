#!/usr/bin/env python3
"""
Intrusion Detection System (IDS)
----------------------------------
Watches a stream of packets (live via Scapy, or a synthetic/replayed
stream) and raises alerts for:
  - Port scans     : one source IP hitting many distinct destination ports
                      in a short time window
  - Brute force     : one source IP making many connection attempts to the
                      SAME port (e.g. repeated SSH/RDP logins)
  - Traffic spikes  : overall packet rate exceeding a threshold

Alerts are written to a SQLite database and can be viewed live in a small
Flask dashboard.

Tech: Scapy (optional live capture), SQLite, Flask.

Usage:
    python3 ids.py --demo                 # run the built-in synthetic-attack demo
    python3 ids.py --serve                # launch the dashboard (reads alerts.db)
    sudo python3 ids.py --iface eth0      # live monitoring (needs raw socket perms)
"""
import argparse
import sqlite3
import time
from collections import defaultdict, deque
from datetime import datetime

DB_PATH = "alerts.db"

PORT_SCAN_WINDOW_SEC = 5
PORT_SCAN_THRESHOLD = 10        # distinct ports from one src within window
BRUTE_FORCE_WINDOW_SEC = 10
BRUTE_FORCE_THRESHOLD = 8       # connections to same src:dstport within window
SPIKE_WINDOW_SEC = 2
SPIKE_THRESHOLD = 200           # packets within window


def init_db(path=DB_PATH):
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            src TEXT,
            detail TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


class Detector:
    def __init__(self, conn):
        self.conn = conn
        self.port_events = defaultdict(deque)      # src -> deque[(ts, dport)]
        self.conn_events = defaultdict(deque)       # (src,dport) -> deque[ts]
        self.all_events = deque()                   # ts of every packet

    def _raise(self, alert_type, src, detail):
        ts = datetime.now().isoformat(timespec="seconds")
        self.conn.execute(
            "INSERT INTO alerts (ts, alert_type, src, detail) VALUES (?, ?, ?, ?)",
            (ts, alert_type, src, detail),
        )
        self.conn.commit()
        print(f"[ALERT] {ts} {alert_type:12} src={src or '-':16} {detail}")

    def process(self, src: str, dst: str, dport, now=None):
        now = now if now is not None else time.time()

        # -- traffic spike --
        self.all_events.append(now)
        while self.all_events and now - self.all_events[0] > SPIKE_WINDOW_SEC:
            self.all_events.popleft()
        if len(self.all_events) == SPIKE_THRESHOLD:
            self._raise("SPIKE", src, f"{len(self.all_events)} packets in {SPIKE_WINDOW_SEC}s window")

        if src is None or dport is None:
            return

        # -- port scan: many distinct ports from one source --
        dq = self.port_events[src]
        dq.append((now, dport))
        while dq and now - dq[0][0] > PORT_SCAN_WINDOW_SEC:
            dq.popleft()
        distinct_ports = len({p for _, p in dq})
        if distinct_ports == PORT_SCAN_THRESHOLD:
            self._raise("PORT_SCAN", src, f"{distinct_ports} distinct dst ports to {dst} in {PORT_SCAN_WINDOW_SEC}s")

        # -- brute force: many hits to the same dst port from one source --
        key = (src, dport)
        cdq = self.conn_events[key]
        cdq.append(now)
        while cdq and now - cdq[0] > BRUTE_FORCE_WINDOW_SEC:
            cdq.popleft()
        if len(cdq) == BRUTE_FORCE_THRESHOLD:
            self._raise("BRUTE_FORCE", src, f"{len(cdq)} connection attempts to {dst}:{dport} in {BRUTE_FORCE_WINDOW_SEC}s")


def run_demo():
    """Feed the detector a synthetic stream that contains a port scan,
    an SSH brute force, and a traffic spike, so you can see all three
    alert types fire without needing root or a live network."""
    conn = init_db()
    detector = Detector(conn)
    t = time.time()

    print("[*] Simulating normal background traffic...")
    for i in range(5):
        detector.process("10.0.0.5", "10.0.0.1", 443, now=t)
        t += 0.3

    print("[*] Simulating a port scan from 192.168.1.99...")
    for port in range(1, 15):
        detector.process("192.168.1.99", "10.0.0.1", port, now=t)
        t += 0.05

    print("[*] Simulating an SSH brute force from 203.0.113.7...")
    for _ in range(12):
        detector.process("203.0.113.7", "10.0.0.1", 22, now=t)
        t += 0.2

    print("[*] Simulating a traffic spike...")
    for _ in range(SPIKE_THRESHOLD):
        detector.process(f"10.0.0.{_ % 200}", "10.0.0.1", 80, now=t)
        t += 0.0005

    print("\n[*] Demo complete. Alerts stored in alerts.db. Run --serve to view the dashboard.")


def run_live(iface):
    from scapy.all import sniff, IP, TCP
    conn = init_db()
    detector = Detector(conn)

    def handle(pkt):
        if IP in pkt and TCP in pkt:
            detector.process(pkt[IP].src, pkt[IP].dst, pkt[TCP].dport)

    print(f"[*] Live monitoring on {iface or 'default interface'}. Ctrl+C to stop.")
    try:
        sniff(iface=iface, filter="tcp", prn=handle, store=False)
    except PermissionError:
        print("[!] Permission denied opening raw socket. Run with sudo, or use --demo for a synthetic run.")
    except OSError as e:
        print(f"[!] Could not start capture: {e}. Run with sudo, or use --demo.")


def serve_dashboard():
    from flask import Flask, render_template_string

    app = Flask(__name__)

    TEMPLATE = """
    <!doctype html>
    <html>
    <head>
        <title>IDS Dashboard</title>
        <meta http-equiv="refresh" content="5">
        <style>
            body { font-family: monospace; background:#0d1117; color:#c9d1d9; padding:24px; }
            h1 { color:#58a6ff; }
            table { border-collapse: collapse; width:100%; }
            th, td { border:1px solid #30363d; padding:6px 10px; text-align:left; }
            th { background:#161b22; }
            .PORT_SCAN { color:#f0883e; }
            .BRUTE_FORCE { color:#f85149; }
            .SPIKE { color:#d29922; }
            .summary { margin-bottom: 16px; }
            .badge { display:inline-block; padding:2px 8px; border-radius:4px; margin-right:8px; background:#161b22; }
        </style>
    </head>
    <body>
        <h1>Intrusion Detection Dashboard</h1>
        <div class="summary">
            <span class="badge">Total alerts: {{ alerts|length }}</span>
            <span class="badge">Port scans: {{ counts.get('PORT_SCAN', 0) }}</span>
            <span class="badge">Brute force: {{ counts.get('BRUTE_FORCE', 0) }}</span>
            <span class="badge">Spikes: {{ counts.get('SPIKE', 0) }}</span>
        </div>
        <table>
            <tr><th>Time</th><th>Type</th><th>Source</th><th>Detail</th></tr>
            {% for a in alerts %}
            <tr class="{{ a[2] }}">
                <td>{{ a[1] }}</td><td>{{ a[2] }}</td><td>{{ a[3] }}</td><td>{{ a[4] }}</td>
            </tr>
            {% endfor %}
        </table>
    </body>
    </html>
    """

    @app.route("/")
    def index():
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 200").fetchall()
        counts = {}
        for r in conn.execute("SELECT alert_type, COUNT(*) FROM alerts GROUP BY alert_type"):
            counts[r[0]] = r[1]
        return render_template_string(TEMPLATE, alerts=rows, counts=counts)

    app.run(host="0.0.0.0", port=5001, debug=False)


def main():
    parser = argparse.ArgumentParser(description="Simple intrusion detection system.")
    parser.add_argument("--demo", action="store_true", help="Run synthetic attack demo and populate alerts.db")
    parser.add_argument("--serve", action="store_true", help="Launch the Flask alert dashboard")
    parser.add_argument("--iface", help="Interface for live capture (needs root)")
    args = parser.parse_args()

    if args.demo:
        run_demo()
    elif args.serve:
        serve_dashboard()
    else:
        run_live(args.iface)


if __name__ == "__main__":
    main()
