# Intrusion Detection System

Detects port scans (many distinct dst ports from one src in a
window), brute force (many hits to the same dst port from one src), and
traffic spikes. Alerts are logged to SQLite; a Flask dashboard visualizes
them.

## Legal / ethical notice

This is a defensive tool meant to be run on your own machine/network.
## Setup

```bash
pip install -r requirements.txt
```

## Usage

```bash
python3 ids.py --demo
python3 ids.py --serve       # dashboard on :5001
sudo python3 ids.py --iface eth0   # live capture, needs root
```

## Tested

Synthetic demo correctly fired all three alert types and the
dashboard rendered them, confirmed on this machine (including a full
SQLite write/read round trip -- the sandbox build had hit disk I/O errors
on its mounted outputs folder, but SQLite writes work cleanly here). Live
`--iface` capture with `sudo` still needs to be run in a real terminal with
an interactive password prompt -- see repo issue / do this yourself with
`sudo python3 ids.py --iface <your-iface>`.
