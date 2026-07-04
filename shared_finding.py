"""Map ids.py's alerts onto the ecosystem-wide shared finding schema.

Zero new runtime dependency. This is a streaming tool (like packet-sniffer),
so findings are appended as alerts fire, not written once at the end.

Schema: ../finding-schema/schema/finding.schema.json
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

SOURCE = "intrusion-detection-system"

# alert_type -> shared-schema severity/title/MITRE mapping. SPIKE is left
# without a MITRE mapping on purpose -- a raw traffic spike alone doesn't
# confirm a specific attacker technique (could be DoS, could be a burst of
# legitimate traffic), so forcing one would be a weak, dishonest fit.
_ALERT_META = {
    "PORT_SCAN": {
        "severity": "medium",
        "title": "Port scan detected",
        "mitre_attack": ["T1046"],  # Network Service Discovery
    },
    "BRUTE_FORCE": {
        "severity": "high",
        "title": "Brute-force attempt detected",
        "mitre_attack": ["T1110"],  # Brute Force
    },
    "SPIKE": {
        "severity": "medium",
        "title": "Traffic spike detected",
        "mitre_attack": [],
    },
}


def to_shared_finding(alert_type: str, src: str | None, detail: str) -> dict:
    meta = _ALERT_META[alert_type]
    return {
        "id": str(uuid.uuid4()),
        "source": SOURCE,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": meta["severity"],
        "category": "intrusion",
        "title": meta["title"],
        "description": detail,
        "resource": src,
        "mitre_attack": meta["mitre_attack"],
        "owasp": [],
        "remediation": None,
        "raw": {"alert_type": alert_type},
    }


def reset_findings_file(path: str | Path) -> None:
    """Start a fresh findings.jsonl for this run."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("", encoding="utf-8")


def append_shared_finding(alert_type: str, src: str | None, detail: str, path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(to_shared_finding(alert_type, src, detail)))
        f.write("\n")
