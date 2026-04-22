import json
from pathlib import Path

TRIVY_FILE = Path("trivy.json")
RISK_FILE = Path("risk.json")

WEIGHTS = {
    "CRITICAL": 1.0,
    "HIGH": 0.7,
    "MEDIUM": 0.4,
    "LOW": 0.1,
    "UNKNOWN": 0.05
}

def main():
    if not TRIVY_FILE.exists():
        result = {
            "risk": 0.0,
            "vuln_count": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "unknown": 0
        }
        RISK_FILE.write_text(json.dumps(result, indent=2))
        return

    data = json.loads(TRIVY_FILE.read_text(encoding="utf-8"))
    results = data.get("Results", [])

    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0
    }

    for result in results:
        for vuln in result.get("Vulnerabilities", []) or []:
            sev = (vuln.get("Severity") or "UNKNOWN").upper()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["UNKNOWN"] += 1

    vuln_count = sum(counts.values())

    raw_score = sum(counts[k] * WEIGHTS[k] for k in counts)

    risk = min(1.0, raw_score / 10.0)

    output = {
        "risk": round(risk, 4),
        "vuln_count": vuln_count,
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
        "unknown": counts["UNKNOWN"]
    }

    RISK_FILE.write_text(json.dumps(output, indent=2))
    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()