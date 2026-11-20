"""
SIEM-Lite | Test Script
Validates log parsing and threat detection engine rules.
"""

from src.parser.log_parser import load_all_logs
from src.detector.detection_engine import DetectionEngine


def main():
    logs = load_all_logs('logs/samples')
    engine = DetectionEngine()
    alerts = engine.run(logs)

    print("=" * 60)
    print("  SIEM-Lite — Analysis Summary")
    print("=" * 60)
    print(f"Auth events:     {len(logs['auth'])}")
    print(f"Firewall events: {len(logs['firewall'])}")
    print(f"Alerts detected: {len(alerts)}")
    print("-" * 60)
    print(f"{'SEVERITY':<10} {'ALERT TYPE':<25} | {'SOURCE IP':<15} | {'MITRE ID'}")
    print("-" * 60)
    for a in alerts:
        print(f"[{a.severity:<8}] {a.alert_type:<25} | {a.source_ip:<15} | {a.mitre_id}")
    print("=" * 60)


if __name__ == "__main__":
    main()
