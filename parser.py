"""
parser.py
Wczytuje alerty z pliku JSON i normalizuje je do jednego,
spójnego formatu, z którego korzysta reszta narzędzia.
"""

import json
from datetime import datetime


def load_alerts(filepath):
    """Wczytuje listę alertów z pliku JSON."""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def normalize_alert(alert):
    """
    Sprowadza pojedynczy alert do wspólnej struktury.
    Dzięki temu reszta kodu nie musi znać oryginalnego formatu Wazuh/Sysmon.
    """
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {})

    return {
        "alert_id": alert.get("alert_id", "N/A"),
        "timestamp": alert.get("timestamp", ""),
        "severity": rule.get("level", 0),
        "description": rule.get("description", "No description"),
        "mitre": rule.get("mitre", []),
        "host": agent.get("name", "unknown"),
        "host_ip": agent.get("ip", ""),
        "user": data.get("user", ""),
        # zbieramy wszystkie pozostałe szczegóły do jednego słownika
        "details": {k: v for k, v in data.items() if k != "user"},
    }


def parse(filepath):
    """Wczytuje i normalizuje wszystkie alerty. Zwraca listę posortowaną po czasie."""
    raw_alerts = load_alerts(filepath)
    normalized = [normalize_alert(a) for a in raw_alerts]
    # sortujemy chronologicznie - kluczowe dla timeline w raporcie
    normalized.sort(key=lambda x: x["timestamp"])
    return normalized


if __name__ == "__main__":
    # szybki test parsera
    alerts = parse("sample_alerts/alerts.json")
    print(f"Wczytano {len(alerts)} alertow:\n")
    for a in alerts:
        print(f"  [{a['timestamp']}] lvl{a['severity']:>2} | {a['host']:<12} | {a['description']}")
