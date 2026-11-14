"""
enrichment.py
Wzbogaca przetworzone alerty o dodatkowy kontekst:
- tlumaczy kody MITRE na czytelne nazwy i taktyki
- wyciaga IOC (IP, domeny, pliki) z alertow
- ocenia ogolny poziom zagrozenia calego incydentu
"""

import json
import ipaddress
from mitreattack.stix20 import MitreAttackData

def load_attack(filepath="data/enterprise-attack.json"):
    """Wczytuje baze MITRE ATT&CK i slownik nazw taktyk."""
    attack = MitreAttackData(filepath)
    tactic_names = {tac.x_mitre_shortname: tac.name for tac in attack.get_tactics()}
    return attack, tactic_names


def enrich_mitre(alerts, attack, tactic_names):
    techniques = {}
    for alert in alerts:
        for code in alert.get("mitre", []):
            if code in techniques:
                continue
            obj = attack.get_object_by_attack_id(code, "attack-pattern")
            if obj is None:
                techniques[code] = {"name": "Unknown technique", "tactics": []}
                continue
            tactics = [tactic_names[p.phase_name] for p in obj.kill_chain_phases]
            techniques[code] = {"name": obj.name, "tactics": tactics}
    return [
        {"code": code, "name": info["name"], "tactics": info["tactics"]}
        for code, info in sorted(techniques.items())
    ]


def extract_iocs(alerts):
    """
    Wyciaga wskazniki kompromitacji (IOC) z pol szczegolowych alertow.
    Grupuje po typie: IP, domeny, pliki, hashe.
    """
    iocs = {"ips": set(), "domains": set(), "files": set(), "hashes": set()}

    for alert in alerts:
        details = alert.get("details", {})
        for key, value in details.items():
            if not value:
                continue
            k = key.lower()
            if "ip" in k:
                if not ipaddress.ip_address(value).is_private:
                    iocs["ips"].add(value)
            elif "domain" in k:
                iocs["domains"].add(value)
            elif "file" in k:
                iocs["files"].add(value)
            elif "hash" in k or "md5" in k or "sha" in k:
                iocs["hashes"].add(value)

    # zamieniamy zbiory na posortowane listy (dla ladnego raportu)
    return {k: sorted(v) for k, v in iocs.items()}


def assess_severity(alerts):
    """
    Ocenia ogolny poziom zagrozenia incydentu na podstawie
    najwyzszego poziomu alertu (skala Wazuh 0-15).
    """
    if not alerts:
        return "Informational", 0

    max_level = max(a["severity"] for a in alerts)

    if max_level >= 13:
        rating = "Critical"
    elif max_level >= 10:
        rating = "High"
    elif max_level >= 7:
        rating = "Medium"
    elif max_level >= 4:
        rating = "Low"
    else:
        rating = "Informational"

    return rating, max_level


def get_affected_systems(alerts):
    """Zwraca liste unikalnych systemow i uzytkownikow dotknietych incydentem."""
    systems = {}
    for alert in alerts:
        host = alert["host"]
        if host not in systems:
            systems[host] = {"ip": alert["host_ip"], "users": set()}
        if alert["user"]:
            systems[host]["users"].add(alert["user"])
    # zbiory -> listy
    for host in systems:
        systems[host]["users"] = sorted(systems[host]["users"])
    return systems


if __name__ == "__main__":
    from parser import parse

    alerts = parse("sample_alerts/alerts.json")

    print("=== MITRE techniki ===")
    attack, tactic_names = load_attack()
    for t in enrich_mitre(alerts, attack, tactic_names):
        print(f"  {t['code']} - {t['name']} ({', '.join(t['tactics'])})")

    print("\n=== IOC ===")
    for typ, values in extract_iocs(alerts).items():
        if values:
            print(f"  {typ}: {', '.join(values)}")

    print("\n=== Severity ===")
    rating, level = assess_severity(alerts)
    print(f"  {rating} (max level {level})")

    print("\n=== Affected systems ===")
    for host, info in get_affected_systems(alerts).items():
        print(f"  {host} ({info['ip']}) - users: {', '.join(info['users'])}")
