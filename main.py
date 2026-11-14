"""
main.py
Glowny punkt wejscia narzedzia SOC Report Generator.

Uzycie:
    python3 main.py --input sample_alerts/alerts.json --output output/report.md --analyst "Lukasz M."
"""

import argparse
from datetime import datetime, timezone
from jinja2 import Environment, FileSystemLoader

from parser import parse
from enrichment import (
    load_mitre_map,
    enrich_mitre,
    extract_iocs,
    assess_severity,
    get_affected_systems,
)


# Rekomendacje generowane na podstawie wykrytych taktyk MITRE.
# To jest miejsce ktore mozesz rozbudowac - im wiecej regul, tym madrzejszy raport.
RECOMMENDATION_RULES = {
    "Initial Access": "Isolate the affected host and review the delivery vector (email/attachment).",
    "Execution": "Terminate malicious processes and collect the full command line for analysis.",
    "Command and Control": "Block the identified C2 domain/IP at the firewall and proxy.",
    "Persistence": "Remove the persistence mechanism (scheduled task/registry) and verify it does not recreate.",
    "Credential Access": "Force password reset for affected accounts and review authentication logs.",
    "Exfiltration": "Assess what data may have been exfiltrated and notify relevant stakeholders.",
}

DEFAULT_RECOMMENDATIONS = [
    "Preserve evidence (memory, logs) before remediation for potential forensic analysis.",
    "Document all response actions in the incident tracking system.",
]


def build_recommendations(techniques):
    """Buduje liste rekomendacji na podstawie wykrytych taktyk."""
    tactics = {t["tactic"] for t in techniques}
    recs = [RECOMMENDATION_RULES[t] for t in RECOMMENDATION_RULES if t in tactics]
    return recs + DEFAULT_RECOMMENDATIONS


def generate_report(input_file, output_file, analyst):
    """Glowna funkcja - wczytuje, wzbogaca i renderuje raport."""
    # 1. Wczytaj i sparsuj alerty
    alerts = parse(input_file)
    if not alerts:
        print("[!] Brak alertow w pliku wejsciowym.")
        return

    # 2. Wzbogac dane
    mitre_map = load_mitre_map()
    techniques = enrich_mitre(alerts, mitre_map)
    iocs = extract_iocs(alerts)
    severity_rating, severity_level = assess_severity(alerts)
    systems = get_affected_systems(alerts)

    # 3. Zbuduj kontekst dla szablonu
    tactics = sorted({t["tactic"] for t in techniques})
    context = {
        "report_id": "IR-" + datetime.now().strftime("%Y%m%d-%H%M%S"),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "analyst": analyst,
        "alert_count": len(alerts),
        "system_count": len(systems),
        "severity_rating": severity_rating,
        "severity_level": severity_level,
        "tactics_summary": ", ".join(tactics),
        "alerts": alerts,
        "systems": systems,
        "iocs": iocs,
        "techniques": techniques,
        "recommendations": build_recommendations(techniques),
    }

    # 4. Renderuj szablon
    env = Environment(loader=FileSystemLoader("templates"), trim_blocks=True, lstrip_blocks=True)
    template = env.get_template("report_template.md")
    report = template.render(context)

    # 5. Zapisz raport
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"[+] Raport wygenerowany: {output_file}")
    print(f"    Alertow: {len(alerts)} | Severity: {severity_rating} | Systemow: {len(systems)}")


def main():
    p = argparse.ArgumentParser(description="SOC Report Generator - automatyczny raport z alertow")
    p.add_argument("--input", "-i", default="sample_alerts/alerts.json", help="Plik JSON z alertami")
    p.add_argument("--output", "-o", default="output/incident_report.md", help="Sciezka raportu wyjsciowego")
    p.add_argument("--analyst", "-a", default="Unassigned", help="Imie analityka")
    args = p.parse_args()

    generate_report(args.input, args.output, args.analyst)


if __name__ == "__main__":
    main()
