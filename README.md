
# SOC Report Generator
 
A small Python CLI that turns raw **Wazuh / Sysmon alerts (JSON)** into a ready-to-read **incident report in Markdown** — with a timeline, affected hosts and users, extracted IOCs, MITRE ATT&CK mapping and response recommendations.
 
I built it to automate the most repetitive part of an L1 analyst's job: going through a pile of alerts and turning them into a clear, consistent incident write-up that someone else can act on.
 
---
 
## Why
 
When several alerts fire for the same incident, an analyst usually has to:
 
1. sort them into a timeline,
2. figure out which hosts and accounts are involved,
3. pull out the indicators (IPs, domains, files, hashes),
4. look up what the MITRE technique IDs mean and which tactics they belong to,
5. write recommendations and a severity rating.
That's slow and easy to get inconsistent. This tool does the boring, mechanical part so the analyst can focus on the judgement calls.
 
---
 
## How it works
 
The pipeline has three stages — **parse → enrich → render**:
 
```
alerts.json ──► parser.py ──► enrichment.py ──► main.py + Jinja2 template ──► incident_report.md
               (normalize)    (MITRE, IOC,       (recommendations,
                               severity, hosts)   final report)
```
 
### 1. Parsing and normalizing — `parser.py`
The tool loads the JSON file with alerts and brings every alert to **one common structure** (ID, timestamp, severity, description, MITRE codes, host, host IP, user, and all remaining details).
Thanks to that, the rest of the code doesn't need to know the original Wazuh/Sysmon format — if the input format changes, only the parser has to be updated.
Finally, the alerts are **sorted by time**, which gives the report a correct timeline.
 
### 2. Enrichment — `enrichment.py`
- **MITRE ATT&CK mapping** — the tool loads the official MITRE ATT&CK dataset (STIX) using `mitreattack-python` and builds a dictionary of tactic names. Each technique ID from the alerts (e.g. `T1003.001`) is translated into its full name and **all** tactics it belongs to — one technique can map to several tactics (for example `T1053.005` → Execution, Persistence, Privilege Escalation). It also uses the current ATT&CK tactic names, e.g. *Stealth* and *Defense Impairment*.
- **IOC extraction** — indicators are pulled out of the alert details and grouped by type: **IP addresses, domains, files and hashes**. Private IP ranges (RFC 1918, e.g. `192.168.x.x`) are filtered out, so the report only lists external addresses that are worth blocking or checking in threat intel.
- **Severity assessment** — the incident gets an overall rating based on the highest Wazuh rule level (0–15 scale): *Informational, Low, Medium, High* or *Critical*.
- **Affected systems** — a list of unique hosts with their IPs and the user accounts seen on each of them.
### 3. Recommendations and report — `main.py`
Based on the tactics that were detected, the tool picks **response recommendations** (e.g. for *Credential Access* → force password resets and review authentication logs). They are listed **in kill-chain order** (Initial Access → … → Impact), so the report reads in the same order an attack progresses. A few general recommendations (preserve evidence, document actions) are always added.
 
Everything is then passed to a **Jinja2 template** (`templates/report_template.md`), and the final report is saved to the `output/` folder.
 
---
 
## Project structure
 
```
soc-report-generator/
├── main.py                    # entry point: CLI, recommendations, report rendering
├── parser.py                  # loading + normalizing alerts
├── enrichment.py              # MITRE mapping, IOC extraction, severity, affected systems
├── templates/
│   └── report_template.md     # Jinja2 template of the report
├── sample_alerts/
│   └── alerts.json            # example alerts to try the tool
├── data/
│   └── enterprise-attack.json # MITRE ATT&CK dataset (download separately, see below)
└── output/                    # generated reports land here
```
 
---
 
## Installation
 
Requires **Python 3.11+**. I use conda, but a normal virtual environment works too.
 
```bash
git clone https://github.com/XanDuri/soc-report-generator.git
cd soc-report-generator
 
conda create -n soc-report python=3.11
conda activate soc-report
pip install mitreattack-python jinja2
```
 
### Download the MITRE ATT&CK data
The ATT&CK dataset is large (~40 MB), so it's not stored in the repo. Download `enterprise-attack.json` from the official
[mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data) repository and put it in the `data/` folder:
 
```bash
mkdir -p data
curl -L -o data/enterprise-attack.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
```
 
(On Windows you can simply download the file in the browser and save it as `data/enterprise-attack.json`.)
 
---
 
## Usage
 
```bash
python main.py --input sample_alerts/alerts.json --output output/report.md --analyst "Lukasz M."
```
 
| Option | Short | Default | Description |
| --- | --- | --- | --- |
| `--input` | `-i` | `sample_alerts/alerts.json` | JSON file with alerts |
| `--output` | `-o` | `output/incident_report.md` | where to save the report |
| `--analyst` | `-a` | `Unassigned` | analyst name shown in the report |
 
You can also run the modules on their own to see intermediate results:
 
```bash
python parser.py       # prints the normalized, sorted alerts
python enrichment.py   # prints MITRE techniques, IOCs, severity and affected systems
```
 
### Input format
Each alert is a JSON object in a Wazuh-like format:
 
```json
{
  "alert_id": "A-001",
  "timestamp": "2026-11-10T14:02:11Z",
  "rule": {
    "level": 12,
    "description": "Possible credential dumping: access to lsass.exe",
    "mitre": ["T1003.001"]
  },
  "agent": { "name": "WS-01", "ip": "192.168.56.20" },
  "data": {
    "user": "jdoe",
    "src_ip": "203.0.113.45",
    "file": "C:\\Users\\Public\\dump.dmp",
    "sha256": "…"
  }
}
```
 
Any key in `data` containing `ip`, `domain`, `file` or `hash`/`md5`/`sha` is picked up as an IOC.
 
---
 
## Example output
 
<!-- TODO: paste a short real excerpt of output/report.md here (e.g. the summary, the MITRE table and recommendations) -->
 
---
 
## Limitations and roadmap
 
This is a learning project and I'm actively improving it. Next steps:
 
- [ ] Support **real Wazuh alerts** (nested structure, `+0100` timezones → parse timestamps with `datetime` instead of sorting strings)
- [ ] Safer IOC parsing — validate values before treating them as IPs (`try/except ValueError`) and match field names more precisely
- [ ] Show the **parent technique name** for sub-techniques (e.g. `T1003` → *OS Credential Dumping*)
- [ ] Cache the ATT&CK data — loading the full dataset takes a few seconds
- [ ] Export to HTML/PDF in addition to Markdown
---
 
## What I learned
 
- Normalizing data from different sources into one structure before processing it
- Working with the official **MITRE ATT&CK STIX data** instead of a hand-written mapping (and why one technique can belong to several tactics)
- Filtering IOCs so a report contains only actionable indicators
- Generating documents from templates with **Jinja2**
- Writing a simple CLI with **argparse**
---
 
## Author
 
**Łukasz Moszczyński** — Junior SOC / Security Analyst
[LinkedIn](https://linkedin.com/in/lukasz-moszczynski-soc) · [TryHackMe](https://tryhackme.com/p/XanDuri) · [GitHub](https://github.com/XanDuri)
 
## License
 
MIT
 
