# 🛡️ Security Incident Report

**Report ID:** {{ report_id }}
**Generated:** {{ generated_at }}
**Severity:** {{ severity_rating }} (max alert level {{ severity_level }}/15)
**Analyst:** {{ analyst }}

---

## 1. Executive Summary

An incident involving **{{ alert_count }} correlated alerts** was detected across
**{{ system_count }} system(s)**. The activity has been classified as
**{{ severity_rating }}** severity. The observed behavior is consistent with a
multi-stage attack spanning the following MITRE ATT&CK tactics:
{{ tactics_summary }}.

Immediate review and containment are recommended.

---

## 2. Timeline of Events

| Time | Host | Lvl | Description |
|------|------|-----|-------------|
{% for a in alerts -%}
| {{ a.timestamp }} | {{ a.host }} | {{ a.severity }} | {{ a.description }} |
{% endfor %}

---

## 3. Affected Systems

{% for host, info in systems.items() -%}
- **{{ host }}** ({{ info.ip }}) — user(s): {{ info.users | join(", ") if info.users else "N/A" }}
{% endfor %}

---

## 4. Indicators of Compromise (IOCs)

{% if iocs.ips %}**IP Addresses:**
{% for ip in iocs.ips %}- `{{ ip }}`
{% endfor %}{% endif %}

{% if iocs.domains %}**Domains:**
{% for d in iocs.domains %}- `{{ d }}`
{% endfor %}{% endif %}

{% if iocs.files %}**Files:**
{% for f in iocs.files %}- `{{ f }}`
{% endfor %}{% endif %}

{% if iocs.hashes %}**Hashes:**
{% for h in iocs.hashes %}- `{{ h }}`
{% endfor %}{% endif %}

---

## 5. MITRE ATT&CK Mapping

| Technique | Name | Tactic |
|-----------|------|--------|
{% for t in techniques -%}
| {{ t.code }} | {{ t.name }} | {{ t.tactics | join(", ") }} |
{% endfor %}

---

## 6. Recommendations

{% for rec in recommendations -%}
- {{ rec }}
{% endfor %}

---

*This report was generated automatically by the SOC Report Generator.*
