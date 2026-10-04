# Cybersecurity Awareness & Threat Intelligence Dashboard

A defensive, offline-first SOC-style student project combining synthetic cyber threat intelligence, IOC analysis, risk/confidence scoring, correlation, alerts, vulnerability awareness, MITRE ATT&CK concepts, and security awareness training.

## Safety
All demo indicators are synthetic, reserved, fictional, or generated locally. The application performs database/static analysis only: it does not visit URLs, contact IPs/domains, execute files, exploit systems, or provide attack functionality.

## Features
- 2,000 synthetic threat records
- IP/domain/URL/hash/CVE validation
- IOC search and enrichment
- Separate 0–100 risk and confidence scores
- Severity classification: Informational/Low/Medium/High/Critical
- Threat correlation and alert generation
- Analyst notes and alert status workflow
- MITRE ATT&CK mapping only where justified by category context
- Synthetic vulnerability/CVE awareness
- SOC threat queue and threat details
- 15 awareness topics represented through expandable content
- 30-question security awareness quiz and educational score
- Executive cybersecurity summary
- SQLite persistence and Flask REST API

## Stack
Python, Flask, SQLite, Pandas-compatible CSV workflow, HTML, CSS, JavaScript, Chart.js.

## Run locally
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python data\generate_threat_data.py
python backend\app.py
```
Open `http://127.0.0.1:5000`.

## Testing
```powershell
pytest -v
```

## Architecture
Synthetic/Public Defensive Data → Ingestion → Normalization → IOC Validation → Enrichment → Risk + Confidence → Correlation → Threat DB / Alert Engine / ATT&CK Mapping → SOC Dashboard → Analyst. A parallel Awareness Center provides learning modules, quiz scoring and recommendations.

## Risk vs Confidence
Risk describes how concerning an item may be. Confidence describes the strength of the available evidence. High risk does not automatically mean confirmed compromise.

## Project limitation
This student implementation is an offline synthetic demonstration. Production deployment would require authenticated analyst functions, RBAC, rate limiting, stronger input/output sanitization, HTTPS, audit logging, live authorized feeds, and more extensive automated testing.

## Ethical disclaimer
This project is designed exclusively for defensive cybersecurity education, threat-intelligence analysis, and security awareness. It does not execute, deploy, or interact with malicious payloads or unauthorized systems.
