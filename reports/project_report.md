# Project Report — Cybersecurity Awareness & Threat Intelligence Dashboard

## Abstract
This project demonstrates a defensive threat-intelligence workflow using safe synthetic data. It validates IOCs, enriches context, separates risk from confidence, correlates observations, generates alerts, supports SOC-style investigation, and provides cybersecurity awareness education.

## Objectives
Collect, normalize, validate, score, correlate and visualize defensive intelligence while teaching users how to recognize common threats.

## Results
The local generator produces 2,000 synthetic records. The dashboard exposes threat statistics, severity/category charts, IOC search, threat details, alerts, vulnerability awareness, awareness modules and a 30-question quiz.

## Limitations
Synthetic data does not represent live operational threat intelligence. IOC matches can be stale or benign, feeds can disagree, and correlation does not prove attribution.

## Future Scope
Authorized STIX/TAXII feeds, SIEM/SOAR integration, CVE/KEV feeds, stronger deduplication, IOC expiration, improved confidence scoring, ATT&CK visualization, RBAC, CI/CD and centralized logging.
