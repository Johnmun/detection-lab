# Detection Lab

A personal detection engineering repository containing Sigma-based detection rules validated against real attack simulation telemetry. Each rule is paired with a lab writeup documenting the technique, execution method, observed telemetry, and detection logic.

**Focus areas:** Credential Access · Privilege Escalation · Persistence · Defense Evasion  
**Platforms:** Windows · Linux (in progress)  
**Validation method:** Atomic Red Team simulation → Sysmon telemetry → Splunk analysis

---

## Lab Environment

| Component | Details |
|---|---|
| Victim Host | Windows 10 VM |
| Logging | Sysmon (process creation, registry, network) |
| Ingestion | Splunk Universal Forwarder → Splunk (Ubuntu indexer) |
| Attack Simulation | Atomic Red Team |
| Rule Format | Sigma (converted to SPL and KQL) |

---

## Detections

| Technique | MITRE ID | Platform | Sigma Rule | Writeup | Status |
|---|---|---|---|---|---|
| LSASS Memory Dump via Comsvcs (LotL) | T1003.001 | Windows | [🔗](rules/windows/credential_access/lsass_memory_dump_comsvcs.yml) | [🔗](writeups/2026-03_lsass-memory-dump_T1003-001.md) | ✅ Lab Validated |
| UAC Bypass via Fodhelper Registry Hijack | T1548.002 | Windows | [🔗](rules/windows/privilege_escalation/uac_bypass_fodhelper.yml) | Coming soon | ✅ Lab Validated |
| Persistence via Registry Run Keys | T1547.001 | Windows | Coming soon | Coming soon | 🔄 In Progress |

---

## Repository Structure
```
detection-lab/
├── rules/                  # Sigma detection rules
│   ├── windows/
│   │   ├── credential_access/
│   │   ├── persistence/
│   │   └── privilege_escalation/
│   ├── linux/
│   └── web/
├── output/                 # Auto-generated SPL and KQL conversions
│   ├── splunk/
│   └── sentinel/
├── writeups/               # Lab validation reports
│   └── assets/             # Screenshots and evidence
└── tests/
    └── samples/            # Sample log events for rule testing
```

---

## Detection Engineering Methodology

Each detection in this repository follows a consistent validation pipeline:

**1. Technique Research** — MITRE ATT&CK mapping, real-world threat actor usage, existing detection gaps.

**2. Attack Simulation** — Atomic Red Team execution against an isolated Windows VM with Sysmon instrumented logging.

**3. Telemetry Analysis** — Raw log review in Splunk to identify reliable behavioral indicators that distinguish malicious from benign activity.

**4. Sigma Rule Development** — Vendor-neutral rule authored in Sigma format targeting the highest-fidelity behavioral indicators observed in telemetry.

**5. Conversion & Validation** — Rule converted to SPL (Splunk) and KQL (Microsoft Sentinel) via pySigma. Detection confirmed to fire against sample telemetry.

**6. Documentation** — Full writeup published covering technique overview, lab setup, execution, observed telemetry, detection logic, and false positive analysis.

---

## About

Security analyst with a background in threat hunting, SIEM engineering, and detection development. SC-200 certified. Building toward detection-as-code practices across Splunk and Microsoft Sentinel environments.

📍 Miami, FL · [LinkedIn](https://www.linkedin.com/in/johnmun6)

---

*Rules are provided for defensive and educational purposes. All attack simulations were conducted in an isolated home lab environment.*