# TLOA IR Cases — Incident Response Documentation

This repository documents simulated incident response investigations conducted within the **TLOA Lab (Threat Lab Offensive Architecture)** — a personal Active Directory home lab built for adversary emulation and detection engineering.

Each case follows a real-world IR workflow: an attack is executed against the lab environment, Wazuh SIEM and Sysmon capture the activity, and the analyst (me) responds as if it were a live incident — triaging alerts, building a timeline, mapping TTPs to MITRE ATT&CK, and producing a formal IR report.

> All activity was performed in an isolated lab environment for educational purposes only.

---

## Lab Environment

| Component | Details |
|---|---|
| **Domain** | `tloa.local` |
| **DC** | Windows Server 2025 — `DC01` |
| **Target** | Windows 10 Pro — Sysmon + Wazuh Agent |
| **Attacker** | Kali Linux |
| **SIEM** | Wazuh 4.7.5 (Ubuntu Server 24.04) |
| **Network** | VMware Host-Only — `192.168.204.x` |

---

## Repository Structure

```
TLOA-IR-Cases/
├── README.md
├── case-001/
│   ├── IR-REPORT.md
│   └── evidence/
│       ├── wazuh-alert.png
│       └── sysmon-event.png
├── case-002/
│   ├── IR-REPORT.md
│   └── evidence/
└── case-003/
    ├── IR-REPORT.md
    └── evidence/
```

---

## Cases

| Case | TTPs | Tactic | Status |
|---|---|---|---|
| [Case 001](./case-001/IR-REPORT.md) | T1003.001 | Credential Access | 🔵 Planned |
| [Case 002](./case-002/IR-REPORT.md) | T1548.002 + T1053.005 | Privilege Escalation + Persistence | 🔵 Planned |
| [Case 003](./case-003/IR-REPORT.md) | T1046 + T1112 | Discovery + Defense Evasion | 🔵 Planned |

---

## IR Workflow

Every case in this repository follows the same structured workflow, divided into four phases:

---

### Phase 1 — Attack Execution

The attack is executed from the Kali Linux attacker machine against the Windows 10 target or the DC01, simulating a threat actor operating inside the network.

**What happens in this phase:**
- The technique is executed using tools relevant to real-world threat actors (Mimikatz, Atomic Red Team, native Windows binaries, etc.)
- The goal is not stealth — the focus is on generating real, observable telemetry
- Screenshots of the attacker's terminal are saved as evidence

**Output:** Raw attack activity captured by Sysmon on the target host.

---

### Phase 2 — Detection & Triage

Switching roles to analyst, the Wazuh SIEM dashboard is reviewed to identify what was detected and what was missed.

**What happens in this phase:**
- Review Wazuh alerts triggered by the attack
- Identify which Sysmon Event IDs fired (e.g. EID 1 for process creation, EID 10 for process access, EID 13 for registry modification)
- Determine the severity and scope of the alert
- Ask: *"If this were a real environment, would the SOC have caught this?"*

**Output:** List of detected events with rule IDs, timestamps, and confidence level.

---

### Phase 3 — Investigation & Timeline

With the alerts identified, a full investigation is conducted to reconstruct exactly what happened and in what order.

**What happens in this phase:**
- Correlate Wazuh alerts with raw Sysmon logs
- Build a chronological timeline of events with real timestamps
- Identify affected hosts, accounts, processes, registry keys, and network connections
- Map every observed behavior to a MITRE ATT&CK technique
- Document forensic artifacts (files, processes, registry modifications, network IOCs)
- Identify detection gaps — techniques or steps that generated no alert

**Output:** Complete timeline + ATT&CK mapping + artifact list.

---

### Phase 4 — Reporting & Lessons Learned

The full IR report is written in markdown, structured for a professional audience.

**What happens in this phase:**
- Write the executive summary (non-technical)
- Document the full technical analysis with evidence screenshots
- Clearly separate what was detected from what was not detected
- Define containment and eradication steps
- Write actionable hardening and detection improvement recommendations
- Reflect on lab improvements (new rules, new tools, coverage gaps)

**Output:** Final `IR-REPORT.md` committed to the case folder with evidence screenshots.

---

## Relationship to Other TLOA Projects

This repository is part of a broader portfolio built around the TLOA framework:

| Repository | Description |
|---|---|
| [TLOA Lab](https://github.com/[username]/TLOA) | AD home lab setup — infrastructure, configuration, and initial TTP execution |
| **TLOA IR Cases** | Incident response documentation based on TLOA attack scenarios ← you are here |
| TLOA Red Team *(planned)* | Structured adversary emulation campaigns building on lab findings |
| [Threat-Intel-Reports](https://github.com/[username]/Threat-Intel-Reports) | Weekly CTI reports tracking real-world threat actors |
| [Bash-Log-Threat-Analyzer](https://github.com/[username]/Bash-Log-Threat-Analyzer) | Bash-based log analysis tool for threat detection |

> The TLOA IR Cases sit at the intersection of offensive and defensive — attacks executed in the lab become the incidents investigated here, creating a complete attack-defend-learn cycle.

---

## Skills Demonstrated

- Incident response workflow (triage → investigation → containment → reporting)
- SIEM alert analysis (Wazuh)
- Endpoint telemetry analysis (Sysmon)
- MITRE ATT&CK mapping from real observed behavior
- Detection gap analysis
- Formal IR report writing
- Active Directory attack surface understanding

---

*Part of the TLOA — Threat Lab Offensive Architecture*  
*Built by Higor [Last Name] | [LinkedIn] | [GitHub]*
