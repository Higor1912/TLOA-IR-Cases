# Incident Response Report — Case 001

**Case ID:** TLOA-IR-2026-01
**Date:** 2026-05-07
**Analyst:** Higor Silva
**Environment:** TLOA Lab (`tloa.local`)
**Severity:** High
**Status:** Closed

---

## 1. Executive Summary

On May 7, 2026, a persistence mechanism was identified on host `WIN10-TARGET` within the `tloa.local` lab environment. A registry Run key entry named `SecurityHealth` was found under `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` pointing to `calc.exe`, causing the Windows Calculator to launch automatically on every system startup. The entry name was chosen to impersonate a legitimate Windows Defender component, demonstrating a masquerading technique commonly used by threat actors to evade detection. The persistence was identified through manual registry enumeration via PowerShell after the anomalous behavior (calculator opening without user interaction) was observed. The malicious registry key was exported as forensic evidence and subsequently removed, confirming full eradication.

---

## 2. Incident Details

| Field | Details |
|---|---|
| **Detection Source** | Manual investigation — PowerShell registry enumeration |
| **Affected Host(s)** | `WIN10-TARGET (192.168.204.x)` |
| **Affected Account(s)** | `HKLM` scope — applies to all users on the host |
| **Attack Vector** | Registry Run key persistence (local execution) |
| **Initial Symptom** | Calculator (`calc.exe`) opening automatically on startup |
| **Initial Detection** | 2026-05-07 11:09 UTC-3 |
| **Containment Time** | 2026-05-07 11:18 UTC-3 |

---

## 3. Timeline

| Timestamp (UTC-3) | Event | Source |
|---|---|---|
| 2026-05-07 11:09 | Calculator (`calc.exe`) observed launching automatically without user interaction | Visual observation |
| 2026-05-07 11:10 | Wazuh SIEM reviewed — no specific alert for registry Run key modification | Wazuh Security Events |
| 2026-05-07 11:10 | T1078 logon events observed in Wazuh (Rule 60106) — multiple logon success events | Wazuh Rule 60106 |
| 2026-05-07 11:12 | PowerShell enumeration initiated — scheduled tasks queried for `calc.exe` reference | PowerShell / Analyst |
| 2026-05-07 11:12 | No scheduled task pointing to `calc.exe` found | PowerShell output |
| 2026-05-07 11:13 | Registry Run keys enumerated via `Get-ItemProperty` | PowerShell / Analyst |
| 2026-05-07 11:13 | Malicious entry identified: `SecurityHealth = calc.exe` under `HKLM\...\Run` | PowerShell output |
| 2026-05-07 11:17 | Registry key exported to `evidence-run-key.reg` for forensic preservation | PowerShell — `reg export` |
| 2026-05-07 11:18 | Malicious registry entry removed via `Remove-ItemProperty` | PowerShell / Analyst |
| 2026-05-07 11:18 | Containment confirmed — calculator no longer launches on startup | Visual verification |

---

## 4. ATT&CK Mapping

| Tactic | Technique | ID | Method Used |
|---|---|---|---|
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 | Registry entry `SecurityHealth = calc.exe` under `HKLM\...\Run` |
| Defense Evasion | Masquerading | T1036 | Entry named `SecurityHealth` to impersonate Windows Defender component |

> 🔗 [View on MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

---

## 5. Technical Analysis

### 5.1 Attack Description

A registry-based persistence mechanism was planted on the Windows 10 target host. The attacker (simulated) created a new value under the `HKLM` Run key, which instructs Windows to execute the specified binary automatically at system startup for all users.

The entry was deliberately named `SecurityHealth` — a name associated with the legitimate `SecurityHealthSystray.exe` process used by Windows Security Center — in order to blend in with expected system entries and avoid raising immediate suspicion during a casual review.

**Registry key modified:**
```
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

**Entry created:**
```
Name  : SecurityHealth
Value : calc.exe
```

This technique requires no elevated execution at trigger time — once the key exists under HKLM, the binary executes automatically on every boot before the user interacts with the system.

**PowerShell command used for discovery:**
```powershell
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
```

**PowerShell command used for eradication:**
```powershell
Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth"
```

**PowerShell command used for forensic export:**
```powershell
reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" C:\Users\higor\Desktop\evidence-run-key.reg
```

### 5.2 Evidence

**calc.exe launching automatically on startup:**
![Persistence symptom](./evidence/case-001-calc-persistence.png)

**PowerShell — scheduled task enumeration (no results for calc.exe):**
![Scheduled task enumeration](./evidence/case-001-scheduled-tasks-enum.png)

**Wazuh Security Events — alerts observed during the incident window:**
![Wazuh alerts](./evidence/case-001-wazuh-alerts.png)

**PowerShell — registry Run key showing malicious entry:**
![Registry Run key — SecurityHealth = calc.exe](./evidence/case-001-registry-runkey.png)

**Forensic export of Run key (raw .reg file):**
`./evidence/case-001-runkey-export.reg`

### 5.3 Artifacts

| Artifact Type | Value / Location |
|---|---|
| Registry Key | `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` |
| Registry Value Name | `SecurityHealth` |
| Registry Value Data | `calc.exe` |
| Binary | `calc.exe` (Windows Calculator — used as payload placeholder) |
| Forensic Export | `evidence/case-001-runkey-export.reg` |

---

## 6. Detection Analysis

### What Was Detected ✅

| Detection | Rule / Method | Confidence |
|---|---|---|
| Multiple logon success events at startup | Wazuh Rule 60106 (T1078) | Medium — expected behavior at boot, but volume warrants review |
| Critical SessionEnv notification event | Wazuh Rule 60776 (Level 7) | Medium — environmental noise, not directly linked to persistence |

### What Was NOT Detected ❌

| Gap | Reason | Recommendation |
|---|---|---|
| Registry Run key creation (`SecurityHealth = calc.exe`) | No Wazuh rule configured to monitor `HKLM\...\Run` modifications | Configure Sysmon EID 13 (Registry value set) and create Wazuh rule for Run key writes |
| Masquerading via legitimate-looking key name | No behavioral analysis or name-based heuristics in place | Implement allowlist of expected Run key entries and alert on unknown values |
| Payload execution at startup | `calc.exe` execution not flagged — not inherently malicious | Alert on unexpected processes spawned from Run key context |

> **Key takeaway:** The persistence was only discovered through manual investigation triggered by anomalous behavior. Automated detection did not catch the registry modification at time of creation. This represents a significant detection gap for T1547.001 in the current lab configuration.

---

## 7. Containment & Eradication

- [x] Identified malicious registry entry via PowerShell enumeration
- [x] Exported full Run key as forensic evidence (`evidence-run-key.reg`)
- [x] Removed malicious entry: `Remove-ItemProperty -Name "SecurityHealth"`
- [x] Confirmed `calc.exe` no longer launches automatically on startup
- [x] Reviewed scheduled tasks — no additional persistence found
- [x] Reviewed `HKCU\...\Run` — no additional malicious entries found

---

## 8. Root Cause Analysis

The persistence was successful because no monitoring was configured for registry Run key modifications on the Windows 10 target. Sysmon was active on the host but Event ID 13 (RegistryEvent — Value Set) was either not configured or not forwarded with a specific rule for `HKLM\...\Run` writes.

Additionally, the masquerading technique (naming the entry `SecurityHealth`) reduced the likelihood of detection during manual review, as the name closely resembles a legitimate Windows Security component. Without an established baseline of expected Run key entries, distinguishing malicious from legitimate values requires active investigation rather than automated alerting.

---

## 9. Lessons Learned

### Detection Improvements
- Configure Sysmon EID 13 to monitor writes to `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` and `HKCU\...\Run`
- Create a Wazuh rule to alert (Level 10+) on any new or modified Run key values
- Build a baseline of expected Run key entries and alert on deviations

### Hardening Recommendations
- Restrict write access to `HKLM\...\Run` to SYSTEM and Administrator only
- Enable Wazuh File Integrity Monitoring (FIM) on registry Run keys
- Periodically audit Run key entries as part of routine host hardening checks

### Lab Improvements
- Add Sysmon EID 13 rules to `sysmonconfig.xml` targeting Run key paths
- Test detection coverage by re-running this technique after rule updates
- Document expected Run key baseline for `WIN10-TARGET` for future comparison

---

## 10. References

- [MITRE ATT&CK T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)
- [MITRE ATT&CK T1036 — Masquerading](https://attack.mitre.org/techniques/T1036/)
- [Sysmon Event ID 13 — RegistryEvent (Value Set)](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90013)
- [Wazuh SIEM Documentation](https://documentation.wazuh.com/)
- [Microsoft — Run and RunOnce Registry Keys](https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys)

---

*Report generated as part of the TLOA Lab — Threat Lab Offensive Architecture*
*All activity performed in an isolated lab environment for educational purposes.*
