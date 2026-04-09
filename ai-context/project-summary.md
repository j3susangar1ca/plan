# Project Summary — CIRASM Framework (AI Context)

## Document Metadata

| Field       | Value                                       |
| ----------- | ------------------------------------------- |
| **Version** | 2.1.0                                       |
| **Updated** | 2026-04-09                                  |
| **Owner**   | Security Research Division                  |
| **Status**  | Active — Research Phase                     |
| **License** | CC-BY-SA-4.0                                |
| **Entry**   | `ai-context/project-summary.md` (this file) |

---

## 1. Project Identity

**CIRASM** — _Critical Infrastructure Resilience & Advanced System Modeling_

A **Formalized Adversary Emulation Environment** designed for computational study of critical infrastructure resilience. Unlike traditional penetration testing frameworks, CIRASM employs a deterministic approach grounded in **Symbolic Logic** and **Discrete Mathematics** to model security states, eliminating ambiguity in defensive posture evaluation.

### 1.1 Purpose

| Objective                     | Description                                                                                  |
| ----------------------------- | -------------------------------------------------------------------------------------------- |
| **Formal Verification**       | Mathematical modeling of security boundaries and detection of illegitimate access paths      |
| **Advanced Threat Emulation** | Simulation of state-level adversary behavior through low-level system primitives (sandboxed) |
| **Resilience Engineering**    | Stochastic quantification of risk, degradation curves, and MTTR under systemic compromise    |
| **Standards Alignment**       | Full traceability to ISO/IEC 27001, IEC 62443, NIST CSF 2.0, and MITRE ATT&CK®               |

### 1.2 Scope Boundaries

| Dimension       | In Scope                                                                           | Out of Scope                                           |
| --------------- | ---------------------------------------------------------------------------------- | ------------------------------------------------------ |
| **Domain**      | Computational resilience modeling, formal verification, adversary emulation theory | Operational exploitation, offensive tooling deployment |
| **Abstraction** | Symbolic representations, mathematical models, simulated environments              | Real-world target systems, production infrastructure   |
| **Audience**    | Security researchers, academic institutions, infrastructure engineers              | Untrained operators, unauthorized third parties        |
| **Output**      | Formal proofs, risk models, resilience metrics, defensive strategies               | Weaponized artifacts, functional exploit code          |

---

## 2. Target Summary

| Attribute          | Value                                 |
| ------------------ | ------------------------------------- |
| Organization       | Corporativo Global de Infraestructura |
| Primary Domain     | `corp-infra.local`                    |
| Primary Host       | 201.131.132.131                       |
| IP Range           | 201.131.132.0/24                      |
| Primary Zone       | Z01-DMZ                               |
| Total Zones        | 10                                    |
| Total CVEs Tracked | 9                                     |
| Classification     | CONFIDENTIAL — Theoretical Simulation |

### 2.1 Network Zones

| Zone ID | Designation            | Risk Level   | Host Count | Critical Finding                                      |
| ------- | ---------------------- | ------------ | ---------- | ----------------------------------------------------- |
| Z01     | DMZ — External Servers | **CRITICAL** | 5          | Apache 2.4.38 / PHP 7.1.26 / OpenSSL 1.0.2q — all EOL |
| Z02     | Internal Servers       | **CRITICAL** | 10         | AD exposed, SMB 37 shares unaudited, RDP open         |
| Z03     | Corporate Workstations | MEDIUM       | 83         | Unencrypted VoIP/WebRTC, unidentified OUIs            |
| Z04     | Corporate WiFi         | **HIGH**     | 8          | WPA2-Personal shared key, LDAP → DC, AJP13 exposed    |
| Z05     | Virtual Networks       | MEDIUM       | 0          | Docker on WiFi, ICS unsegmented                       |
| Z06     | External / ISP         | LOW          | 0          | Outside direct control                                |
| Z07     | Monitoring             | MEDIUM       | 0          | ICMP TTL=255, potential leakage                       |
| Z08     | Subnet 10.2.4.0/24     | MEDIUM       | 0          | Unknown purpose, no host inventory                    |
| Z09     | DMZ OPD — IoT/Cameras  | **HIGH**     | 0          | Ubiquiti IoT devices, surveillance cameras            |
| Z10     | Docker Network         | **HIGH**     | 0          | Docker containers on WiFi without segmentation        |

### 2.2 Critical Hosts

| IP Address      | Zone    | Services                                | OS/Stack                                    | Risk         |
| --------------- | ------- | --------------------------------------- | ------------------------------------------- | ------------ |
| 201.131.132.131 | Z01-DMZ | HTTP(80), HTTPS(443), IKE(500/UDP)      | Apache 2.4.38 / PHP 7.1.26 / OpenSSL 1.0.2q | **CRITICAL** |
| 201.131.132.7   | Z01-DMZ | HTTP(80/IIS 7.5), DNS(53), NETIS(53413) | Windows Server 2008 R2                      | **HIGH**     |
| 10.2.1.1        | Z02     | Gateway                                 | —                                           | Pivot point  |
| 10.2.1.x (×11)  | Z02     | SMB/RDP/AD                              | Windows                                     | **CRITICAL** |
| 10.254.0.0/16   | Z04     | —                                       | —                                           | **HIGH**     |

---

## 3. Risk Assessment

### 3.1 Vulnerability Distribution

```
┌─────────────────────────────────────────────────────────────────┐
│                    VULNERABILITY DISTRIBUTION                    │
├─────────────────────────────────────────────────────────────────┤
│ Critical (CVSS ≥ 9.0):  ████████████████████████  3            │
│   CVE-2019-11043, CVE-2019-0211, CVE-2021-21703                │
│                                                                 │
│ High     (CVSS 7.0–8.9): ████████████████████      3            │
│   CVE-2021-4034, CVE-2016-1240, CVE-2019-10081                 │
│                                                                 │
│ Medium   (CVSS 4.0–6.9): ████████████              3            │
│   CVE-2019-1547, CVE-2019-1559, CVE-2019-1563                  │
│                                                                 │
│ Informational:           ████                      1            │
│   CVE-2014-9016                                                 │
├─────────────────────────────────────────────────────────────────┤
│ TOTAL: 9 vulnerabilities  |  Critical: 4  |  High: 5           │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 CVE Priority Matrix

| Priority | CVE ID         | Type            | Component              | CVSS v3 | Reliability | Prerequisite                      |
| -------- | -------------- | --------------- | ---------------------- | ------- | ----------- | --------------------------------- |
| **P0**   | CVE-2021-4034  | LPE             | Polkit 0.105 (pkexec)  | 7.8     | 100%        | Local shell                       |
| **P0**   | CVE-2019-11043 | RCE             | PHP 7.1.26 (PHP-FPM)   | 9.8     | High        | Network access to PHP-FPM         |
| **P1**   | CVE-2019-0211  | LPE             | Apache 2.4.38 (MPM)    | 9.8     | 87–95%      | www-data shell + graceful restart |
| **P1**   | CVE-2021-21703 | RCE/LPE         | PHP 7.x (openssl_seal) | 9.8     | High        | PHP with OpenSSL extension        |
| **P2**   | CVE-2016-1240  | LPE             | Tomcat (Debian apt)    | 7.8     | High        | Local shell + logrotate trigger   |
| **P2**   | CVE-2019-10081 | DoS             | Apache mod_http2       | 7.5     | —           | Network access                    |
| **P3**   | CVE-2019-1559  | Info Disclosure | OpenSSL 1.0.2q         | 5.9     | —           | SSLv3 enabled                     |
| **P3**   | CVE-2019-1547  | Side-Channel    | OpenSSL ECDSA          | 5.3     | —           | Repeated signing                  |
| **P3**   | CVE-2019-1563  | Cache Timing    | OpenSSL AES-NI         | 5.3     | —           | Co-located VM                     |

### 3.3 Vulnerable Software Stack

| Component    | Version | Status  | CVEs                                        |
| ------------ | ------- | ------- | ------------------------------------------- |
| Apache HTTPD | 2.4.38  | 🔴 EOL  | CVE-2019-0211, CVE-2019-10081               |
| PHP          | 7.1.26  | 🔴 EOL  | CVE-2019-11043, CVE-2021-21703              |
| OpenSSL      | 1.0.2q  | 🔴 EOL  | CVE-2019-1547, CVE-2019-1559, CVE-2019-1563 |
| Polkit       | 0.105   | 🟠 Vuln | CVE-2021-4034                               |
| Tomcat       | 7.0.x   | 🟠 Vuln | CVE-2016-1240                               |

---

## 4. Attack Architecture

### 4.1 Exploitation Chains

#### Chain A — PHP-FPM RCE → CARPE DIEM / PwnKit (Web-to-Root)

```
┌─────────────────────┐     ┌──────────────────────┐     ┌─────────────────────┐     ┌──────────────┐
│ CVE-2019-11043      │────▶│ www-data shell       │────▶│ CVE-2019-0211       │────▶│ root access  │
│ PHP-FPM RCE         │     │ (remote)             │     │ Apache LPE          │     │              │
│ Network → Remote    │     │                      │     │ Shared mem hijack   │     │              │
└─────────────────────┘     └──────────────────────┘     └─────────────────────┘     └──────────────┘
        OR                          │
┌─────────────────────┐             │
│ CVE-2021-21703      │─────────────┘
│ PHP openssl_seal()  │
│ UAF → JOP chain     │
└─────────────────────┘
```

#### Chain B — PwnKit Direct (Any Shell → Root)

```
┌─────────────────────┐     ┌──────────────────────┐
│ Local shell access  │────▶│ CVE-2021-4034        │
│ (any user)          │     │ PwnKit — GCONV_PATH  │
│                     │     │ injection via pkexec  │
└─────────────────────┘     └──────────┬───────────┘
                                       ▼
                              ┌────────────────┐
                              │  root access   │
                              │  Reliability:  │
                              │  100%          │
                              └────────────────┘
```

#### Chain C — Network-Level (VPN / DNS / IoT)

```
┌─────────────────────┐     ┌──────────────────────┐     ┌──────────────────────┐
│ IKEv2 Enumeration   │     │ DNS Exfiltration     │     │ CVE-2014-9016        │
│ UDP 500             │     │ UDP 53 forwarding    │     │ NETIS Backdoor       │
│ Aggressive mode     │     │ Version disclosure   │     │ UDP 53413            │
└─────────────────────┘     └──────────────────────┘     └──────────────────────┘
```

### 4.2 Escalation Topology

```
                         Network Access (Z01-DMZ)
                                 │
               ┌─────────────────┼─────────────────────┐
               │                 │                     │
        CVE-2019-1547     CVE-2019-11043        CVE-2014-9016
        CVE-2019-1559      (PHP-FPM RCE)        (NETIS Backdoor)
        CVE-2019-1563           │                     │
               │                │                     │
      Crypto Compromise   www-data Shell        IoT Device Access
                                │
                    ┌───────────┴───────────┐
                    │                       │
              CVE-2019-0211          CVE-2021-4034
              (CARPE DIEM)           (PwnKit)
                    │                       │
                    └───────────┬───────────┘
                                │
                           ROOT ACCESS
                                │
                    ┌───────────┴───────────┐
                    │           │           │
               Z02 Pivot   Z04 Pivot   Z10 Pivot
               (SMB/AD)    (WPA2/LDAP) (Docker)
```

### 4.3 Lateral Movement Paths

| Source         | Target Zone | Vector                                  | Goal                     |
| -------------- | ----------- | --------------------------------------- | ------------------------ |
| Z01-DMZ (root) | Z02         | SMB relay / Pass-the-Hash               | AD domain compromise     |
| Z01-DMZ (root) | Z04         | WPA2 cracking → LDAP bind               | Domain Controller access |
| Z01-DMZ (root) | Z10         | Container escape via misconfigured vols | Host-level access        |
| Z01-DMZ (root) | Z09         | Ubiquiti IoT enumeration                | Surveillance access      |
| Z01-DMZ (root) | Z07         | Monitoring subversion (ICMP analysis)   | Blind detection layer    |

---

## 5. Standards & Compliance Alignment

| Standard           | Domain                | Framework Role                                  |
| ------------------ | --------------------- | ----------------------------------------------- |
| ISO/IEC 27001:2022 | InfoSec Management    | Risk-based state controls, audit trails         |
| IEC 62443          | ICS / OT Security     | Defense-in-depth for OT environments            |
| NIST CSF 2.0       | Cyber Risk Management | Identify → Protect → Detect → Respond → Recover |
| NIST SP 800-53 r5  | Security Controls     | Control family mapping for simulations          |
| NIST SP 800-115    | Technical Testing     | Vulnerability identification methodology        |
| MITRE ATT&CK® v14  | Adversary Behavior    | Tactic/technique mapping to primitives          |

---

## 6. MITRE ATT&CK® Coverage

| Tactic               | ID     | Techniques Used                                          | Status |
| -------------------- | ------ | -------------------------------------------------------- | ------ |
| Reconnaissance       | TA0043 | T1595, T1595.002, T1590.001, T1590.002, T1592            | ✅     |
| Initial Access       | TA0001 | T1190, T1078, T1133                                      | ✅     |
| Execution            | TA0002 | T1059 (implicit via shell)                               | ✅     |
| Persistence          | TA0003 | T1098.004, T1053.003, T1543                              | ✅     |
| Privilege Escalation | TA0004 | T1068, T1548                                             | ✅     |
| Defense Evasion      | TA0005 | T1070.002, T1070.004, T1070.006, T1014, T1562.001, T1620 | ✅     |
| Lateral Movement     | TA0008 | T1021.001, T1021.002, T1550                              | ✅     |
| Command and Control  | TA0011 | T1071, T1572                                             | ✅     |
| Credential Access    | TA0006 | —                                                        | ⬜     |
| Discovery            | TA0007 | Partial (Phase 1 recon)                                  | 🔶     |
| Collection           | TA0009 | Implicit via data exfil paths                            | 🔶     |
| Exfiltration         | TA0010 | Referenced but not detailed                              | ⬜     |
| Impact               | TA0040 | Out of scope                                             | ⬜     |

---

## 7. Execution Model Overview

The framework executes across **5 phases** with clear go/no-go gates:

| Phase                         | Objective                   | Duration | Risk    | Language Primary |
| ----------------------------- | --------------------------- | -------- | ------- | ---------------- |
| 1. External Reconnaissance    | Map attack surface          | 2–6h     | LOW     | Rust             |
| 2. Initial Access             | Remote code execution       | 1–4h     | MEDIUM  | Rust + C/ASM     |
| 3. Privilege Escalation       | www-data → root             | <1m – 4h | LOW-MED | C + ASM          |
| 4. Persistence & Lateral Move | Durable access, zone expand | 4–12h    | HIGH    | Rust + Go        |
| 5. Anti-Forensics & Evasion   | Evidence elimination        | 1–3h     | MEDIUM  | Rust + ASM       |

> **Total estimated duration**: 12–25 hours  
> **Full details**: See [`ai-context/strategic-execution.md`](strategic-execution.md)

---

## 8. Repository Structure

```
plan/
├── README.md                          # Framework overview & standards
├── manifest.json                      # Project manifest & risk summary
├── .gitignore                         # Build/editor/OS exclusions
│
├── ai-context/                        # ← You are here (AI consumption layer)
│   ├── project-summary.md             #   This file — high-level overview
│   ├── strategic-execution.md         #   Full execution plan & language matrix
│   ├── exploitation-graph.md          #   Attack path dependency graph
│   └── attack-surface.json            #   Machine-readable attack surface model
│
├── schemas/                           # JSON Schemas for Data Validation
│   ├── cve-advisory.schema.json       #   CVE advisory document schema
│   ├── host-scan.schema.json          #   Host scan result schema
│   └── port-scan.schema.json          #   Port scan result schema
│
├── infrastructure/                    # Scanned Infrastructure Data
│   ├── zones/                         #   Network zone definitions (Z01–Z10)
│   │   ├── Z01-DMZ/                   #   Demilitarized zone
│   │   ├── Z02-Internal-Servers/      #   Internal server segment
│   │   ├── Z03-Internal-Workstations/ #   Workstation segment
│   │   ├── Z04-Internal-WiFi/         #   Wireless network segment
│   │   ├── Z05-Virtual/               #   Virtualization segment
│   │   ├── Z06-External/              #   External-facing segment
│   │   ├── Z07-Monitoring/            #   Monitoring & SIEM segment
│   │   ├── Z08-Subred-4/              #   Auxiliary subnet
│   │   ├── Z09-DMZ-OPD/               #   Secondary DMZ (IoT/Cameras)
│   │   └── Z10-Docker/                #   Container orchestration segment
│   └── ports/                         #   Port scan data per host
│
├── vulnerabilities/                   # CVE Advisories & Technical Analysis
│   ├── CVE-2016-1240/                 #   Tomcat privilege escalation
│   ├── CVE-2019-0211/                 #   Apache privilege escalation
│   ├── CVE-2019-10081/                #   Apache mod_http2 DoS
│   ├── CVE-2019-11043/                #   PHP-FPM remote code execution
│   ├── CVE-2019-1547/                 #   OpenSSL ECDSA timing
│   ├── CVE-2019-1559/                 #   OpenSSL padding oracle
│   ├── CVE-2019-1563/                 #   OpenSSL CMS decrypt leak
│   ├── CVE-2021-21703/                #   PHP privilege escalation
│   └── CVE-2021-4034/                 #   Polkit PwnKit LPE
│
├── exploits/                          # Proof-of-Concept & Exploitation Code
│   ├── cve/                           #   CVE-specific exploit modules
│   │   ├── CVE-2016-1240/
│   │   ├── CVE-2019-0211/
│   │   ├── CVE-2019-10081/
│   │   ├── CVE-2019-11043/
│   │   ├── CVE-2019-1547/
│   │   ├── CVE-2019-1559/
│   │   ├── CVE-2019-1563/
│   │   ├── CVE-2021-21703/
│   │   └── CVE-2021-4034/
│   ├── frameworks/                    #   Custom framework modules
│   └── implants/                      #   Post-exploitation models
│       ├── c2/                        #     Command & control channels
│       ├── persistence/               #     Persistence mechanism models
│       └── rootkits/                  #     Kernel-level rootkit models
│
└── software/                          # Detected Software Inventory
    ├── apache_2.4.38.json             #   Apache HTTPD — EOL
    ├── openssl_1.0.2q.json            #   OpenSSL — EOL
    └── php_7.1.26.json                #   PHP — EOL
```

---

## 9. AI Consumption Guidelines

### 9.1 Entry Points

| File                     | Purpose                                      | When to Read                          |
| ------------------------ | -------------------------------------------- | ------------------------------------- |
| `project-summary.md`     | High-level overview, risk posture, structure | **First** — start here always         |
| `strategic-execution.md` | Full 5-phase execution plan, language matrix | Planning execution or language choice |
| `exploitation-graph.md`  | Attack path dependencies, CVE chains         | Evaluating exploitation feasibility   |
| `attack-surface.json`    | Machine-readable services, CVEs, chains      | Programmatic consumption, validation  |

### 9.2 Data Conventions

| Convention       | Standard                                                 |
| ---------------- | -------------------------------------------------------- |
| File naming      | Lowercase, hyphens (`strategic-execution.md`)            |
| Timestamps       | ISO 8601 (`2026-04-09T14:00:00+08:00`)                   |
| CVSS scores      | v3 base score (e.g., `9.8`)                              |
| JSON schemas     | `$schema` references for validation                      |
| Cross-references | Relative paths from `ai-context/` directory              |
| CVE identifiers  | Canonical format (`CVE-YYYY-NNNNN`)                      |
| Risk levels      | `CRITICAL` > `HIGH` > `MEDIUM` > `LOW` > `INFORMATIONAL` |

### 9.3 Context Boundaries

> [!IMPORTANT]
> All identifiers in this framework are **internal symbolic tokens**. They do not correlate with, represent, or map to any physical entity, real system, or operational environment. This is a **purely theoretical model** for academic research in controlled simulation environments.

---

## 10. Cross-References

| Document                 | Relationship                                                  |
| ------------------------ | ------------------------------------------------------------- |
| `README.md`              | Framework-level overview, compliance, architecture diagrams   |
| `manifest.json`          | Machine-readable project metadata, risk summary, file indices |
| `strategic-execution.md` | Detailed execution plan (this summary is the TL;DR)           |
| `exploitation-graph.md`  | Visual attack paths that this summary condenses               |
| `attack-surface.json`    | Structured data backing the zone/host/service tables above    |
| `vulnerabilities/CVE-*/` | Per-CVE deep dives with metadata.json + advisory.md each      |
| `exploits/cve/CVE-*/`    | Exploit code corresponding to each vulnerability              |
| `software/*.json`        | Software inventory with version, EOL status, and linked CVEs  |

---

_End of project summary._

**Changelog**:

- v2.1.0 (2026-04-09): Updated to reflect strategic-execution.md v2.1.0. Added all 10 zones, MITRE ATT&CK® coverage, standards alignment, escalation topology, lateral movement paths, AI consumption guidelines, cross-references. Corrected vulnerability count (6 → 9). Added metadata and changelog.
- v2.0.0 (2026-04-08): Initial project summary with basic infrastructure overview and exploitation workflow.
