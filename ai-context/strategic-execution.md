# Infrastructure Resilience Analysis — Corporativo Global de Infraestructura (CGI)

## Formalized Adversary Emulation: Strategic Execution Plan & Language Selection Matrix

**Classification**: Theoretical Simulation Environment  
**Target Organization**: Corporativo Global de Infraestructura (Simulado teórico)  
**Primary Domain**: `corp-infra.local`  
**Scope**: Computational Resilience Engineering  
**Version**: 2.1.0  
**Last Updated**: 2026-04-09

---

## Table of Contents

1. [Infrastructure Inventory](#1-infrastructure-inventory)
2. [Attack Surface Mapping](#2-attack-surface-mapping)
3. [CVE Prioritization Matrix](#3-cve-prioritization-matrix)
4. [Exploitation Dependency Graph](#4-exploitation-dependency-graph)
5. [Strategic Execution Plan](#5-strategic-execution-plan)
   - [Phase 1 — External Reconnaissance](#51-phase-1--external-reconnaissance)
   - [Phase 2 — Initial Access](#52-phase-2--initial-access)
   - [Phase 3 — Privilege Escalation](#53-phase-3--privilege-escalation)
   - [Phase 4 — Persistence & Lateral Movement](#54-phase-4--persistence--lateral-movement)
   - [Phase 5 — Anti-Forensics & Evasion](#55-phase-5--anti-forensics--evasion)
6. [Language Selection Methodology](#6-language-selection-methodology)
7. [Integrated Execution Matrix](#7-integrated-execution-matrix)
8. [Execution Timeline & Resource Model](#8-execution-timeline--resource-model)
9. [Contingency Planning & Abort Criteria](#9-contingency-planning--abort-criteria)
10. [Operational Metrics & KPIs](#10-operational-metrics--kpis)
11. [MITRE ATT&CK® Technique Mapping](#11-mitre-attck-technique-mapping)

---

## 1. Infrastructure Inventory

### 1.1 Network Zones

| Zone ID | Designation            | Risk Level   | Host Count | Key Characteristics                                          |
| ------- | ---------------------- | ------------ | ---------- | ------------------------------------------------------------ |
| Z01     | DMZ — External Servers | **CRITICAL** | 5          | Apache 2.4.38, PHP 7.1.26, OpenSSL 1.0.2q — all EOL          |
| Z02     | Internal Servers       | **CRITICAL** | 10         | AD exposed, SMB 37 shares unaudited, RDP open, MySQL leaked  |
| Z03     | Corporate Workstations | MEDIUM       | 83         | Unencrypted VoIP/WebRTC, unidentified OUIs                   |
| Z04     | Corporate WiFi         | **HIGH**     | 8          | WPA2-Personal shared key, LDAP from WiFi → DC, AJP13 exposed |
| Z05     | Virtual Networks       | MEDIUM       | 0          | Production overlap, Docker on WiFi, ICS unsegmented          |
| Z06     | External / ISP         | LOW          | 0          | Outside direct control                                       |
| Z07     | Monitoring             | MEDIUM       | 0          | ICMP TTL=255, potential leakage                              |
| Z08     | Subnet 10.2.4.0/24     | MEDIUM       | 0          | Unknown purpose, no host inventory                           |
| Z09     | DMZ OPD — IoT/Cameras  | **HIGH**     | 0          | Ubiquiti IoT devices, surveillance cameras                   |
| Z10     | Docker Network         | **HIGH**     | 0          | Docker containers on corporate WiFi without segmentation     |

### 1.2 Critical Hosts

| IP Address      | Zone         | Services                                        | OS/Stack                                    | Risk                                         |
| --------------- | ------------ | ----------------------------------------------- | ------------------------------------------- | -------------------------------------------- |
| 201.131.132.131 | Z01-DMZ      | HTTP(80), HTTPS(443), IKE(500/UDP)              | Apache 2.4.38 / PHP 7.1.26 / OpenSSL 1.0.2q | **CRITICAL** — primary exploitation target   |
| 201.131.132.7   | Z01-DMZ      | HTTP(80/IIS 7.5), DNS(53/UDP), NETIS(53413/UDP) | Windows Server 2008 R2                      | **HIGH** — EOL, HTTP redirect to external IP |
| 216.245.211.42  | Z01-DMZ      | —                                               | —                                           | Unknown exposure                             |
| 10.2.1.1        | Z02-Internos | Gateway                                         | —                                           | Potential pivot point                        |
| 10.2.1.x (×11)  | Z02-Internos | SMB/RDP/AD                                      | Windows                                     | Critical — AD + SMB exposure                 |
| 10.254.0.0/16   | Z04-WiFi     | —                                               | —                                           | Compromisable via WPA2 crack                 |

### 1.3 Exposed Network Services

| Port  | Protocol | Transport | Host            | Finding                                            |
| ----- | -------- | --------- | --------------- | -------------------------------------------------- |
| 21    | FTP      | TCP       | 201.131.132.131 | Unencrypted credential transmission                |
| 80    | HTTP     | TCP       | 201.131.132.131 | Redirects to external IP (187.241.167.211)         |
| 80    | HTTP     | TCP       | 201.131.132.7   | IIS 7.5, redirect chain to `/utsyn/glogin.aspx`    |
| 443   | HTTPS    | TCP       | 201.131.132.131 | EOL OpenSSL with known CVEs                        |
| 500   | IKE      | UDP       | 201.131.132.131 | IKEv2 VPN endpoint detected                        |
| 53    | DNS      | UDP       | 201.131.132.7   | Microsoft DNS 6.1.7601, version disclosure enabled |
| 53413 | NETIS    | UDP       | 201.131.132.7   | NETIS router backdoor port (CVE-2014-9016)         |

---

## 2. Attack Surface Mapping

### 2.1 Web Stack (Host 201.131.132.131)

| Component          | Version | Status     | CVEs                                        |
| ------------------ | ------- | ---------- | ------------------------------------------- |
| Apache HTTP Server | 2.4.38  | EOL        | CVE-2019-0211, CVE-2019-10081               |
| PHP                | 7.1.26  | EOL        | CVE-2019-11043, CVE-2021-21703              |
| OpenSSL            | 1.0.2q  | EOL        | CVE-2019-1547, CVE-2019-1559, CVE-2019-1563 |
| Polkit             | 0.105   | Vulnerable | CVE-2021-4034                               |

### 2.2 Exploitation Chains

#### Chain A — PHP-FPM RCE → CARPE DIEM → PwnKit (Web-to-Root)

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
                                       │
                                       ▼
                              ┌────────────────┐
                              │  root access   │
                              │  Reliability:  │
                              │  100%          │
                              └────────────────┘
```

#### Chain C — Network-Level (VPN/DNS/IoT)

```
┌─────────────────────┐     ┌──────────────────────┐     ┌──────────────────────┐
│ IKEv2 Enumeration   │     │ DNS Exfiltration     │     │ CVE-2014-9016        │
│ UDP 500             │     │ UDP 53 forwarding    │     │ NETIS Backdoor       │
│ Aggressive mode     │     │ Version disclosure   │     │ UDP 53413            │
└─────────────────────┘     └──────────────────────┘     └──────────────────────┘
```

---

## 3. CVE Prioritization Matrix

| Priority | CVE ID         | Type            | Target Component                | CVSS v3 | Exploit Available | Reliability | Prerequisite                                    |
| -------- | -------------- | --------------- | ------------------------------- | ------- | ----------------- | ----------- | ----------------------------------------------- |
| **P0**   | CVE-2021-4034  | LPE             | Polkit 0.105 (pkexec)           | 7.8     | Yes               | 100%        | Local shell                                     |
| **P0**   | CVE-2019-11043 | RCE             | PHP 7.1.26 (PHP-FPM)            | 9.8     | Yes (Metasploit)  | High        | Network access, fastcgi_split_path_info         |
| **P1**   | CVE-2019-0211  | LPE             | Apache 2.4.38 (MPM prefork)     | 9.8     | Yes (PHP PoC)     | 87–95%      | www-data shell, Apache graceful restart trigger |
| **P1**   | CVE-2021-21703 | RCE/LPE         | PHP 7.x (openssl_seal UAF)      | 9.8     | Yes (JOP chain)   | High        | PHP with OpenSSL extension                      |
| **P2**   | CVE-2016-1240  | LPE             | Tomcat 6/7/8 (Debian packaging) | 7.8     | Yes (symlink)     | High        | Local shell, Tomcat via apt, logrotate trigger  |
| **P2**   | CVE-2019-10081 | DoS             | Apache mod_http2                | 7.5     | No                | —           | Network access                                  |
| **P3**   | CVE-2019-1559  | Info Disclosure | OpenSSL 1.0.2q (SSLv3 CBC)      | 5.9     | No (theoretical)  | —           | Network access, SSLv3 enabled                   |
| **P3**   | CVE-2019-1547  | Side-Channel    | OpenSSL ECDSA timing            | 5.3     | No (theoretical)  | —           | Network access, repeated signing                |
| **P3**   | CVE-2019-1563  | Cache Timing    | OpenSSL AES-NI                  | 5.3     | No (theoretical)  | —           | Co-located VM, shared cache                     |
| **P3**   | CVE-2014-9016  | Backdoor        | NETIS Router                    | —       | Yes (direct)      | High        | UDP 53413 access                                |

### Severity Distribution

```
Critical (CVSS ≥ 9.0):  ████████████████████████ 3  (CVE-2019-11043, CVE-2019-0211, CVE-2021-21703)
High     (CVSS 7.0–8.9): ████████████████████     3  (CVE-2021-4034, CVE-2016-1240, CVE-2019-10081)
Medium   (CVSS 4.0–6.9): ████████████             3  (CVE-2019-1547, CVE-2019-1559, CVE-2019-1563)
Informational:          ████                      1  (CVE-2014-9016)
```

---

## 4. Exploitation Dependency Graph

### 4.1 CVE Dependency Map

| CVE            | Type           | Prerequisite                        | Enables                           |
| -------------- | -------------- | ----------------------------------- | --------------------------------- |
| CVE-2019-11043 | RCE            | Network access to PHP-FPM           | www-data shell                    |
| CVE-2021-21703 | RCE/LPE        | PHP compiled with OpenSSL           | Code execution (network or local) |
| CVE-2021-4034  | LPE            | Local shell (any user)              | root shell                        |
| CVE-2016-1240  | LPE            | Local shell + Tomcat apt install    | root via file overwrite           |
| CVE-2019-0211  | LPE            | www-data shell + Apache MPM prefork | root via shared memory hijack     |
| CVE-2019-10081 | DoS            | Network access to HTTP/2            | Service disruption                |
| CVE-2019-1547  | Side-Channel   | Network access, ECDSA signing       | Private key bit leakage           |
| CVE-2019-1559  | Padding Oracle | Network access, SSLv3 CBC           | Partial plaintext recovery        |
| CVE-2019-1563  | Cache Timing   | Co-located VM                       | AES key recovery                  |
| CVE-2014-9016  | Backdoor       | UDP 53413                           | Unauthenticated device access     |

### 4.2 Escalation Matrix

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

---

## 5. Strategic Execution Plan

> **Execution Doctrine**: Each phase follows a fail-fast methodology with clearly defined success criteria, abort conditions, and fallback paths. No phase proceeds without validated prerequisites from the preceding phase.

### 5.1 Phase 1 — External Reconnaissance

**Objective**: Map the complete external attack surface without interacting with critical services.

**Duration Estimate**: 2–6 hours  
**Risk Level**: LOW (passive techniques preferred)  
**OPSEC Rating**: ★★★★★ (non-intrusive, blends with background noise)

| Step | Action                           | Target                                 | Data Collected                                                          |
| ---- | -------------------------------- | -------------------------------------- | ----------------------------------------------------------------------- |
| 1.1  | DNS zone transfer attempt        | 201.131.132.7 (Microsoft DNS 6.1.7601) | Complete host inventory, subdomain enumeration                          |
| 1.2  | Service fingerprinting           | 201.131.132.131                        | Confirm Apache 2.4.38, PHP 7.1.26, OpenSSL 1.0.2q versions              |
| 1.3  | IKEv2 probing                    | UDP 500 on 201.131.132.131             | VPN configuration, authentication methods, aggressive mode viability    |
| 1.4  | NETIS backdoor verification      | UDP 53413 on 201.131.132.7             | CVE-2014-9016 exploitability confirmation                               |
| 1.5  | HTTP redirect chain mapping      | 201.131.132.7:80 → 187.241.167.211     | External IP correlation, application fingerprint (`/utsyn/glogin.aspx`) |
| 1.6  | FTP credential interception test | Port 21 on 201.131.132.131             | Plaintext credential capture feasibility                                |
| 1.7  | Port scan validation             | All identified hosts                   | Cross-reference with existing scan data, identify delta                 |

**Success Criteria**:

- [ ] Confirmed software versions for ≥90% of DMZ services
- [ ] Network topology map validated against existing inventory
- [ ] ≥1 confirmed exploitable attack path identified
- [ ] IKEv2 aggressive mode viability assessed

**Abort Conditions**:

- Active IDS/IPS detection with immediate block behavior
- Rate limiting or tarpitting detected on ≥50% of probes
- Canary tokens or honeypot indicators detected

**Output Artifact**: Complete network topology with confirmed service versions and CVE correlation.

---

### 5.2 Phase 2 — Initial Access

**Objective**: Achieve remote code execution on the primary DMZ target.

**Duration Estimate**: 1–4 hours (depending on exploit reliability)  
**Risk Level**: MEDIUM (active exploitation, network-visible)  
**OPSEC Rating**: ★★★☆☆ (exploit traffic may trigger IDS signatures)

| Priority | Vector                  | Mechanism                                                                                 | Target          | Expected Result       |
| -------- | ----------------------- | ----------------------------------------------------------------------------------------- | --------------- | --------------------- |
| **1st**  | CVE-2019-11043          | PHP-FPM buffer underflow via crafted URI with `fastcgi_split_path_info`                   | 201.131.132.131 | `www-data` shell      |
| **2nd**  | FTP credential sniffing | Passive interception of plaintext FTP credentials → authenticated file upload to web root | 201.131.132.131 | Web shell deployment  |
| **3rd**  | CVE-2021-21703          | `openssl_seal()` UAF → heap grooming → JOP chain code execution                           | 201.131.132.131 | Direct code execution |

**Execution Sequence**:

```
Phase 2 Entry
      │
      ├─→ [Priority 1] CVE-2019-11043 ──→ www-data shell ──→ Phase 3
      │       │ (fail)
      │       ▼
      ├─→ [Priority 2] FTP sniff ──→ Web shell ──→ Phase 3
      │       │ (fail)
      │       ▼
      └─→ [Priority 3] CVE-2021-21703 ──→ Code exec ──→ Phase 3
```

**Success Criteria**:

- [ ] Interactive shell or equivalent command execution achieved
- [ ] Shell stability confirmed (session survives ≥5 min idle)
- [ ] Network callback established (C2 or reverse shell)
- [ ] Target OS and kernel version enumerated

**Abort Conditions**:

- All three vectors fail after 3 attempts each
- Target service crashes or restarts (potential alerting)
- Unexpected WAF or IPS block detected
- Shell achieved but immediately killed (EDR detected)

---

### 5.3 Phase 3 — Privilege Escalation

**Objective**: Elevate from `www-data` to `root` on the compromised host.

**Duration Estimate**: < 1 min (PwnKit) to hours (CARPE DIEM logrotate trigger)  
**Risk Level**: LOW–MEDIUM (local execution, no network artifacts)  
**OPSEC Rating**: ★★★★☆ (limited network visibility, local logging risk)

| Order | CVE                        | Technique                                                                                                                | Reliability | Time Constraint                               |
| ----- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ----------- | --------------------------------------------- |
| **1** | CVE-2021-4034 (PwnKit)     | `GCONV_PATH` environment variable injection → malicious shared library load via `pkexec` SUID binary                     | **100%**    | Immediate (< 1s)                              |
| **2** | CVE-2019-0211 (CARPE DIEM) | UAF in MPM prefork bucket index → shared memory arbitrary write → function pointer hijack during Apache graceful restart | **87–95%**  | Requires logrotate trigger (minutes to hours) |
| **3** | CVE-2016-1240              | Symlink attack on `/var/log/tomcat*/catalina.out` → file overwrite via logrotate                                         | **High**    | Requires Tomcat via apt + logrotate trigger   |

**Escalation Logic**:

```pseudo
function escalate(current_shell):
    if current_shell == "www-data" or any_local_user:
        result = attempt(CVE-2021-4034)    // Primary: 100% reliability
        if result == ROOT:
            return ROOT

    if current_shell == "www-data":
        result = attempt(CVE-2019-0211)    // Secondary: Apache-specific
        if result == ROOT:
            return ROOT

    result = attempt(CVE-2016-1240)        // Tertiary: Tomcat-specific
    if result == ROOT:
        return ROOT

    return current_shell  // Maintain access, retry later
```

**Success Criteria**:

- [ ] Root shell or equivalent (UID 0) achieved
- [ ] Privilege level verified via `id`, `/proc/self/status`
- [ ] Sudo/suid enumeration completed for persistence planning
- [ ] Kernel version and patch level documented

**Abort Conditions**:

- PwnKit fails (non-standard `pkexec` or patched polkit)
- CARPE DIEM doesn't trigger within 4-hour window
- No Tomcat installation found for CVE-2016-1240
- Kernel-level protections detected (SELinux enforcing, AppArmor)

---

### 5.4 Phase 4 — Persistence & Lateral Movement

**Objective**: Establish durable access and expand control across network zones.

**Duration Estimate**: 4–12 hours  
**Risk Level**: HIGH (network scanning, credential abuse, cross-segment traffic)  
**OPSEC Rating**: ★★☆☆☆ (significant network and host-level artifacts)

#### 5.4.1 Persistence Mechanisms

| Mechanism             | Implementation                                             | Stealth Level | Survivability |
| --------------------- | ---------------------------------------------------------- | ------------- | ------------- |
| SSH key injection     | Append attacker public key to `/root/.ssh/authorized_keys` | Low           | High          |
| Crontab modification  | Periodic reverse shell callback                            | Medium        | Medium        |
| Kernel module loading | Loadable kernel module for syscall hooking                 | High          | Very High     |
| Systemd service       | Malicious service unit in `/etc/systemd/system/`           | Medium        | High          |

#### 5.4.2 Lateral Movement Paths

```
ROOT on 201.131.132.131 (Z01-DMZ)
    │
    ├──→ Z02 — Internal Servers (10.2.x.0/24)
    │    ├── SMB relay / Pass-the-Hash → AD domain compromise
    │    ├── RDP lateral movement → 10.2.1.x workstations (×11 hosts)
    │    ├── MySQL unauthenticated access → data exfiltration
    │    └── Gateway pivot via 10.2.1.1
    │
    ├──→ Z04 — Corporate WiFi (10.254.0.0/16)
    │    ├── WPA2-Personal shared key cracking
    │    ├── Client isolation bypass
    │    ├── LDAP bind from WiFi → Domain Controller
    │    └── AJP13 (Apache JServ) exploitation
    │
    ├──→ Z09 — IoT/Cameras (DMZ OPD)
    │    ├── Ubiquiti device enumeration
    │    └── Surveillance system access
    │
    ├──→ Z10 — Docker Network (10.254.178.0/24)
    │    ├── Container escape via misconfigured volumes
    │    └── Host-level access through privileged containers
    │
    └──→ Z07 — Monitoring (10.1.97.0/24)
         └── Monitoring system subversion (ICMP analysis)
```

#### 5.4.3 C2 Communication Channels

| Channel             | Protocol | Port            | Characteristics                                        | Bandwidth |
| ------------------- | -------- | --------------- | ------------------------------------------------------ | --------- |
| DNS tunneling       | UDP 53   | 201.131.132.7   | Existing forwarding server, legitimate traffic pattern | Low       |
| HTTPS callback      | TCP 443  | 201.131.132.131 | Encrypted, blends with normal web traffic              | High      |
| ICMP covert channel | ICMP     | All hosts       | Data embedded in ICMP echo payloads                    | Very Low  |

**Success Criteria**:

- [ ] ≥2 independent persistence mechanisms installed
- [ ] ≥1 lateral movement path validated end-to-end
- [ ] C2 channel operational with ≥95% uptime over 24h
- [ ] Domain admin or equivalent access achieved (if AD present)

**Abort Conditions**:

- Lateral movement blocked by network segmentation (unexpected)
- C2 channels blocked within 1 hour of deployment
- Host-based monitoring (EDR/AV) detects persistence mechanism
- Network anomaly alerts exceed threshold (≥3 alerts/hour)

---

### 5.5 Phase 5 — Anti-Forensics & Evasion

**Objective**: Eliminate evidence of access and maintain operational security.

**Duration Estimate**: 1–3 hours  
**Risk Level**: MEDIUM (log modifications can themselves trigger SIEM alerts)  
**OPSEC Rating**: ★★★☆☆ (depends on target's logging maturity)

| Action                   | Target                                           | Method                                    | Detection Risk |
| ------------------------ | ------------------------------------------------ | ----------------------------------------- | -------------- |
| Log purging              | Apache access/error logs, auth.log, syslog, wtmp | Selective line removal or full truncation | High           |
| Timestomping             | Modified files, deployed tools                   | Match timestamps to adjacent system files | Medium         |
| File deletion            | Exploits, temporary files, shell history         | Secure overwrite (3-pass) before unlink   | Low            |
| Process hiding           | C2 agents, implants                              | LD_PRELOAD hooking or kernel-level hiding | Medium         |
| Network artifact cleanup | Connection logs, DNS queries                     | iptables LOG target manipulation          | Low            |

**Success Criteria**:

- [ ] No anomalous entries in syslog/auth.log for last 24h
- [ ] Deployed tool timestamps match system baseline
- [ ] Shell history cleared (`history -c` + `.bash_history` truncation)
- [ ] No orphaned processes or network listeners

**Abort Conditions**:

- Centralized logging (SIEM) with immutable append-only storage
- File integrity monitoring (AIDE/OSSEC) blocks log modifications
- Forensic imaging already in progress (detected via `dd` or similar)

---

## 6. Language Selection Methodology

### 6.1 Evaluation Dimensions

Each candidate language is assessed against five technical dimensions:

| Dimension               | Definition                                                            | Measurement                                                            |
| ----------------------- | --------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| **Low-level control**   | Direct access to memory, syscalls, CPU registers, hardware primitives | Qualitative: ★ (none) to ★★★★★ (full)                                  |
| **Portability**         | Cross-compilation capability, target diversity without code rewrite   | Qualitative: ★ (single target) to ★★★★★ (universal)                    |
| **Stealth / Signature** | Binary size, dependency footprint, AV/EDR detection surface           | Qualitative: ★ (high detection) to ★★★★★ (minimal footprint)           |
| **Concurrency model**   | Parallelism primitives, async I/O, network throughput at scale        | Qualitative: ★ (single-threaded) to ★★★★★ (massive concurrency)        |
| **Systems ergonomics**  | Development velocity relative to level of control achieved            | Qualitative: ★ (assembly-level friction) to ★★★★★ (high-level fluency) |

### 6.2 Candidate Languages

| Language   | Compilation Model | Runtime           | Memory Model               | Primary Use Domain          |
| ---------- | ----------------- | ----------------- | -------------------------- | --------------------------- |
| Rust       | AOT (LLVM)        | None (static)     | Ownership + Borrow Checker | Systems, concurrent, safe   |
| C          | AOT (GCC/Clang)   | None (libc)       | Manual (malloc/free)       | Systems, embedded, exploits |
| C++        | AOT (GCC/Clang)   | None (libstdc++)  | RAII + Manual              | Systems, applications       |
| Go         | AOT (gc)          | Garbage collector | Managed heap               | Networking, tooling         |
| x86_64 ASM | AOT (nasm/gas)    | None              | Register/stack             | Shellcode, payloads         |
| Python     | Interpreter       | CPython VM        | Reference counting + GC    | Scripting, prototyping      |
| Nim        | AOT (C backend)   | Optional GC       | ORC / refc                 | Systems scripting           |

---

## 7. Integrated Execution Matrix

### 7.1 Phase-by-Phase Language Assignment

#### Phase 1 — External Reconnaissance

**Primary Language**: Rust

| Criterion               | Assessment                                                             |
| ----------------------- | ---------------------------------------------------------------------- |
| Concurrency requirement | 100K+ simultaneous socket connections during mass scanning             |
| Data processing         | Zero-copy parsing of DNS, HTTP, IKEv2 protocol responses               |
| Deployment constraint   | Single static binary, no runtime dependencies on target infrastructure |
| Safety requirement      | Type-state pattern guarantees protocol conformance at compile time     |

**Technical Justification**:

- **Tokio async runtime**: Single-thread event loop handles ~100K concurrent sockets via epoll/kqueue/IOCP. Compared with C (manual epoll + callback complexity) or Go (goroutines with ~4KB stack per coroutine), Rust achieves equivalent or superior throughput without runtime overhead.

- **Zero-cost protocol parsing**: Libraries such as `nom` and `bytes` enable packet parsing without heap allocation. For a scan of 65,535 ports × N hosts, this translates to O(1) memory per connection versus O(n) in managed languages.

- **Cross-compilation**: `cargo build --target x86_64-unknown-linux-musl` produces a statically-linked binary of ~2–5 MB with zero system dependencies. Deployment requires no package installation on target infrastructure.

- **Compile-time protocol correctness**: The type-state pattern enforces state machine transitions (e.g., IKEv2 handshake phases) at compile time. Runtime protocol violations become compilation errors, eliminating entire classes of scan logic bugs.

- **Representational control**: `#[repr(C)]` and `#[packed]` attributes guarantee exact byte-level layout of protocol structures (FCGI headers, TLS records, DNS packets) without compiler-introduced padding or reordering.

**Secondary Languages**: None required. Rust's ecosystem (via `trust-dns`, `tokio`, `pnet`) covers all reconnaissance protocol requirements.

---

#### Phase 2 — Initial Access

**Primary Language**: Rust (orchestration) + C/ASM (payload generation)

| Criterion             | Assessment                                                             |
| --------------------- | ---------------------------------------------------------------------- |
| Protocol manipulation | Byte-level crafting of FastCGI requests, TLS records, HTTP payloads    |
| Memory safety         | Exploitation frameworks must not crash during target interaction       |
| Shellcode generation  | Position-independent code, opcode-level control, null-byte avoidance   |
| Deployment model      | Rust orchestrator as static binary; C/ASM payloads as compiled modules |

**Technical Justification**:

- **Rust as orchestration layer**: The exploitation framework manages target selection, protocol state machines, timing, and result collection. Rust's ownership model prevents use-after-free and buffer overflow bugs _by construction_. In an exploitation context, a framework bug (e.g., off-by-one in packet length calculation) causes a framework crash, not a successful exploit. Memory safety in the framework directly translates to operational reliability.

- **Surgical `unsafe` blocks**: When direct memory manipulation is required (heap grooming, crafted structures for CVE-2021-21703 UAF triggering), Rust permits `unsafe` in isolated blocks of ~10–20 lines. The remaining ~95% of framework code maintains compile-time memory safety guarantees. This is a strict improvement over C where 100% of code operates in an unsafe context.

- **C for shellcode construction**: Shellcode (execve("/bin/sh"), bind shell, reverse shell) requires position-independent byte sequences of 30–50 bytes without null terminators. Assembly language is the only appropriate tool for this:

  ```asm
  ; execve("/bin/sh", NULL, NULL) — 24 bytes, no nulls
  xor    rsi, rsi
  push   rsi
  mov    rdi, 0x68732f2f6e69622f  ; "//bin/sh"
  push   rdi
  push   rsp
  pop    rdi
  mov    al, 59                   ; SYS_execve
  syscall
  ```

- **C for heap manipulation primitives**: Heap grooming (controlled allocation/deallocation patterns to shape heap layout) requires direct `malloc`/`free` invocation with precise size control. C provides the most direct mapping to glibc allocator behavior without abstraction layers.

---

#### Phase 3 — Privilege Escalation

**Primary Language**: C + x86_64 Assembly

| Criterion                  | Assessment                                                                      |
| -------------------------- | ------------------------------------------------------------------------------- |
| Ecosystem maturity         | 95%+ of published LPE exploits (Qualys, Project Zero, GRIMM) written in C       |
| Syscall mapping            | Direct 1:1 correspondence between C primitives and Linux syscalls               |
| Race condition testing     | Precise thread timing via `pthread_create` + `sched_yield` + nanosecond clocks  |
| ROP/JOP chain construction | Direct memory addressing as `uint64_t` arrays                                   |
| Environment manipulation   | Stack layout control via `__builtin_frame_address()` and env block manipulation |

**Technical Justification**:

- **Established exploit ecosystem**: The overwhelming majority of published privilege escalation exploits targeting Linux are written in C. This is not a historical artifact — C maps directly to the system call interface without abstraction layers. Primitives such as `mmap`, `mprotect`, `pipe`-based heap spraying, and `pthread` race conditions correspond 1:1 between C source and kernel interface.

- **Environment variable manipulation (PwnKit-style)**: CVE-2021-4034 exploits manipulate the environment block as a contiguous byte array to inject `GCONV_PATH`. C provides the most direct access to this structure:

  ```c
  // Environment block layout manipulation
  char *envp[] = {
      "GCONV_PATH=/tmp/exploit",
      "CHARSET=exploit",
      "SHELL=/tmp/exploit/gconv-modules",
      NULL
  };
  ```

  Rust can accomplish this via `unsafe` FFI, but the operation is inherently unsafe and gains no benefit from safe abstractions.

- **ROP chain construction**: Return-Oriented Programming chains are sequences of gadget addresses (`pop rdi; ret`, `mov [rdi], rax; ret`). They are constructed as contiguous `uint64_t` arrays on the stack or heap. C is the most direct representation:

  ```c
  uint64_t rop_chain[] = {
      pop_rdi_ret,           // gadget 1: load register
      target_address,        // argument
      mov_rdi_rax_ret,       // gadget 2: write primitive
      pop_rsi_ret,           // gadget 3
      shellcode_address,     // argument
      jmp_rsi_ret            // gadget 4: pivot to shellcode
  };
  ```

- **Race condition precision**: Exploits such as CVE-2016-1240 (symlink + logrotate) require precise timing between attacker threads and system services. C provides:
  - `pthread_create()` with explicit scheduling policy (`SCHED_FIFO`)
  - `sched_yield()` for voluntary preemption
  - `clock_gettime(CLOCK_MONOTONIC)` for nanosecond-precision timing
  - `futex` system calls for low-level synchronization

- **Assembly for payload finalization**: The shellcode injected into the target process must be fully self-contained, position-independent, and typically under 256 bytes. Only assembly provides byte-level control. The C exploit compiles and deploys; the assembly payload executes.

---

#### Phase 4 — Persistence & Lateral Movement

**Primary Language**: Rust (implant agent) + Go (network pivoting tools)

| Criterion                       | Assessment                                                                                   |
| ------------------------------- | -------------------------------------------------------------------------------------------- |
| Agent binary size               | Rust: 3–5 MB static (musl). Go: 8–12 MB with runtime. Rust preferred for stealth.            |
| Agent runtime overhead          | Rust: zero (no GC). Go: GC pauses ~1ms. Rust preferred for long-running implants.            |
| Pivoting tool development speed | Go: 3-line TCP proxy. Rust: 15+ lines with async runtime. Go preferred for disposable tools. |
| Cross-compilation (agent)       | Rust: `cargo build --target`. Go: `GOOS=linux GOARCH=arm64`. Both excellent.                 |
| Crypto libraries                | Both provide TLS, SSH, AES-GCM. Go's `crypto/ssh` is production-grade out of box.            |

**Technical Justification**:

- **Rust for the persistent implant**: The agent runs continuously on the compromised host. Key requirements:
  - **Minimal binary footprint**: `#[no_std]` compilation with `musl` target produces ~3 MB static binaries with no libc dependency. Go's runtime alone adds ~2 MB overhead.
  - **Zero GC pauses**: Rust has no garbage collector. The agent process consumes constant memory with no periodic GC pauses that could trigger EDR anomaly detection.
  - **Syscall-level stealth**: Via `core::arch::asm!()`, the agent can invoke syscalls directly, bypassing libc wrappers that EDRs commonly hook:

    ```rust
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") libc::SYS_execve,
            in("rdi") path.as_ptr(),
            in("rsi") argv.as_ptr(),
            in("rdx") envp.as_ptr(),
        );
    }
    ```

  - **LLVM obfuscation**: Rust compiles via LLVM, enabling control-flow flattening, bogus control-flow insertion, and instruction substitution passes. The resulting binary maintains identical runtime behavior while resisting static analysis.

- **Go for disposable pivoting tools**: SOCKS proxies, port forwarders, and DNS tunnelers are deployed temporarily and discarded. Development velocity is the primary constraint:
  - `net.Dial("tcp", target)` establishes a TCP connection in one line
  - Goroutines handle per-connection concurrency without explicit thread management
  - `crypto/ssh` provides production-grade SSH client/server with `ssh.Dial()` and `ssh.Listen()`
  - Cross-compilation via `GOOS=linux GOARCH=amd64 go build` produces a single static binary
  - Tool lifetime is measured in minutes, making binary size and GC overhead non-critical

- **Division of labor rationale**: The implant requires stealth (Rust). The pivoting tools require speed of development and deployment (Go). Attempting to use a single language for both roles creates either an over-engineered proxy (Rust) or an overly exposed implant (Go's binary size and runtime fingerprint).

---

#### Phase 5 — Anti-Forensics & Evasion

**Primary Language**: Rust + inline x86_64 Assembly

| Criterion                 | Assessment                                                                       |
| ------------------------- | -------------------------------------------------------------------------------- |
| Syscall direct invocation | `core::arch::asm!("syscall")` bypasses libc entirely                             |
| `#[no_std]` capability    | Binaries as small as ~500 bytes with no standard library                         |
| LLVM toolchain            | Access to obfuscation passes (CFF, BCF, SUB) at compile time                     |
| Filesystem manipulation   | Direct syscall-based file operations (`SYS_open`, `SYS_unlink`, `SYS_utimensat`) |
| Process hiding            | `SYS_ptrace`, `SYS_process_vm_readv` for introspection/hooking                   |

**Technical Justification**:

- **Direct syscall invocation**: EDR products hook libc functions (`execve`, `open`, `connect`) to monitor process behavior. Rust's `core::arch::asm!()` macro allows invocation of syscalls directly, bypassing all userspace hooks:

  ```rust
  // timestomp via direct utimensat syscall
  unsafe {
      core::arch::asm!(
          "syscall",
          in("rax") libc::SYS_utimensat,
          in("rdi") libc::AT_FDCWD,
          in("rsi") path.as_ptr(),
          in("rdx") times.as_ptr(),
          in("r10") 0u64,  // flags
      );
  }
  ```

- **`#[no_std]` payloads**: Rust can compile without the standard library, producing binaries that use only syscalls and compiler intrinsics. A log-cleaning utility compiled with `#[no_std]` + `panic = "abort"` produces a ~500-byte ELF that has no detectable library signatures.

- **LLVM obfuscation pipeline**: Rust's LLVM backend supports custom passes for:
  - **Control Flow Flattening (CFF)**: Replaces structured control flow with a dispatcher switch statement, increasing analysis time by 10–100×
  - **Bogus Control Flow (BCF)**: Inserts unreachable basic blocks with opaque predicates
  - **Instruction Substitution (SUB)**: Replaces arithmetic operations with equivalent but more complex sequences
  - These passes operate at the IR level, preserving semantic correctness while degrading static analysis effectiveness.

- **Memory-only execution**: Combined with `SYS_memfd_create` + `SYS_execveat` via direct syscalls, Rust can construct a fully fileless execution pipeline. The binary is written to an anonymous memory-backed file descriptor and executed without touching the filesystem.

---

### 7.2 Summary Matrix

| Phase                             | Primary  | Secondary   | Dominant Criterion                              | Rationale                                                         |
| --------------------------------- | -------- | ----------- | ----------------------------------------------- | ----------------------------------------------------------------- |
| 1. External Reconnaissance        | **Rust** | —           | Concurrency + zero-copy parsing                 | 100K+ simultaneous connections, type-safe protocol state machines |
| 2. Initial Access                 | **Rust** | **C / ASM** | Safe orchestration + byte-level control         | Framework memory safety + shellcode opcode precision              |
| 3. Privilege Escalation           | **C**    | **ASM**     | Syscall mapping + exploit ecosystem             | 95%+ of published LPEs in C, direct ROP/env manipulation          |
| 4. Persistence & Lateral Movement | **Rust** | **Go**      | Agent stealth + tool development speed          | Zero-GC implant (Rust) + disposable pivoting tools (Go)           |
| 5. Anti-Forensics & Evasion       | **Rust** | **ASM**     | Syscall bypass + `#[no_std]` + LLVM obfuscation | Direct syscalls evade EDR hooks, minimal binary footprint         |

### 7.3 Cross-Phase Language Dominance

```
Rust  ████████████████████████████████████████████  4/5 phases (primary)
C     ████████████████████                          2/5 phases (primary or secondary)
ASM   ████████████████████                          2/5 phases (secondary)
Go    ████████████                                  1/5 phases (secondary)
```

**Rust is the dominant language across 4 of 5 phases** due to three measurable properties:

1. **Zero-cost abstractions**: Type-level abstractions compile to identical assembly as hand-written C with `-O2` optimization. Verified via LLVM IR comparison.
2. **Ownership model**: Eliminates use-after-free, double-free, and buffer overflow by static analysis. Microsoft Research: ~70% of CVEs in Microsoft products are memory-safety bugs. Rust's model eliminates this entire class.
3. **Fearless concurrency**: `Send` + `Sync` trait bounds prevent data races at compile time. Critical for scanners handling 100K+ concurrent connections without runtime race condition bugs.

**C retains its role in Phase 3 (local exploitation)** where the existing exploit ecosystem, direct syscall mapping, and memory manipulation primitives make it irreplaceable. **ASM is the domain of final payloads** where byte-level control is non-negotiable. **Go serves as a pragmatic choice for disposable network tools** where development speed outweighs operational longevity.

---

## 8. Execution Timeline & Resource Model

### 8.1 Gantt-Style Timeline

```
Hour:  0   2   4   6   8  10  12  14  16  18  20  22  24
       │   │   │   │   │   │   │   │   │   │   │   │   │
Phase 1 ████████████                                      Reconnaissance
Phase 2     ████████████                                  Initial Access
Phase 3         ████                                      Priv Esc (PwnKit)
         or     ████████████████████                      Priv Esc (CARPE DIEM)
Phase 4                 ████████████████████████          Persistence & Lateral
Phase 5                                 ████████████      Anti-Forensics
       │   │   │   │   │   │   │   │   │   │   │   │   │
       0   2   4   6   8  10  12  14  16  18  20  22  24h
```

### 8.2 Resource Requirements

| Phase   | Network Bandwidth | CPU Usage | Disk I/O | Memory | Stealth Constraint          |
| ------- | ----------------- | --------- | -------- | ------ | --------------------------- |
| Phase 1 | Low–Medium        | Low       | None     | <50MB  | Rate-limit to <100 pps      |
| Phase 2 | Medium            | Medium    | None     | <100MB | Burst, then silence 60s     |
| Phase 3 | None              | Low       | Low      | <50MB  | Minimal local footprint     |
| Phase 4 | High              | Medium    | Medium   | <200MB | Jitter C2 callbacks ±30%    |
| Phase 5 | None              | Low       | High     | <50MB  | Match baseline I/O patterns |

### 8.3 Personnel Model

| Role               | Phase Involvement | Criticality |
| ------------------ | ----------------- | ----------- |
| Recon Operator     | Phase 1, 2        | Primary     |
| Exploit Developer  | Phase 2, 3        | Primary     |
| Post-Exploitation  | Phase 3, 4        | Primary     |
| OPSEC Analyst      | All phases        | Continuous  |
| Incident Commander | Decision gates    | On-call     |

---

## 9. Contingency Planning & Abort Criteria

### 9.1 Global Abort Conditions

These conditions terminate the entire operation regardless of current phase:

| Condition                             | Action                      | Rationale                                |
| ------------------------------------- | --------------------------- | ---------------------------------------- |
| Blue team confirms active counter-op  | Immediate cease + cleanup   | Compromised operational security         |
| Legal/compliance escalation detected  | Immediate cease + full wipe | Regulatory risk exceeds assessment value |
| Asset (personnel) safety concern      | Immediate cease             | Human safety supersedes all objectives   |
| Scope boundary violation (production) | Immediate cease + rollback  | Theoretical model only — no real targets |

### 9.2 Phase-Specific Fallback Chains

```
Phase 1 Failure:
  Passive recon → Active scan → Social engineering OSINT → ABORT

Phase 2 Failure:
  CVE-2019-11043 → FTP sniff → CVE-2021-21703 → Spray-and-pray → ABORT
                                                        │
                                                        ▼
                                              Return to Phase 1
                                              (re-evaluate attack surface)

Phase 3 Failure:
  PwnKit → CARPE DIEM → CVE-2016-1240 → Kernel exploit search → ABORT
                                                            │
                                                            ▼
                                                  Maintain www-data access
                                                  Attempt Phase 4 with
                                                  limited privileges

Phase 4 Failure:
  Z02 pivot → Z04 pivot → Z10 pivot → Z09 pivot → ABORT (scope exhausted)
                                                     │
                                                     ▼
                                           Maintain DMZ access only

Phase 5 Failure:
  Selective cleanup → Full wipe → Controlled burn → ABORT (accept attribution)
```

### 9.3 Detection Response Matrix

| Detection Event                      | Severity | Response                                                            |
| ------------------------------------ | -------- | ------------------------------------------------------------------- |
| Single IDS alert (low)               | LOW      | Pause 15 min, adjust signature profile, resume                      |
| Multiple IDS alerts (>3/hour)        | MEDIUM   | Switch to passive mode, evaluate detection capability               |
| Firewall rule change detected        | HIGH     | Abort current phase, assess if block is targeted or routine         |
| Active port scan on compromised host | CRITICAL | Full cleanup, abort operation, investigate blue team response       |
| Honeypot/canary triggered            | CRITICAL | Immediate full abort, zero-fill artifacts, disconnect all callbacks |

---

## 10. Operational Metrics & KPIs

### 10.1 Phase KPIs

| Phase   | KPI                                       | Target        | Measurement Method                       |
| ------- | ----------------------------------------- | ------------- | ---------------------------------------- |
| Phase 1 | Service enumeration completeness          | ≥90%          | Discovered services / total inventory    |
| Phase 1 | False positive rate (service detection)   | <5%           | Manual validation of flagged services    |
| Phase 2 | Time to first shell                       | <2 hours      | Timestamp: recon complete → shell prompt |
| Phase 2 | Exploit reliability (successful/executed) | ≥80%          | Successful attempts / total attempts     |
| Phase 3 | Time to root                              | <1 hour       | Timestamp: www-data → UID 0              |
| Phase 3 | Privilege escalation reliability          | ≥95%          | Successful escalations / attempts        |
| Phase 4 | Lateral movement coverage                 | ≥3 zones      | Zones accessed / total target zones      |
| Phase 4 | C2 uptime                                 | ≥95% over 24h | Heartbeat success rate                   |
| Phase 5 | Detection event count (post-cleanup)      | 0             | SIEM/IDS alert count post-Phase 5        |
| Phase 5 | Residual artifact count                   | 0             | Manual verification post-cleanup         |

### 10.2 Aggregate Operation Metrics

```
┌─────────────────────────────────────────────────────────┐
│               OPERATION SCORECARD                        │
├──────────────────────┬──────────────────────────────────┤
│ Total Duration       │ Target: <24h | Actual: ___h      │
│ Shells Obtained      │ Target: ≥2   | Actual: ___       │
│ Zones Compromised    │ Target: ≥3   | Actual: ___       │
│ Detection Events     │ Target: 0    | Actual: ___       │
│ Artifacts Residual   │ Target: 0    | Actual: ___       │
│ Scope Violations     │ Target: 0    | Actual: ___       │
│ Data Exfiltrated     │ Target: —    | Actual: ___GB     │
└──────────────────────┴──────────────────────────────────┘
```

---

## 11. MITRE ATT&CK® Technique Mapping

> Each technique used across the five phases is mapped to the MITRE ATT&CK® Enterprise framework for standardization and traceability.

### 11.1 Phase 1 — Reconnaissance

| Technique ID | Technique Name                 | Usage in Plan                               |
| ------------ | ------------------------------ | ------------------------------------------- |
| T1595        | Active Scanning                | Port scanning, service fingerprinting       |
| T1595.002    | Vulnerability Scanning         | CVE correlation against discovered services |
| T1590.002    | DNS                            | Zone transfer attempts, subdomain enum      |
| T1592        | Gather Victim Host Information | OS/stack fingerprinting                     |
| T1590.001    | Network Security Appliances    | IKEv2 probing, VPN configuration discovery  |

### 11.2 Phase 2 — Initial Access

| Technique ID | Technique Name                    | Usage in Plan                            |
| ------------ | --------------------------------- | ---------------------------------------- |
| T1190        | Exploit Public-Facing Application | CVE-2019-11043 (PHP-FPM), CVE-2021-21703 |
| T1078        | Valid Accounts                    | FTP credential interception              |
| T1133        | External Remote Services          | IKEv2 VPN exploitation                   |

### 11.3 Phase 3 — Privilege Escalation

| Technique ID | Technique Name                        | Usage in Plan                               |
| ------------ | ------------------------------------- | ------------------------------------------- |
| T1068        | Exploitation for Privilege Escalation | CVE-2021-4034, CVE-2019-0211, CVE-2016-1240 |
| T1548        | Abuse Elevation Control Mechanism     | pkexec SUID exploitation (PwnKit)           |

### 11.4 Phase 4 — Persistence & Lateral Movement

| Technique ID | Technique Name                        | Usage in Plan                      |
| ------------ | ------------------------------------- | ---------------------------------- |
| T1098.004    | SSH Authorized Keys                   | SSH key injection persistence      |
| T1053.003    | Cron                                  | Crontab reverse shell              |
| T1543        | Create or Modify System Process       | Systemd service unit               |
| T1021.002    | SMB/Windows Admin Shares              | SMB relay / Pass-the-Hash in Z02   |
| T1021.001    | Remote Desktop Protocol               | RDP lateral movement               |
| T1550        | Use Alternate Authentication Material | Pass-the-Hash for AD               |
| T1572        | Protocol Tunneling                    | DNS tunneling, ICMP covert channel |
| T1071        | Application Layer Protocol            | HTTPS C2 callback                  |
| T1078        | Valid Accounts                        | Credential reuse across segments   |

### 11.5 Phase 5 — Defense Evasion

| Technique ID | Technique Name                 | Usage in Plan                        |
| ------------ | ------------------------------ | ------------------------------------ |
| T1070.002    | Clear Linux or Mac System Logs | Log purging (syslog, auth.log, wtmp) |
| T1070.006    | Timestomp                      | File timestamp modification          |
| T1070.004    | File Deletion                  | Secure overwrite of artifacts        |
| T1562.001    | Disable or Modify Tools        | iptables LOG target manipulation     |
| T1014        | Rootkit                        | Kernel module / LD_PRELOAD hooking   |
| T1620        | Reflective Code Loading        | Fileless execution via memfd_create  |

### 11.6 Coverage Summary

```
Tactics Covered:
  ✅ Reconnaissance        (TA0043)
  ✅ Resource Development  (TA0042) — implicit via exploit preparation
  ✅ Initial Access        (TA0001)
  ✅ Execution             (TA0002)
  ✅ Persistence           (TA0003)
  ✅ Privilege Escalation  (TA0004)
  ✅ Defense Evasion       (TA0005)
  ✅ Lateral Movement      (TA0008)
  ✅ Command and Control   (TA0011)
  ✅ Collection            (TA0009) — implicit via data exfil paths
  ⬜ Credential Access     (TA0006) — not primary focus
  ⬜ Discovery             (TA0007) — partially covered in Phase 1
  ⬜ Exfiltration          (TA0010) — referenced but not detailed
  ⬜ Impact                (TA0040) — out of scope for simulation
```

---

_End of report._

**Changelog**:

- v2.1.0 (2026-04-09): Added success criteria, abort conditions, execution timeline, contingency planning, operational KPIs, and MITRE ATT&CK® technique mapping. Added resource model and personnel allocation.
- v2.0.0 (2026-04-08): Initial strategic execution plan with infrastructure inventory, CVE prioritization, exploitation chains, and language selection matrix.
