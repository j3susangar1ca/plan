# Security Audit Framework - AI Context

## Project Overview

This security audit framework provides a structured knowledge base for penetration testing activities targeting the Hospital Civil de Guadalajara (HCG) infrastructure.

## Target Summary

| Attribute | Value |
|-----------|-------|
| Organization | Hospital Civil de Guadalajara |
| Primary Domain | hcg.gob.mx |
| Network Zone | Z01-DMZ |
| IP Range | 201.131.132.0/24 |
| Primary Host | 201.131.132.131 |

## Risk Assessment Summary

```
┌─────────────────────────────────────────────┐
│           RISK DISTRIBUTION                 │
├─────────────────────────────────────────────┤
│ Critical: ████████████ 2                   │
│ High:     ████████████████████ 4            │
│ Medium:   0                                 │
│ Low:      0                                 │
├─────────────────────────────────────────────┤
│ TOTAL:    6 vulnerabilities                 │
└─────────────────────────────────────────────┘
```

## Critical Attack Vectors

### 1. CVE-2019-0211 (Apache LPE)
- **Type**: Local Privilege Escalation
- **Target**: Apache 2.4.38
- **Impact**: www-data → root
- **Exploit**: `/exploits/CVE-2019-0211/carpe-diem.php`
- **Reliability**: 87-95%

### 2. CVE-2019-11043 (PHP-FPM RCE)
- **Type**: Remote Code Execution
- **Target**: PHP 7.1.26 (PHP-FPM)
- **Impact**: Remote shell acquisition
- **Exploit**: `/exploits/CVE-2019-11043/metasploit.rb`
- **Reliability**: High

## Technology Stack (EOL - Critical)

| Software | Version | Status | CVEs |
|----------|---------|--------|------|
| Apache | 2.4.38 | EOL | CVE-2019-0211, CVE-2019-10081 |
| PHP | 7.1.26 | EOL | CVE-2019-11043 |
| OpenSSL | 1.0.2q | EOL | CVE-2019-1547, CVE-2019-1559, CVE-2019-1563 |

## Recommended Exploitation Workflow

```mermaid
graph TD
    A[Initial Access] --> B{PHP-FPM Exposed?}
    B -->|Yes| C[CVE-2019-11043 RCE]
    B -->|No| D[FTP Credential Sniffing]
    C --> E[www-data shell]
    D --> E
    E --> F[CVE-2019-0211 LPE]
    F --> G[root access]
    G --> H[Persistence]
```

## File Structure

```
security-audit-framework/
├── manifest.json                    # Project metadata
├── schemas/                         # JSON validation schemas
│   ├── host-scan.schema.json
│   ├── port-scan.schema.json
│   └── cve-advisory.schema.json
├── infrastructure/                  # Scanned assets
│   ├── zones/Z01-DMZ/              # Network zone
│   └── ports/                       # Port scan results
├── vulnerabilities/                 # CVE advisories
│   ├── CVE-2019-0211/
│   ├── CVE-2019-11043/
│   ├── CVE-2019-1547/
│   ├── CVE-2019-1559/
│   ├── CVE-2019-1563/
│   └── CVE-2019-10081/
├── exploits/                        # Proof-of-concept code
│   ├── CVE-2019-0211/
│   └── CVE-2019-11043/
├── software/                        # Software inventory
└── ai-context/                      # AI consumption context
```

## Quick Reference for AI Agents

### Primary Exploitation Path
1. Deploy `carpe-diem.php` to target web server
2. Trigger via HTTP request
3. Wait for Apache graceful restart (logrotate)
4. Execute payload as root

### Secondary Exploitation Path
1. Use Metasploit module `metasploit.rb`
2. Configure TARGETURI and options
3. Execute for PHP-FPM RCE
4. Escalate via CVE-2019-0211 if needed

## Data Consumption Guidelines

All JSON files include:
- `$schema` references for validation
- Consistent naming conventions (lowercase, hyphens)
- ISO 8601 timestamps
- CVSS scores and vectors
- Cross-references between entities
