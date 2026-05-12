# GhostHound

> Lightweight Active Directory attack surface analysis without Neo4j.

GhostHound is a lightweight Active Directory attack surface analyzer designed to process and correlate BloodHound Python and NetExec (NXC) data to identify high-risk attack paths, privilege escalation opportunities, and AD misconfigurations — without requiring the full BloodHound + Neo4j stack.

Unlike traditional graph-heavy AD analysis platforms, GhostHound focuses on:

- High-value attack path discovery
- Offensive security visibility
- Lightweight analysis workflows
- Human-readable findings
- Fast CLI-based auditing
- Future multi-source correlation

---

## Features

- BloodHound ZIP/JSON parsing
- Lightweight AD analysis engine
- Kerberoastable account detection
- AS-REP roastable account detection
- Privileged group analysis
- Normalized internal AD models
- Modular analyzer architecture
- Clean CLI reporting
- Multi-source ready architecture
- Future NetExec (NXC) correlation support

---

## Why GhostHound?

Traditional BloodHound deployments require:
- Neo4j
- Large graph datasets
- Heavy infrastructure
- Full graph visualization workflows

GhostHound takes a different approach.

Instead of visualizing every edge in the environment, GhostHound focuses on extracting actionable offensive security findings from collected AD data.

The goal is to prioritize:
- What is exploitable
- What is dangerous
- What leads to privilege escalation
- What should be investigated first

---

## Demo

### Loading BloodHound Data

```bash
ghosthound analyze input/
```

```text
============================================================
BloodHound Data Loaded Successfully
============================================================
Domains:  1
  - OFFSEC.NL

Total Users:     2493
Total Computers: 103
Total Groups:    550
============================================================
```

---

### Example Findings

```text
============================================================
Security Findings
============================================================

[CRITICAL] 3 Domain Admin Members

[HIGH] 165 AS-REP Roastable Users Found

[HIGH] 50 Kerberoastable Users Found
```

---

## Architecture

GhostHound is designed around a normalized internal data model.

All external data sources are converted into clean internal objects before analysis.

```text
BloodHound / NXC / LDAP
            ↓
         Parsers
            ↓
    Normalized Models
            ↓
         Analyzers
            ↓
         Findings
            ↓
      Correlation Engine
            ↓
       Attack Paths
            ↓
         Reporting
```

This architecture allows GhostHound to:
- remain data-source agnostic
- support future integrations easily
- separate parsing from analysis logic
- avoid tightly coupled detection code

---

## Project Structure

```text
ghosthound/
│
├── ghosthound/
│   ├── analyzers/
│   ├── collectors/
│   ├── correlation/
│   ├── models/
│   ├── parsers/
│   ├── reports/
│   ├── scoring/
│   └── utils/
│
├── tests/
├── screenshots/
├── input/
├── main.py
├── pyproject.toml
└── README.md
```

---

## Installation

```bash
git clone https://github.com/YOURNAME/ghosthound
cd ghosthound

pip install -e .
```

---

## Usage

### Analyze BloodHound ZIP Export

```bash
ghosthound analyze input/bloodhound.zip
```

### Analyze JSON Directory

```bash
ghosthound analyze input/
```

---

## Supported Findings

Current detection modules include:

- Kerberoastable users
- AS-REP roastable accounts
- Domain Admin members
- Privileged group analysis

Planned detections:

- Unconstrained delegation
- Constrained delegation
- Local admin relationships
- Session analysis
- ADCS abuse paths
- Shadow credentials
- SMB exposure correlation

---

## Design Principles

GhostHound is built with the following goals:

### Lightweight
No Neo4j or graph database required.

### Offensive Security Focused
Built for red team operators, internal pentesters, and AD auditors.

### Modular
Easy to extend with new parsers, analyzers, and correlation engines.

### Clean Architecture
Parsing, analysis, scoring, and reporting are fully separated.

### Multi-Source Ready
Designed to support:
- BloodHound Python
- NetExec (NXC)
- LDAP enumeration
- SMB enumeration
- Kerberos enumeration

---

## Roadmap

### Phase 1
- BloodHound parser
- Normalized models
- Initial analyzers

### Phase 2
- Correlation engine
- Attack chain generation
- Risk scoring

### Phase 3
- NetExec integration
- SMB exposure analysis
- Attack validation

### Phase 4
- HTML reporting
- Interactive TUI
- Continuous AD exposure monitoring

---

## Future Vision

GhostHound is evolving toward a lightweight AD intelligence engine capable of correlating offensive security data from multiple sources to automatically identify realistic attack opportunities and privilege escalation paths.

---

## Contributing

Contributions, ideas, pull requests, and feedback are welcome.

Future contributors may help with:
- new analyzers
- correlation rules
- reporting modules
- parsers
- attack path logic
- ADCS support

---

## License

GPLv3 License

Copyright (c) 2026 oko-ops
