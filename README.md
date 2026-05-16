# 👻 GhostHound

> Lightweight Active Directory attack surface analyzer without Neo4j.
<p align="center">
  <img src="banner.png" alt="GhostHound Banner" />
</p>
GhostHound transforms BloodHound data into **actionable security findings** in seconds — focusing on what actually matters in Active Directory environments: misconfigurations, privilege escalation paths, and high-risk exposures.

---

## ⚡ What is GhostHound?

GhostHound is a fast AD security analysis tool that:

- Parses BloodHound Python exports
- Normalizes Active Directory objects
- Runs lightweight security analyzers
- Outputs prioritized findings (not graphs)

Instead of visualizing everything, GhostHound answers:

> “What is actually exploitable in this domain?”

---

## 🚨 Problem

Traditional AD analysis tools like BloodHound:

- Require Neo4j database setup
- Produce complex graph structures
- Require manual analysis of attack paths
- Are heavy for quick assessments

This slows down real-world red team workflows.

---

## 💡 Solution

GhostHound focuses on **actionable intelligence**, not visualization.

It extracts:

- 🔥 Exploitable misconfigurations
- 🔑 Credential attack opportunities
- 🧭 Privilege escalation paths
- ⚠️ High-risk AD exposures

---

## ⚡ Example Output

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

```text
============================================================
Security Findings
============================================================

[CRITICAL] 3 Domain Admin Members
  ADMINISTRATOR@OFFSEC.NL
  CLARENCE_WILSON@OFFSEC.NL
  DON_ROBERTS@OFFSEC.NL

[HIGH] 165 AS-REP Roastable Users Found

[HIGH] 50 Kerberoastable Users Found
============================================================
```

---

## 🧠 Key Features

- BloodHound ZIP/JSON parsing
- Normalized AD data model
- Kerberoast detection
- AS-REP roast detection
- Domain Admin analysis
- Lightweight CLI output
- Modular analyzer system

---

## 🏗 Architecture

```text
BloodHound Data
        ↓
     Parsers
        ↓
Normalized Models
        ↓
    Analyzers
        ↓
     Findings
        ↓
     CLI Output
```

---

## 🎯 Use Cases

- Internal penetration testing
- Active Directory security audits
- Red team reconnaissance
- Attack surface reduction
- Pre-engagement analysis

---

## ⚠️ What GhostHound is NOT

GhostHound is NOT:

- ❌ A BloodHound replacement
- ❌ A graph visualization tool
- ❌ A full attack simulation framework

It is a **focused analysis engine for actionable findings**.

---

## 🚀 Roadmap

### v0.1 (Current)
- BloodHound parser
- Basic analyzers
- CLI reporting

### v0.2
- NetExec integration
- Correlation engine
- Attack path linking

### v0.3
- Risk scoring system
- Session analysis
- Lateral movement mapping

---

## 📦 Installation

```bash
git clone https://github.com/oko-ops/ghosthound
cd ghosthound
pip install -e .
```

---

## 🧪 Usage

```bash
ghosthound analyze input/
```

or

```bash
ghosthound analyze input/bloodhound.zip
```

---

## 🤝 Contributing

Contributions are welcome in:

- New analyzers
- Correlation logic
- Data parsers
- Reporting improvements

---

## 🧠 Design Philosophy

- Lightweight over complex
- Actionable over visual
- Fast over feature-heavy
- Modular over monolithic

---

## 📄 License

GPLv3 © 2026 oko-ops
