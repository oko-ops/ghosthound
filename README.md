![Python](https://img.shields.io/badge/python-3.10+-blue)
![License](https://img.shields.io/badge/license-GPLv3-red)
![Status](https://img.shields.io/badge/status-active-green)

# 👻 GhostHound

> Lightweight Active Directory attack surface analyzer without Neo4j.

<p align="center">
  <img src="banner.png" alt="GhostHound Banner" />
</p>

<p align="center">
  <img src="demo.gif" alt="GhostHound Demo" />
</p>

---

## ⚡ TL;DR

GhostHound turns BloodHound data into **prioritized security findings** in seconds — focusing on what is exploitable, not what is visualized.

> BloodHound shows relationships.  
> GhostHound shows attack surface.

---

## ⚡ Why This Exists

Traditional AD analysis tools are powerful but:

- Require Neo4j and heavy setup
- Produce large, complex graph datasets
- Force manual interpretation of attack paths
- Slow down real-world red team workflows

👉 Result: **too much data, not enough decisions**

---

## 💡 What GhostHound Does Instead

GhostHound removes graph complexity and focuses only on **security impact**:

- 🔥 Exploitable misconfigurations
- 🔑 Credential attack opportunities
- 🧭 Privilege escalation paths
- ⚠️ High-risk Active Directory exposures

All delivered in a fast CLI workflow.

---

## ⚖️ GhostHound vs BloodHound

| Feature | BloodHound | GhostHound |
|--------|-------------|-------------|
| Core Output | Relationship Graphs | Security Findings |
| Setup | Neo4j required | No database required |
| Focus | Visualization | Exploitation insight |
| Workflow | Manual analysis | Automated prioritization |
| Speed | Heavy | Lightweight & fast |

---

## ⚡ Example Output

```text
[CRITICAL] 3 Domain Admin Members
- ADMINISTRATOR@OFFSEC.NL
- CLARENCE_WILSON@OFFSEC.NL
- DON_ROBERTS@OFFSEC.NL

[HIGH] 165 AS-REP Roastable Users

[HIGH] 50 Kerberoastable Users
```

---

## 🧠 Key Features

- BloodHound ZIP/JSON parsing
- Normalized AD object model
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

- Active Directory security assessments
- Red team reconnaissance
- Internal penetration testing
- Attack surface review
- Pre-engagement analysis

---

## ⚠️ Scope

GhostHound is NOT:

- ❌ A BloodHound replacement
- ❌ A graph visualization tool
- ❌ A full attack simulation framework

It is a **focused analysis engine for actionable AD security findings**.

---

## 🚀 Roadmap

### v0.1 (Current)
- BloodHound parser
- Core analyzers
- CLI reporting

### v0.2
- NetExec integration
- Correlation engine
- Attack path linking

### v0.3
- Risk scoring system
- Session correlation
- Lateral movement analysis

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

Pull requests are welcome:

- New analyzers
- Data parsers
- Correlation logic
- Reporting improvements

---

## 📄 License

GPLv3 © 2026 oko-ops
