# Harsh Srivastava — Lead SDET | XDR & Cybersecurity Quality Engineering Portfolio

> **Production-grade portfolio website showcasing 6+ years of Quality Engineering, Living-off-the-Land (LOLBin) Malware Detonation Engines, High-Precision Endpoint Telemetry, and Indisputable Forensic Evidence Generation across Enterprise Cybersecurity Platforms.**

---

## 🚀 Live Public Portfolio & Quickstart

- **Live Public URL**: **https://harshsrivastava1997.github.io/xdr-testing-portfolio/**
- **GitHub Repository**: **https://github.com/Harshsrivastava1997/xdr-testing-portfolio**

---

## 🎯 What Makes This Portfolio Stand Out in Interviews

This portfolio was crafted specifically for **Senior SDET, Lead SDET, and Cybersecurity QA Automation** technical interviews at top-tier security companies (e.g. CrowdStrike, SentinelOne, Palo Alto Networks, Microsoft Defender, Fortinet, Sophos).

### 1. Interactive Telemetry Simulator ("Show, Don't Just Tell")
Interviewers can click between 5 live automated test scenarios:
- **EPP Aggressive Defense**: Demonstrates recursive LOLBin execution (PowerShell + test payload) and simultaneous dual-process termination (`ProcessTreeValidator`).
- **Endpoint Performance Monitor**: Sustained CPU threshold breach ($\ge 10s$ at 34.6%) triggering Evidence ID with external process noise isolation.
- **Web Filtering & Sinkhole Enforcement**: Domain interception with MITRE ATT&CK `T1036.001` telemetry.
- **DLP Sensitive Data Intercept**: Luhn Mod-10 checksum validation on synthetic credit cards.
- **YARA In-Memory Threat Engine**: Real-time memory scanning for credential dump strings.

### 2. Six Real-World Case Studies with Actual Engineering Metrics
1. **EPP Aggressive Defense Anti-Respawn & LOLBin Testing Engine** (Python 3.11, psutil, Windows Subsystems, 10 LOLBins, 5 safe negative tests, 42ms kill latency).
2. **Portable Endpoint Performance Monitor & Objective Evidence Generator** (C# .NET 8, WPF, SQLite WAL, 9 security daemons monitored, zero causal claims).
3. **End-to-End Black-Box Security Feature Validation Suite** (14/14 tests PASS across Web Filtering, Blacklist, Whitelist, Device Control, YARA, DLP).
4. **Distributed Threat Telemetry & SIEM Event Correlation Engine** (Docker microservices root-cause engineering on Linux systems; verified active containment and schema mappings).
5. **1,340+ Malware Detonation & Automated Quarantine Reliability Benchmark** (Automated detonation pipeline measuring detection rates across RATs, Worms, Ransomware, Stealers).
6. **Cross-Platform Network Gateway & Multi-Threaded Probe Engine** (Cross-platform testing; validated 16+ enterprise device parsers and Windows EventID 4624/4625).

### 3. Core Security Testing Architecture & Framework Workflows
Interactive architectural breakdowns and verification code for:
- Recursive Process Tree & Anti-Respawn Flow
- High-Resolution Resource Telemetry Pipeline
- Network Threat Interception & DNS Sinkhole Engine
- Synthetic PII & Algorithmic DLP Intercept
- In-Memory Signature & YARA Inspection
- Distributed Telemetry & SIEM Ingestion Flow

---

## 📁 Repository Directory Structure

```text
xdr-testing-portfolio/
│
├── index.html                   # Main high-tech single-page application portfolio
├── README.md                    # Setup, architecture & interview walkthrough
│
├── css/
│   └── style.css                # Custom SOC cyber theme, dark mode & responsive styles
│
├── js/
│   └── main.js                  # Telemetry simulator, architecture modals, filter engine
│
└── assets/
    ├── docs/
    │   └── Harsh_Srivastava_Lead_SDET.pdf   # Resume (PDF)
    │
    └── images/
        └── harsh_profile.jpg                # Profile photo
```

---

## 💼 Interview Talking Points Cheat Sheet

When asked in interviews:
- *"Tell me about a challenging test framework you built from scratch:"*
  > Discuss **Feature 1 (EPP Aggressive Defense)**. Explain how malware abuses living-off-the-land binaries (PowerShell, Certutil, WMIC) to respawn from parent processes, and how you architected `ProcessTreeValidator` to track recursive process nodes and measure dual-process kill latencies down to 42 milliseconds.

- *"How do you handle customer escalations regarding agent performance?"*
  > Discuss **Feature 2 (Performance Monitor)**. Explain your architectural decision to build a single-file portable tool in C# .NET 8 (avoiding Python environment contamination), implementing normalized CPU math across logical cores, filtering transient spikes via a $\ge 10s$ sustained threshold guardrail, and maintaining strict "Zero Causal Claims" in Jira-ready evidence.

- *"Tell me about a time you investigated a distributed systems bug:"*
  > Discuss **Feature 4 (SIEM & Telemetry Correlation)**. Explain how you inspected distributed microservices on Linux, diagnosed an `ImportError` in active containment daemons, and resolved a datastore schema type collision that had been silently dropping telemetry.

---
*Created for Harsh Srivastava — Lead SDET & XDR Quality Engineering Specialist.*
