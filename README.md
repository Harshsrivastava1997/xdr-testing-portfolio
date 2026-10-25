# Harsh Srivastava — Lead SDET | XDR & Cybersecurity QA Portfolio

> **Production-grade portfolio website showcasing 6+ years of Quality Engineering, Living-off-the-Land (LOLBin) Malware Detonation Engines, High-Precision Endpoint Telemetry, and Indisputable Forensic Evidence Generation across Enterprise Cybersecurity Platforms.**

---

## 🚀 Live Local Quickstart

You can view the portfolio immediately in any web browser:

1. **Option 1 (Direct)**: Double-click [index.html](file:///c:/Users/Dell/Desktop/XDR-Testing-portfolio/index.html) to open directly in Google Chrome, Microsoft Edge, or Mozilla Firefox.
2. **Option 2 (Local Web Server)**:
   ```bash
   python -m http.server 8000
   ```
   Then open `http://localhost:8000` in your browser.
3. **Option 3 (1-Click Deployment to GitHub Pages / Vercel)**:
   - Push this directory to a GitHub repository (`harsh-xdr-portfolio`).
   - Go to **Settings -> Pages -> Deploy from branch -> main / root**.
   - Your portfolio will be live at `https://<username>.github.io/harsh-xdr-portfolio/`!

---

## 🎯 What Makes This Portfolio Stand Out in Interviews

This portfolio was crafted specifically for **Senior SDET, Lead SDET, and Cybersecurity QA Automation** technical interviews at top-tier security companies (e.g. CrowdStrike, SentinelOne, Palo Alto Networks, Microsoft Defender, Fortinet, Sophos).

### 1. Interactive Telemetry Simulator ("Show, Don't Just Tell")
Interviewers can click between 5 live automated test scenarios:
- **EPP Aggressive Mode**: Demonstrates recursive LOLBin execution (PowerShell + EICAR) and simultaneous dual-process termination (`ProcessTreeValidator`).
- **Performance Monitor Breach**: Sustained CPU threshold breach ($\ge 10s$ at 34.6%) triggering Evidence ID `EPP-RES-20260919-0017` with external process noise isolation.
- **Web Filtering & Sinkhole Enforcement**: Domain interception of `web.whatsapp.com` with MITRE ATT&CK `T1036.001` telemetry.
- **DLP Sensitive Data Intercept**: Luhn Mod-10 checksum validation on synthetic credit cards.
- **YARA Threat Engine**: Real-time memory scanning for Mimikatz and credential dump strings.

### 2. Six Real-World Case Studies with Actual Engineering Metrics
1. **EPP Aggressive Mode Anti-Respawn & LOLBin Testing Engine** (Python 3.11, psutil, Windows Subsystems, 10 LOLBins, 5 safe negative tests, 42ms kill latency).
2. **Enterprise EPP/EDR Portable Performance Monitor** (C# .NET 8, WPF, SQLite WAL, 9 security daemons monitored, zero causal claims, 15-section Jira HTML evidence reports).
3. **EPP Black-Box E2E Automated Security Validation Suite** (14/14 tests PASS across Web Filtering, Blacklist, Whitelist, Device Control, YARA, DLP).
4. **EDR & CCE Reliability Audit** (Docker microservices root-cause engineering on Rocky Linux 9.5; fixed `websocket` library crash in `cce-remediation` and OpenSearch `FreeGB` float mapping conflict).
5. **1,349 Live Malware Quarantine Benchmark** (Automated detonation pipeline measuring detection rates across RATs, Worms, Ransomware, Stealers).
6. **Linux Web Filter Tester & SIEM Device Integration Parsers** (Cross-platform testing on port 18081; validated 16+ enterprise device parsers and Windows EventID 4624/4625).

### 3. Real Console Artifacts & Forensic Evidence Reports
- **Interactive Report Modal**: Preview the actual 15-section Jira Evidence Report (`Sample_Evidence_Report.html`) and E2E BlackBox report (`EPP_BlackBox_E2E_Report.html`) directly within the site.
- **Console Gallery**: High-resolution screenshots of the Enterprise MSSP Dashboard, PMax Configuration, EDR Rules Page, Device Control toggles, and Web Filtering categories.
- **Interview Architecture Q&A**: Battle-tested answers to the top 6 hardest EDR/XDR testing questions.

---

## 📁 Repository Directory Structure

```text
XDR-Testing-portfolio/
│
├── index.html                   # Main high-tech single-page application portfolio
├── README.md                    # Setup, architecture & interview walkthrough
│
├── css/
│   └── style.css                # Custom SOC cyber theme, dark mode & responsive styles
│
├── js/
│   └── main.js                  # Telemetry simulator, modal preview, filter engine & lightbox
│
└── assets/
    ├── docs/                    # PDF resumes and technical audit reports
    │   ├── Harsh_Srivastava_Lead_SDET.pdf
    │   ├── Performance_Monitor_Report.pdf
    │   └── EDR_System_Health_Audit_Report.pdf
    │
    ├── images/                  # Real console screenshots & profile photo
    │   ├── harsh_profile.jpg
    │   ├── XDR_MSSP_Dashboard.png
    │   ├── aiXDR_PMax_Configuration.png
    │   ├── EDR_Rules_Page.png
    │   ├── features_dc_enabled.png
    │   ├── wf_categories_configured.png
    │   ├── dc_block_all_selected.png
    │   ├── Rudra_Test_Tenant_Dashboard.png
    │   ├── Rule_Created_Screenshot.png
    │   └── Rule_Updated_Final.png
    │
    └── reports/                 # Standalone HTML evidence reports for preview
        ├── Sample_Evidence_Report.html
        ├── EPP_Aggressive_Mode_Testing_Guide.html
        └── EPP_BlackBox_E2E_Report.html
```

---

## 💼 Interview Talking Points Cheat Sheet

When asked in interviews:
- *"Tell me about a challenging test framework you built from scratch:"*
  > Discuss **Project 1 (EPP Aggressive Mode)**. Explain how malware abuses living-off-the-land binaries (PowerShell, Certutil, WMIC) to respawn from parent processes, and how you architected `ProcessTreeValidator` to track recursive process nodes and measure dual-process kill latencies down to 42 milliseconds.

- *"How do you handle customer escalations regarding agent performance?"*
  > Discuss **Project 2 (Performance Monitor)**. Explain your architectural decision to build a single-file portable tool in C# .NET 8 (avoiding Python environment contamination), implementing normalized CPU math across logical cores, filtering transient spikes via a $\ge 10s$ sustained threshold guardrail, and maintaining strict "Zero Causal Claims" in Jira-ready HTML evidence.

- *"Tell me about a time you investigated a distributed systems bug:"*
  > Discuss **Project 4 (EDR/CCE Reliability Audit)**. Explain how you inspected 14 Docker microservices on Rocky Linux, diagnosed an `ImportError` in `cce-remediation` caused by conflicting Python websocket packages, and resolved an OpenSearch HTTP 400 schema collision that had been silently dropping telemetry.

---
*Created for Harsh Srivastava — Lead SDET & XDR Quality Engineering Specialist.*
