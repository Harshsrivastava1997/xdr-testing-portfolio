/**
 * HARSH SRIVASTAVA - LEAD SDET | XDR & CYBERSECURITY QA PORTFOLIO
 * Interactive Engine: Telemetry Simulator, Modal Evidence Viewer, Filter System & Lightbox
 */

document.addEventListener('DOMContentLoaded', () => {
  initTelemetrySimulator();
  initProjectFilters();
  initModals();
  initLightbox();
  initScrollSpy();
  initCopyButtons();
});

// ===================================================================
// 1. INTERACTIVE TELEMETRY & TEST SCENARIO SIMULATOR
// ===================================================================
const SIM_SCENARIOS = {
  aggressive_mode: {
    title: "EPP Aggressive Mode: LOLBin + Dual-Process Kill",
    module: "EPP Endpoint Defense",
    status: "PASS",
    latency: "42 ms",
    description: "Malicious payload spawned via PowerShell with embedded EICAR. Aggressive Mode detects malicious child activity and recursively terminates BOTH child and parent processes to prevent malware respawning.",
    tree: [
      { name: "explorer.exe", pid: 4120, role: "System Root", status: "alive", text: "ALIVE (System Host)" },
      { name: "└─ powershell.exe", pid: 8412, role: "Parent (LOLBin)", status: "killed", text: "TERMINATED BY EPP [Aggressive Mode]" },
      { name: "   ├─ conhost.exe", pid: 9104, role: "Child Helper", status: "killed", text: "TERMINATED BY EPP" },
      { name: "   └─ test_payload.py", pid: 10220, role: "Malicious Child", status: "killed", text: "TERMINATED BY EPP [EICAR Detected]" }
    ],
    telemetry: {
      "event_id": "EPP-AGG-20261025-0841",
      "event_type": "Aggressive_Mode_Dual_Kill",
      "target_binary": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "parent_pid": 8412,
      "child_pid": 10220,
      "rule_matched": "LOLBIN_EICAR_PATTERN_DETECTION",
      "mitre_technique": "T1059.001 - Command and Scripting Interpreter: PowerShell",
      "kill_latency_ms": 42.18,
      "parent_killed": true,
      "child_killed": true,
      "respawn_prevented": true,
      "verdict": "THREAT_NEUTRALIZED"
    },
    log: `[08:41:12.010] [MONITOR] Launching positive test: powershell (LOLBin with EICAR payload)
[08:41:12.015] [DISCOVERY] Root PID: 8412 (powershell.exe) spawned
[08:41:12.022] [DISCOVERY] Child PID: 9104 (conhost.exe), Child PID: 10220 (python.exe / EICAR)
[08:41:12.054] [EPP_SENSOR] Aggressive mode threat detected in child PID 10220!
[08:41:12.057] [EPP_ACTION] Sending kernel terminate signal to child PID 10220... OK
[08:41:12.062] [EPP_ACTION] Sending kernel terminate signal to parent PID 8412... OK
[08:41:12.096] [VERIFY] ProcessTreeValidator confirmed 0 alive child/parent processes.
[08:41:12.097] [RESULT] >>> TEST PASSED (Kill latency: 42.18ms) <<<`
  },

  resource_breach: {
    title: "Resource Performance Monitor: Sustained Threshold & Jira Evidence",
    module: "EPP / EDR Reliability & Telemetry",
    status: "ALERT RECORDED",
    latency: "1.0s Interval",
    description: "EPP service (eppd) sustained CPU utilization above 15% for >= 10 consecutive seconds. High-resolution telemetry recorded, PID reuse tracked, system context captured, and self-contained Jira report generated.",
    tree: [
      { name: "eppd.exe (EPP Core Service)", pid: 3410, role: "Target Focus", status: "monitored", text: "CPU: 34.6% | RAM: 312 MB (BREACH: 12s)" },
      { name: "EPP-ExploitDP.exe", pid: 4890, role: "Sub-Engine", status: "alive", text: "CPU: 2.1% | RAM: 48 MB (Normal)" },
      { name: "EDR-ADMP.exe", pid: 5122, role: "Sensor Core", status: "alive", text: "CPU: 1.4% | RAM: 64 MB (Normal)" },
      { name: "System (Chrome.exe)", pid: 11408, role: "External Baseline Context", status: "alive", text: "CPU: 42.1% | RAM: 1.2 GB (NO ALERT - Guardrail)" }
    ],
    telemetry: {
      "evidence_id": "EPP-RES-20260919-0017",
      "monitoring_session": "SESSION_PROD_SCALE_2026",
      "monitored_process": "eppd.exe",
      "target_pid": 3410,
      "breach_metric": "CPU_UTILIZATION_SUSTAINED",
      "measured_peak_cpu": "34.6%",
      "threshold_cpu": "15.0%",
      "breach_duration_seconds": 12,
      "sustained_threshold_met": true,
      "system_baseline_cpu": "78.5%",
      "external_high_procs": ["chrome.exe (42.1%)"],
      "external_proc_alert_fired": false,
      "evidence_report_generated": "Sample_Evidence_Report.html",
      "zero_causal_claim_verified": true
    },
    log: `[13:01:45.000] [SAMPLER] Polling 9 security agent processes across win-x64 host...
[13:01:48.000] [TELEMETRY] PID 3410 (eppd) CPU crossed 15% threshold (28.4%). Timer started: 3s
[13:01:52.000] [TELEMETRY] PID 3410 CPU sustains 34.6%. Elapsed: 7s
[13:01:55.000] [BREACH] Sustained breach criteria satisfied (>= 10s at 34.6% CPU).
[13:01:55.010] [ALERT] Evidence ID generated: EPP-RES-20260919-0017. Native Toast sent.
[13:01:55.025] [GUARDRAIL] External non-EDR process chrome.exe (42.1%) logged for baseline context. Zero alerts triggered.
[13:01:55.040] [JIRA_EXPORTER] 15-section self-contained HTML evidence report saved to SQLite WAL DB.`
  },

  web_filtering: {
    title: "PAC / EDR Web Filtering: Domain Interception & Sinkhole Enforcement",
    module: "EPP Web Defense",
    status: "PASS",
    latency: "0.88s",
    description: "Evaluates real-time PAC proxy and EDR network driver enforcement on blacklisted social media and malware domains. Validates block page interstitial and Elasticsearch ingestion with MITRE mapping.",
    tree: [
      { name: "chrome.exe", pid: 7820, role: "Browser Client", status: "alive", text: "HTTP GET Request Initiated" },
      { name: "└─ edr_win.ext.exe", pid: 6114, role: "EDR Network Filter", status: "alive", text: "INTERCEPTED: web.whatsapp.com" },
      { name: "   └─ PAC Proxy Driver", pid: 0, role: "Enforcement Layer", status: "killed", text: "HTTP 403 SINKHOLE / INTERSTITIAL SERVED" }
    ],
    telemetry: {
      "event_id": "e7cefb87-a6c3-47e2-833b-4ac75fa7f8ea",
      "event_type_name": "Suspicious Web Access",
      "event_type_id": "1286024",
      "tenant_id": "RUD1234",
      "provider_name": "EPP-WebFiltering",
      "blocked_domain": "web.whatsapp.com",
      "category": "socialmedia",
      "action": "quarantine / block",
      "mitre_technique_id": ["T1036"],
      "sub_technique_id": ["T1036.001"],
      "risk_score": 55,
      "index_name": "xdrevents-rud1234-2026.09.05-000001"
    },
    log: `[13:11:00.051] [PROBE] Request sent to: https://web.whatsapp.com/sw.js
[13:11:00.062] [EPP_SENSOR] Domain match: 'web.whatsapp.com' in category 'socialmedia'
[13:11:00.065] [ENFORCEMENT] Tenant rule 'Block Social Media' triggered. Connection sinkholed.
[13:11:00.070] [INTERSTITIAL] Served EPP Block Page: 'Access to this website is blocked by Enterprise EPP.'
[13:11:00.217] [CCE_PIPELINE] EDR telemetry ingested into Elasticsearch index 'xdrevents-rud1234'.
[13:11:00.220] [VERIFY] Event validated: 1286024, MITRE T1036.001, Status: PASS.`
  },

  dlp_pii: {
    title: "Data Loss Prevention (DLP): Synthetic Credit Card & Sensitive Data Intercept",
    module: "EPP PII/PHI Protection",
    status: "PASS",
    latency: "0.12s",
    description: "Synthetic credit card generation validated via Luhn checksum. Intercepts outbound buffers and file writes matching sensitive PII/PHI regex patterns without impacting legitimate traffic.",
    tree: [
      { name: "dlp_test_sender.exe", pid: 9940, role: "Data Probe", status: "alive", text: "Buffer Transmission Staged" },
      { name: "└─ EPP-Core (DLP Hook)", pid: 3410, role: "DLP Inspector", status: "alive", text: "Luhn Checksum MATCH: Synthetic Visa" },
      { name: "   └─ Kernel Filter", pid: 0, role: "Block & Alert", status: "killed", text: "EXFILTRATION ABORTED [PII Leak]" }
    ],
    telemetry: {
      "event_id": "DLP-PII-20261025-4111",
      "event_type": "Sensitive_Data_Pattern_Intercept",
      "data_classification": "PII / PCI-DSS",
      "algorithm_applied": "Luhn_Mod10_Checksum",
      "masked_card": "4111-XXXX-XXXX-4444",
      "tenant_id": "BDE1623",
      "action_taken": "BLOCK_AND_LOG",
      "false_positive_score": 0.00
    },
    log: `[14:23:01.100] [DLP_ENGINE] Monitoring file/network buffers on DESKTOP-74
[14:23:01.104] [INSPECTION] Pattern match: 16-digit numeric card string
[14:23:01.106] [ALGORITHM] Applying Luhn Mod-10 checksum validation... VALID
[14:23:01.108] [POLICY] Tenant policy 'PII/PHI Protection' = ENABLE. Blocking transfer!
[14:23:01.112] [TELEMETRY] Emitting event to CCE: Sensitive Data Pattern Intercept.
[14:23:01.115] [VERIFY] Exfiltration prevented. Telemetry verified in pipeline.`
  },

  yara_engine: {
    title: "YARA Threat Engine: Mimikatz & Credential Dumping Intercept",
    module: "EPP / EDR Memory & File Defense",
    status: "PASS",
    latency: "1.45s",
    description: "Dynamic memory injection of credential harvesting strings ('sekurlsa::logonpasswords', 'lsadump::sam'). Tested against custom and bundled YARA signature rules.",
    tree: [
      { name: "credential_dumper.exe", pid: 12480, role: "Attacker Mock", status: "killed", text: "TERMINATED [YARA Match]" },
      { name: "└─ EPP-ExploitDP", pid: 4890, role: "YARA Scanner", status: "alive", text: "Matched: Detect_Credential_Dump" },
      { name: "   └─ Memory Guard", pid: 0, role: "Anti-Dumping", status: "alive", text: "SAM & LSA Memory Access Quarantined" }
    ],
    telemetry: {
      "event_id": "YARA-THREAT-20261025-0099",
      "rule_name": "Detect_Credential_Dump",
      "strings_matched": ["sekurlsa::logonpasswords", "lsadump::sam"],
      "threat_category": "Credential Access",
      "mitre_technique": "T1003.001 - OS Credential Dumping: LSASS Memory",
      "action": "PROCESS_TERMINATE_AND_QUARANTINE",
      "file_path": "C:\\Testing\\Tools\\mimikatz_sample.exe",
      "quarantined": true
    },
    log: `[15:10:20.120] [YARA_SCANNER] Ingested rule Detect_Credential_Dump
[15:10:20.145] [TARGET_EXEC] Process 12480 attempted memory read on lsass.exe
[15:10:20.160] [YARA_MATCH] Rule Detect_Credential_Dump condition satisfied!
[15:10:20.165] [MITIGATION] Kernel signal sent: Terminate PID 12480.
[15:10:20.170] [FILE_ACTION] File moved to EPP Quarantine Vault.
[15:10:20.180] [VERIFY] Credential theft blocked. Full telemetry pipeline PASS.`
  }
};

function initTelemetrySimulator() {
  const tabBtns = document.querySelectorAll('.sim-tab-btn');
  if (!tabBtns.length) return;

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      const scenarioKey = btn.getAttribute('data-scenario');
      renderSimulator(scenarioKey);
    });
  });

  // Initial render
  renderSimulator('aggressive_mode');
}

function renderSimulator(key) {
  const data = SIM_SCENARIOS[key];
  if (!data) return;

  const headerElem = document.getElementById('sim-title');
  const moduleElem = document.getElementById('sim-module');
  const statusElem = document.getElementById('sim-status');
  const latencyElem = document.getElementById('sim-latency');
  const descElem = document.getElementById('sim-desc');
  const treeContainer = document.getElementById('sim-tree-container');
  const jsonContainer = document.getElementById('sim-json-container');
  const logContainer = document.getElementById('sim-log-container');

  if (headerElem) headerElem.innerText = data.title;
  if (moduleElem) moduleElem.innerText = data.module;
  if (statusElem) statusElem.innerText = data.status;
  if (latencyElem) latencyElem.innerText = data.latency;
  if (descElem) descElem.innerText = data.description;

  // Render Tree
  if (treeContainer) {
    treeContainer.innerHTML = '';
    data.tree.forEach(node => {
      const nodeDiv = document.createElement('div');
      nodeDiv.className = `tree-node ${node.status}`;
      nodeDiv.innerHTML = `
        <span><strong>${node.name}</strong> (PID: ${node.pid}) <span class="badge ${node.status === 'killed' ? 'badge-red' : 'badge-green'}">${node.role}</span></span>
        <span style="font-size:0.75rem; color:${node.status === 'killed' ? '#ef4444' : '#10b981'}">${node.text}</span>
      `;
      treeContainer.appendChild(nodeDiv);
    });
  }

  // Render Telemetry JSON
  if (jsonContainer) {
    jsonContainer.innerText = JSON.stringify(data.telemetry, null, 2);
  }

  // Render Log
  if (logContainer) {
    logContainer.innerText = data.log;
  }
}

// ===================================================================
// 2. PROJECT FILTERING SYSTEM
// ===================================================================
function initProjectFilters() {
  const filterBtns = document.querySelectorAll('.filter-btn');
  const projectCards = document.querySelectorAll('.project-card');

  if (!filterBtns.length) return;

  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      filterBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      const filter = btn.getAttribute('data-filter');

      projectCards.forEach(card => {
        const categories = card.getAttribute('data-category') || '';
        if (filter === 'all' || categories.includes(filter)) {
          card.style.display = 'flex';
        } else {
          card.style.display = 'none';
        }
      });
    });
  });
}

// ===================================================================
// 3. MODAL EVIDENCE VIEWER
// ===================================================================
function initModals() {
  const modal = document.getElementById('evidence-modal');
  const modalIframe = document.getElementById('modal-iframe');
  const modalTitle = document.getElementById('modal-title');
  const closeBtn = document.getElementById('modal-close');
  const viewReportBtns = document.querySelectorAll('.open-report-btn');

  if (!modal) return;

  viewReportBtns.forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      const reportUrl = btn.getAttribute('data-report');
      const title = btn.getAttribute('data-title') || 'Evidence Report Preview';

      if (modalTitle) modalTitle.innerText = title;
      if (modalIframe) modalIframe.src = reportUrl;

      modal.classList.add('open');
      document.body.style.overflow = 'hidden';
    });
  });

  const closeModal = () => {
    modal.classList.remove('open');
    if (modalIframe) modalIframe.src = '';
    document.body.style.overflow = '';
  };

  if (closeBtn) closeBtn.addEventListener('click', closeModal);
  modal.addEventListener('click', (e) => {
    if (e.target === modal) closeModal();
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && modal.classList.contains('open')) {
      closeModal();
    }
  });
}

// ===================================================================
// 4. SCREENSHOT LIGHTBOX
// ===================================================================
function initLightbox() {
  const lightboxModal = document.getElementById('lightbox-modal');
  const lightboxImg = document.getElementById('lightbox-img');
  const lightboxCaption = document.getElementById('lightbox-caption');
  const closeBtn = document.getElementById('lightbox-close');
  const galleryCards = document.querySelectorAll('.gallery-card');

  if (!lightboxModal) return;

  galleryCards.forEach(card => {
    card.addEventListener('click', () => {
      const img = card.querySelector('img');
      const title = card.querySelector('h4')?.innerText || '';
      const desc = card.querySelector('p')?.innerText || '';

      if (img && lightboxImg) {
        lightboxImg.src = img.src;
      }
      if (lightboxCaption) {
        lightboxCaption.innerHTML = `<h3 style="color:#fff; margin-bottom:4px;">${title}</h3><p style="color:#94a3b8; font-size:0.9rem;">${desc}</p>`;
      }

      lightboxModal.classList.add('open');
      document.body.style.overflow = 'hidden';
    });
  });

  const closeLightbox = () => {
    lightboxModal.classList.remove('open');
    document.body.style.overflow = '';
  };

  if (closeBtn) closeBtn.addEventListener('click', closeLightbox);
  lightboxModal.addEventListener('click', (e) => {
    if (e.target === lightboxModal) closeLightbox();
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && lightboxModal.classList.contains('open')) {
      closeLightbox();
    }
  });
}

// ===================================================================
// 5. SCROLLSPY
// ===================================================================
function initScrollSpy() {
  const sections = document.querySelectorAll('section[id]');
  const navLinks = document.querySelectorAll('.nav-links a');

  window.addEventListener('scroll', () => {
    let current = '';
    const scrollY = window.pageYOffset;

    sections.forEach(section => {
      const sectionHeight = section.offsetHeight;
      const sectionTop = section.offsetTop - 100;
      if (scrollY >= sectionTop && scrollY < sectionTop + sectionHeight) {
        current = section.getAttribute('id');
      }
    });

    navLinks.forEach(link => {
      link.classList.remove('active');
      if (link.getAttribute('href') === `#${current}`) {
        link.classList.add('active');
      }
    });
  });
}

// ===================================================================
// 6. COPY BUTTONS & UTILITIES
// ===================================================================
function initCopyButtons() {
  const copyBtns = document.querySelectorAll('.btn-copy');
  copyBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-copy-target');
      const targetElem = document.getElementById(targetId);
      if (!targetElem) return;

      const textToCopy = targetElem.innerText || targetElem.textContent;
      navigator.clipboard.writeText(textToCopy).then(() => {
        const originalText = btn.innerHTML;
        btn.innerHTML = `<span style="color:#10b981;">✓ Copied!</span>`;
        setTimeout(() => {
          btn.innerHTML = originalText;
        }, 2000);
      });
    });
  });
}
