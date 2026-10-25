/**
 * HARSH SRIVASTAVA - LEAD SDET | XDR & CYBERSECURITY QUALITY ENGINEERING
 * Interactive Engine: Telemetry Simulator, Framework Architecture Modals, Filters & Utilities
 */

document.addEventListener('DOMContentLoaded', () => {
  initTelemetrySimulator();
  initProjectFilters();
  initArchitectureModals();
  initScrollSpy();
  initCopyButtons();
  initContact();
});

// ===================================================================
// 1. INTERACTIVE TELEMETRY & TEST SCENARIO SIMULATOR (100% SYNTHETIC)
// ===================================================================
const SIM_SCENARIOS = {
  aggressive_mode: {
    title: "EPP Aggressive Defense: Recursive Process Tree & Anti-Respawn Validation",
    module: "Endpoint Protection (EPP)",
    status: "PASS",
    latency: "42 ms",
    description: "Evaluates automated detection of child process threats spawned via Living-off-the-Land Binaries (LOLBins). Verifies that the endpoint agent recursively terminates both child and parent process trees within milliseconds to prevent malware respawning.",
    tree: [
      { name: "explorer.exe", pid: 4120, role: "System Root", status: "alive", text: "ACTIVE (Legitimate User Shell)" },
      { name: "└─ powershell.exe", pid: 8412, role: "Parent (LOLBin)", status: "killed", text: "TERMINATED BY AGENT [Parent Kill]" },
      { name: "   ├─ conhost.exe", pid: 9104, role: "Child Helper", status: "killed", text: "TERMINATED BY AGENT" },
      { name: "   └─ payload_sample.exe", pid: 10220, role: "Malicious Child", status: "killed", text: "TERMINATED BY AGENT [Threat Signature]" }
    ],
    telemetry: {
      "event_id": "EVT-EPP-2026-0841",
      "event_type": "Recursive_Tree_Termination",
      "target_binary": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "parent_pid": 8412,
      "child_pid": 10220,
      "rule_matched": "LOLBIN_ANOMALOUS_EXECUTION",
      "mitre_technique": "T1059.001 - Command and Scripting Interpreter: PowerShell",
      "kill_latency_ms": 42.18,
      "parent_killed": true,
      "child_killed": true,
      "anti_respawn_verified": true,
      "verdict": "THREAT_CONTAINED"
    },
    log: `[08:41:12.010] [HARNESS] Initiating positive test: powershell.exe with test payload
[08:41:12.015] [DISCOVERY] ProcessTreeValidator registered root PID 8412
[08:41:12.022] [DISCOVERY] Spawned child PID: 9104 (conhost.exe), Child PID: 10220 (payload_sample.exe)
[08:41:12.054] [AGENT_SENSOR] Malicious child activity flagged on PID 10220
[08:41:12.057] [AGENT_KERNEL] Emitting terminate signal to child PID 10220... SUCCESS
[08:41:12.062] [AGENT_KERNEL] Emitting terminate signal to parent PID 8412... SUCCESS
[08:41:12.096] [TREE_VALIDATOR] Refreshing process tree status: 0 active child/parent processes remaining
[08:41:12.097] [RESULT] >>> TEST STATUS: PASS (Total Dual-Kill Latency: 42.18ms) <<<`
  },

  resource_breach: {
    title: "Endpoint Resource Performance & Sustained Threshold Benchmarking",
    module: "EDR Performance & Telemetry",
    status: "ALERT RECORDED",
    latency: "1.0s Interval",
    description: "Monitors endpoint security agent processes at 1-second intervals with logical CPU normalization. Enforces a sustained breach guardrail (>= 10 seconds above threshold) to eliminate false transient alerts while capturing non-security processes for objective baseline context.",
    tree: [
      { name: "endpoint_core_agent.exe", pid: 3410, role: "Target Focus", status: "monitored", text: "CPU: 34.6% | RAM: 312 MB (Sustained: 12s)" },
      { name: "edr_sensor_svc.exe", pid: 4890, role: "Sensor Daemon", status: "alive", text: "CPU: 1.8% | RAM: 52 MB (Normal Baseline)" },
      { name: "edr_extension_host.exe", pid: 5122, role: "Extension Daemon", status: "alive", text: "CPU: 1.1% | RAM: 64 MB (Normal Baseline)" },
      { name: "External (browser_process.exe)", pid: 11408, role: "Baseline Context", status: "alive", text: "CPU: 42.1% | RAM: 1.2 GB (NO ALERT - Guardrail)" }
    ],
    telemetry: {
      "evidence_id": "PERF-EV-202609-0017",
      "session_name": "BENCHMARK_PROD_SCALE",
      "monitored_process": "endpoint_core_agent.exe",
      "target_pid": 3410,
      "breach_metric": "CPU_UTILIZATION_SUSTAINED",
      "measured_peak_cpu": "34.6%",
      "threshold_cpu": "15.0%",
      "breach_duration_seconds": 12,
      "sustained_threshold_met": true,
      "host_total_cpu": "78.5%",
      "external_high_procs": ["browser_process.exe (42.1%)"],
      "external_proc_alert_fired": false,
      "zero_causal_claim_verified": true
    },
    log: `[13:01:45.000] [SAMPLER] Sampling 9 core endpoint security processes across win-x64 host...
[13:01:48.000] [TELEMETRY] PID 3410 CPU utilization crossed 15% threshold (28.4%). Breach timer: 3s
[13:01:52.000] [TELEMETRY] PID 3410 CPU sustained at 34.6%. Breach timer: 7s
[13:01:55.000] [GUARDRAIL] Sustained threshold condition satisfied (>= 10s at 34.6% CPU)
[13:01:55.010] [ALERT] Evidence ID generated: PERF-EV-202609-0017. Native OS toast notification sent.
[13:01:55.025] [CONTEXT] External process browser_process.exe (42.1%) captured for host baseline. Zero alerts fired.
[13:01:55.040] [RECORDER] Full 15-section self-contained forensic evidence report archived to SQLite.`
  },

  web_filtering: {
    title: "Network & Web Filtering: Domain Interception & DNS Sinkholing",
    module: "Network EDR / Proxy Filter",
    status: "PASS",
    latency: "0.88s",
    description: "Validates driver-level network proxy filtering and DNS sinkhole enforcement against categorized blacklists. Ensures network timeouts and DNS errors are strictly isolated and not falsely scored as security policy blocks.",
    tree: [
      { name: "browser_client.exe", pid: 7820, role: "Client Application", status: "alive", text: "Outbound HTTPS Request Initiated" },
      { name: "└─ edr_network_filter.sys", pid: 6114, role: "Kernel Network Driver", status: "alive", text: "INTERCEPTED: unauthorized-domain-test.com" },
      { name: "   └─ DNS Sinkhole Proxy", pid: 0, role: "Enforcement Layer", status: "killed", text: "HTTP 403 SINKHOLE / INTERSTITIAL SERVED" }
    ],
    telemetry: {
      "event_id": "EVT-NET-2026-1286",
      "event_type": "Suspicious_Web_Access_Blocked",
      "event_type_id": "1286024",
      "tenant_id": "TENANT-SECURITY-01",
      "blocked_domain": "unauthorized-domain-test.com",
      "category": "High_Risk_Category",
      "enforcement_action": "SINKHOLE_AND_BLOCK",
      "mitre_technique_id": ["T1036"],
      "sub_technique_id": ["T1036.001"],
      "risk_score": 55,
      "siem_index": "securityevents-tenant01-telemetry"
    },
    log: `[13:11:00.051] [PROBE] Dispatching automated test probe to: https://unauthorized-domain-test.com
[13:11:00.062] [FILTER_SENSOR] Domain match identified in policy category 'High_Risk_Category'
[13:11:00.065] [ENFORCEMENT] Tenant rule 'Block High Risk' applied. Connection routed to DNS sinkhole.
[13:11:00.070] [INTERSTITIAL] Served security block interstitial: 'Access to this website is blocked by Security Policy.'
[13:11:00.217] [SIEM_PIPELINE] Normalized telemetry event ingested into SIEM cluster index.
[13:11:00.220] [VERIFY] Telemetry validated: Event ID 1286024, MITRE T1036.001, Status: PASS.`
  },

  dlp_pii: {
    title: "Data Loss Prevention (DLP): Synthetic PII & Algorithmic Card Checksum",
    module: "Data Loss Prevention (DLP)",
    status: "PASS",
    latency: "0.12s",
    description: "Evaluates real-time buffer interception for sensitive financial and identity records. Uses algorithmic Luhn Mod-10 verification on synthetic card numbers to eliminate false positive triggers on random 16-digit strings.",
    tree: [
      { name: "test_data_sender.exe", pid: 9940, role: "Exfiltration Probe", status: "alive", text: "Buffer Transmission Staged" },
      { name: "└─ edr_dlp_driver.sys", pid: 3410, role: "Kernel DLP Hook", status: "alive", text: "Luhn Checksum MATCH: Synthetic Visa" },
      { name: "   └─ Outbound Filter", pid: 0, role: "Block & Alert", status: "killed", text: "TRANSMISSION DROPPED [DLP Policy]" }
    ],
    telemetry: {
      "event_id": "EVT-DLP-2026-4111",
      "event_type": "Sensitive_Data_Pattern_Intercepted",
      "data_classification": "PII / PCI-DSS",
      "algorithm_applied": "Luhn_Mod10_Checksum",
      "masked_identifier": "4111-XXXX-XXXX-4444",
      "tenant_id": "TENANT-CORP-SEC",
      "action_taken": "BLOCK_AND_LOG",
      "false_positive_score": 0.00
    },
    log: `[14:23:01.100] [DLP_ENGINE] Inspecting file I/O and network payload buffers on test host
[14:23:01.104] [INSPECTION] Pattern match: 16-digit numeric card structure detected
[14:23:01.106] [ALGORITHM] Executing algorithmic Luhn Mod-10 checksum validation... VALID CARD NUMBER
[14:23:01.108] [POLICY] Tenant policy 'Financial PII/PHI Protection' = ENABLED. Intercepting transfer!
[14:23:01.112] [TELEMETRY] Emitting normalized alert to SIEM: Sensitive Data Exfiltration Intercepted.
[14:23:01.115] [VERIFY] Exfiltration prevented. DLP telemetry verified in pipeline.`
  },

  yara_engine: {
    title: "In-Memory Signature Detection: YARA Rule Memory Scan Validation",
    module: "Memory & Signature Defense",
    status: "PASS",
    latency: "1.45s",
    description: "Tests live memory scanning against credential harvesting patterns (e.g. sekurlsa and LSASS dumping signatures). Verifies process quarantine and memory access termination before credential theft completes.",
    tree: [
      { name: "credential_dumper_mock.exe", pid: 12480, role: "Attacker Mock", status: "killed", text: "TERMINATED [YARA Signature Match]" },
      { name: "└─ edr_exploit_guard.exe", pid: 4890, role: "YARA Scanner", status: "alive", text: "Matched Rule: Detect_Credential_Dump" },
      { name: "   └─ Memory Protection", pid: 0, role: "Anti-Dumping Guard", status: "alive", text: "LSASS Process Memory Quarantined" }
    ],
    telemetry: {
      "event_id": "EVT-YARA-2026-0099",
      "rule_name": "Detect_Credential_Dump",
      "strings_matched": ["sekurlsa::logonpasswords", "lsadump::sam"],
      "threat_category": "Credential Access",
      "mitre_technique": "T1003.001 - OS Credential Dumping: LSASS Memory",
      "action": "PROCESS_TERMINATE_AND_QUARANTINE",
      "file_path": "C:\\Testing\\Tools\\mock_dumper.exe",
      "quarantined": true
    },
    log: `[15:10:20.120] [YARA_SCANNER] Ingested custom threat detection rule: Detect_Credential_Dump
[15:10:20.145] [TARGET_EXEC] Process 12480 attempted memory read on lsass.exe address space
[15:10:20.160] [YARA_MATCH] Rule signature condition satisfied in process memory buffer!
[15:10:20.165] [MITIGATION] Kernel signal sent: Terminate PID 12480 immediately.
[15:10:20.170] [FILE_ACTION] Binary moved to Secure Endpoint Quarantine Vault.
[15:10:20.180] [VERIFY] Credential theft blocked. Full telemetry pipeline verified PASS.`
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
// 3. ARCHITECTURE DETAILS MODAL
// ===================================================================
const ARCHITECTURE_DETAILS = {
  process_tree: {
    title: "Recursive Process Tree & Anti-Respawn Architecture",
    category: "EPP Endpoint Defense",
    overview: "How automated testing validates dual-process tree termination when malware executes via Living-off-the-Land Binaries (LOLBins).",
    steps: [
      { step: "1. Process Spawn Interception", desc: "Test runner spawns root administrative binary (e.g. powershell.exe, wmic.exe, mshta.exe) with synthetic threat payload." },
      { step: "2. Recursive Hierarchy Discovery", desc: "ProcessTreeValidator recursively queries OS job objects to discover all spawned helper and child PIDs in real time." },
      { step: "3. Millisecond Kill Latency Hook", desc: "Captures high-resolution performance counters to measure the exact delta between payload drop and agent kill signals." },
      { step: "4. Dual-Process Termination Verification", desc: "Validates that the endpoint kernel driver kills BOTH the offending child AND the parent LOLBin to prevent respawn." },
      { step: "5. Safe Baseline Regression", desc: "Runs 5 negative test cases (safe CMD, safe Notepad, safe Ping) to ensure legitimate administration tools are never terminated." }
    ],
    code: `class ProcessTreeValidator:
    def __init__(self, root_pid, timeout=60):
        self.root_pid = root_pid
        self.timeout = timeout
        self.tree = self.build_process_tree(root_pid)

    def validate_dual_kill(self):
        # Verify both child and parent processes are neutralized
        alive_procs = self.get_alive_processes()
        kill_latency_ms = self._calculate_latencies()
        return len(alive_procs) == 0, kill_latency_ms`
  },

  resource_monitor: {
    title: "High-Resolution Resource Telemetry & Sustained Threshold Pipeline",
    category: "EDR Performance & Reliability",
    overview: "Zero-dependency portable resource monitor architecture designed in C# .NET 8 to resolve customer CPU/memory disputes with indisputable objective evidence.",
    steps: [
      { step: "1. Normalized Multi-Core Sampling", desc: "Samples security processes at 1-second intervals, normalizing CPU usage against total logical processor count." },
      { step: "2. Sustained Threshold Guardrail", desc: "Applies a temporal filter: alerts trigger ONLY if CPU > 15% or RAM > 200MB sustained for >= 10 consecutive seconds, filtering transient spikes." },
      { step: "3. External System Baseline Context", desc: "Simultaneously records non-security high-resource processes (e.g. Chrome, IDEs) for comparative baseline context without alerting on them." },
      { step: "4. SQLite WAL Persistence", desc: "Batched asynchronous writes to embedded SQLite database in Write-Ahead-Log (WAL) mode with zero host performance impact." },
      { step: "5. Self-Contained Jira Report", desc: "Generates an offline, 15-section HTML report with embedded vector SVG charts, exact timestamps, and strict zero-causal compliance." }
    ],
    code: `// Normalized CPU utilization calculation
double rawCpuUsage = (currentCpuTime - previousCpuTime).TotalMilliseconds;
double elapsedTotal = (currentTime - previousTime).TotalMilliseconds;
double normalizedCpu = (rawCpuUsage / (elapsedTotal * Environment.ProcessorCount)) * 100.0;

// Sustained breach condition (>= 10 seconds continuous)
if (normalizedCpu > ThresholdCpu) {
    consecutiveBreachSeconds++;
    if (consecutiveBreachSeconds >= 10 && !alertTriggered) {
        TriggerEvidenceAlert(EvidenceId.Generate());
    }
}`
  },

  web_filter: {
    title: "Network Threat Interception & DNS Sinkhole Probe Engine",
    category: "Network EDR & Gateway Security",
    overview: "Automated multi-threaded test harness evaluating real-time driver proxy filtering and sinkhole routing against categorized URL blacklists.",
    steps: [
      { step: "1. Concurrent Probe Generation", desc: "ThreadPoolExecutor dispatches multi-threaded DNS lookups and HTTPS cURL requests across thousands of test URLs." },
      { step: "2. Interception Signature Detection", desc: "Detects security proxy block interstitials, injected headers, and DNS sinkhole redirection IPs." },
      { step: "3. Strict Error Isolation", desc: "Separates DNS resolution failures and network timeouts from security blocks, ensuring timeouts are never misclassified as policy passes." },
      { step: "4. Distributed Telemetry Verification", desc: "Queries SIEM API to ensure blocked web requests are indexed with MITRE ATT&CK T1036.001 taxonomy and accurate tenant IDs." }
    ],
    code: `def probe_domain(domain, policy_type, sinkhole_ips):
    dns_resolved_ip = resolve_dns(domain)
    if dns_resolved_ip in sinkhole_ips:
        return "BLOCKED_SINKHOLE"
    response = requests.get(f"https://{domain}", timeout=10, verify=False)
    if is_block_interstitial(response.text):
        return "BLOCKED_INTERSTITIAL"
    return "ALLOWED" if response.status_code == 200 else "ERROR_NETWORK"`
  },

  dlp_pipeline: {
    title: "Synthetic PII & Algorithmic DLP Intercept Architecture",
    category: "Data Loss Prevention (DLP)",
    overview: "End-to-end testing of data loss prevention hooks across file writes, clipboard, and network buffers using programmatic checksum verification.",
    steps: [
      { step: "1. Algorithmic Synthetic Card Generation", desc: "Generates synthetic Visa/Mastercard/Amex numbers mathematically valid under Luhn Mod-10 algorithm." },
      { step: "2. Buffer Exfiltration Staging", desc: "Stages synthetic PII payloads (SSN, national IDs, credit cards, emails) across mock network streams and disk I/O." },
      { step: "3. Driver-Level Inspection & Intercept", desc: "Validates that endpoint DLP filter drivers intercept the transfer before payload leaves host memory." },
      { step: "4. False-Positive Validation", desc: "Executes control batches of random numeric strings to confirm non-Luhn numbers pass without false alarm triggers." }
    ],
    code: `def verify_luhn_checksum(card_number_str):
    digits = [int(d) for d in card_number_str if d.isdigit()]
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += (doubled - 9) if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0`
  },

  yara_scan: {
    title: "In-Memory Signature & YARA Inspection Engine",
    category: "Memory & Signature Defense",
    overview: "Testing methodology for dynamic memory and disk pattern scanning against credential theft, LSASS dumping, and obfuscated payload execution.",
    steps: [
      { step: "1. Rule Compilation & Ingestion", desc: "Compiles custom YARA rules targeting credential dumping strings (e.g. sekurlsa::logonpasswords, lsadump::sam)." },
      { step: "2. Controlled Memory Injection", desc: "Spawns sandbox test process allocating heap/stack buffers containing target signature strings." },
      { step: "3. Memory Scanner Detection", desc: "Confirms endpoint agent scanner detects signature matches in active process memory." },
      { step: "4. Remediation & Quarantine", desc: "Validates process termination, memory dump abort, and file isolation into secure quarantine storage." }
    ],
    code: `rule Detect_Credential_Dump {
    meta:
        description = "Detects credential dumping indicators in process memory"
    strings:
        $a = "sekurlsa::logonpasswords"
        $b = "lsadump::sam"
        $c = "powershell -enc"
    condition:
        any of them
}`
  },

  siem_correlation: {
    title: "Distributed Telemetry & SIEM Ingestion Flow",
    category: "SIEM & Log Correlation",
    overview: "Verifying end-to-end log parsing, schema mapping, and correlation rule triggers across multi-vendor enterprise security formats.",
    steps: [
      { step: "1. Syslog & Event Stream Ingestion", desc: "Injects synthetic RFC 5424 Syslog and Windows Security Event logs (EventID 4624/4625/4776)." },
      { step: "2. Parser Schema Validation", desc: "Validates field extraction (source IP, destination user, event type ID, platform) against strict YAML schemas." },
      { step: "3. MITRE ATT&CK Enrichment", desc: "Verifies automated tagging of tactics and technique IDs (e.g. T1059 Command Execution, T1036 Masquerading)." },
      { step: "4. Indexing & Telemetry Verification", desc: "Queries OpenSearch REST APIs to confirm zero document drops, correct type mappings, and real-time alert generation." }
    ],
    code: `schema:
  platform: Windows
  event_ids:
    "2000001":
      match: EventID
      patterns: "^4624$"
      category: Authentication
      eventtype: Host Login Success
      outcome: success
    "2000002":
      match: EventID
      patterns: "^4625$|^4776$"
      category: Authentication
      eventtype: Host Login Failure
      outcome: failure`
  }
};

function initArchitectureModals() {
  const modal = document.getElementById('architecture-modal');
  const modalTitle = document.getElementById('arch-modal-title');
  const modalCategory = document.getElementById('arch-modal-cat');
  const modalOverview = document.getElementById('arch-modal-overview');
  const modalSteps = document.getElementById('arch-modal-steps');
  const modalCode = document.getElementById('arch-modal-code');
  const closeBtn = document.getElementById('arch-modal-close');
  const archCards = document.querySelectorAll('.arch-card');

  if (!modal) return;

  archCards.forEach(card => {
    card.addEventListener('click', () => {
      const archKey = card.getAttribute('data-arch');
      const data = ARCHITECTURE_DETAILS[archKey];
      if (!data) return;

      if (modalTitle) modalTitle.innerText = data.title;
      if (modalCategory) modalCategory.innerText = data.category;
      if (modalOverview) modalOverview.innerText = data.overview;

      if (modalSteps) {
        modalSteps.innerHTML = '';
        data.steps.forEach(s => {
          const stepDiv = document.createElement('div');
          stepDiv.className = 'arch-step-item';
          stepDiv.innerHTML = `
            <h4 style="color:#00f0ff; font-size:0.95rem; margin-bottom:4px;">${s.step}</h4>
            <p style="color:#cbd5e1; font-size:0.88rem; line-height:1.5;">${s.desc}</p>
          `;
          modalSteps.appendChild(stepDiv);
        });
      }

      if (modalCode) {
        modalCode.innerText = data.code;
      }

      modal.classList.add('open');
      document.body.style.overflow = 'hidden';
    });
  });

  const closeModal = () => {
    modal.classList.remove('open');
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
// 4. SCROLLSPY
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
// 5. COPY BUTTONS & UTILITIES
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

// ===================================================================
// 6. CONTACT & CLIPBOARD UTILITIES
// ===================================================================
const PRIMARY_EMAIL = "harshvns0102@gmail.com";

function showToast(message) {
  const toast = document.getElementById('toast-notify');
  const msgElem = document.getElementById('toast-message');
  if (!toast) return;
  if (msgElem) msgElem.textContent = message;
  toast.classList.add('show');
  setTimeout(() => {
    toast.classList.remove('show');
  }, 3200);
}

function copyToClipboard(text, onSuccess) {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(() => {
      if (onSuccess) onSuccess();
      showToast(`Copied ${text} to clipboard!`);
    }).catch(() => {
      fallbackCopy(text, onSuccess);
    });
  } else {
    fallbackCopy(text, onSuccess);
  }
}

function fallbackCopy(text, onSuccess) {
  const textArea = document.createElement('textarea');
  textArea.value = text;
  textArea.style.position = 'fixed';
  textArea.style.left = '-9999px';
  textArea.style.top = '-9999px';
  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();
  try {
    document.execCommand('copy');
    if (onSuccess) onSuccess();
    showToast(`Copied ${text} to clipboard!`);
  } catch (err) {
    prompt('Copy email manually:', text);
  }
  document.body.removeChild(textArea);
}

function initContact() {
  const contactModal = document.getElementById('contact-modal');
  const contactModalClose = document.getElementById('contact-modal-close');
  const navContactBtn = document.getElementById('nav-contact-btn');
  const profileEmailBadge = document.getElementById('profile-email-badge');

  const openContactModal = (e) => {
    if (e) e.preventDefault();
    if (!contactModal) {
      const contactSection = document.getElementById('contact');
      if (contactSection) contactSection.scrollIntoView({ behavior: 'smooth' });
      return;
    }
    contactModal.classList.add('open');
    document.body.style.overflow = 'hidden';
  };

  const closeContactModal = () => {
    if (contactModal) {
      contactModal.classList.remove('open');
      document.body.style.overflow = '';
    }
  };

  if (navContactBtn) navContactBtn.addEventListener('click', openContactModal);
  if (profileEmailBadge) {
    profileEmailBadge.addEventListener('click', (e) => {
      openContactModal(e);
    });
  }

  if (contactModalClose) contactModalClose.addEventListener('click', closeContactModal);
  if (contactModal) {
    contactModal.addEventListener('click', (e) => {
      if (e.target === contactModal) closeContactModal();
    });
  }

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && contactModal && contactModal.classList.contains('open')) {
      closeContactModal();
    }
  });

  // Modal Copy Button
  const modalCopyBtn = document.getElementById('modal-copy-btn');
  if (modalCopyBtn) {
    modalCopyBtn.addEventListener('click', () => {
      const origHtml = modalCopyBtn.innerHTML;
      copyToClipboard(PRIMARY_EMAIL, () => {
        modalCopyBtn.innerHTML = `<span style="color:#10b981;">✓ Copied</span>`;
        setTimeout(() => { modalCopyBtn.innerHTML = origHtml; }, 2500);
      });
    });
  }

  // Section Copy Button
  const sectionCopyBtn = document.getElementById('section-copy-email-btn');
  if (sectionCopyBtn) {
    sectionCopyBtn.addEventListener('click', () => {
      const label = sectionCopyBtn.querySelector('.btn-copy-label');
      const origText = label ? label.textContent : sectionCopyBtn.innerHTML;
      copyToClipboard(PRIMARY_EMAIL, () => {
        if (label) label.textContent = '✓ Copied!';
        setTimeout(() => {
          if (label) label.textContent = origText;
        }, 2500);
      });
    });
  }

  // Footer Copy Button
  const footerCopyBtn = document.getElementById('footer-copy-email-btn');
  if (footerCopyBtn) {
    footerCopyBtn.addEventListener('click', () => {
      const label = document.getElementById('footer-email-label');
      const origText = label ? label.textContent : '';
      copyToClipboard(PRIMARY_EMAIL, () => {
        if (label) label.textContent = '✓ Copied to clipboard!';
        setTimeout(() => {
          if (label) label.textContent = PRIMARY_EMAIL;
        }, 2500);
      });
    });
  }
}

