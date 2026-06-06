document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const categorySelect = document.getElementById('category-select');
    const optionSelect = document.getElementById('option-select');
    const metaContextBar = document.getElementById('meta-context-bar');
    const simulateBtn = document.getElementById('simulate-btn');
    const consoleLogs = document.getElementById('console-logs');

    // Metadata Token DOM References (read-only display)
    const metaSrcIp = document.getElementById('meta-src-ip');
    const metaDstIp = document.getElementById('meta-dst-ip');
    const metaProto = document.getElementById('meta-proto');
    const metaSport = document.getElementById('meta-sport');
    const metaDport = document.getElementById('meta-dport');
    const metaApp = document.getElementById('meta-app');

    // Verdict Toggle Elements
    const verdictAllowBtn = document.getElementById('verdict-allow-btn');
    const verdictDenyBtn = document.getElementById('verdict-deny-btn');
    const overrideIndicator = document.getElementById('override-mode-indicator');

    // Controls
    const prevBtn = document.getElementById('prev-step');
    const playPauseBtn = document.getElementById('play-pause');
    const nextBtn = document.getElementById('next-step');
    const resetBtn = document.getElementById('reset-sim');
    const detailsContainer = document.getElementById('step-details-container');
    const verdictContainer = document.getElementById('verdict-banner-container');

    // Simulation State
    let simulationSteps = [];
    let currentStepIndex = -1;
    let playInterval = null;
    let isPlaying = false;
    let currentVerdict = "ALLOW";
    let currentDropReason = null;
    let currentBrand = "fortigate";
    let userVerdict = "allow"; // "allow" | "deny" — segmented control state
    let isOverrideMode = false; // true when CLI paste overrides scenario
    let isCustomTrace = false;  // true when live debug log parsing is active

    // Current scenario state — derived from universalScenarios or override
    let currentScenario = null;

    // ============================================================
    // Re-Engineered Diagnostic Profile Schema
    // ============================================================
    const inspectionCategories = [
        {
            id: "cat_browsing",
            name: "1. Standard Cleartext Browsing",
            options: [
                { id: "opt_browsing_allow", name: "Allowed (Standard Core SNAT)", flags: { path: "slowpath", outcome: "ALLOW", engine: "l4_core" } },
                { id: "opt_browsing_deny", name: "Denied (L3/L4 Policy/ACL Drop)", flags: { path: "slowpath", outcome: "DROP", engine: "policy_acl" } }
            ]
        },
        {
            id: "cat_ssl",
            name: "2. SSL/TLS Inspection Behavior",
            options: [
                { id: "opt_ssl_deep", name: "Deep SSL Inspection (Decrypted & Allowed)", flags: { path: "slowpath", outcome: "ALLOW", useSslDecrypt: true, engine: "ssl_gateway" } },
                { id: "opt_ssl_cert", name: "Certificate-Only Inspection (No Decrypt)", flags: { path: "slowpath", outcome: "ALLOW", useSslDecrypt: false, engine: "ssl_gateway" } },
                { id: "opt_ssl_deny", name: "Untrusted/Expired Cert (Decrypted & Blocked)", flags: { path: "slowpath", outcome: "DROP", useSslDecrypt: true, engine: "ssl_gateway" } }
            ]
        },
        {
            id: "cat_acceleration",
            name: "3. Hardware & Stateful Acceleration",
            brandOptions: {
              fortigate: [
                { 
                  id: "fg_acc_slow", 
                  name: "Host CPU Stateful Setup (Slow Path)", 
                  description: "Initial TCP SYN processing via the FortiOS kernel to build state table entries.",
                  flags: { pathType: "slowpath", targetEngine: "fortigate_policy_lookup", outcome: "ALLOW" } 
                },
                { 
                  id: "fg_acc_np", 
                  name: "NP6/NP7 Network Processor Offload (Fast Path)", 
                  description: "Established L3/L4 payload fully switched inside specialized hardware ASICs, bypassing host CPU.",
                  flags: { pathType: "fastpath", targetEngine: "fortigate_session_lookup", outcome: "ALLOW" } 
                },
                { 
                  id: "fg_acc_cp", 
                  name: "CP9/CP10 Content Processor Crypto Offload", 
                  description: "Bulk VPN encryption/decryption tasks systematically offloaded to dedicated coprocessors.",
                  flags: { pathType: "slowpath", targetEngine: "fortigate_ipsec_decrypt", outcome: "ALLOW", useSslDecrypt: true, isVpn: true } 
                }
              ],
              checkpoint: [
                { 
                  id: "cp_acc_f2f", 
                  name: "CoreXL F2F - First to Fire (Slow Path)", 
                  description: "Traffic fails acceleration template matching, falling back completely to sequential CoreXL OS instances.",
                  flags: { pathType: "slowpath", targetEngine: "checkpoint_f2f_session", outcome: "ALLOW" } 
                },
                { 
                  id: "cp_acc_pxl", 
                  name: "SecureXL PXL Medium Path Streaming", 
                  description: "SecureXL accelerates TCP stream assembly and passes payload straight to CMI Software Blades.",
                  flags: { pathType: "mediumpath", targetEngine: "checkpoint_psl_stream", outcome: "ALLOW" } 
                },
                { 
                  id: "cp_acc_fast", 
                  name: "SecureXL Packet Acceleration (Fast Path)", 
                  description: "Packet matches an accept template at the lowest driver layer and egresses immediately without hitting kernel rows.",
                  flags: { pathType: "fastpath", targetEngine: "checkpoint_template_hit", outcome: "ALLOW" } 
                }
              ],
              paloalto: [
                { 
                  id: "pa_acc_slow", 
                  name: "Control Plane Session Setup (Slowpath)", 
                  description: "Full rulebase evaluation and hardware table programming for a brand-new connection stream.",
                  flags: { pathType: "slowpath", targetEngine: "paloalto_forwarding", outcome: "ALLOW" } 
                },
                { 
                  id: "pa_acc_fast", 
                  name: "Data Plane Hardware Offload (Fastpath)", 
                  description: "Subsequent packet matching an on-chip session table descriptor, maximizing single-pass efficiency.",
                  flags: { pathType: "fastpath", targetEngine: "paloalto_session_lookup", outcome: "ALLOW" } 
                }
              ],
              cisco_ftd: [
                { 
                  id: "ftd_acc_slow", 
                  name: "DAQ Handover to Snort 3 Engine (Slow Path)", 
                  description: "LINA intercept handoff passing traffic to the Snort L7 container matrix for deep scanning profile matching.",
                  flags: { pathType: "slowpath", targetEngine: "ftd_daq_handover", outcome: "ALLOW" } 
                },
                { 
                  id: "ftd_acc_fast", 
                  name: "LINA Prefilter / Trust Bypass (Fast Path)", 
                  description: "Traffic hits a Prefilter Fastpath or Trusted ACL, allowing LINA to switch the stream while avoiding Snort.",
                  flags: { pathType: "fastpath", targetEngine: "ftd_prefilter", outcome: "ALLOW" } 
                }
              ]
            }
        },
        {
            id: "cat_threat",
            name: "4. Threat Prevention Engines",
            brandOptions: {
                fortigate: [
                    { id: "fg_threat_ips", name: "Exploit Attack Blocked (Flow IPS Engine)", flags: { path: "slowpath", outcome: "DROP", engine: "ips_flow" } },
                    { id: "fg_threat_av", name: "Malware Drop (Flow Antivirus Stream)", flags: { path: "slowpath", outcome: "DROP", engine: "av_flow" } },
                    { id: "fg_threat_dlp", name: "Data Leak Transmit Prevented (Proxy DLP Scan)", flags: { path: "slowpath", outcome: "DROP", engine: "dlp_proxy" } },
                    { id: "fg_threat_wf", name: "Malicious Category Blocked (Flow WebFilter)", flags: { path: "slowpath", outcome: "DROP", engine: "wf_flow" } }
                ],
                checkpoint: [
                    { id: "cp_threat_ips", name: "Signature Exploit Blocked (IPS Blade)", flags: { path: "mediumpath", outcome: "DROP", engine: "cp_ips" } },
                    { id: "cp_threat_bot", name: "C2 Callback Intercepted (Anti-Bot Blade)", flags: { path: "mediumpath", outcome: "DROP", engine: "cp_bot" } },
                    { id: "cp_threat_te", name: "Zero-Day Malware Quarantined (Threat Emulation)", flags: { path: "slowpath", outcome: "DROP", engine: "cp_sandbox" } },
                    { id: "cp_threat_url", name: "Compliance Policy Drop (URL Filtering Blade)", flags: { path: "mediumpath", outcome: "DROP", engine: "cp_url" } }
                ],
                paloalto: [
                    { id: "pa_threat_ips", name: "Vulnerability Exploit Blocked (Content-ID IPS)", flags: { path: "slowpath", outcome: "DROP", engine: "pa_ips" } },
                    { id: "pa_threat_wf", name: "Zero-Day File Dropped (WildFire Sandbox)", flags: { path: "slowpath", outcome: "DROP", engine: "pa_wildfire" } },
                    { id: "pa_threat_url", name: "Malicious Host Blocked (URL Filtering)", flags: { path: "slowpath", outcome: "DROP", engine: "pa_url" } },
                    { id: "pa_threat_app", name: "Unauthorized Sub-App Blocked (App-ID Rule match)", flags: { path: "slowpath", outcome: "DROP", engine: "pa_appid" } }
                ],
                cisco_ftd: [
                    { id: "ftd_threat_ips", name: "Inline Exploit Blocked (Snort 3 IPS Engine)", flags: { path: "slowpath", outcome: "DROP", engine: "ftd_snort_ips" } },
                    { id: "ftd_threat_si", name: "Malicious Attacker Dropped (Security Intelligence)", flags: { path: "slowpath", outcome: "DROP", engine: "ftd_si" } },
                    { id: "ftd_threat_amp", name: "Malware Signature Blocked (AMP for Networks)", flags: { path: "slowpath", outcome: "DROP", engine: "ftd_amp" } },
                    { id: "ftd_threat_url", name: "Prohibited Domain Blocked (Snort URL Filter)", flags: { path: "slowpath", outcome: "DROP", engine: "ftd_url" } }
                ]
            }
        },
        {
            id: "cat_vpn",
            name: "5. Secure VPN Traffic Boundaries",
            options: [
                { id: "opt_vpn_inbound", name: "Inbound Tunnel Traffic (Decrypt & Cleartext Route)", flags: { path: "slowpath", outcome: "ALLOW", isVpn: true, direction: "inbound" } },
                { id: "opt_vpn_outbound", name: "Outbound Protected Traffic (Cleartext Route & Encrypt)", flags: { path: "slowpath", outcome: "ALLOW", isVpn: true, direction: "outbound" } }
            ]
        },
        {
            id: "cat_dnat",
            name: "6. Server Publishing (Destination NAT)",
            options: [
                { id: "opt_dnat_vip", name: "Inbound Virtual IP Map (Pre-Routing Port Forward)", flags: { path: "slowpath", outcome: "ALLOW", isDnat: true, direction: "inbound" } }
            ]
        }
    ];

    // Rich options metadata and simParams repository
    const optionMetadata = {
        opt_browsing_allow: {
            metadata: { src: "192.168.1.100", dst: "93.184.216.34", proto: "TCP", sport: "51001", dport: "80", app: "http" },
            simParams: { payload_type: "clean_web", existing_connection: false, ssl_decrypt: false, nat_type: "dynamic", security_intel: "clean" },
            contextText: "Active: Cleartext HTTP Browsing. Source PAT translation enabled."
        },
        opt_browsing_deny: {
            metadata: { src: "192.168.1.100", dst: "93.184.216.34", proto: "TCP", sport: "51001", dport: "80", app: "http" },
            simParams: { payload_type: "clean_web", existing_connection: false, ssl_decrypt: false, nat_type: "dynamic", security_intel: "clean" },
            contextText: "Active: Cleartext HTTP Browsing. Drop at Security Policy Lookup."
        },
        opt_ssl_deep: {
            metadata: { src: "192.168.1.50", dst: "8.8.8.8", proto: "TCP", sport: "49152", dport: "443", app: "ssl" },
            simParams: { payload_type: "clean_web", existing_connection: false, ssl_decrypt: true, nat_type: "dynamic", security_intel: "clean" },
            contextText: "Active: SSL Deep Inspection. SSL Decryption Keys Loaded. Cipher: TLS_AES_256_GCM."
        },
        opt_ssl_cert: {
            metadata: { src: "192.168.1.50", dst: "8.8.8.8", proto: "TCP", sport: "49152", dport: "443", app: "ssl" },
            simParams: { payload_type: "clean_web", existing_connection: false, ssl_decrypt: false, nat_type: "dynamic", security_intel: "clean" },
            contextText: "Active: SSL Certificate Validation (No Decrypt). SNI Inspection Only."
        },
        opt_ssl_deny: {
            metadata: { src: "192.168.1.50", dst: "104.18.2.44", proto: "TCP", sport: "54930", dport: "443", app: "web-browsing" },
            simParams: { payload_type: "blocked_url", existing_connection: false, ssl_decrypt: true, nat_type: "dynamic", security_intel: "clean" },
            contextText: "Active: Expired Certificate Block. Decrypted stream URL matches forbidden category."
        },
        opt_acc_fast: {
            metadata: { src: "192.168.1.50", dst: "8.8.8.8", proto: "UDP", sport: "53", dport: "53", app: "dns" },
            simParams: { payload_type: "prefilter_fastpath", existing_connection: true, ssl_decrypt: false, nat_type: "dynamic", security_intel: "clean" },
            contextText: "Active: NP7 / ASIC / SecureXL Fastpath session hit. Bypassing L7 UTM engines."
        },
        opt_acc_medium: {
            metadata: { src: "192.168.1.100", dst: "93.184.216.34", proto: "TCP", sport: "51001", dport: "80", app: "http" },
            simParams: { payload_type: "clean_web", existing_connection: true, ssl_decrypt: false, nat_type: "dynamic", security_intel: "clean" },
            contextText: "Active: Medium Path (Stream assembled inspection). PSL/PXL acceleration."
        },
        opt_acc_slow: {
            metadata: { src: "192.168.1.100", dst: "93.184.216.34", proto: "TCP", sport: "51001", dport: "80", app: "http" },
            simParams: { payload_type: "clean_web", existing_connection: false, ssl_decrypt: false, nat_type: "dynamic", security_intel: "clean" },
            contextText: "Active: Slow Path (First packet / connection setup). Core inspection active."
        },
        fg_acc_slow: {
            metadata: { src: "192.168.1.100", dst: "93.184.216.34", proto: "TCP", sport: "51001", dport: "80", app: "http" },
            simParams: { payload_type: "clean_web", existing_connection: false, ssl_decrypt: false, nat_type: "dynamic", security_intel: "clean" },
            contextText: "Host CPU Stateful Setup (Slow Path): Initial TCP SYN processing via the FortiOS kernel to build state table entries."
        },
        fg_acc_np: {
            metadata: { src: "192.168.1.100", dst: "93.184.216.34", proto: "TCP", sport: "51001", dport: "80", app: "http" },
            simParams: { payload_type: "prefilter_fastpath", existing_connection: true, ssl_decrypt: false, nat_type: "dynamic", security_intel: "clean" },
            contextText: "NP7 / ASIC Hardware Fastpath session hit. Processing offloaded entirely to Network Processor silicon, bypassing Host CPU network stack and L7 UTM engines. [INSIDE ➔ OUTSIDE]"
        },
        fg_acc_cp: {
            metadata: { src: "192.168.1.100", dst: "93.184.216.34", proto: "TCP", sport: "51001", dport: "443", app: "ssl" },
            simParams: { payload_type: "clean_web", existing_connection: false, ssl_decrypt: true, nat_type: "dynamic", security_intel: "clean" },
            contextText: "CP9/CP10 Content Processor Crypto Offload. Bulk VPN encryption/decryption tasks systematically offloaded to dedicated coprocessors."
        },
        cp_acc_f2f: {
            metadata: { src: "192.168.1.100", dst: "93.184.216.34", proto: "TCP", sport: "51001", dport: "80", app: "http" },
            simParams: { payload_type: "clean_web", existing_connection: false, ssl_decrypt: false, nat_type: "dynamic", security_intel: "clean" },
            contextText: "CoreXL F2F - First to Fire (Slow Path): Traffic fails acceleration template matching, falling back completely to sequential CoreXL OS instances."
        },
        cp_acc_pxl: {
            metadata: { src: "192.168.1.100", dst: "93.184.216.34", proto: "TCP", sport: "51001", dport: "80", app: "http" },
            simParams: { payload_type: "clean_web", existing_connection: true, ssl_decrypt: false, nat_type: "dynamic", security_intel: "clean" },
            contextText: "SecureXL PXL Medium Path Streaming: SecureXL accelerates TCP stream assembly and passes payload straight to CMI Software Blades."
        },
        cp_acc_fast: {
            metadata: { src: "192.168.1.100", dst: "93.184.216.34", proto: "TCP", sport: "51001", dport: "80", app: "http" },
            simParams: { payload_type: "prefilter_fastpath", existing_connection: true, ssl_decrypt: false, nat_type: "dynamic", security_intel: "clean" },
            contextText: "SecureXL Packet Acceleration (Fast Path): Packet matches an accept template at the lowest driver layer and egresses immediately."
        },
        pa_acc_slow: {
            metadata: { src: "192.168.1.100", dst: "93.184.216.34", proto: "TCP", sport: "51001", dport: "80", app: "http" },
            simParams: { payload_type: "clean_web", existing_connection: false, ssl_decrypt: false, nat_type: "dynamic", security_intel: "clean" },
            contextText: "Control Plane Session Setup (Slowpath): Full rulebase evaluation and hardware table programming for a brand-new connection stream."
        },
        pa_acc_fast: {
            metadata: { src: "192.168.1.100", dst: "93.184.216.34", proto: "TCP", sport: "51001", dport: "80", app: "http" },
            simParams: { payload_type: "prefilter_fastpath", existing_connection: true, ssl_decrypt: false, nat_type: "dynamic", security_intel: "clean" },
            contextText: "Data Plane Hardware Offload (Fastpath): Subsequent packet matching an on-chip session table descriptor, maximizing single-pass efficiency."
        },
        ftd_acc_slow: {
            metadata: { src: "192.168.1.100", dst: "93.184.216.34", proto: "TCP", sport: "51001", dport: "80", app: "http" },
            simParams: { payload_type: "clean_web", existing_connection: false, ssl_decrypt: false, nat_type: "dynamic", security_intel: "clean" },
            contextText: "DAQ Handover to Snort 3 Engine (Slow Path): LINA intercept handoff passing traffic to the Snort L7 container matrix."
        },
        ftd_acc_fast: {
            metadata: { src: "192.168.1.100", dst: "93.184.216.34", proto: "TCP", sport: "51001", dport: "80", app: "http" },
            simParams: { payload_type: "prefilter_fastpath", existing_connection: true, ssl_decrypt: false, nat_type: "dynamic", security_intel: "clean" },
            contextText: "LINA Prefilter / Trust Bypass (Fast Path): Traffic hits a Prefilter Fastpath or Trusted ACL, allowing LINA to switch the stream while avoiding Snort."
        },
        // FortiGate Threats
        fg_threat_ips: {
            metadata: { src: "198.51.100.45", dst: "203.0.113.80", proto: "TCP", sport: "51000", dport: "80", app: "http" },
            simParams: { payload_type: "sql_injection", existing_connection: false, ssl_decrypt: false, nat_type: "static", security_intel: "clean" },
            contextText: "Exploit: SQL Injection Pattern matched. Signature: UNION SELECT. Action: Drop."
        },
        fg_threat_av: {
            metadata: { src: "93.184.216.34", dst: "192.168.1.100", proto: "TCP", sport: "80", dport: "52001", app: "http-file-transfer" },
            simParams: { payload_type: "malware", existing_connection: false, ssl_decrypt: false, nat_type: "none", security_intel: "clean" },
            contextText: "Malware: EICAR Signature matched on stream. Payload Hash: 275a021b. Action: Drop."
        },
        fg_threat_dlp: {
            metadata: { src: "192.168.1.100", dst: "93.184.216.34", proto: "TCP", sport: "51001", dport: "80", app: "http-file-transfer" },
            simParams: { payload_type: "malware", existing_connection: false, ssl_decrypt: false, nat_type: "dynamic", security_intel: "clean" },
            contextText: "DLP Block: Credit card regex pattern matched outbound file proxy stream. Action: Block."
        },
        fg_threat_wf: {
            metadata: { src: "192.168.1.50", dst: "104.18.2.44", proto: "TCP", sport: "54930", dport: "443", app: "web-browsing" },
            simParams: { payload_type: "blocked_url", existing_connection: false, ssl_decrypt: true, nat_type: "dynamic", security_intel: "clean" },
            contextText: "WebFilter: Prohibited domain category 'Gambling' detected. Site poker-online block."
        },
        // Check Point Threats
        cp_threat_ips: {
            metadata: { src: "198.51.100.45", dst: "203.0.113.80", proto: "TCP", sport: "51000", dport: "80", app: "http" },
            simParams: { payload_type: "sql_injection", existing_connection: true, ssl_decrypt: false, nat_type: "static", security_intel: "clean" },
            contextText: "IPS Blade: Signature matched UNION SELECT on PXL Medium Path. Action: Terminate."
        },
        cp_threat_bot: {
            metadata: { src: "192.168.1.100", dst: "185.220.101.5", proto: "TCP", sport: "51001", dport: "443", app: "ssl" },
            simParams: { payload_type: "clean_web", existing_connection: true, ssl_decrypt: false, nat_type: "dynamic", security_intel: "blacklisted_ip" },
            contextText: "Anti-Bot: Malicious Command & Control callback detected on PXL Medium Path. Action: Drop."
        },
        cp_threat_te: {
            metadata: { src: "93.184.216.34", dst: "192.168.1.100", proto: "TCP", sport: "80", dport: "52001", app: "http-file-transfer" },
            simParams: { payload_type: "malware", existing_connection: false, ssl_decrypt: false, nat_type: "none", security_intel: "clean" },
            contextText: "Zero-Day Malware quarantined in Threat Emulation sandbox. Hash: eicar.com. Action: Drop."
        },
        cp_threat_url: {
            metadata: { src: "192.168.1.50", dst: "104.18.2.44", proto: "TCP", sport: "54930", dport: "443", app: "web-browsing" },
            simParams: { payload_type: "blocked_url", existing_connection: true, ssl_decrypt: true, nat_type: "dynamic", security_intel: "clean" },
            contextText: "URL Filtering: Site category 'Gambling' blocked. Compliance policy violation."
        },
        // Palo Alto Threats
        pa_threat_ips: {
            metadata: { src: "198.51.100.45", dst: "203.0.113.80", proto: "TCP", sport: "51000", dport: "80", app: "http" },
            simParams: { payload_type: "sql_injection", existing_connection: false, ssl_decrypt: false, nat_type: "static", security_intel: "clean" },
            contextText: "Content-ID IPS: Vulnerability exploit pattern matched SQL Injection UNION SELECT. Action: Drop."
        },
        pa_threat_wf: {
            metadata: { src: "93.184.216.34", dst: "192.168.1.100", proto: "TCP", sport: "80", dport: "52001", app: "http-file-transfer" },
            simParams: { payload_type: "malware", existing_connection: false, ssl_decrypt: false, nat_type: "none", security_intel: "clean" },
            contextText: "WildFire Sandbox: File Hash 275a021b flagged as active zero-day threat. Action: Reset-Both."
        },
        pa_threat_url: {
            metadata: { src: "192.168.1.50", dst: "104.18.2.44", proto: "TCP", sport: "54930", dport: "443", app: "web-browsing" },
            simParams: { payload_type: "blocked_url", existing_connection: false, ssl_decrypt: true, nat_type: "dynamic", security_intel: "clean" },
            contextText: "URL Filtering: Dest host poker-online category matched blocked list 'Gambling'. Action: Drop."
        },
        pa_threat_app: {
            metadata: { src: "192.168.1.100", dst: "13.107.42.14", proto: "TCP", sport: "50400", dport: "443", app: "ms-office-365" },
            simParams: { payload_type: "blocked_url", existing_connection: false, ssl_decrypt: false, nat_type: "dynamic", security_intel: "clean" },
            contextText: "App-ID Block: Sub-application block matched. Rule 'Block_Office_Chat' triggered. Action: Drop."
        },
        // Cisco FTD Threats
        ftd_threat_ips: {
            metadata: { src: "198.51.100.45", dst: "203.0.113.80", proto: "TCP", sport: "51000", dport: "80", app: "http" },
            simParams: { payload_type: "sql_injection", existing_connection: false, ssl_decrypt: false, nat_type: "static", security_intel: "clean" },
            contextText: "Snort 3 IPS: GID: 1, SID: 19412 exploit UNION SELECT SQL injection detected. Action: Drop."
        },
        ftd_threat_si: {
            metadata: { src: "185.220.101.5", dst: "203.0.113.10", proto: "TCP", sport: "39582", dport: "443", app: "ssl" },
            simParams: { payload_type: "clean_web", existing_connection: false, ssl_decrypt: false, nat_type: "none", security_intel: "blacklisted_ip" },
            contextText: "Talos Security Intelligence: Source matches blacklisted Botnet C2 server IP address. Action: Drop."
        },
        ftd_threat_amp: {
            metadata: { src: "93.184.216.34", dst: "192.168.1.100", proto: "TCP", sport: "80", dport: "52001", app: "http-file-transfer" },
            simParams: { payload_type: "malware", existing_connection: false, ssl_decrypt: false, nat_type: "none", security_intel: "clean" },
            contextText: "AMP for Networks: Executable file hash lookup matched malicious signature. Action: Drop."
        },
        ftd_threat_url: {
            metadata: { src: "192.168.1.50", dst: "104.18.2.44", proto: "TCP", sport: "54930", dport: "443", app: "web-browsing" },
            simParams: { payload_type: "blocked_url", existing_connection: false, ssl_decrypt: true, nat_type: "dynamic", security_intel: "clean" },
            contextText: "Snort URL Filter: Gambling category domain block poker-online. Action: Deny/TCP-Reset."
        },
        // VPN Options
        opt_vpn_inbound: {
            metadata: { src: "192.168.1.100", dst: "10.0.50.22", proto: "ESP (50)", sport: "None", dport: "None", app: "ipsec-encapsulated" },
            simParams: { payload_type: "vpn_in", existing_connection: false, ssl_decrypt: false, nat_type: "none", security_intel: "clean" },
            contextText: "Active: Inbound tunnel traffic. Decrypting ESP packet into cleartext. SPI: 0x4b7e8d2."
        },
        opt_vpn_outbound: {
            metadata: { src: "192.168.1.100", dst: "10.0.50.22", proto: "ESP (50)", sport: "None", dport: "None", app: "ipsec-encapsulated" },
            simParams: { payload_type: "vpn_in", existing_connection: false, ssl_decrypt: false, nat_type: "none", security_intel: "clean" },
            contextText: "Active: Outbound protected traffic. Encrypting cleartext packet inside dynamic ESP tunnel."
        },
        // DNAT Options
        opt_dnat_vip: {
            metadata: { src: "203.0.113.80", dst: "192.168.1.100", proto: "TCP", sport: "51000", dport: "80", app: "http" },
            simParams: { payload_type: "clean_web", existing_connection: false, ssl_decrypt: false, nat_type: "static", security_intel: "clean" },
            contextText: "Active: Virtual IP Destination Port Forward translation (DNAT) from 203.0.113.80 -> 192.168.1.100."
        }
    };

    // Engine to backend target mapper
    const mapEngineToBackendTarget = (engine) => {
        switch (engine) {
            case "l4_core":
                return "l4_core";
            case "policy_acl":
                return "acl_rulebase";
            case "ssl_gateway":
                return "ssl_engine";
            case "ips_flow":
            case "cp_ips":
            case "pa_ips":
            case "ftd_snort_ips":
                return "ips_engine";
            case "av_flow":
            case "cp_sandbox":
            case "pa_wildfire":
            case "ftd_amp":
            case "cp_bot":
            case "dlp_proxy":
                return "malware_engine";
            case "wf_flow":
            case "cp_url":
            case "pa_url":
            case "ftd_url":
                return "url_filter";
            case "pa_appid":
                return "auth_engine";
            case "ftd_si":
                return "threat_intel";
            case "asic_sxl_fast":
            case "pxl_flow_med":
            case "kernel_lina_slow":
            case "fortigate_session_lookup":
            case "checkpoint_template_hit":
            case "paloalto_session_lookup":
            case "ftd_prefilter":
            case "checkpoint_psl_stream":
                return "prefilter";
            case "fortigate_policy_lookup":
            case "fortigate_ipsec_decrypt":
            case "checkpoint_f2f_session":
            case "paloalto_forwarding":
            case "ftd_daq_handover":
                return "l4_core";
            default:
                return "l4_core";
        }
    };

    const brandTitles = {
        cisco: "FTD Inspection Pipeline",
        paloalto: "Palo Alto Inspection Pipeline",
        fortigate: "Fortigate Inspection Pipeline",
        checkpoint: "Check Point Inspection Pipeline"
    };

    const brandConsoleTitles = {
        cisco: "FTD packet-tracer console output",
        paloalto: "Palo Alto security-policy-match output",
        fortigate: "Fortigate CLI packet-trace output",
        checkpoint: "Check Point CLI fw monitor output"
    };

    // ============================================================
    // Metadata Token Display Update
    // ============================================================
    function updateMetadataTokens(meta) {
        if (metaSrcIp) metaSrcIp.textContent = meta.src || '—';
        if (metaDstIp) metaDstIp.textContent = meta.dst || '—';
        if (metaProto) metaProto.textContent = meta.proto || '—';
        if (metaSport) metaSport.textContent = meta.sport || '—';
        if (metaDport) metaDport.textContent = meta.dport || '—';
        if (metaApp) metaApp.textContent = meta.app || '—';
    }

    // ============================================================
    // Verdict Segmented Control
    // ============================================================
    function setVerdictToggle(verdict) {
        userVerdict = verdict;
        if (verdict === 'allow') {
            verdictAllowBtn.className = 'verdict-seg-btn active-allow';
            verdictDenyBtn.className = 'verdict-seg-btn';
        } else {
            verdictAllowBtn.className = 'verdict-seg-btn';
            verdictDenyBtn.className = 'verdict-seg-btn active-deny';
        }
    }

    if (verdictAllowBtn) {
        verdictAllowBtn.addEventListener('click', () => {
            setVerdictToggle('allow');
            appendLog('> Policy verdict set to: ALLOWED', 'system');
        });
    }
    if (verdictDenyBtn) {
        verdictDenyBtn.addEventListener('click', () => {
            setVerdictToggle('deny');
            appendLog('> Policy verdict set to: DENIED', 'system');
        });
    }

    // ============================================================
    // Apply Re-Engineered Diagnostic Option
    // ============================================================
    function applyOption(optionId) {
        const optMeta = optionMetadata[optionId];
        if (!optMeta) return;

        // Find Category
        const currentCategoryObj = inspectionCategories.find(c => {
            if (c.options && c.options.find(o => o.id === optionId)) return true;
            if (c.brandOptions) {
                return Object.values(c.brandOptions).some(opts => opts.find(o => o.id === optionId));
            }
            return false;
        });

        if (!currentCategoryObj) return;

        const optionObj = currentCategoryObj.options ? currentCategoryObj.options.find(o => o.id === optionId) :
                          currentCategoryObj.brandOptions[currentBrand === 'cisco' ? 'cisco_ftd' : currentBrand].find(o => o.id === optionId);

        if (!optionObj) return;

        // Synchronize Policy Verdict segmented control highlight based on outcome
        if (optionObj.flags.outcome === "DROP" || optionObj.flags.outcome === "REDIRECT") {
            userVerdict = "deny";
            if (verdictAllowBtn) verdictAllowBtn.classList.remove('active-allow');
            if (verdictDenyBtn) verdictDenyBtn.classList.add('active-deny');
        } else {
            userVerdict = "allow";
            if (verdictAllowBtn) verdictAllowBtn.classList.add('active-allow');
            if (verdictDenyBtn) verdictDenyBtn.classList.remove('active-deny');
        }

        const virtualScenario = {
            id: optionId,
            label: optionObj.name,
            description: optionObj.name,
            metadata: optMeta.metadata,
            engineFlags: {
                useVpn: !!optionObj.flags.isVpn,
                useSsl: !!optionObj.flags.useSslDecrypt,
                pathType: optionObj.flags.pathType || optionObj.flags.path,
                targetEngine: mapEngineToBackendTarget(optionObj.flags.targetEngine || optionObj.flags.engine)
            },
            simParams: optMeta.simParams
        };

        currentScenario = virtualScenario;
        isOverrideMode = false;
        if (overrideIndicator) overrideIndicator.style.display = 'none';

        // Update metadata tokens
        updateMetadataTokens(virtualScenario.metadata);

        // Consolidate profile description and direction inside the metadata context bar
        if (metaContextBar) {
            const isSrcInternal = virtualScenario.metadata.src.startsWith('192.168.') ||
                virtualScenario.metadata.src.startsWith('10.') ||
                virtualScenario.metadata.src.startsWith('172.16.');
            const dirText = isSrcInternal ? 'INSIDE -> OUTSIDE' : 'OUTSIDE -> INSIDE';
            metaContextBar.textContent = `${optMeta.contextText || "Active Packet Diagnostic Flow Matrix"} [${dirText}]`;
        }

        appendLog(`> Diagnostic profile loaded: ${optionObj.name}`, 'system');
        resetSimulationState();
        syncPipelineReactivity();

        // Auto-execute trace path simulation on selection change
        if (simulateBtn) {
            simulateBtn.click();
        }
    }

    // Dynamic Select Populators
    function populateCategoriesAndOptions() {
        if (!categorySelect) return;
        categorySelect.replaceChildren();

        inspectionCategories.forEach(cat => {
            const opt = document.createElement('option');
            opt.value = cat.id;
            opt.textContent = cat.name;
            categorySelect.appendChild(opt);
        });

        // Category change listener
        categorySelect.addEventListener('change', (e) => {
            populateOptions(e.target.value);
        });

        // Option change listener
        if (optionSelect) {
            optionSelect.addEventListener('change', (e) => {
                applyOption(e.target.value);
            });
        }
    }

    function populateOptions(categoryId, selectedOptionId = null) {
        if (!optionSelect) return;
        optionSelect.replaceChildren();

        const cat = inspectionCategories.find(c => c.id === categoryId);
        if (!cat) return;

        let optionsToLoad = [];
        if (cat.options) {
            optionsToLoad = cat.options;
        } else if (cat.brandOptions) {
            const activeBrandKey = currentBrand === 'cisco' ? 'cisco_ftd' : currentBrand;
            optionsToLoad = cat.brandOptions[activeBrandKey] || [];
        }

        optionsToLoad.forEach(o => {
            const opt = document.createElement('option');
            opt.value = o.id;
            opt.textContent = o.name;
            optionSelect.appendChild(opt);
        });

        if (selectedOptionId && optionsToLoad.some(o => o.id === selectedOptionId)) {
            optionSelect.value = selectedOptionId;
        } else if (optionsToLoad.length > 0) {
            optionSelect.value = optionsToLoad[0].id;
        }

        if (optionSelect.value) {
            applyOption(optionSelect.value);
        }
    }

    // ============================================================
    // Brand Tab Click Event Listeners
    // ============================================================
    document.querySelectorAll('.brand-tab').forEach(tabBtn => {
        tabBtn.addEventListener('click', () => {
            const brand = tabBtn.getAttribute('data-brand');
            if (brand === currentBrand) return;

            currentBrand = brand;

            // Reset custom override states on brand switch
            isCustomTrace = false;
            isOverrideMode = false;
            if (overrideIndicator) overrideIndicator.style.display = 'none';

            // Toggle active style on tab buttons
            document.querySelectorAll('.brand-tab').forEach(btn => btn.classList.remove('active'));
            tabBtn.classList.add('active');

            // Switch active pipeline flow container layout
            document.querySelectorAll('.brand-flow-layout').forEach(flowContainer => {
                flowContainer.classList.remove('active');
            });
            const activeFlow = document.getElementById(`brand-flow-${brand}`);
            if (activeFlow) {
                activeFlow.classList.add('active');
            }

            // Update titles
            const titleEl = document.getElementById('pipeline-title-brand');
            if (titleEl && brandTitles[brand]) {
                titleEl.textContent = brandTitles[brand];
            }

            const consoleTitleEl = document.getElementById('console-terminal-title');
            if (consoleTitleEl && brandConsoleTitles[brand]) {
                consoleTitleEl.textContent = brandConsoleTitles[brand];
            }

            updateCLIGuide();

            appendLog(`> Switched active firewall brand to: ${tabBtn.textContent}`, 'system');
            resetSimulationState();

            // Re-apply current option, or re-populate threats if threat or acceleration category is selected
            if (categorySelect && optionSelect) {
                if (categorySelect.value === 'cat_threat' || categorySelect.value === 'cat_acceleration') {
                    populateOptions(categorySelect.value);
                } else if (currentScenario) {
                    applyOption(currentScenario.id);
                }
            }
        });
    });

    // ============================================================
    // Init: Default brand state on page load
    // ============================================================
    (function initDefaultBrand() {
        const brand = currentBrand;

        // Set pipeline title
        const titleEl = document.getElementById('pipeline-title-brand');
        if (titleEl && brandTitles[brand]) titleEl.textContent = brandTitles[brand];

        // Set console title
        const consoleTitleEl = document.getElementById('console-terminal-title');
        if (consoleTitleEl && brandConsoleTitles[brand]) consoleTitleEl.textContent = brandConsoleTitles[brand];
    })();

    // ============================================================
    // Console Logger
    // ============================================================
    function appendLog(message, type = 'normal') {
        const line = document.createElement('div');
        line.className = `console-line ${type}`;
        line.textContent = message;
        consoleLogs.appendChild(line);
        consoleLogs.scrollTop = consoleLogs.scrollHeight;
    }

    // ============================================================
    // Reset UI node styling
    // ============================================================
    function resetSimulationState() {
        // Clear custom trace flag
        isCustomTrace = false;

        // Clear active interval
        if (playInterval) {
            clearInterval(playInterval);
            playInterval = null;
        }
        isPlaying = false;
        playPauseBtn.textContent = "Play";
        playPauseBtn.className = "ctrl-btn";
        
        currentStepIndex = -1;
        updateControls();

        // Clear all highlight classes from pipeline nodes
        document.querySelectorAll('.node').forEach(node => {
            node.classList.remove('active', 'pass', 'fail', 'nat', 'decrypt', 'bypass', 'node-disabled');
        });

        // Clear side panels
        detailsContainer.replaceChildren();
        const placeholder = document.createElement('p');
        placeholder.className = 'placeholder-text';
        placeholder.textContent = 'Please simulate a packet trace to inspect step details.';
        detailsContainer.appendChild(placeholder);
        
        verdictContainer.replaceChildren();
    }

    // Update Step Controls state
    function updateControls() {
        prevBtn.disabled = (currentStepIndex <= 0);
        nextBtn.disabled = (simulationSteps.length === 0 || currentStepIndex >= simulationSteps.length - 1);
        
        if (currentStepIndex >= 0 && currentStepIndex < simulationSteps.length) {
            renderStepDetails(simulationSteps[currentStepIndex]);
        }
    }

    // Safe render step description with DOM builders — grouped into distinct boxes
    function renderStepDetails(step) {
        detailsContainer.replaceChildren();

        const wrapper = document.createElement('div');
        wrapper.className = 'details-wrapper';

        // ─── Box 1: Engine / Description / Verdict ─────────────────────
        const box1 = document.createElement('div');
        box1.className = 'details-box';

        const title = document.createElement('div');
        title.className = 'details-step-title';
        title.textContent = `${step.subTitle || step.component} Engine: ${step.title || step.name}`;
        box1.appendChild(title);

        const explanationText = step.explanation || step.description;
        if (explanationText) {
            const explanationBox = document.createElement('div');
            explanationBox.className = 'details-explanation-box';
            explanationBox.textContent = explanationText;
            box1.appendChild(explanationBox);
        }

        const verdictBadge = document.createElement('div');
        const vText = step.verdict || step.status.toUpperCase();
        verdictBadge.className = `verdict-badge-step ${vText.toLowerCase()}`;
        verdictBadge.textContent = `Verdict: ${vText}`;
        box1.appendChild(verdictBadge);

        wrapper.appendChild(box1);

        // ─── Box 2: Technical Behavior Details ────────────────────────
        const box2 = document.createElement('div');
        box2.className = 'details-box';

        const technicalHeader = document.createElement('h4');
        technicalHeader.className = 'info-sub-header';
        technicalHeader.textContent = 'Technical Behavior Details';
        box2.appendChild(technicalHeader);

        const desc = document.createElement('div');
        desc.className = 'details-desc';
        desc.textContent = step.technicalBehaviorDetails || step.details || step.description;
        box2.appendChild(desc);

        wrapper.appendChild(box2);

        // ─── Box 3: CLI Log line ──────────────────────────────────────
        const cliLog = step.mockCliLogLine;
        if (cliLog) {
            const box3 = document.createElement('div');
            box3.className = 'details-box';

            const cliHeader = document.createElement('h4');
            cliHeader.className = 'info-sub-header';
            cliHeader.textContent = 'CLI Log line';
            box3.appendChild(cliHeader);

            const cliPre = document.createElement('pre');
            cliPre.className = 'cli-log-line';
            cliPre.textContent = cliLog;
            box3.appendChild(cliPre);

            wrapper.appendChild(box3);
        }

        detailsContainer.appendChild(wrapper);
    }

    // Display flow simulation verdict banner
    function renderVerdictBanner() {
        verdictContainer.replaceChildren();
        const banner = document.createElement('div');
        
        if (currentVerdict === "ALLOW") {
            banner.className = 'verdict-banner allow';
            banner.textContent = 'Final Verdict: ALLOWED (Stream Transmitted)';
            appendLog(`[Result] Packet successfully forwarded. Verdict: ALLOW`, 'success');
        } else {
            banner.className = 'verdict-banner drop';
            banner.textContent = `Final Verdict: DROPPED (${currentDropReason})`;
            appendLog(`[Result] Packet discarded. Verdict: DROP. Reason: ${currentDropReason}`, 'danger');
        }
        verdictContainer.appendChild(banner);
    }

    // Set styling of a pipeline node
    function highlightNode(step, isActive = false, shouldScroll = false) {
        const nodeEl = document.getElementById(`node-${step.id}`);
        if (!nodeEl) return;

        const isDecision = nodeEl.classList.contains('decision') || nodeEl.id === 'node-existing_conn';
        
        nodeEl.className = 'node';
        if (isDecision) {
            nodeEl.classList.add('decision');
        }

        nodeEl.classList.add(step.status);
        if (isActive) {
            nodeEl.classList.add('active');
            if (shouldScroll) {
                nodeEl.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' });
            }
        }
    }

    // Execute full step traversal animation
    function gotoStep(index) {
        if (index < 0 || index >= simulationSteps.length) return;

        for (let i = 0; i < simulationSteps.length; i++) {
            const step = simulationSteps[i];
            if (i < index) {
                highlightNode(step, false);
            } else if (i === index) {
                highlightNode(step, true, true);
                
                let cliTool = "packet-tracer";
                if (currentBrand === "paloalto") cliTool = "test security-policy-match";
                else if (currentBrand === "fortigate") cliTool = "diagnose debug flow";
                else if (currentBrand === "checkpoint") cliTool = "fw monitor";
                
                appendLog(`[${cliTool}] Phase ${i + 1}: ${step.component} - ${step.name} -> Result: ${step.status.toUpperCase()}`, 'cmd');
            } else {
                const nodeEl = document.getElementById(`node-${step.id}`);
                if (nodeEl) {
                    nodeEl.classList.remove('active', 'pass', 'fail', 'nat', 'decrypt', 'bypass');
                }
            }
        }

        // If traffic is dropped, gray out all unreached nodes
        if (currentVerdict === "DROP") {
            const traversedIds = new Set(simulationSteps.map(s => s.id));
            document.querySelectorAll('.node').forEach(nodeEl => {
                const stepId = nodeEl.getAttribute('data-step');
                if (stepId && !traversedIds.has(stepId)) {
                    nodeEl.classList.add('node-disabled');
                }
            });
        }

        currentStepIndex = index;
        updateControls();

        if (currentStepIndex === simulationSteps.length - 1) {
            renderVerdictBanner();
            if (playInterval) {
                clearInterval(playInterval);
                playInterval = null;
                isPlaying = false;
                playPauseBtn.textContent = "Play";
                playPauseBtn.className = "ctrl-btn";
            }
        }
    }

    function completePipeline() {
        if (simulationSteps.length === 0) return;

        // Clear active classes from all nodes first
        document.querySelectorAll('.node').forEach(nodeEl => {
            nodeEl.classList.remove('active', 'pass', 'fail', 'nat', 'decrypt', 'bypass');
        });

        // Highlight every traversed node with its status
        for (let i = 0; i < simulationSteps.length; i++) {
            const step = simulationSteps[i];
            const isActive = (i === simulationSteps.length - 1);
            highlightNode(step, isActive, false); // DO NOT AUTOSCROLL AFTER SIMULATING TEMPLATE

            let cliTool = "packet-tracer";
            if (currentBrand === "paloalto") cliTool = "test security-policy-match";
            else if (currentBrand === "fortigate") cliTool = "diagnose debug flow";
            else if (currentBrand === "checkpoint") cliTool = "fw monitor";
            
            appendLog(`[${cliTool}] Phase ${i + 1}: ${step.component} - ${step.name} -> Result: ${step.status.toUpperCase()}`, 'cmd');
        }

        // If traffic is dropped, gray out all unreached nodes
        if (currentVerdict === "DROP") {
            const traversedIds = new Set(simulationSteps.map(s => s.id));
            document.querySelectorAll('.node').forEach(nodeEl => {
                const stepId = nodeEl.getAttribute('data-step');
                if (stepId && !traversedIds.has(stepId)) {
                    nodeEl.classList.add('node-disabled');
                }
            });

            // Terminal Intercept — custom trace drop truncation hook
            if (isCustomTrace) {
                const dropStep = simulationSteps.find(s => s.status === 'fail');
                if (dropStep) {
                    appendLog(`> 🔴 [Terminal Intercept] Packet dropped at "${dropStep.name}" (${dropStep.subTitle || dropStep.component}). ${dropStep.verdict === 'DROPPED' ? 'Truncated all downstream nodes to inactive_skipped mask.' : ''}`, 'danger');
                }
            }
        }

        // FortiGate fastpath: gray out Host CPU nodes bypassed by ASIC
        if (currentBrand === 'fortigate' && currentScenario && currentScenario.engineFlags.pathType === 'fastpath') {
            ['node-fg_routing_in', 'node-fg_tcp_sanity', 'node-fg_session_lookup', 'node-fg_proxy_decision'].forEach(id => {
                const node = document.getElementById(id);
                if (node) node.classList.add('node-disabled');
            });
        }

        currentStepIndex = simulationSteps.length - 1;
        renderVerdictBanner();
        updateControls();
    }

    function selectNodeForDetails(index) {
        if (index < 0 || index >= simulationSteps.length) return;

        for (let i = 0; i < simulationSteps.length; i++) {
            const step = simulationSteps[i];
            const isActive = (i === index);
            highlightNode(step, isActive, true); // SCROLL WHEN MANUALLY CLICKED / SELECTED
        }
        currentStepIndex = index;
        renderStepDetails(simulationSteps[index]);
    }

    // ============================================================
    // Simulation Trigger (button click, no form submit)
    // ============================================================
    simulateBtn.addEventListener('click', async () => {
        resetSimulationState();

        if (!currentScenario) {
            appendLog('> No scenario selected. Please choose a scenario.', 'danger');
            return;
        }

        simulateBtn.disabled = true;
        simulateBtn.querySelector('.btn-text').textContent = 'Analyzing...';
        let brandLogName = "Cisco FTD Packet Simulation Tracer";
        if (currentBrand === "paloalto") brandLogName = "Palo Alto security-policy-match Tracer";
        else if (currentBrand === "fortigate") brandLogName = "FortiGate diagnose debug flow Tracer";
        else if (currentBrand === "checkpoint") brandLogName = "Check Point fw monitor Tracer";
        
        appendLog(`> Initiating ${brandLogName}...`, 'system');

        // Build payload from current scenario's simParams
        const sp = currentScenario.simParams;
        const meta = currentScenario.metadata;
        const payload = {
            brand: currentBrand,
            src_ip: meta.src,
            dst_ip: meta.dst,
            src_port: parseInt(meta.sport) || 0,
            dst_port: parseInt(meta.dport) || 0,
            protocol: meta.proto.replace(/\s*\(.*\)/, ''), // strip "(50)" from "ESP (50)"
            payload_type: sp.payload_type,
            existing_connection: sp.existing_connection,
            ssl_decrypt: sp.ssl_decrypt,
            nat_type: sp.nat_type,
            security_intel: sp.security_intel,
            path_type: currentScenario.engineFlags.pathType || currentScenario.engineFlags.path || "",
            option_id: currentScenario.id || ""
        };

        // Force verdict support
        if (userVerdict === 'deny') {
            payload.force_verdict = 'deny';
            payload.target_engine = currentScenario.engineFlags.targetEngine;
        }

        try {
            const response = await fetch('/api/simulate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            const result = await response.json();
            
            if (result.status === 'success') {
                simulationSteps = result.steps;
                
                // Apply log parser overrides
                if (window.parsedLogOverrides) {
                    simulationSteps.forEach(step => {
                        if (step.id === 'fg_policy' && window.parsedLogOverrides.fgPolicyId) {
                            step.description = `[Pasted Log policy matched ID: ${window.parsedLogOverrides.fgPolicyId}] ` + step.description;
                            step.technicalBehaviorDetails = `Pasted log policy-ID ${window.parsedLogOverrides.fgPolicyId} matched exactly. ` + step.technicalBehaviorDetails;
                        }
                        if (step.id === 'fg_snat' && window.parsedLogOverrides.fgSnat) {
                            step.description = `[Pasted Log SNAT validated] ` + step.description;
                        }
                        if (step.id === 'pa_app_rematch' && window.parsedLogOverrides.paAppId) {
                            step.description = `[App-ID dynamic log change to: ${window.parsedLogOverrides.paAppId}] ` + step.description;
                        }
                        if (step.id === 'l3_route' && window.parsedLogOverrides.ciscoRoute) {
                            step.description = `[Pasted Log resolved Route Lookup successfully] ` + step.description;
                        }
                        if (step.id === 'l3_l4_acl' && window.parsedLogOverrides.ciscoAcl) {
                            step.description = `[Pasted Log ACCESS-LIST ALLOW verified] ` + step.description;
                        }
                    });
                }
                
                currentVerdict = result.verdict;
                currentDropReason = result.drop_reason;
                
                appendLog(`> Simulation complete. Engine traced ${simulationSteps.length} inspection layers.`, 'system');
                
                // Jump to first step automatically
                completePipeline();
            } else {
                appendLog(`> Simulation engine failed: ${result.message}`, 'danger');
            }
        } catch (err) {
            appendLog(`> Network connection failure to simulation API.`, 'danger');
        } finally {
            simulateBtn.disabled = false;
            simulateBtn.querySelector('.btn-text').textContent = 'Trace Packet Path';
        }
    });

    // Helper to identify animation-skippable steps
    function shouldSkipStepInAnimation(step) {
        if (step.id === 'pa_fast_ssl_decrypt') {
            return false;
        }
        return step.status === 'bypass';
    }

    // Navigation Controls Setup
    nextBtn.addEventListener('click', () => {
        let idx = currentStepIndex + 1;
        while (idx < simulationSteps.length && shouldSkipStepInAnimation(simulationSteps[idx])) {
            idx++;
        }
        if (idx < simulationSteps.length) {
            gotoStep(idx);
        } else if (currentStepIndex < simulationSteps.length - 1) {
            gotoStep(simulationSteps.length - 1);
        }
    });

    prevBtn.addEventListener('click', () => {
        let idx = currentStepIndex - 1;
        while (idx >= 0 && shouldSkipStepInAnimation(simulationSteps[idx])) {
            idx--;
        }
        if (idx >= 0) {
            gotoStep(idx);
        }
    });

    resetBtn.addEventListener('click', () => {
        resetSimulationState();
        appendLog(`> Simulation environment reset.`, 'system');
    });

    playPauseBtn.addEventListener('click', () => {
        if (simulationSteps.length === 0) return;

        if (isPlaying) {
            clearInterval(playInterval);
            playInterval = null;
            isPlaying = false;
            playPauseBtn.textContent = "Play";
            playPauseBtn.className = "ctrl-btn";
            appendLog(`> Animation paused.`, 'system');
        } else {
            isPlaying = true;
            playPauseBtn.textContent = "Pause";
            playPauseBtn.className = "ctrl-btn paused";
            appendLog(`> Animation playing...`, 'system');

            if (currentStepIndex >= simulationSteps.length - 1) {
                let firstIdx = 0;
                while (firstIdx < simulationSteps.length && shouldSkipStepInAnimation(simulationSteps[firstIdx])) {
                    firstIdx++;
                }
                if (firstIdx < simulationSteps.length) {
                    gotoStep(firstIdx);
                } else {
                    gotoStep(0);
                }
            }

            playInterval = setInterval(() => {
                let idx = currentStepIndex + 1;
                while (idx < simulationSteps.length && shouldSkipStepInAnimation(simulationSteps[idx])) {
                    idx++;
                }
                if (idx < simulationSteps.length) {
                    gotoStep(idx);
                } else {
                    clearInterval(playInterval);
                    playInterval = null;
                    isPlaying = false;
                    playPauseBtn.textContent = "Play";
                    playPauseBtn.className = "ctrl-btn";
                }
            }, 1800);
        }
    });

    // Node interactive click
    document.querySelectorAll('.node').forEach(nodeEl => {
        nodeEl.addEventListener('click', () => {
            const stepId = nodeEl.getAttribute('data-step');
            const stepIndex = simulationSteps.findIndex(s => s.id === stepId);
            if (stepIndex !== -1) {
                selectNodeForDetails(stepIndex);
            }
        });
    });

    // ============================================================
    // Dynamic CLI Commands Guide Generator
    // ============================================================
    function updateCLIGuide() {
        const guideBox = document.getElementById('guide-brand-content-box');
        if (!guideBox) return;

        guideBox.replaceChildren();

        const meta = currentScenario ? currentScenario.metadata : { src: "192.168.1.100", dst: "1.1.1.1", sport: "51001", dport: "80", proto: "TCP" };
        const srcIp = meta.src || "192.168.1.100";
        const dstIp = meta.dst || "1.1.1.1";
        const dstPort = meta.dport || "80";
        const srcPort = meta.sport || "51001";
        const proto = meta.proto ? meta.proto.replace(/\s*\(.*\)/, '') : "TCP";
        const protoNum = (proto === "UDP") ? "17" : ((proto === "ICMP") ? "1" : "6");

        let guideText = "";
        if (currentBrand === "fortigate") {
            guideText = `# Dynamic FortiGate CLI Flow Trace Commands
diagnose debug reset
diagnose debug flow filter saddr ${srcIp}
diagnose debug flow filter daddr ${dstIp}
diagnose debug flow filter dport ${dstPort}
diagnose debug flow show function-name enable
diagnose debug flow trace start 100
diagnose debug enable`;
        } else if (currentBrand === "checkpoint") {
            guideText = `# Check Point Active Kernel Monitor
fw monitor -e "accept (src=${srcIp} or dst=${dstIp});"`;
        } else if (currentBrand === "paloalto") {
            guideText = `# Palo Alto Security Policy & Route Engine
test security-policy-match source ${srcIp} destination ${dstIp} protocol ${protoNum} destination-port ${dstPort}`;
        } else if (currentBrand === "cisco") {
            guideText = `# Cisco FTD packet-tracer CLI Utility
packet-tracer input inside ${proto.toLowerCase()} ${srcIp} ${srcPort} ${dstIp} ${dstPort}`;
        } else {
            guideText = "# No debug guide matches active brand.";
        }
        
        const container = document.createElement('div');
        const pre = document.createElement('pre');
        pre.className = "guide-box";
        pre.textContent = guideText;
        container.appendChild(pre);

        guideBox.appendChild(container);
    }

    // Config sub-tabs toggle listeners
    document.querySelectorAll('.sub-tab').forEach(subTab => {
        subTab.addEventListener('click', () => {
            const targetTab = subTab.getAttribute('data-tab');
            if (!targetTab) return;

            subTab.parentElement.querySelectorAll('.sub-tab').forEach(b => b.classList.remove('active'));
            subTab.classList.add('active');

            document.querySelectorAll('.sub-tab-content').forEach(c => {
                c.classList.remove('active');
            });
            const activeContent = document.getElementById(`sub-tab-content-${targetTab}`);
            if (activeContent) {
                activeContent.classList.add('active');
            }

            const copyBtn = document.getElementById('copy-guide-btn');
            if (targetTab === 'attach') {
                if (copyBtn) copyBtn.style.display = 'none';
            } else if (targetTab === 'guide') {
                if (copyBtn) copyBtn.style.display = 'flex';
            }
        });
    });

    // Copy to clipboard listener for guides
    const copyGuideBtn = document.getElementById('copy-guide-btn');
    if (copyGuideBtn) {
        copyGuideBtn.addEventListener('click', () => {
            const guideBox = document.getElementById('guide-brand-content-box');
            if (guideBox) {
                const textContent = guideBox.innerText;
                navigator.clipboard.writeText(textContent).then(() => {
                    const originalText = copyGuideBtn.textContent;
                    copyGuideBtn.textContent = "Copied Guide!";
                    setTimeout(() => {
                        copyGuideBtn.textContent = originalText;
                    }, 2000);
                }).catch(() => {
                    // TODO(security): Use framework modal instead of alert for production
                    appendLog('> Failed to copy guide text to clipboard.', 'danger');
                });
            }
        });
    }

    // ============================================================
    // Custom Live Debug Log Parser (Override Mode)
    // ============================================================
    const rawDebugLog = document.getElementById('raw-debug-log');

    function processDebugLog() {
        try {
            const rawText = rawDebugLog.value.trim();
            if (!rawText) return;

            // Part 3: Activate custom trace state
            isCustomTrace = true;

            appendLog("> Custom trace log received. Analyzing signatures...", "system");

            // Start with defaults
            let payload_type = "clean_web";
            let security_intel = "clean";
            let existing_connection = false;
            let ssl_decrypt = false;
            let nat_type = "dynamic";

            // Parsed metadata (for override display)
            let parsedMeta = {
                src: "—", dst: "—", proto: "TCP", sport: "—", dport: "—", app: "unknown"
            };

            const textLower = rawText.toLowerCase();

            // 1. Dynamic brand auto-detection
            if (textLower.includes("func=print_pkt_detail") || textLower.includes("vd-root") || textLower.includes("trace_id=") || textLower.includes('msg="np outbound offload success"')) {
                const fgTab = document.querySelector('.brand-tab[data-brand="fortigate"]');
                if (fgTab && currentBrand !== "fortigate") {
                    appendLog("  [Auto-Detect] FortiGate debug log signature matched. Switching brand...", "success");
                    fgTab.click();
                }
            } 
            else if (textLower.includes("fw monitor") || textLower.includes("securexl") || textLower.includes("corexl") || textLower.includes("securexl path:")) {
                const cpTab = document.querySelector('.brand-tab[data-brand="checkpoint"]');
                if (cpTab && currentBrand !== "checkpoint") {
                    appendLog("  [Auto-Detect] Check Point debug log signature matched. Switching brand...", "success");
                    cpTab.click();
                }
            }
            else if (textLower.includes("security-policy-match") || textLower.includes("pan-os") || textLower.includes("stage: flow") || textLower.includes("flow_fastpath_process")) {
                const paTab = document.querySelector('.brand-tab[data-brand="paloalto"]');
                if (paTab && currentBrand !== "paloalto") {
                    appendLog("  [Auto-Detect] Palo Alto debug log signature matched. Switching brand...", "success");
                    paTab.click();
                }
            }
            else if (textLower.includes("packet-tracer") || textLower.includes("lina") || textLower.includes("snort") || textLower.includes("prefilter policy: rule matches action fastpath")) {
                const ftdTab = document.querySelector('.brand-tab[data-brand="cisco"]');
                if (ftdTab && currentBrand !== "cisco") {
                    appendLog("  [Auto-Detect] Cisco FTD debug log signature matched. Switching brand...", "success");
                    ftdTab.click();
                }
            }

            // 2. Initialize parsed logs overrides object
            window.parsedLogOverrides = {};

            // 3. Universal Token Extraction Layer — works across all vendor log formats
            let universalMatch = false;
            const dropDownArrowIp = /(?:from\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*[:\]]+(\d{1,5})\s*[-]?[>]*\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*[:\]]+(\d{1,5})/;
            const keyValuePair = /(?:^|\s)(?:src|saddr)=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\s,]*(?:sport|src_port)=(\d{1,5})/im;
            const keyValueDst = /(?:^|\s)(?:dst|daddr)=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\s,]*(?:dport|dst_port)=(\d{1,5})/im;
            const arrowFlow = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})\s*->\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})/;

            // Try FortiGate format first
            const fgPktRegex = /received a packet\(proto=(\d+),\s*([\d\.]+):(\d+)->([\d\.]+):(\d+)\)/i;
            const fgMatch = rawText.match(fgPktRegex);
            if (fgMatch) {
                const protoNum = parseInt(fgMatch[1]);
                parsedMeta.src = fgMatch[2];
                parsedMeta.sport = fgMatch[3];
                parsedMeta.dst = fgMatch[4];
                parsedMeta.dport = fgMatch[5];
                if (protoNum === 17) parsedMeta.proto = "UDP";
                else if (protoNum === 1) parsedMeta.proto = "ICMP";
                else parsedMeta.proto = "TCP";
                universalMatch = true;
                appendLog(`  [Parsed Flow] ${parsedMeta.src}:${parsedMeta.sport} -> ${parsedMeta.dst}:${parsedMeta.dport} (proto=${protoNum})`, "success");
            }

            // Try key=value src/sport dst/dport patterns
            if (!universalMatch) {
                const kvSrc = rawText.match(keyValuePair);
                const kvDst = rawText.match(keyValueDst);
                if (kvSrc) {
                    parsedMeta.src = kvSrc[1];
                    parsedMeta.sport = kvSrc[2];
                }
                if (kvDst) {
                    parsedMeta.dst = kvDst[1];
                    parsedMeta.dport = kvDst[2];
                }
                if (kvSrc || kvDst) {
                    // Extract protocol if present
                    const protoMatch = rawText.match(/(?:proto|protocol)=(\d+|6|17|1|tcp|udp|icmp)/i);
                    if (protoMatch) {
                        const p = protoMatch[1].toLowerCase();
                        if (p === '17' || p === 'udp') parsedMeta.proto = "UDP";
                        else if (p === '1' || p === 'icmp') parsedMeta.proto = "ICMP";
                        else parsedMeta.proto = "TCP";
                    }
                    universalMatch = true;
                    appendLog(`  [Parsed Flow] Key-value extraction: ${parsedMeta.src}:${parsedMeta.sport} -> ${parsedMeta.dst}:${parsedMeta.dport}`, "success");
                }
            }

            // Try arrow/IP:port->IP:port flow format
            if (!universalMatch) {
                const arrowMatch = rawText.match(arrowFlow);
                if (arrowMatch) {
                    parsedMeta.src = arrowMatch[1];
                    parsedMeta.sport = arrowMatch[2];
                    parsedMeta.dst = arrowMatch[3];
                    parsedMeta.dport = arrowMatch[4];
                    universalMatch = true;
                    appendLog(`  [Parsed Flow] Arrow-flow extraction: ${parsedMeta.src}:${parsedMeta.sport} -> ${parsedMeta.dst}:${parsedMeta.dport}`, "success");
                }
            }

            // Try generic from/to format (fw monitor style)
            if (!universalMatch) {
                const fromToMatch = rawText.match(dropDownArrowIp);
                if (fromToMatch) {
                    parsedMeta.src = fromToMatch[1];
                    parsedMeta.sport = fromToMatch[2];
                    parsedMeta.dst = fromToMatch[3];
                    parsedMeta.dport = fromToMatch[4];
                    appendLog(`  [Parsed Flow] From/To extraction: ${parsedMeta.src}:${parsedMeta.sport} -> ${parsedMeta.dst}:${parsedMeta.dport}`, "success");
                }
            }

            // Detect Application Protocol Identifier
            const appMatch = rawText.match(/(?:app|application)[=:]\s*([a-zA-Z0-9_.-]+)/i);
            if (appMatch) parsedMeta.app = appMatch[1].toLowerCase();
            else if (parsedMeta.dport === "443" || parsedMeta.dport === "8443") parsedMeta.app = "ssl";
            else if (parsedMeta.dport === "80" || parsedMeta.dport === "8080") parsedMeta.app = "http";
            else if (parsedMeta.dport === "53") parsedMeta.app = "dns";

            // FortiGate specific parsing
            const fgPolicyRegex = /policy-(\d+)|policy check denied|policy check.*policy\s*(\d+)/i;
            const fgPolicyMatch = rawText.match(fgPolicyRegex);
            if (fgPolicyMatch) {
                const policyId = fgPolicyMatch[1] || fgPolicyMatch[2];
                window.parsedLogOverrides.fgPolicyId = policyId;
                appendLog(`  [Parsed Log] FortiGate Policy ID resolved: ${policyId}`, "success");
            }

            if (/allocate a new session.*snat:/i.test(rawText) || /snat:\s*\d+\.\d+\.\d+\.\d+:\d+/i.test(rawText)) {
                window.parsedLogOverrides.fgSnat = true;
                appendLog("  [Parsed Log] FortiGate SNAT session allocation verified.", "success");
            }

            // Palo Alto specific parsing
            if (/flow_sequence_setup|Session allocated/i.test(rawText)) {
                window.parsedLogOverrides.paPath = 'slowpath';
                existing_connection = false;
                appendLog("  [Parsed Path] Palo Alto Slowpath (Session Setup) detected.", "success");
            } else if (/flow_fastpath_process/i.test(rawText)) {
                window.parsedLogOverrides.paPath = 'fastpath';
                existing_connection = true;
                appendLog("  [Parsed Path] Palo Alto Fastpath (SP3 Accelerated) detected.", "success");
            }

            const paAppIdRegex = /App-ID changed to:\s*([a-zA-Z0-9_-]+)/i;
            const paAppIdMatch = rawText.match(paAppIdRegex);
            if (paAppIdMatch) {
                const paAppId = paAppIdMatch[1];
                window.parsedLogOverrides.paAppId = paAppId;
                parsedMeta.app = paAppId;
                appendLog(`  [Parsed Log] Palo Alto App-ID changed to: ${paAppId}`, "success");
            }

            // Cisco FTD specific parsing
            if (/Phase:.*ROUTE-LOOKUP/i.test(rawText)) {
                window.parsedLogOverrides.ciscoRoute = true;
                appendLog("  [Parsed Phase] Cisco Route Lookup phase matched.", "success");
            }
            if (/Phase:.*ACCESS-LIST.*Result:\s*ALLOW/i.test(rawText)) {
                window.parsedLogOverrides.ciscoAcl = true;
                appendLog("  [Parsed Phase] Cisco ACCESS-LIST Permit result matched.", "success");
            }

            // 4. Implement target ingestion hooks for nested selector control
            let resolvedCategory = null;
            let resolvedOption = null;

            if (currentBrand === "fortigate") {
                // FortiGate Scenario A: Standard Forward Policy Drop
                if (textLower.includes("denied by forward policy check")) {
                    resolvedCategory = "cat_browsing";
                    resolvedOption = "opt_browsing_deny";
                }
                // FortiGate Scenario B: ASIC Fastpath Session Bypass Hit
                else if (textLower.includes('msg="np outbound offload success"') || textLower.includes("find an existing session")) {
                    resolvedCategory = "cat_acceleration";
                    resolvedOption = "fg_acc_np";
                }
                // FortiGate Scenario C: CP9 Deep SSL Decryption
                else if (textLower.includes("profile: deep-inspection active") && textLower.includes("ssl decrypt success")) {
                    resolvedCategory = "cat_ssl";
                    resolvedOption = "opt_ssl_deep";
                }
                // FortiGate Scenario D+E: Security Profile Check Threats
                else if (textLower.includes("security profile check") && (textLower.includes('action="drop"') || textLower.includes('action drop') || textLower.includes('drop'))) {
                    resolvedCategory = "cat_threat";
                    if (textLower.includes('profile="ips"') || textLower.includes("ips exploit") || textLower.includes("ips")) {
                        resolvedOption = "fg_threat_ips";
                    } else if (textLower.includes('profile="av"') || textLower.includes("antivirus") || textLower.includes("av")) {
                        resolvedOption = "fg_threat_av";
                    } else if (textLower.includes('profile="dlp"') || textLower.includes("dlp scan") || textLower.includes("dlp")) {
                        resolvedOption = "fg_threat_dlp";
                    } else if (textLower.includes('profile="webfilter"') || textLower.includes('profile="wf"') || textLower.includes("webfilter") || textLower.includes("wf")) {
                        resolvedOption = "fg_threat_wf";
                    }
                }
                // FortiGate: ips_signature_match + drop
                else if (textLower.includes("ips_signature_match") && textLower.includes("action=drop")) {
                    resolvedCategory = "cat_threat";
                    resolvedOption = "fg_threat_ips";
                }
            } 
            else if (currentBrand === "checkpoint") {
                // Check Point Scenario A: SecureXL Template Fast Path Hit
                if (textLower.includes("securexl path: packet acceleration") || textLower.includes("sxl template match")) {
                    resolvedCategory = "cat_acceleration";
                    resolvedOption = "cp_acc_fast";
                }
                // Check Point Scenario B: SecureXL PXL Medium Path Streaming
                else if (textLower.includes("securexl path: medium path") || textLower.includes("securexl: outbound streaming pass") || textLower.includes("pxl tracking initialized")) {
                    resolvedCategory = "cat_acceleration";
                    resolvedOption = "cp_acc_pxl";
                }
                // Check Point Scenario C: HTTPS Inspection Certificate Drop
                else if (textLower.includes("https inspection: untrusted certificate") && textLower.includes("action: drop")) {
                    resolvedCategory = "cat_ssl";
                    resolvedOption = "opt_ssl_deny";
                }
                // Check Point Scenario D: Anti-Bot C2 Callback Drop
                else if (textLower.includes("blade: antibot") && (textLower.includes("verdict: drop") || textLower.includes("verdict drop") || textLower.includes("drop"))) {
                    resolvedCategory = "cat_threat";
                    resolvedOption = "cp_threat_bot";
                }
                // Check Point Scenario E: Threat Emulation Zero-Day Block
                else if (textLower.includes("blade: threat emulation") && textLower.includes("action: drop")) {
                    resolvedCategory = "cat_threat";
                    resolvedOption = "cp_threat_te";
                }
            } 
            else if (currentBrand === "paloalto") {
                // Palo Alto Scenario A: Data Plane Session Fastpath Processing
                if (textLower.includes("flow_fastpath_process") || textLower.includes("hardware offload match")) {
                    resolvedCategory = "cat_acceleration";
                    resolvedOption = "pa_acc_fast";
                }
                // Palo Alto Scenario B: SSL Decryption Proxy Core Untrusted Failure
                else if (textLower.includes("decryption profile rule matched") && textLower.includes("action: drop-expired-cert")) {
                    resolvedCategory = "cat_ssl";
                    resolvedOption = "opt_ssl_deny";
                }
                // Palo Alto Scenario C: Content-ID Vulnerability Protection Drop (IPS)
                else if (textLower.includes("vulnerability exploit pattern matched") && textLower.includes("action: drop")) {
                    resolvedCategory = "cat_threat";
                    resolvedOption = "pa_threat_ips";
                }
                // Palo Alto Scenario D: WildFire Cloud Sandboxing File Drop
                else if (textLower.includes("wildfire sandbox: file hash") && textLower.includes("action: reset-both")) {
                    resolvedCategory = "cat_threat";
                    resolvedOption = "pa_threat_wf";
                }
                // Palo Alto Scenario E: App-ID Enforcement Drop
                else if (textLower.includes("app-id block: sub-application block matched") || textLower.includes("app-id transition verified") || textLower.includes("policy re-match evaluated")) {
                    resolvedCategory = "cat_threat";
                    resolvedOption = "pa_threat_app";
                }
            } 
            else if (currentBrand === "cisco") {
                // Cisco FTD Scenario A: LINA Prefilter Fastpath Bypass
                if (textLower.includes("prefilter policy: rule matches action fastpath") || textLower.includes("action fastpath")) {
                    resolvedCategory = "cat_acceleration";
                    resolvedOption = "ftd_acc_fast";
                }
                // Cisco FTD Scenario B: Security Intelligence Blacklist IP Drop
                else if (textLower.includes("talos security intelligence") && textLower.includes("action: drop")) {
                    resolvedCategory = "cat_threat";
                    resolvedOption = "ftd_threat_si";
                }
                // Cisco FTD Scenario C: Snort 3 IPS Engine Signature Match Drop
                else if (textLower.includes("snort 3 ips: gid") && textLower.includes("action: drop")) {
                    resolvedCategory = "cat_threat";
                    resolvedOption = "ftd_threat_ips";
                }
                // Cisco FTD Scenario D: AMP for Networks File Hash Match
                else if (textLower.includes("amp for networks: executable file hash lookup matched")) {
                    resolvedCategory = "cat_threat";
                    resolvedOption = "ftd_threat_amp";
                }
            }

            if (resolvedCategory && resolvedOption) {
                appendLog(`  [Log Ingestion Sync] Raw log signature matched option: ${resolvedOption} in category: ${resolvedCategory}`, "success");
                
                // Update dropdown values
                if (categorySelect) categorySelect.value = resolvedCategory;
                populateOptions(resolvedCategory, resolvedOption);

                const optMeta = optionMetadata[resolvedOption];
                if (optMeta) {
                    // Merge parsed flow details if they were resolved
                    if (fgMatch) {
                        optMeta.metadata.src = parsedMeta.src;
                        optMeta.metadata.sport = parsedMeta.sport;
                        optMeta.metadata.dst = parsedMeta.dst;
                        optMeta.metadata.dport = parsedMeta.dport;
                        optMeta.metadata.proto = parsedMeta.proto;
                    }
                    
                    applyOption(resolvedOption);
                    
                    // Explicit override banner display
                    isOverrideMode = true;
                    if (overrideIndicator) overrideIndicator.style.display = 'inline-flex';
                    
                    if (metaContextBar) {
                        metaContextBar.textContent = `Override Mode (Synchronized): Pasted CLI log matched diagnostic option — ${optMeta.contextText || ""}`;
                    }
                }
            } else {
                // Fall back to building custom overrideScenario if no specific target hook matched
                appendLog("  [Log Ingestion Sync] No specific threat/acceleration signature matched. Using generic parsed values.", "info");
                
                if (textLower.includes("union select") || textLower.includes("sql injection") || textLower.includes("prevent") || textLower.includes("ips exploit")) {
                    payload_type = "sql_injection";
                    parsedMeta.app = "sql-exploit";
                } else if (textLower.includes("malware") || textLower.includes("virus") || textLower.includes("wildfire") || textLower.includes("eicar")) {
                    payload_type = "malware";
                    parsedMeta.app = "malware-file";
                } else if (textLower.includes("gambling") || textLower.includes("url filtering") || textLower.includes("category")) {
                    payload_type = "blocked_url";
                    parsedMeta.app = "web-browsing";
                } else if (textLower.includes("vpn") || textLower.includes("ipsec") || textLower.includes("esp") || textLower.includes("decrypted")) {
                    payload_type = "vpn_in";
                    parsedMeta.app = "ipsec-encapsulated";
                }

                if (textLower.includes("denied by forward policy") || textLower.includes("denied by policy") || textLower.includes("policy check denied") || textLower.includes("denied by") || textLower.includes("policy deny") || textLower.includes("deny")) {
                    security_intel = "blacklisted_dns";
                }

                if (textLower.includes("fastpath") || textLower.includes("securexl connection hit") || textLower.includes("session matched") || textLower.includes("existing connection") || textLower.includes("existing session") || textLower.includes("fast path")) {
                    existing_connection = true;
                }

                if (textLower.includes("decrypt") || textLower.includes("ssl proxy") || textLower.includes("forward proxy")) {
                    ssl_decrypt = true;
                }

                if (textLower.includes("dnat") || textLower.includes("destination nat")) {
                    nat_type = "static";
                } else if (textLower.includes("snat") || textLower.includes("source nat") || textLower.includes("hide nat")) {
                    nat_type = "dynamic";
                }

                const overrideScenario = {
                    id: "override_parsed",
                    label: "Override: Parsed Debug Log",
                    description: "Parameters extracted from pasted raw CLI debug trace output.",
                    metadata: parsedMeta,
                    engineFlags: {
                        useVpn: (payload_type === 'vpn_in'),
                        useSsl: ssl_decrypt,
                        pathType: existing_connection ? 'fastpath' : 'slowpath',
                        targetEngine: 'l4_core'
                    },
                    simParams: {
                        payload_type: payload_type,
                        existing_connection: existing_connection,
                        ssl_decrypt: ssl_decrypt,
                        nat_type: nat_type,
                        security_intel: security_intel
                    }
                };

                currentScenario = overrideScenario;
                isOverrideMode = true;
                if (overrideIndicator) overrideIndicator.style.display = 'inline-flex';

                updateMetadataTokens(parsedMeta);

                if (metaContextBar) {
                    metaContextBar.textContent = `Override Mode: Parameters extracted from pasted CLI debug trace.`;
                }
            }

            // Sync CLI guide with parsed metadata
            updateCLIGuide();
            
            // Trigger reactive rendering
            syncPipelineReactivity();

            appendLog("> Dynamic trace log parameters compiled. Triggering packet simulation...", "success");

            // Trigger simulation
            simulateBtn.click();
        } catch (err) {
            appendLog(`> Error during parsing: ${err.message}`, "danger");
        }
    }

    let parseTimeout = null;
    if (rawDebugLog) {
        rawDebugLog.addEventListener('input', () => {
            clearTimeout(parseTimeout);
            parseTimeout = setTimeout(() => {
                processDebugLog();
            }, 400);
        });
    }

    // ============================================================
    // Dynamic Pipeline Reactivity (driven by scenario engineFlags)
    // ============================================================
    function syncPipelineReactivity() {
        if (!currentScenario) return;

        const flags = currentScenario.engineFlags;
        const isFastpath = flags.pathType === 'fastpath';
        const isDecrypt = flags.useSsl;
        const isVpnTraffic = flags.useVpn;
        const natType = currentScenario.simParams.nat_type;

        const container = document.getElementById('pipeline-canvas-container');
        if (!container) return;

        // 1. Decrypt reactivity
        document.querySelectorAll('[id*="ssl_decrypt"], [id*="ssl_encrypt"], [id*="ssl_check"], [id*="ssl_proxy"]').forEach(node => {
            if (isDecrypt) {
                node.classList.remove('node-disabled');
            } else {
                node.classList.add('node-disabled');
            }
        });

        // 2. NAT reactivity
        document.querySelectorAll('[id*="snat"], [id*="nat_src"], [id*="egress_nat"]').forEach(node => {
            if (natType === 'none') {
                node.classList.add('node-disabled');
            } else {
                node.classList.remove('node-disabled');
            }
        });

        // 3.1 Palo Alto Fastpath
        const paloaltoFlow = document.getElementById('brand-flow-paloalto');
        if (paloaltoFlow) {
            const paSwimlanes = paloaltoFlow.querySelector('.pipeline-swimlanes');
            if (paSwimlanes) {
                const branches = paSwimlanes.querySelectorAll('.swimlane-branch');
                if (branches.length === 2) {
                    const slowpathBranch = branches[0];
                    const fastpathBranch = branches[1];
                    if (isFastpath) {
                        slowpathBranch.style.opacity = '0.35';
                        slowpathBranch.style.filter = 'grayscale(0.7)';
                        fastpathBranch.style.opacity = '1';
                        fastpathBranch.style.filter = 'none';
                    } else {
                        slowpathBranch.style.opacity = '1';
                        slowpathBranch.style.filter = 'none';
                        fastpathBranch.style.opacity = '0.35';
                        fastpathBranch.style.filter = 'grayscale(0.7)';
                    }
                }
            }

            const appIdTitle = paloaltoFlow.querySelector('.pa-bypass-wrapper .palo-header');
            const appIdGrid = paloaltoFlow.querySelector('.pa-bypass-wrapper .palo-header + .pipeline-grid');
            if (isFastpath) {
                paloaltoFlow.classList.add('pa-fastpath-active');
                if (appIdTitle) appIdTitle.style.opacity = '0.35';
                if (appIdGrid) {
                    appIdGrid.style.opacity = '0.35';
                    appIdGrid.style.filter = 'grayscale(0.7)';
                }
            } else {
                paloaltoFlow.classList.remove('pa-fastpath-active');
                if (appIdTitle) appIdTitle.style.opacity = '1';
                if (appIdGrid) {
                    appIdGrid.style.opacity = '1';
                    appIdGrid.style.filter = 'none';
                }
            }
        }

        // 3.2 FortiGate Fastpath
        const fortigateFlow = document.getElementById('brand-flow-fortigate');
        if (fortigateFlow) {
            const slowpathRow = fortigateFlow.querySelector('.fg-bypass-wrapper .pipeline-grid:nth-of-type(2)');
            const fpArrows = fortigateFlow.querySelectorAll('.fg-fastpath-bypass-arrow');
            if (isFastpath) {
                fortigateFlow.classList.add('fg-fastpath-active');
                if (slowpathRow) {
                    slowpathRow.style.opacity = '0.35';
                    slowpathRow.style.filter = 'grayscale(0.7)';
                }
                fpArrows.forEach(arrow => {
                    arrow.classList.add('opacity-20');
                });
                // ASIC offload bypasses Host CPU pipeline entirely
                ['node-fg_routing_in', 'node-fg_tcp_sanity', 'node-fg_session_lookup', 'node-fg_proxy_decision'].forEach(id => {
                    const node = document.getElementById(id);
                    if (node) node.classList.add('node-disabled');
                });
            } else {
                fortigateFlow.classList.remove('fg-fastpath-active');
                if (slowpathRow) {
                    slowpathRow.style.opacity = '1';
                    slowpathRow.style.filter = 'none';
                }
                fpArrows.forEach(arrow => {
                    arrow.classList.remove('opacity-20');
                });
                ['node-fg_routing_in', 'node-fg_tcp_sanity', 'node-fg_session_lookup', 'node-fg_proxy_decision'].forEach(id => {
                    const node = document.getElementById(id);
                    if (node) node.classList.remove('node-disabled');
                });
            }
        }

        // 3.3 Check Point Fastpath
        const checkpointFlow = document.getElementById('brand-flow-checkpoint');
        if (checkpointFlow) {
            let cpPath = 'slowpath';
            if (flags.pathType === 'fastpath') {
                cpPath = 'fastpath';
            } else if (flags.pathType === 'mediumpath') {
                cpPath = 'pxl';
            } else {
                // Dynamic log fallback check
                if (isFastpath) {
                    const payloadVal = currentScenario.simParams.payload_type;
                    if (['malware', 'blocked_url', 'sql_injection'].includes(payloadVal)) {
                        cpPath = 'pxl';
                    } else {
                        cpPath = 'fastpath';
                    }
                }
            }

            checkpointFlow.classList.remove('cp-fastpath-active', 'cp-pxl-active', 'cp-slowpath-active');
            
            const fastpathBranch = checkpointFlow.querySelector('.check-point-swimlanes .swimlane-branch:nth-child(1)');
            const pxlBranch = checkpointFlow.querySelector('.check-point-swimlanes .swimlane-branch:nth-child(2)');
            const f2fBranch = checkpointFlow.querySelector('.check-point-swimlanes .swimlane-branch:nth-child(3)');

            const allBranches = [fastpathBranch, pxlBranch, f2fBranch];
            allBranches.forEach(b => {
                if (b) {
                    b.style.opacity = '0.35';
                    b.style.filter = 'grayscale(0.7)';
                }
            });

            if (cpPath === 'fastpath') {
                checkpointFlow.classList.add('cp-fastpath-active');
                if (fastpathBranch) {
                    fastpathBranch.style.opacity = '1';
                    fastpathBranch.style.filter = 'none';
                }
            } else if (cpPath === 'pxl') {
                checkpointFlow.classList.add('cp-pxl-active');
                if (pxlBranch) {
                    pxlBranch.style.opacity = '1';
                    pxlBranch.style.filter = 'none';
                }
            } else {
                checkpointFlow.classList.add('cp-slowpath-active');
                if (f2fBranch) {
                    f2fBranch.style.opacity = '1';
                    f2fBranch.style.filter = 'none';
                }
            }
        }

        // 3.4 Cisco FTD Fastpath
        const ciscoFlow = document.getElementById('brand-flow-cisco');
        if (ciscoFlow) {
            const isCiscoBypass = (currentScenario.simParams.payload_type === 'prefilter_fastpath' || isFastpath);
            const ciscoSnortTitle = ciscoFlow.querySelector('.snort-header');
            const ciscoSnortGrid = ciscoFlow.querySelector('.snort-header + .pipeline-grid');
            if (isCiscoBypass) {
                ciscoFlow.classList.add('cisco-fastpath-active');
                if (ciscoSnortTitle) ciscoSnortTitle.style.opacity = '0.35';
                if (ciscoSnortGrid) {
                    ciscoSnortGrid.style.opacity = '0.35';
                    ciscoSnortGrid.style.filter = 'grayscale(0.8)';
                }
            } else {
                ciscoFlow.classList.remove('cisco-fastpath-active');
                if (ciscoSnortTitle) ciscoSnortTitle.style.opacity = '1';
                if (ciscoSnortGrid) {
                    ciscoSnortGrid.style.opacity = '1';
                    ciscoSnortGrid.style.filter = 'none';
                }
            }
        }

        // 4. Global VPN boundary nodes reactivity
        document.querySelectorAll(
            '#node-vpn_decrypt, #node-vpn_encrypt, ' +
            '#node-pa_ingress_vpn_decrypt, #node-pa_egress_vpn_encrypt, ' +
            '#node-fg_ipsec_in, #node-fg_ipsec_out, ' +
            '#node-cp_snd_decrypt, #node-cp_egress_encrypt'
        ).forEach(node => {
            if (isVpnTraffic) {
                node.classList.remove('node-disabled');
            } else {
                node.classList.add('node-disabled');
            }
        });
    }

    // ============================================================
    // Initialize with default category, option, and guides
    // ============================================================
    populateCategoriesAndOptions();
    if (categorySelect) categorySelect.value = 'cat_browsing';
    populateOptions('cat_browsing', 'opt_browsing_allow');
    updateCLIGuide();
    setTimeout(syncPipelineReactivity, 300);
});
