import os
import secrets
from flask import Flask, jsonify, request, render_template

app = Flask(__name__)

# Security configuration (Random session key per run)
app.secret_key = secrets.token_hex(32)

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response


@app.route('/')
def index():
    return render_template('index.html')

def make_step(step_id, vendor_id, title, sub_title, status, verdict, description, behavior, mock_cli=""):
    """
    Helper to generate a step dictionary supporting both:
    1. Legacy properties: id, name, component, status, description, explanation, details
    2. InspectionStepMetadata properties: id, vendorId, title, subTitle, verdict, description, technicalBehaviorDetails, mockCliLogLine
    """
    # Map status to verdict if not specified
    if not verdict:
        if status == 'pass':
            verdict = 'ALLOWED'
        elif status == 'fail':
            verdict = 'DROPPED'
        elif status == 'bypass':
            verdict = 'FASTPATH'
        else:
            verdict = 'INSPECTING'

    return {
        # Legacy properties
        "id": step_id,
        "name": title,
        "component": sub_title,
        "status": status,
        "explanation": description,
        "details": behavior,

        # InspectionStepMetadata properties
        "vendorId": vendor_id,
        "title": title,
        "subTitle": sub_title,
        "verdict": verdict,
        "description": description,
        "technicalBehaviorDetails": behavior,
        "mockCliLogLine": mock_cli
    }

@app.route('/api/simulate', methods=['POST'])
def simulate():
    try:
        data = request.json or {}
        
        # Inputs & Sanity validation
        brand = str(data.get('brand', 'fortigate')).lower().strip()
        src_ip = str(data.get('src_ip', '192.168.1.100')).strip()
        dst_ip = str(data.get('dst_ip', '1.1.1.1')).strip()
        src_port = int(data.get('src_port', 51234))
        dst_port = int(data.get('dst_port', 80))
        protocol = str(data.get('protocol', 'TCP')).upper()
        payload_type = str(data.get('payload_type', 'clean_web')).strip()
        existing_conn = bool(data.get('existing_connection', False))
        ssl_decrypt = bool(data.get('ssl_decrypt', False))
        nat_type = str(data.get('nat_type', 'dynamic')).strip()
        sec_intel = str(data.get('security_intel', 'clean')).strip()
        path_type = str(data.get('path_type', '')).strip().lower()
        option_id = str(data.get('option_id', '')).strip().lower()

        # Enforce Crypto Offload requirements: VPN Decrypt/Encrypt and SSL Decrypt
        if option_id == 'fg_acc_cp':
            payload_type = 'vpn_in'
            ssl_decrypt = True

        # Force verdict parameters (driven by UI segmented control)
        force_verdict_raw = data.get('force_verdict', None)
        target_engine_raw = data.get('target_engine', None)
        # Validate against allow-lists
        valid_force_verdicts = ['allow', 'deny']
        valid_target_engines = ['l4_core', 'ips_engine', 'malware_engine', 'url_filter',
                                'vpn_engine', 'acl_rulebase', 'auth_engine', 'threat_intel',
                                'ssl_engine', 'prefilter']
        force_verdict = str(force_verdict_raw).strip().lower() if force_verdict_raw else None
        target_engine = str(target_engine_raw).strip().lower() if target_engine_raw else None
        if force_verdict not in valid_force_verdicts:
            force_verdict = None
        if target_engine not in valid_target_engines:
            target_engine = None

        # Bounds validation
        src_port = max(1, min(src_port, 65535))
        dst_port = max(1, min(dst_port, 65535))
        if protocol not in ['TCP', 'UDP', 'ICMP', 'ESP']:
            protocol = 'TCP'

        # Determine flow direction dynamically
        is_internal_src = src_ip.startswith('192.168.') or src_ip.startswith('10.') or src_ip.startswith('172.16.')
        ingress_interface = "inside" if is_internal_src else "outside"
        egress_interface = "outside" if is_internal_src else "inside"
        
        steps = []
        verdict = "ALLOW"
        drop_reason = None
        
        current_src_ip = src_ip
        current_dst_ip = dst_ip
        current_src_port = src_port
        current_dst_port = dst_port

        # ----------------------------------------------------
        # 1. FORTIGATE SIMULATION PIPELINE
        # ----------------------------------------------------
        if brand == 'fortigate':
            vendor_id = 'fortigate'
            # Stage 1: Ingress Packet Flow
            steps.append(make_step("fg_ingress", vendor_id, "Interface (L2)", "FortiOS", "pass", "ALLOWED",
                "Frame received on physical interface 'port1'. Link layer checks complete.",
                f"Interface: port1. MAC: 00:50:56:be:ef:10. MTU: 1500.",
                f"FGT-11 # id=65308 trace_id=301 func=print_pkt_detail msg=\"vd-root:0 received a packet(proto=6, {src_ip}:{src_port}->{dst_ip}:{dst_port}) from port1.\""))

            if sec_intel == 'blacklisted_ip' and not existing_conn:
                steps.append(make_step("fg_dos", vendor_id, "DoS Sensor", "FortiOS SPU", "fail", "DROPPED",
                    "DoS sensor blocked source IP due to suspicious flood signature rate.",
                    "SPU DoS Drop: Packet flood limit exceeded.",
                    "id=65308 trace_id=301 func=dos_sensor_check msg=\"Denied by DoS anomaly policy rule ID 1.\""))
                verdict = "DROP"
                drop_reason = "DoS Policy Block"
            else:
                steps.append(make_step("fg_dos", vendor_id, "DoS Sensor", "FortiOS SPU", "pass", "ALLOWED",
                    "DoS sensor validated packet flow rate as safe.",
                    "SPU DoS Pass: Normal connections limits.",
                    "id=65308 trace_id=301 func=dos_sensor_check msg=\"DoS sensor check passed.\""))

            if verdict == "ALLOW":
                steps.append(make_step("fg_integrity", vendor_id, "IP Integrity", "FortiOS", "pass", "ALLOWED",
                    "IPv4 header parsed successfully. Checksum and size are valid.",
                    "IP header integrity verified. TTL: 64.",
                    "id=65308 trace_id=301 func=ip_integrity_check msg=\"IP checksum valid.\""))
            else:
                steps.append(make_step("fg_integrity", vendor_id, "IP Integrity", "FortiOS", "bypass", "FASTPATH", "Skipped.", "Status: Bypassed."))

            if verdict == "ALLOW" and (payload_type == "vpn_in" or option_id == "fg_acc_cp"):
                desc = "ESP payload matched crypto map association. SPU decrypted tunnel frame."
                behavior = "SPI: 0x93FA, Cipher: AES256-GCM. Extracted cleartext headers."
                if option_id == "fg_acc_cp":
                    desc = "SPU CP9 Cryptographic Engine hardware offload success. Bulk IPsec decryption completed in specialized ASICs, bypassing host CPU."
                    behavior = "SPI: 0x93FA. SPU CP9 Processing Metrics: Throughput: 40 Gbps, Latency: 2.1μs, Crypto Engine Queue Depth: 0."
                steps.append(make_step("fg_ipsec_in", vendor_id, "IPsec Decrypt", "FortiOS VPN", "decrypt", "INSPECTING",
                    desc, behavior,
                    "id=65308 trace_id=301 func=ipsec_tunnel_decrypt msg=\"ESP packet decrypted successfully.\""))
            else:
                steps.append(make_step("fg_ipsec_in", vendor_id, "IPsec Decrypt", "FortiOS VPN", "bypass", "FASTPATH",
                    "No IPsec VPN encapsulation detected.", "Bypassed VPN decryption."))

            if verdict == "ALLOW" and nat_type == 'static' and ingress_interface == 'outside':
                current_dst_ip = "10.0.0.100"
                steps.append(make_step("fg_dnat", vendor_id, "NAT (DNAT)", "FortiOS VIP", "nat", "INSPECTING",
                    f"Virtual IP rule matched. Translating Destination to internal server {current_dst_ip}.",
                    f"VIP Object: WebServer_VIP. Destination rewritten to {current_dst_ip}.",
                    "id=65308 trace_id=301 func=dnat_lookup msg=\"Match Virtual IP object. Destination translated.\""))
            else:
                steps.append(make_step("fg_dnat", vendor_id, "NAT (DNAT)", "FortiOS VIP", "bypass", "FASTPATH",
                    "No Virtual IP mapping matched. Destination IP unchanged.", f"Destination: {dst_ip}"))

            if verdict == "ALLOW":
                steps.append(make_step("fg_routing_in", vendor_id, "Routing Lookup", "FortiOS", "pass", "ALLOWED",
                    f"Routing table lookup succeeded for target destination {current_dst_ip}.",
                    f"Egress interface: port2. Next hop gateway: 203.0.113.1.",
                    "id=65308 trace_id=301 func=__vf_ip_route_input_rcu msg=\"find a route: via port2\""))
            else:
                steps.append(make_step("fg_routing_in", vendor_id, "Routing Lookup", "FortiOS", "bypass", "FASTPATH", "Skipped.", "Status: Bypassed."))

            if verdict == "ALLOW":
                steps.append(make_step("fg_tcp_sanity", vendor_id, "TCP State Sanity Check", "FortiOS L4", "pass", "ALLOWED",
                    "TCP 3-way handshake validation clean. Window sequence checks verified.",
                    "L4 TCP state validation: ESTABLISHED.",
                    "id=65308 trace_id=301 func=tcp_state_sanity msg=\"TCP state check valid. Window sequence in sync.\""))
            else:
                steps.append(make_step("fg_tcp_sanity", vendor_id, "TCP State Sanity Check", "FortiOS L4", "bypass", "FASTPATH", "Skipped.", "Status: Bypassed."))

            # Stage 2: Stateful Engine Fork
            steps.append(make_step("fg_session_lookup", vendor_id, "Session Table Lookup", "FortiOS Stateful", "pass",
                "FASTPATH" if existing_conn else "INSPECTING",
                "Existing session located in active session lookup table." if existing_conn else "No existing session found. Processing slow-path setup.",
                f"Offload hardware state: {'NP7 SPU session hit' if existing_conn else 'Session miss'}.",
                f"id=65308 trace_id=301 func=resolve_ip_tuple_fast msg=\"{'Find an existing session' if existing_conn else 'No existing session found'}.\""))

            # If existing_conn is FALSE -> execute slowpath policy lookups
            is_slowpath = not existing_conn
            
            if verdict == "ALLOW" and is_slowpath:
                steps.append(make_step("fg_session_helpers", vendor_id, "Session Helpers", "FortiOS Helpers", "pass", "INSPECTING",
                    "No helper pinholes required for target port.", f"Port: {dst_port}.",
                    "id=65308 trace_id=301 func=session_helper_check msg=\"No helper matched.\""))
                
                steps.append(make_step("fg_auth", vendor_id, "Authentication", "FortiOS Auth", "pass", "INSPECTING",
                    "User identity resolved passively via FortiAuthenticator.", "User: guest_developer (FSSO)",
                    "id=65308 trace_id=301 func=fsso_auth_check msg=\"FSSO authenticated user guest_developer.\""))
                
                steps.append(make_step("fg_mgmt", vendor_id, "Local Mgmt Traffic Check", "FortiOS Management", "pass", "INSPECTING",
                    "Traffic is transit, not bound for local system IPs.", "Management IP matched: No.",
                    "id=65308 trace_id=301 func=local_mgmt_check msg=\"Packet is transit.\""))

                if sec_intel == 'blacklisted_dns':
                    steps.append(make_step("fg_policy", vendor_id, "Firewall Policy Lookup", "FortiOS Rulebase", "fail", "DROPPED",
                        "Denied by forward policy check. Destination IP resides inside forbidden C2 subnet.",
                        "Policy ID: 2 (Deny).",
                        "id=65308 trace_id=301 func=fw_forward_handler msg=\"Denied by forward policy check (policy 2)\""))
                    verdict = "DROP"
                    drop_reason = "Firewall Policy Denied"
                else:
                    steps.append(make_step("fg_policy", vendor_id, "Firewall Policy Lookup", "FortiOS Rulebase", "pass", "ALLOWED",
                        "Firewall Policy ID 5 'Permit_LAN' matched. Action: ACCEPT.",
                        "Policy ID: 5. Flow-based security profiling enabled.",
                        "id=65308 trace_id=301 func=fw_forward_handler msg=\"Allowed by policy 5. Session created.\""))
            else:
                # Bypassed slowpath steps
                for sid, name in [("fg_session_helpers", "Session Helpers"), ("fg_auth", "Authentication"), 
                                  ("fg_mgmt", "Local Mgmt Traffic Check"), ("fg_policy", "Firewall Policy Lookup")]:
                    steps.append(make_step(sid, vendor_id, name, "FortiOS", "bypass", "FASTPATH", 
                        "Bypassed by fastpath session hit.", "Status: Bypassed."))

            # Stage 2.5: SSL Inspection Gateway
            ssl_check_desc = "SSL Deep Inspection profile is active on matched policy." if ssl_decrypt else "SSL Deep Inspection is not requested or protocol is cleartext."
            ssl_check_behavior = f"Decrypt target profile: {'Deep_SSL_Inspection' if ssl_decrypt else 'Bypassed'}."
            if option_id == "fg_acc_cp" and ssl_decrypt:
                ssl_check_desc = "SSL Deep Inspection profile active. Hardware validation scheduled on CP9 content processor coprocessor cluster."
                ssl_check_behavior = "CP9 Core load: 12%, Certificate status: VALID, Hardware session ID: 0x98f41a."
            steps.append(make_step("fg_ssl_check", vendor_id, "SSL Deep Inspection Profile Check", "FortiOS SSL Gateway", 
                "pass" if option_id == "fg_acc_cp" else ("decrypt" if ssl_decrypt else "bypass"),
                "ALLOWED" if option_id == "fg_acc_cp" else ("INSPECTING" if ssl_decrypt else "FASTPATH"),
                ssl_check_desc, ssl_check_behavior,
                "id=65308 trace_id=301 func=ssl_gateway_profile msg=\"SSL profile matched.\""))

            if verdict == "ALLOW" and ssl_decrypt:
                ssl_dec_desc = "SSL session decrypted using local sensor proxy certificate. Exposing payload."
                ssl_dec_behavior = "Cipher: TLS_AES_256_GCM_SHA384."
                if option_id == "fg_acc_cp":
                    ssl_dec_desc = "SSL session decrypted via SPU CP9 content processor hardware coprocessor. Decryption offloaded completely to protect kernel space."
                    ssl_dec_behavior = "Cipher: TLS_AES_256_GCM_SHA384. CP9/CP10 Offload Metrics: Decryption Rate: 15,000 req/sec, CP Core Latency: 1.4μs."
                steps.append(make_step("fg_ssl_decrypt", vendor_id, "SSL Decrypt", "FortiOS SSL Gateway", 
                    "pass" if option_id == "fg_acc_cp" else "decrypt", 
                    "ALLOWED" if option_id == "fg_acc_cp" else "INSPECTING",
                    ssl_dec_desc, ssl_dec_behavior,
                    "id=65308 trace_id=301 func=ssl_decrypt_payload msg=\"Cleartext stream exposed for UTM scan.\""))
            else:
                steps.append(make_step("fg_ssl_decrypt", vendor_id, "SSL Decrypt", "FortiOS SSL Gateway", "bypass", "FASTPATH",
                    "SSL decryption bypassed or cleartext traffic.", "Decryption: Bypassed."))

            # Stage 3 & 4: UTM Split (Flow / Proxy engines)
            has_utm = verdict == "ALLOW" and not existing_conn
            
            # Stage 3: Flow-Based UTM Engine
            if has_utm:
                steps.append(make_step("fg_sec_decision", vendor_id, "Security Profile Check", "FortiOS UTM", "pass", "INSPECTING",
                    "Flow-based profiles are enabled. Initializing UTM flow scanning.", "Active: IPS, AppCtrl.",
                    "id=65308 trace_id=301 func=utm_flow_init msg=\"Flow UTM engine started.\""))
                
                if payload_type == "sql_injection":
                    steps.append(make_step("fg_ips", vendor_id, "IPS Engine", "FortiOS UTM", "fail", "DROPPED",
                        "Intrusion Prevention System matched exploit signature: Web.Database.SQL.Injection.Union.",
                        "Verdict: DROP. Pattern 'UNION SELECT' detected.",
                        "id=65308 trace_id=301 func=ips_engine_scan msg=\"Signature block matched: SQL.Injection.\""))
                    verdict = "DROP"
                    drop_reason = "UTM IPS Exploit Block"
                else:
                    steps.append(make_step("fg_ips", vendor_id, "IPS Engine", "FortiOS UTM", "pass", "ALLOWED",
                        "IPS engine scan complete. No malicious exploit signatures found.", "Matches: 0.",
                        "id=65308 trace_id=301 func=ips_engine_scan msg=\"IPS scan passed.\""))
                
                if verdict == "ALLOW":
                    steps.append(make_step("fg_app_ctrl", vendor_id, "Application Control", "FortiOS UTM", "pass", "INSPECTING",
                        "Application identified as HTTP/S WebBrowsing. Acceptable policy matched.",
                        "App ID resolved: HTTP.Web.",
                        "id=65308 trace_id=301 func=app_id_resolve msg=\"App HTTP.Web resolved. Allowed.\""))
                else:
                    steps.append(make_step("fg_app_ctrl", vendor_id, "Application Control", "FortiOS", "bypass", "FASTPATH", "Skipped.", "Status: Bypassed."))

                if verdict == "ALLOW" and payload_type == "malware" and option_id != "fg_threat_dlp":
                    steps.append(make_step("fg_av_flow", vendor_id, "Flow AV", "FortiOS UTM", "fail", "DROPPED",
                        "Flow-based Antivirus matched virus threat pattern: EICAR_TEST_FILE.",
                        "Verdict: DROP. Threat deleted.",
                        "id=65308 trace_id=301 func=av_flow_scan msg=\"Malware detected. Session terminated.\""))
                    verdict = "DROP"
                    drop_reason = "Flow AV Malware Block"
                else:
                    steps.append(make_step("fg_av_flow", vendor_id, "Flow AV", "FortiOS UTM", "pass", "ALLOWED",
                        "Flow Antivirus scan complete. Stream verified clean.", "Virus status: Clean.",
                        "id=65308 trace_id=301 func=av_flow_scan msg=\"Antivirus clean.\""))

                if verdict == "ALLOW" and payload_type == "blocked_url":
                    if option_id == "opt_ssl_deny":
                        steps.append(make_step("fg_wf_flow", vendor_id, "Flow WebFilter", "FortiOS UTM", "fail", "DROPPED",
                            "FortiGuard WebFilter blocked connection: Decrypted SSL stream host header matches forbidden category 'Gambling' and cert validation failed.",
                            "Verdict: DROP. SSL decrypted URL matched Gambling category. Certificate status: EXPIRED/UNTRUSTED.",
                            "id=65308 trace_id=301 func=wf_flow_scan msg=\"FortiGuard WebFilter category matched: Gambling. Certificate verification failed: Expired Cert. Blocked.\""))
                        verdict = "DROP"
                        drop_reason = "Untrusted/Expired SSL Certificate"
                    else:
                        steps.append(make_step("fg_wf_flow", vendor_id, "Flow WebFilter", "FortiOS UTM", "fail", "DROPPED",
                            "FortiGuard URL Filter category 'Gambling' matches denied rule.",
                            "Verdict: DROP. Action: Deny.",
                            "id=65308 trace_id=301 func=wf_flow_scan msg=\"FortiGuard WebFilter category matched: Gambling. Blocked.\""))
                        verdict = "DROP"
                        drop_reason = "URL Category Restricted"
                else:
                    steps.append(make_step("fg_wf_flow", vendor_id, "Flow WebFilter", "FortiOS UTM", "pass", "ALLOWED",
                        "FortiGuard URL reputation verified safe.", "Category: Business. Score: 95.",
                        "id=65308 trace_id=301 func=wf_flow_scan msg=\"WebFilter approved.\""))
            else:
                for sid, name in [("fg_sec_decision", "Security Profile Check"), ("fg_ips", "IPS Engine"), 
                                  ("fg_app_ctrl", "Application Control"), ("fg_av_flow", "Flow AV"), 
                                  ("fg_wf_flow", "Flow WebFilter")]:
                    steps.append(make_step(sid, vendor_id, name, "FortiOS", "bypass", "FASTPATH", 
                        "UTM flow engine bypassed.", "Status: Bypassed."))

            # Stage 4: Proxy-Based UTM Engine
            is_proxy_active = has_utm and (payload_type in ["malware", "blocked_url"] or option_id == "fg_threat_dlp")
            steps.append(make_step("fg_proxy_decision", vendor_id, "Proxy Required?", "FortiOS Proxy",
                "pass" if is_proxy_active else "bypass",
                "INSPECTING" if is_proxy_active else "FASTPATH",
                "Matched security profile enforces proxy-based proxy buffering for detailed scan." if is_proxy_active else "Policy operates in flow mode. Bypassing proxy engine.",
                f"Proxy buffer: {'ACTIVE' if is_proxy_active else 'Bypassed'}.",
                "id=65308 trace_id=301 func=proxy_mode_eval msg=\"Proxy mode evaluated.\""))

            if is_proxy_active and verdict == "ALLOW":
                steps.append(make_step("fg_voip", vendor_id, "VoIP Inspection", "FortiOS Proxy", "pass", "INSPECTING",
                    "Traffic is not SIP/H323. VoIP proxy bypassed.", "Protocol check: Non-VoIP.",
                    "id=65308 trace_id=301 func=voip_proxy_inspect msg=\"SIP inspection skipped.\""))
                
                if option_id == "fg_threat_dlp":
                    steps.append(make_step("fg_dlp", vendor_id, "DLP Scan", "FortiOS Proxy", "fail", "DROPPED",
                        "Data Leak Prevention matched credit card regex pattern on outbound file proxy stream. Action: Block.",
                        "Verdict: BLOCK. Credit card regex pattern matched.",
                        "id=65308 trace_id=301 func=dlp_inspect_scan msg=\"DLP block matched. Session dropped.\""))
                    verdict = "DROP"
                    drop_reason = "DLP Policy Block"
                else:
                    steps.append(make_step("fg_dlp", vendor_id, "DLP Scan", "FortiOS Proxy", "pass", "INSPECTING",
                        "Data Leak Prevention complete. No sensitive patterns matched.", "CC/SSN count: 0.",
                        "id=65308 trace_id=301 func=dlp_inspect_scan msg=\"No DLP violations.\""))
                
                steps.append(make_step("fg_email", vendor_id, "Email Filter", "FortiOS Proxy", "pass", "INSPECTING",
                    "Not email protocol (SMTP/IMAP). Bypassed.", "Port: Standard.",
                    "id=65308 trace_id=301 func=email_proxy_inspect msg=\"SMTP skipped.\""))
                steps.append(make_step("fg_av_proxy", vendor_id, "Proxy AV", "FortiOS Proxy", "pass", "ALLOWED",
                    "Reassembled payload successfully analyzed by proxy AV buffer.", "Reconstruction: Successful. Clean.",
                    "id=65308 trace_id=301 func=av_proxy_reconstruct msg=\"Proxy antivirus clean.\""))
                steps.append(make_step("fg_icap", vendor_id, "ICAP Server", "FortiOS Proxy", "pass", "INSPECTING",
                    "No external sandboxing proxy required.", "ICAP status: Disabled.",
                    "id=65308 trace_id=301 func=icap_offload_check msg=\"ICAP not active.\""))
            else:
                for sid, name in [("fg_voip", "VoIP Inspection"), ("fg_dlp", "DLP Scan"), 
                                  ("fg_email", "Email Filter"), ("fg_av_proxy", "Proxy AV"), 
                                  ("fg_icap", "ICAP Server")]:
                    steps.append(make_step(sid, vendor_id, name, "FortiOS", "bypass", "FASTPATH", 
                        "Proxy buffering UTM scan bypassed.", "Status: Bypassed."))

            # Stage 5: Egress Packet Flow (Reordered)
            if verdict == "ALLOW":
                if ssl_decrypt:
                    ssl_enc_desc = "Resealed the decrypted cleartext payload back into secure TLS packet."
                    ssl_enc_behavior = "Re-encrypted with verified target CA certificate."
                    if option_id == "fg_acc_cp":
                        ssl_enc_desc = "Outbound SSL stream hardware re-encrypted via SPU CP9 content processor."
                        ssl_enc_behavior = "CP9 Core load: 8%, Re-encrypt Latency: 1.1μs, Offload active: Yes."
                    steps.append(make_step("fg_ssl_encrypt", vendor_id, "SSL Re-encrypt", "FortiOS SSL Gateway", 
                        "pass" if option_id == "fg_acc_cp" else "decrypt", 
                        "ALLOWED" if option_id == "fg_acc_cp" else "INSPECTING",
                        ssl_enc_desc, ssl_enc_behavior,
                        "id=65308 trace_id=301 func=ssl_reencrypt_payload msg=\"TLS session re-encrypted.\""))
                else:
                    steps.append(make_step("fg_ssl_encrypt", vendor_id, "SSL Re-encrypt", "FortiOS SSL Gateway", "bypass", "FASTPATH",
                        "No SSL decryption active.", "Status: Bypassed."))

                if nat_type == 'dynamic' and egress_interface == 'outside':
                    current_src_ip = "203.0.113.15"
                    steps.append(make_step("fg_snat", vendor_id, "NAT (SNAT)", "FortiOS SPU", "nat", "INSPECTING",
                        f"Dynamic PAT source rule matched. Rewrite Source IP to public IP {current_src_ip}.",
                        f"Translated source address: {current_src_ip}.",
                        "id=65308 trace_id=301 func=snat_apply msg=\"Source NAT translation successful.\""))
                else:
                    steps.append(make_step("fg_snat", vendor_id, "NAT (SNAT)", "FortiOS SPU", "bypass", "FASTPATH",
                        "No Source NAT applied.", "Status: Bypassed."))

                if payload_type == "vpn_in" or option_id == "fg_acc_cp":
                    desc_out = "Egress path matched VPN crypto tunnel. Encrypting outbound payload."
                    behavior_out = "Tunnel destination peer: 54.120.30.40."
                    if option_id == "fg_acc_cp":
                        desc_out = "Outbound IPsec SPU CP9 crypto offload encryption successful. Bulk payload encrypted via hardware coprocessors."
                        behavior_out = "Tunnel peer: 54.120.30.40. CP9 Encrypt Metrics: Offload efficiency: 100%, Cipher: AES256-GCM."
                    steps.append(make_step("fg_ipsec_out", vendor_id, "IPsec Encrypt", "FortiOS VPN", "pass", "INSPECTING",
                        desc_out, behavior_out,
                        "id=65308 trace_id=301 func=ipsec_tunnel_encrypt msg=\"Packet encrypted for VPN transmission.\""))
                else:
                    steps.append(make_step("fg_ipsec_out", vendor_id, "IPsec Encrypt", "FortiOS VPN", "bypass", "FASTPATH",
                        "No outbound VPN mapping.", "Status: Bypassed."))

                steps.append(make_step("fg_shaping", vendor_id, "Traffic Shaping (QoS)", "FortiOS SPU", "pass", "ALLOWED",
                    "Shaping queues, drops, and constraints applied right before wire transmission.",
                    "Class: Default-Priority. Drops: 0.",
                    "id=65308 trace_id=301 func=traffic_shaper_apply msg=\"QoS constraints processed.\""))

                steps.append(make_step("fg_egress", vendor_id, "Interface (TX)", "FortiOS Link", "pass", "ALLOWED",
                    f"Packet successfully transmitted onto outbound physical wire. Trace complete.",
                    f"Egress port: port2. Source: {current_src_ip}:{current_src_port} -> Destination: {current_dst_ip}:{current_dst_port}",
                    "id=65308 trace_id=301 func=packet_egress_tx msg=\"Sent packet to physical layer.\""))
            else:
                for sid, name in [("fg_ssl_encrypt", "SSL Re-encrypt"), ("fg_snat", "NAT (SNAT)"), 
                                  ("fg_ipsec_out", "IPsec Encrypt"), ("fg_shaping", "Traffic Shaping (QoS)")]:
                    steps.append(make_step(sid, vendor_id, name, "FortiOS", "bypass", "FASTPATH", "Skipped.", "Status: Bypassed."))
                
                steps.append(make_step("fg_egress", vendor_id, "Interface (TX)", "FortiOS Link", "fail", "DROPPED",
                    "Transmission aborted. Packet discarded inside firewall engine.",
                    f"Discarded at stage: {drop_reason}.",
                    "id=65308 trace_id=301 func=packet_drop_handler msg=\"Discarded packet in kernel.\""))

        # ----------------------------------------------------
        # 2. CHECK POINT SIMULATION PIPELINE
        # ----------------------------------------------------
        elif brand == 'checkpoint':
            vendor_id = 'checkpoint'
            # Stage 1: SND Ingress
            steps.append(make_step("cp_nic_in", vendor_id, "NIC In", "CheckPoint OS", "pass", "ALLOWED",
                f"Packet received on physical network card 'eth0' ({ingress_interface}).",
                f"Ingress: eth0. Interface MAC: 00:50:56:be:ef:10.",
                "[eth0] Inbound packet captured. Size: 120 bytes."))

            if payload_type == "vpn_in":
                steps.append(make_step("cp_snd_decrypt", vendor_id, "SND Decrypt?", "CheckPoint SND", "decrypt", "INSPECTING",
                    "SND core detected IPsec tunnel packet. SPU decapsulated ESP payload successfully.",
                    "SPI: 0xa87c5, Cipher: AES256-GCM. Cleartext payload passed to SecureXL driver.",
                    "[SND-Core-0] ESP tunnel decrypted successfully."))
            else:
                steps.append(make_step("cp_snd_decrypt", vendor_id, "SND Decrypt?", "CheckPoint SND", "bypass", "FASTPATH",
                    "No IPsec VPN encapsulation detected.", "Bypassed VPN decryption."))

            steps.append(make_step("cp_snd_qos", vendor_id, "SND QoS?", "CheckPoint SND", "pass", "INSPECTING",
                "SND early classification lookup complete. Direct traffic prioritization checked.",
                "Status: Regular priority.",
                "[SND-Core-0] QoS early classification pass."))

            # Stage 2: SecureXL 3-Way Router
            steps.append(make_step("cp_sxl_router", vendor_id, "SecureXL Enabled?", "SecureXL Driver", "pass", "INSPECTING",
                "SecureXL acceleration driver verified active.", "Status: Acceleration ON.",
                "[SecureXL] Active driver processing templates."))

            # Determine SecureXL path
            # Fast Path: existing_conn = True AND clean traffic
            # Medium Path (PXL): existing_conn = True AND payload matches blades (malware/blocked_url)
            # Slow Path (F2F): existing_conn = False
            sxl_path = "f2f"
            if existing_conn:
                if path_type == "mediumpath" or payload_type in ["malware", "blocked_url", "sql_injection"]:
                    sxl_path = "pxl"
                elif path_type == "fastpath":
                    sxl_path = "fastpath"
                else:
                    sxl_path = "fastpath"

            if sxl_path == "fastpath":
                steps.append(make_step("cp_sxl_fastpath", vendor_id, "SecureXL Hit", "SecureXL Templates", "pass", "FASTPATH",
                    "Connection matched SecureXL fastpath session templates. Acceleration active.",
                    "Jumping directly to egress NIC Out, bypassing all CoreXL and CMI inspection stages.",
                    "[SecureXL] Template HIT! Offloading packet flows immediately to Stage 6 (NIC Out)."))
                steps.append(make_step("cp_sxl_pxl", vendor_id, "SecureXL hit", "SecureXL", "bypass", "FASTPATH", "Bypassed.", "Status: Bypassed."))
                steps.append(make_step("cp_sxl_f2f", vendor_id, "Slow Path F2F", "SecureXL", "bypass", "FASTPATH", "Bypassed.", "Status: Bypassed."))
            elif sxl_path == "pxl":
                steps.append(make_step("cp_sxl_fastpath", vendor_id, "SecureXL Hit", "SecureXL", "bypass", "FASTPATH", "Bypassed.", "Status: Bypassed."))
                steps.append(make_step("cp_sxl_pxl", vendor_id, "SecureXL Hit (Medium Path)", "SecureXL Templates", "pass", "INSPECTING",
                    "Connection matches Medium Path (PXL). Executes streaming assembly, forwarding to CMI blades.",
                    "Forwards directly to Stage 5 CMI Blades Loader, bypassing Stage 3 and 4.",
                    "[SecureXL] Medium Path redirect to PSL stream engine."))
                steps.append(make_step("cp_sxl_f2f", vendor_id, "Slow Path F2F", "SecureXL", "bypass", "FASTPATH", "Bypassed.", "Status: Bypassed."))
            else:
                steps.append(make_step("cp_sxl_fastpath", vendor_id, "SecureXL Hit", "SecureXL", "bypass", "FASTPATH", "Bypassed.", "Status: Bypassed."))
                steps.append(make_step("cp_sxl_pxl", vendor_id, "SecureXL Hit", "SecureXL", "bypass", "FASTPATH", "Bypassed.", "Status: Bypassed."))
                steps.append(make_step("cp_sxl_f2f", vendor_id, "Slow Path F2F", "SecureXL Templates", "pass", "INSPECTING",
                    "SecureXL acceleration miss. Diverting connection sequentially into CoreXL Slow Path.",
                    "Slow Path (F2F) drop down active.",
                    "[SecureXL] Miss. Forwarding packet to CoreXL FW Kernel (F2F path)."))

            # Stage 3: CoreXL FW Kernel (Slow Path / F2F Inbound)
            is_f2f = sxl_path == "f2f"
            
            if is_f2f and verdict == "ALLOW":
                steps.append(make_step("cp_f2f_conn_table", vendor_id, "F2F Session Hit?", "CheckPoint Kernel", "pass", "INSPECTING",
                    "No existing conversation found in firewall connection table. Initializing new entry.",
                    "Connection state: NEW.",
                    "[CoreXL] Conn lookup: Miss. Preparing stateful setup."))
                
                # Inbound DNAT BEFORE Policy Lookup (Check Point Specification)
                if nat_type == 'static' and ingress_interface == 'outside':
                    current_dst_ip = "10.0.0.100"
                    steps.append(make_step("cp_f2f_nat_dest", vendor_id, "NAT (Dest)? [Inbound DNAT]", "CheckPoint Kernel", "nat", "INSPECTING",
                        f"Inbound Destination NAT (DNAT) applied. Translating {dst_ip} to internal server {current_dst_ip}.",
                        f"Translated Destination Address: {current_dst_ip}.",
                        f"[CoreXL] DNAT Rule matched. Target destination rewritten to {current_dst_ip}."))
                else:
                    steps.append(make_step("cp_f2f_nat_dest", vendor_id, "NAT (Dest)? [Inbound DNAT]", "CheckPoint Kernel", "bypass", "FASTPATH",
                        "No inbound destination address translations match.", "Status: Bypassed."))

                if sec_intel == 'blacklisted_ip':
                    steps.append(make_step("cp_f2f_policy", vendor_id, "Firewall Policy [Access Rulebase]", "CheckPoint Kernel", "fail", "DROPPED",
                        "Packet denied by access control policy Rule ID 3. Dropping flow.",
                        "Access Control Policy match: DROP.",
                        "[CoreXL] Rulebase lookup: rule 3 (Deny). Action: Drop packet."))
                    verdict = "DROP"
                    drop_reason = "Rulebase Deny"
                else:
                    steps.append(make_step("cp_f2f_policy", vendor_id, "Firewall Policy [Access Rulebase]", "CheckPoint Kernel", "pass", "ALLOWED",
                        "Access Control Rule ID 1 'LAN_Internet' matched. Action: ACCEPT.",
                        "Security access rule ID: 1. Action: ACCEPT.",
                        "[CoreXL] Rulebase lookup: rule 1 (Permit). Action: Forward to IN-Chain."))

                if verdict == "ALLOW":
                    steps.append(make_step("cp_f2f_in_modules", vendor_id, "In-Chain Mods", "CheckPoint Kernel", "pass", "INSPECTING",
                        "Kernel virtual machine inbound chains executed successfully.",
                        "IN-chain modules: stateless firewalls rules passed.",
                        "[CoreXL] IN chain modules successfully processed."))
                    
                    steps.append(make_step("cp_f2f_content_check", vendor_id, "Content Scan?", "CheckPoint Kernel", "pass", "INSPECTING",
                        "Flow metadata dictates that deep payload scanning is required. Forwarding to PXL.",
                        "Redirect trigger: CMI engine requested.",
                        "[CoreXL] Deep content check required. Invoking CMI blades."))
                else:
                    steps.append(make_step("cp_f2f_in_modules", vendor_id, "In-Chain Mods", "CheckPoint", "bypass", "FASTPATH", "Skipped.", "Status: Bypassed."))
                    steps.append(make_step("cp_f2f_content_check", vendor_id, "Content Scan?", "CheckPoint", "bypass", "FASTPATH", "Skipped.", "Status: Bypassed."))
            else:
                for sid, name in [("cp_f2f_conn_table", "F2F Session Hit?"), ("cp_f2f_nat_dest", "NAT (Dest)? [Inbound DNAT]"),
                                  ("cp_f2f_policy", "Firewall Policy [Access Rulebase]"), ("cp_f2f_in_modules", "In-Chain Mods"),
                                  ("cp_f2f_content_check", "Content Scan?")]:
                    steps.append(make_step(sid, vendor_id, name, "CheckPoint", "bypass", "FASTPATH", 
                        "CoreXL FW Kernel slowpath bypassed by SecureXL hit.", "Status: Bypassed."))

            # Stage 4: CMI Engine & Streaming Security Blades (Medium / Inline Paths)
            # Active if sxl_path == "pxl" OR (sxl_path == "f2f" and verdict == "ALLOW")
            is_cmi_active = sxl_path == "pxl" or (sxl_path == "f2f" and verdict == "ALLOW")
            
            if is_cmi_active and verdict == "ALLOW":
                steps.append(make_step("cp_cmi_psl", vendor_id, "PSL Stream Engine", "CheckPoint CMI", "pass", "INSPECTING",
                    "Passive Streaming Library initialized TCP stream reassembly.",
                    "Stream state: Reassembled.",
                    "[PSL] TCP segment aligned. Full payload reassembly active."))
                
                steps.append(make_step("cp_cmi_modules", vendor_id, "CMI Blades Loader", "CheckPoint CMI", "pass", "INSPECTING",
                    "Content Inspection Engine dynamically parsed stream and loaded context software blades.",
                    "Blades loaded: AppControl, URLFiltering, IPS, ThreatEmulation.",
                    "[CMI] Software blades container successfully initialized."))

                if ssl_decrypt:
                    if option_id == "opt_ssl_deny":
                        steps.append(make_step("cp_cmi_https_decrypt", vendor_id, "HTTPS Decrypt", "CheckPoint CMI", "fail", "DROPPED",
                            "SSL Certificate validation failed. Untrusted or expired certificate detected on decrypted stream.",
                            "Certificate status: EXPIRED. SNI: blocked_site.example.com.",
                            "[CMI] HTTPS Decrypt: Certificate validation FAILED. Session terminated."))
                        verdict = "DROP"
                        drop_reason = "SSL Certificate untrusted/expired"
                    else:
                        steps.append(make_step("cp_cmi_https_decrypt", vendor_id, "HTTPS Decrypt", "CheckPoint CMI", "decrypt", "INSPECTING",
                            "HTTPS inspection policy matched. SSL layer terminated and payload decrypted for security blades analysis.",
                            "Certificate: Check Point gateway CA. TLS version: TLSv1.3.",
                            "[CMI] HTTPS Decrypt: Payload successfully decrypted."))
                else:
                    steps.append(make_step("cp_cmi_https_decrypt", vendor_id, "HTTPS Decrypt", "CheckPoint CMI", "bypass", "FASTPATH",
                        "HTTPS inspection is disabled or traffic is cleartext.", "Status: Bypassed.",
                        "[CMI] HTTPS Decrypt: Bypassed."))

                steps.append(make_step("cp_cmi_l7_app", vendor_id, "L7 App Control", "CheckPoint CMI", "pass", "INSPECTING",
                    "Application Control software blade successfully identified web traffic headers.",
                    "Application: HTTPS.",
                    "[Blades] Application Control verified allowed protocol HTTPS."))

                if verdict == "ALLOW" and payload_type == "blocked_url":
                    steps.append(make_step("cp_cmi_url", vendor_id, "URL Filtering & Content Awareness", "CheckPoint CMI", "fail", "DROPPED",
                        "URL Filtering Software Blade matched blocked category 'Gambling'. Drop resolved.",
                        "Verdict: DROP. Site poker-online matches compliance blocklist.",
                        "[Blades] URL Filtering matched gambling site. Action: BLOCK."))
                    verdict = "DROP"
                    drop_reason = "URL Filter gambling block"
                elif verdict == "ALLOW":
                    steps.append(make_step("cp_cmi_url", vendor_id, "URL Filtering & Content Awareness", "CheckPoint CMI", "pass", "ALLOWED",
                        "URL filtering database verified target safe.", "Reputation: Safe.",
                        "[Blades] URL Filtering lookup completed: Allowed."))
                else:
                    steps.append(make_step("cp_cmi_url", vendor_id, "URL Filtering & Content Awareness", "CheckPoint", "bypass", "FASTPATH",
                        "Skipped — prior blade already dropped the session.", "Status: Downstream skipped."))

                if verdict == "ALLOW" and payload_type == "sql_injection":
                    steps.append(make_step("cp_cmi_ips", vendor_id, "IPS Engine", "CheckPoint CMI", "fail", "DROPPED",
                        "SmartDefense IPS Engine detected SQL Union database exploit injection signature. Drop.",
                        "Verdict: DROP. Signature: SQL_Injection_Attempt.",
                        "[Blades] SmartDefense IPS signature matched. Session dropped."))
                    verdict = "DROP"
                    drop_reason = "IPS exploit signature matched"
                elif verdict == "ALLOW":
                    steps.append(make_step("cp_cmi_ips", vendor_id, "IPS Engine", "CheckPoint CMI", "pass", "ALLOWED",
                        "IPS signature matching passed successfully.", "Matches: 0.",
                        "[Blades] IPS Engine scanning completed: Safe."))
                else:
                    steps.append(make_step("cp_cmi_ips", vendor_id, "IPS Engine", "CheckPoint", "bypass", "FASTPATH",
                        "Skipped — prior blade already dropped the session.", "Status: Downstream skipped."))

                if verdict == "ALLOW" and option_id == "cp_threat_bot":
                    steps.append(make_step("cp_cmi_ab_av", vendor_id, "Anti-Bot / Anti-Virus", "CheckPoint CMI", "fail", "DROPPED",
                        "Anti-Bot Software Blade detected C2 callback to known malicious command & control server.",
                        "Verdict: DROP. C2 destination: 185.220.101.5.",
                        "[Blades] Anti-Bot C2 callback signature matched. Session terminated."))
                    verdict = "DROP"
                    drop_reason = "Anti-Bot C2 callback block"
                elif verdict == "ALLOW" and payload_type == "malware" and option_id != "cp_threat_te":
                    steps.append(make_step("cp_cmi_ab_av", vendor_id, "Anti-Bot / Anti-Virus", "CheckPoint CMI", "fail", "DROPPED",
                        "Anti-Virus Software Blade identified EICAR test virus malware payload file drop.",
                        "Verdict: DROP. Attachment blocked.",
                        "[Blades] Antivirus matched malware hash. Session terminated."))
                    verdict = "DROP"
                    drop_reason = "Anti-Virus malware block"
                elif verdict == "ALLOW":
                    steps.append(make_step("cp_cmi_ab_av", vendor_id, "Anti-Bot / Anti-Virus", "CheckPoint CMI", "pass", "ALLOWED",
                        "Anti-Virus and Anti-Bot signatures checked. Stream verified clean.", "Virus signature: None.",
                        "[Blades] Anti-Virus scanning completed: Safe."))
                else:
                    steps.append(make_step("cp_cmi_ab_av", vendor_id, "Anti-Bot / Anti-Virus", "CheckPoint", "bypass", "FASTPATH",
                        "Skipped — prior blade already dropped the session.", "Status: Downstream skipped."))

                if verdict == "ALLOW" and option_id == "cp_threat_te":
                    steps.append(make_step("cp_cmi_threat_emulation", vendor_id, "Threat Emulation", "CheckPoint CMI", "fail", "DROPPED",
                        "Threat Emulation sandbox detected zero-day malware signature. File quarantined.",
                        "Verdict: DROP. Sandbox hash matched eicar.com malicious signature.",
                        "[Blades] Threat Emulation sandbox verdict: MALICIOUS. Session terminated."))
                    verdict = "DROP"
                    drop_reason = "Threat Emulation zero-day detection"
                elif verdict == "ALLOW":
                    steps.append(make_step("cp_cmi_threat_emulation", vendor_id, "Threat Emulation", "CheckPoint CMI", "pass", "INSPECTING",
                        "Threat Emulation cloud sandboxing cache matched safe file hash. Bypassing sandbox buffer delay.",
                        "Sandboxing mode: Emulate in cloud.",
                        "[Blades] Threat Emulation cache HIT: File verified safe."))
                else:
                    steps.append(make_step("cp_cmi_threat_emulation", vendor_id, "Threat Emulation", "CheckPoint", "bypass", "FASTPATH", "Skipped.", "Status: Bypassed."))

                if ssl_decrypt and verdict == "ALLOW":
                    steps.append(make_step("cp_cmi_https_encrypt", vendor_id, "HTTPS Encrypt", "CheckPoint CMI", "decrypt", "INSPECTING",
                        "HTTPS payload re-encrypted using ephemeral TLS session keys prior to forwarding.",
                        "Cipher suite: TLS_AES_256_GCM_SHA384.",
                        "[CMI] HTTPS Encrypt: Payload successfully re-encrypted."))
                else:
                    steps.append(make_step("cp_cmi_https_encrypt", vendor_id, "HTTPS Encrypt", "CheckPoint CMI", "bypass", "FASTPATH",
                        "HTTPS encryption not required or bypassed.", "Status: Bypassed.",
                        "[CMI] HTTPS Encrypt: Bypassed."))

                # Blades final verdict
                steps.append(make_step("cp_cmi_action", vendor_id, "Security Blade Action", "CheckPoint CMI", 
                    "pass" if verdict == "ALLOW" else "fail", 
                    "ALLOWED" if verdict == "ALLOW" else "DROPPED",
                    "CMI blades final verdict evaluated." if verdict == "ALLOW" else f"CMI blades dropped session. Reason: {drop_reason}.",
                    f"Blades overall result: {verdict}.",
                    f"[CMI] Streaming security check complete. Verdict: {verdict}."))
            else:
                for sid, name in [("cp_cmi_psl", "PSL Stream Engine"), ("cp_cmi_modules", "CMI Blades Loader"),
                                  ("cp_cmi_https_decrypt", "HTTPS Decrypt"),
                                  ("cp_cmi_l7_app", "L7 App Control"), ("cp_cmi_url", "URL Filtering & Content Awareness"),
                                  ("cp_cmi_ips", "IPS Engine"), ("cp_cmi_ab_av", "Anti-Bot / Anti-Virus"),
                                  ("cp_cmi_threat_emulation", "Threat Emulation"), 
                                  ("cp_cmi_https_encrypt", "HTTPS Encrypt"),
                                  ("cp_cmi_action", "Security Blade Action")]:
                    steps.append(make_step(sid, vendor_id, name, "CheckPoint", "bypass", "FASTPATH", 
                        "CMI Software Blades engine bypassed.", "Status: Bypassed."))

            # Stage 5: Routing & Outbound Kernel
            if is_f2f and verdict == "ALLOW":
                steps.append(make_step("cp_routing", vendor_id, "Routing Lookup", "CheckPoint OS", "pass", "ALLOWED",
                    f"OS route lookup verified egress interface eth1 and next hop gateway.",
                    "Route destination metric: 1. Gateway: 203.0.113.1.",
                    "[OS-Route] Resolved interface eth1 for target path."))

                if nat_type == 'dynamic' and egress_interface == 'outside':
                    current_src_ip = "203.0.113.15"
                    steps.append(make_step("cp_f2f_nat_src", vendor_id, "Source NAT?", "CheckPoint Kernel", "nat", "INSPECTING",
                        f"Outbound Hide NAT (Source Translation) applied. Translating {src_ip} -> public IP {current_src_ip}.",
                        f"Translated dynamic source PAT IP: {current_src_ip}.",
                        f"[CoreXL] Outbound Hide NAT rule matched. Translated source to {current_src_ip}."))
                else:
                    steps.append(make_step("cp_f2f_nat_src", vendor_id, "Source NAT?", "CheckPoint Kernel", "bypass", "FASTPATH",
                        "No outbound Hide NAT rules match.", "Status: Bypassed."))

                steps.append(make_step("cp_f2f_out_modules", vendor_id, "Out-Chain Mods", "CheckPoint Kernel", "pass", "INSPECTING",
                    "Outbound virtual machine kernel chain modules executed.",
                    "OUT-chain modules processed successfully.",
                    "[CoreXL] OUT chain modules successfully processed."))
            else:
                for sid, name in [("cp_routing", "Routing Lookup"), ("cp_f2f_nat_src", "Source NAT?"), 
                                  ("cp_f2f_out_modules", "Out-Chain Mods")]:
                    steps.append(make_step(sid, vendor_id, name, "CheckPoint", "bypass", "FASTPATH", 
                        "Outbound kernel routing bypassed.", "Status: Bypassed."))

            # Stage 6: Path Execution & Outbound Gateway
            if verdict == "ALLOW":
                steps.append(make_step("cp_path_resolution", vendor_id, "Path Resolved", "CheckPoint OS", "pass", "ALLOWED",
                    f"Final stream delivery path resolved to: {sxl_path.upper()}.",
                    f"Delivery mode: {sxl_path.upper()} acceleration.",
                    "[Path] Resolving outbound flow interface. Mode: Accelerated."))

                steps.append(make_step("cp_egress_qos", vendor_id, "QoS OUT?", "CheckPoint Kernel", "pass", "INSPECTING",
                    "Outbound bandwidth shaper applied. QoS packet transmission queues configured.",
                    "Egress traffic class: Default.",
                    "[OS] QoS shaper applied outbound rules."))

                if payload_type == "vpn_in":
                    steps.append(make_step("cp_egress_encrypt", vendor_id, "VPN Encrypt?", "CheckPoint Kernel", "pass", "INSPECTING",
                        "Packet matches outbound VPN community. Encrypting payload with Site-to-Site tunnel.",
                        "Encryption mode: ESP. SPI: 0x4b7e8d2.",
                        "[VPN] Packet encrypted for outbound peer Site-To-Site."))
                else:
                    steps.append(make_step("cp_egress_encrypt", vendor_id, "VPN Encrypt?", "CheckPoint Kernel", "bypass", "FASTPATH",
                        "No outbound VPN mapping.", "Status: Bypassed."))

                steps.append(make_step("cp_nic_out", vendor_id, "NIC Out", "CheckPoint OS", "pass", "ALLOWED",
                    f"Packet successfully transmitted outbound via physical interface 'eth1'. Trace complete.",
                    f"Egress port: eth1. Source: {current_src_ip}:{current_src_port} -> Destination: {current_dst_ip}:{current_dst_port}",
                    "[eth1] Outbound packet transmitted successfully."))
            else:
                for sid, name in [("cp_path_resolution", "Path Resolved"), ("cp_egress_qos", "QoS OUT?"), 
                                  ("cp_egress_encrypt", "VPN Encrypt?")]:
                    steps.append(make_step(sid, vendor_id, name, "CheckPoint", "bypass", "FASTPATH", "Skipped.", "Status: Bypassed."))
                
                steps.append(make_step("cp_nic_out", vendor_id, "NIC Out", "CheckPoint OS", "bypass", "FASTPATH",
                    "NIC Outbound aborted. Packet discarded inside firewall engine.",
                    f"Discarded status at stage: {drop_reason}.",
                    "[eth1] Physical egress transmission aborted."))

        # ----------------------------------------------------
        # 3. PALO ALTO SIMULATION PIPELINE
        # ----------------------------------------------------
        elif brand == 'paloalto':
            vendor_id = 'paloalto'
            ingress_mac = "00:50:56:be:ef:10"
            # Stage 1 Ingress:
            steps.append(make_step("pa_ingress_receive", vendor_id, "Receive Packet", "PAN-OS Parser", "pass", "ALLOWED",
                "Packet arrived on physical interface 'ethernet1/1'. Layer 2 headers parsed.",
                "Ingress port: ethernet1/1. Port speed: 10Gbps. Frame checksum: Valid.",
                "=> ethernet1/1: received packet flow L2 frame parsed."))

            steps.append(make_step("pa_ingress_parse", vendor_id, "Parsing & Zone", "PAN-OS Parser", "pass", "ALLOWED",
                "L2/L3/L4 headers successfully extracted. Source IP and port validated.",
                f"Source Zone: trust. Source MAC: {ingress_mac}.",
                f"=> extracted L3/L4 metadata. Src Zone: trust. Proto: {protocol}."))

            if sec_intel == 'blacklisted_ip' and not existing_conn:
                steps.append(make_step("pa_ingress_error", vendor_id, "Ingress Error Check", "PAN-OS Zone Protection", "fail", "DROPPED",
                    "Ingress process error: Source IP matches forbidden rate-limit blacklist threshold. Packet discarded.",
                    "Zone Protection anti-DoS check matched. Action: DISCARD.",
                    "=> Zone Protection profiles matches threat feed: DISCARD."))
                verdict = "DROP"
                drop_reason = "Zone Protection drop"
            else:
                steps.append(make_step("pa_ingress_error", vendor_id, "Ingress Error Check", "PAN-OS Zone Protection", "pass", "ALLOWED",
                    "No ingress process errors found. Packet headers are structurally normal.",
                    "Zone Protection profile verified clean.",
                    "=> Zone Protection verification: Normal traffic rate."))

            if verdict == "ALLOW":
                steps.append(make_step("pa_ingress_fw_inspect", vendor_id, "FW Inspect Check", "PAN-OS Engine", "pass", "ALLOWED",
                    "Stateful inspection applicable. Routing packet toward Session Engine.",
                    "Stateful inspection: Yes.",
                    "=> Ingress filter: stateful inspection active."))
            else:
                steps.append(make_step("pa_ingress_fw_inspect", vendor_id, "FW Inspect Check", "PAN-OS", "bypass", "FASTPATH", "Skipped.", "Status: Bypassed."))

            if verdict == "ALLOW" and payload_type == "vpn_in":
                steps.append(make_step("pa_ingress_vpn_decrypt", vendor_id, "VPN Decrypt Check", "PAN-OS VPN", "decrypt", "INSPECTING",
                    "Incoming IPsec VPN tunnel packet detected. Decrypting ESP payload using local Security Association.",
                    "Decryption mode: IPsec Tunnel. Cipher: AES256-GCM. SPI: 0x5b3f12d.",
                    "=> VPN decrypt: Decrypting tunnel packet SPI 0x5b3f12d."))
            else:
                steps.append(make_step("pa_ingress_vpn_decrypt", vendor_id, "VPN Decrypt Check", "PAN-OS VPN", "bypass", "FASTPATH",
                    "No IPsec VPN encapsulation detected.", "Bypassed VPN decryption."))

            # SP3 Split Gateway
            is_slowpath = not existing_conn

            # Branch A (Slowpath / Session Setup)
            if verdict == "ALLOW" and is_slowpath:
                steps.append(make_step("pa_slow_forwarding", vendor_id, "Forwarding", "PAN-OS Route Lookup", "pass", "INSPECTING",
                    "Route table lookup resolves next-hop interface ethernet1/2 and Egress Zone untrust.",
                    "Egress Zone resolved: untrust. VSYS ID: vsys1.",
                    "flow_sequence_setup: routing lookup resolved next hop."))
                
                if nat_type == 'static' and ingress_interface == 'outside':
                    current_dst_ip = "10.0.0.100"
                    steps.append(make_step("pa_slow_nat", vendor_id, "NAT Policy", "PAN-OS NAT Engine", "pass", "INSPECTING",
                        f"Destination NAT (DNAT Check) rule matched. Translating Destination to internal server {current_dst_ip}.",
                        f"DNAT Match: Mapped destination to {current_dst_ip}. Re-routing flow.",
                        "flow_sequence_setup: DNAT policy matched. Rewriting target."))
                else:
                    steps.append(make_step("pa_slow_nat", vendor_id, "NAT Policy", "PAN-OS NAT Engine", "bypass", "FASTPATH",
                        "No Destination NAT rules apply. Target address remains original.", "NAT: Bypassed."))

                if sec_intel == 'blacklisted_dns':
                    steps.append(make_step("pa_slow_security_policy", vendor_id, "Security Policy", "PAN-OS Policy Engine", "fail", "DROPPED",
                        "Denied by Security Policy lookup. Subnet access restricted.",
                        "Policy rule: 'Block_Malicious_Outbound' matched. Action: DENY.",
                        "flow_sequence_setup: security policy matched rule ID 9 (Deny). DROP."))
                    verdict = "DROP"
                    drop_reason = "Security Policy Denied"
                else:
                    steps.append(make_step("pa_slow_security_policy", vendor_id, "Security Policy", "PAN-OS Policy Engine", "pass", "ALLOWED",
                        "Security Policy rule ID 1 'Allow_Corporate_Outbound' matched. Action: ACCEPT.",
                        "Policy rule: 'Allow_Corporate_Outbound'.",
                        "flow_sequence_setup: security policy matched rule ID 1 (Allow). ACCEPT."))

                if verdict == "ALLOW":
                    steps.append(make_step("pa_slow_session_install", vendor_id, "Install Session", "PAN-OS Session Engine", "pass", "INSPECTING",
                        "Session successfully installed in firewall state table.",
                        "Session allocated. Type: Active.",
                        "flow_sequence_setup: Session allocated successfully."))
                else:
                    steps.append(make_step("pa_slow_session_install", vendor_id, "Install Session", "PAN-OS Session Engine", "bypass", "FASTPATH", "Skipped.", "Status: Bypassed."))
            else:
                for sid, name in [("pa_slow_forwarding", "Forwarding"), ("pa_slow_nat", "NAT Policy"),
                                  ("pa_slow_security_policy", "Security Policy"), ("pa_slow_session_install", "Install Session")]:
                    steps.append(make_step(sid, vendor_id, name, "PAN-OS", "bypass", "FASTPATH", 
                        "Slowpath session setup bypassed by Fastpath.", "Status: Bypassed."))

            # Branch B (Fastpath)
            is_fastpath = existing_conn
            if verdict == "ALLOW" and is_fastpath:
                steps.append(make_step("pa_fast_session_lookup", vendor_id, "Session Lookup", "PAN-OS Session Engine", "pass", "FASTPATH",
                    "Active session found in state table cache. Acceleration active.",
                    "Session State: Active. SPU accelerated: Yes.",
                    "flow_fastpath_process: Session lookup hit. State: ACTIVE."))
                
                steps.append(make_step("pa_fast_l2_l4", vendor_id, "L2 - 4 Process", "PAN-OS SPU", "pass", "INSPECTING",
                    "SPU hardware offloader processed layer 2-4 integrity. Connection timers updated.",
                    "Timer state: Refreshed.",
                    "flow_fastpath_process: Timers refreshed. Flow processing accelerated."))
            else:
                for sid, name in [("pa_fast_session_lookup", "Session Lookup"), ("pa_fast_l2_l4", "L2 - 4 Process")]:
                    steps.append(make_step(sid, vendor_id, name, "PAN-OS", "bypass", "FASTPATH", 
                        "Fastpath acceleration bypassed.", "Status: Bypassed."))

            # SSL decrypt check (Intermediate node before App-ID)
            if verdict == "ALLOW" and ssl_decrypt:
                if option_id == "opt_ssl_deny":
                    steps.append(make_step("pa_fast_ssl_decrypt", vendor_id, "SSL Decrypt?", "PAN-OS SSL Proxy", "fail", "DROPPED",
                        "SSL Certificate validation failed. Untrusted or expired certificate detected on decrypted stream.",
                        "Certificate status: EXPIRED. SNI: blocked_site.example.com.",
                        "flow_fastpath_process: SSL forward proxy cert validation FAILED. Session terminated."))
                    verdict = "DROP"
                    drop_reason = "SSL Certificate untrusted/expired"
                else:
                    steps.append(make_step("pa_fast_ssl_decrypt", vendor_id, "SSL Decrypt?", "PAN-OS SSL Proxy", "decrypt", "INSPECTING",
                        "SSL Forward Proxy profile matches connection. Decrypting payload to cleartext.",
                        "Proxy mode: Forward Proxy. Cipher: TLS_AES_256_GCM.",
                        "flow_fastpath_process: SSL forward proxy decrypting session."))
            else:
                steps.append(make_step("pa_fast_ssl_decrypt", vendor_id, "SSL Decrypt?", "PAN-OS SSL Proxy", "bypass", "FASTPATH",
                    "Decryption bypassed or cleartext traffic.", "Decryption: Bypassed."))

            # Stage 4: Application Identification (App-ID)
            if verdict == "ALLOW" and not existing_conn:
                steps.append(make_step("pa_app_pattern", vendor_id, "Pattern App-ID", "PAN-OS App-ID", "pass", "INSPECTING",
                    "Application Identification engine resolved stream pattern to signature: web-browsing.",
                    "Resolved App: web-browsing.",
                    "App-ID changed to: web-browsing"))
                
                steps.append(make_step("pa_app_rematch", vendor_id, "Security Policy Re-Match Loop", "PAN-OS App-ID", "pass", "INSPECTING",
                    "App-ID resolved. Re-evaluating Access Control rulebase based on parsed L7 Application.",
                    "Re-match rule: 'Allow_Web_Browsing' (Rule 5).",
                    "flow_sequence_setup: App-ID changed. Re-evaluating security policy rulebase."))

                if verdict == "ALLOW" and payload_type == "blocked_url" and option_id != "pa_threat_url":
                    steps.append(make_step("pa_app_allow_check", vendor_id, "App Allowed Check", "PAN-OS App-ID", "fail", "DROPPED",
                        "Security Policy Re-match action: DENY. Target Gambling category matched URL block rule.",
                        "Verdict: DROP. Rule: 'Block_Gambling'.",
                        "flow_sequence_setup: Re-matched policy rule ID 12 (Deny URL category). DROP."))
                    verdict = "DROP"
                    drop_reason = "App URL Category Deny"
                elif verdict == "ALLOW":
                    steps.append(make_step("pa_app_allow_check", vendor_id, "App Allowed Check", "PAN-OS App-ID", "pass", "ALLOWED",
                        "Security Policy Re-match action: ALLOW. Application matches allowed corporate standards.",
                        "Verdict: ALLOW. Rule: 'Allow_Web_Browsing'.",
                        "flow_sequence_setup: Re-matched policy rule ID 5 (Allow App web-browsing). ACCEPT."))
                else:
                    steps.append(make_step("pa_app_allow_check", vendor_id, "App Allowed Check", "PAN-OS", "bypass", "FASTPATH",
                        "Skipped — prior blade already dropped the session.", "Status: Downstream skipped."))

                if verdict == "ALLOW":
                    steps.append(make_step("pa_app_sp3_setup", vendor_id, "Scan Setup", "PAN-OS Content-ID", "pass", "INSPECTING",
                        "Initializes Content-ID Single-Pass Parallel Scan engine contexts.",
                        "Status: Parallel contexts initialized.",
                        "ctd_engine: Initializing SP3 scan contexts."))
                else:
                    steps.append(make_step("pa_app_sp3_setup", vendor_id, "Scan Setup", "PAN-OS Content-ID", "bypass", "FASTPATH", "Skipped.", "Status: Bypassed."))
            else:
                for sid, name in [("pa_app_pattern", "Pattern App-ID"), ("pa_app_rematch", "Security Policy Re-Match Loop"),
                                  ("pa_app_allow_check", "App Allowed Check"), ("pa_app_sp3_setup", "Scan Setup")]:
                    steps.append(make_step(sid, vendor_id, name, "PAN-OS", "bypass", "FASTPATH", "Skipped.", "Status: Bypassed."))

            # Stage 5: Content Inspection (Single-Pass Parallel Scan Engine)
            # In the real PA architecture, all Content-ID blades scan concurrently.
            # We snapshot the pre-scan verdict so every parallel block shows its
            # own execution result (pass/drop) independently — no downstream
            # cascading within the parallel grid.
            is_content_active = verdict == "ALLOW"
            
            if is_content_active:
                pre_scan_verdict = verdict  # Snapshot for parallel block visibility
                
                # --- Antivirus ---
                if pre_scan_verdict == "ALLOW" and payload_type == "malware" and option_id != "pa_threat_wf":
                    steps.append(make_step("pa_content_av", vendor_id, "Antivirus", "PAN-OS Content-ID", "fail", "DROPPED",
                        "Antivirus signature matched known malware download payload. Verdict: DROP.",
                        "Threat Signature: EICAR_TEST_FILE. Action: Block.",
                        "ctd_engine: Antivirus scan hit signature. Action: DROP."))
                    verdict = "DROP"
                    drop_reason = "Content-ID Antivirus Drop"
                elif pre_scan_verdict == "ALLOW":
                    steps.append(make_step("pa_content_av", vendor_id, "Antivirus", "PAN-OS Content-ID", "pass", "ALLOWED",
                        "Antivirus dynamic scans passed. File clean.", "Status: Safe.",
                        "ctd_engine: Antivirus scan passed."))
                else:
                    steps.append(make_step("pa_content_av", vendor_id, "Antivirus", "PAN-OS", "bypass", "FASTPATH",
                        "Skipped — prior blade already dropped the session.", "Status: Downstream skipped."))

                # --- WildFire Analysis — only activates when files are present ---
                if pre_scan_verdict == "ALLOW" and option_id == "pa_threat_wf":
                    steps.append(make_step("pa_content_wildfire", vendor_id, "WildFire Analysis", "PAN-OS Content-ID", "fail", "DROPPED",
                        "WildFire cloud sandbox analysis flagged file hash as zero-day malware. File quarantined.",
                        "Verdict: DROP. Hash: 275a021b classified as malicious.",
                        "ctd_engine: WildFire sandbox verdict: MALICIOUS. Session terminated."))
                    verdict = "DROP"
                    drop_reason = "WildFire zero-day detection"
                elif pre_scan_verdict == "ALLOW":
                    # No file attachments — WildFire has nothing to sandbox
                    steps.append(make_step("pa_content_wildfire", vendor_id, "WildFire Analysis", "PAN-OS Content-ID", "bypass", "FASTPATH",
                        "No file attachments detected in stream. WildFire sandbox analysis skipped.",
                        "Stream type: HTTP text. No executable payload to sandbox.",
                        "ctd_engine: WildFire skipped — no file payload."))
                else:
                    steps.append(make_step("pa_content_wildfire", vendor_id, "WildFire Analysis", "PAN-OS", "bypass", "FASTPATH",
                        "Skipped — prior blade already dropped the session.", "Status: Downstream skipped."))

                # --- Vulnerability Protection ---
                if pre_scan_verdict == "ALLOW" and payload_type == "sql_injection":
                    steps.append(make_step("pa_content_vuln", vendor_id, "Vulnerability Protection", "PAN-OS Content-ID", "fail", "DROPPED",
                        "Vulnerability protection engine matched SQL Database Injection pattern. Verdict: DROP.",
                        "Threat Signature: Web_Database_SQL_Injection. Action: Reset.",
                        "ctd_engine: Vulnerability scan matched signature. Action: DROP."))
                    verdict = "DROP"
                    drop_reason = "Content-ID IPS Exploit Drop"
                elif pre_scan_verdict == "ALLOW":
                    steps.append(make_step("pa_content_vuln", vendor_id, "Vulnerability Protection", "PAN-OS Content-ID", "pass", "ALLOWED",
                        "Vulnerability IPS scan complete. Exploit threats: 0.", "Status: Safe.",
                        "ctd_engine: Vulnerability scan passed."))
                else:
                    steps.append(make_step("pa_content_vuln", vendor_id, "Vulnerability Protection", "PAN-OS", "bypass", "FASTPATH",
                        "Skipped — prior blade already dropped the session.", "Status: Downstream skipped."))

                # --- Anti-Spyware ---
                if pre_scan_verdict == "ALLOW":
                    steps.append(make_step("pa_content_spyware", vendor_id, "Anti-Spyware", "PAN-OS Content-ID", "pass", "INSPECTING",
                        "Anti-spyware signatures analyzed. No anomalous C2 host patterns detected.", "Status: Safe.",
                        "ctd_engine: Anti-Spyware scan passed."))
                else:
                    steps.append(make_step("pa_content_spyware", vendor_id, "Anti-Spyware", "PAN-OS", "bypass", "FASTPATH",
                        "Skipped — prior blade already dropped the session.", "Status: Downstream skipped."))

                # --- URL Filtering ---
                if pre_scan_verdict == "ALLOW" and option_id == "pa_threat_url":
                    steps.append(make_step("pa_content_url", vendor_id, "URL Filtering", "PAN-OS Content-ID", "fail", "DROPPED",
                        "URL Filtering database matched prohibited category. Dest host flagged as malicious.",
                        "Verdict: DROP. URL category: Gambling. Site poker-online matched compliance blocklist.",
                        "ctd_engine: URL Filtering matched blocked category. Action: DROP."))
                    verdict = "DROP"
                    drop_reason = "URL Filtering category block"
                elif pre_scan_verdict == "ALLOW":
                    steps.append(make_step("pa_content_url", vendor_id, "URL Filtering", "PAN-OS Content-ID", "pass", "INSPECTING",
                        "URL Filtering database checked outbound URL. Web category is allowed.", "Category: Computer Info.",
                        "ctd_engine: URL Filtering scan passed."))
                else:
                    steps.append(make_step("pa_content_url", vendor_id, "URL Filtering", "PAN-OS", "bypass", "FASTPATH",
                        "Skipped — prior blade already dropped the session.", "Status: Downstream skipped."))

                if ssl_decrypt and verdict == "ALLOW":
                    steps.append(make_step("pa_content_ssl_encrypt", vendor_id, "SSL Re-encrypt", "PAN-OS SSL Proxy", "decrypt", "INSPECTING",
                        "SSL forward proxy re-encrypts the payload for transmission to external network host.",
                        "Encryption mode: Forward proxy. Cipher: TLS_AES_256_GCM.",
                        "flow_fastpath_process: SSL forward proxy re-encrypting session."))
                else:
                    steps.append(make_step("pa_content_ssl_encrypt", vendor_id, "SSL Re-encrypt", "PAN-OS SSL Proxy", "bypass", "FASTPATH",
                        "Re-encryption skipped.", "Status: Bypassed."))
            else:
                for sid, name in [("pa_content_av", "Antivirus"), ("pa_content_wildfire", "WildFire Analysis"),
                                  ("pa_content_vuln", "Vulnerability Protection"),
                                  ("pa_content_spyware", "Anti-Spyware"), ("pa_content_url", "URL Filtering"),
                                  ("pa_content_ssl_encrypt", "SSL Re-encrypt")]:
                    steps.append(make_step(sid, vendor_id, name, "PAN-OS", "bypass", "FASTPATH", 
                        "Content-ID parallel scan bypassed.", "Status: Bypassed."))

            # Stage 6: Forwarding / Egress
            if verdict == "ALLOW":
                steps.append(make_step("pa_egress_processing", vendor_id, "Egress Processing", "PAN-OS Interface", "pass", "ALLOWED",
                    "QoS outbound queuing, route selection, and interface mapping check passed.",
                    "Class: default. Gateway IP: 203.0.113.1.",
                    "flow_fastpath_process: Egress resolved."))

                if payload_type == "vpn_in":
                    steps.append(make_step("pa_egress_vpn_encrypt", vendor_id, "VPN Encrypt", "PAN-OS VPN", "pass", "INSPECTING",
                        "Egress interface matched outbound VPN tunnel mapping. Encapsulating raw packet into IPsec wrapper.",
                        "ESP encryption: AES256-GCM. Peer destination: 54.120.30.40.",
                        "flow_fastpath_process: Outbound VPN encryption completed."))
                else:
                    steps.append(make_step("pa_egress_vpn_encrypt", vendor_id, "VPN Encrypt", "PAN-OS VPN", "bypass", "FASTPATH",
                        "No outbound VPN tunnel mapping found. cleartext forwarding active.", "Status: Bypassed."))

                steps.append(make_step("pa_egress_transmission", vendor_id, "Transmission", "PAN-OS Interface", "pass", "ALLOWED",
                    "Outbound MTU check passed (1500 bytes). Frame transmitted onto physical wire ethernet1/2.",
                    "Egress interface: ethernet1/2. Next hop gateway MAC: 00:08:e3:11:22:33.",
                    "flow_fastpath_process: Packet transmission completed."))
            else:
                for sid, name in [("pa_egress_processing", "Egress Processing"), 
                                  ("pa_egress_vpn_encrypt", "VPN Encrypt"),
                                  ("pa_egress_transmission", "Transmission")]:
                    steps.append(make_step(sid, vendor_id, name, "PAN-OS Interface", "bypass", "FASTPATH", "Skipped.", "Status: Bypassed."))

        # ----------------------------------------------------
        # 4. CISCO FTD SIMULATION PIPELINE
        # ----------------------------------------------------
        elif brand == 'cisco':
            vendor_id = 'cisco_ftd'
            # Stage 1: Ingress
            steps.append(make_step("ingress", vendor_id, "Ingress Physical", "FTD LINA", "pass", "ALLOWED",
                "Packet received on physical network interface. Link layer headers validated.",
                "Source MAC: 00:50:56:be:ef:10. MTU: 1500.",
                f"Phase: 1 Type: INGRESS Result: ALLOW"))

            steps.append(make_step("capture", vendor_id, "Capture Check", "FTD LINA", "pass", "INSPECTING",
                "LINA packet capture diagnostic filter checked. Flow matches active trace.",
                "Capture ID: trace_flow. Matches: 1.",
                "Phase: 2 Type: CAPTURE-CHECK Result: ALLOW"))

            steps.append(make_step("lina_defrag", vendor_id, "IP Defrag", "FTD LINA", "pass", "ALLOWED",
                "IP reassembly layer analyzed packet. Fragment reassembly is not required.",
                "Fragment status: Intact.",
                "Phase: 3 Type: IP-DEFRAGMENTATION Result: ALLOW"))

            # Stateful bypass check
            steps.append(make_step("existing_conn", vendor_id, "Existing Conn?", "FTD LINA", "pass",
                "FASTPATH" if existing_conn else "INSPECTING",
                "Stateful connection lookup succeeded. Session accelerated." if existing_conn else "Stateful connection lookup missed. Routing packet to Slow-Path.",
                f"Session Table offload: {'HIT (FASTPATH)' if existing_conn else 'MISS'}.",
                f"Phase: 4 Type: SESSION-LOOKUP Result: {'ALLOW (FASTPATH)' if existing_conn else 'ALLOW (SLOWPATH)'}"))

            is_slowpath = not existing_conn

            # Stage 2: LINA Core Routing & Access Rules
            if verdict == "ALLOW" and is_slowpath:
                if payload_type == "vpn_in":
                    steps.append(make_step("vpn_decrypt", vendor_id, "VPN Decrypt", "FTD LINA", "decrypt", "INSPECTING",
                        "ESP packet decrypted successfully inside crypto-tunnel wrapper.",
                        "Tunnel Association: Site-to-Site. Decrypted payload cleartext headers exposed.",
                        "Phase: 5 Type: VPN-DECRYPT Result: ALLOW"))
                else:
                    steps.append(make_step("vpn_decrypt", vendor_id, "VPN Decrypt", "FTD LINA", "bypass", "FASTPATH",
                        "No VPN encapsulation detected.", "Bypassed VPN decryption."))

                if nat_type == 'static' and ingress_interface == 'outside':
                    current_dst_ip = "10.0.0.100"
                    steps.append(make_step("un_nat", vendor_id, "UN-NAT (DNAT)", "FTD LINA", "nat", "INSPECTING",
                        f"Static Destination NAT rule matched on ingress. Translating target {dst_ip} to internal server {current_dst_ip}.",
                        f"Rule Object: Web_Server_DNAT. Destination translated to {current_dst_ip}.",
                        "Phase: 6 Type: UN-NAT Result: ALLOW"))
                else:
                    steps.append(make_step("un_nat", vendor_id, "UN-NAT (DNAT)", "FTD LINA", "bypass", "FASTPATH",
                        "No Destination NAT rules apply. Target unchanged.", "Status: Bypassed."))

                # ROUTE LOOKUP MOVED TO STAGE 2 (Cisco FTD Specification)
                steps.append(make_step("l3_route", vendor_id, "L3 Route Lookup", "FTD LINA", "pass", "ALLOWED",
                    f"Routing table lookup successful. Egress interface resolved to egress untrust gateway.",
                    "Egress: outside. Gateway: 203.0.113.1.",
                    "Phase: 7 Type: ROUTE-LOOKUP Result: ALLOW"))

                if payload_type == 'prefilter_fastpath':
                    steps.append(make_step("prefilter", vendor_id, "Prefilter Policy", "FTD LINA", "bypass", "FASTPATH",
                        "Prefilter rule 'Bypass_Fastpath' matched. Packet is fast-pathed around Snort threat inspection to conserve CPU.",
                        "Action: Fastpath/Trust bypass.",
                        "Phase: 8 Type: PREFILTER Result: ALLOW (FASTPATH)"))
                else:
                    steps.append(make_step("prefilter", vendor_id, "Prefilter Policy", "FTD LINA", "pass", "ALLOWED",
                        "Prefilter policy verified. No whitelists matched. Flow must enter Snort L7 scanning.",
                        "Action: Standard scan.",
                        "Phase: 8 Type: PREFILTER Result: ALLOW (SCAN)"))

                if sec_intel == 'blacklisted_ip':
                    steps.append(make_step("l3_l4_acl", vendor_id, "L3/L4 ACL", "FTD LINA", "pass", "ALLOWED",
                        "L3/L4 Access Control rule 'Permit_Internet' matched. Security Intelligence handles IP reputation.",
                        "Verdict: ALLOW. Action: Forward to Snort for SI inspection.",
                        "Phase: 9 Type: ACCESS-LIST Result: ALLOW"))
                else:
                    steps.append(make_step("l3_l4_acl", vendor_id, "L3/L4 ACL", "FTD LINA", "pass", "ALLOWED",
                        "L3/L4 Access Control rule 'Permit_Internet' matched. Initializing session.",
                        "Verdict: ALLOW. Action: Forward to Snort.",
                        "Phase: 9 Type: ACCESS-LIST Result: ALLOW"))
            else:
                for sid, name in [("vpn_decrypt", "VPN Decrypt"), ("un_nat", "UN-NAT (DNAT)"), 
                                  ("l3_route", "L3 Route Lookup"), ("prefilter", "Prefilter Policy"), 
                                  ("l3_l4_acl", "L3/L4 ACL")]:
                    steps.append(make_step(sid, vendor_id, name, "FTD LINA", "bypass", "FASTPATH", 
                        "LINA core rules bypassed by session hit.", "Status: Bypassed."))

            # Stage 3: Snort 3 Threat Prevention (Layer 7)
            # Snort is bypassed if Fastpath connection hit, prefilter Trust/Fastpath, or already dropped in LINA
            is_snort_active = is_slowpath and verdict == "ALLOW" and payload_type != 'prefilter_fastpath'

            if is_snort_active:
                steps.append(make_step("daq", vendor_id, "DAQ Handover", "FTD Snort", "pass", "INSPECTING",
                    "LINA successfully hands packet data to Snort 3 DAQ ring buffer context.",
                    "Handover: Complete.",
                    "Phase: 10 Type: DAQ-HANDOVER Result: ALLOW"))
                
                steps.append(make_step("snort_defrag", vendor_id, "Stream Defrag", "FTD Snort", "pass", "INSPECTING",
                    "Snort preprocessors performed TCP stream assembly and protocol decoding.",
                    "Reassembly context: Complete.",
                    "Phase: 11 Type: STREAM-DEFRAGMENTATION Result: ALLOW"))

                if ssl_decrypt:
                    if option_id == "opt_ssl_deny":
                        steps.append(make_step("ssl_decrypt", vendor_id, "SSL Decrypt", "FTD Snort", "fail", "DROPPED",
                            "SSL certificate validation failed. Untrusted/expired certificate detected on decrypted stream.",
                            "Certificate status: EXPIRED. SNI: blocked_site.example.com.",
                            "Phase: 12 Type: SSL-DECRYPT Result: DROP"))
                        verdict = "DROP"
                        drop_reason = "SSL Certificate untrusted/expired"
                    else:
                        steps.append(make_step("ssl_decrypt", vendor_id, "SSL Decrypt", "FTD Snort", "decrypt", "INSPECTING",
                            "SSL decrypted using proxy private certificate keys. Cleartext payloads exposed for threat scanning.",
                            "Proxy mode: Decrypt. TLS cipher: TLS_AES_256_GCM.",
                            "Phase: 12 Type: SSL-DECRYPT Result: ALLOW"))
                else:
                    steps.append(make_step("ssl_decrypt", vendor_id, "SSL Decrypt", "FTD Snort", "bypass", "FASTPATH",
                        "SSL decryption bypassed or cleartext traffic.", "Decryption: Bypassed."))

                if verdict == "ALLOW":
                    if sec_intel in ('blacklisted_dns', 'blacklisted_ip'):
                        is_c2 = sec_intel == 'blacklisted_ip'
                        c2_desc = "C2 Server IP" if is_c2 else "domain blacklist"
                        c2_feed = "Botnet feed (IP)" if is_c2 else "Botnet feed blacklist"
                        steps.append(make_step("security_intel", vendor_id, "Security Intel", "FTD Snort", "fail", "DROPPED",
                            f"Security Intelligence matched blacklisted {c2_desc}. Discarding.",
                            f"Verdict: DROP. Object: {c2_feed}.",
                            "Phase: 13 Type: SECURITY-INTELLIGENCE Result: DROP"))
                        verdict = "DROP"
                        drop_reason = f"Security Intelligence {'C2 IP' if is_c2 else 'Domain'} Block"
                    else:
                        steps.append(make_step("security_intel", vendor_id, "Security Intel", "FTD Snort", "pass", "ALLOWED",
                            "Security Intelligence feeds checked. No threat list matches verified.",
                            "Feeds checked: Malware, Botnet. Matches: 0.",
                            "Phase: 13 Type: SECURITY-INTELLIGENCE Result: ALLOW"))
                else:
                    steps.append(make_step("security_intel", vendor_id, "Security Intel", "FTD Snort", "bypass", "FASTPATH",
                        "Skipped — prior blade already dropped the session.", "Status: Downstream skipped."))

                if verdict == "ALLOW":
                    steps.append(make_step("identity_policy", vendor_id, "Identity Rule", "FTD Snort", "pass", "INSPECTING",
                        "Identity policy parsed. Active Directory resolved user passively.",
                        "User: security_admin (Passive AD).",
                        "Phase: 14 Type: IDENTITY-POLICY Result: ALLOW"))
                else:
                    steps.append(make_step("identity_policy", vendor_id, "Identity Rule", "FTD Snort", "bypass", "FASTPATH", "Skipped.", "Status: Bypassed."))

                if verdict == "ALLOW":
                    steps.append(make_step("l7_acl", vendor_id, "L7 App Filter", "FTD Snort", "pass", "INSPECTING",
                        "Application control verified application identity as HTTPS. Compliance check approved.",
                        "App ID resolved: web-browsing.",
                        "Phase: 15 Type: APPLICATION-CONTROL Result: ALLOW"))
                else:
                    steps.append(make_step("l7_acl", vendor_id, "L7 App Filter", "FTD Snort", "bypass", "FASTPATH", "Skipped.", "Status: Bypassed."))

                # Adjacent URL Filtering step in Snort Container (Cisco FTD Specification)
                if verdict == "ALLOW" and payload_type == "blocked_url":
                    steps.append(make_step("url_filter", vendor_id, "URL Filtering", "FTD Snort", "fail", "DROPPED",
                        "URL Filtering category matches forbidden blocklist 'Gambling'. Drop resolved.",
                        "Verdict: DROP. Site poker-online category matched. Action: DENY.",
                        "Phase: 16 Type: URL-FILTERING Result: DROP"))
                    verdict = "DROP"
                    drop_reason = "URL Category Restricted"
                elif verdict == "ALLOW":
                    steps.append(make_step("url_filter", vendor_id, "URL Filtering", "FTD Snort", "pass", "ALLOWED",
                        "URL filtering category lookup verified target safe.", "Matches: 0.",
                        "Phase: 16 Type: URL-FILTERING Result: ALLOW"))
                else:
                    steps.append(make_step("url_filter", vendor_id, "URL Filtering", "FTD Snort", "bypass", "FASTPATH",
                        "Skipped — prior blade already dropped the session.", "Status: Downstream skipped."))

                if verdict == "ALLOW" and payload_type == "sql_injection":
                    steps.append(make_step("ips", vendor_id, "IPS (Snort 3)", "FTD Snort", "fail", "DROPPED",
                        "Snort 3 IPS engine triggered rules. Exploits pattern matches SQL Injection attempt.",
                        "Verdict: DROP. GID: 1, SID: 19412 (SQL Injection). Pattern matched: UNION SELECT.",
                        "Phase: 17 Type: INTRUSION-PREVENTION Result: DROP"))
                    verdict = "DROP"
                    drop_reason = "Snort 3 IPS exploit match"
                elif verdict == "ALLOW":
                    steps.append(make_step("ips", vendor_id, "IPS (Snort 3)", "FTD Snort", "pass", "ALLOWED",
                        "Snort 3 IPS deep payload scans passed. No signatures matches.", "Threat signatures checked: 5800. Matches: 0.",
                        "Phase: 17 Type: INTRUSION-PREVENTION Result: ALLOW"))
                else:
                    steps.append(make_step("ips", vendor_id, "IPS (Snort 3)", "FTD Snort", "bypass", "FASTPATH",
                        "Skipped — prior blade already dropped the session.", "Status: Downstream skipped."))

                if verdict == "ALLOW" and payload_type == "malware":
                    steps.append(make_step("file_malware", vendor_id, "AMP Malware", "FTD Snort", "fail", "DROPPED",
                        "File policy matched executable payload transfer. Advanced Malware Protection (AMP) query resolved hash as MALICIOUS.",
                        "Verdict: DROP. File: eicar.com. SHA256: 275a021b. Threat: EICAR_Test_File.",
                        "Phase: 18 Type: MALWARE-AMP Result: DROP"))
                    verdict = "DROP"
                    drop_reason = "AMP Malware Block"
                elif verdict == "ALLOW":
                    steps.append(make_step("file_malware", vendor_id, "AMP Malware", "FTD Snort", "pass", "ALLOWED",
                        "File transfer policy analyzed. Safe file transfer verified.", "AMP status: Clean hash.",
                        "Phase: 18 Type: MALWARE-AMP Result: ALLOW"))
                else:
                    steps.append(make_step("file_malware", vendor_id, "AMP Malware", "FTD Snort", "bypass", "FASTPATH",
                        "Skipped — prior blade already dropped the session.", "Status: Downstream skipped."))

                if ssl_decrypt and verdict == "ALLOW":
                    steps.append(make_step("ssl_encrypt", vendor_id, "SSL Encrypt", "FTD Snort", "decrypt", "INSPECTING",
                        "Cleartext payloads re-encrypted using dynamic ephemeral TLS keys before egress.",
                        "Proxy mode: Re-encrypt. TLS cipher: TLS_AES_256_GCM.",
                        "Phase: 18.5 Type: SSL-ENCRYPT Result: ALLOW"))
                else:
                    steps.append(make_step("ssl_encrypt", vendor_id, "SSL Encrypt", "FTD Snort", "bypass", "FASTPATH",
                        "SSL encryption bypassed or traffic already cleartext.", "Encryption: Bypassed."))
            else:
                for sid, name in [("daq", "DAQ Handover"), ("snort_defrag", "Stream Defrag"),
                                  ("ssl_decrypt", "SSL Decrypt"), ("security_intel", "Security Intel"),
                                  ("identity_policy", "Identity Rule"), ("l7_acl", "L7 App Filter"),
                                  ("url_filter", "URL Filtering"), ("ips", "IPS (Snort 3)"),
                                  ("file_malware", "AMP Malware"), ("ssl_encrypt", "SSL Encrypt")]:
                    steps.append(make_step(sid, vendor_id, name, "FTD Snort", "bypass", "FASTPATH", 
                        "Snort 3 deep content threat scanning bypassed.", "Status: Bypassed."))

            # Stage 4: LINA Egress Core Processing
            if verdict == "ALLOW":
                steps.append(make_step("flow_update", vendor_id, "Flow Update", "FTD LINA", "pass", "INSPECTING",
                    "Snort 3 returned approved verdict. LINA updates packet flow tables. Connection offloaded.",
                    "Flow Acceleration State: ENABLED.",
                    "Phase: 19 Type: FLOW-UPDATE Result: ALLOW"))

                if nat_type == 'dynamic' and egress_interface == 'outside':
                    current_src_ip = "203.0.113.15"
                    steps.append(make_step("egress_nat", vendor_id, "Egress NAT (PAT)", "FTD LINA", "nat", "INSPECTING",
                        f"Dynamic PAT source NAT rule matched. Rewrite Source IP to public IP {current_src_ip}.",
                        f"Translated dynamic source: {current_src_ip}.",
                        "Phase: 20 Type: EGRESS-NAT Result: ALLOW"))
                else:
                    steps.append(make_step("egress_nat", vendor_id, "Egress NAT (PAT)", "FTD LINA", "bypass", "FASTPATH",
                        "No dynamic outbound Hide NAT translation rules apply.", "Status: Bypassed."))

                steps.append(make_step("qos", vendor_id, "QoS Shaping", "FTD LINA", "pass", "ALLOWED",
                    "Outbound QoS bandwidth shapes and prioritizes flow.",
                    "Class: Default-Priority. Drops: 0.",
                    "Phase: 21 Type: QOS-SHAPING Result: ALLOW"))

                if payload_type == "vpn_in":
                    steps.append(make_step("vpn_encrypt", vendor_id, "VPN Encrypt", "FTD LINA", "pass", "INSPECTING",
                        "Egress interface matched outbound VPN community encryption rules. Encapsulating raw packet into ESP tunnel.",
                        "ESP Cipher: AES256-GCM. Peer destination: 54.120.30.40.",
                        "Phase: 22 Type: VPN-ENCRYPT Result: ALLOW"))
                else:
                    steps.append(make_step("vpn_encrypt", vendor_id, "VPN Encrypt", "FTD LINA", "bypass", "FASTPATH",
                        "No outbound VPN mapping.", "Status: Bypassed."))

                steps.append(make_step("l2_arp", vendor_id, "L2 ARP Gateway", "FTD LINA", "pass", "ALLOWED",
                    "ARP cache contains resolved hardware MAC address mapping for next-hop gateway 203.0.113.1.",
                    "Next Hop MAC resolved: 00:08:e3:11:22:33.",
                    "Phase: 23 Type: ARP-RESOLUTION Result: ALLOW"))

                steps.append(make_step("egress", vendor_id, "Egress Send", "FTD LINA", "pass", "ALLOWED",
                    f"Packet successfully transmitted outbound via physical interface. Trace complete.",
                    f"Egress interface: outside. Final packet: {current_src_ip}:{current_src_port} -> {current_dst_ip}:{current_dst_port}",
                    "Phase: 24 Type: TRANSMIT Result: ALLOW"))
            else:
                for sid, name in [("flow_update", "Flow Update"), ("egress_nat", "Egress NAT (PAT)"),
                                  ("qos", "QoS Shaping"), ("vpn_encrypt", "VPN Encrypt"),
                                  ("l2_arp", "L2 ARP Gateway")]:
                    steps.append(make_step(sid, vendor_id, name, "FTD LINA", "bypass", "FASTPATH", "Skipped.", "Status: Bypassed."))
                
                steps.append(make_step("egress", vendor_id, "Egress Send", "FTD LINA", "bypass", "FASTPATH",
                    "Egress transmission aborted. Packet discarded inside firewall engine.",
                    f"Discarded status at stage: {drop_reason}.",
                    "Phase: 24 Type: TRANSMIT Result: DROP"))

        # ============================================================
        # Force Verdict Override (DENIED segmented control)
        # ============================================================
        if force_verdict == 'deny' and verdict == 'ALLOW':
            # Map target_engine to step ID prefixes where the drop should occur
            engine_drop_map = {
                'l4_core': ['fg_policy', 'pa_slow_security_policy', 'cp_f2f_policy', 'l3_l4_acl', 'prefilter'],
                'ips_engine': ['fg_ips', 'pa_content_vuln', 'cp_cmi_ips', 'ips'],
                'malware_engine': ['fg_av', 'fg_dlp', 'pa_content_av', 'pa_content_spyware', 'cp_cmi_ab_av', 'cp_cmi_threat_emulation', 'cp_cmi_te', 'file_malware'],
                'url_filter': ['fg_wf', 'fg_webfilter', 'pa_content_url', 'cp_cmi_url', 'url_filter'],
                'vpn_engine': ['fg_ipsec_in', 'pa_ingress_vpn_decrypt', 'cp_snd_decrypt', 'vpn_decrypt'],
                'acl_rulebase': ['fg_policy', 'pa_slow_security_policy', 'cp_f2f_policy', 'l3_l4_acl'],
                'auth_engine': ['fg_auth', 'pa_app_allow_check', 'cp_f2f_policy', 'identity_policy'],
                'threat_intel': ['fg_dos', 'pa_ingress_error', 'cp_snd_acl', 'security_intel'],
                'ssl_engine': ['fg_ssl_decrypt', 'fg_ssl_check', 'pa_fast_ssl_decrypt', 'cp_cmi_https_decrypt', 'ssl_decrypt'],
                'prefilter': ['fg_session_lookup', 'pa_fast_session_lookup', 'cp_sxl_fastpath', 'cp_sxl_pxl', 'existing_conn', 'prefilter']
            }
            drop_targets = engine_drop_map.get(target_engine, ['fg_policy', 'pa_slow_security_policy', 'cp_f2f_policy', 'l3_l4_acl'])

            # Find the first matching step and mark it as fail
            drop_applied = False
            for i, step in enumerate(steps):
                if drop_applied:
                    # Mark remaining steps as bypass
                    step['status'] = 'bypass'
                    step['verdict'] = 'FASTPATH'
                    step['explanation'] = 'Skipped — packet already dropped.'
                    step['details'] = 'Status: Bypassed.'
                    step['technicalBehaviorDetails'] = 'Status: Bypassed.'
                elif any(step['id'].startswith(t) or step['id'] == t for t in drop_targets):
                    step['status'] = 'fail'
                    step['verdict'] = 'DROPPED'
                    step['explanation'] = f'[Force Denied] Policy verdict override: packet dropped at {step["name"]}.'
                    step['technicalBehaviorDetails'] = f'Forced deny applied at engine: {target_engine}. Step: {step["id"]}.'
                    drop_applied = True

            if drop_applied:
                verdict = 'DROP'
                drop_reason = f'Policy Verdict Override ({target_engine})'
            else:
                # Fallback: drop at the last non-egress step
                for i in range(len(steps) - 1, -1, -1):
                    if 'egress' not in steps[i]['id'] and 'nic_out' not in steps[i]['id']:
                        steps[i]['status'] = 'fail'
                        steps[i]['verdict'] = 'DROPPED'
                        steps[i]['explanation'] = '[Force Denied] Policy verdict override.'
                        for j in range(i + 1, len(steps)):
                            steps[j]['status'] = 'bypass'
                            steps[j]['verdict'] = 'FASTPATH'
                        verdict = 'DROP'
                        drop_reason = 'Policy Verdict Override'
                        break

        # Truncate steps for FortiGate brand if there's a DROP verdict
        if brand == 'fortigate' and verdict == 'DROP':
            truncated_steps = []
            for step in steps:
                truncated_steps.append(step)
                if step['status'] == 'fail':
                    break
            steps = truncated_steps

        return jsonify({
            "status": "success",
            "verdict": verdict,
            "drop_reason": drop_reason,
            "steps": steps
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8002, debug=False)
