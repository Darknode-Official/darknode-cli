"use strict";
// ================= attack planner — AI-guided penetration testing methodology engine =================
// Darknode's attack planner is a knowledge base + decision engine for authorized security
// assessments. It encodes standard pentest methodology (PTES/OSSTMM/OWASP-flavored) as data:
//   - METHODOLOGY_PHASES  : the 7-phase lifecycle of an engagement (recon -> reporting)
//   - SERVICE_PLAYBOOKS   : per-service enumeration/exploitation/post-exploitation notes
//   - COMMON_ATTACK_PATHS : named attack chains ("if you see X, try Y then Z")
//   - suggestNextStep()   : given current findings, recommend the single next action
//   - generatePlan()      : given a target + scope, build a full structured engagement plan
//
// This module is descriptive, not offensive: it does not run scans or exploits, it only
// organizes publicly documented methodology so an operator (human or AI co-pilot) can decide
// what to do next during an ENGAGEMENT THEY ARE AUTHORIZED TO PERFORM. Nothing here should be
// used against systems without written permission.
//
// Only Node.js built-ins are used. No network calls, no external dependencies.

// ---------------------------------------------------------------------------------------
// METHODOLOGY_PHASES — the 7-phase engagement lifecycle
// ---------------------------------------------------------------------------------------

const METHODOLOGY_PHASES = [
  {
    name: "Reconnaissance",
    description:
      "Passive and semi-passive information gathering about the target organization, its " +
      "people, and its infrastructure, performed without directly touching in-scope systems " +
      "where possible. Builds the map that every later phase depends on.",
    objectives: [
      "Establish the full attack surface (domains, subdomains, IP ranges, cloud assets)",
      "Identify the technology stack in use before any active probing occurs",
      "Collect human intelligence (employee names, roles, emails) for later social engineering tests",
      "Discover inadvertently leaked credentials, keys, or configuration",
      "Confirm scope boundaries and rules of engagement before any active testing begins",
    ],
    steps: [
      "Review the signed rules of engagement and confirm in-scope hosts, domains, and IP ranges",
      "Perform WHOIS lookups on the primary domain and any related domains",
      "Enumerate DNS records: A, AAAA, MX, TXT, NS, SOA, CNAME, SRV",
      "Attempt a DNS zone transfer (AXFR) against each authoritative nameserver",
      "Query certificate transparency logs (crt.sh, censys) for subdomain names",
      "Run passive and active subdomain enumeration and de-duplicate the results",
      "Resolve all discovered subdomains and record live vs. dead hosts",
      "Identify IP ranges and ASN ownership via RIR/BGP lookups (ARIN, RIPE, APNIC)",
      "Search Shodan/Censys/ZoomEye for internet-facing assets tied to the organization",
      "Check for exposed cloud storage (S3 buckets, Azure blobs, GCS buckets) using naming patterns",
      "Harvest employee names, job titles, and email addresses from LinkedIn and the corporate site",
      "Search public job postings for technology stack and internal tooling clues",
      "Search GitHub/GitLab/Bitbucket for leaked credentials, API keys, or internal configuration",
      "Search public paste sites and breach databases for previously leaked organizational data",
      "Run search-engine reconnaissance (Google dorking) against the target domain",
      "Review the Wayback Machine / archive.org for historical site content and old endpoints",
      "Fingerprint web technology stacks across all discovered web properties",
      "Map organizational structure, subsidiaries, and third-party vendor relationships",
      "Inspect public document metadata (PDF/DOCX authorship, software versions, usernames)",
      "Compile all findings into a structured reconnaissance dossier for the next phase",
    ],
    tools: [
      "whois", "dig", "nslookup", "amass", "subfinder", "assetfinder", "theHarvester",
      "crt.sh", "Shodan", "Censys", "Recon-ng", "Maltego", "SpiderFoot", "Google dorks",
      "Wayback Machine", "LinkedIn", "GitHub code search", "ExifTool",
    ],
    outputs: [
      "Validated in-scope host and domain inventory",
      "Subdomain and DNS record map",
      "ASN / IP range ownership map",
      "Employee and role directory with email format",
      "Technology stack fingerprint per web property",
      "List of leaked credentials, keys, or sensitive files found publicly",
      "Reconnaissance report feeding into the Scanning phase",
    ],
  },
  {
    name: "Scanning",
    description:
      "Active probing of in-scope hosts to determine what is alive, what ports are open, and " +
      "what services and versions are running behind them. The first phase that directly " +
      "touches target infrastructure.",
    objectives: [
      "Determine which in-scope hosts are live and reachable",
      "Enumerate open TCP and UDP ports across all live hosts",
      "Identify running services and their version numbers",
      "Fingerprint operating systems and network devices",
      "Detect basic filtering, load balancing, or IDS/IPS behavior",
    ],
    steps: [
      "Re-confirm the exact scope boundary before sending a single packet",
      "Perform host discovery (ICMP, ARP for local networks, TCP/UDP ping sweeps)",
      "Run a fast full-port TCP scan to identify all open ports on each live host",
      "Run a slower, more thorough TCP scan (SYN/connect) to catch filtered or slow-to-respond ports",
      "Run a UDP scan against common UDP services (DNS, SNMP, NTP, TFTP)",
      "Perform service and version detection against every open port",
      "Perform OS fingerprinting on each live host",
      "Grab banners manually on non-standard or unrecognized ports",
      "Run scripted vulnerability/enumeration checks (e.g. nmap NSE scripts) against detected services",
      "Test for basic firewall/IDS evasion behavior (fragmentation, decoys, timing) if scope allows",
      "Identify load balancers, WAFs, or reverse proxies fronting web services",
      "Scan for common management interfaces (IPMI, iLO, iDRAC, printers, IoT admin panels)",
      "Enumerate SSL/TLS configuration, supported protocol versions, and certificate details",
      "Cross-reference open ports against the recon-phase technology fingerprint for consistency",
      "Record round-trip times and scan behavior to identify rate-limiting or throttling",
      "Re-scan any host that timed out or gave inconsistent results",
      "Deduplicate and normalize scan output into a single host/port/service inventory",
      "Flag any host or service that appears to be out of scope and pause testing on it",
      "Compile a service inventory ranked by likely attack value",
    ],
    tools: [
      "nmap", "masscan", "rustscan", "zmap", "unicornscan", "hping3", "netcat",
      "OpenSSL s_client", "testssl.sh", "sslscan", "Wireshark", "tcpdump",
    ],
    outputs: [
      "Live host inventory",
      "Open port list per host (TCP and UDP)",
      "Service and version inventory",
      "OS fingerprint per host",
      "TLS/SSL configuration summary",
      "Ranked list of interesting services for the Enumeration phase",
    ],
  },
  {
    name: "Enumeration",
    description:
      "Deep, service-specific interrogation of everything found during scanning: shares, users, " +
      "groups, web application structure, database schemas, and configuration details that turn " +
      "an open port into an actionable target.",
    objectives: [
      "Extract usable detail from every service discovered during scanning",
      "Enumerate valid usernames and account naming conventions",
      "Map web application structure, endpoints, and parameters",
      "Identify authentication mechanisms and session handling",
      "Discover misconfigurations that reduce the effort required for exploitation",
    ],
    steps: [
      "Enumerate SMB shares, null sessions, and RID cycling against Windows hosts",
      "Enumerate SNMP via public/private community strings (snmpwalk)",
      "Enumerate NFS exports and check for no_root_squash misconfiguration",
      "Enumerate LDAP via anonymous bind and dump directory structure where permitted",
      "Enumerate SMTP/POP3/IMAP for user validation (VRFY/EXPN/RCPT TO behavior)",
      "Crawl and spider all in-scope web applications to build a full endpoint map",
      "Brute-force discover hidden directories, files, and backup artifacts on web servers",
      "Identify web application frameworks, CMS platforms, and plugin/theme versions",
      "Enumerate web application parameters and input points for later vulnerability analysis",
      "Test for default or well-known administrative interfaces and login portals",
      "Enumerate database service banners and attempt default-credential logins where in scope",
      "Enumerate RPC services and DCE/RPC endpoints on Windows hosts",
      "Enumerate FTP/TFTP for anonymous access and directory listings",
      "Enumerate Kerberos for valid usernames (AS-REP pre-auth checks) where applicable",
      "Enumerate RDP/VNC/WinRM for authentication method and version details",
      "Review HTTP response headers and cookies for framework and session fingerprints",
      "Identify API endpoints, GraphQL introspection, and undocumented interfaces",
      "Cross-reference recon-phase leaked credentials against discovered login portals",
      "Document account lockout policy and password complexity signals observed during testing",
      "Consolidate enumeration output into a per-service findings sheet",
    ],
    tools: [
      "enum4linux-ng", "smbclient", "rpcclient", "snmpwalk", "showmount", "ldapsearch",
      "gobuster", "ffuf", "feroxbuster", "wfuzz", "nikto", "whatweb", "Burp Suite",
      "smtp-user-enum", "kerbrute", "CrackMapExec", "nmap NSE",
    ],
    outputs: [
      "Per-service enumeration findings sheet",
      "Valid username list and naming convention",
      "Web application endpoint and parameter map",
      "Share, export, and directory listing inventory",
      "Observed authentication and lockout policy notes",
      "Candidate misconfiguration list feeding into Vulnerability Analysis",
    ],
  },
  {
    name: "Vulnerability Analysis",
    description:
      "Correlate enumerated versions and configurations against known vulnerabilities, then " +
      "manually verify each candidate to separate real findings from scanner noise before any " +
      "exploitation is attempted.",
    objectives: [
      "Map discovered software versions to known CVEs and advisories",
      "Run automated vulnerability scanning where scope permits",
      "Manually validate every automated finding to eliminate false positives",
      "Score and prioritize confirmed vulnerabilities by real-world exploitability and impact",
      "Identify logic flaws and misconfigurations that scanners cannot detect",
    ],
    steps: [
      "Run an authenticated or unauthenticated vulnerability scan against in-scope hosts",
      "Run a dedicated web application scan against every discovered web property",
      "Cross-reference each service version against public CVE databases",
      "Search Exploit-DB, Metasploit modules, and GitHub PoCs for each candidate CVE",
      "Manually verify each automated finding against the live target before trusting it",
      "Eliminate false positives introduced by version-string mismatches or backported patches",
      "Review web application logic for business-logic flaws automated scanners miss",
      "Manually test for OWASP Top 10 classes: injection, broken auth, XSS, SSRF, deserialization",
      "Check for default credentials across every enumerated service",
      "Check for missing security headers, verbose error messages, and information disclosure",
      "Assess certificate and TLS configuration weaknesses identified during scanning",
      "Review file upload, file inclusion, and path traversal exposure on web applications",
      "Review API endpoints for broken object level authorization (BOLA/IDOR)",
      "Score each confirmed vulnerability using CVSS and business-impact context",
      "Group vulnerabilities into candidate attack chains rather than treating them in isolation",
      "Flag any finding that risks service disruption and require explicit client sign-off first",
      "Prioritize the final vulnerability list by exploitability, impact, and time available",
      "Document proof-of-concept evidence for every confirmed finding",
    ],
    tools: [
      "Nessus", "OpenVAS", "Qualys", "Nuclei", "Nikto", "Burp Suite Pro", "OWASP ZAP",
      "searchsploit", "Metasploit (search)", "sqlmap (detection mode)", "testssl.sh",
      "CVE/NVD databases", "GitHub advisory database",
    ],
    outputs: [
      "Confirmed vulnerability list with CVSS scores",
      "False-positive elimination log",
      "Candidate attack-chain groupings",
      "Proof-of-concept evidence per finding",
      "Prioritized exploitation shortlist for the Exploitation phase",
    ],
  },
  {
    name: "Exploitation",
    description:
      "Careful, controlled attempts to prove that confirmed vulnerabilities are actually " +
      "exploitable, gaining an initial foothold while minimizing risk of service disruption " +
      "or unintended damage to production systems.",
    objectives: [
      "Prove exploitability of prioritized vulnerabilities with minimal-impact techniques",
      "Gain an initial foothold on at least one in-scope system where feasible",
      "Avoid denial-of-service or data-destruction side effects during testing",
      "Capture clean evidence of each successful exploitation for the report",
      "Escalate access only as far as the rules of engagement allow",
    ],
    steps: [
      "Re-confirm rules of engagement, especially any prohibition on denial-of-service techniques",
      "Select the least-destructive exploitation path first among equally viable options",
      "Test exploits in a lab/staging replica before running against production where one exists",
      "Attempt credential-based access using any credentials recovered during earlier phases",
      "Attempt password spraying with a small, low-lockout-risk candidate list where authorized",
      "Exploit confirmed web application vulnerabilities (injection, upload, deserialization, SSRF)",
      "Exploit confirmed service-level vulnerabilities using vetted, version-matched exploit code",
      "Exploit misconfigurations (default creds, open shares, anonymous access) before memory-corruption bugs",
      "Validate exploit stability and success rate before relying on it for further phases",
      "Establish a stable but minimally invasive foothold (web shell, reverse shell, valid session)",
      "Avoid installing unnecessary persistence unless explicitly scoped for a persistence test",
      "Capture screenshots, command output, and timestamps as evidence immediately after success",
      "Note the exact payload, command, and target state for reproducibility in the report",
      "Pause and reassess if an exploitation attempt causes unexpected service behavior",
      "Notify the client immediately per the engagement's emergency contact procedure if instability occurs",
      "Record failed exploitation attempts and the reason for failure for completeness",
      "Confirm the level of access obtained (user, service account, admin, root/SYSTEM)",
      "Hand off the foothold and access level cleanly into the Post-Exploitation phase",
    ],
    tools: [
      "Metasploit Framework", "sqlmap", "Burp Suite Intruder/Repeater", "Hydra",
      "custom PoC exploit code", "msfvenom", "Cobalt Strike (authorized engagements)",
      "curl/httpie for manual HTTP exploitation", "John the Ripper", "Hashcat",
    ],
    outputs: [
      "List of successfully exploited vulnerabilities with reproduction steps",
      "Initial foothold access details and access level achieved",
      "Evidence package (screenshots, logs, command transcripts)",
      "Failed-attempt log with root cause notes",
      "Handoff summary for Post-Exploitation",
    ],
  },
  {
    name: "Post-Exploitation",
    description:
      "From an established foothold, determine the real-world business impact of the breach: " +
      "how far an attacker could escalate, move laterally, and reach sensitive data, always " +
      "within the boundaries and depth the client authorized.",
    objectives: [
      "Escalate privileges from the initial foothold where authorized",
      "Assess lateral movement potential across the internal network",
      "Identify what sensitive data or systems the compromised access can reach",
      "Demonstrate business impact without exfiltrating or damaging real data",
      "Document a realistic attacker's-eye view of the environment for the client",
    ],
    steps: [
      "Confirm with the client the exact depth of post-exploitation activity that is authorized",
      "Enumerate local privilege escalation vectors on the compromised host",
      "Enumerate stored credentials, tokens, and configuration secrets on the compromised host",
      "Attempt privilege escalation using the least invasive technique available",
      "Dump accessible credential material (hashes, tickets, tokens) where authorized",
      "Map the internal network reachable from the compromised host",
      "Identify domain trust relationships and directory service structure where applicable",
      "Attempt lateral movement to a second host using harvested credentials or trust relationships",
      "Identify high-value targets reachable from current access (domain controllers, databases, file servers)",
      "Demonstrate access to representative sensitive data without exfiltrating bulk records",
      "Assess whether the compromised access could reach out-of-scope systems and stop before crossing that line",
      "Document any evidence of prior compromise or unrelated malicious activity discovered incidentally",
      "Test detection and response: note whether any defensive control alerted during activity",
      "Record every command executed and system touched for a full activity timeline",
      "Clean up any test artifacts, accounts, or files created during the engagement",
      "Revert any configuration changes made for testing purposes",
      "Confirm no persistence mechanism remains active after testing concludes",
      "Summarize the realistic blast radius and business impact for the reporting phase",
    ],
    tools: [
      "BloodHound", "Mimikatz (authorized engagements)", "CrackMapExec", "Impacket suite",
      "LinPEAS/WinPEAS", "PowerView", "Rubeus", "PsExec", "SSH agent forwarding analysis",
    ],
    outputs: [
      "Privilege escalation chain documentation",
      "Lateral movement map and reachable-asset inventory",
      "Business impact and blast-radius assessment",
      "Detection/response observation notes",
      "Cleanup and remediation confirmation log",
    ],
  },
  {
    name: "Reporting",
    description:
      "Translate technical findings into a report that both executives and engineers can act " +
      "on: clear risk framing for decision-makers, precise reproduction steps for defenders, " +
      "and concrete remediation guidance for every finding.",
    objectives: [
      "Communicate business risk clearly to non-technical stakeholders",
      "Provide engineers with exact reproduction steps for every finding",
      "Prioritize remediation guidance by risk and effort",
      "Preserve a clean, defensible evidence trail for every claim in the report",
      "Support the client through remediation and retesting",
    ],
    steps: [
      "Draft an executive summary framed around business risk, not technical jargon",
      "Draft a scope and methodology section describing exactly what was and was not tested",
      "List every finding with a clear title, affected asset, and risk rating",
      "Write detailed technical descriptions with exact reproduction steps for each finding",
      "Attach evidence (screenshots, logs, request/response pairs) for every finding",
      "Assign a CVSS score and a business-context risk rating to each finding",
      "Group related findings into attack narratives showing how they chain together",
      "Write specific, actionable remediation guidance for each finding, not generic advice",
      "Distinguish between quick wins and structural/long-term remediation items",
      "Include a prioritized remediation roadmap ordered by risk reduction per unit of effort",
      "Review the report internally for technical accuracy before delivery",
      "Redact or handle sensitive data captured during testing according to the data handling agreement",
      "Deliver the report through an agreed secure channel",
      "Walk the client through findings in a live debrief session",
      "Answer client questions about reproduction, impact, and remediation approach",
      "Offer a retest window to verify remediation of critical and high findings",
      "Perform the retest and issue a retest addendum documenting closed vs. open findings",
      "Archive engagement evidence per the data retention policy and securely destroy it after that",
    ],
    tools: [
      "Reporting templates (PTES/OSSTMM-aligned)", "Dradis", "PlexTrac", "Serpico",
      "Markdown/LaTeX report tooling", "screenshot/annotation tools", "secure file transfer",
    ],
    outputs: [
      "Executive summary",
      "Full technical findings report with reproduction steps and evidence",
      "Prioritized remediation roadmap",
      "Client debrief record",
      "Retest addendum",
    ],
  },
];

// ---------------------------------------------------------------------------------------
// SERVICE_PLAYBOOKS — per-service enumeration / exploitation / post-exploitation notes
// ---------------------------------------------------------------------------------------

const SERVICE_PLAYBOOKS = {
  SSH: {
    port: 22,
    description: "Secure Shell remote administration service, commonly the primary remote access path on Linux/Unix hosts.",
    enumeration: [
      "Grab the SSH banner to identify software and version",
      "Enumerate supported authentication methods (password, publickey, keyboard-interactive)",
      "Enumerate supported key exchange algorithms and ciphers for weak-crypto findings",
      "Check for username enumeration via timing differences on failed authentication",
      "Check for any exposed SSH host key reused across other known systems",
    ],
    commonVulnerabilities: [
      "Weak or default credentials",
      "Password authentication enabled alongside weak password policy",
      "Outdated OpenSSH version with known CVEs",
      "Reused SSH keys across multiple hosts or environments",
      "Username enumeration via authentication timing",
    ],
    exploitation: [
      "Attempt low-and-slow credential brute force respecting lockout thresholds",
      "Attempt authentication with credentials recovered during recon or other services",
      "Attempt authentication with any private keys recovered from source repos or backups",
      "Exploit known CVEs for the specific OpenSSH version if applicable",
    ],
    postExploitation: [
      "Review shell history and configuration files for further credentials",
      "Check for SSH agent forwarding or cached keys enabling lateral movement",
      "Review authorized_keys files across user home directories",
      "Assess sudo configuration for local privilege escalation paths",
    ],
    tools: ["ssh", "hydra", "medusa", "ncrack", "ssh-audit", "nmap NSE (ssh2-enum-algos)"],
  },
  "HTTP/HTTPS": {
    port: 80,
    description: "Web server / web application service, the largest and most common attack surface on nearly every engagement.",
    enumeration: [
      "Fingerprint the web server, framework, and CMS in use",
      "Crawl the site and enumerate all reachable endpoints and parameters",
      "Brute-force discover hidden directories, files, and backup artifacts",
      "Review HTTP response headers, cookies, and security header configuration",
      "Enumerate API endpoints, GraphQL schemas, and undocumented routes",
      "Identify authentication and session management mechanisms",
    ],
    commonVulnerabilities: [
      "SQL injection, command injection, and other injection classes",
      "Cross-site scripting (reflected, stored, DOM-based)",
      "Broken authentication and session management",
      "Insecure direct object references / broken object level authorization",
      "Server-side request forgery",
      "Insecure file upload leading to remote code execution",
      "Outdated CMS/plugin versions with known CVEs",
      "Missing security headers and verbose error disclosure",
    ],
    exploitation: [
      "Exploit confirmed injection vulnerabilities to extract data or achieve code execution",
      "Exploit insecure file upload to obtain a web shell",
      "Exploit known CMS/plugin CVEs matching the fingerprinted version",
      "Exploit authentication or session flaws to hijack accounts or escalate privilege",
      "Chain SSRF into internal network access or cloud metadata service exposure",
    ],
    postExploitation: [
      "Review web application configuration files for embedded credentials",
      "Pivot from the web server host into the internal network if reachable",
      "Review database connection strings and application secrets",
      "Assess the web server process's OS-level privileges for local escalation",
    ],
    tools: ["Burp Suite", "OWASP ZAP", "sqlmap", "ffuf", "gobuster", "nikto", "whatweb", "wpscan"],
  },
  FTP: {
    port: 21,
    description: "File Transfer Protocol service, frequently misconfigured to allow anonymous or overly permissive access.",
    enumeration: [
      "Check for anonymous login (anonymous/anonymous or anonymous/blank)",
      "Grab the FTP banner to identify server software and version",
      "List directory contents and check write permissions if authenticated",
      "Check whether the FTP service supports active and/or passive mode bounce techniques",
    ],
    commonVulnerabilities: [
      "Anonymous access enabled with sensitive files exposed",
      "Weak or default credentials",
      "Outdated FTP daemon with known remote code execution CVEs",
      "World-writable directories enabling malicious file upload",
      "Cleartext credential transmission",
    ],
    exploitation: [
      "Log in anonymously and download any accessible files for review",
      "Upload a test file to confirm write access if in scope",
      "Attempt credential brute force respecting lockout policy",
      "Exploit known CVEs for the specific FTP daemon and version",
    ],
    postExploitation: [
      "Review downloaded files for credentials, configuration, or source code",
      "If write access exists on a web-served directory, consider chaining to web shell upload",
    ],
    tools: ["ftp", "lftp", "hydra", "nmap NSE (ftp-anon, ftp-vsftpd-backdoor)"],
  },
  "SMB/CIFS": {
    port: 445,
    description: "Windows file and printer sharing protocol; a primary enumeration and lateral movement surface in Windows environments.",
    enumeration: [
      "Enumerate SMB shares and their access permissions",
      "Attempt a null session or guest session to list shares and users",
      "Perform RID cycling to enumerate users and groups",
      "Enumerate the SMB dialect and signing configuration",
      "Check for the presence of known vulnerable SMB implementations",
    ],
    commonVulnerabilities: [
      "SMB signing not required, enabling relay attacks",
      "Anonymous/null session access to shares",
      "EternalBlue-class remote code execution (unpatched SMBv1)",
      "Weak share permissions exposing sensitive files",
      "Weak or default local administrator credentials reused across hosts",
    ],
    exploitation: [
      "Exploit unpatched SMBv1 remote code execution vulnerabilities where present",
      "Perform SMB relay attacks when signing is not enforced",
      "Authenticate with credentials recovered elsewhere and access shares directly",
      "Use pass-the-hash with recovered NTLM hashes to authenticate without a plaintext password",
    ],
    postExploitation: [
      "Enumerate and read accessible shares for sensitive data",
      "Dump SAM/LSA secrets if administrative access is achieved",
      "Use recovered credentials or hashes for lateral movement to other hosts",
    ],
    tools: ["smbclient", "enum4linux-ng", "CrackMapExec", "Impacket (psexec.py, secretsdump.py)", "nmap NSE (smb-vuln-*)"],
  },
  MySQL: {
    port: 3306,
    description: "Relational database service, often reachable directly or reachable indirectly via an associated web application.",
    enumeration: [
      "Grab the MySQL banner and version",
      "Attempt an unauthenticated or default-credential connection",
      "Enumerate available databases and table structure if authenticated",
      "Check the configured privileges of the connecting account",
    ],
    commonVulnerabilities: [
      "Default or weak root/admin credentials",
      "Remote root login enabled and reachable from untrusted networks",
      "Outdated MySQL/MariaDB version with known CVEs",
      "User-defined function (UDF) privilege escalation misconfiguration",
    ],
    exploitation: [
      "Attempt default and weak credential logins",
      "Exploit UDF-based command execution if FILE privilege and writable plugin directory are available",
      "Exploit SQL injection in a connected web application to reach the database directly",
    ],
    postExploitation: [
      "Dump credential tables and application secrets",
      "Search for cross-application credential reuse in stored data",
      "Attempt OS command execution via UDF if privileges allow",
    ],
    tools: ["mysql client", "sqlmap", "hydra", "nmap NSE (mysql-*)"],
  },
  PostgreSQL: {
    port: 5432,
    description: "Relational database service supporting powerful extensibility features that can lead to remote code execution if misconfigured.",
    enumeration: [
      "Grab the PostgreSQL banner and version",
      "Attempt default-credential and trust-authentication login",
      "Enumerate databases, schemas, and roles if authenticated",
      "Check whether the connecting role has superuser privileges",
    ],
    commonVulnerabilities: [
      "Default or weak postgres account credentials",
      "pg_hba.conf configured with trust authentication from untrusted networks",
      "COPY ... TO/FROM PROGRAM command execution available to superuser roles",
      "Outdated PostgreSQL version with known CVEs",
    ],
    exploitation: [
      "Attempt default and weak credential logins",
      "Use COPY ... FROM PROGRAM to execute OS commands if superuser privileges are available",
      "Exploit SQL injection in a connected web application to reach the database directly",
    ],
    postExploitation: [
      "Dump credential and configuration tables",
      "Achieve OS command execution via COPY PROGRAM if privileges allow",
      "Review server-side configuration files for further credentials",
    ],
    tools: ["psql", "sqlmap", "hydra", "nmap NSE (pgsql-brute)"],
  },
  MSSQL: {
    port: 1433,
    description: "Microsoft SQL Server database service, frequently a strong pivot point into Windows/Active Directory environments.",
    enumeration: [
      "Grab the MSSQL banner and version via the TDS protocol",
      "Attempt default or weak sa/administrator credential login",
      "Enumerate linked servers and database roles if authenticated",
      "Check whether xp_cmdshell is enabled or can be enabled",
    ],
    commonVulnerabilities: [
      "Default or weak sa account credentials",
      "xp_cmdshell available or re-enablable, permitting OS command execution",
      "Excessive privileges granted to the connecting application account",
      "Linked server misconfiguration enabling privilege escalation across servers",
    ],
    exploitation: [
      "Attempt default and weak credential logins including sa",
      "Enable and use xp_cmdshell to achieve OS command execution",
      "Abuse linked server trust relationships to pivot between database instances",
    ],
    postExploitation: [
      "Use OS command execution to establish a foothold on the underlying Windows host",
      "Harvest service account credentials used to run the SQL Server service",
      "Pivot into the Active Directory environment using the harvested service account",
    ],
    tools: ["Impacket (mssqlclient.py)", "sqsh", "hydra", "sqlmap", "CrackMapExec"],
  },
  Redis: {
    port: 6379,
    description: "In-memory key-value data store commonly deployed without authentication, making it a frequent remote code execution vector.",
    enumeration: [
      "Attempt an unauthenticated connection to confirm whether AUTH is required",
      "Run the INFO command to fingerprint version and configuration",
      "Check whether the server is bound to a non-loopback interface",
    ],
    commonVulnerabilities: [
      "No authentication required (unauthenticated access)",
      "Writable filesystem paths reachable via the CONFIG SET/GET commands",
      "Outdated Redis version with known CVEs",
      "Exposure to the internet without network-level restriction",
    ],
    exploitation: [
      "Use CONFIG SET to write an SSH authorized_keys file for remote access",
      "Use CONFIG SET dbfilename/dir combined with a crafted webshell for web-root-adjacent RCE",
      "Abuse the Redis module loading feature to achieve remote code execution where enabled",
    ],
    postExploitation: [
      "Review stored keys for cached credentials, session tokens, or application secrets",
      "Use the gained host access to pivot toward the application server it supports",
    ],
    tools: ["redis-cli", "Metasploit (redis modules)", "nmap NSE (redis-info)"],
  },
  MongoDB: {
    port: 27017,
    description: "Document-oriented NoSQL database frequently exposed without authentication in default configurations.",
    enumeration: [
      "Attempt an unauthenticated connection to confirm whether access control is enabled",
      "List databases and collections if access is unauthenticated or credentials are known",
      "Check the bound network interface and exposure to untrusted networks",
    ],
    commonVulnerabilities: [
      "No authentication required (unauthenticated access to all data)",
      "Default or weak administrative credentials",
      "Outdated MongoDB version with known CVEs",
      "Exposure to the internet without network-level restriction",
    ],
    exploitation: [
      "Connect without credentials and enumerate all accessible databases",
      "Attempt default credential logins against protected instances",
      "Extract collections directly to assess data exposure impact",
    ],
    postExploitation: [
      "Review extracted collections for credentials, PII, or application secrets",
      "Assess whether recovered credentials are reused on other in-scope services",
    ],
    tools: ["mongo shell", "nmap NSE (mongodb-info)", "Metasploit (mongodb modules)"],
  },
  SNMP: {
    port: 161,
    description: "Simple Network Management Protocol used to monitor and configure network devices, often left with default community strings.",
    enumeration: [
      "Attempt SNMP walks using the community strings public and private",
      "Enumerate system information, running processes, and installed software via SNMP MIBs",
      "Enumerate network interfaces and routing information via SNMP",
      "Identify the SNMP version in use (v1/v2c lack encryption, v3 supports it)",
    ],
    commonVulnerabilities: [
      "Default or guessable community strings (public/private)",
      "SNMPv1/v2c in use, transmitting community strings in cleartext",
      "Sensitive configuration and credential data exposed via writable MIBs",
      "Write access enabled allowing device reconfiguration",
    ],
    exploitation: [
      "Walk the full MIB tree using a discovered community string to extract configuration data",
      "Use SNMP write access, where present, to modify device configuration",
      "Extract cleartext credentials sometimes stored in vendor-specific MIBs",
    ],
    postExploitation: [
      "Use extracted device configuration to identify further internal targets",
      "Use any recovered credentials against SSH, Telnet, or web management interfaces on the same device",
    ],
    tools: ["snmpwalk", "snmp-check", "onesixtyone", "Metasploit (snmp modules)"],
  },
  SMTP: {
    port: 25,
    description: "Simple Mail Transfer Protocol service used for mail relay and delivery, useful for username enumeration and open-relay testing.",
    enumeration: [
      "Grab the SMTP banner to identify mail server software and version",
      "Enumerate valid usernames via VRFY, EXPN, or RCPT TO response differences",
      "Check whether the server permits open relay to external domains",
      "Enumerate supported authentication mechanisms",
    ],
    commonVulnerabilities: [
      "Username enumeration via VRFY/EXPN/RCPT TO",
      "Open relay configuration allowing unauthorized mail forwarding",
      "Outdated mail server software with known CVEs",
      "Weak or default authentication credentials",
    ],
    exploitation: [
      "Enumerate a candidate username list for use in later password spraying",
      "Confirm and document open relay behavior if present",
      "Exploit known CVEs for the specific mail server software and version",
    ],
    postExploitation: [
      "Feed enumerated usernames into a controlled, low-volume password spray against other services",
      "Review mail server configuration files for credentials if host access is later obtained",
    ],
    tools: ["smtp-user-enum", "nmap NSE (smtp-enum-users, smtp-open-relay)", "swaks"],
  },
  POP3: {
    port: 110,
    description: "Post Office Protocol mail retrieval service, commonly checked for credential reuse and weak authentication.",
    enumeration: [
      "Grab the POP3 banner to identify server software and version",
      "Check for support of the USER/PASS and APOP authentication mechanisms",
      "Check whether the service supports STLS/TLS for encrypted authentication",
    ],
    commonVulnerabilities: [
      "Cleartext authentication over an unencrypted channel",
      "Weak or reused credentials shared with other mail-related services",
      "Outdated POP3 daemon with known CVEs",
    ],
    exploitation: [
      "Attempt credential logins using usernames enumerated from SMTP or recon phases",
      "Test credentials recovered from breach data or leaked source code against the service",
    ],
    postExploitation: [
      "Review retrieved mailbox content for further credentials or sensitive information",
      "Check for credential reuse across other in-scope services",
    ],
    tools: ["hydra", "nmap NSE (pop3-brute)", "openssl s_client for STLS testing"],
  },
  IMAP: {
    port: 143,
    description: "Internet Message Access Protocol mail retrieval service, functionally similar to POP3 with more feature surface.",
    enumeration: [
      "Grab the IMAP banner and capability list",
      "Check for support of STARTTLS and enforce-encryption behavior",
      "Enumerate supported authentication mechanisms",
    ],
    commonVulnerabilities: [
      "Cleartext authentication over an unencrypted channel",
      "Weak or reused credentials shared with other mail-related services",
      "Outdated IMAP daemon with known CVEs",
    ],
    exploitation: [
      "Attempt credential logins using usernames enumerated from SMTP or recon phases",
      "Test recovered breach or leaked credentials against the service",
    ],
    postExploitation: [
      "Review mailbox content and folders for further credentials or sensitive information",
      "Check for credential reuse across other in-scope services",
    ],
    tools: ["hydra", "nmap NSE (imap-brute)", "openssl s_client for STARTTLS testing"],
  },
  DNS: {
    port: 53,
    description: "Domain Name System service, valuable both for reconnaissance and, when misconfigured, for full zone disclosure.",
    enumeration: [
      "Attempt a zone transfer (AXFR) against each authoritative nameserver",
      "Enumerate DNS record types across the domain (A, AAAA, MX, TXT, NS, SOA, SRV)",
      "Check for DNSSEC configuration and validation behavior",
      "Check for cache poisoning susceptibility if the server is a recursive resolver",
    ],
    commonVulnerabilities: [
      "Zone transfer allowed to arbitrary hosts, disclosing the full DNS zone",
      "Recursive resolution open to untrusted networks (amplification/poisoning risk)",
      "Outdated DNS server software with known CVEs",
      "Wildcard or stale records disclosing internal naming conventions",
    ],
    exploitation: [
      "Pull a full zone transfer where allowed to map the entire internal/external namespace",
      "Use disclosed internal hostnames to expand the scope of later scanning",
    ],
    postExploitation: [
      "Fold newly discovered subdomains and internal hostnames back into the Reconnaissance phase",
    ],
    tools: ["dig", "dnsrecon", "fierce", "nmap NSE (dns-zone-transfer)"],
  },
  LDAP: {
    port: 389,
    description: "Lightweight Directory Access Protocol used for directory services, most commonly Active Directory in Windows environments.",
    enumeration: [
      "Attempt an anonymous bind to enumerate directory structure and objects",
      "Enumerate users, groups, and organizational units if bind succeeds",
      "Enumerate password policy and account lockout settings from the directory",
      "Check for LDAP signing and channel binding enforcement",
    ],
    commonVulnerabilities: [
      "Anonymous bind enabled, disclosing directory contents without authentication",
      "LDAP signing not enforced, enabling relay attacks",
      "Weak or default service account credentials",
      "Overly permissive delegation or ACL configuration on directory objects",
    ],
    exploitation: [
      "Extract user and group information via anonymous or low-privilege bind",
      "Perform LDAP relay attacks when signing/channel binding is not enforced",
      "Use extracted directory data to inform Kerberoasting or AS-REP roasting attempts",
    ],
    postExploitation: [
      "Map Active Directory attack paths using extracted directory data",
      "Identify privileged group membership and delegation misconfigurations for escalation",
    ],
    tools: ["ldapsearch", "BloodHound", "PowerView", "nmap NSE (ldap-search)"],
  },
  RDP: {
    port: 3389,
    description: "Remote Desktop Protocol used for interactive Windows remote administration, a common initial-access and lateral-movement target.",
    enumeration: [
      "Grab the RDP security layer and supported protocol details",
      "Check for Network Level Authentication (NLA) enforcement",
      "Check the server's exposure to the internet versus internal-only reachability",
    ],
    commonVulnerabilities: [
      "Weak or default local administrator credentials",
      "NLA not enforced, widening the pre-authentication attack surface",
      "Outdated RDP implementation with known remote code execution CVEs (e.g. BlueKeep-class)",
      "Credential reuse across multiple hosts enabling lateral RDP access",
    ],
    exploitation: [
      "Attempt low-and-slow credential brute force respecting lockout thresholds",
      "Attempt authentication with credentials recovered from other services",
      "Exploit known pre-authentication RDP remote code execution CVEs where the target is confirmed unpatched",
    ],
    postExploitation: [
      "Use interactive access to harvest further credentials from the desktop session",
      "Review saved RDP connection files and credential manager entries for lateral movement targets",
    ],
    tools: ["xfreerdp", "rdesktop", "hydra", "nmap NSE (rdp-enum-encryption)", "Metasploit (rdp modules)"],
  },
  VNC: {
    port: 5900,
    description: "Virtual Network Computing remote desktop protocol, frequently deployed with weak or no authentication.",
    enumeration: [
      "Grab the VNC protocol version and supported security types",
      "Check whether authentication is required at all",
      "Enumerate the specific VNC server implementation for version-specific issues",
    ],
    commonVulnerabilities: [
      "No authentication required (unauthenticated remote desktop access)",
      "Weak or default VNC password",
      "Outdated VNC server implementation with known authentication bypass CVEs",
    ],
    exploitation: [
      "Connect without credentials where authentication is not enforced",
      "Attempt weak/default password logins",
      "Exploit known authentication bypass CVEs for the specific VNC implementation",
    ],
    postExploitation: [
      "Use interactive desktop access to harvest credentials and sensitive data",
      "Review the host for further pivot opportunities once desktop access is established",
    ],
    tools: ["vncviewer", "hydra", "nmap NSE (vnc-info, realvnc-auth-bypass)"],
  },
  Telnet: {
    port: 23,
    description: "Legacy cleartext remote administration protocol, still found on network devices, embedded systems, and legacy servers.",
    enumeration: [
      "Grab the Telnet login banner to fingerprint the device or OS",
      "Check whether authentication is required at all",
      "Identify the device type (network gear, IoT, legacy server) from banner and behavior",
    ],
    commonVulnerabilities: [
      "Cleartext transmission of credentials and session data",
      "Default or hardcoded vendor credentials, especially on network/IoT devices",
      "No authentication required on some embedded device configurations",
    ],
    exploitation: [
      "Attempt default vendor credential logins for the identified device type",
      "Attempt low-and-slow credential brute force respecting lockout thresholds",
      "Capture cleartext credentials via passive network monitoring where authorized",
    ],
    postExploitation: [
      "Use device access to review configuration for further embedded credentials",
      "Use recovered device credentials against other management interfaces on the network",
    ],
    tools: ["telnet client", "hydra", "nmap NSE (telnet-encryption)"],
  },
  NFS: {
    port: 2049,
    description: "Network File System used for Unix/Linux file sharing, frequently misconfigured to trust client-supplied UID/GID values.",
    enumeration: [
      "Enumerate exported shares via showmount or rpcinfo",
      "Check export permissions for each share (read-only vs. read-write)",
      "Check whether no_root_squash is set on any writable export",
    ],
    commonVulnerabilities: [
      "World-readable exports containing sensitive data",
      "no_root_squash enabled on writable exports, allowing root-equivalent file writes",
      "Overly permissive host-based access control on exports",
    ],
    exploitation: [
      "Mount readable exports and review contents for sensitive data or credentials",
      "On no_root_squash writable exports, write a SUID binary as root from an attacker-controlled UID for local privilege escalation on a host that mounts the same export",
      "Mount and modify shared configuration or authorized_keys files if writable",
    ],
    postExploitation: [
      "Use recovered files and credentials to pivot to hosts that mount the same NFS export",
      "Leverage the SUID escalation path on any host with local access to the export",
    ],
    tools: ["showmount", "mount.nfs", "rpcinfo", "nmap NSE (nfs-showmount, nfs-ls)"],
  },
  Kerberos: {
    port: 88,
    description: "Authentication protocol underpinning Active Directory, exploitable via ticket-based attacks when accounts are misconfigured.",
    enumeration: [
      "Enumerate valid usernames via AS-REQ pre-authentication response differences",
      "Identify accounts with Kerberos pre-authentication disabled",
      "Identify service accounts with registered Service Principal Names (SPNs)",
    ],
    commonVulnerabilities: [
      "Accounts with pre-authentication disabled, enabling AS-REP roasting",
      "Service accounts with weak passwords vulnerable to Kerberoasting",
      "Weak Kerberos encryption types still permitted (RC4)",
      "Golden/Silver ticket forgery risk if the krbtgt or service account hash is later compromised",
    ],
    exploitation: [
      "Perform AS-REP roasting against accounts with pre-authentication disabled and crack offline",
      "Perform Kerberoasting against SPN-registered accounts and crack the resulting TGS tickets offline",
      "Forge Silver/Golden tickets if the relevant service or krbtgt hash has been recovered during post-exploitation",
    ],
    postExploitation: [
      "Use cracked service account credentials for lateral movement or further privilege escalation",
      "Use forged tickets to maintain access within the scoped persistence-testing window only",
    ],
    tools: ["Rubeus", "Impacket (GetNPUsers.py, GetUserSPNs.py)", "kerbrute", "hashcat"],
  },
  WinRM: {
    port: 5985,
    description: "Windows Remote Management service enabling remote PowerShell administration, a common lateral-movement and initial-access path.",
    enumeration: [
      "Confirm WinRM is listening and identify HTTP vs. HTTPS listener configuration",
      "Check which authentication mechanisms are accepted (Negotiate, Kerberos, Basic)",
      "Test candidate credentials for WinRM access where authorized",
    ],
    commonVulnerabilities: [
      "Weak or reused local administrator credentials",
      "Basic authentication enabled over an unencrypted HTTP listener",
      "Overly broad group membership granting WinRM access to standard users",
    ],
    exploitation: [
      "Authenticate with credentials or hashes recovered from other phases",
      "Use pass-the-hash to authenticate to WinRM without a plaintext password where supported",
      "Establish a remote PowerShell session to execute commands on the target",
    ],
    postExploitation: [
      "Use the remote PowerShell session to harvest further credentials and enumerate the host",
      "Use WinRM access as a lateral movement path to additional domain-joined hosts",
    ],
    tools: ["evil-winrm", "CrackMapExec", "Impacket (wmiexec.py)", "PowerShell remoting"],
  },
};

// ---------------------------------------------------------------------------------------
// COMMON_ATTACK_PATHS — named, ordered attack chains
// ---------------------------------------------------------------------------------------

const COMMON_ATTACK_PATHS = [
  {
    id: "anonymous-ftp-to-shell",
    name: "Anonymous FTP to Shell",
    description: "Anonymous FTP write access on a host serving web content is abused to drop a web shell.",
    prerequisites: ["Anonymous FTP login enabled", "FTP write access to a web-served directory"],
    steps: [
      "Confirm anonymous FTP login succeeds",
      "Identify whether the FTP root overlaps with the web server document root",
      "Upload a minimal web shell to the shared directory",
      "Request the uploaded file via HTTP to confirm execution",
      "Use the resulting shell to enumerate the host for further escalation",
    ],
    expectedOutcome: "Remote code execution on the web/FTP host",
    difficulty: "easy",
    tags: ["ftp", "web", "misconfiguration", "initial-access"],
  },
  {
    id: "smb-null-session-to-domain-admin",
    name: "SMB Null Session to Domain Admin",
    description: "A null SMB session discloses usernames, which feed a password spray that lands a foothold, ultimately escalating via BloodHound-mapped paths to Domain Admin.",
    prerequisites: ["SMB null/guest session available on a domain-joined host", "Weak password policy or password reuse in the domain"],
    steps: [
      "Establish a null/guest SMB session and enumerate users via RID cycling",
      "Build a candidate username list from the enumerated accounts",
      "Perform a low-volume password spray respecting lockout policy",
      "Authenticate to a low-privilege domain account discovered by the spray",
      "Collect BloodHound data using the low-privilege account",
      "Identify a shortest path to Domain Admin from the compromised account",
      "Execute the identified escalation path (e.g. abusable ACL, unconstrained delegation)",
      "Confirm Domain Admin equivalent access",
    ],
    expectedOutcome: "Domain Admin (or equivalent) access to the Active Directory environment",
    difficulty: "hard",
    tags: ["smb", "active-directory", "password-spray", "bloodhound", "privilege-escalation"],
  },
  {
    id: "weak-snmp-to-full-compromise",
    name: "Weak SNMP Community String to Full Device Compromise",
    description: "A guessable SNMP community string discloses device configuration containing cleartext credentials reused elsewhere.",
    prerequisites: ["SNMP service reachable", "Default or guessable community string in use"],
    steps: [
      "Identify SNMP is open and attempt public/private community strings",
      "Walk the full MIB tree with a working community string",
      "Extract configuration data, including any embedded credentials",
      "Test extracted credentials against SSH, Telnet, and the device's web management interface",
      "Gain administrative access to the network device",
    ],
    expectedOutcome: "Administrative access to a network device and recovered credentials for further pivoting",
    difficulty: "easy",
    tags: ["snmp", "network-device", "credential-reuse"],
  },
  {
    id: "web-sqli-to-shell",
    name: "SQL Injection to OS Shell",
    description: "A SQL injection vulnerability in a web application is escalated from data extraction to full operating system command execution.",
    prerequisites: ["Confirmed SQL injection vulnerability", "Database account with FILE or equivalent privileges"],
    steps: [
      "Confirm and characterize the SQL injection point",
      "Extract database version, current user, and privilege level",
      "Use the injection to write a web shell to a web-accessible directory if FILE privileges allow",
      "Request the written web shell over HTTP to confirm code execution",
      "Use the resulting shell to enumerate and escalate on the host",
    ],
    expectedOutcome: "Remote code execution on the database/web host",
    difficulty: "medium",
    tags: ["web", "sql-injection", "rce"],
  },
  {
    id: "wordpress-plugin-rce",
    name: "WordPress Vulnerable Plugin to RCE",
    description: "An outdated WordPress plugin with a known unauthenticated file upload or RCE vulnerability is exploited for code execution.",
    prerequisites: ["WordPress site fingerprinted", "Outdated plugin/theme with a known CVE identified"],
    steps: [
      "Fingerprint the WordPress version and all installed plugins/themes",
      "Cross-reference plugin versions against known CVE databases",
      "Confirm the target plugin version matches a known vulnerable release",
      "Exploit the vulnerability using a vetted proof-of-concept",
      "Confirm code execution and establish a foothold",
    ],
    expectedOutcome: "Remote code execution on the WordPress hosting server",
    difficulty: "medium",
    tags: ["web", "cms", "wordpress", "rce"],
  },
  {
    id: "redis-unauth-to-rce",
    name: "Unauthenticated Redis to RCE",
    description: "An unauthenticated Redis instance is abused via CONFIG SET to write an SSH key or web shell, achieving remote code execution.",
    prerequisites: ["Redis reachable without authentication", "Writable filesystem path accessible to the Redis process"],
    steps: [
      "Connect to Redis without authentication and confirm write access",
      "Use CONFIG SET dir/dbfilename to target a writable path (e.g. .ssh or web root)",
      "Write a crafted authorized_keys entry or web shell payload as a Redis key",
      "Trigger a SAVE to write the payload to disk",
      "Access the written payload (SSH login or HTTP request) to confirm code execution",
    ],
    expectedOutcome: "Remote code execution on the Redis host",
    difficulty: "medium",
    tags: ["redis", "nosql", "misconfiguration", "rce"],
  },
  {
    id: "mongodb-noauth-dataexfil",
    name: "Unauthenticated MongoDB Data Exposure",
    description: "An unauthenticated MongoDB instance directly discloses collections containing sensitive or credential data.",
    prerequisites: ["MongoDB reachable without authentication"],
    steps: [
      "Connect to MongoDB without credentials",
      "List all databases and collections",
      "Sample representative documents to assess data sensitivity",
      "Search sampled data for credentials or PII to demonstrate impact",
    ],
    expectedOutcome: "Confirmed unauthorized access to sensitive application data",
    difficulty: "easy",
    tags: ["mongodb", "nosql", "misconfiguration", "data-exposure"],
  },
  {
    id: "vnc-noauth-to-access",
    name: "Unauthenticated VNC to Desktop Access",
    description: "A VNC server with no authentication enforced grants full interactive desktop access.",
    prerequisites: ["VNC service reachable", "No authentication or weak password configured"],
    steps: [
      "Confirm VNC does not require authentication or accepts a weak/default password",
      "Connect using a standard VNC client",
      "Confirm interactive desktop control",
      "Harvest visible credentials, documents, or session tokens",
    ],
    expectedOutcome: "Interactive desktop access to the target host",
    difficulty: "easy",
    tags: ["vnc", "misconfiguration", "initial-access"],
  },
  {
    id: "telnet-default-creds",
    name: "Telnet Default Credentials on Network Device",
    description: "A network or embedded device exposing Telnet with unchanged vendor default credentials is fully compromised.",
    prerequisites: ["Telnet reachable on a network/embedded device", "Default credentials not changed"],
    steps: [
      "Fingerprint the device type from the Telnet banner",
      "Look up the vendor's default credential set for that device family",
      "Attempt the default credentials",
      "Confirm administrative access to the device configuration",
    ],
    expectedOutcome: "Administrative access to the network/embedded device",
    difficulty: "easy",
    tags: ["telnet", "iot", "network-device", "default-credentials"],
  },
  {
    id: "rdp-unpatched-rce",
    name: "Unpatched RDP Pre-Auth RCE",
    description: "An RDP service confirmed unpatched against a known pre-authentication remote code execution CVE is exploited for a direct foothold.",
    prerequisites: ["RDP reachable", "Confirmed unpatched against a known pre-auth RCE CVE"],
    steps: [
      "Fingerprint the RDP security layer and version indicators",
      "Confirm the patch level is consistent with the target CVE",
      "Test the exploit in a lab replica if available before running against the live target",
      "Execute the vetted exploit against the target",
      "Confirm code execution and establish a foothold",
    ],
    expectedOutcome: "Remote code execution on the RDP host",
    difficulty: "hard",
    tags: ["rdp", "windows", "rce", "unpatched"],
  },
  {
    id: "kerberoasting-to-da",
    name: "Kerberoasting to Domain Admin",
    description: "SPN-registered service accounts are Kerberoasted, a weak service account password is cracked offline, and BloodHound reveals a path from that account to Domain Admin.",
    prerequisites: ["Valid low-privilege domain credentials or a foothold with domain user context", "At least one SPN-registered account with a crackable password"],
    steps: [
      "Enumerate SPN-registered accounts from the domain",
      "Request TGS tickets for each SPN-registered account",
      "Crack the recovered ticket hashes offline",
      "Authenticate as the cracked service account",
      "Collect BloodHound data and identify the shortest path to Domain Admin",
      "Execute the identified escalation path",
    ],
    expectedOutcome: "Domain Admin (or equivalent) access",
    difficulty: "hard",
    tags: ["kerberos", "active-directory", "credential-cracking", "privilege-escalation"],
  },
  {
    id: "asreproast-to-shell",
    name: "AS-REP Roasting to Initial Shell",
    description: "Accounts with Kerberos pre-authentication disabled are AS-REP roasted and a weak resulting hash is cracked to gain valid domain credentials.",
    prerequisites: ["At least one domain account with pre-authentication disabled"],
    steps: [
      "Enumerate domain usernames from recon/enumeration phases",
      "Request AS-REP responses for accounts with pre-authentication disabled",
      "Crack the recovered hashes offline",
      "Authenticate to a domain-joined host or service using the cracked credentials",
    ],
    expectedOutcome: "Valid domain user credentials and an initial foothold",
    difficulty: "medium",
    tags: ["kerberos", "active-directory", "credential-cracking", "initial-access"],
  },
  {
    id: "ldap-anonymous-bind-recon",
    name: "LDAP Anonymous Bind Reconnaissance",
    description: "An anonymous LDAP bind discloses the full directory structure, informing later targeted attacks.",
    prerequisites: ["LDAP anonymous bind enabled"],
    steps: [
      "Attempt an anonymous LDAP bind",
      "Enumerate users, groups, and organizational units",
      "Enumerate password policy and privileged group membership",
      "Feed extracted usernames into password spraying or Kerberos-based attacks",
    ],
    expectedOutcome: "Full directory enumeration usable to plan further attacks",
    difficulty: "easy",
    tags: ["ldap", "active-directory", "enumeration"],
  },
  {
    id: "nfs-noroot-squash-privesc",
    name: "NFS no_root_squash Privilege Escalation",
    description: "A writable NFS export with no_root_squash is used to plant a SUID root binary, then executed locally on a host that mounts the same export.",
    prerequisites: ["Writable NFS export with no_root_squash", "Local access (or ability to mount) on a host sharing the export"],
    steps: [
      "Mount the writable NFS export from an attacker-controlled machine",
      "Create a SUID root binary while impersonating UID 0 on the attacker machine",
      "Unmount and instead access the same export from the target host",
      "Execute the planted SUID binary on the target host to gain a root shell",
    ],
    expectedOutcome: "Local root privilege escalation on a host sharing the NFS export",
    difficulty: "medium",
    tags: ["nfs", "linux", "privilege-escalation", "misconfiguration"],
  },
  {
    id: "winrm-creds-to-shell",
    name: "Recovered Credentials to WinRM Shell",
    description: "Credentials or hashes recovered elsewhere in the engagement are used to open a remote PowerShell session over WinRM.",
    prerequisites: ["WinRM reachable on a Windows host", "Valid credentials or NTLM hash for a WinRM-permitted account"],
    steps: [
      "Confirm WinRM is listening on the target host",
      "Test recovered credentials or hashes against the WinRM service",
      "Establish a remote PowerShell session on success",
      "Use the session to enumerate the host and harvest further credentials",
    ],
    expectedOutcome: "Interactive remote command execution on the target host",
    difficulty: "medium",
    tags: ["winrm", "windows", "lateral-movement", "pass-the-hash"],
  },
  {
    id: "mssql-xpcmdshell",
    name: "MSSQL xp_cmdshell to Windows Foothold",
    description: "Default or weak MSSQL sa credentials are used to enable xp_cmdshell and execute operating system commands.",
    prerequisites: ["MSSQL reachable", "sa or sysadmin-equivalent credentials available"],
    steps: [
      "Authenticate to MSSQL with recovered or default sa credentials",
      "Enable xp_cmdshell if not already enabled",
      "Execute a command to confirm OS-level code execution",
      "Establish a reverse shell or persistent foothold via xp_cmdshell",
    ],
    expectedOutcome: "OS-level code execution on the SQL Server host",
    difficulty: "medium",
    tags: ["mssql", "windows", "rce", "default-credentials"],
  },
  {
    id: "postgresql-copy-program-rce",
    name: "PostgreSQL COPY PROGRAM RCE",
    description: "A superuser-privileged PostgreSQL connection abuses COPY ... FROM PROGRAM to execute arbitrary operating system commands.",
    prerequisites: ["PostgreSQL reachable", "Superuser-equivalent credentials available"],
    steps: [
      "Authenticate to PostgreSQL with superuser-equivalent credentials",
      "Execute a COPY ... FROM PROGRAM statement to run an OS command",
      "Confirm command output is returned via the query result",
      "Escalate to an interactive shell via the command execution primitive",
    ],
    expectedOutcome: "OS-level code execution on the PostgreSQL host",
    difficulty: "medium",
    tags: ["postgresql", "rce", "misconfiguration"],
  },
  {
    id: "mysql-udf-privesc",
    name: "MySQL UDF Privilege Escalation to RCE",
    description: "FILE privilege and a writable plugin directory are combined to load a malicious user-defined function achieving OS command execution.",
    prerequisites: ["MySQL reachable", "Credentials with FILE privilege", "Writable plugin directory"],
    steps: [
      "Authenticate to MySQL with FILE-privileged credentials",
      "Write a malicious UDF shared library to the plugin directory",
      "Register the UDF function within MySQL",
      "Invoke the UDF function to execute an OS command",
    ],
    expectedOutcome: "OS-level code execution on the MySQL host",
    difficulty: "hard",
    tags: ["mysql", "rce", "privilege-escalation"],
  },
  {
    id: "smtp-user-enum-phish",
    name: "SMTP User Enumeration to Targeted Phishing List",
    description: "SMTP VRFY/RCPT TO behavior discloses valid usernames, producing a precise target list for an authorized phishing simulation.",
    prerequisites: ["SMTP service reachable and disclosing user validity"],
    steps: [
      "Enumerate candidate usernames from recon-phase employee data",
      "Test each candidate against the SMTP server's VRFY/RCPT TO behavior",
      "Compile the confirmed valid address list",
      "Hand the confirmed list to the authorized phishing simulation workstream",
    ],
    expectedOutcome: "A validated target list for a scoped phishing simulation",
    difficulty: "easy",
    tags: ["smtp", "enumeration", "social-engineering"],
  },
  {
    id: "pop3-imap-credential-reuse",
    name: "Credential Reuse Against POP3/IMAP",
    description: "Credentials recovered from breach data or another in-scope service are tested against mail retrieval services to confirm reuse.",
    prerequisites: ["POP3 or IMAP reachable", "Candidate credential list from recon or other services"],
    steps: [
      "Compile a candidate credential list from recon findings and other compromised services",
      "Test the candidate list against POP3/IMAP respecting lockout thresholds",
      "Confirm successful logins and note the affected accounts",
      "Review retrieved mail for further sensitive information",
    ],
    expectedOutcome: "Confirmed mailbox access via credential reuse",
    difficulty: "easy",
    tags: ["pop3", "imap", "credential-reuse"],
  },
  {
    id: "dns-zonetransfer-recon",
    name: "DNS Zone Transfer Reconnaissance Expansion",
    description: "A misconfigured nameserver permits a full zone transfer, dramatically expanding the known attack surface.",
    prerequisites: ["A nameserver misconfigured to allow AXFR to arbitrary hosts"],
    steps: [
      "Identify all authoritative nameservers for the target domain",
      "Attempt an AXFR zone transfer against each nameserver",
      "Parse the returned zone file for internal hostnames and IP addresses",
      "Fold newly discovered hosts back into the scanning phase",
    ],
    expectedOutcome: "Significantly expanded target inventory",
    difficulty: "easy",
    tags: ["dns", "reconnaissance", "misconfiguration"],
  },
  {
    id: "ssh-weak-creds-bruteforce",
    name: "SSH Weak Credential Brute Force",
    description: "A slow, lockout-aware credential brute force against SSH succeeds due to weak password policy.",
    prerequisites: ["SSH password authentication enabled", "Weak password policy or known-weak account"],
    steps: [
      "Enumerate valid usernames from recon or other service enumeration",
      "Build a small, targeted password candidate list",
      "Run a low-and-slow brute force respecting the observed lockout threshold",
      "Authenticate on success and confirm the access level obtained",
    ],
    expectedOutcome: "Valid SSH shell access to the target host",
    difficulty: "medium",
    tags: ["ssh", "credential-attack", "initial-access"],
  },
  {
    id: "ssh-key-reuse-lateral",
    name: "SSH Private Key Reuse for Lateral Movement",
    description: "A private SSH key recovered from a compromised host or leaked repository is reused to authenticate to additional hosts.",
    prerequisites: ["A private SSH key recovered during recon or post-exploitation", "The key is unencrypted or its passphrase is known"],
    steps: [
      "Recover the private key from a leaked repository, backup, or compromised host",
      "Identify likely additional hosts trusting the same key (config files, known_hosts, naming conventions)",
      "Attempt authentication to each candidate host using the recovered key",
      "Confirm successful lateral movement and document the trust relationship",
    ],
    expectedOutcome: "Lateral movement to additional hosts trusting the recovered key",
    difficulty: "medium",
    tags: ["ssh", "lateral-movement", "credential-reuse"],
  },
  {
    id: "http-file-upload-webshell",
    name: "Insecure File Upload to Web Shell",
    description: "A web application file upload feature with insufficient validation is abused to plant an executable web shell.",
    prerequisites: ["A file upload feature reachable", "Insufficient file type/content validation"],
    steps: [
      "Identify a file upload feature and determine accepted file types",
      "Test bypass techniques for extension and content-type validation",
      "Upload a minimal web shell payload",
      "Determine the uploaded file's accessible URL",
      "Request the web shell to confirm code execution",
    ],
    expectedOutcome: "Remote code execution on the web application host",
    difficulty: "medium",
    tags: ["web", "file-upload", "rce"],
  },
  {
    id: "https-heartbleed-memdump",
    name: "TLS Heartbeat Memory Disclosure",
    description: "A TLS service using an outdated OpenSSL build vulnerable to the historical Heartbleed-class memory disclosure bug leaks process memory.",
    prerequisites: ["TLS service confirmed to use a vulnerable OpenSSL build"],
    steps: [
      "Confirm the OpenSSL version in use via banner/handshake fingerprinting",
      "Confirm vulnerability using a non-destructive detection technique",
      "Perform a small number of controlled memory reads to confirm impact",
      "Analyze recovered memory fragments for credentials or private key material",
    ],
    expectedOutcome: "Confirmed sensitive memory disclosure, potentially including credentials or private keys",
    difficulty: "medium",
    tags: ["tls", "openssl", "memory-disclosure"],
  },
  {
    id: "java-deserialization-rce",
    name: "Java Insecure Deserialization to RCE",
    description: "A Java application accepting untrusted serialized objects is exploited via a known gadget chain to achieve remote code execution.",
    prerequisites: ["A Java application endpoint accepting serialized object input", "A usable gadget chain present on the classpath"],
    steps: [
      "Identify an endpoint accepting serialized Java objects",
      "Fingerprint libraries present on the classpath to select a candidate gadget chain",
      "Generate a malicious serialized payload using a matching gadget chain tool",
      "Submit the payload to the vulnerable endpoint",
      "Confirm remote code execution via an out-of-band callback or direct response",
    ],
    expectedOutcome: "Remote code execution on the Java application host",
    difficulty: "hard",
    tags: ["java", "deserialization", "rce"],
  },
  {
    id: "log4shell-rce",
    name: "Log4Shell-Class JNDI Injection to RCE",
    description: "Untrusted input reaching a vulnerable logging library's message-lookup feature triggers a JNDI lookup, resulting in remote code execution.",
    prerequisites: ["Application uses a logging library vulnerable to JNDI lookup injection", "Outbound network access from the application host"],
    steps: [
      "Identify input fields that are likely to be logged (headers, usernames, search terms)",
      "Submit a JNDI lookup payload in a candidate input field",
      "Monitor an attacker-controlled listener for the resulting callback",
      "Confirm the vulnerable library version and escalate to full RCE via a malicious LDAP/RMI response",
    ],
    expectedOutcome: "Remote code execution on the affected application host",
    difficulty: "hard",
    tags: ["java", "log4j", "jndi", "rce"],
  },
  {
    id: "printnightmare-privesc",
    name: "Windows Print Spooler Privilege Escalation",
    description: "A vulnerable Windows Print Spooler service is abused to escalate a low-privilege local or domain foothold to SYSTEM.",
    prerequisites: ["Initial foothold on a Windows host", "Print Spooler service running and unpatched against the relevant CVE"],
    steps: [
      "Confirm the Print Spooler service is running and unpatched",
      "Prepare a malicious driver package for local privilege escalation",
      "Trigger the vulnerable spooler API to load the malicious driver",
      "Confirm SYSTEM-level code execution",
    ],
    expectedOutcome: "Local privilege escalation to SYSTEM on the target host",
    difficulty: "hard",
    tags: ["windows", "print-spooler", "privilege-escalation"],
  },
  {
    id: "zerologon-domain-compromise",
    name: "Netlogon Cryptographic Flaw to Domain Compromise",
    description: "A cryptographic flaw in the Netlogon protocol is exploited to reset the domain controller's computer account password and seize domain control.",
    prerequisites: ["Network access to a domain controller", "Domain controller unpatched against the relevant Netlogon CVE"],
    steps: [
      "Confirm the domain controller is unpatched against the relevant Netlogon CVE",
      "Establish a Netlogon secure channel using the cryptographic flaw",
      "Reset the domain controller's computer account password to a known value",
      "Use the reset computer account to dump domain credential material",
      "Restore the original password hash to avoid disrupting the production domain controller",
    ],
    expectedOutcome: "Full domain compromise via the domain controller's computer account",
    difficulty: "expert",
    tags: ["active-directory", "netlogon", "domain-compromise", "high-risk"],
  },
  {
    id: "golden-ticket-persistence",
    name: "Golden Ticket Forgery (Authorized Persistence Test)",
    description: "With the krbtgt account hash recovered during a scoped post-exploitation phase, forged Kerberos tickets grant domain-wide access for a persistence demonstration.",
    prerequisites: ["krbtgt account NTLM hash recovered", "Explicit client authorization for persistence testing"],
    steps: [
      "Confirm explicit client authorization for persistence testing before proceeding",
      "Recover the krbtgt account hash via an already-established Domain Admin-equivalent foothold",
      "Forge a Kerberos TGT using the recovered hash",
      "Use the forged ticket to authenticate to a target service as an arbitrary domain principal",
      "Document the forged-ticket detection window and rotate the krbtgt secret twice with the client post-engagement",
    ],
    expectedOutcome: "Demonstrated domain-wide persistence risk for client remediation planning",
    difficulty: "expert",
    tags: ["kerberos", "active-directory", "persistence", "high-risk"],
  },
  {
    id: "password-spray-o365",
    name: "Low-and-Slow Password Spray Against Cloud Identity",
    description: "A small set of common passwords is sprayed across a large enumerated username list against a cloud identity provider to avoid per-account lockout.",
    prerequisites: ["A validated employee username list", "Explicit authorization to test the cloud identity provider"],
    steps: [
      "Compile a validated username list from recon-phase OSINT",
      "Select a small set of common, policy-compliant candidate passwords",
      "Spray one password across the full username list, then wait out the lockout window before trying the next",
      "Confirm any successful authentication and note the account's assigned privileges",
    ],
    expectedOutcome: "One or more compromised cloud identity accounts",
    difficulty: "medium",
    tags: ["cloud", "identity", "password-spray"],
  },
  {
    id: "responder-llmnr-poisoning",
    name: "LLMNR/NBT-NS Poisoning to Credential Capture",
    description: "Broadcast name resolution protocols still enabled on the internal network are poisoned to capture and relay or crack NTLM authentication attempts.",
    prerequisites: ["Internal network access", "LLMNR/NBT-NS enabled on the network"],
    steps: [
      "Position on the internal network segment with visibility to broadcast traffic",
      "Start a poisoning listener for LLMNR, NBT-NS, and mDNS requests",
      "Capture NTLMv2 challenge/response hashes from responding hosts",
      "Crack captured hashes offline or relay them live to a target service where SMB signing is not enforced",
    ],
    expectedOutcome: "Captured or relayed domain credentials",
    difficulty: "medium",
    tags: ["active-directory", "network", "credential-capture"],
  },
  {
    id: "pass-the-hash-lateral",
    name: "Pass-the-Hash Lateral Movement",
    description: "An NTLM hash recovered from one compromised host is reused directly, without cracking, to authenticate to additional hosts sharing the same local administrator credentials.",
    prerequisites: ["An NTLM hash recovered from a compromised host", "Password reuse across hosts (common with unmanaged local administrator accounts)"],
    steps: [
      "Dump local credential material (SAM/LSA secrets) from the compromised host",
      "Identify candidate additional hosts likely to share the same local administrator credentials",
      "Authenticate to each candidate host using the recovered hash directly",
      "Confirm access and repeat the credential dump on each newly compromised host",
    ],
    expectedOutcome: "Lateral movement across multiple hosts sharing reused local credentials",
    difficulty: "medium",
    tags: ["windows", "lateral-movement", "pass-the-hash"],
  },
  {
    id: "unquoted-service-path-privesc",
    name: "Unquoted Service Path Privilege Escalation",
    description: "A Windows service configured with an unquoted binary path containing spaces is abused to plant an executable that Windows launches with the service's elevated privileges.",
    prerequisites: ["Local foothold on a Windows host", "A service running as SYSTEM with an unquoted, space-containing binary path", "Write access to a directory in the resolution chain"],
    steps: [
      "Enumerate services and their binary path configuration",
      "Identify a service with an unquoted path containing spaces and a writable directory earlier in the resolution order",
      "Place a malicious executable named to match the earlier path segment",
      "Restart the vulnerable service or wait for a scheduled restart",
      "Confirm the malicious executable runs with the service's elevated privileges",
    ],
    expectedOutcome: "Local privilege escalation to the service account's privilege level (often SYSTEM)",
    difficulty: "medium",
    tags: ["windows", "privilege-escalation", "misconfiguration"],
  },
  {
    id: "sudo-misconfig-privesc",
    name: "Sudo Misconfiguration Privilege Escalation",
    description: "An overly permissive sudoers entry allows a low-privilege Linux user to escalate to root via a binary known to enable command execution or file read/write as root.",
    prerequisites: ["Local foothold on a Linux host as a low-privilege user", "A sudoers entry granting passwordless or broad execution rights on an escalation-capable binary"],
    steps: [
      "Enumerate the current user's sudo privileges with sudo -l",
      "Cross-reference any permitted binaries against known privilege escalation techniques for that binary",
      "Execute the appropriate escalation technique for the permitted binary",
      "Confirm a root shell has been obtained",
    ],
    expectedOutcome: "Local privilege escalation to root on the target host",
    difficulty: "easy",
    tags: ["linux", "privilege-escalation", "misconfiguration"],
  },
];

// ---------------------------------------------------------------------------------------
// Lookup helpers
// ---------------------------------------------------------------------------------------

// Aliases so common alternate spellings resolve to the right playbook key.
const SERVICE_ALIASES = {
  ssh: "SSH",
  http: "HTTP/HTTPS",
  https: "HTTP/HTTPS",
  web: "HTTP/HTTPS",
  ftp: "FTP",
  smb: "SMB/CIFS",
  cifs: "SMB/CIFS",
  netbios: "SMB/CIFS",
  mysql: "MySQL",
  mariadb: "MySQL",
  postgres: "PostgreSQL",
  postgresql: "PostgreSQL",
  mssql: "MSSQL",
  "sql server": "MSSQL",
  redis: "Redis",
  mongo: "MongoDB",
  mongodb: "MongoDB",
  snmp: "SNMP",
  smtp: "SMTP",
  mail: "SMTP",
  pop3: "POP3",
  pop: "POP3",
  imap: "IMAP",
  dns: "DNS",
  ldap: "LDAP",
  "active directory": "LDAP",
  rdp: "RDP",
  "remote desktop": "RDP",
  vnc: "VNC",
  telnet: "Telnet",
  nfs: "NFS",
  kerberos: "Kerberos",
  krb5: "Kerberos",
  winrm: "WinRM",
  "windows remote management": "WinRM",
};

function findServicePlaybook(serviceName) {
  if (!serviceName) return null;
  const key = String(serviceName).trim();
  if (SERVICE_PLAYBOOKS[key]) return SERVICE_PLAYBOOKS[key];
  const aliased = SERVICE_ALIASES[key.toLowerCase()];
  if (aliased && SERVICE_PLAYBOOKS[aliased]) return SERVICE_PLAYBOOKS[aliased];
  // Loose case-insensitive match against playbook keys as a last resort.
  const lower = key.toLowerCase();
  for (const k of Object.keys(SERVICE_PLAYBOOKS)) {
    if (k.toLowerCase() === lower) return SERVICE_PLAYBOOKS[k];
  }
  return null;
}

function findPhase(name) {
  if (!name) return null;
  const lower = String(name).trim().toLowerCase();
  return METHODOLOGY_PHASES.find((p) => p.name.toLowerCase() === lower) || null;
}

// ---------------------------------------------------------------------------------------
// suggestNextStep — recommend the single next logical action from current findings
// ---------------------------------------------------------------------------------------

// findings shape (all fields optional, missing/empty treated as "not yet done"):
//   {
//     discoveredServices: [{ name, host, port, version }],
//     vulnerabilities: [{ name, service, severity, cve, confirmed }],
//     credentials: [{ username, password, service, verified }],
//     accessLevel: "none" | "user" | "service" | "admin" | "root" | "domain-admin",
//   }
function suggestNextStep(findings) {
  const f = findings || {};
  const services = Array.isArray(f.discoveredServices) ? f.discoveredServices : [];
  const vulnerabilities = Array.isArray(f.vulnerabilities) ? f.vulnerabilities : [];
  const credentials = Array.isArray(f.credentials) ? f.credentials : [];
  const accessLevel = f.accessLevel || "none";

  // Nothing discovered yet -> start at Reconnaissance/Scanning.
  if (services.length === 0) {
    return {
      recommendedAction:
        "No services have been discovered yet. Run host discovery and a full port scan against the in-scope range.",
      reasoning:
        "The engine has no service inventory to reason about. Every later phase (enumeration, vulnerability analysis, exploitation) depends on knowing what is alive and what is listening.",
      phase: "Scanning",
      tools: ["nmap", "masscan", "rustscan"],
      priority: "critical",
    };
  }

  // Services known, but nothing enumerated/analyzed yet for high-value ones.
  const confirmedVulns = vulnerabilities.filter((v) => v && v.confirmed);
  const candidateVulns = vulnerabilities.filter((v) => v && !v.confirmed);

  if (vulnerabilities.length === 0) {
    // Recommend enumeration/vuln-analysis for the first recognized service with a playbook.
    const target = services.find((s) => findServicePlaybook(s && s.name)) || services[0];
    const playbook = target ? findServicePlaybook(target.name) : null;
    return {
      recommendedAction: playbook
        ? `Enumerate the ${target.name} service on ${target.host || "the target"}${target.port ? ":" + target.port : ""} and check it against known vulnerabilities.`
        : "Enumerate each discovered service to establish exact versions before searching for vulnerabilities.",
      reasoning:
        "Services are known but no vulnerability candidates have been logged yet. Enumeration and version fingerprinting must happen before vulnerabilities can be matched or confirmed.",
      phase: "Enumeration",
      tools: playbook ? playbook.tools : ["nmap NSE", "nikto", "enum4linux-ng"],
      priority: "high",
    };
  }

  // Unconfirmed candidates exist -> verify them before attempting exploitation.
  if (candidateVulns.length > 0 && confirmedVulns.length === 0) {
    const top = candidateVulns[0];
    return {
      recommendedAction: `Manually verify the candidate vulnerability "${top.name || top.cve || "unnamed finding"}" before attempting exploitation.`,
      reasoning:
        "Automated scanners produce false positives. Confirming a finding manually avoids wasting an exploitation attempt (and engagement time) on a non-issue.",
      phase: "Vulnerability Analysis",
      tools: ["Burp Suite", "manual protocol client", "searchsploit"],
      priority: "medium",
    };
  }

  // Confirmed vulnerabilities exist but no access yet -> exploit the highest severity one.
  if (confirmedVulns.length > 0 && (accessLevel === "none" || !accessLevel)) {
    const bySeverity = { critical: 4, high: 3, medium: 2, low: 1 };
    const sorted = [...confirmedVulns].sort(
      (a, b) => (bySeverity[(b.severity || "").toLowerCase()] || 0) - (bySeverity[(a.severity || "").toLowerCase()] || 0)
    );
    const top = sorted[0];
    const playbook = findServicePlaybook(top.service);
    return {
      recommendedAction: `Attempt exploitation of the confirmed ${top.severity || ""} finding "${top.name || top.cve || "unnamed finding"}" on ${top.service || "the affected service"}.`,
      reasoning:
        "A confirmed vulnerability with no corresponding access is the highest-value next action: exploiting it converts a paper finding into a demonstrated foothold.",
      phase: "Exploitation",
      tools: playbook ? playbook.exploitation.slice(0, 4) : ["Metasploit Framework", "custom PoC exploit code"],
      priority: sorted[0] && (top.severity || "").toLowerCase() === "critical" ? "critical" : "high",
    };
  }

  // Credentials recovered but not yet leveraged for access.
  const unverifiedCreds = credentials.filter((c) => c && !c.verified);
  if (unverifiedCreds.length > 0 && (accessLevel === "none" || !accessLevel)) {
    const cred = unverifiedCreds[0];
    return {
      recommendedAction: `Test the recovered credential set (${cred.username || "unknown user"}) against ${cred.service || "any reachable authenticated service"}.`,
      reasoning:
        "Unverified credentials are low-risk, high-value next actions -- confirming them is far less disruptive than exploit-based access attempts and often yields a clean foothold.",
      phase: "Exploitation",
      tools: ["hydra", "CrackMapExec", "manual login"],
      priority: "high",
    };
  }

  // Have some access -> decide between privilege escalation and lateral movement.
  if (accessLevel === "user" || accessLevel === "service") {
    return {
      recommendedAction:
        "Enumerate local privilege escalation vectors on the compromised host before attempting lateral movement.",
      reasoning:
        "Current access is limited (user/service level). Escalating locally first typically yields more credential material and a stronger position for later lateral movement than moving laterally at low privilege.",
      phase: "Post-Exploitation",
      tools: ["LinPEAS/WinPEAS", "PowerView", "BloodHound"],
      priority: "high",
    };
  }

  if (accessLevel === "admin" || accessLevel === "root") {
    return {
      recommendedAction:
        "Harvest local credentials and assess lateral movement / domain escalation opportunities from this host.",
      reasoning:
        "Administrative access on a single host is valuable but usually not the engagement's end state. The next highest-value action is determining how far this access reaches across the environment.",
      phase: "Post-Exploitation",
      tools: ["Mimikatz (authorized engagements)", "Impacket suite", "BloodHound"],
      priority: "medium",
    };
  }

  if (accessLevel === "domain-admin") {
    return {
      recommendedAction:
        "Stop further escalation and begin documenting the full attack chain, evidence, and business impact for the report.",
      reasoning:
        "Domain Admin (or equivalent) access typically represents the practical ceiling of impact for an internal engagement. Continued escalation adds risk without adding meaningful proof of impact.",
      phase: "Reporting",
      tools: ["Dradis", "PlexTrac", "reporting templates"],
      priority: "medium",
    };
  }

  // Fallback -- nothing more specific matched.
  return {
    recommendedAction: "Review current findings with the team and decide whether to continue enumeration or begin reporting.",
    reasoning: "Findings do not clearly indicate a single next action; a manual checkpoint avoids wasted effort.",
    phase: "Vulnerability Analysis",
    tools: [],
    priority: "low",
  };
}

// ---------------------------------------------------------------------------------------
// generatePlan — build a full structured engagement plan for a target within a scope
// ---------------------------------------------------------------------------------------

// target shape:
//   { host: "10.0.0.5" | "example.com", knownServices: [{ name, port }] }
// scope shape:
//   { allowedPhases: [phaseName,...], excludedHosts: [host,...], timeLimitHours: number }
function generatePlan(target, scope) {
  const t = target || {};
  const s = scope || {};
  const hostLabel = t.host || t.hostname || t.ip || "unspecified-target";
  const knownServices = Array.isArray(t.knownServices) ? t.knownServices : [];
  const excludedHosts = Array.isArray(s.excludedHosts) ? s.excludedHosts : [];
  const timeLimitHours = typeof s.timeLimitHours === "number" && s.timeLimitHours > 0 ? s.timeLimitHours : null;

  if (excludedHosts.includes(hostLabel)) {
    return {
      target: hostLabel,
      error: `Target "${hostLabel}" is explicitly excluded from scope. No plan generated.`,
      phases: [],
      milestones: [],
      decisionPoints: [],
    };
  }

  // Resolve which phases are in play, preserving methodology order.
  const allowedPhaseNames = Array.isArray(s.allowedPhases) && s.allowedPhases.length > 0
    ? s.allowedPhases.map((n) => String(n).toLowerCase())
    : null; // null == all phases allowed
  const activePhases = METHODOLOGY_PHASES.filter((p) =>
    !allowedPhaseNames || allowedPhaseNames.includes(p.name.toLowerCase())
  );

  if (activePhases.length === 0) {
    return {
      target: hostLabel,
      error: "The requested scope excludes every methodology phase. No plan generated.",
      phases: [],
      milestones: [],
      decisionPoints: [],
    };
  }

  // Distribute the time budget proportionally to each active phase's step count, if a limit was given.
  const totalSteps = activePhases.reduce((sum, p) => sum + p.steps.length, 0);
  const planPhases = activePhases.map((p) => {
    const allocatedHours = timeLimitHours
      ? Math.max(0.5, Math.round((p.steps.length / totalSteps) * timeLimitHours * 10) / 10)
      : null;
    return {
      name: p.name,
      description: p.description,
      objectives: p.objectives,
      steps: p.steps,
      tools: p.tools,
      outputs: p.outputs,
      allocatedHours,
    };
  });

  // Attach known-service playbooks so the plan is target-specific, not just generic methodology.
  const servicePlan = knownServices.map((svc) => {
    const playbook = findServicePlaybook(svc && svc.name);
    return {
      service: svc && svc.name,
      port: (svc && svc.port) || (playbook && playbook.port) || null,
      playbookFound: !!playbook,
      enumeration: playbook ? playbook.enumeration : [],
      commonVulnerabilities: playbook ? playbook.commonVulnerabilities : [],
      exploitation: playbook ? playbook.exploitation : [],
      postExploitation: playbook ? playbook.postExploitation : [],
      tools: playbook ? playbook.tools : [],
    };
  });

  // Suggest relevant attack chains based on known services.
  const knownServiceNames = new Set(
    knownServices
      .map((svc) => {
        const playbook = findServicePlaybook(svc && svc.name);
        return playbook ? Object.keys(SERVICE_PLAYBOOKS).find((k) => SERVICE_PLAYBOOKS[k] === playbook) : null;
      })
      .filter(Boolean)
      .map((n) => n.toLowerCase())
  );
  const suggestedAttackPaths = COMMON_ATTACK_PATHS.filter((path) =>
    path.tags.some((tag) => {
      const t2 = tag.toLowerCase();
      return (
        knownServiceNames.has(t2) ||
        (knownServiceNames.has("smb/cifs") && t2 === "smb") ||
        (knownServiceNames.has("http/https") && (t2 === "web" || t2 === "http")) ||
        (knownServiceNames.has("ldap") && t2 === "active-directory") ||
        (knownServiceNames.has("kerberos") && t2 === "active-directory")
      );
    })
  );

  // Build milestones -- one checkpoint per phase, marking the deliverable that closes it out.
  const milestones = planPhases.map((p, idx) => ({
    order: idx + 1,
    phase: p.name,
    milestone: `${p.name} complete: ${p.outputs[p.outputs.length - 1] || "phase deliverables produced"}`,
    dependsOn: idx === 0 ? [] : [planPhases[idx - 1].name],
  }));

  // Decision points -- the moments where the plan branches based on findings, not a fixed script.
  const decisionPoints = [
    {
      after: "Scanning",
      question: "Which discovered services justify the deepest enumeration effort given the time budget?",
      guidance: "Prioritize services with known high-impact playbooks (SMB, HTTP/HTTPS, database services, Kerberos/LDAP) over low-value ones.",
    },
    {
      after: "Enumeration",
      question: "Do any enumerated services match a known COMMON_ATTACK_PATHS chain?",
      guidance: "Prefer executing a documented attack chain over ad-hoc exploitation -- it has a clearer prerequisite and evidence trail.",
    },
    {
      after: "Vulnerability Analysis",
      question: "Which confirmed vulnerabilities are safe to exploit within the agreed risk tolerance?",
      guidance: "Rule out anything with denial-of-service risk unless explicitly authorized; prefer credential-based and misconfiguration-based access first.",
    },
    {
      after: "Exploitation",
      question: "Has a foothold been established, and how deep is post-exploitation authorized to go?",
      guidance: "Re-confirm the authorized depth (privilege escalation only vs. full lateral movement / domain compromise) before proceeding.",
    },
    {
      after: "Post-Exploitation",
      question: "Has the realistic blast radius been demonstrated without unnecessary risk to production systems?",
      guidance: "Stop escalating once impact is clearly demonstrated; further access rarely changes the report's risk rating but does add risk.",
    },
  ].filter((dp) => planPhases.some((p) => p.name === dp.after));

  return {
    target: hostLabel,
    scope: {
      allowedPhases: activePhases.map((p) => p.name),
      excludedHosts,
      timeLimitHours,
    },
    generatedAt: new Date().toISOString(),
    phases: planPhases,
    servicePlan,
    suggestedAttackPaths: suggestedAttackPaths.map((p) => ({
      id: p.id,
      name: p.name,
      difficulty: p.difficulty,
      expectedOutcome: p.expectedOutcome,
    })),
    milestones,
    decisionPoints,
  };
}

module.exports = {
  METHODOLOGY_PHASES,
  SERVICE_PLAYBOOKS,
  COMMON_ATTACK_PATHS,
  suggestNextStep,
  generatePlan,
  findServicePlaybook,
  findPhase,
};
