"use strict";

// ---------------------------------------------------------------------------
// Learning resources, curriculum paths, certifications, CTF platforms, books,
// and training materials for the darknode CLI "learn" / "study" commands.
// ---------------------------------------------------------------------------

const LEARNING_PATHS = [
  // -----------------------------------------------------------------------
  // 1. Web Application Security
  // -----------------------------------------------------------------------
  {
    name: "Web Application Security",
    desc: "Master the art of finding and exploiting vulnerabilities in modern web applications, from classic injection flaws to advanced logic bugs.",
    difficulty: "intermediate",
    estimatedHours: 320,
    modules: [
      {
        name: "HTTP Fundamentals and Web Architecture",
        desc: "Understand the protocols and architectures that underpin every web application.",
        topics: [
          "HTTP/1.1 and HTTP/2 request/response lifecycle",
          "TLS handshake and certificate pinning",
          "REST vs GraphQL vs gRPC",
          "Content negotiation and MIME types",
          "Cookie attributes: Secure, HttpOnly, SameSite",
          "CORS preflight and simple requests",
          "WebSocket upgrade and frame format",
          "HTTP caching headers and poisoning surface"
        ],
        labs: [
          "Intercept and modify HTTP traffic with Burp proxy",
          "Craft raw requests with curl and netcat",
          "Analyze TLS certificates with openssl s_client",
          "Map an application with passive spidering"
        ],
        resources: [
          "MDN HTTP documentation",
          "RFC 7230-7235 (HTTP/1.1)",
          "PortSwigger Web Security Academy - HTTP basics"
        ]
      },
      {
        name: "SQL Injection",
        desc: "From simple UNION-based extraction to blind, time-based, and out-of-band techniques across database engines.",
        topics: [
          "UNION-based SQLi column enumeration",
          "Error-based extraction (MySQL, MSSQL, Oracle)",
          "Blind boolean-based inference",
          "Time-based blind with SLEEP / WAITFOR",
          "Second-order SQL injection",
          "SQLi in INSERT, UPDATE, DELETE statements",
          "WAF bypass with encoding and comments",
          "SQLMap tamper scripts and custom injection points"
        ],
        labs: [
          "Extract database schema via UNION injection",
          "Automate blind extraction with custom Python script",
          "Bypass ModSecurity CRS with comment-based obfuscation",
          "Escalate SQLi to OS command execution via xp_cmdshell"
        ],
        resources: [
          "PortSwigger SQL injection labs",
          "PentesterLab SQL injection exercises",
          "OWASP SQL Injection Prevention Cheat Sheet"
        ]
      },
      {
        name: "Cross-Site Scripting (XSS)",
        desc: "Reflected, stored, and DOM-based XSS with filter bypass and CSP evasion.",
        topics: [
          "Reflected XSS in URL parameters and headers",
          "Stored XSS in user profiles, comments, file uploads",
          "DOM-based XSS via document.location, innerHTML",
          "Mutation XSS (mXSS) with DOMPurify bypasses",
          "CSP bypass techniques: JSONP, base-uri, script gadgets",
          "Dangling markup injection",
          "XSS in JavaScript template literals",
          "Polyglot payloads for multi-context injection"
        ],
        labs: [
          "Steal admin cookies via stored XSS",
          "Bypass CSP using a JSONP endpoint",
          "Construct a DOM-clobbering attack chain",
          "Deliver XSS through SVG file upload"
        ],
        resources: [
          "PortSwigger XSS labs",
          "Cure53 mXSS research papers",
          "OWASP XSS Prevention Cheat Sheet"
        ]
      },
      {
        name: "Authentication and Session Management",
        desc: "Attack login flows, session tokens, OAuth, and multi-factor implementations.",
        topics: [
          "Credential stuffing and password spraying",
          "Session fixation and session hijacking",
          "JWT algorithm confusion and claim tampering",
          "OAuth 2.0 redirect_uri manipulation",
          "SAML assertion forgery",
          "MFA bypass: SIM swap, phishing, race conditions",
          "Account takeover via password reset flows",
          "Remember-me token weaknesses"
        ],
        labs: [
          "Forge a JWT with none algorithm",
          "Exploit OAuth redirect_uri to steal tokens",
          "Bypass MFA via response manipulation",
          "Chain password reset poisoning to account takeover"
        ],
        resources: [
          "PortSwigger Authentication labs",
          "Auth0 security best practices",
          "RFC 6749 (OAuth 2.0)"
        ]
      },
      {
        name: "Server-Side Request Forgery (SSRF)",
        desc: "Force the server to make requests to internal services, cloud metadata, and other attack surfaces.",
        topics: [
          "Basic SSRF to internal services",
          "SSRF to cloud metadata endpoints (169.254.169.254)",
          "Blind SSRF with out-of-band detection",
          "SSRF via URL parsers: gopher, dict, file protocols",
          "DNS rebinding attacks",
          "SSRF filter bypass with IP encoding and redirects",
          "SSRF in PDF generators and image processors",
          "Server-side cache poisoning via SSRF"
        ],
        labs: [
          "Access AWS metadata via SSRF in image fetch",
          "Bypass SSRF allowlist using DNS rebinding",
          "Chain SSRF to internal admin panel access",
          "Exploit blind SSRF with Collaborator-style detection"
        ],
        resources: [
          "PortSwigger SSRF labs",
          "Orange Tsai SSRF research",
          "OWASP SSRF Prevention Cheat Sheet"
        ]
      },
      {
        name: "XML External Entities (XXE)",
        desc: "Exploit XML parsers to read files, perform SSRF, and exfiltrate data.",
        topics: [
          "Classic XXE file read via ENTITY declaration",
          "Blind XXE with out-of-band exfiltration",
          "XXE via file upload (DOCX, XLSX, SVG)",
          "Parameter entity abuse for OOB data extraction",
          "XXE to SSRF escalation",
          "Error-based XXE data extraction",
          "XXE in SOAP and XML-RPC endpoints",
          "XInclude attacks when you cannot control DOCTYPE"
        ],
        labs: [
          "Read /etc/passwd via XXE in XML API",
          "Exfiltrate data via blind XXE with external DTD",
          "Exploit XXE in a file upload endpoint",
          "Use XInclude to read server files"
        ],
        resources: [
          "PortSwigger XXE labs",
          "OWASP XXE Prevention Cheat Sheet",
          "PayloadsAllTheThings XXE section"
        ]
      },
      {
        name: "Insecure Deserialization",
        desc: "Exploit object deserialization in Java, PHP, Python, and .NET.",
        topics: [
          "Java deserialization with ysoserial gadget chains",
          "PHP unserialize() object injection",
          "Python pickle RCE",
          ".NET BinaryFormatter and TypeNameHandling",
          "Ruby Marshal.load exploitation",
          "Identifying serialized data in cookies and parameters",
          "Gadget chain construction methodology",
          "Mitigation: allowlisting, integrity checks, alternatives"
        ],
        labs: [
          "Exploit Java deserialization in a web app cookie",
          "Gain RCE via PHP object injection",
          "Craft a Python pickle payload for reverse shell",
          "Identify and exploit .NET ViewState deserialization"
        ],
        resources: [
          "PortSwigger Deserialization labs",
          "ysoserial GitHub repository documentation",
          "Frohoff deserialization research papers"
        ]
      },
      {
        name: "Server-Side Template Injection (SSTI)",
        desc: "Inject code into server-side template engines for RCE.",
        topics: [
          "SSTI detection methodology and decision tree",
          "Jinja2 RCE via __subclasses__ chain",
          "Twig template injection payloads",
          "Freemarker and Velocity exploitation",
          "Pebble and Thymeleaf injection",
          "Mako template code execution",
          "Sandboxed template engine escapes",
          "SSTI in error pages and email templates"
        ],
        labs: [
          "Detect template engine via polyglot probes",
          "Achieve RCE through Jinja2 SSTI",
          "Exploit SSTI in a Twig-based CMS",
          "Bypass template sandbox restrictions"
        ],
        resources: [
          "PortSwigger SSTI labs",
          "James Kettle SSTI research",
          "PayloadsAllTheThings SSTI section"
        ]
      },
      {
        name: "API Security Testing",
        desc: "Test REST, GraphQL, and gRPC APIs for authorization, injection, and logic flaws.",
        topics: [
          "REST API endpoint enumeration and documentation",
          "Broken Object Level Authorization (BOLA / IDOR)",
          "Broken Function Level Authorization",
          "Mass assignment and parameter pollution",
          "GraphQL introspection and query depth attacks",
          "GraphQL batch query abuse",
          "Rate limiting bypass techniques",
          "API versioning and deprecated endpoint abuse"
        ],
        labs: [
          "Enumerate hidden API endpoints via wordlist",
          "Exploit IDOR to access other users data",
          "Perform GraphQL introspection and extract schema",
          "Bypass rate limiting with header manipulation"
        ],
        resources: [
          "OWASP API Security Top 10",
          "HackTheBox API-focused machines",
          "Postman API security testing guides"
        ]
      },
      {
        name: "Business Logic Vulnerabilities",
        desc: "Find flaws in application workflows that automated scanners miss.",
        topics: [
          "Price manipulation in e-commerce flows",
          "Race conditions in financial transactions",
          "Coupon and discount code abuse",
          "Privilege escalation via workflow manipulation",
          "File upload bypass via content-type mismatch",
          "Multi-step process skipping",
          "Insufficient workflow validation",
          "Time-of-check to time-of-use (TOCTOU) bugs"
        ],
        labs: [
          "Manipulate shopping cart totals via negative quantities",
          "Exploit race condition in money transfer",
          "Bypass file upload restrictions for web shell",
          "Skip payment verification in multi-step checkout"
        ],
        resources: [
          "PortSwigger Business Logic labs",
          "Bug bounty writeups on HackerOne",
          "OWASP Testing Guide - Business Logic"
        ]
      },
      {
        name: "Advanced Client-Side Attacks",
        desc: "Prototype pollution, web cache poisoning, request smuggling, and browser exploitation.",
        topics: [
          "HTTP request smuggling (CL.TE, TE.CL, TE.TE)",
          "Web cache poisoning via unkeyed headers",
          "Prototype pollution in JavaScript libraries",
          "Clickjacking and UI redress attacks",
          "WebSocket hijacking",
          "CORS misconfiguration exploitation",
          "Subdomain takeover via dangling DNS",
          "Browser-based side-channel attacks"
        ],
        labs: [
          "Perform CL.TE request smuggling attack",
          "Poison web cache with malicious header",
          "Exploit prototype pollution for XSS",
          "Take over a subdomain via unclaimed CNAME"
        ],
        resources: [
          "PortSwigger Request Smuggling labs",
          "James Kettle cache poisoning research",
          "Prototype Pollution research by Michail Shcherbakov"
        ]
      }
    ]
  },

  // -----------------------------------------------------------------------
  // 2. Network Penetration Testing
  // -----------------------------------------------------------------------
  {
    name: "Network Penetration Testing",
    desc: "Learn to assess network infrastructure from reconnaissance through exploitation, pivoting, and post-exploitation.",
    difficulty: "intermediate",
    estimatedHours: 280,
    modules: [
      {
        name: "Network Fundamentals for Pentesters",
        desc: "Understand the protocols and architectures you will encounter and exploit.",
        topics: [
          "TCP/IP stack and OSI model from an attacker perspective",
          "ARP, DHCP, and DNS internals",
          "VLAN hopping and trunk negotiation",
          "IPv6 fundamentals and attack surface",
          "Routing protocols: OSPF, BGP, EIGRP",
          "Network segmentation and firewall architecture",
          "VPN technologies: IPSec, SSL, WireGuard",
          "802.1X and NAC bypass techniques"
        ],
        labs: [
          "Capture and analyze ARP traffic with Wireshark",
          "Perform VLAN hopping with DTP manipulation",
          "Map network topology using traceroute and TTL analysis",
          "Identify IPv6 hosts on a dual-stack network"
        ],
        resources: [
          "TCP/IP Illustrated by W. Richard Stevens",
          "CompTIA Network+ study materials",
          "Practical Networking YouTube channel"
        ]
      },
      {
        name: "Passive Reconnaissance",
        desc: "Gather intelligence without directly touching the target.",
        topics: [
          "DNS enumeration: zone transfers, subdomain brute force",
          "OSINT with Shodan, Censys, and ZoomEye",
          "Google dorking for sensitive files",
          "LinkedIn and social media profiling",
          "Certificate transparency log mining",
          "Wayback Machine for historical data",
          "ASN and BGP route analysis",
          "Leaked credential databases and breach data"
        ],
        labs: [
          "Enumerate subdomains using multiple techniques",
          "Find exposed services with Shodan queries",
          "Discover hidden endpoints via Wayback Machine",
          "Map an organization ASN and IP ranges"
        ],
        resources: [
          "OSINT Framework (osintframework.com)",
          "theHarvester documentation",
          "Recon-ng wiki and modules"
        ]
      },
      {
        name: "Active Scanning and Enumeration",
        desc: "Discover hosts, ports, services, and vulnerabilities on the target network.",
        topics: [
          "Host discovery: ARP, ICMP, TCP SYN, UDP probes",
          "Port scanning strategies: SYN, connect, FIN, XMAS",
          "Service version detection and OS fingerprinting",
          "NSE script scanning and custom scripts",
          "SMB enumeration: shares, users, null sessions",
          "SNMP community string brute forcing",
          "LDAP anonymous bind enumeration",
          "NFS share discovery and mounting"
        ],
        labs: [
          "Perform comprehensive Nmap scan of a /24 network",
          "Enumerate SMB shares and extract user list",
          "Discover SNMP community strings and extract MIB data",
          "Map all services with version detection"
        ],
        resources: [
          "Nmap Network Scanning (official book)",
          "Nmap NSE script documentation",
          "Enum4linux and smbclient man pages"
        ]
      },
      {
        name: "Vulnerability Assessment",
        desc: "Identify and prioritize vulnerabilities in network services.",
        topics: [
          "Nessus scan configuration and policy tuning",
          "OpenVAS setup and custom scan profiles",
          "Manual verification of scanner findings",
          "CVE research and exploit availability",
          "Vulnerability prioritization with CVSS scoring",
          "False positive identification and elimination",
          "Compliance scanning: PCI DSS, CIS benchmarks",
          "Reporting vulnerability findings effectively"
        ],
        labs: [
          "Configure and run a credentialed Nessus scan",
          "Verify top findings manually with Nmap scripts",
          "Research CVEs and find public exploits",
          "Generate a prioritized vulnerability report"
        ],
        resources: [
          "Nessus documentation and plugin reference",
          "NIST National Vulnerability Database",
          "ExploitDB and Searchsploit"
        ]
      },
      {
        name: "Network Exploitation",
        desc: "Exploit vulnerabilities in network services to gain access.",
        topics: [
          "Metasploit framework workflow and module types",
          "Exploit selection and payload configuration",
          "Password attacks: brute force, spraying, credential stuffing",
          "Man-in-the-middle with ARP spoofing and Responder",
          "LLMNR/NBT-NS poisoning for credential capture",
          "Relay attacks: SMB, LDAP, HTTP",
          "Exploiting unpatched services (EternalBlue, etc.)",
          "Custom exploit development basics"
        ],
        labs: [
          "Capture NTLMv2 hashes with Responder",
          "Relay captured credentials with ntlmrelayx",
          "Exploit a vulnerable service with Metasploit",
          "Crack captured hashes with Hashcat"
        ],
        resources: [
          "Metasploit Unleashed (Offensive Security)",
          "Impacket documentation and examples",
          "Responder and ntlmrelayx guides"
        ]
      },
      {
        name: "Post-Exploitation on Linux",
        desc: "Escalate privileges, maintain access, and extract data from Linux hosts.",
        topics: [
          "Linux enumeration: users, processes, network, cron",
          "SUID/SGID binary exploitation",
          "Kernel exploit identification and compilation",
          "Capability-based privilege escalation",
          "Cron job hijacking and path injection",
          "Sudo misconfiguration exploitation",
          "Docker group and LXD privilege escalation",
          "Data exfiltration and credential harvesting"
        ],
        labs: [
          "Run LinPEAS and analyze output",
          "Escalate via SUID binary on GTFOBins",
          "Exploit a writable cron script for root",
          "Escape a Docker container to host"
        ],
        resources: [
          "GTFOBins reference",
          "LinPEAS and LinEnum documentation",
          "HackTricks Linux privilege escalation"
        ]
      },
      {
        name: "Post-Exploitation on Windows",
        desc: "Privilege escalation, credential extraction, and persistence on Windows.",
        topics: [
          "Windows enumeration: users, services, patches, tasks",
          "Unquoted service path exploitation",
          "DLL hijacking and search order abuse",
          "Token impersonation with Potato exploits",
          "AlwaysInstallElevated MSI exploitation",
          "Registry autorun key persistence",
          "SAM and LSASS credential dumping",
          "Mimikatz usage and Kerberos ticket extraction"
        ],
        labs: [
          "Run WinPEAS and identify escalation vectors",
          "Exploit an unquoted service path",
          "Dump credentials with Mimikatz",
          "Establish persistence via scheduled task"
        ],
        resources: [
          "PayloadsAllTheThings Windows privesc",
          "WinPEAS documentation",
          "HackTricks Windows privilege escalation"
        ]
      },
      {
        name: "Pivoting and Tunneling",
        desc: "Extend your reach through compromised hosts to access internal networks.",
        topics: [
          "SSH local, remote, and dynamic port forwarding",
          "Chisel TCP tunneling through HTTP",
          "Ligolo-ng for double-pivot scenarios",
          "sshuttle transparent proxy",
          "Proxychains configuration and usage",
          "Metasploit autoroute and socks proxy",
          "DNS tunneling with dnscat2",
          "ICMP tunneling with ptunnel"
        ],
        labs: [
          "Set up SSH dynamic port forwarding as SOCKS proxy",
          "Tunnel through a compromised host with Chisel",
          "Use Proxychains to scan an internal subnet",
          "Pivot through two network segments"
        ],
        resources: [
          "SSH tunneling visual guide",
          "Chisel GitHub documentation",
          "Ligolo-ng usage guide"
        ]
      },
      {
        name: "Active Directory Attacks",
        desc: "Enumerate, attack, and dominate Windows Active Directory environments.",
        topics: [
          "AD enumeration with BloodHound and SharpHound",
          "Kerberoasting and AS-REP roasting",
          "Pass-the-Hash and Pass-the-Ticket",
          "Silver Ticket and Golden Ticket attacks",
          "Constrained and unconstrained delegation abuse",
          "Group Policy Preferences credential extraction",
          "DCSync attack for domain credential dump",
          "Trust relationship abuse across forests"
        ],
        labs: [
          "Map AD attack paths with BloodHound",
          "Kerberoast a service account and crack the hash",
          "Perform Pass-the-Hash with Impacket",
          "Execute DCSync to dump domain hashes"
        ],
        resources: [
          "Active Directory Security blog (adsecurity.org)",
          "BloodHound documentation",
          "ired.team Active Directory attack notes"
        ]
      },
      {
        name: "Wireless Network Attacks",
        desc: "Assess and exploit wireless networks and protocols.",
        topics: [
          "Monitor mode and packet capture with airmon-ng",
          "WPA/WPA2 handshake capture and cracking",
          "WPS PIN brute force with Reaver",
          "Evil Twin and Karma attacks",
          "PMKID capture for clientless cracking",
          "Deauthentication attacks and jamming",
          "WPA3 SAE and Dragonblood vulnerabilities",
          "Bluetooth and BLE attack surface"
        ],
        labs: [
          "Capture WPA2 handshake and crack with aircrack-ng",
          "Set up an Evil Twin access point",
          "Perform PMKID attack with hcxdumptool",
          "Scan for vulnerable WPS-enabled access points"
        ],
        resources: [
          "Aircrack-ng documentation wiki",
          "WiFi Pineapple field guide",
          "Wireless Penetration Testing courses"
        ]
      },
      {
        name: "Reporting and Documentation",
        desc: "Write professional penetration test reports that communicate risk to stakeholders.",
        topics: [
          "Executive summary writing for non-technical audiences",
          "Finding documentation: evidence, impact, remediation",
          "CVSS scoring methodology and justification",
          "Risk rating frameworks and prioritization",
          "Screenshot and proof-of-concept best practices",
          "Report templates and consistent formatting",
          "Remediation verification and retesting",
          "Compliance mapping: PCI, HIPAA, SOC 2"
        ],
        labs: [
          "Document a finding with full evidence chain",
          "Write an executive summary for a simulated engagement",
          "Create a remediation priority matrix",
          "Build a reusable report template"
        ],
        resources: [
          "PTES reporting guidelines",
          "Offensive Security report writing guide",
          "TCM Security report examples"
        ]
      }
    ]
  },

  // -----------------------------------------------------------------------
  // 3. Red Team Operations
  // -----------------------------------------------------------------------
  {
    name: "Red Team Operations",
    desc: "Simulate advanced persistent threats to test organizational detection and response capabilities.",
    difficulty: "advanced",
    estimatedHours: 400,
    modules: [
      {
        name: "Red Team Planning and Scoping",
        desc: "Plan adversary simulation engagements with clear objectives and rules of engagement.",
        topics: [
          "Red team vs penetration test vs vulnerability assessment",
          "Threat modeling with MITRE ATT&CK framework",
          "Rules of engagement and legal considerations",
          "Objective-based engagement planning",
          "Communication plans and deconfliction",
          "Purple team integration and feedback loops",
          "Risk management during operations",
          "Reporting adversary simulation results"
        ],
        labs: [
          "Develop a red team engagement plan",
          "Map attack scenarios to MITRE ATT&CK techniques",
          "Create rules of engagement documentation",
          "Build a communication and deconfliction plan"
        ],
        resources: [
          "MITRE ATT&CK framework documentation",
          "Red Team Development and Operations (Joe Vest)",
          "CBEST Intelligence-Led Testing framework"
        ]
      },
      {
        name: "OPSEC and Infrastructure Setup",
        desc: "Build resilient, covert attack infrastructure for red team operations.",
        topics: [
          "Redirector setup with Apache mod_rewrite",
          "Domain fronting and CDN abuse",
          "Categorized domains for phishing campaigns",
          "SMTP infrastructure for email delivery",
          "SSL/TLS certificate configuration",
          "Cloud-based infrastructure provisioning with Terraform",
          "Log scrubbing and forensic awareness",
          "Operational security principles and tradecraft"
        ],
        labs: [
          "Deploy a redirector with domain categorization",
          "Set up a phishing infrastructure with GoPhish",
          "Configure HTTPS listeners with valid certificates",
          "Build disposable cloud infrastructure with Terraform"
        ],
        resources: [
          "Red Team Infrastructure Wiki",
          "Cobalt Strike documentation (infrastructure)",
          "Steve Borosh infrastructure blog posts"
        ]
      },
      {
        name: "Initial Access Techniques",
        desc: "Gain a foothold through phishing, drive-by attacks, and supply chain compromise.",
        topics: [
          "Spear phishing with weaponized documents",
          "HTML smuggling for payload delivery",
          "Macro-enabled document creation and obfuscation",
          "ISO, LNK, and OneNote payload vectors",
          "Watering hole attacks",
          "Supply chain compromise scenarios",
          "Physical access: USB drops, badge cloning",
          "Credential harvesting with Evilginx2 and Modlishka"
        ],
        labs: [
          "Create a phishing email with HTML smuggled payload",
          "Build an ISO-based payload for macro block bypass",
          "Set up credential harvesting with Evilginx2",
          "Deliver a payload via LNK file"
        ],
        resources: [
          "MITRE ATT&CK Initial Access tactics",
          "Outflank blog on payload delivery",
          "Evilginx2 documentation"
        ]
      },
      {
        name: "Command and Control (C2)",
        desc: "Deploy and operate C2 frameworks for persistent, covert communications.",
        topics: [
          "Cobalt Strike Beacon configuration and malleable C2",
          "Sliver C2 framework setup and implant generation",
          "Havoc framework deployment",
          "Mythic C2 agents and profiles",
          "C2 over DNS, HTTP, HTTPS, and SMB",
          "Peer-to-peer (P2P) C2 channels",
          "Traffic shaping and jitter configuration",
          "C2 channel redundancy and failover"
        ],
        labs: [
          "Deploy Sliver C2 and generate an implant",
          "Configure Mythic with a custom C2 profile",
          "Set up DNS-based C2 communication channel",
          "Implement C2 with domain fronting"
        ],
        resources: [
          "Sliver C2 documentation",
          "Mythic C2 documentation",
          "Cobalt Strike user guide"
        ]
      },
      {
        name: "Defense Evasion",
        desc: "Bypass endpoint protection, AMSI, ETW, and network monitoring.",
        topics: [
          "AMSI bypass techniques and patching",
          "ETW tracing evasion",
          "Windows Defender exclusion abuse",
          "PE packing and crypter usage",
          "Shellcode loaders: syscalls, callback functions",
          "Process injection: classic, APC, hollow, Doppelganging",
          "Memory-only execution and fileless malware",
          "Timestomping and indicator removal"
        ],
        labs: [
          "Bypass AMSI in PowerShell session",
          "Build a custom shellcode loader with direct syscalls",
          "Perform process hollowing to evade EDR",
          "Create a fileless execution chain"
        ],
        resources: [
          "Red Team Notes on evasion",
          "Sektor7 Malware Development courses",
          "elastic/protections-artifacts on GitHub"
        ]
      },
      {
        name: "Credential Access and Theft",
        desc: "Extract credentials from memory, files, and Active Directory.",
        topics: [
          "LSASS memory dumping techniques",
          "SAM database extraction: reg save, Volume Shadow Copy",
          "DPAPI master key and credential decryption",
          "Kerberos ticket extraction and manipulation",
          "Credential vault and browser password theft",
          "Keylogging and screen capture",
          "Cloud credential harvesting from metadata and config files",
          "Certificate-based authentication abuse"
        ],
        labs: [
          "Dump LSASS with a custom MiniDump tool",
          "Extract DPAPI-protected credentials",
          "Harvest Kerberos tickets for lateral movement",
          "Recover browser saved passwords"
        ],
        resources: [
          "Mimikatz documentation and wiki",
          "Benjamin Delpy credential research",
          "Gentilkiwi blog posts"
        ]
      },
      {
        name: "Lateral Movement",
        desc: "Move through the network while maintaining operational security.",
        topics: [
          "PsExec and SMBExec for remote execution",
          "WMI and WinRM-based lateral movement",
          "DCOM-based remote code execution",
          "RDP hijacking and session theft",
          "SSH key reuse and agent forwarding abuse",
          "Pass-the-Hash, Pass-the-Ticket, Overpass-the-Hash",
          "Lateral movement via scheduled tasks and services",
          "Living-off-the-land binaries (LOLBins)"
        ],
        labs: [
          "Move laterally using WMI and WinRM",
          "Perform Overpass-the-Hash with Rubeus",
          "Hijack an existing RDP session",
          "Execute commands via DCOM objects"
        ],
        resources: [
          "LOLBAS project reference",
          "Impacket lateral movement tools",
          "ired.team lateral movement notes"
        ]
      },
      {
        name: "Persistence Mechanisms",
        desc: "Maintain long-term access through reboots, password changes, and remediation.",
        topics: [
          "Registry run key and startup folder persistence",
          "Scheduled task and service creation",
          "DLL search order hijacking for persistence",
          "COM object hijacking",
          "WMI event subscription persistence",
          "Golden and Diamond ticket persistence",
          "Skeleton key and AdminSDHolder abuse",
          "Linux persistence: cron, systemd, bashrc, SSH keys"
        ],
        labs: [
          "Establish persistence via WMI event subscription",
          "Create a Golden Ticket for domain persistence",
          "Set up COM object hijacking",
          "Deploy persistence across multiple hosts"
        ],
        resources: [
          "MITRE ATT&CK Persistence techniques",
          "Persistence mechanisms reference sheet",
          "Mandiant persistence research"
        ]
      },
      {
        name: "Data Exfiltration",
        desc: "Identify, stage, and exfiltrate sensitive data without triggering alerts.",
        topics: [
          "Data discovery and classification",
          "Data staging and compression",
          "Exfiltration over C2 channel",
          "Exfiltration over DNS queries",
          "Exfiltration over HTTPS to cloud storage",
          "Steganography for covert data transfer",
          "Encrypted archive creation and transfer",
          "DLP evasion and protocol tunneling"
        ],
        labs: [
          "Exfiltrate data via DNS tunneling",
          "Stage and compress sensitive data for transfer",
          "Use steganography to hide data in image files",
          "Transfer data through an encrypted HTTPS tunnel"
        ],
        resources: [
          "MITRE ATT&CK Exfiltration techniques",
          "dnscat2 documentation",
          "Data exfiltration research papers"
        ]
      },
      {
        name: "Active Directory Domination",
        desc: "Complete Active Directory attack chains from initial foothold to full domain compromise.",
        topics: [
          "AD Certificate Services (ADCS) abuse: ESC1-ESC8",
          "Shadow Credentials and Key Trust abuse",
          "Resource-based constrained delegation (RBCD)",
          "NTLMv1 downgrade attacks",
          "Group Policy Object (GPO) abuse",
          "AdminSDHolder and SDProp exploitation",
          "Domain trust enumeration and cross-forest attacks",
          "Azure AD and hybrid identity attacks"
        ],
        labs: [
          "Exploit ADCS ESC1 for domain admin",
          "Abuse RBCD for privilege escalation",
          "Perform a cross-forest trust attack",
          "Exploit Shadow Credentials for account takeover"
        ],
        resources: [
          "SpecterOps ADCS whitepaper",
          "Harmj0y AD security blog",
          "Active Directory exploitation cheat sheets"
        ]
      },
      {
        name: "Adversary Simulation and Reporting",
        desc: "Execute full adversary simulation campaigns and deliver actionable reports.",
        topics: [
          "Campaign execution and milestone tracking",
          "Detection gap analysis methodology",
          "Purple team exercise facilitation",
          "Adversary simulation report structure",
          "MITRE ATT&CK technique mapping in reports",
          "Remediation and hardening recommendations",
          "Metrics: dwell time, detection rate, MTTD, MTTR",
          "Lessons learned and improvement roadmaps"
        ],
        labs: [
          "Execute a full red team campaign scenario",
          "Map all techniques to MITRE ATT&CK",
          "Conduct a purple team exercise with defenders",
          "Produce a comprehensive adversary simulation report"
        ],
        resources: [
          "MITRE ATT&CK Evaluations methodology",
          "TIBER-EU framework documentation",
          "Red Team Development and Operations book"
        ]
      }
    ]
  },

  // -----------------------------------------------------------------------
  // 4. Cloud Security
  // -----------------------------------------------------------------------
  {
    name: "Cloud Security",
    desc: "Assess and exploit cloud environments across AWS, Azure, and GCP, including containers and serverless.",
    difficulty: "advanced",
    estimatedHours: 350,
    modules: [
      {
        name: "Cloud Fundamentals for Security",
        desc: "Understand cloud service models, shared responsibility, and common architectures.",
        topics: [
          "IaaS, PaaS, SaaS security boundaries",
          "Shared responsibility model across providers",
          "Cloud identity and access management concepts",
          "Virtual networking: VPCs, subnets, security groups",
          "Cloud storage types and access controls",
          "Serverless and container-based architectures",
          "Cloud logging and monitoring foundations",
          "Multi-cloud and hybrid cloud considerations"
        ],
        labs: [
          "Map the shared responsibility model for each service type",
          "Review a cloud architecture diagram for security gaps",
          "Configure VPC security groups and NACLs",
          "Set up basic CloudTrail or equivalent logging"
        ],
        resources: [
          "AWS Well-Architected Framework Security Pillar",
          "Azure Security Benchmark documentation",
          "GCP Security Best Practices guide"
        ]
      },
      {
        name: "AWS Security Assessment",
        desc: "Enumerate, attack, and secure Amazon Web Services environments.",
        topics: [
          "AWS IAM enumeration: users, roles, policies",
          "S3 bucket misconfiguration and public access",
          "EC2 instance metadata service (IMDS) v1 and v2",
          "Lambda function code extraction and injection",
          "STS assume-role abuse and privilege escalation",
          "Secrets Manager and Parameter Store extraction",
          "CloudTrail log analysis and evasion",
          "AWS Organizations and cross-account attacks"
        ],
        labs: [
          "Enumerate IAM permissions with enumerate-iam",
          "Discover and exploit public S3 buckets",
          "Escalate privileges through IAM policy misconfiguration",
          "Extract secrets from Lambda environment variables"
        ],
        resources: [
          "Rhino Security Labs AWS research",
          "CloudGoat vulnerable AWS deployment",
          "Pacu AWS exploitation framework docs"
        ]
      },
      {
        name: "Azure Security Assessment",
        desc: "Attack and defend Microsoft Azure cloud environments.",
        topics: [
          "Azure AD enumeration and user profiling",
          "Azure RBAC vs Azure AD roles",
          "Managed identity abuse for lateral movement",
          "Azure Blob storage misconfiguration",
          "Azure Function and Logic App exploitation",
          "Azure Key Vault access and secret extraction",
          "Azure DevOps pipeline poisoning",
          "Conditional Access Policy bypass techniques"
        ],
        labs: [
          "Enumerate Azure AD with ROADtools",
          "Exploit a managed identity for privilege escalation",
          "Access misconfigured Azure Blob containers",
          "Extract secrets from Azure Key Vault"
        ],
        resources: [
          "Microsoft Azure security documentation",
          "ROADtools and AADInternals documentation",
          "XMGoat vulnerable Azure deployment"
        ]
      },
      {
        name: "GCP Security Assessment",
        desc: "Assess Google Cloud Platform for security weaknesses.",
        topics: [
          "GCP IAM policy enumeration and analysis",
          "Service account key discovery and abuse",
          "GCS bucket enumeration and permission flaws",
          "Compute Engine metadata server access",
          "Cloud Functions source code extraction",
          "BigQuery data access and exfiltration",
          "GCP project enumeration and lateral movement",
          "Workspace (G Suite) integration attacks"
        ],
        labs: [
          "Enumerate GCP projects and service accounts",
          "Exploit metadata server for service account tokens",
          "Discover publicly accessible GCS buckets",
          "Escalate privileges through service account impersonation"
        ],
        resources: [
          "GCP security best practices documentation",
          "Rhino Security GCP research",
          "ThunderCTF GCP security challenges"
        ]
      },
      {
        name: "Container Security",
        desc: "Assess Docker and container runtime security posture.",
        topics: [
          "Docker image analysis and layer inspection",
          "Container escape via privileged mode",
          "Docker socket exposure and abuse",
          "Container capabilities and seccomp profiles",
          "Image supply chain attacks and trojanized base images",
          "Container registry enumeration and unauthorized pulls",
          "Runtime security monitoring with Falco",
          "Rootless and unprivileged container hardening"
        ],
        labs: [
          "Escape a privileged Docker container",
          "Exploit an exposed Docker socket for host access",
          "Analyze Docker image layers for embedded secrets",
          "Scan container images with Trivy and Grype"
        ],
        resources: [
          "Docker security documentation",
          "CIS Docker Benchmark",
          "Container Security by Liz Rice"
        ]
      },
      {
        name: "Kubernetes Security",
        desc: "Attack and defend Kubernetes clusters from all angles.",
        topics: [
          "Kubernetes API server enumeration and authentication",
          "RBAC misconfiguration and privilege escalation",
          "Pod escape to node via hostPID, hostNetwork, hostPath",
          "Service account token abuse",
          "Secrets enumeration and decoding",
          "Kubelet API unauthenticated access",
          "etcd data extraction",
          "Admission controller bypass and mutating webhooks"
        ],
        labs: [
          "Enumerate Kubernetes resources with kubectl",
          "Exploit a misconfigured RBAC role for cluster admin",
          "Escape a pod to the underlying node",
          "Extract secrets from etcd directly"
        ],
        resources: [
          "Kubernetes security documentation",
          "CIS Kubernetes Benchmark",
          "Kubernetes Goat vulnerable cluster"
        ]
      },
      {
        name: "Serverless Security",
        desc: "Assess serverless functions and event-driven architectures.",
        topics: [
          "Lambda/Functions/Cloud Functions code review",
          "Event injection via S3, SNS, SQS triggers",
          "Environment variable and secret exposure",
          "Cold start and timeout abuse",
          "Serverless application model (SAM) analysis",
          "API Gateway misconfiguration",
          "Step Functions and workflow manipulation",
          "Serverless framework deployment review"
        ],
        labs: [
          "Extract environment variables from a Lambda function",
          "Inject malicious events through an S3 trigger",
          "Exploit an API Gateway misconfiguration",
          "Review serverless application code for vulnerabilities"
        ],
        resources: [
          "OWASP Serverless Top 10",
          "ServerlessGoat vulnerable application",
          "SANS serverless security whitepaper"
        ]
      },
      {
        name: "Infrastructure as Code Security",
        desc: "Find security issues in Terraform, CloudFormation, and other IaC templates.",
        topics: [
          "Terraform state file analysis and secret extraction",
          "CloudFormation template security review",
          "Pulumi and CDK security considerations",
          "Hardcoded credentials in IaC templates",
          "Overly permissive IAM policies in IaC",
          "Network security group misconfigurations",
          "Encryption at rest and in transit settings",
          "Automated IaC scanning with Checkov and tfsec"
        ],
        labs: [
          "Scan Terraform files with Checkov",
          "Find secrets in Terraform state files",
          "Review CloudFormation for security misconfigurations",
          "Implement policy-as-code with OPA"
        ],
        resources: [
          "Checkov documentation",
          "tfsec documentation",
          "HashiCorp Terraform security best practices"
        ]
      },
      {
        name: "Cloud Forensics and Incident Response",
        desc: "Investigate security incidents in cloud environments.",
        topics: [
          "CloudTrail log analysis and event correlation",
          "VPC Flow Log examination",
          "Cloud instance forensic acquisition",
          "Azure Activity Log and Diagnostic Log analysis",
          "GCP Audit Log investigation",
          "Container runtime event analysis",
          "Automated incident response with Lambda/Functions",
          "Evidence preservation in cloud environments"
        ],
        labs: [
          "Analyze CloudTrail logs for unauthorized API calls",
          "Correlate VPC Flow Logs with security events",
          "Acquire a forensic image of a cloud instance",
          "Set up automated response to security events"
        ],
        resources: [
          "AWS Incident Response documentation",
          "SANS Cloud Forensics poster",
          "Cloud forensics tools comparison"
        ]
      },
      {
        name: "Cloud Penetration Testing Methodology",
        desc: "Apply a structured methodology to cloud-focused engagements.",
        topics: [
          "Cloud-specific rules of engagement",
          "Provider penetration testing policies",
          "External vs internal cloud assessments",
          "Multi-cloud assessment planning",
          "Cloud-native tools for assessment",
          "Credential and secret management testing",
          "Data exposure and privacy compliance",
          "Cloud security posture management (CSPM) review"
        ],
        labs: [
          "Plan a cloud penetration test engagement",
          "Execute a full AWS assessment workflow",
          "Test cross-service privilege escalation paths",
          "Produce a cloud security assessment report"
        ],
        resources: [
          "PTES cloud testing supplement",
          "HackerOne cloud bounty scope examples",
          "Cloud Pentesting by Nick Raienko"
        ]
      }
    ]
  },

  // -----------------------------------------------------------------------
  // 5. Reverse Engineering and Malware Analysis
  // -----------------------------------------------------------------------
  {
    name: "Reverse Engineering and Malware Analysis",
    desc: "Analyze malicious software and reverse engineer binaries to understand their behavior and purpose.",
    difficulty: "expert",
    estimatedHours: 450,
    modules: [
      {
        name: "x86 and x64 Assembly Fundamentals",
        desc: "Understand the assembly language underpinning all binary analysis.",
        topics: [
          "Registers, flags, and addressing modes",
          "Stack operations: push, pop, call, ret",
          "Common instruction patterns and idioms",
          "Function calling conventions: cdecl, stdcall, fastcall",
          "Control flow: jmp, conditional jumps, loops",
          "Data structures in assembly: arrays, structs, vtables",
          "System calls and interrupts",
          "ARM assembly basics for mobile analysis"
        ],
        labs: [
          "Write simple programs in x86 assembly",
          "Identify function prologues and epilogues in disassembly",
          "Reverse a compiled C program to pseudo-code",
          "Analyze a crackme binary to find the key"
        ],
        resources: [
          "Intel Software Developer Manuals",
          "Programming from the Ground Up (free book)",
          "x86 Assembly wikibook"
        ]
      },
      {
        name: "Static Analysis with Disassemblers",
        desc: "Use IDA Pro, Ghidra, and Binary Ninja for static binary analysis.",
        topics: [
          "Ghidra project setup and navigation",
          "IDA Pro interface and hotkeys",
          "Binary Ninja intermediate language (IL)",
          "Function identification and naming conventions",
          "Cross-reference analysis (xrefs)",
          "Data type reconstruction and struct creation",
          "Decompiler usage and output refinement",
          "Scripting: IDAPython, Ghidra Script, BinaryNinja API"
        ],
        labs: [
          "Load and analyze a binary in Ghidra",
          "Use cross-references to trace data flow",
          "Reconstruct structures from decompiler output",
          "Write a Ghidra script to automate string decryption"
        ],
        resources: [
          "Ghidra documentation and tutorials",
          "The IDA Pro Book by Chris Eagle",
          "Reverse Engineering for Beginners by Dennis Yurichev"
        ]
      },
      {
        name: "Dynamic Analysis and Debugging",
        desc: "Run and debug binaries to observe runtime behavior.",
        topics: [
          "x64dbg/OllyDbg for Windows debugging",
          "GDB and GDB-PEDA/GEF for Linux debugging",
          "WinDbg for kernel-mode debugging",
          "Breakpoint types: software, hardware, conditional",
          "Memory inspection and watchpoints",
          "API monitoring with API Monitor and strace/ltrace",
          "System call tracing and interception",
          "Anti-debug detection and bypass techniques"
        ],
        labs: [
          "Debug a crackme with x64dbg to patch validation",
          "Use GDB to trace program execution flow",
          "Monitor API calls of a suspicious binary",
          "Bypass anti-debug checks in a protected binary"
        ],
        resources: [
          "x64dbg documentation",
          "GDB quick reference and cheat sheets",
          "Practical Binary Analysis by Dennis Andriesse"
        ]
      },
      {
        name: "PE and ELF Binary Format Analysis",
        desc: "Understand executable file formats for deeper analysis.",
        topics: [
          "PE format: DOS header, PE header, sections, imports",
          "ELF format: header, sections, segments, symbols",
          "Import Address Table (IAT) and Export Address Table",
          "Section characteristics and anomalies",
          "Relocation and position-independent code",
          "Resource section analysis (PE)",
          "Debug information and symbol files",
          "Malformed headers and parser differential attacks"
        ],
        labs: [
          "Parse PE headers manually with a hex editor",
          "Analyze ELF sections and segments with readelf",
          "Identify suspicious imports and exports",
          "Detect packed binaries from section characteristics"
        ],
        resources: [
          "PE Format specification (Microsoft docs)",
          "ELF specification (man elf)",
          "Corkami PE and ELF reference posters"
        ]
      },
      {
        name: "Malware Behavior Analysis",
        desc: "Observe malware behavior in controlled environments.",
        topics: [
          "Sandbox setup: FlareVM, REMnux, ANY.RUN",
          "Network traffic capture and analysis during execution",
          "File system activity monitoring with ProcMon",
          "Registry modification tracking",
          "Process creation chains and injection detection",
          "DNS and HTTP request analysis from samples",
          "Automated sandbox report interpretation",
          "Indicators of Compromise (IOC) extraction"
        ],
        labs: [
          "Set up a malware analysis VM with FlareVM",
          "Execute malware in a sandbox and capture behavior",
          "Extract network IOCs from packet capture",
          "Generate a behavioral analysis report"
        ],
        resources: [
          "Practical Malware Analysis (Sikorski & Honig)",
          "FlareVM installation guide",
          "REMnux documentation and tool list"
        ]
      },
      {
        name: "Unpacking and Deobfuscation",
        desc: "Defeat packers, crypters, and obfuscation to reveal original code.",
        topics: [
          "Common packers: UPX, Themida, VMProtect, ASPack",
          "Manual unpacking methodology: OEP finding",
          "Entropy analysis for packed binary detection",
          "Import reconstruction after unpacking",
          "String deobfuscation: XOR, RC4, base64, custom",
          "Control flow flattening deobfuscation",
          "JavaScript and VBScript deobfuscation",
          "PowerShell obfuscation layers and decoding"
        ],
        labs: [
          "Unpack a UPX-packed binary manually",
          "Find the Original Entry Point of a custom packer",
          "Deobfuscate XOR-encrypted strings in malware",
          "Decode multi-layered PowerShell obfuscation"
        ],
        resources: [
          "UPX documentation",
          "Unpacking tutorials on OALabs YouTube",
          "de4dot .NET deobfuscator documentation"
        ]
      },
      {
        name: "Shellcode Analysis",
        desc: "Analyze and understand shellcode payloads.",
        topics: [
          "Shellcode identification in documents and exploits",
          "Position-independent code analysis",
          "API hashing and resolution techniques",
          "Shellcode emulation with scdbg and unicorn",
          "Egg hunters and staged shellcode",
          "Encoder/decoder stubs: shikata_ga_nai, etc.",
          "Shellcode extraction from exploit payloads",
          "Custom shellcode writing and testing"
        ],
        labs: [
          "Extract shellcode from a malicious document",
          "Emulate shellcode with scdbg to identify behavior",
          "Decode an encoded shellcode payload",
          "Analyze staged shellcode communication"
        ],
        resources: [
          "Shellcoding for Linux and Windows tutorial",
          "scdbg documentation",
          "Project Shellcode archives"
        ]
      },
      {
        name: "Windows Internals for Reversing",
        desc: "Understand Windows internals essential for malware analysis.",
        topics: [
          "Windows process and thread management",
          "Virtual memory layout and page protections",
          "Windows API categories: kernel32, ntdll, advapi32",
          "Registry hives and common malware keys",
          "Windows service architecture and SCM",
          "Driver loading and kernel-mode concepts",
          "COM and DCOM object model",
          "Windows event logging architecture"
        ],
        labs: [
          "Explore process memory layout with Process Explorer",
          "Trace Windows API calls with API Monitor",
          "Analyze malware persistence via registry keys",
          "Examine a malicious Windows service"
        ],
        resources: [
          "Windows Internals by Russinovich and Solomon",
          "Windows System Programming by Johnson Hart",
          "MSDN Windows API documentation"
        ]
      },
      {
        name: "Network Protocol Reverse Engineering",
        desc: "Reverse engineer custom and proprietary network protocols used by malware.",
        topics: [
          "C2 protocol identification and decryption",
          "Custom binary protocol structure analysis",
          "HTTP-based C2 traffic pattern recognition",
          "DNS tunneling protocol reverse engineering",
          "TLS certificate analysis and pinning bypass",
          "Protocol replay and manipulation",
          "Network signature development (Snort/Suricata)",
          "Domain generation algorithm (DGA) analysis"
        ],
        labs: [
          "Reverse engineer a custom C2 protocol from PCAP",
          "Decrypt malware HTTPS traffic with extracted keys",
          "Analyze a DNS tunneling communication channel",
          "Develop detection signatures for malware traffic"
        ],
        resources: [
          "Wireshark display filter reference",
          "Network Forensics by Sherri Davidoff",
          "Suricata rule writing documentation"
        ]
      },
      {
        name: "Threat Intelligence and Reporting",
        desc: "Transform analysis findings into actionable threat intelligence.",
        topics: [
          "STIX/TAXII structured threat data",
          "YARA rule writing for malware detection",
          "Sigma rules for log-based detection",
          "Malware family classification and naming",
          "Campaign tracking and actor attribution",
          "IOC management and sharing platforms",
          "Technical malware analysis report writing",
          "Diamond Model and Kill Chain mapping"
        ],
        labs: [
          "Write YARA rules to detect a malware family",
          "Create Sigma rules for behavioral detection",
          "Build a STIX bundle for a threat campaign",
          "Produce a comprehensive malware analysis report"
        ],
        resources: [
          "YARA documentation and rule writing guide",
          "MISP threat sharing platform docs",
          "MITRE ATT&CK for threat intelligence"
        ]
      }
    ]
  }
];

// ---------------------------------------------------------------------------
// Certifications
// ---------------------------------------------------------------------------

const CERTIFICATIONS = [
  {
    name: "OSCP",
    fullName: "Offensive Security Certified Professional",
    provider: "Offensive Security (OffSec)",
    difficulty: "intermediate",
    cost: "$1,749 - $5,499 (with lab access)",
    duration: "90 days lab access + 24-hour exam",
    desc: "The gold standard for hands-on penetration testing. A 24-hour practical exam requiring exploitation of multiple machines and a professional report.",
    topics: [
      "Information gathering and enumeration",
      "Vulnerability analysis",
      "Web application attacks",
      "Buffer overflow exploitation",
      "Client-side attacks",
      "Active Directory attacks",
      "Privilege escalation (Linux and Windows)",
      "Port forwarding and tunneling"
    ],
    prerequisites: [
      "Strong networking fundamentals",
      "Linux and Windows command-line proficiency",
      "Basic scripting ability (Python, Bash)"
    ],
    url: "https://www.offsec.com/courses/pen-200/"
  },
  {
    name: "OSEP",
    fullName: "Offensive Security Experienced Penetration Tester",
    provider: "Offensive Security (OffSec)",
    difficulty: "advanced",
    cost: "$1,749 - $5,499",
    duration: "90 days lab access + 48-hour exam",
    desc: "Advanced penetration testing focusing on evasion, custom exploit development, and Active Directory attacks in hardened environments.",
    topics: [
      "Advanced client-side attacks",
      "Process injection and migration",
      "Antivirus and EDR evasion",
      "Advanced Active Directory attacks",
      "Custom exploit development",
      "Lateral movement in hardened networks",
      "AMSI and AppLocker bypass",
      "Advanced phishing campaigns"
    ],
    prerequisites: [
      "OSCP or equivalent experience",
      "Strong Active Directory knowledge",
      "C# or C++ programming ability"
    ],
    url: "https://www.offsec.com/courses/pen-300/"
  },
  {
    name: "OSED",
    fullName: "Offensive Security Exploit Developer",
    provider: "Offensive Security (OffSec)",
    difficulty: "expert",
    cost: "$1,749 - $5,499",
    duration: "90 days lab access + 48-hour exam",
    desc: "Windows user-mode exploit development covering reverse engineering, custom shellcode, and modern exploit mitigations bypass.",
    topics: [
      "x86 and x64 assembly",
      "WinDbg debugging",
      "Stack buffer overflow exploitation",
      "SEH overwrite attacks",
      "DEP and ASLR bypass techniques",
      "Egg hunters and custom shellcode",
      "Format string vulnerabilities",
      "Reverse engineering with IDA Pro"
    ],
    prerequisites: [
      "OSCP or equivalent experience",
      "x86 assembly language knowledge",
      "C programming proficiency"
    ],
    url: "https://www.offsec.com/courses/exp-301/"
  },
  {
    name: "OSWE",
    fullName: "Offensive Security Web Expert",
    provider: "Offensive Security (OffSec)",
    difficulty: "advanced",
    cost: "$1,749 - $5,499",
    duration: "90 days lab access + 48-hour exam",
    desc: "White-box web application security assessment through source code review, focusing on finding and exploiting logic vulnerabilities.",
    topics: [
      "Source code review methodology",
      "Authentication bypass through code analysis",
      "SQL injection via code review",
      "Cross-site scripting in frameworks",
      "Insecure deserialization",
      "Server-side template injection",
      "Type juggling vulnerabilities",
      "Custom exploit scripting in Python"
    ],
    prerequisites: [
      "Web development experience",
      "OSCP or equivalent penetration testing skills",
      "Proficiency in at least one web language (PHP, Java, C#, Python)"
    ],
    url: "https://www.offsec.com/courses/web-300/"
  },
  {
    name: "CEH",
    fullName: "Certified Ethical Hacker",
    provider: "EC-Council",
    difficulty: "beginner",
    cost: "$950 - $1,199",
    duration: "5-day course + 4-hour exam (125 MCQ)",
    desc: "Broad coverage of ethical hacking concepts and tools. Widely recognized in corporate and government environments.",
    topics: [
      "Footprinting and reconnaissance",
      "Network scanning",
      "Enumeration techniques",
      "Vulnerability analysis",
      "System hacking methodology",
      "Malware threats",
      "Sniffing and social engineering",
      "Web server and application hacking"
    ],
    prerequisites: [
      "Basic IT knowledge",
      "Networking fundamentals",
      "2 years information security experience (recommended)"
    ],
    url: "https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/"
  },
  {
    name: "PNPT",
    fullName: "Practical Network Penetration Tester",
    provider: "TCM Security",
    difficulty: "intermediate",
    cost: "$399",
    duration: "5-day practical exam + report",
    desc: "Practical penetration testing certification covering OSINT, external/internal testing, Active Directory, and professional reporting.",
    topics: [
      "OSINT and external reconnaissance",
      "External network penetration testing",
      "Internal network penetration testing",
      "Active Directory enumeration and attacks",
      "Report writing and communication",
      "Privilege escalation",
      "Post-exploitation",
      "Pivoting techniques"
    ],
    prerequisites: [
      "Basic networking knowledge",
      "Linux command-line familiarity",
      "Willingness to learn (beginner-friendly coursework)"
    ],
    url: "https://certifications.tcm-sec.com/pnpt/"
  },
  {
    name: "eJPT",
    fullName: "eLearnSecurity Junior Penetration Tester",
    provider: "INE Security",
    difficulty: "beginner",
    cost: "$249",
    duration: "35-hour practical exam window",
    desc: "Entry-level practical penetration testing certification ideal for those starting their security career.",
    topics: [
      "Networking fundamentals",
      "Web application security basics",
      "Host and network penetration testing",
      "Information gathering",
      "Vulnerability assessment",
      "Basic exploitation",
      "Post-exploitation basics",
      "Penetration testing methodology"
    ],
    prerequisites: [
      "Basic computer knowledge",
      "Basic networking concepts",
      "No prior security experience required"
    ],
    url: "https://security.ine.com/certifications/ejpt-certification/"
  },
  {
    name: "eCPPT",
    fullName: "eLearnSecurity Certified Professional Penetration Tester",
    provider: "INE Security",
    difficulty: "intermediate",
    cost: "$400",
    duration: "14-day practical exam + 7-day report",
    desc: "Intermediate practical certification covering network exploitation, web application testing, and pivoting through complex networks.",
    topics: [
      "System security and exploitation",
      "Network security",
      "PowerShell for penetration testers",
      "Web application security",
      "WiFi security testing",
      "Ruby for penetration testers",
      "Metasploit advanced usage",
      "Pivoting and double pivoting"
    ],
    prerequisites: [
      "eJPT or equivalent experience",
      "Solid networking knowledge",
      "Basic scripting ability"
    ],
    url: "https://security.ine.com/certifications/ecppt-certification/"
  },
  {
    name: "CRTP",
    fullName: "Certified Red Team Professional",
    provider: "Altered Security (formerly Pentester Academy)",
    difficulty: "intermediate",
    cost: "$249 - $449",
    duration: "30 days lab access + 24-hour exam",
    desc: "Focused Active Directory attack and defense certification with a fully hands-on exam in a realistic AD environment.",
    topics: [
      "Active Directory enumeration with PowerShell",
      "Domain privilege escalation",
      "Kerberos attacks: Kerberoasting, AS-REP roasting",
      "Delegation abuse",
      "Cross-trust attacks",
      "Persistence mechanisms",
      "Defense evasion in AD",
      "Post-exploitation in AD environments"
    ],
    prerequisites: [
      "Basic Windows and Active Directory knowledge",
      "PowerShell fundamentals",
      "Basic penetration testing experience"
    ],
    url: "https://www.alteredsecurity.com/adlab"
  },
  {
    name: "CRTO",
    fullName: "Certified Red Team Operator",
    provider: "Zero-Point Security",
    difficulty: "intermediate",
    cost: "$445 (with lab access)",
    duration: "48-hour practical exam",
    desc: "Red team operations certification using Cobalt Strike C2 framework, covering the full attack lifecycle.",
    topics: [
      "C2 infrastructure setup with Cobalt Strike",
      "Initial access techniques",
      "Host reconnaissance and privilege escalation",
      "Credential theft and lateral movement",
      "Domain dominance",
      "Data exfiltration",
      "OPSEC and evasion",
      "Reporting for red team engagements"
    ],
    prerequisites: [
      "OSCP or equivalent experience",
      "Active Directory fundamentals",
      "Familiarity with Windows post-exploitation"
    ],
    url: "https://training.zeropointsecurity.co.uk/courses/red-team-ops"
  },
  {
    name: "GPEN",
    fullName: "GIAC Penetration Tester",
    provider: "SANS / GIAC",
    difficulty: "intermediate",
    cost: "$8,525+ (with SANS course)",
    duration: "6-day course + proctored exam (3 hours, 82 questions)",
    desc: "Comprehensive penetration testing certification from GIAC covering methodology, tools, and techniques for network assessments.",
    topics: [
      "Penetration testing planning and scoping",
      "Reconnaissance and discovery",
      "Vulnerability scanning",
      "Exploitation techniques",
      "Password attacks",
      "Wireless and web application testing",
      "Post-exploitation and pivoting",
      "Penetration test reporting"
    ],
    prerequisites: [
      "SEC560 (SANS course) recommended",
      "Networking and system administration experience",
      "Prior security experience recommended"
    ],
    url: "https://www.giac.org/certifications/penetration-tester-gpen/"
  },
  {
    name: "GWAPT",
    fullName: "GIAC Web Application Penetration Tester",
    provider: "SANS / GIAC",
    difficulty: "intermediate",
    cost: "$8,525+ (with SANS course)",
    duration: "6-day course + proctored exam (3 hours, 82 questions)",
    desc: "Web application penetration testing certification covering OWASP methodology, injection attacks, and modern web vulnerabilities.",
    topics: [
      "Web application penetration testing methodology",
      "Authentication and session management attacks",
      "SQL injection and other injection flaws",
      "Cross-site scripting (XSS) attacks",
      "Cross-site request forgery (CSRF)",
      "Logic flaws and business logic testing",
      "Web services and API testing",
      "Reconnaissance and mapping"
    ],
    prerequisites: [
      "SEC542 (SANS course) recommended",
      "Web development or security experience",
      "HTTP protocol understanding"
    ],
    url: "https://www.giac.org/certifications/web-application-penetration-tester-gwapt/"
  },
  {
    name: "GCIH",
    fullName: "GIAC Certified Incident Handler",
    provider: "SANS / GIAC",
    difficulty: "intermediate",
    cost: "$8,525+ (with SANS course)",
    duration: "6-day course + proctored exam (4 hours, 106 questions)",
    desc: "Incident handling and response certification covering attack techniques and the incident handling process.",
    topics: [
      "Incident handling process and methodology",
      "Malware and attack detection",
      "Network attack analysis",
      "System and application attacks",
      "Denial of service attacks",
      "Worms and bots",
      "Post-incident activity and recovery",
      "Legal and compliance considerations"
    ],
    prerequisites: [
      "SEC504 (SANS course) recommended",
      "System and network administration experience",
      "Security fundamentals understanding"
    ],
    url: "https://www.giac.org/certifications/certified-incident-handler-gcih/"
  },
  {
    name: "Security+",
    fullName: "CompTIA Security+",
    provider: "CompTIA",
    difficulty: "beginner",
    cost: "$404 (exam voucher)",
    duration: "90-minute exam (90 questions)",
    desc: "Vendor-neutral foundational security certification widely recognized as a baseline for IT security roles.",
    topics: [
      "Threats, attacks, and vulnerabilities",
      "Technologies and tools",
      "Architecture and design",
      "Identity and access management",
      "Risk management",
      "Cryptography and PKI",
      "Security operations",
      "Governance and compliance"
    ],
    prerequisites: [
      "CompTIA Network+ recommended",
      "2 years IT administration experience recommended",
      "No strict prerequisites"
    ],
    url: "https://www.comptia.org/certifications/security"
  },
  {
    name: "PenTest+",
    fullName: "CompTIA PenTest+",
    provider: "CompTIA",
    difficulty: "intermediate",
    cost: "$404 (exam voucher)",
    duration: "165-minute exam (85 questions, performance-based and MCQ)",
    desc: "Intermediate penetration testing certification covering planning, scoping, vulnerability management, and reporting.",
    topics: [
      "Planning and scoping penetration tests",
      "Information gathering and vulnerability scanning",
      "Attacks and exploits",
      "Reporting and communication",
      "Tools and code analysis",
      "Post-exploitation techniques",
      "Web application attacks",
      "Network and wireless attacks"
    ],
    prerequisites: [
      "Security+ or equivalent knowledge",
      "3-4 years hands-on security experience recommended",
      "Network+ recommended"
    ],
    url: "https://www.comptia.org/certifications/pentest"
  },
  {
    name: "CPTS",
    fullName: "Certified Penetration Testing Specialist",
    provider: "Hack The Box",
    difficulty: "intermediate",
    cost: "$210 (exam + lab access via HTB subscription)",
    duration: "10-day practical exam + report",
    desc: "Practical penetration testing certification from Hack The Box covering full engagement methodology with a realistic exam environment.",
    topics: [
      "Network enumeration and exploitation",
      "Web application attacks",
      "Active Directory exploitation",
      "Privilege escalation (Linux and Windows)",
      "Lateral movement and pivoting",
      "Post-exploitation",
      "Penetration testing methodology",
      "Professional report writing"
    ],
    prerequisites: [
      "Completion of HTB CPTS learning path",
      "Comfortable with Linux and Windows CLI",
      "Basic penetration testing experience"
    ],
    url: "https://academy.hackthebox.com/preview/certifications/htb-certified-penetration-testing-specialist"
  },
  {
    name: "BSCP",
    fullName: "Burp Suite Certified Practitioner",
    provider: "PortSwigger",
    difficulty: "intermediate",
    cost: "$99",
    duration: "4-hour practical exam",
    desc: "Web security certification from the creators of Burp Suite, testing practical ability to find and exploit web vulnerabilities.",
    topics: [
      "SQL injection",
      "Cross-site scripting (XSS)",
      "Cross-site request forgery (CSRF)",
      "Clickjacking",
      "Server-side request forgery (SSRF)",
      "HTTP request smuggling",
      "OS command injection",
      "Authentication vulnerabilities"
    ],
    prerequisites: [
      "Completion of PortSwigger Web Security Academy labs",
      "Proficiency with Burp Suite Professional",
      "Strong web application security knowledge"
    ],
    url: "https://portswigger.net/web-security/certification"
  }
];

// ---------------------------------------------------------------------------
// CTF Platforms
// ---------------------------------------------------------------------------

const CTF_PLATFORMS = [
  {
    name: "Hack The Box",
    url: "https://www.hackthebox.com",
    desc: "Premier platform with active and retired machines, challenges, and a competitive ranking system. Includes Prolabs for advanced multi-machine environments.",
    difficulty: "beginner to expert",
    categories: [
      "Network exploitation",
      "Web application attacks",
      "Reverse engineering",
      "Cryptography",
      "Forensics",
      "Active Directory",
      "Mobile security",
      "Blockchain"
    ],
    free: true,
    features: [
      "Active and retired machines",
      "Seasonal competitive events (seasons)",
      "ProLabs multi-machine environments",
      "Starting Point guided machines",
      "Community writeups and walkthroughs",
      "Team features and competitions"
    ]
  },
  {
    name: "TryHackMe",
    url: "https://tryhackme.com",
    desc: "Beginner-friendly platform with guided learning paths, interactive rooms, and browser-based attack environments requiring no local setup.",
    difficulty: "beginner to intermediate",
    categories: [
      "Network fundamentals",
      "Web application security",
      "Linux and Windows exploitation",
      "Cryptography",
      "Reverse engineering",
      "Forensics",
      "Red teaming",
      "Defensive security"
    ],
    free: true,
    features: [
      "Browser-based attack machines (AttackBox)",
      "Structured learning paths",
      "Step-by-step guided rooms",
      "King of the Hill competitions",
      "Advent of Cyber annual event",
      "Badge and streak system"
    ]
  },
  {
    name: "PicoCTF",
    url: "https://picoctf.org",
    desc: "Free CTF platform run by Carnegie Mellon University, designed for students and beginners with progressive difficulty challenges.",
    difficulty: "beginner to intermediate",
    categories: [
      "Web exploitation",
      "Reverse engineering",
      "Forensics",
      "Cryptography",
      "Binary exploitation",
      "General skills"
    ],
    free: true,
    features: [
      "Annual CTF competition for students",
      "Persistent practice challenges (picoGym)",
      "Hints and progressive difficulty",
      "Educational focus with learning resources",
      "Classroom integration tools",
      "Browser-based challenge solving"
    ]
  },
  {
    name: "OverTheWire",
    url: "https://overthewire.org/wargames/",
    desc: "SSH-based wargames teaching Linux security concepts through progressive challenges, from basic commands to advanced exploitation.",
    difficulty: "beginner to advanced",
    categories: [
      "Linux commands and navigation",
      "File permissions and SUID",
      "Network services exploitation",
      "Cryptography",
      "Binary exploitation",
      "Web security"
    ],
    free: true,
    features: [
      "SSH-based challenges (no web interface)",
      "Progressive difficulty within each wargame",
      "Bandit (beginner Linux), Natas (web), Narnia (exploitation)",
      "Community-driven hints and solutions",
      "Self-paced with no time limits",
      "Minimal hand-holding for deeper learning"
    ]
  },
  {
    name: "VulnHub",
    url: "https://www.vulnhub.com",
    desc: "Repository of downloadable vulnerable virtual machines for offline practice. Build your own lab environment.",
    difficulty: "beginner to expert",
    categories: [
      "Boot-to-root challenges",
      "Web application exploitation",
      "Privilege escalation",
      "Network exploitation",
      "Realistic scenarios",
      "OSCP-like machines"
    ],
    free: true,
    features: [
      "Downloadable OVA/VMDK virtual machines",
      "Offline practice (no internet required)",
      "Community walkthroughs and writeups",
      "Difficulty ratings and tags",
      "Realistic multi-service machines",
      "OSCP preparation machines"
    ]
  },
  {
    name: "CTFtime",
    url: "https://ctftime.org",
    desc: "The central hub for competitive CTF events worldwide. Tracks team rankings, upcoming events, and past competition archives.",
    difficulty: "intermediate to expert",
    categories: [
      "Jeopardy-style CTFs",
      "Attack-defense CTFs",
      "Mixed format CTFs",
      "Hardware CTFs",
      "King of the Hill",
      "Boot2Root"
    ],
    free: true,
    features: [
      "Global CTF event calendar",
      "Team registration and ranking",
      "Historical results and archives",
      "Writeup aggregation",
      "Rating system for teams and events",
      "Event weight and quality metrics"
    ]
  },
  {
    name: "Root-Me",
    url: "https://www.root-me.org",
    desc: "French-origin platform with hundreds of challenges across all security domains, plus realistic virtual environments.",
    difficulty: "beginner to expert",
    categories: [
      "Web client and server",
      "Network forensics",
      "Cryptanalysis",
      "Reverse engineering",
      "App system exploitation",
      "Steganography",
      "Programming challenges",
      "Realistic scenarios"
    ],
    free: true,
    features: [
      "400+ challenges across 10+ categories",
      "Realistic multi-step environments",
      "Community solutions and discussions",
      "Scoring and ranking system",
      "Virtual environments for practice",
      "Multi-language support"
    ]
  },
  {
    name: "PortSwigger Web Security Academy",
    url: "https://portswigger.net/web-security",
    desc: "Free, comprehensive web security training from the creators of Burp Suite. Includes interactive labs for every vulnerability type.",
    difficulty: "beginner to advanced",
    categories: [
      "SQL injection",
      "XSS and CSRF",
      "SSRF and XXE",
      "Authentication attacks",
      "Access control",
      "Business logic flaws",
      "HTTP request smuggling",
      "Prototype pollution"
    ],
    free: true,
    features: [
      "Interactive labs with Burp Suite integration",
      "Detailed learning materials for each topic",
      "Community edition of Burp Suite sufficient",
      "Progressive difficulty: apprentice to expert",
      "Mystery lab challenges",
      "BSCP certification path"
    ]
  },
  {
    name: "CryptoHack",
    url: "https://cryptohack.org",
    desc: "Dedicated cryptography challenge platform teaching modern crypto concepts through interactive programming challenges.",
    difficulty: "beginner to expert",
    categories: [
      "Symmetric cryptography",
      "RSA and public-key crypto",
      "Elliptic curve cryptography",
      "Hash functions",
      "Diffie-Hellman",
      "Lattice-based crypto",
      "Math fundamentals",
      "Real-world crypto attacks"
    ],
    free: true,
    features: [
      "Browser-based Python coding environment",
      "Progressive difficulty with unlocking",
      "Real-world crypto vulnerability focus",
      "Community discussions and hints",
      "Regular new challenge releases",
      "Achievement and ranking system"
    ]
  },
  {
    name: "pwnable.kr",
    url: "https://pwnable.kr",
    desc: "Binary exploitation and pwn challenge platform with SSH-based challenges focusing on memory corruption and exploit development.",
    difficulty: "intermediate to expert",
    categories: [
      "Stack buffer overflows",
      "Heap exploitation",
      "Format string vulnerabilities",
      "Race conditions",
      "Kernel exploitation",
      "Return-oriented programming (ROP)",
      "Shellcoding",
      "Sandbox escape"
    ],
    free: true,
    features: [
      "SSH-based challenge access",
      "Source code provided for many challenges",
      "Difficulty tiers: Toddler, Rookiss, Grotesque, Hacker",
      "Point-based scoring system",
      "Community boards for discussion",
      "Focus on low-level exploitation skills"
    ]
  },
  {
    name: "SANS Holiday Hack Challenge",
    url: "https://www.holidayhackchallenge.com",
    desc: "Annual free CTF by SANS with a holiday theme, featuring diverse challenges and a narrative-driven experience.",
    difficulty: "beginner to advanced",
    categories: [
      "Web exploitation",
      "Cloud security",
      "Forensics",
      "Cryptography",
      "Network analysis",
      "Reverse engineering",
      "OSINT",
      "AI and machine learning security"
    ],
    free: true,
    features: [
      "Annual event (December-January)",
      "Narrative-driven storyline",
      "Multiple difficulty tiers",
      "Prizes for top submissions",
      "Talk and workshop content",
      "Past challenges available for practice"
    ]
  },
  {
    name: "Hack The Box Academy",
    url: "https://academy.hackthebox.com",
    desc: "Structured learning platform from HTB with curated modules, skill paths, and certification preparation tracks.",
    difficulty: "beginner to advanced",
    categories: [
      "Penetration testing fundamentals",
      "Web application attacks",
      "Active Directory",
      "Privilege escalation",
      "Bug bounty hunting",
      "SOC analyst training",
      "Incident handling",
      "Defensive security"
    ],
    free: false,
    features: [
      "Structured learning modules with quizzes",
      "Skill assessment practical exams",
      "Job role paths (Penetration Tester, SOC Analyst)",
      "CPTS and CDSA certification tracks",
      "Cubes credit system for module access",
      "Interactive exercises and real environments"
    ]
  }
];

// ---------------------------------------------------------------------------
// Book List
// ---------------------------------------------------------------------------

const BOOK_LIST = [
  {
    title: "The Web Application Hacker's Handbook",
    author: "Dafydd Stuttard and Marcus Pinto",
    category: "Web Application Security",
    difficulty: "intermediate",
    desc: "The definitive guide to web application security testing. Covers methodology, tools, and techniques for finding web vulnerabilities.",
    isbn: "978-1118026472",
    year: 2011,
    topics: [
      "Web application mapping",
      "Authentication and session management attacks",
      "SQL injection",
      "XSS and CSRF",
      "Logic vulnerabilities",
      "Server-side attacks",
      "Methodology and reporting"
    ]
  },
  {
    title: "Hacking: The Art of Exploitation",
    author: "Jon Erickson",
    category: "Exploitation",
    difficulty: "intermediate",
    desc: "Classic text on exploitation fundamentals including networking, shellcode, cryptology, and software exploitation from first principles.",
    isbn: "978-1593271442",
    year: 2008,
    topics: [
      "C programming for hackers",
      "Buffer overflows and format strings",
      "Network protocol exploitation",
      "Shellcode development",
      "Countermeasure bypass",
      "Cryptography fundamentals"
    ]
  },
  {
    title: "Metasploit: The Penetration Tester's Guide",
    author: "David Kennedy, Jim O'Gorman, Devon Kearns, and Mati Aharoni",
    category: "Penetration Testing",
    difficulty: "intermediate",
    desc: "Comprehensive guide to the Metasploit Framework covering exploitation, post-exploitation, and custom module development.",
    isbn: "978-1593272883",
    year: 2011,
    topics: [
      "Metasploit framework architecture",
      "Information gathering modules",
      "Vulnerability scanning",
      "Exploitation techniques",
      "Post-exploitation with Meterpreter",
      "Social engineering toolkit",
      "Custom module development"
    ]
  },
  {
    title: "RTFM: Red Team Field Manual",
    author: "Ben Clark",
    category: "Reference",
    difficulty: "intermediate",
    desc: "Compact reference guide containing essential commands and syntax for red team operations, organized by task category.",
    isbn: "978-1494295509",
    year: 2014,
    topics: [
      "Linux command reference",
      "Windows command reference",
      "Networking commands",
      "Exploitation one-liners",
      "Post-exploitation commands",
      "Scripting quick reference"
    ]
  },
  {
    title: "The Hacker Playbook 3: Practical Guide to Penetration Testing",
    author: "Peter Kim",
    category: "Penetration Testing",
    difficulty: "intermediate",
    desc: "Third edition of the popular practical guide, focusing on red team operations with updated tools and techniques.",
    isbn: "978-1980901754",
    year: 2018,
    topics: [
      "Pre-game setup and infrastructure",
      "External and web application attacks",
      "Internal network exploitation",
      "Social engineering campaigns",
      "Physical security testing",
      "Evasion techniques",
      "Red team operations"
    ]
  },
  {
    title: "Black Hat Python",
    author: "Justin Seitz and Tim Arnold",
    category: "Programming",
    difficulty: "intermediate",
    desc: "Python programming for hackers and pentesters. Build network sniffers, manipulate packets, infect VMs, and create trojans.",
    isbn: "978-1718501126",
    year: 2021,
    topics: [
      "Network programming with sockets",
      "Raw packet manipulation with Scapy",
      "Web scraping and fuzzing",
      "Trojan development",
      "Privilege escalation tools",
      "Offensive forensics",
      "GitHub C2 implementation"
    ]
  },
  {
    title: "Practical Malware Analysis",
    author: "Michael Sikorski and Andrew Honig",
    category: "Malware Analysis",
    difficulty: "advanced",
    desc: "The standard text on malware analysis covering static analysis, dynamic analysis, and advanced anti-analysis techniques.",
    isbn: "978-1593272906",
    year: 2012,
    topics: [
      "Static analysis fundamentals",
      "Dynamic analysis in sandboxes",
      "IDA Pro disassembly",
      "Debugging with OllyDbg and WinDbg",
      "Anti-disassembly and anti-debugging",
      "Packer identification and unpacking",
      "Shellcode and C2 analysis"
    ]
  },
  {
    title: "Network Security Assessment",
    author: "Chris McNab",
    category: "Network Security",
    difficulty: "intermediate",
    desc: "Thorough methodology for network security testing, covering all common protocols and services with practical testing techniques.",
    isbn: "978-0596006112",
    year: 2016,
    topics: [
      "Network scanning and enumeration",
      "IP and routing protocol assessment",
      "Transport layer testing",
      "Application layer protocols",
      "Microsoft services assessment",
      "Email and DNS security",
      "Database security testing"
    ]
  },
  {
    title: "Bug Bounty Bootcamp",
    author: "Vickie Li",
    category: "Bug Bounty",
    difficulty: "beginner",
    desc: "Beginner-friendly guide to bug bounty hunting covering vulnerability classes, methodology, and how to write effective reports.",
    isbn: "978-1718501546",
    year: 2021,
    topics: [
      "Bug bounty methodology and platforms",
      "Reconnaissance techniques",
      "XSS, CSRF, and SSRF",
      "IDOR and access control flaws",
      "SQL injection and RCE",
      "Report writing",
      "Automation and tooling"
    ]
  },
  {
    title: "Penetration Testing: A Hands-On Introduction to Hacking",
    author: "Georgia Weidman",
    category: "Penetration Testing",
    difficulty: "beginner",
    desc: "Beginner-friendly penetration testing guide walking through setting up a lab and performing real-world attacks step by step.",
    isbn: "978-1593275648",
    year: 2014,
    topics: [
      "Lab setup with VMs",
      "Reconnaissance and scanning",
      "Capturing traffic",
      "Exploitation with Metasploit",
      "Password attacks",
      "Client-side exploitation",
      "Social engineering",
      "Post-exploitation"
    ]
  },
  {
    title: "Red Team Development and Operations",
    author: "Joe Vest and James Tubberville",
    category: "Red Teaming",
    difficulty: "advanced",
    desc: "Comprehensive guide to planning, building, and executing red team engagements based on military and intelligence community practices.",
    isbn: "978-1735740126",
    year: 2020,
    topics: [
      "Red team planning and organization",
      "Engagement management",
      "Threat intelligence integration",
      "Infrastructure development",
      "Tradecraft and OPSEC",
      "Campaign execution",
      "Reporting and metrics"
    ]
  },
  {
    title: "The Tangled Web: A Guide to Securing Modern Web Applications",
    author: "Michal Zalewski",
    category: "Web Security",
    difficulty: "advanced",
    desc: "Deep dive into browser security models, same-origin policy, and the complexities of securing modern web applications from the inside out.",
    isbn: "978-1593273880",
    year: 2011,
    topics: [
      "Browser security model",
      "Same-origin policy nuances",
      "URL and content handling quirks",
      "HTTP protocol security",
      "Cookie security",
      "Content rendering attacks",
      "New browser features and risks"
    ]
  },
  {
    title: "Attacking Network Protocols",
    author: "James Forshaw",
    category: "Network Security",
    difficulty: "advanced",
    desc: "A guide to finding and exploiting vulnerabilities in network protocols, from analysis through to exploitation.",
    isbn: "978-1593277505",
    year: 2017,
    topics: [
      "Network protocol analysis",
      "Packet capture and injection",
      "Protocol reverse engineering",
      "Cryptographic protocol analysis",
      "Authentication protocol attacks",
      "Network protocol fuzzing",
      "Exploitation of protocol flaws"
    ]
  },
  {
    title: "Serious Cryptography",
    author: "Jean-Philippe Aumasson",
    category: "Cryptography",
    difficulty: "advanced",
    desc: "Practical introduction to modern cryptography covering real-world implementations and common mistakes in cryptographic systems.",
    isbn: "978-1593278267",
    year: 2017,
    topics: [
      "Encryption fundamentals",
      "Block ciphers and stream ciphers",
      "Hash functions and MACs",
      "Authenticated encryption",
      "RSA and Diffie-Hellman",
      "Elliptic curve cryptography",
      "TLS protocol analysis"
    ]
  },
  {
    title: "Operator Handbook: Red Team + OSINT + Blue Team Reference",
    author: "Joshua Picolet",
    category: "Reference",
    difficulty: "intermediate",
    desc: "Quick reference guide combining red team, blue team, and OSINT commands and techniques in a single searchable handbook.",
    isbn: "978-1736526507",
    year: 2020,
    topics: [
      "Red team command reference",
      "Blue team detection commands",
      "OSINT tools and techniques",
      "Forensics commands",
      "Cloud security reference",
      "Scripting quick reference",
      "Tool configuration guides"
    ]
  },
  {
    title: "Practical Binary Analysis",
    author: "Dennis Andriesse",
    category: "Reverse Engineering",
    difficulty: "advanced",
    desc: "Build your own Linux-based binary analysis tools to dissect ELF binaries, instrument code, and deobfuscate malware.",
    isbn: "978-1593279127",
    year: 2018,
    topics: [
      "ELF binary format",
      "Disassembly and binary loading",
      "Dynamic analysis with ltrace/strace",
      "Binary instrumentation with Pin",
      "Symbolic execution",
      "Taint analysis",
      "Custom binary analysis tools"
    ]
  },
  {
    title: "Silence on the Wire: A Field Guide to Passive Reconnaissance",
    author: "Michal Zalewski",
    category: "Reconnaissance",
    difficulty: "intermediate",
    desc: "Explores the information leaked by systems and networks through passive observation, covering TCP/IP fingerprinting and traffic analysis.",
    isbn: "978-1593270469",
    year: 2005,
    topics: [
      "Passive OS fingerprinting",
      "TCP/IP stack behavior analysis",
      "Timing and traffic analysis",
      "Electromagnetic emanations",
      "DNS and routing protocol leaks",
      "Social information leakage"
    ]
  },
  {
    title: "Web Security for Developers",
    author: "Malcolm McDonald",
    category: "Web Security",
    difficulty: "beginner",
    desc: "Accessible introduction to web security for developers covering common vulnerabilities and secure coding practices.",
    isbn: "978-1593279943",
    year: 2020,
    topics: [
      "Injection attacks and prevention",
      "Authentication best practices",
      "Session management security",
      "Cross-site scripting defenses",
      "HTTPS and encryption",
      "Third-party code risks",
      "Security headers"
    ]
  },
  {
    title: "Active Directory Attacks for Red and Blue Teams",
    author: "Nikhil Mittal",
    category: "Active Directory",
    difficulty: "advanced",
    desc: "Comprehensive guide to attacking and defending Active Directory environments, covering enumeration through domain dominance.",
    isbn: "978-9355513519",
    year: 2023,
    topics: [
      "AD enumeration techniques",
      "Kerberos attack chains",
      "Delegation abuse",
      "Trust relationship attacks",
      "Persistence mechanisms",
      "Detection and hunting",
      "Hardening recommendations"
    ]
  },
  {
    title: "Real-World Bug Hunting",
    author: "Peter Yaworski",
    category: "Bug Bounty",
    difficulty: "beginner",
    desc: "Learn bug bounty hunting through real-world disclosed vulnerability examples, covering all major vulnerability classes.",
    isbn: "978-1593278618",
    year: 2019,
    topics: [
      "Open redirect vulnerabilities",
      "HTTP parameter pollution",
      "CSRF and IDOR",
      "SQL injection case studies",
      "XSS in the wild",
      "Server-side vulnerabilities",
      "Race conditions"
    ]
  },
  {
    title: "Hands-On AWS Penetration Testing with Kali Linux",
    author: "Karl Gilbert and Benjamin Caudill",
    category: "Cloud Security",
    difficulty: "intermediate",
    desc: "Practical guide to penetration testing AWS environments, covering service enumeration, exploitation, and post-exploitation in the cloud.",
    isbn: "978-1789136722",
    year: 2019,
    topics: [
      "AWS account enumeration",
      "IAM privilege escalation",
      "S3 bucket exploitation",
      "EC2 instance attacks",
      "Lambda function exploitation",
      "RDS database attacks",
      "CloudTrail evasion"
    ]
  },
  {
    title: "Tribe of Hackers Red Team",
    author: "Marcus J. Carey and Jennifer Jin",
    category: "Career",
    difficulty: "beginner",
    desc: "Interviews with red team professionals sharing career advice, methodology insights, and lessons learned from the field.",
    isbn: "978-1119643326",
    year: 2019,
    topics: [
      "Career development advice",
      "Red team methodologies",
      "Tool recommendations",
      "Lessons from real engagements",
      "Team building and management",
      "Industry perspectives",
      "Getting started in red teaming"
    ]
  }
];

// ---------------------------------------------------------------------------
// Training Resources
// ---------------------------------------------------------------------------

const TRAINING_RESOURCES = [
  {
    name: "SANS SEC560: Network Penetration Testing and Ethical Hacking",
    provider: "SANS Institute",
    url: "https://www.sans.org/cyber-security-courses/network-penetration-testing-ethical-hacking/",
    type: "course",
    difficulty: "intermediate",
    desc: "Flagship SANS penetration testing course covering reconnaissance, scanning, exploitation, and post-exploitation with hands-on labs.",
    topics: ["Network penetration testing", "Exploitation", "Post-exploitation", "Reporting"],
    free: false
  },
  {
    name: "SANS SEC542: Web App Penetration Testing and Ethical Hacking",
    provider: "SANS Institute",
    url: "https://www.sans.org/cyber-security-courses/web-app-penetration-testing-ethical-hacking/",
    type: "course",
    difficulty: "intermediate",
    desc: "SANS web application penetration testing course with detailed methodology and hands-on exercises.",
    topics: ["Web application testing", "OWASP Top 10", "Authentication attacks", "Injection flaws"],
    free: false
  },
  {
    name: "PEN-200: Penetration Testing with Kali Linux",
    provider: "Offensive Security",
    url: "https://www.offsec.com/courses/pen-200/",
    type: "course",
    difficulty: "intermediate",
    desc: "The official OSCP preparation course. Hands-on labs with a comprehensive curriculum covering all aspects of penetration testing.",
    topics: ["Kali Linux tools", "Enumeration", "Exploitation", "Privilege escalation", "Active Directory"],
    free: false
  },
  {
    name: "Practical Ethical Hacking",
    provider: "TCM Security",
    url: "https://academy.tcm-sec.com/p/practical-ethical-hacking-the-complete-course",
    type: "course",
    difficulty: "beginner",
    desc: "Comprehensive beginner-friendly course covering networking, Linux, Python, Active Directory, and hands-on hacking methodology.",
    topics: ["Networking", "Linux", "Python scripting", "Active Directory", "Web application attacks"],
    free: false
  },
  {
    name: "PortSwigger Web Security Academy",
    provider: "PortSwigger",
    url: "https://portswigger.net/web-security",
    type: "lab",
    difficulty: "beginner to advanced",
    desc: "Free interactive labs covering all major web vulnerability classes, from the creators of Burp Suite.",
    topics: ["SQL injection", "XSS", "SSRF", "XXE", "Authentication", "Access control", "Business logic"],
    free: true
  },
  {
    name: "PentesterLab",
    provider: "PentesterLab",
    url: "https://pentesterlab.com",
    type: "lab",
    difficulty: "beginner to advanced",
    desc: "Hands-on web security exercises progressing from basic to advanced, with badges for completing learning paths.",
    topics: ["Web vulnerabilities", "Code review", "Android security", "JWT attacks", "Deserialization"],
    free: false
  },
  {
    name: "INE Security Training",
    provider: "INE",
    url: "https://security.ine.com",
    type: "course",
    difficulty: "beginner to advanced",
    desc: "Comprehensive security training platform with courses for eJPT, eCPPT, and other certification preparation.",
    topics: ["Penetration testing", "Web security", "Network security", "Host exploitation", "PowerShell"],
    free: false
  },
  {
    name: "Cybrary",
    provider: "Cybrary",
    url: "https://www.cybrary.it",
    type: "course",
    difficulty: "beginner to intermediate",
    desc: "Online cybersecurity training platform with courses covering offensive and defensive security topics.",
    topics: ["Security fundamentals", "Ethical hacking", "Incident response", "Forensics", "Compliance"],
    free: true
  },
  {
    name: "OWASP Web Security Testing Guide",
    provider: "OWASP Foundation",
    url: "https://owasp.org/www-project-web-security-testing-guide/",
    type: "blog",
    difficulty: "intermediate",
    desc: "Comprehensive open-source web application security testing methodology covering every aspect of web app assessment.",
    topics: ["Testing methodology", "Authentication testing", "Input validation", "Session management", "Business logic"],
    free: true
  },
  {
    name: "IppSec YouTube Channel",
    provider: "IppSec",
    url: "https://www.youtube.com/c/ippsec",
    type: "video",
    difficulty: "intermediate to advanced",
    desc: "Detailed walkthrough videos of Hack The Box machines demonstrating real-world penetration testing methodology.",
    topics: ["HTB machine walkthroughs", "Web exploitation", "Privilege escalation", "Active Directory", "Scripting"],
    free: true
  },
  {
    name: "LiveOverflow YouTube Channel",
    provider: "LiveOverflow",
    url: "https://www.youtube.com/c/LiveOverflow",
    type: "video",
    difficulty: "intermediate to advanced",
    desc: "In-depth security research videos covering binary exploitation, web hacking, CTF challenges, and security concepts.",
    topics: ["Binary exploitation", "Web security", "CTF writeups", "Browser security", "Reverse engineering"],
    free: true
  },
  {
    name: "John Hammond YouTube Channel",
    provider: "John Hammond",
    url: "https://www.youtube.com/c/JohnHammond010",
    type: "video",
    difficulty: "beginner to intermediate",
    desc: "Accessible security content including CTF walkthroughs, tool tutorials, and malware analysis videos.",
    topics: ["CTF walkthroughs", "Malware analysis", "Tool tutorials", "Career advice", "Security news"],
    free: true
  },
  {
    name: "HackerOne Bug Bounty Platform",
    provider: "HackerOne",
    url: "https://www.hackerone.com",
    type: "community",
    difficulty: "intermediate to advanced",
    desc: "Leading bug bounty platform connecting security researchers with organizations. Includes public programs and educational resources.",
    topics: ["Bug bounty hunting", "Vulnerability disclosure", "Report writing", "Web application testing"],
    free: true
  },
  {
    name: "Bugcrowd Bug Bounty Platform",
    provider: "Bugcrowd",
    url: "https://www.bugcrowd.com",
    type: "community",
    difficulty: "intermediate to advanced",
    desc: "Bug bounty and vulnerability disclosure platform with programs ranging from open to invite-only.",
    topics: ["Bug bounty methodology", "Vulnerability research", "Security testing", "Triage and reporting"],
    free: true
  },
  {
    name: "Hack The Box Academy",
    provider: "Hack The Box",
    url: "https://academy.hackthebox.com",
    type: "lab",
    difficulty: "beginner to advanced",
    desc: "Structured learning platform with guided modules covering penetration testing, web security, and defensive operations.",
    topics: ["Penetration testing", "Web attacks", "Active Directory", "Bug bounty", "SOC operations"],
    free: false
  },
  {
    name: "CloudGoat",
    provider: "Rhino Security Labs",
    url: "https://github.com/RhinoSecurityLabs/cloudgoat",
    type: "lab",
    difficulty: "intermediate",
    desc: "Vulnerable-by-design AWS deployment tool for learning cloud security attack and defense scenarios.",
    topics: ["AWS IAM exploitation", "S3 misconfiguration", "Lambda attacks", "Privilege escalation", "Cloud enumeration"],
    free: true
  },
  {
    name: "DVWA (Damn Vulnerable Web Application)",
    provider: "DVWA Project",
    url: "https://github.com/digininja/DVWA",
    type: "lab",
    difficulty: "beginner",
    desc: "Classic deliberately vulnerable web application for practicing web security fundamentals at adjustable difficulty levels.",
    topics: ["SQL injection", "XSS", "CSRF", "File inclusion", "Command injection", "Brute force"],
    free: true
  },
  {
    name: "OWASP Juice Shop",
    provider: "OWASP Foundation",
    url: "https://owasp.org/www-project-juice-shop/",
    type: "lab",
    difficulty: "beginner to intermediate",
    desc: "Modern vulnerable web application with gamification, covering the OWASP Top 10 and beyond in a realistic e-commerce setting.",
    topics: ["OWASP Top 10", "Injection attacks", "Broken authentication", "Sensitive data exposure", "XSS"],
    free: true
  },
  {
    name: "Vulnhub Machines Collection",
    provider: "VulnHub",
    url: "https://www.vulnhub.com",
    type: "lab",
    difficulty: "beginner to expert",
    desc: "Large collection of downloadable vulnerable VMs for offline penetration testing practice.",
    topics: ["Boot to root", "Web exploitation", "Privilege escalation", "Enumeration", "Realistic scenarios"],
    free: true
  },
  {
    name: "Sektor7 Malware Development Courses",
    provider: "Sektor7",
    url: "https://institute.sektor7.net",
    type: "course",
    difficulty: "advanced",
    desc: "Advanced courses on Windows malware development, evasion, and red team tool development.",
    topics: ["Shellcode development", "Process injection", "EDR evasion", "Windows internals", "Custom implants"],
    free: false
  },
  {
    name: "Altered Security (Pentester Academy) Labs",
    provider: "Altered Security",
    url: "https://www.alteredsecurity.com",
    type: "lab",
    difficulty: "intermediate to advanced",
    desc: "Active Directory attack labs and courses, including CRTP and CRTE certification preparation.",
    topics: ["Active Directory attacks", "Kerberos exploitation", "Delegation abuse", "Forest trust attacks"],
    free: false
  },
  {
    name: "Zero-Point Security Red Team Ops",
    provider: "Zero-Point Security",
    url: "https://training.zeropointsecurity.co.uk",
    type: "course",
    difficulty: "intermediate to advanced",
    desc: "Red team operations training using Cobalt Strike, covering the full attack lifecycle for CRTO certification.",
    topics: ["C2 operations", "Initial access", "Lateral movement", "Persistence", "Data exfiltration"],
    free: false
  },
  {
    name: "HackTricks",
    provider: "Carlos Polop",
    url: "https://book.hacktricks.xyz",
    type: "blog",
    difficulty: "beginner to advanced",
    desc: "Comprehensive pentesting wiki with cheat sheets, methodology guides, and technique references for almost every attack vector.",
    topics: ["Linux privesc", "Windows privesc", "Active Directory", "Web attacks", "Cloud security", "Mobile"],
    free: true
  },
  {
    name: "PayloadsAllTheThings",
    provider: "swisskyrepo",
    url: "https://github.com/swisskyrepo/PayloadsAllTheThings",
    type: "blog",
    difficulty: "intermediate",
    desc: "Massive GitHub repository of payloads and bypass techniques for web application security testing.",
    topics: ["SQL injection payloads", "XSS payloads", "SSRF", "XXE", "SSTI", "Command injection"],
    free: true
  },
  {
    name: "GTFOBins",
    provider: "GTFOBins Project",
    url: "https://gtfobins.github.io",
    type: "tool",
    difficulty: "intermediate",
    desc: "Curated list of Unix binaries that can be used to bypass local security restrictions for privilege escalation.",
    topics: ["SUID exploitation", "Sudo bypass", "Capabilities abuse", "File read/write", "Reverse shells"],
    free: true
  },
  {
    name: "LOLBAS Project",
    provider: "LOLBAS Project",
    url: "https://lolbas-project.github.io",
    type: "tool",
    difficulty: "intermediate",
    desc: "Living Off The Land Binaries, Scripts, and Libraries -- legitimate Windows tools that can be abused for offensive purposes.",
    topics: ["Download cradles", "Execution bypass", "UAC bypass", "Persistence", "Reconnaissance"],
    free: true
  },
  {
    name: "Kubernetes Goat",
    provider: "Madhu Akula",
    url: "https://madhuakula.com/kubernetes-goat/",
    type: "lab",
    difficulty: "intermediate",
    desc: "Interactive Kubernetes security learning environment with vulnerable-by-design scenarios for hands-on practice.",
    topics: ["Container escape", "RBAC misconfiguration", "Secret exposure", "Network policies", "Supply chain"],
    free: true
  },
  {
    name: "Offensive Security Proving Grounds",
    provider: "Offensive Security",
    url: "https://www.offsec.com/labs/",
    type: "lab",
    difficulty: "intermediate to advanced",
    desc: "Practice machines from OffSec for OSCP preparation, with Play (free community machines) and Practice (curated lab) tiers.",
    topics: ["Network exploitation", "Web attacks", "Privilege escalation", "Active Directory", "Buffer overflow"],
    free: false
  },
  {
    name: "Exploit Education",
    provider: "Exploit Education",
    url: "https://exploit.education",
    type: "lab",
    difficulty: "beginner to advanced",
    desc: "Free VMs and challenges teaching memory corruption, format strings, networking, and kernel exploitation from the ground up.",
    topics: ["Stack overflows", "Heap exploitation", "Format strings", "Network exploitation", "Kernel exploits"],
    free: true
  },
  {
    name: "CyberDefenders",
    provider: "CyberDefenders",
    url: "https://cyberdefenders.org",
    type: "lab",
    difficulty: "beginner to advanced",
    desc: "Blue team focused CTF platform with challenges in DFIR, threat hunting, and security operations.",
    topics: ["Digital forensics", "Incident response", "Threat hunting", "Malware analysis", "Log analysis"],
    free: true
  },
  {
    name: "Antisyphon Training",
    provider: "Antisyphon Training",
    url: "https://www.antisyphontraining.com",
    type: "course",
    difficulty: "beginner to advanced",
    desc: "Affordable live training courses taught by industry experts covering offensive security, DFIR, and blue team topics.",
    topics: ["Penetration testing", "SOC operations", "Threat hunting", "Red team operations", "Cloud security"],
    free: false
  },
  {
    name: "MITRE ATT&CK Navigator",
    provider: "MITRE",
    url: "https://mitre-attack.github.io/attack-navigator/",
    type: "tool",
    difficulty: "intermediate",
    desc: "Interactive tool for visualizing and mapping adversary techniques to the ATT&CK framework for both offensive and defensive use.",
    topics: ["ATT&CK technique mapping", "Threat modeling", "Coverage analysis", "Red team planning", "Detection gaps"],
    free: true
  },
  {
    name: "Offensive Security Proving Grounds Play",
    provider: "Offensive Security",
    url: "https://portal.offsec.com/labs/play",
    type: "lab",
    difficulty: "beginner to intermediate",
    desc: "Free community-contributed machines for penetration testing practice, including VulnHub machines in a cloud environment.",
    topics: ["Linux exploitation", "Windows exploitation", "Web attacks", "Enumeration", "Privilege escalation"],
    free: true
  },
  {
    name: "Immersive Labs",
    provider: "Immersive Labs",
    url: "https://www.immersivelabs.com",
    type: "lab",
    difficulty: "beginner to advanced",
    desc: "Enterprise-focused cyber skills platform with labs covering offensive, defensive, and crisis simulation scenarios.",
    topics: ["Penetration testing", "Incident response", "Cloud security", "Application security", "Crisis management"],
    free: false
  }
];

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  LEARNING_PATHS,
  CERTIFICATIONS,
  CTF_PLATFORMS,
  BOOK_LIST,
  TRAINING_RESOURCES
};
