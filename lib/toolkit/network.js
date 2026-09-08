"use strict";

// ---------------------------------------------------------------------------
// network.js -- Protocol references, Nmap NSE scripts, Wireshark display
// filters, and IP utility helpers for the Darknode toolkit.
// ---------------------------------------------------------------------------

/**
 * PROTOCOLS -- 55 common network protocols with port, transport layer,
 * description, and known vulnerability classes.
 */
const PROTOCOLS = [
  {
    name: "HTTP",
    port: 80,
    description: "Hypertext Transfer Protocol for web traffic",
    transport: "tcp",
    vulnerabilities: ["directory traversal", "header injection", "verb tampering", "request smuggling"]
  },
  {
    name: "HTTPS",
    port: 443,
    description: "HTTP over TLS/SSL encrypted web traffic",
    transport: "tcp",
    vulnerabilities: ["certificate mismatch", "weak cipher suites", "protocol downgrade", "HSTS bypass"]
  },
  {
    name: "FTP",
    port: 21,
    description: "File Transfer Protocol for file uploads and downloads",
    transport: "tcp",
    vulnerabilities: ["anonymous login", "cleartext credentials", "bounce attack", "path traversal"]
  },
  {
    name: "FTPS",
    port: 990,
    description: "FTP over implicit TLS",
    transport: "tcp",
    vulnerabilities: ["certificate validation bypass", "fallback to cleartext"]
  },
  {
    name: "SSH",
    port: 22,
    description: "Secure Shell for encrypted remote administration",
    transport: "tcp",
    vulnerabilities: ["brute force", "weak key exchange", "username enumeration", "agent forwarding abuse"]
  },
  {
    name: "Telnet",
    port: 23,
    description: "Unencrypted remote terminal access",
    transport: "tcp",
    vulnerabilities: ["cleartext credentials", "session hijacking", "man-in-the-middle"]
  },
  {
    name: "SMTP",
    port: 25,
    description: "Simple Mail Transfer Protocol for email relay",
    transport: "tcp",
    vulnerabilities: ["open relay", "user enumeration via VRFY/EXPN", "header injection", "spoofing"]
  },
  {
    name: "SMTPS",
    port: 465,
    description: "SMTP over implicit TLS for secure mail submission",
    transport: "tcp",
    vulnerabilities: ["downgrade attacks", "weak TLS configuration"]
  },
  {
    name: "SMTP-Submission",
    port: 587,
    description: "Mail submission agent port with STARTTLS",
    transport: "tcp",
    vulnerabilities: ["STARTTLS stripping", "credential brute force"]
  },
  {
    name: "DNS",
    port: 53,
    description: "Domain Name System for hostname resolution",
    transport: "both",
    vulnerabilities: ["zone transfer", "cache poisoning", "amplification/reflection", "DNS tunneling"]
  },
  {
    name: "DHCP",
    port: 67,
    description: "Dynamic Host Configuration Protocol server port",
    transport: "udp",
    vulnerabilities: ["rogue DHCP server", "starvation attack", "snooping"]
  },
  {
    name: "TFTP",
    port: 69,
    description: "Trivial File Transfer Protocol with no authentication",
    transport: "udp",
    vulnerabilities: ["no authentication", "directory traversal", "data interception"]
  },
  {
    name: "HTTP-Alt",
    port: 8080,
    description: "Alternate HTTP port often used for proxies and dev servers",
    transport: "tcp",
    vulnerabilities: ["proxy misconfiguration", "unauthenticated admin panels"]
  },
  {
    name: "POP3",
    port: 110,
    description: "Post Office Protocol v3 for email retrieval",
    transport: "tcp",
    vulnerabilities: ["cleartext credentials", "brute force", "buffer overflow"]
  },
  {
    name: "POP3S",
    port: 995,
    description: "POP3 over TLS for secure email retrieval",
    transport: "tcp",
    vulnerabilities: ["weak TLS versions", "certificate pinning bypass"]
  },
  {
    name: "IMAP",
    port: 143,
    description: "Internet Message Access Protocol for email management",
    transport: "tcp",
    vulnerabilities: ["cleartext credentials", "brute force", "command injection"]
  },
  {
    name: "IMAPS",
    port: 993,
    description: "IMAP over TLS for secure email management",
    transport: "tcp",
    vulnerabilities: ["weak TLS configuration", "session fixation"]
  },
  {
    name: "SNMP",
    port: 161,
    description: "Simple Network Management Protocol for device monitoring",
    transport: "udp",
    vulnerabilities: ["default community strings", "information disclosure", "SNMPv1/v2 cleartext"]
  },
  {
    name: "SNMP-Trap",
    port: 162,
    description: "SNMP trap receiver for asynchronous notifications",
    transport: "udp",
    vulnerabilities: ["spoofed traps", "information leakage"]
  },
  {
    name: "BGP",
    port: 179,
    description: "Border Gateway Protocol for inter-AS routing",
    transport: "tcp",
    vulnerabilities: ["route hijacking", "session reset", "prefix spoofing", "MD5 auth weakness"]
  },
  {
    name: "LDAP",
    port: 389,
    description: "Lightweight Directory Access Protocol for directory services",
    transport: "tcp",
    vulnerabilities: ["anonymous bind", "LDAP injection", "cleartext credentials", "null base DN"]
  },
  {
    name: "LDAPS",
    port: 636,
    description: "LDAP over TLS for secure directory queries",
    transport: "tcp",
    vulnerabilities: ["certificate validation bypass", "downgrade to cleartext"]
  },
  {
    name: "SMB",
    port: 445,
    description: "Server Message Block for Windows file and printer sharing",
    transport: "tcp",
    vulnerabilities: ["EternalBlue (MS17-010)", "null session", "relay attacks", "signing disabled"]
  },
  {
    name: "NetBIOS-NS",
    port: 137,
    description: "NetBIOS Name Service for name registration and resolution",
    transport: "udp",
    vulnerabilities: ["name spoofing", "information enumeration"]
  },
  {
    name: "NetBIOS-SSN",
    port: 139,
    description: "NetBIOS Session Service for legacy SMB transport",
    transport: "tcp",
    vulnerabilities: ["null session enumeration", "credential relay"]
  },
  {
    name: "RDP",
    port: 3389,
    description: "Remote Desktop Protocol for Windows remote access",
    transport: "tcp",
    vulnerabilities: ["BlueKeep (CVE-2019-0708)", "brute force", "NLA bypass", "man-in-the-middle"]
  },
  {
    name: "MySQL",
    port: 3306,
    description: "MySQL relational database server",
    transport: "tcp",
    vulnerabilities: ["default credentials", "SQL injection", "privilege escalation", "cleartext auth"]
  },
  {
    name: "PostgreSQL",
    port: 5432,
    description: "PostgreSQL relational database server",
    transport: "tcp",
    vulnerabilities: ["trust authentication", "SQL injection", "pg_hba misconfiguration"]
  },
  {
    name: "MongoDB",
    port: 27017,
    description: "MongoDB NoSQL document database",
    transport: "tcp",
    vulnerabilities: ["no authentication", "NoSQL injection", "SSRF via ObjectId", "data exposure"]
  },
  {
    name: "Redis",
    port: 6379,
    description: "Redis in-memory key-value data store",
    transport: "tcp",
    vulnerabilities: ["no authentication", "command injection via EVAL", "RCE via module load", "replication abuse"]
  },
  {
    name: "Memcached",
    port: 11211,
    description: "Memcached distributed memory caching system",
    transport: "both",
    vulnerabilities: ["no authentication", "DDoS amplification", "data exfiltration"]
  },
  {
    name: "MQTT",
    port: 1883,
    description: "Message Queuing Telemetry Transport for IoT messaging",
    transport: "tcp",
    vulnerabilities: ["no authentication", "topic enumeration", "cleartext messages", "broker hijacking"]
  },
  {
    name: "MQTTS",
    port: 8883,
    description: "MQTT over TLS for secure IoT messaging",
    transport: "tcp",
    vulnerabilities: ["weak TLS configuration", "certificate mismanagement"]
  },
  {
    name: "SIP",
    port: 5060,
    description: "Session Initiation Protocol for VoIP signaling",
    transport: "both",
    vulnerabilities: ["caller ID spoofing", "registration hijacking", "eavesdropping", "toll fraud"]
  },
  {
    name: "SIPS",
    port: 5061,
    description: "SIP over TLS for secure VoIP signaling",
    transport: "tcp",
    vulnerabilities: ["TLS downgrade", "certificate validation issues"]
  },
  {
    name: "NTP",
    port: 123,
    description: "Network Time Protocol for clock synchronization",
    transport: "udp",
    vulnerabilities: ["amplification attack", "time shifting", "monlist information leak"]
  },
  {
    name: "Kerberos",
    port: 88,
    description: "Kerberos authentication protocol for Active Directory",
    transport: "both",
    vulnerabilities: ["AS-REP roasting", "Kerberoasting", "golden ticket", "silver ticket"]
  },
  {
    name: "MSSQL",
    port: 1433,
    description: "Microsoft SQL Server database",
    transport: "tcp",
    vulnerabilities: ["default sa credentials", "xp_cmdshell RCE", "SQL injection", "credential relay"]
  },
  {
    name: "Oracle-DB",
    port: 1521,
    description: "Oracle Database TNS Listener",
    transport: "tcp",
    vulnerabilities: ["TNS poisoning", "default credentials", "privilege escalation", "SID enumeration"]
  },
  {
    name: "VNC",
    port: 5900,
    description: "Virtual Network Computing for remote desktop sharing",
    transport: "tcp",
    vulnerabilities: ["weak/no authentication", "cleartext session", "brute force"]
  },
  {
    name: "OSPF",
    port: 89,
    description: "Open Shortest Path First interior gateway routing protocol",
    transport: "tcp",
    vulnerabilities: ["route injection", "adjacency spoofing", "MD5 auth weakness"]
  },
  {
    name: "Syslog",
    port: 514,
    description: "Syslog message logging protocol",
    transport: "udp",
    vulnerabilities: ["log injection", "spoofed source", "cleartext transmission"]
  },
  {
    name: "RTSP",
    port: 554,
    description: "Real Time Streaming Protocol for media streaming control",
    transport: "tcp",
    vulnerabilities: ["default credentials", "stream enumeration", "buffer overflow"]
  },
  {
    name: "PPTP",
    port: 1723,
    description: "Point-to-Point Tunneling Protocol for VPN",
    transport: "tcp",
    vulnerabilities: ["MS-CHAPv2 weakness", "GRE session hijacking", "broken encryption"]
  },
  {
    name: "L2TP",
    port: 1701,
    description: "Layer 2 Tunneling Protocol for VPN tunneling",
    transport: "udp",
    vulnerabilities: ["no native encryption", "relies on IPSec", "authentication bypass"]
  },
  {
    name: "OpenVPN",
    port: 1194,
    description: "OpenVPN SSL-based VPN tunnel",
    transport: "both",
    vulnerabilities: ["weak cipher configuration", "certificate mismanagement", "key reuse"]
  },
  {
    name: "WireGuard",
    port: 51820,
    description: "WireGuard modern VPN protocol",
    transport: "udp",
    vulnerabilities: ["key compromise", "endpoint discovery", "no user authentication layer"]
  },
  {
    name: "CouchDB",
    port: 5984,
    description: "Apache CouchDB document-oriented database",
    transport: "tcp",
    vulnerabilities: ["admin party mode", "REST API exposure", "replication abuse"]
  },
  {
    name: "Elasticsearch",
    port: 9200,
    description: "Elasticsearch search and analytics engine REST API",
    transport: "tcp",
    vulnerabilities: ["no authentication", "script injection", "data exposure", "cluster takeover"]
  },
  {
    name: "Cassandra",
    port: 9042,
    description: "Apache Cassandra distributed NoSQL database",
    transport: "tcp",
    vulnerabilities: ["default credentials", "no authentication", "CQL injection"]
  },
  {
    name: "Docker-API",
    port: 2375,
    description: "Docker Engine unencrypted REST API",
    transport: "tcp",
    vulnerabilities: ["unauthenticated container creation", "host filesystem access", "privilege escalation"]
  },
  {
    name: "Kubernetes-API",
    port: 6443,
    description: "Kubernetes API server",
    transport: "tcp",
    vulnerabilities: ["anonymous access", "RBAC misconfiguration", "etcd exposure", "token theft"]
  },
  {
    name: "etcd",
    port: 2379,
    description: "etcd distributed key-value store used by Kubernetes",
    transport: "tcp",
    vulnerabilities: ["unauthenticated reads", "secret extraction", "cluster compromise"]
  },
  {
    name: "Rsync",
    port: 873,
    description: "Rsync file synchronization protocol",
    transport: "tcp",
    vulnerabilities: ["anonymous module access", "path traversal", "data exfiltration"]
  },
  {
    name: "IRC",
    port: 6667,
    description: "Internet Relay Chat for real-time messaging",
    transport: "tcp",
    vulnerabilities: ["botnet C2 channel", "DCC exploits", "cleartext credentials"]
  }
];


/**
 * NMAP_SCRIPTS -- 55 commonly used Nmap Scripting Engine (NSE) scripts with
 * category, description, and example usage syntax.
 */
const NMAP_SCRIPTS = [
  {
    name: "http-title",
    category: "default, safe",
    description: "Retrieves the title of the default web page",
    usage: "nmap --script http-title -p 80,443 <target>"
  },
  {
    name: "http-headers",
    category: "discovery, safe",
    description: "Retrieves HTTP response headers from the target web server",
    usage: "nmap --script http-headers -p 80,443 <target>"
  },
  {
    name: "http-enum",
    category: "discovery, intrusive",
    description: "Enumerates common web application directories and files",
    usage: "nmap --script http-enum -p 80,443 <target>"
  },
  {
    name: "http-methods",
    category: "default, safe",
    description: "Discovers supported HTTP methods such as GET, POST, PUT, DELETE",
    usage: "nmap --script http-methods -p 80,443 <target>"
  },
  {
    name: "http-robots.txt",
    category: "default, safe",
    description: "Retrieves and parses the robots.txt file",
    usage: "nmap --script http-robots.txt -p 80,443 <target>"
  },
  {
    name: "http-server-header",
    category: "default, safe",
    description: "Extracts the server software version from the HTTP Server header",
    usage: "nmap --script http-server-header -p 80,443 <target>"
  },
  {
    name: "http-vuln-cve2017-5638",
    category: "vuln",
    description: "Detects Apache Struts 2 RCE vulnerability (CVE-2017-5638)",
    usage: "nmap --script http-vuln-cve2017-5638 -p 80,443 <target>"
  },
  {
    name: "http-shellshock",
    category: "vuln",
    description: "Detects the Shellshock vulnerability in CGI scripts",
    usage: "nmap --script http-shellshock --script-args uri=/cgi-bin/test.cgi -p 80 <target>"
  },
  {
    name: "http-sql-injection",
    category: "vuln",
    description: "Crawls a web server and tests for SQL injection vulnerabilities",
    usage: "nmap --script http-sql-injection -p 80,443 <target>"
  },
  {
    name: "http-csrf",
    category: "vuln",
    description: "Detects Cross-Site Request Forgery vulnerabilities in web forms",
    usage: "nmap --script http-csrf -p 80,443 <target>"
  },
  {
    name: "ssl-heartbleed",
    category: "vuln",
    description: "Detects the OpenSSL Heartbleed vulnerability (CVE-2014-0160)",
    usage: "nmap --script ssl-heartbleed -p 443 <target>"
  },
  {
    name: "ssl-poodle",
    category: "vuln",
    description: "Detects the SSLv3 POODLE vulnerability (CVE-2014-3566)",
    usage: "nmap --script ssl-poodle -p 443 <target>"
  },
  {
    name: "ssl-cert",
    category: "default, safe",
    description: "Retrieves SSL/TLS certificate details from the target",
    usage: "nmap --script ssl-cert -p 443 <target>"
  },
  {
    name: "ssl-enum-ciphers",
    category: "discovery, safe",
    description: "Enumerates supported SSL/TLS cipher suites and grades them",
    usage: "nmap --script ssl-enum-ciphers -p 443 <target>"
  },
  {
    name: "ssl-dh-params",
    category: "vuln, safe",
    description: "Checks for weak Diffie-Hellman parameters (Logjam)",
    usage: "nmap --script ssl-dh-params -p 443 <target>"
  },
  {
    name: "smb-vuln-ms17-010",
    category: "vuln",
    description: "Detects EternalBlue SMB vulnerability (MS17-010)",
    usage: "nmap --script smb-vuln-ms17-010 -p 445 <target>"
  },
  {
    name: "smb-vuln-ms08-067",
    category: "vuln",
    description: "Detects Conficker/MS08-067 SMB vulnerability",
    usage: "nmap --script smb-vuln-ms08-067 -p 445 <target>"
  },
  {
    name: "smb-os-discovery",
    category: "default, safe",
    description: "Discovers OS, computer name, domain, and workgroup via SMB",
    usage: "nmap --script smb-os-discovery -p 445 <target>"
  },
  {
    name: "smb-enum-shares",
    category: "discovery, intrusive",
    description: "Enumerates SMB shares and their access permissions",
    usage: "nmap --script smb-enum-shares -p 445 <target>"
  },
  {
    name: "smb-enum-users",
    category: "discovery, intrusive",
    description: "Enumerates user accounts via SMB",
    usage: "nmap --script smb-enum-users -p 445 <target>"
  },
  {
    name: "smb-brute",
    category: "brute",
    description: "Performs brute-force password guessing against SMB",
    usage: "nmap --script smb-brute -p 445 <target>"
  },
  {
    name: "dns-brute",
    category: "discovery, intrusive",
    description: "Brute-forces DNS subdomains via a wordlist",
    usage: "nmap --script dns-brute --script-args dns-brute.domain=example.com <target>"
  },
  {
    name: "dns-zone-transfer",
    category: "discovery",
    description: "Attempts a DNS zone transfer (AXFR) from the name server",
    usage: "nmap --script dns-zone-transfer --script-args dns-zone-transfer.domain=example.com -p 53 <target>"
  },
  {
    name: "dns-cache-snoop",
    category: "discovery, intrusive",
    description: "Checks DNS server cache for recently resolved domains",
    usage: "nmap --script dns-cache-snoop -p 53 <target>"
  },
  {
    name: "vulners",
    category: "vuln, external",
    description: "Queries the Vulners database for known CVEs matching detected services",
    usage: "nmap -sV --script vulners -p- <target>"
  },
  {
    name: "vulscan",
    category: "vuln, external",
    description: "Searches multiple vulnerability databases for version-based CVEs",
    usage: "nmap -sV --script vulscan --script-args vulscandb=cve.csv <target>"
  },
  {
    name: "ftp-anon",
    category: "default, safe",
    description: "Checks if FTP server allows anonymous login",
    usage: "nmap --script ftp-anon -p 21 <target>"
  },
  {
    name: "ftp-bounce",
    category: "default, safe",
    description: "Checks if FTP server is vulnerable to bounce attacks",
    usage: "nmap --script ftp-bounce -p 21 <target>"
  },
  {
    name: "ftp-brute",
    category: "brute",
    description: "Performs brute-force password guessing against FTP",
    usage: "nmap --script ftp-brute -p 21 <target>"
  },
  {
    name: "ssh-brute",
    category: "brute",
    description: "Performs brute-force password guessing against SSH",
    usage: "nmap --script ssh-brute -p 22 <target>"
  },
  {
    name: "ssh-hostkey",
    category: "default, safe",
    description: "Retrieves SSH host key fingerprints",
    usage: "nmap --script ssh-hostkey -p 22 <target>"
  },
  {
    name: "ssh-auth-methods",
    category: "auth, safe",
    description: "Enumerates authentication methods supported by the SSH server",
    usage: "nmap --script ssh-auth-methods -p 22 <target>"
  },
  {
    name: "smtp-commands",
    category: "default, safe",
    description: "Lists SMTP commands supported by the mail server",
    usage: "nmap --script smtp-commands -p 25 <target>"
  },
  {
    name: "smtp-open-relay",
    category: "discovery",
    description: "Tests if an SMTP server is configured as an open relay",
    usage: "nmap --script smtp-open-relay -p 25 <target>"
  },
  {
    name: "smtp-enum-users",
    category: "discovery, intrusive",
    description: "Enumerates valid email users via VRFY, EXPN, or RCPT TO commands",
    usage: "nmap --script smtp-enum-users -p 25 <target>"
  },
  {
    name: "snmp-brute",
    category: "brute",
    description: "Brute-forces SNMP community strings",
    usage: "nmap --script snmp-brute -p 161 <target>"
  },
  {
    name: "snmp-info",
    category: "default, safe",
    description: "Extracts system information via SNMP (sysDescr, sysContact, etc.)",
    usage: "nmap --script snmp-info -sU -p 161 <target>"
  },
  {
    name: "snmp-sysdescr",
    category: "default, safe",
    description: "Retrieves the SNMP system description string",
    usage: "nmap --script snmp-sysdescr -sU -p 161 <target>"
  },
  {
    name: "mysql-info",
    category: "default, safe",
    description: "Retrieves MySQL server version, protocol, and capabilities",
    usage: "nmap --script mysql-info -p 3306 <target>"
  },
  {
    name: "mysql-brute",
    category: "brute",
    description: "Performs brute-force password guessing against MySQL",
    usage: "nmap --script mysql-brute -p 3306 <target>"
  },
  {
    name: "mysql-databases",
    category: "discovery",
    description: "Lists accessible MySQL databases with valid credentials",
    usage: "nmap --script mysql-databases --script-args mysqluser=root,mysqlpass=pass -p 3306 <target>"
  },
  {
    name: "ms-sql-info",
    category: "default, safe",
    description: "Retrieves Microsoft SQL Server instance information",
    usage: "nmap --script ms-sql-info -p 1433 <target>"
  },
  {
    name: "ms-sql-brute",
    category: "brute",
    description: "Performs brute-force password guessing against MSSQL",
    usage: "nmap --script ms-sql-brute -p 1433 <target>"
  },
  {
    name: "mongodb-info",
    category: "default, safe",
    description: "Retrieves MongoDB server build info and status",
    usage: "nmap --script mongodb-info -p 27017 <target>"
  },
  {
    name: "mongodb-databases",
    category: "discovery",
    description: "Lists MongoDB databases when authentication is not required",
    usage: "nmap --script mongodb-databases -p 27017 <target>"
  },
  {
    name: "redis-info",
    category: "default, safe",
    description: "Retrieves Redis server information and configuration",
    usage: "nmap --script redis-info -p 6379 <target>"
  },
  {
    name: "redis-brute",
    category: "brute",
    description: "Performs brute-force password guessing against Redis",
    usage: "nmap --script redis-brute -p 6379 <target>"
  },
  {
    name: "ldap-rootdse",
    category: "discovery, safe",
    description: "Retrieves LDAP root DSE information",
    usage: "nmap --script ldap-rootdse -p 389 <target>"
  },
  {
    name: "ldap-brute",
    category: "brute",
    description: "Performs brute-force credential guessing against LDAP",
    usage: "nmap --script ldap-brute -p 389 <target>"
  },
  {
    name: "rdp-enum-encryption",
    category: "discovery, safe",
    description: "Enumerates encryption protocols supported by RDP",
    usage: "nmap --script rdp-enum-encryption -p 3389 <target>"
  },
  {
    name: "rdp-vuln-ms12-020",
    category: "vuln",
    description: "Detects MS12-020 RDP denial-of-service vulnerability",
    usage: "nmap --script rdp-vuln-ms12-020 -p 3389 <target>"
  },
  {
    name: "vnc-brute",
    category: "brute",
    description: "Performs brute-force password guessing against VNC",
    usage: "nmap --script vnc-brute -p 5900 <target>"
  },
  {
    name: "vnc-info",
    category: "default, safe",
    description: "Retrieves VNC server protocol version and authentication types",
    usage: "nmap --script vnc-info -p 5900 <target>"
  },
  {
    name: "ntp-monlist",
    category: "discovery",
    description: "Retrieves NTP monlist data for amplification testing",
    usage: "nmap --script ntp-monlist -sU -p 123 <target>"
  },
  {
    name: "nbstat",
    category: "default, safe",
    description: "Retrieves NetBIOS names, MAC address, and login user via NetBIOS",
    usage: "nmap --script nbstat -sU -p 137 <target>"
  }
];


/**
 * WIRESHARK_FILTERS -- 55 commonly used Wireshark display filters with
 * name, filter syntax, and description.
 */
const WIRESHARK_FILTERS = [
  {
    name: "HTTP Traffic",
    filter: "http",
    description: "Display all HTTP protocol traffic"
  },
  {
    name: "HTTP GET Requests",
    filter: "http.request.method == \"GET\"",
    description: "Show only HTTP GET request packets"
  },
  {
    name: "HTTP POST Requests",
    filter: "http.request.method == \"POST\"",
    description: "Show only HTTP POST request packets"
  },
  {
    name: "HTTP Response Codes",
    filter: "http.response.code >= 400",
    description: "Display HTTP error responses (4xx and 5xx)"
  },
  {
    name: "HTTP by Host",
    filter: "http.host contains \"example.com\"",
    description: "Filter HTTP traffic to a specific hostname"
  },
  {
    name: "HTTPS/TLS Traffic",
    filter: "tls",
    description: "Display all TLS encrypted traffic"
  },
  {
    name: "TLS Handshake",
    filter: "tls.handshake",
    description: "Show TLS handshake messages (Client Hello, Server Hello, etc.)"
  },
  {
    name: "TLS Client Hello",
    filter: "tls.handshake.type == 1",
    description: "Show only TLS Client Hello messages"
  },
  {
    name: "TLS Certificate",
    filter: "tls.handshake.type == 11",
    description: "Show TLS certificate exchange messages"
  },
  {
    name: "TLS Alerts",
    filter: "tls.alert_message",
    description: "Display TLS alert messages indicating errors or warnings"
  },
  {
    name: "DNS Queries",
    filter: "dns",
    description: "Display all DNS traffic (queries and responses)"
  },
  {
    name: "DNS Query Names",
    filter: "dns.qry.name contains \"example\"",
    description: "Filter DNS queries containing a specific domain substring"
  },
  {
    name: "DNS Response Errors",
    filter: "dns.flags.rcode != 0",
    description: "Show DNS responses with error codes (NXDOMAIN, SERVFAIL, etc.)"
  },
  {
    name: "DNS A Records",
    filter: "dns.qry.type == 1",
    description: "Show DNS queries requesting A (IPv4 address) records"
  },
  {
    name: "DNS AAAA Records",
    filter: "dns.qry.type == 28",
    description: "Show DNS queries requesting AAAA (IPv6 address) records"
  },
  {
    name: "DNS Zone Transfer",
    filter: "dns.qry.type == 252",
    description: "Detect DNS zone transfer (AXFR) attempts"
  },
  {
    name: "TCP Traffic",
    filter: "tcp",
    description: "Display all TCP protocol traffic"
  },
  {
    name: "TCP SYN Packets",
    filter: "tcp.flags.syn == 1 && tcp.flags.ack == 0",
    description: "Show TCP SYN packets indicating new connection attempts"
  },
  {
    name: "TCP RST Packets",
    filter: "tcp.flags.reset == 1",
    description: "Show TCP RST packets indicating connection resets"
  },
  {
    name: "TCP Retransmissions",
    filter: "tcp.analysis.retransmission",
    description: "Display TCP retransmitted segments"
  },
  {
    name: "TCP Window Zero",
    filter: "tcp.window_size_value == 0",
    description: "Detect TCP zero window conditions (receiver buffer full)"
  },
  {
    name: "TCP Port Filter",
    filter: "tcp.port == 80",
    description: "Show TCP traffic on a specific port (adjust port number)"
  },
  {
    name: "UDP Traffic",
    filter: "udp",
    description: "Display all UDP protocol traffic"
  },
  {
    name: "UDP Port Filter",
    filter: "udp.port == 53",
    description: "Show UDP traffic on a specific port (adjust port number)"
  },
  {
    name: "ARP Traffic",
    filter: "arp",
    description: "Display all ARP traffic for MAC-to-IP mapping"
  },
  {
    name: "ARP Requests",
    filter: "arp.opcode == 1",
    description: "Show ARP request packets (who-has)"
  },
  {
    name: "ARP Replies",
    filter: "arp.opcode == 2",
    description: "Show ARP reply packets (is-at)"
  },
  {
    name: "Gratuitous ARP",
    filter: "arp.isgratuitous == 1",
    description: "Detect gratuitous ARP packets that may indicate ARP spoofing"
  },
  {
    name: "ICMP Traffic",
    filter: "icmp",
    description: "Display all ICMP traffic (ping, traceroute, errors)"
  },
  {
    name: "ICMP Echo Request",
    filter: "icmp.type == 8",
    description: "Show ICMP echo request (ping) packets"
  },
  {
    name: "ICMP Echo Reply",
    filter: "icmp.type == 0",
    description: "Show ICMP echo reply (pong) packets"
  },
  {
    name: "ICMP Unreachable",
    filter: "icmp.type == 3",
    description: "Show ICMP destination unreachable messages"
  },
  {
    name: "SMB Traffic",
    filter: "smb || smb2",
    description: "Display all SMB/SMB2 file sharing traffic"
  },
  {
    name: "SMB Tree Connect",
    filter: "smb2.cmd == 3",
    description: "Show SMB2 tree connect requests (share access)"
  },
  {
    name: "SMB File Operations",
    filter: "smb2.cmd == 5",
    description: "Show SMB2 create/open file operations"
  },
  {
    name: "DHCP Traffic",
    filter: "dhcp",
    description: "Display all DHCP lease negotiation traffic"
  },
  {
    name: "DHCP Discover",
    filter: "dhcp.option.dhcp == 1",
    description: "Show DHCP Discover messages from clients seeking an IP"
  },
  {
    name: "DHCP Offer",
    filter: "dhcp.option.dhcp == 2",
    description: "Show DHCP Offer messages from servers"
  },
  {
    name: "FTP Traffic",
    filter: "ftp",
    description: "Display all FTP command channel traffic"
  },
  {
    name: "FTP Data",
    filter: "ftp-data",
    description: "Display FTP data channel file transfers"
  },
  {
    name: "FTP Credentials",
    filter: "ftp.request.command == \"USER\" || ftp.request.command == \"PASS\"",
    description: "Capture FTP username and password commands"
  },
  {
    name: "SSH Traffic",
    filter: "ssh",
    description: "Display all SSH encrypted traffic"
  },
  {
    name: "Telnet Traffic",
    filter: "telnet",
    description: "Display all Telnet cleartext remote access traffic"
  },
  {
    name: "SMTP Traffic",
    filter: "smtp",
    description: "Display all SMTP email traffic"
  },
  {
    name: "Source IP Filter",
    filter: "ip.src == 192.168.1.100",
    description: "Show packets from a specific source IP (adjust address)"
  },
  {
    name: "Destination IP Filter",
    filter: "ip.dst == 10.0.0.1",
    description: "Show packets to a specific destination IP (adjust address)"
  },
  {
    name: "IP Conversation",
    filter: "ip.addr == 192.168.1.100 && ip.addr == 10.0.0.1",
    description: "Show all packets between two specific IP addresses"
  },
  {
    name: "Subnet Filter",
    filter: "ip.addr == 192.168.1.0/24",
    description: "Show all traffic from or to a specific subnet"
  },
  {
    name: "Broadcast Traffic",
    filter: "eth.dst == ff:ff:ff:ff:ff:ff",
    description: "Display all Ethernet broadcast frames"
  },
  {
    name: "VLAN Tagged Traffic",
    filter: "vlan",
    description: "Display 802.1Q VLAN tagged frames"
  },
  {
    name: "SIP Traffic",
    filter: "sip",
    description: "Display all SIP VoIP signaling traffic"
  },
  {
    name: "RTP Traffic",
    filter: "rtp",
    description: "Display RTP real-time media streams (VoIP audio/video)"
  },
  {
    name: "SNMP Traffic",
    filter: "snmp",
    description: "Display all SNMP management traffic"
  },
  {
    name: "NTP Traffic",
    filter: "ntp",
    description: "Display all NTP time synchronization traffic"
  },
  {
    name: "Malformed Packets",
    filter: "_ws.malformed",
    description: "Show packets that Wireshark could not fully parse"
  }
];


// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/**
 * isPrivateIP -- Returns true if the given IPv4 address string falls within
 * RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) or
 * is a loopback address (127.0.0.0/8).
 *
 * @param {string} ip - Dotted-decimal IPv4 address
 * @returns {boolean}
 */
function isPrivateIP(ip) {
  if (typeof ip !== "string") {
    return false;
  }

  const parts = ip.split(".");
  if (parts.length !== 4) {
    return false;
  }

  const octets = parts.map(Number);

  // Validate each octet is an integer in 0-255
  for (let i = 0; i < 4; i++) {
    if (!Number.isInteger(octets[i]) || octets[i] < 0 || octets[i] > 255) {
      return false;
    }
  }

  const [a, b] = octets;

  // 127.0.0.0/8 -- loopback
  if (a === 127) {
    return true;
  }

  // 10.0.0.0/8 -- Class A private
  if (a === 10) {
    return true;
  }

  // 172.16.0.0/12 -- Class B private (172.16.x.x through 172.31.x.x)
  if (a === 172 && b >= 16 && b <= 31) {
    return true;
  }

  // 192.168.0.0/16 -- Class C private
  if (a === 192 && b === 168) {
    return true;
  }

  return false;
}


/**
 * cidrToRange -- Parses a CIDR notation string (e.g. "192.168.1.0/24") and
 * returns the network address, broadcast address, first and last usable
 * host addresses, and total number of addresses in the block.
 *
 * @param {string} cidr - CIDR notation string, e.g. "10.0.0.0/8"
 * @returns {{ network: string, broadcast: string, first: string, last: string, size: number }}
 */
function cidrToRange(cidr) {
  if (typeof cidr !== "string" || !cidr.includes("/")) {
    throw new Error("Invalid CIDR notation: expected format like 192.168.1.0/24");
  }

  const [ipStr, prefixStr] = cidr.split("/");
  const prefix = parseInt(prefixStr, 10);

  if (isNaN(prefix) || prefix < 0 || prefix > 32) {
    throw new Error("Invalid CIDR prefix length: must be between 0 and 32");
  }

  const parts = ipStr.split(".");
  if (parts.length !== 4) {
    throw new Error("Invalid IP address in CIDR notation");
  }

  const octets = parts.map(Number);
  for (let i = 0; i < 4; i++) {
    if (!Number.isInteger(octets[i]) || octets[i] < 0 || octets[i] > 255) {
      throw new Error("Invalid octet in IP address: " + parts[i]);
    }
  }

  // Convert IP to 32-bit unsigned integer
  const ipNum = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;

  // Build the subnet mask and its inverse (host mask)
  const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
  const hostMask = (~mask) >>> 0;

  // Network and broadcast addresses
  const networkNum = (ipNum & mask) >>> 0;
  const broadcastNum = (networkNum | hostMask) >>> 0;

  // Total addresses in the block
  const size = hostMask + 1;

  // First and last usable host addresses
  // For /31 and /32 blocks the concept of "usable" differs, but we still
  // compute them consistently: first = network + 1, last = broadcast - 1,
  // clamped to the network range.
  let firstNum, lastNum;
  if (prefix >= 31) {
    firstNum = networkNum;
    lastNum = broadcastNum;
  } else {
    firstNum = networkNum + 1;
    lastNum = broadcastNum - 1;
  }

  /**
   * Convert a 32-bit unsigned integer back to dotted-decimal string.
   */
  function numToIP(num) {
    return [
      (num >>> 24) & 0xFF,
      (num >>> 16) & 0xFF,
      (num >>> 8) & 0xFF,
      num & 0xFF
    ].join(".");
  }

  return {
    network: numToIP(networkNum),
    broadcast: numToIP(broadcastNum),
    first: numToIP(firstNum),
    last: numToIP(lastNum),
    size: size
  };
}


/**
 * reverseIP -- Reverses the octets of an IPv4 address for use in DNS PTR
 * (reverse DNS) lookups. For example, "192.168.1.10" becomes
 * "10.1.168.192".
 *
 * @param {string} ip - Dotted-decimal IPv4 address
 * @returns {string} The reversed IP string
 */
function reverseIP(ip) {
  if (typeof ip !== "string") {
    throw new Error("Expected a string IP address");
  }

  const parts = ip.split(".");
  if (parts.length !== 4) {
    throw new Error("Invalid IPv4 address: expected four octets separated by dots");
  }

  // Validate each part is a number 0-255
  for (let i = 0; i < 4; i++) {
    const n = Number(parts[i]);
    if (!Number.isInteger(n) || n < 0 || n > 255) {
      throw new Error("Invalid octet in IP address: " + parts[i]);
    }
  }

  return parts.reverse().join(".");
}


// ---------------------------------------------------------------------------
// Module exports
// ---------------------------------------------------------------------------

module.exports = { PROTOCOLS, NMAP_SCRIPTS, WIRESHARK_FILTERS, isPrivateIP, cidrToRange, reverseIP };
