"use strict";

// ---------------------------------------------------------------------------
// nmap-parser.js -- Nmap output parser, vulnerability identifier, and
//                   follow-up recommendation engine for Darknode Nexus.
//
// Parses both XML (-oX) and greppable (-oG) nmap output into a unified
// internal representation, then layers vulnerability identification and
// actionable next-step suggestions on top.
// ---------------------------------------------------------------------------

const { EventEmitter } = require("events");

// ============================= CONSTANTS ===================================

/**
 * SERVICE_VULN_DB -- A database mapping service name + version patterns to
 * known vulnerability information.  Each entry contains:
 *   - pattern   : RegExp source string matched against "service/version"
 *   - cve       : Representative CVE identifier(s)
 *   - severity  : "critical" | "high" | "medium" | "low" | "info"
 *   - summary   : One-line description
 *   - remediation : Short remediation guidance
 */
const SERVICE_VULN_DB = [
  // --- Apache HTTP Server ---
  {
    pattern: "apache httpd/2\\.4\\.(0|[1-9]|1[0-9]|2[0-9]|3[0-9]|4[0-9])($|\\s)",
    cve: ["CVE-2021-44790", "CVE-2021-42013"],
    severity: "critical",
    summary: "Apache HTTP Server <2.4.50 path traversal and buffer overflow",
    remediation: "Upgrade to Apache HTTP Server 2.4.54 or later"
  },
  {
    pattern: "apache httpd/2\\.4\\.5[0-2]($|\\s)",
    cve: ["CVE-2022-31813"],
    severity: "high",
    summary: "Apache HTTP Server 2.4.50-2.4.52 mod_proxy X-Forwarded-For bypass",
    remediation: "Upgrade to Apache HTTP Server 2.4.54 or later"
  },
  {
    pattern: "apache httpd/2\\.2\\.",
    cve: ["CVE-2017-9798", "CVE-2017-7679"],
    severity: "critical",
    summary: "Apache HTTP Server 2.2.x is end-of-life with multiple unpatched vulns",
    remediation: "Migrate to Apache HTTP Server 2.4.x branch immediately"
  },
  // --- Nginx ---
  {
    pattern: "nginx/1\\.(0|1|2|3|4|5|6|7|8|9|1[0-9])\\.",
    cve: ["CVE-2021-23017"],
    severity: "high",
    summary: "Nginx <1.20.1 DNS resolver off-by-one heap write",
    remediation: "Upgrade to Nginx 1.24.x or later"
  },
  {
    pattern: "nginx/1\\.2[0-1]\\.[0-1]($|\\s)",
    cve: ["CVE-2022-41741", "CVE-2022-41742"],
    severity: "high",
    summary: "Nginx 1.20-1.21 mp4 module memory corruption",
    remediation: "Upgrade to Nginx 1.23.2+ or 1.22.1+"
  },
  // --- OpenSSH ---
  {
    pattern: "openssh[_ ]([1-6]\\.|7\\.[0-5]($|[^0-9]))",
    cve: ["CVE-2016-10009", "CVE-2016-10010"],
    severity: "high",
    summary: "OpenSSH <7.6 agent forwarding arbitrary library loading",
    remediation: "Upgrade to OpenSSH 9.x"
  },
  {
    pattern: "openssh[_ ]7\\.[6-9]($|[^0-9])",
    cve: ["CVE-2018-15473"],
    severity: "medium",
    summary: "OpenSSH 7.6-7.9 user enumeration via malformed packets",
    remediation: "Upgrade to OpenSSH 8.x or later"
  },
  {
    pattern: "openssh[_ ]8\\.[0-7]($|[^0-9])",
    cve: ["CVE-2021-41617"],
    severity: "medium",
    summary: "OpenSSH 8.0-8.7 privilege escalation via AuthorizedKeysCommand",
    remediation: "Upgrade to OpenSSH 8.8 or later"
  },
  {
    pattern: "openssh[_ ]8\\.(8|9)($|[^0-9])",
    cve: ["CVE-2023-38408"],
    severity: "medium",
    summary: "OpenSSH 8.8-8.9 PKCS#11 remote code execution via agent",
    remediation: "Upgrade to OpenSSH 9.3p2 or later"
  },
  {
    pattern: "openssh[_ ]9\\.[0-2]($|[^0-9])",
    cve: ["CVE-2023-38408"],
    severity: "medium",
    summary: "OpenSSH 9.0-9.2 PKCS#11 feature remote code execution",
    remediation: "Upgrade to OpenSSH 9.3p2 or later"
  },
  // --- ProFTPD ---
  {
    pattern: "proftpd/1\\.3\\.[0-5]($|[a-e])",
    cve: ["CVE-2019-12815", "CVE-2015-3306"],
    severity: "critical",
    summary: "ProFTPD 1.3.0-1.3.5e arbitrary file copy / remote code execution",
    remediation: "Upgrade to ProFTPD 1.3.8 or later"
  },
  {
    pattern: "proftpd/1\\.3\\.6($|[^0-9])",
    cve: ["CVE-2019-12815"],
    severity: "high",
    summary: "ProFTPD 1.3.6 mod_copy arbitrary file copy",
    remediation: "Upgrade to ProFTPD 1.3.8 or later"
  },
  // --- vsftpd ---
  {
    pattern: "vsftpd 2\\.3\\.4",
    cve: ["CVE-2011-2523"],
    severity: "critical",
    summary: "vsftpd 2.3.4 backdoor command execution",
    remediation: "Upgrade to vsftpd 3.x immediately"
  },
  {
    pattern: "vsftpd (2\\.[0-2]|1\\.)",
    cve: ["CVE-2011-0762"],
    severity: "high",
    summary: "vsftpd <2.3 denial of service via crafted glob expression",
    remediation: "Upgrade to vsftpd 3.x"
  },
  // --- MySQL ---
  {
    pattern: "mysql/5\\.5\\.",
    cve: ["CVE-2016-6662", "CVE-2012-2122"],
    severity: "critical",
    summary: "MySQL 5.5.x is end-of-life with multiple critical vulns",
    remediation: "Migrate to MySQL 8.x"
  },
  {
    pattern: "mysql/5\\.6\\.",
    cve: ["CVE-2016-6662"],
    severity: "high",
    summary: "MySQL 5.6.x is end-of-life",
    remediation: "Migrate to MySQL 8.x"
  },
  {
    pattern: "mysql/5\\.7\\.([0-9]|[12][0-9]|3[0-6])($|[^0-9])",
    cve: ["CVE-2020-14775", "CVE-2020-14812"],
    severity: "high",
    summary: "MySQL 5.7.0-5.7.36 multiple server vulnerabilities",
    remediation: "Upgrade to MySQL 5.7.40+ or migrate to 8.x"
  },
  {
    pattern: "mysql/8\\.0\\.([0-9]|[12][0-9])($|[^0-9])",
    cve: ["CVE-2021-2307", "CVE-2021-2304"],
    severity: "medium",
    summary: "MySQL 8.0.0-8.0.29 multiple vulnerabilities",
    remediation: "Upgrade to MySQL 8.0.33 or later"
  },
  // --- MariaDB ---
  {
    pattern: "mariadb/10\\.([0-3])\\.",
    cve: ["CVE-2021-27928"],
    severity: "high",
    summary: "MariaDB 10.0-10.3 end-of-life or writable-plugin-dir RCE",
    remediation: "Upgrade to MariaDB 10.11.x or later"
  },
  {
    pattern: "mariadb/10\\.(4|5)\\.([0-9]|1[0-7])($|[^0-9])",
    cve: ["CVE-2022-32084"],
    severity: "medium",
    summary: "MariaDB 10.4/10.5 segfault via crafted query",
    remediation: "Upgrade to latest MariaDB 10.5.x or migrate to 10.11.x"
  },
  // --- PostgreSQL ---
  {
    pattern: "postgresql/(9\\.[0-5]|8\\.)",
    cve: ["CVE-2018-1058", "CVE-2017-7547"],
    severity: "critical",
    summary: "PostgreSQL 8.x/9.0-9.5 end-of-life with unpatched vulns",
    remediation: "Migrate to PostgreSQL 15.x or later"
  },
  {
    pattern: "postgresql/9\\.6\\.",
    cve: ["CVE-2018-1058"],
    severity: "high",
    summary: "PostgreSQL 9.6 end-of-life since Nov 2021",
    remediation: "Migrate to PostgreSQL 15.x or later"
  },
  {
    pattern: "postgresql/1[0-2]\\.",
    cve: ["CVE-2022-2625"],
    severity: "medium",
    summary: "PostgreSQL 10-12 extensions can replace objects in other schemas",
    remediation: "Upgrade to latest minor release or migrate to 15.x+"
  },
  // --- Redis ---
  {
    pattern: "redis/([1-4]\\.|5\\.[0-9]($|[^0-9])|5\\.0\\.([0-9]|1[0-3])($|[^0-9]))",
    cve: ["CVE-2021-32761", "CVE-2021-32675"],
    severity: "high",
    summary: "Redis <6.0 multiple integer overflow and DoS vulnerabilities",
    remediation: "Upgrade to Redis 7.x"
  },
  {
    pattern: "redis/6\\.0\\.([0-9]|1[0-5])($|[^0-9])",
    cve: ["CVE-2022-24735", "CVE-2022-24736"],
    severity: "medium",
    summary: "Redis 6.0.x Lua scripting and denial of service issues",
    remediation: "Upgrade to Redis 6.0.20 or 7.x"
  },
  {
    pattern: "redis/6\\.2\\.([0-6])($|[^0-9])",
    cve: ["CVE-2022-24735"],
    severity: "medium",
    summary: "Redis 6.2.0-6.2.6 Lua sandbox escape",
    remediation: "Upgrade to Redis 6.2.14 or 7.x"
  },
  // --- MongoDB ---
  {
    pattern: "mongodb/(2\\.|3\\.[0-4])",
    cve: ["CVE-2017-2665"],
    severity: "critical",
    summary: "MongoDB 2.x/3.0-3.4 end-of-life with multiple vulns",
    remediation: "Migrate to MongoDB 6.x or later"
  },
  {
    pattern: "mongodb/3\\.6\\.",
    cve: ["CVE-2019-2390"],
    severity: "high",
    summary: "MongoDB 3.6 end-of-life since April 2021",
    remediation: "Migrate to MongoDB 6.x or later"
  },
  {
    pattern: "mongodb/4\\.0\\.",
    cve: ["CVE-2020-7921"],
    severity: "medium",
    summary: "MongoDB 4.0 end-of-life",
    remediation: "Migrate to MongoDB 6.x or later"
  },
  // --- Microsoft SQL Server ---
  {
    pattern: "ms-sql-s.*2012",
    cve: ["CVE-2012-2122"],
    severity: "critical",
    summary: "SQL Server 2012 is end-of-extended-support",
    remediation: "Migrate to SQL Server 2022"
  },
  {
    pattern: "ms-sql-s.*2014",
    cve: ["CVE-2015-1763"],
    severity: "high",
    summary: "SQL Server 2014 approaching end-of-life",
    remediation: "Migrate to SQL Server 2022"
  },
  {
    pattern: "ms-sql-s.*2016",
    cve: ["CVE-2017-8516"],
    severity: "medium",
    summary: "SQL Server 2016 information disclosure",
    remediation: "Apply latest CU or migrate to SQL Server 2022"
  },
  // --- SMB / Samba ---
  {
    pattern: "samba smbd/3\\.",
    cve: ["CVE-2017-7494"],
    severity: "critical",
    summary: "Samba 3.x remote code execution via writable share",
    remediation: "Upgrade to Samba 4.17+ or apply mitigations"
  },
  {
    pattern: "samba smbd/4\\.([0-9]|1[0-3])\\.",
    cve: ["CVE-2021-44142"],
    severity: "critical",
    summary: "Samba 4.0-4.13 out-of-bounds heap read/write via VFS module",
    remediation: "Upgrade to Samba 4.17 or later"
  },
  {
    pattern: "samba smbd/4\\.1[4-5]\\.",
    cve: ["CVE-2022-45141"],
    severity: "high",
    summary: "Samba 4.14-4.15 Heimdal KDC RC4 ticket issuance",
    remediation: "Upgrade to Samba 4.17 or later"
  },
  // --- Microsoft IIS ---
  {
    pattern: "microsoft iis httpd/6\\.0",
    cve: ["CVE-2017-7269"],
    severity: "critical",
    summary: "IIS 6.0 WebDAV ScStoragePathFromUrl buffer overflow",
    remediation: "Migrate off Windows Server 2003 / IIS 6"
  },
  {
    pattern: "microsoft iis httpd/7\\.[05]",
    cve: ["CVE-2010-3972"],
    severity: "high",
    summary: "IIS 7.0/7.5 FTP service memory corruption",
    remediation: "Upgrade to IIS 10.x"
  },
  {
    pattern: "microsoft iis httpd/8\\.",
    cve: ["CVE-2014-4078"],
    severity: "medium",
    summary: "IIS 8.x request filtering security bypass",
    remediation: "Upgrade to IIS 10.x and apply latest patches"
  },
  // --- OpenSSL ---
  {
    pattern: "openssl/(0\\.|1\\.0\\.0|1\\.0\\.1[a-n]?($|[^a-z]))",
    cve: ["CVE-2014-0160"],
    severity: "critical",
    summary: "OpenSSL Heartbleed (1.0.1 through 1.0.1f)",
    remediation: "Upgrade to OpenSSL 3.x"
  },
  {
    pattern: "openssl/1\\.0\\.2[a-z]?($|[^a-z])",
    cve: ["CVE-2016-2107", "CVE-2022-0778"],
    severity: "high",
    summary: "OpenSSL 1.0.2 end-of-life with multiple vulns",
    remediation: "Upgrade to OpenSSL 3.x"
  },
  {
    pattern: "openssl/1\\.1\\.0",
    cve: ["CVE-2017-3735"],
    severity: "high",
    summary: "OpenSSL 1.1.0 end-of-life",
    remediation: "Upgrade to OpenSSL 3.x"
  },
  {
    pattern: "openssl/1\\.1\\.1[a-s]?($|[^a-z])",
    cve: ["CVE-2022-0778"],
    severity: "medium",
    summary: "OpenSSL 1.1.1 approaching end-of-life",
    remediation: "Upgrade to OpenSSL 3.1.x or later"
  },
  {
    pattern: "openssl/3\\.0\\.[0-6]($|[^0-9])",
    cve: ["CVE-2022-3602", "CVE-2022-3786"],
    severity: "high",
    summary: "OpenSSL 3.0.0-3.0.6 X.509 certificate name constraint overflow",
    remediation: "Upgrade to OpenSSL 3.0.12+ or 3.1.x"
  },
  // --- Exim ---
  {
    pattern: "exim smtpd/4\\.([0-8]|9[0-3])",
    cve: ["CVE-2019-10149"],
    severity: "critical",
    summary: "Exim <4.94 remote command execution (The Return of the WIZard)",
    remediation: "Upgrade to Exim 4.96 or later"
  },
  {
    pattern: "exim smtpd/4\\.94($|\\.0)",
    cve: ["CVE-2021-27216"],
    severity: "high",
    summary: "Exim 4.94 local privilege escalation",
    remediation: "Upgrade to Exim 4.96 or later"
  },
  // --- Postfix ---
  {
    pattern: "postfix smtpd/(2\\.|3\\.0\\.[0-3]($|[^0-9]))",
    cve: ["CVE-2017-10140"],
    severity: "medium",
    summary: "Postfix <3.0.4 Berkeley DB read settings from CWD",
    remediation: "Upgrade to Postfix 3.7.x or later"
  },
  {
    pattern: "postfix smtpd/3\\.[1-5]\\.",
    cve: ["CVE-2023-51764"],
    severity: "medium",
    summary: "Postfix 3.1-3.5 SMTP smuggling",
    remediation: "Upgrade to Postfix 3.8.4+ or apply mitigations"
  },
  // --- Dovecot ---
  {
    pattern: "dovecot/(1\\.|2\\.([0-2]|3\\.([0-9]|1[0-5])))",
    cve: ["CVE-2022-30550"],
    severity: "high",
    summary: "Dovecot <2.3.16 privilege escalation when auth and service user differ",
    remediation: "Upgrade to Dovecot 2.3.21 or later"
  },
  // --- Bind / named ---
  {
    pattern: "isc bind/9\\.([0-9]|1[0-5])\\.",
    cve: ["CVE-2020-8617"],
    severity: "high",
    summary: "BIND 9.0-9.15 assertion failure via TSIG check",
    remediation: "Upgrade to BIND 9.18.x or later"
  },
  {
    pattern: "isc bind/9\\.16\\.([0-9]|[1-2][0-9]|3[0-5])($|[^0-9])",
    cve: ["CVE-2022-3094"],
    severity: "medium",
    summary: "BIND 9.16.0-9.16.35 memory leak via UPDATE flood",
    remediation: "Upgrade to BIND 9.16.37 or 9.18.x"
  },
  // --- Tomcat ---
  {
    pattern: "apache tomcat/([5-7]\\.|8\\.0\\.)",
    cve: ["CVE-2020-1938"],
    severity: "critical",
    summary: "Tomcat 5-8.0 end-of-life, Ghostcat AJP file read/inclusion",
    remediation: "Migrate to Tomcat 10.x"
  },
  {
    pattern: "apache tomcat/8\\.5\\.([0-9]|[1-7][0-9]|8[0-4])($|[^0-9])",
    cve: ["CVE-2022-42252"],
    severity: "high",
    summary: "Tomcat 8.5.0-8.5.84 request smuggling via invalid header",
    remediation: "Upgrade to Tomcat 8.5.85+ or migrate to 10.x"
  },
  {
    pattern: "apache tomcat/9\\.0\\.([0-9]|[1-6][0-9]|7[0-1])($|[^0-9])",
    cve: ["CVE-2023-28709"],
    severity: "medium",
    summary: "Tomcat 9.0.0-9.0.71 incomplete DoS fix",
    remediation: "Upgrade to Tomcat 9.0.74 or later"
  },
  // --- PHP ---
  {
    pattern: "php/(5\\.|7\\.0|7\\.1|7\\.2|7\\.3)",
    cve: ["CVE-2019-11043"],
    severity: "critical",
    summary: "PHP 5.x-7.3 end-of-life / env_path_info underflow RCE",
    remediation: "Upgrade to PHP 8.2.x or later"
  },
  {
    pattern: "php/7\\.4\\.([0-9]|[12][0-9]|3[0-2])($|[^0-9])",
    cve: ["CVE-2022-31628"],
    severity: "high",
    summary: "PHP 7.4.x multiple vulnerabilities, approaching EOL",
    remediation: "Upgrade to PHP 8.2.x or later"
  },
  {
    pattern: "php/8\\.0\\.([0-9]|[12][0-9])($|[^0-9])",
    cve: ["CVE-2023-3247"],
    severity: "medium",
    summary: "PHP 8.0.x end-of-life since Nov 2023",
    remediation: "Upgrade to PHP 8.2.x or later"
  },
  {
    pattern: "php/8\\.1\\.([0-9]|1[0-9]|2[0-1])($|[^0-9])",
    cve: ["CVE-2023-3824"],
    severity: "medium",
    summary: "PHP 8.1.0-8.1.21 buffer overflow in phar reading",
    remediation: "Upgrade to PHP 8.1.23 or 8.2.x"
  },
  // --- Elasticsearch ---
  {
    pattern: "elasticsearch/(1\\.|2\\.|5\\.|6\\.)",
    cve: ["CVE-2015-1427", "CVE-2018-17246"],
    severity: "critical",
    summary: "Elasticsearch 1.x-6.x end-of-life with RCE / LFI vulns",
    remediation: "Migrate to Elasticsearch 8.x"
  },
  {
    pattern: "elasticsearch/7\\.([0-9]|1[0-6])\\.",
    cve: ["CVE-2021-22145"],
    severity: "medium",
    summary: "Elasticsearch 7.0-7.16 information disclosure",
    remediation: "Upgrade to Elasticsearch 7.17.x or 8.x"
  },
  // --- Jenkins ---
  {
    pattern: "jenkins/(1\\.|2\\.[0-9]($|[^0-9])|2\\.[1-2][0-9]{2}($|[^0-9]))",
    cve: ["CVE-2019-1003000", "CVE-2018-1000861"],
    severity: "critical",
    summary: "Jenkins <2.300 multiple sandbox bypass RCE",
    remediation: "Upgrade to latest Jenkins LTS"
  },
  {
    parameter: "jenkins/2\\.(3[0-9]{2}|4[01][0-9])($|[^0-9])",
    cve: ["CVE-2024-23897"],
    severity: "critical",
    summary: "Jenkins 2.300-2.419 arbitrary file read via CLI",
    remediation: "Upgrade to Jenkins 2.442+ or LTS 2.426.3+"
  },
  // --- Kubernetes ---
  {
    pattern: "kubernetes/(1\\.(1[0-9]|20)\\.[0-9]+)",
    cve: ["CVE-2021-25741"],
    severity: "high",
    summary: "Kubernetes 1.10-1.20 subpath volume mount race condition",
    remediation: "Upgrade to latest Kubernetes patch release"
  },
  // --- RDP / Microsoft Terminal Services ---
  {
    pattern: "ms-wbt-server",
    cve: ["CVE-2019-0708"],
    severity: "critical",
    summary: "RDP service detected -- check for BlueKeep (CVE-2019-0708)",
    remediation: "Ensure NLA is enabled and system is fully patched"
  },
  // --- telnet ---
  {
    pattern: "telnet",
    cve: [],
    severity: "high",
    summary: "Telnet service transmits credentials in cleartext",
    remediation: "Disable telnet and use SSH instead"
  },
  // --- FTP (generic) ---
  {
    pattern: "^ftp($|\\s)",
    cve: [],
    severity: "medium",
    summary: "FTP service transmits data in cleartext",
    remediation: "Use SFTP or FTPS instead of plain FTP"
  },
  // --- SNMP ---
  {
    pattern: "snmp",
    cve: [],
    severity: "medium",
    summary: "SNMP may expose system information if community strings are weak",
    remediation: "Use SNMPv3 with authentication and encryption"
  },
  // --- Docker ---
  {
    pattern: "docker/(1[0-8]\\.|19\\.0[0-2])",
    cve: ["CVE-2019-5736"],
    severity: "critical",
    summary: "Docker <19.03 runc container escape",
    remediation: "Upgrade to Docker 24.x or later"
  },
  // --- Memcached ---
  {
    pattern: "memcached/1\\.([0-4]|5\\.[0-5])",
    cve: ["CVE-2018-1000115"],
    severity: "high",
    summary: "Memcached <1.5.6 UDP reflection amplification / RCE",
    remediation: "Upgrade to Memcached 1.6.x and disable UDP listener"
  },
  // --- RabbitMQ ---
  {
    pattern: "rabbitmq/(3\\.([0-7]|8\\.([0-9]|1[0-9]|2[0-9])))",
    cve: ["CVE-2022-31008"],
    severity: "medium",
    summary: "RabbitMQ <3.8.30 credential exposure in logs",
    remediation: "Upgrade to RabbitMQ 3.12.x or later"
  },
  // --- Grafana ---
  {
    pattern: "grafana/(3\\.|4\\.|5\\.|6\\.|7\\.|8\\.[0-3])",
    cve: ["CVE-2021-43798"],
    severity: "critical",
    summary: "Grafana <8.3.1 directory traversal (unauthenticated file read)",
    remediation: "Upgrade to Grafana 10.x"
  },
  // --- GitLab ---
  {
    pattern: "gitlab.*(1[0-3]\\.|14\\.[0-9]($|\\.))",
    cve: ["CVE-2021-22205"],
    severity: "critical",
    summary: "GitLab <14.10 unauthenticated RCE via image upload",
    remediation: "Upgrade to latest GitLab release"
  },
  // --- Confluence ---
  {
    pattern: "confluence/(7\\.[0-9]\\.|7\\.1[0-7])",
    cve: ["CVE-2022-26134"],
    severity: "critical",
    summary: "Confluence <7.18 OGNL injection RCE",
    remediation: "Upgrade to latest Confluence release"
  },
  // --- Jira ---
  {
    pattern: "jira/(8\\.[0-9]\\.|8\\.1[0-9])",
    cve: ["CVE-2019-11581"],
    severity: "high",
    summary: "Jira 8.x server-side template injection",
    remediation: "Upgrade to latest Jira release"
  },
  // --- CouchDB ---
  {
    pattern: "couchdb/(1\\.|2\\.0|2\\.1($|\\.[0-1]))",
    cve: ["CVE-2017-12636"],
    severity: "critical",
    summary: "CouchDB <2.1.2 remote code execution via runtime config",
    remediation: "Upgrade to CouchDB 3.x"
  },
  // --- Varnish ---
  {
    pattern: "varnish/(4\\.|5\\.|6\\.0\\.([0-7]))",
    cve: ["CVE-2021-36740"],
    severity: "medium",
    summary: "Varnish <6.0.8 HTTP/2 request smuggling",
    remediation: "Upgrade to Varnish 7.x"
  },
  // --- HAProxy ---
  {
    pattern: "haproxy/(1\\.[0-7]|1\\.8\\.([0-9]|[12][0-9])($|[^0-9]))",
    cve: ["CVE-2021-40346"],
    severity: "high",
    summary: "HAProxy <2.0.25 integer overflow request smuggling",
    remediation: "Upgrade to HAProxy 2.8.x or later"
  },
  // --- Squid ---
  {
    pattern: "squid/(3\\.|4\\.([0-9]|1[0-4])($|[^0-9]))",
    cve: ["CVE-2020-15810", "CVE-2020-15811"],
    severity: "high",
    summary: "Squid 3.x/4.x request smuggling and splitting",
    remediation: "Upgrade to Squid 6.x"
  },
  {
    pattern: "squid/5\\.([0-6])($|[^0-9])",
    cve: ["CVE-2023-46847"],
    severity: "high",
    summary: "Squid 5.0-5.6 buffer overflow in HTTP digest auth",
    remediation: "Upgrade to Squid 6.5 or later"
  },
  // --- Webmin ---
  {
    pattern: "webmin/(0\\.|1\\.[0-8])",
    cve: ["CVE-2019-15107"],
    severity: "critical",
    summary: "Webmin <1.930 unauthenticated remote code execution",
    remediation: "Upgrade to Webmin 2.x"
  },
  // --- phpMyAdmin ---
  {
    pattern: "phpmyadmin/(3\\.|4\\.([0-7]|8\\.([0-4])))",
    cve: ["CVE-2018-12613"],
    severity: "high",
    summary: "phpMyAdmin <4.8.5 local file inclusion",
    remediation: "Upgrade to phpMyAdmin 5.x"
  },
  // --- WordPress ---
  {
    pattern: "wordpress/(3\\.|4\\.[0-8])",
    cve: ["CVE-2019-8942", "CVE-2017-8295"],
    severity: "high",
    summary: "WordPress <4.9 multiple vulnerabilities",
    remediation: "Upgrade to latest WordPress release"
  },
  // --- Drupal ---
  {
    pattern: "drupal/(7\\.([0-9]|[1-5][0-9])($|[^0-9]))",
    cve: ["CVE-2018-7600"],
    severity: "critical",
    summary: "Drupal 7 <7.58 remote code execution (Drupalgeddon 2)",
    remediation: "Upgrade to latest Drupal release"
  },
  // --- Node.js ---
  {
    pattern: "node\\.js/(8\\.|10\\.|12\\.|14\\.([0-9]|1[0-7]))",
    cve: ["CVE-2022-32213"],
    severity: "high",
    summary: "Node.js 8-14.17 end-of-life / HTTP request smuggling",
    remediation: "Upgrade to Node.js 20.x LTS or later"
  },
  // --- Lighttpd ---
  {
    pattern: "lighttpd/1\\.4\\.([0-9]|[1-4][0-9]|5[0-1])($|[^0-9])",
    cve: ["CVE-2022-22707"],
    severity: "medium",
    summary: "Lighttpd 1.4.0-1.4.51 use-after-free in mod_extforward",
    remediation: "Upgrade to Lighttpd 1.4.73 or later"
  },
  // --- Nagios ---
  {
    pattern: "nagios/(3\\.|4\\.([0-3]|4\\.[0-5]))",
    cve: ["CVE-2020-28648"],
    severity: "high",
    summary: "Nagios <4.4.6 authenticated RCE",
    remediation: "Upgrade to latest Nagios Core release"
  },
  // --- Zabbix ---
  {
    pattern: "zabbix/(3\\.|4\\.[0-3]|5\\.0\\.([0-9]|[12][0-9])($|[^0-9]))",
    cve: ["CVE-2022-23131"],
    severity: "critical",
    summary: "Zabbix <5.0.30 SAML SSO auth bypass",
    remediation: "Upgrade to Zabbix 6.x or later"
  },
  // --- VNC ---
  {
    pattern: "vnc",
    cve: ["CVE-2019-15681"],
    severity: "medium",
    summary: "VNC service detected -- often weakly authenticated",
    remediation: "Use SSH tunneling for VNC and enforce strong passwords"
  },
  // --- LDAP ---
  {
    pattern: "ldap",
    cve: [],
    severity: "low",
    summary: "LDAP service detected -- verify bind restrictions",
    remediation: "Enforce LDAPS, disable anonymous binds"
  },
  // --- NFS ---
  {
    pattern: "nfs",
    cve: [],
    severity: "medium",
    summary: "NFS service detected -- verify export restrictions",
    remediation: "Review /etc/exports, restrict to specific IPs, use NFSv4 with Kerberos"
  },
  // --- IPMI ---
  {
    pattern: "ipmi",
    cve: ["CVE-2013-4786"],
    severity: "high",
    summary: "IPMI service detected -- cipher zero authentication bypass risk",
    remediation: "Isolate IPMI on a management VLAN, disable cipher zero"
  },
  // --- rsync ---
  {
    pattern: "rsync/(3\\.0|2\\.)",
    cve: ["CVE-2018-5764"],
    severity: "medium",
    summary: "rsync <3.1 path sanitization bypass",
    remediation: "Upgrade to rsync 3.2.x, require authentication"
  },
  // --- CUPS ---
  {
    pattern: "cups/(1\\.|2\\.0\\.([0-3]))",
    cve: ["CVE-2015-1158"],
    severity: "high",
    summary: "CUPS <2.0.4 privilege escalation via web interface",
    remediation: "Upgrade to CUPS 2.4.x, restrict listener to localhost"
  },
  // --- Asterisk ---
  {
    pattern: "asterisk/(1[0-3]\\.|1[4-6]\\.([0-9]|1[0-5])\\.|1[78]\\.)",
    cve: ["CVE-2017-14100"],
    severity: "high",
    summary: "Asterisk PBX <18.x multiple vulnerabilities",
    remediation: "Upgrade to Asterisk 20.x LTS"
  },
  // --- WildFly / JBoss ---
  {
    pattern: "jboss|wildfly/(8\\.|9\\.|10\\.([0-1]))",
    cve: ["CVE-2017-12149"],
    severity: "critical",
    summary: "JBoss/WildFly deserialization remote code execution",
    remediation: "Upgrade to WildFly 30.x or later"
  },
  // --- Oracle WebLogic ---
  {
    pattern: "weblogic/(10\\.|12\\.1|12\\.2\\.1\\.[0-3])",
    cve: ["CVE-2020-14882", "CVE-2019-2725"],
    severity: "critical",
    summary: "WebLogic <12.2.1.4 unauthenticated RCE",
    remediation: "Apply latest Oracle CPU patches or upgrade to 14.x"
  },
  // --- GlassFish ---
  {
    pattern: "glassfish/(3\\.|4\\.0($|[^0-9]))",
    cve: ["CVE-2017-1000028"],
    severity: "high",
    summary: "GlassFish 3.x-4.0 path traversal",
    remediation: "Migrate to Eclipse GlassFish 7.x or Payara"
  },
  // --- Subversion ---
  {
    pattern: "svnserve/(1\\.([0-9]|1[0-3])($|\\.))",
    cve: ["CVE-2020-17525"],
    severity: "medium",
    summary: "Subversion <1.14.1 remote memory corruption",
    remediation: "Upgrade to Subversion 1.14.x or migrate to Git"
  },
];

// Standard port-to-service mapping for heuristic fallback
const PORT_SERVICE_MAP = {
  21: "ftp",
  22: "ssh",
  23: "telnet",
  25: "smtp",
  53: "dns",
  80: "http",
  110: "pop3",
  111: "rpcbind",
  135: "msrpc",
  139: "netbios-ssn",
  143: "imap",
  161: "snmp",
  389: "ldap",
  443: "https",
  445: "microsoft-ds",
  465: "smtps",
  514: "syslog",
  587: "submission",
  631: "ipp",
  636: "ldapssl",
  993: "imaps",
  995: "pop3s",
  1080: "socks",
  1433: "ms-sql-s",
  1434: "ms-sql-m",
  1521: "oracle",
  2049: "nfs",
  2181: "zookeeper",
  3306: "mysql",
  3389: "ms-wbt-server",
  5432: "postgresql",
  5672: "amqp",
  5900: "vnc",
  5984: "couchdb",
  6379: "redis",
  6443: "kubernetes-api",
  8080: "http-proxy",
  8443: "https-alt",
  8888: "http-alt",
  9090: "zeus-admin",
  9200: "elasticsearch",
  11211: "memcached",
  15672: "rabbitmq-mgmt",
  27017: "mongodb",
  50000: "jenkins",
};

// Severity ranking for sorting
const SEVERITY_ORDER = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

// ========================= XML PARSER ======================================

/**
 * parseNmapXML -- Parse nmap -oX XML output into a structured object.
 *
 * @param {string} xml - Raw XML string from nmap -oX
 * @returns {object} Parsed scan result
 */
function parseNmapXML(xml) {
  if (!xml || typeof xml !== "string") {
    throw new Error("parseNmapXML: input must be a non-empty string");
  }

  const result = {
    scanner: "nmap",
    scanInfo: {},
    hosts: [],
    runStats: {},
    rawType: "xml",
  };

  // -- Parse <nmaprun> attributes --
  const nmaprunMatch = xml.match(/<nmaprun\s+([^>]+)>/);
  if (nmaprunMatch) {
    const attrs = _parseXMLAttributes(nmaprunMatch[1]);
    result.scanInfo.scanner = attrs.scanner || "nmap";
    result.scanInfo.args = attrs.args || "";
    result.scanInfo.startTime = attrs.start ? new Date(parseInt(attrs.start, 10) * 1000).toISOString() : null;
    result.scanInfo.startTimestamp = attrs.start ? parseInt(attrs.start, 10) : null;
    result.scanInfo.xmlOutputVersion = attrs.xmloutputversion || "";
    result.scanInfo.version = attrs.version || "";
  }

  // -- Parse <scaninfo> --
  const scanInfoMatch = xml.match(/<scaninfo\s+([^>]+)\/?\s*>/);
  if (scanInfoMatch) {
    const attrs = _parseXMLAttributes(scanInfoMatch[1]);
    result.scanInfo.type = attrs.type || "unknown";
    result.scanInfo.protocol = attrs.protocol || "tcp";
    result.scanInfo.numServices = attrs.numservices ? parseInt(attrs.numservices, 10) : 0;
    result.scanInfo.services = attrs.services || "";
  }

  // -- Parse <host> blocks --
  const hostRegex = /<host\b[^>]*>([\s\S]*?)<\/host>/g;
  let hostMatch;
  while ((hostMatch = hostRegex.exec(xml)) !== null) {
    const hostBlock = hostMatch[1];
    const host = _parseHostBlock(hostBlock);
    if (host) {
      result.hosts.push(host);
    }
  }

  // -- Parse <runstats> --
  const runstatsMatch = xml.match(/<runstats>([\s\S]*?)<\/runstats>/);
  if (runstatsMatch) {
    const statsBlock = runstatsMatch[1];
    const finishedMatch = statsBlock.match(/<finished\s+([^>]+)\/?\s*>/);
    if (finishedMatch) {
      const attrs = _parseXMLAttributes(finishedMatch[1]);
      result.runStats.endTime = attrs.time ? new Date(parseInt(attrs.time, 10) * 1000).toISOString() : null;
      result.runStats.endTimestamp = attrs.time ? parseInt(attrs.time, 10) : null;
      result.runStats.elapsed = attrs.elapsed || "0";
      result.runStats.summary = attrs.summary || "";
      result.runStats.exit = attrs.exit || "success";
    }
    const hostsMatch = statsBlock.match(/<hosts\s+([^>]+)\/?\s*>/);
    if (hostsMatch) {
      const attrs = _parseXMLAttributes(hostsMatch[1]);
      result.runStats.hostsUp = parseInt(attrs.up || "0", 10);
      result.runStats.hostsDown = parseInt(attrs.down || "0", 10);
      result.runStats.hostsTotal = parseInt(attrs.total || "0", 10);
    }
  }

  // Compute duration
  if (result.scanInfo.startTimestamp && result.runStats.endTimestamp) {
    result.runStats.durationSeconds = result.runStats.endTimestamp - result.scanInfo.startTimestamp;
  }

  return result;
}

/**
 * Parse a single <host> XML block.
 * @private
 */
function _parseHostBlock(block) {
  const host = {
    status: "unknown",
    addresses: [],
    hostnames: [],
    ports: [],
    os: [],
    scripts: [],
    uptime: null,
    distance: null,
    trace: [],
  };

  // -- Status --
  const statusMatch = block.match(/<status\s+([^>]+)\/?\s*>/);
  if (statusMatch) {
    const attrs = _parseXMLAttributes(statusMatch[1]);
    host.status = attrs.state || "unknown";
    host.statusReason = attrs.reason || "";
  }

  // -- Addresses --
  const addrRegex = /<address\s+([^>]+)\/?\s*>/g;
  let addrMatch;
  while ((addrMatch = addrRegex.exec(block)) !== null) {
    const attrs = _parseXMLAttributes(addrMatch[1]);
    host.addresses.push({
      addr: attrs.addr || "",
      addrtype: attrs.addrtype || "ipv4",
      vendor: attrs.vendor || "",
    });
  }

  // -- Hostnames --
  const hostnamesMatch = block.match(/<hostnames>([\s\S]*?)<\/hostnames>/);
  if (hostnamesMatch) {
    const hnRegex = /<hostname\s+([^>]+)\/?\s*>/g;
    let hnMatch;
    while ((hnMatch = hnRegex.exec(hostnamesMatch[1])) !== null) {
      const attrs = _parseXMLAttributes(hnMatch[1]);
      host.hostnames.push({
        name: attrs.name || "",
        type: attrs.type || "",
      });
    }
  }

  // -- Ports --
  const portsMatch = block.match(/<ports>([\s\S]*?)<\/ports>/);
  if (portsMatch) {
    // Extra ports summary
    const extraMatch = portsMatch[1].match(/<extraports\s+([^>]+)\/?\s*>/);
    if (extraMatch) {
      const attrs = _parseXMLAttributes(extraMatch[1]);
      host.extraPorts = {
        state: attrs.state || "",
        count: parseInt(attrs.count || "0", 10),
      };
    }

    const portRegex = /<port\s+([^>]*?)>([\s\S]*?)<\/port>/g;
    let portMatch;
    while ((portMatch = portRegex.exec(portsMatch[1])) !== null) {
      const portAttrs = _parseXMLAttributes(portMatch[1]);
      const portBlock = portMatch[2];
      const port = _parsePortBlock(portAttrs, portBlock);
      if (port) {
        host.ports.push(port);
      }
    }
  }

  // -- OS detection --
  const osMatch = block.match(/<os>([\s\S]*?)<\/os>/);
  if (osMatch) {
    const osClassRegex = /<osmatch\s+([^>]+)\/?\s*>/g;
    let osClassMatch;
    while ((osClassMatch = osClassRegex.exec(osMatch[1])) !== null) {
      const attrs = _parseXMLAttributes(osClassMatch[1]);
      host.os.push({
        name: attrs.name || "",
        accuracy: parseInt(attrs.accuracy || "0", 10),
        line: parseInt(attrs.line || "0", 10),
      });
    }
  }

  // -- Host scripts --
  const hostScriptMatch = block.match(/<hostscript>([\s\S]*?)<\/hostscript>/);
  if (hostScriptMatch) {
    host.scripts = _parseScripts(hostScriptMatch[1]);
  }

  // -- Uptime --
  const uptimeMatch = block.match(/<uptime\s+([^>]+)\/?\s*>/);
  if (uptimeMatch) {
    const attrs = _parseXMLAttributes(uptimeMatch[1]);
    host.uptime = {
      seconds: parseInt(attrs.seconds || "0", 10),
      lastboot: attrs.lastboot || "",
    };
  }

  // -- Distance (TTL hops) --
  const distanceMatch = block.match(/<distance\s+([^>]+)\/?\s*>/);
  if (distanceMatch) {
    const attrs = _parseXMLAttributes(distanceMatch[1]);
    host.distance = parseInt(attrs.value || "0", 10);
  }

  // -- Traceroute --
  const traceMatch = block.match(/<trace\b[^>]*>([\s\S]*?)<\/trace>/);
  if (traceMatch) {
    const hopRegex = /<hop\s+([^>]+)\/?\s*>/g;
    let hopMatch;
    while ((hopMatch = hopRegex.exec(traceMatch[1])) !== null) {
      const attrs = _parseXMLAttributes(hopMatch[1]);
      host.trace.push({
        ttl: parseInt(attrs.ttl || "0", 10),
        ipaddr: attrs.ipaddr || "",
        rtt: attrs.rtt || "",
        host: attrs.host || "",
      });
    }
  }

  // Derive primary IP
  const ipv4 = host.addresses.find((a) => a.addrtype === "ipv4");
  const ipv6 = host.addresses.find((a) => a.addrtype === "ipv6");
  host.ip = (ipv4 || ipv6 || host.addresses[0] || {}).addr || "unknown";
  host.mac = (host.addresses.find((a) => a.addrtype === "mac") || {}).addr || "";

  return host;
}

/**
 * Parse a single <port> XML block.
 * @private
 */
function _parsePortBlock(portAttrs, portBlock) {
  const port = {
    portId: parseInt(portAttrs.portid || "0", 10),
    protocol: portAttrs.protocol || "tcp",
    state: "unknown",
    stateReason: "",
    service: {},
    scripts: [],
  };

  // -- State --
  const stateMatch = portBlock.match(/<state\s+([^>]+)\/?\s*>/);
  if (stateMatch) {
    const attrs = _parseXMLAttributes(stateMatch[1]);
    port.state = attrs.state || "unknown";
    port.stateReason = attrs.reason || "";
    port.stateReasonTTL = attrs.reason_ttl || "";
  }

  // -- Service --
  const serviceMatch = portBlock.match(/<service\s+([^>]+)\/?\s*>/);
  if (serviceMatch) {
    const attrs = _parseXMLAttributes(serviceMatch[1]);
    port.service = {
      name: attrs.name || "",
      product: attrs.product || "",
      version: attrs.version || "",
      extraInfo: attrs.extrainfo || "",
      osType: attrs.ostype || "",
      method: attrs.method || "",
      conf: parseInt(attrs.conf || "0", 10),
      tunnel: attrs.tunnel || "",
      cpe: [],
    };
  }

  // -- CPE entries --
  const cpeRegex = /<cpe>([^<]+)<\/cpe>/g;
  let cpeMatch;
  while ((cpeMatch = cpeRegex.exec(portBlock)) !== null) {
    if (port.service.cpe) {
      port.service.cpe.push(cpeMatch[1]);
    }
  }

  // -- Scripts --
  port.scripts = _parseScripts(portBlock);

  return port;
}

/**
 * Extract <script> elements from an XML block.
 * @private
 */
function _parseScripts(block) {
  const scripts = [];
  // Self-closing scripts
  const selfCloseRegex = /<script\s+([^>]+)\/>/g;
  let scMatch;
  while ((scMatch = selfCloseRegex.exec(block)) !== null) {
    const attrs = _parseXMLAttributes(scMatch[1]);
    scripts.push({
      id: attrs.id || "",
      output: attrs.output || "",
      elements: [],
    });
  }
  // Scripts with body
  const bodyRegex = /<script\s+([^>]+)>([\s\S]*?)<\/script>/g;
  let bodyMatch;
  while ((bodyMatch = bodyRegex.exec(block)) !== null) {
    const attrs = _parseXMLAttributes(bodyMatch[1]);
    const elements = _parseScriptElements(bodyMatch[2]);
    scripts.push({
      id: attrs.id || "",
      output: attrs.output || "",
      elements,
    });
  }
  return scripts;
}

/**
 * Parse <elem> and <table> structures inside a script block.
 * @private
 */
function _parseScriptElements(block) {
  const elements = [];
  const elemRegex = /<elem\s+key="([^"]*)"[^>]*>([^<]*)<\/elem>/g;
  let elemMatch;
  while ((elemMatch = elemRegex.exec(block)) !== null) {
    elements.push({ key: elemMatch[1], value: elemMatch[2] });
  }
  return elements;
}

/**
 * Parse XML attributes from a tag's attribute string.
 * @private
 */
function _parseXMLAttributes(attrStr) {
  const attrs = {};
  const regex = /(\w+)\s*=\s*"([^"]*)"/g;
  let match;
  while ((match = regex.exec(attrStr)) !== null) {
    attrs[match[1]] = _unescapeXML(match[2]);
  }
  return attrs;
}

/**
 * Unescape basic XML entities.
 * @private
 */
function _unescapeXML(str) {
  return str
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'");
}

// ========================= GREP PARSER =====================================

/**
 * parseNmapGrep -- Parse nmap -oG (greppable) output into a structured object.
 *
 * @param {string} text - Raw greppable output from nmap -oG
 * @returns {object} Parsed scan result
 */
function parseNmapGrep(text) {
  if (!text || typeof text !== "string") {
    throw new Error("parseNmapGrep: input must be a non-empty string");
  }

  const result = {
    scanner: "nmap",
    scanInfo: {},
    hosts: [],
    runStats: {},
    rawType: "grep",
  };

  const lines = text.split("\n");

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      // Parse comment lines for metadata
      _parseGrepComment(trimmed, result);
      continue;
    }

    if (trimmed.startsWith("Host:")) {
      const host = _parseGrepHostLine(trimmed);
      if (host) {
        result.hosts.push(host);
      }
    }
  }

  return result;
}

/**
 * Parse metadata from greppable comment lines.
 * @private
 */
function _parseGrepComment(line, result) {
  if (!line) return;

  // # Nmap 7.94 scan initiated Mon Jan 1 00:00:00 2024 as: nmap -oG ...
  const initiatedMatch = line.match(
    /^# Nmap\s+(\S+)\s+scan initiated\s+(.*?)\s+as:\s+(.*)$/
  );
  if (initiatedMatch) {
    result.scanInfo.version = initiatedMatch[1];
    result.scanInfo.startTimeStr = initiatedMatch[2];
    result.scanInfo.args = initiatedMatch[3];
    return;
  }

  // # Ports scanned: TCP(1000;1-1000) UDP(0;) ...
  const portsScannedMatch = line.match(/^# Ports scanned:\s+(.*)$/);
  if (portsScannedMatch) {
    result.scanInfo.portsScanned = portsScannedMatch[1];
    return;
  }

  // # Nmap done at Mon Jan 1 00:00:00 2024 -- 1 IP address (1 host up) ...
  const doneMatch = line.match(
    /^# Nmap done at\s+(.*?)\s+--\s+(\d+)\s+IP\s+address.*\((\d+)\s+host[s]?\s+up\)/
  );
  if (doneMatch) {
    result.runStats.endTimeStr = doneMatch[1];
    result.runStats.hostsTotal = parseInt(doneMatch[2], 10);
    result.runStats.hostsUp = parseInt(doneMatch[3], 10);
    result.runStats.hostsDown = result.runStats.hostsTotal - result.runStats.hostsUp;
    return;
  }

  // Elapsed time
  const elapsedMatch = line.match(/scanned in\s+([\d.]+)\s+seconds/);
  if (elapsedMatch) {
    result.runStats.elapsed = elapsedMatch[1];
  }
}

/**
 * Parse a "Host:" line from greppable output.
 * @private
 */
function _parseGrepHostLine(line) {
  // Format: Host: 192.168.1.1 (hostname) Status: Up
  // or: Host: 192.168.1.1 (hostname) Ports: 22/open/tcp//ssh//OpenSSH 8.2p1/ ...
  const hostHeaderMatch = line.match(
    /^Host:\s+([\d.]+(?::[\da-fA-F:]+)?)\s+\(([^)]*)\)\s+(.*)$/
  );
  if (!hostHeaderMatch) return null;

  const host = {
    ip: hostHeaderMatch[1],
    hostname: hostHeaderMatch[2] || "",
    status: "up",
    addresses: [{ addr: hostHeaderMatch[1], addrtype: "ipv4" }],
    hostnames: [],
    ports: [],
    os: [],
    scripts: [],
  };

  if (host.hostname) {
    host.hostnames.push({ name: host.hostname, type: "PTR" });
  }

  const remainder = hostHeaderMatch[3];

  // Check for Status only
  if (remainder.match(/^Status:\s+(\w+)/)) {
    host.status = remainder.match(/^Status:\s+(\w+)/)[1].toLowerCase();
    return host;
  }

  // Parse Ports section
  const portsMatch = remainder.match(/Ports:\s+(.*?)(?:\tIgnored|$)/);
  if (portsMatch) {
    const portEntries = portsMatch[1].split(",").map((p) => p.trim()).filter(Boolean);
    for (const entry of portEntries) {
      const port = _parseGrepPortEntry(entry);
      if (port) {
        host.ports.push(port);
      }
    }
  }

  // Parse OS section
  const osMatch = remainder.match(/OS:\s+(.+?)(?:\t|$)/);
  if (osMatch) {
    host.os.push({
      name: osMatch[1].trim(),
      accuracy: 0,
    });
  }

  // Parse Seq Index
  const seqMatch = remainder.match(/Seq Index:\s+(\d+)/);
  if (seqMatch) {
    host.seqIndex = parseInt(seqMatch[1], 10);
  }

  // Parse IP ID Seq
  const ipidMatch = remainder.match(/IP ID Seq:\s+(\S+)/);
  if (ipidMatch) {
    host.ipIdSeq = ipidMatch[1];
  }

  return host;
}

/**
 * Parse a single port entry from greppable output.
 * Format: port/state/protocol/owner/service/rpc_info/version/
 * @private
 */
function _parseGrepPortEntry(entry) {
  const parts = entry.split("/");
  if (parts.length < 7) return null;

  const portId = parseInt(parts[0], 10);
  const state = (parts[1] || "").toLowerCase();
  const protocol = (parts[2] || "tcp").toLowerCase();
  const owner = parts[3] || "";
  const serviceName = parts[4] || "";
  const rpcInfo = parts[5] || "";
  const version = parts.slice(6).join("/").replace(/\/$/, "");

  // Determine product/version from the version string
  let product = "";
  let versionStr = "";
  if (version) {
    const versionParts = version.match(/^(.*?)\s+([\d][\d.]*\S*)(.*)$/);
    if (versionParts) {
      product = versionParts[1].trim();
      versionStr = versionParts[2].trim();
    } else {
      product = version.trim();
    }
  }

  return {
    portId,
    protocol,
    state,
    stateReason: "",
    service: {
      name: serviceName,
      product,
      version: versionStr,
      extraInfo: rpcInfo,
      owner,
      method: "probed",
      conf: 10,
      tunnel: "",
      cpe: [],
    },
    scripts: [],
  };
}

// ========================= FORMATTER =======================================

/**
 * formatScanResult -- Pretty-print a parsed scan result to a human-readable
 * multi-line string suitable for terminal display.
 *
 * @param {object} data - Parsed scan result from parseNmapXML or parseNmapGrep
 * @param {object} [options] - Formatting options
 * @param {boolean} [options.color=false] - Whether to include ANSI color codes
 * @param {boolean} [options.verbose=false] - Show extended details
 * @param {boolean} [options.showScripts=true] - Include script output
 * @returns {string} Formatted text
 */
function formatScanResult(data, options = {}) {
  const color = options.color || false;
  const verbose = options.verbose || false;
  const showScripts = options.showScripts !== false;

  const lines = [];

  // -- Header --
  lines.push(_fmtLine("=", 72));
  lines.push(_fmtCenter("NMAP SCAN REPORT", 72));
  lines.push(_fmtLine("=", 72));
  lines.push("");

  // -- Scan Info --
  if (data.scanInfo) {
    lines.push(_fmtSection("Scan Information"));
    if (data.scanInfo.args) lines.push(`  Command: ${data.scanInfo.args}`);
    if (data.scanInfo.version) lines.push(`  Nmap version: ${data.scanInfo.version}`);
    if (data.scanInfo.startTime) lines.push(`  Start time: ${data.scanInfo.startTime}`);
    if (data.scanInfo.type) lines.push(`  Scan type: ${data.scanInfo.type}`);
    if (data.scanInfo.protocol) lines.push(`  Protocol: ${data.scanInfo.protocol}`);
    lines.push("");
  }

  // -- Host Reports --
  if (data.hosts && data.hosts.length > 0) {
    for (let i = 0; i < data.hosts.length; i++) {
      const host = data.hosts[i];
      lines.push(_fmtLine("-", 72));
      lines.push(_fmtSection(`Host ${i + 1}: ${host.ip}`));

      // Status
      lines.push(`  Status: ${host.status}${host.statusReason ? ` (${host.statusReason})` : ""}`);

      // Hostnames
      if (host.hostnames && host.hostnames.length > 0) {
        const names = host.hostnames.map((h) => h.name).join(", ");
        lines.push(`  Hostnames: ${names}`);
      }

      // MAC
      if (host.mac) {
        const macEntry = host.addresses.find((a) => a.addrtype === "mac");
        const vendor = macEntry && macEntry.vendor ? ` (${macEntry.vendor})` : "";
        lines.push(`  MAC Address: ${host.mac}${vendor}`);
      }

      // OS
      if (host.os && host.os.length > 0) {
        lines.push(`  OS Detection:`);
        for (const os of host.os.slice(0, 3)) {
          lines.push(`    - ${os.name} (accuracy: ${os.accuracy}%)`);
        }
      }

      // Distance
      if (host.distance) {
        lines.push(`  Network Distance: ${host.distance} hop(s)`);
      }

      // Uptime
      if (host.uptime) {
        const days = Math.floor(host.uptime.seconds / 86400);
        lines.push(`  Uptime: ~${days} days (since ${host.uptime.lastboot})`);
      }

      // Ports
      if (host.ports && host.ports.length > 0) {
        lines.push("");
        lines.push(`  PORT${_pad("", 11)}STATE${_pad("", 7)}SERVICE${_pad("", 13)}VERSION`);
        lines.push(`  ${_fmtLine("-", 68)}`);

        for (const port of host.ports) {
          const portStr = `${port.portId}/${port.protocol}`;
          const stateStr = port.state;
          const svc = port.service || {};
          const serviceStr = svc.name || PORT_SERVICE_MAP[port.portId] || "unknown";
          const versionParts = [];
          if (svc.product) versionParts.push(svc.product);
          if (svc.version) versionParts.push(svc.version);
          if (svc.extraInfo && verbose) versionParts.push(`(${svc.extraInfo})`);
          const versionStr = versionParts.join(" ");

          lines.push(
            `  ${_padRight(portStr, 16)}${_padRight(stateStr, 12)}${_padRight(serviceStr, 20)}${versionStr}`
          );

          // CPE
          if (verbose && svc.cpe && svc.cpe.length > 0) {
            for (const cpe of svc.cpe) {
              lines.push(`    CPE: ${cpe}`);
            }
          }

          // Scripts
          if (showScripts && port.scripts && port.scripts.length > 0) {
            for (const script of port.scripts) {
              lines.push(`    |_ ${script.id}: ${_truncate(script.output, 120)}`);
              if (verbose && script.elements && script.elements.length > 0) {
                for (const elem of script.elements) {
                  lines.push(`    |    ${elem.key}: ${_truncate(elem.value, 100)}`);
                }
              }
            }
          }
        }
      }

      // Host Scripts
      if (showScripts && host.scripts && host.scripts.length > 0) {
        lines.push("");
        lines.push("  Host Scripts:");
        for (const script of host.scripts) {
          lines.push(`    |_ ${script.id}:`);
          const outputLines = (script.output || "").split("\n").filter(Boolean);
          for (const ol of outputLines.slice(0, verbose ? 50 : 10)) {
            lines.push(`    |    ${ol.trim()}`);
          }
        }
      }

      // Traceroute
      if (verbose && host.trace && host.trace.length > 0) {
        lines.push("");
        lines.push("  Traceroute:");
        for (const hop of host.trace) {
          lines.push(
            `    ${_padRight(String(hop.ttl), 4)} ${_padRight(hop.ipaddr, 18)} ${hop.rtt}ms ${hop.host}`
          );
        }
      }

      lines.push("");
    }
  } else {
    lines.push("  No hosts found in scan results.");
    lines.push("");
  }

  // -- Run Stats --
  if (data.runStats) {
    lines.push(_fmtLine("-", 72));
    lines.push(_fmtSection("Statistics"));
    if (data.runStats.hostsUp !== undefined) {
      lines.push(
        `  Hosts: ${data.runStats.hostsUp} up, ${data.runStats.hostsDown || 0} down, ${data.runStats.hostsTotal || 0} total`
      );
    }
    if (data.runStats.elapsed) lines.push(`  Time elapsed: ${data.runStats.elapsed}s`);
    if (data.runStats.endTime) lines.push(`  Completed: ${data.runStats.endTime}`);
    if (data.runStats.summary) lines.push(`  Summary: ${data.runStats.summary}`);
    lines.push("");
  }

  lines.push(_fmtLine("=", 72));

  // Apply ANSI color if requested
  if (color) {
    return _applyColor(lines.join("\n"));
  }

  return lines.join("\n");
}

// Formatting helpers

function _fmtLine(char, width) {
  return char.repeat(width);
}

function _fmtCenter(text, width) {
  const pad = Math.max(0, Math.floor((width - text.length) / 2));
  return " ".repeat(pad) + text;
}

function _fmtSection(title) {
  return `[${title}]`;
}

function _pad(str, len) {
  return " ".repeat(Math.max(0, len - str.length));
}

function _padRight(str, len) {
  return str + " ".repeat(Math.max(0, len - str.length));
}

function _truncate(str, maxLen) {
  if (!str) return "";
  const clean = str.replace(/\n/g, " ").trim();
  if (clean.length <= maxLen) return clean;
  return clean.slice(0, maxLen - 3) + "...";
}

function _applyColor(text) {
  const RESET = "\x1b[0m";
  const BOLD = "\x1b[1m";
  const RED = "\x1b[31m";
  const GREEN = "\x1b[32m";
  const YELLOW = "\x1b[33m";
  const CYAN = "\x1b[36m";

  return text
    .replace(/^(={72})$/gm, `${CYAN}$1${RESET}`)
    .replace(/^(-{72})$/gm, `${CYAN}$1${RESET}`)
    .replace(/\[([^\]]+)\]/g, `${BOLD}${CYAN}[$1]${RESET}`)
    .replace(/\b(open)\b/gi, `${GREEN}$1${RESET}`)
    .replace(/\b(closed)\b/gi, `${RED}$1${RESET}`)
    .replace(/\b(filtered)\b/gi, `${YELLOW}$1${RESET}`)
    .replace(/\b(critical)\b/gi, `${RED}${BOLD}$1${RESET}`)
    .replace(/\b(high)\b/gi, `${RED}$1${RESET}`)
    .replace(/\b(medium)\b/gi, `${YELLOW}$1${RESET}`);
}

// ========================= VULN IDENTIFICATION =============================

/**
 * identifyVulnerableServices -- Analyze a parsed scan result and identify
 * services matching known vulnerability patterns.
 *
 * @param {object} data - Parsed scan result
 * @returns {object} Vulnerability report
 */
function identifyVulnerableServices(data) {
  if (!data || !data.hosts) {
    return { findings: [], summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 } };
  }

  const findings = [];

  for (const host of data.hosts) {
    if (!host.ports) continue;

    for (const port of host.ports) {
      if (port.state !== "open") continue;

      const svc = port.service || {};
      const serviceStr = _buildServiceString(svc, port);

      // Check each pattern in the vulnerability database
      for (const entry of SERVICE_VULN_DB) {
        const patternSrc = entry.pattern;
        if (!patternSrc) continue;

        let regex;
        try {
          regex = new RegExp(patternSrc, "i");
        } catch (e) {
          continue;
        }

        if (regex.test(serviceStr)) {
          findings.push({
            host: host.ip,
            hostname: (host.hostnames[0] || {}).name || "",
            port: port.portId,
            protocol: port.protocol,
            service: svc.name || "",
            product: svc.product || "",
            version: svc.version || "",
            matchedString: serviceStr,
            severity: entry.severity,
            cve: entry.cve || [],
            summary: entry.summary,
            remediation: entry.remediation,
          });
          // Do not break -- a service can match multiple entries
        }
      }

      // Check for plaintext protocol warnings
      _checkPlaintextProtocol(host, port, findings);
    }
  }

  // Sort by severity
  findings.sort((a, b) => {
    const oa = SEVERITY_ORDER[a.severity] !== undefined ? SEVERITY_ORDER[a.severity] : 99;
    const ob = SEVERITY_ORDER[b.severity] !== undefined ? SEVERITY_ORDER[b.severity] : 99;
    return oa - ob;
  });

  // Deduplicate findings for same host+port+summary
  const seen = new Set();
  const deduped = [];
  for (const f of findings) {
    const key = `${f.host}:${f.port}:${f.summary}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduped.push(f);
    }
  }

  // Compute summary counts
  const summary = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of deduped) {
    summary.total++;
    if (summary[f.severity] !== undefined) {
      summary[f.severity]++;
    }
  }

  return {
    findings: deduped,
    summary,
    scanTarget: data.scanInfo && data.scanInfo.args ? data.scanInfo.args : "unknown",
    timestamp: new Date().toISOString(),
  };
}

/**
 * Build a combined service string for pattern matching.
 * @private
 */
function _buildServiceString(svc, port) {
  const parts = [];
  if (svc.name) parts.push(svc.name);
  if (svc.product) parts.push(svc.product);
  if (svc.version) parts.push(svc.version);
  if (svc.extraInfo) parts.push(svc.extraInfo);
  if (svc.cpe) {
    for (const c of svc.cpe) parts.push(c);
  }
  // Also include port-based service guess
  const portGuess = PORT_SERVICE_MAP[port.portId];
  if (portGuess && !parts.includes(portGuess)) {
    parts.push(portGuess);
  }
  return parts.join(" ").toLowerCase();
}

/**
 * Flag cleartext protocols that should not be exposed.
 * @private
 */
function _checkPlaintextProtocol(host, port, findings) {
  const plaintextPorts = {
    21: { name: "FTP", alt: "SFTP/FTPS" },
    23: { name: "Telnet", alt: "SSH" },
    80: null, // HTTP is often intentional
    110: { name: "POP3", alt: "POP3S (port 995)" },
    143: { name: "IMAP", alt: "IMAPS (port 993)" },
    161: { name: "SNMP v1/v2c", alt: "SNMPv3" },
    389: { name: "LDAP", alt: "LDAPS (port 636)" },
    513: { name: "rlogin", alt: "SSH" },
    514: { name: "rsh/syslog", alt: "SSH/syslog-TLS" },
  };

  const info = plaintextPorts[port.portId];
  if (!info) return;
  if (port.state !== "open") return;

  // Avoid duplicate if already flagged by SERVICE_VULN_DB
  const alreadyFlagged = findings.some(
    (f) => f.host === host.ip && f.port === port.portId && f.summary.toLowerCase().includes("cleartext")
  );
  if (alreadyFlagged) return;

  findings.push({
    host: host.ip,
    hostname: (host.hostnames[0] || {}).name || "",
    port: port.portId,
    protocol: port.protocol,
    service: info.name,
    product: "",
    version: "",
    matchedString: "",
    severity: "medium",
    cve: [],
    summary: `${info.name} transmits credentials/data in cleartext`,
    remediation: `Replace with ${info.alt}`,
  });
}

// ========================= NEXT STEPS ======================================

/**
 * suggestNextSteps -- Given a parsed scan result, generate a list of
 * recommended follow-up actions organized by priority.
 *
 * @param {object} data - Parsed scan result
 * @returns {object} Categorized suggestions
 */
function suggestNextSteps(data) {
  if (!data || !data.hosts) {
    return { immediate: [], shortTerm: [], longTerm: [], commands: [] };
  }

  const immediate = [];
  const shortTerm = [];
  const longTerm = [];
  const commands = [];
  const seen = new Set();

  for (const host of data.hosts) {
    if (!host.ports) continue;

    for (const port of host.ports) {
      if (port.state !== "open") continue;

      const svc = port.service || {};
      const serviceName = (svc.name || "").toLowerCase();
      const product = (svc.product || "").toLowerCase();
      const portId = port.portId;
      const ip = host.ip;

      // -- Service-specific deep scan suggestions --

      // SSH
      if (serviceName === "ssh" || portId === 22) {
        _addUnique(seen, commands, {
          category: "enumeration",
          command: `nmap -p ${portId} --script ssh-auth-methods,ssh2-enum-algos,ssh-hostkey ${ip}`,
          description: "Enumerate SSH authentication methods and algorithms",
          priority: "medium",
        });
        _addUnique(seen, shortTerm, {
          action: `Audit SSH configuration on ${ip}:${portId}`,
          detail: "Check for weak ciphers, key exchange algorithms, and password auth",
          priority: "medium",
        });
      }

      // HTTP/HTTPS
      if (serviceName === "http" || serviceName === "https" || portId === 80 || portId === 443 || portId === 8080 || portId === 8443) {
        const scheme = (portId === 443 || portId === 8443 || svc.tunnel === "ssl") ? "https" : "http";
        _addUnique(seen, commands, {
          category: "web",
          command: `nmap -p ${portId} --script http-title,http-headers,http-methods,http-server-header ${ip}`,
          description: `Enumerate HTTP headers and methods on ${ip}:${portId}`,
          priority: "high",
        });
        _addUnique(seen, commands, {
          category: "web",
          command: `nmap -p ${portId} --script http-enum ${ip}`,
          description: `Enumerate common web paths on ${ip}:${portId}`,
          priority: "high",
        });
        _addUnique(seen, commands, {
          category: "web",
          command: `nmap -p ${portId} --script http-vuln-cve2017-5638,http-shellshock ${ip}`,
          description: `Check for common web vulnerabilities on ${ip}:${portId}`,
          priority: "high",
        });
        if (scheme === "https") {
          _addUnique(seen, commands, {
            category: "ssl",
            command: `nmap -p ${portId} --script ssl-enum-ciphers,ssl-cert,ssl-heartbleed ${ip}`,
            description: `Audit SSL/TLS configuration on ${ip}:${portId}`,
            priority: "high",
          });
        }
        _addUnique(seen, shortTerm, {
          action: `Run a web application scanner against ${scheme}://${ip}:${portId}`,
          detail: "Use nikto, dirb, or gobuster for directory enumeration",
          priority: "high",
        });
      }

      // SMB
      if (serviceName === "microsoft-ds" || serviceName === "netbios-ssn" || portId === 445 || portId === 139) {
        _addUnique(seen, commands, {
          category: "smb",
          command: `nmap -p 139,445 --script smb-os-discovery,smb-protocols,smb-security-mode,smb-enum-shares ${ip}`,
          description: `Enumerate SMB shares and configuration on ${ip}`,
          priority: "high",
        });
        _addUnique(seen, commands, {
          category: "smb",
          command: `nmap -p 139,445 --script smb-vuln-ms17-010,smb-vuln-ms08-067 ${ip}`,
          description: `Check for critical SMB vulnerabilities (EternalBlue, MS08-067) on ${ip}`,
          priority: "critical",
        });
        _addUnique(seen, immediate, {
          action: `Verify SMB signing and access controls on ${ip}`,
          detail: "Check for null sessions, guest access, and unsigned SMB",
          priority: "critical",
        });
      }

      // RDP
      if (serviceName === "ms-wbt-server" || portId === 3389) {
        _addUnique(seen, commands, {
          category: "rdp",
          command: `nmap -p ${portId} --script rdp-enum-encryption,rdp-vuln-ms12-020 ${ip}`,
          description: `Check RDP encryption and vulnerabilities on ${ip}`,
          priority: "critical",
        });
        _addUnique(seen, immediate, {
          action: `Verify NLA is enabled for RDP on ${ip}:${portId}`,
          detail: "Network Level Authentication prevents pre-auth attacks (BlueKeep)",
          priority: "critical",
        });
      }

      // MySQL
      if (serviceName === "mysql" || portId === 3306) {
        _addUnique(seen, commands, {
          category: "database",
          command: `nmap -p ${portId} --script mysql-info,mysql-enum,mysql-empty-password ${ip}`,
          description: `Enumerate MySQL configuration on ${ip}:${portId}`,
          priority: "high",
        });
        _addUnique(seen, shortTerm, {
          action: `Check MySQL authentication on ${ip}:${portId}`,
          detail: "Verify no empty passwords, default accounts, or remote root access",
          priority: "high",
        });
      }

      // PostgreSQL
      if (serviceName === "postgresql" || portId === 5432) {
        _addUnique(seen, commands, {
          category: "database",
          command: `nmap -p ${portId} --script pgsql-brute ${ip}`,
          description: `Test PostgreSQL default credentials on ${ip}:${portId}`,
          priority: "high",
        });
      }

      // Redis
      if (serviceName === "redis" || portId === 6379) {
        _addUnique(seen, commands, {
          category: "database",
          command: `nmap -p ${portId} --script redis-info ${ip}`,
          description: `Get Redis info (check for unauthenticated access) on ${ip}:${portId}`,
          priority: "critical",
        });
        _addUnique(seen, immediate, {
          action: `Verify Redis requires authentication on ${ip}:${portId}`,
          detail: "Unauthenticated Redis can lead to RCE via config rewrite",
          priority: "critical",
        });
      }

      // MongoDB
      if (serviceName === "mongodb" || portId === 27017) {
        _addUnique(seen, commands, {
          category: "database",
          command: `nmap -p ${portId} --script mongodb-info,mongodb-databases ${ip}`,
          description: `Enumerate MongoDB databases on ${ip}:${portId}`,
          priority: "critical",
        });
        _addUnique(seen, immediate, {
          action: `Verify MongoDB authentication on ${ip}:${portId}`,
          detail: "Unauthenticated MongoDB is a frequent data breach vector",
          priority: "critical",
        });
      }

      // SNMP
      if (serviceName === "snmp" || portId === 161) {
        _addUnique(seen, commands, {
          category: "enumeration",
          command: `nmap -sU -p 161 --script snmp-info,snmp-brute,snmp-interfaces ${ip}`,
          description: `Enumerate SNMP community strings and interfaces on ${ip}`,
          priority: "high",
        });
      }

      // DNS
      if (serviceName === "domain" || serviceName === "dns" || portId === 53) {
        _addUnique(seen, commands, {
          category: "enumeration",
          command: `nmap -p 53 --script dns-zone-transfer,dns-recursion ${ip}`,
          description: `Check for DNS zone transfer and open recursion on ${ip}`,
          priority: "high",
        });
      }

      // SMTP
      if (serviceName === "smtp" || portId === 25 || portId === 587) {
        _addUnique(seen, commands, {
          category: "enumeration",
          command: `nmap -p ${portId} --script smtp-commands,smtp-open-relay,smtp-enum-users ${ip}`,
          description: `Enumerate SMTP configuration and check open relay on ${ip}:${portId}`,
          priority: "high",
        });
      }

      // FTP
      if (serviceName === "ftp" || portId === 21) {
        _addUnique(seen, commands, {
          category: "enumeration",
          command: `nmap -p ${portId} --script ftp-anon,ftp-syst,ftp-vsftpd-backdoor ${ip}`,
          description: `Check FTP anonymous access and known backdoors on ${ip}:${portId}`,
          priority: "high",
        });
      }

      // Telnet
      if (serviceName === "telnet" || portId === 23) {
        _addUnique(seen, immediate, {
          action: `Disable telnet on ${ip}:${portId} and replace with SSH`,
          detail: "Telnet sends all data including credentials in cleartext",
          priority: "critical",
        });
      }

      // Elasticsearch
      if (serviceName === "elasticsearch" || portId === 9200) {
        _addUnique(seen, commands, {
          category: "database",
          command: `nmap -p ${portId} --script http-title ${ip}`,
          description: `Check Elasticsearch accessibility on ${ip}:${portId}`,
          priority: "high",
        });
        _addUnique(seen, immediate, {
          action: `Verify Elasticsearch authentication on ${ip}:${portId}`,
          detail: "Unauthenticated Elasticsearch exposes all indexed data",
          priority: "critical",
        });
      }

      // VNC
      if (serviceName === "vnc" || portId === 5900 || portId === 5901) {
        _addUnique(seen, commands, {
          category: "remote_access",
          command: `nmap -p ${portId} --script vnc-info,vnc-brute ${ip}`,
          description: `Check VNC authentication on ${ip}:${portId}`,
          priority: "high",
        });
      }

      // LDAP
      if (serviceName === "ldap" || portId === 389 || portId === 636) {
        _addUnique(seen, commands, {
          category: "enumeration",
          command: `nmap -p ${portId} --script ldap-rootdse,ldap-search ${ip}`,
          description: `Enumerate LDAP directory on ${ip}:${portId}`,
          priority: "medium",
        });
      }

      // NFS
      if (serviceName === "nfs" || portId === 2049) {
        _addUnique(seen, commands, {
          category: "enumeration",
          command: `nmap -p 111,2049 --script nfs-ls,nfs-showmount,nfs-statfs ${ip}`,
          description: `Enumerate NFS exports on ${ip}`,
          priority: "high",
        });
      }
    }

    // General long-term recommendations per host
    if (host.ports && host.ports.filter((p) => p.state === "open").length > 15) {
      _addUnique(seen, longTerm, {
        action: `Review firewall rules for ${host.ip} -- ${host.ports.filter((p) => p.state === "open").length} open ports detected`,
        detail: "A high number of open ports increases attack surface; close unnecessary services",
        priority: "high",
      });
    }
  }

  // General suggestions
  longTerm.push({
    action: "Establish a regular vulnerability scanning schedule",
    detail: "Run authenticated scans weekly and unauthenticated scans monthly",
    priority: "medium",
  });
  longTerm.push({
    action: "Implement network segmentation",
    detail: "Separate critical services into dedicated VLANs with restricted inter-VLAN routing",
    priority: "medium",
  });
  longTerm.push({
    action: "Deploy an intrusion detection/prevention system (IDS/IPS)",
    detail: "Tools like Suricata or Snort can detect exploitation attempts in real time",
    priority: "medium",
  });

  return {
    immediate: _sortByPriority(immediate),
    shortTerm: _sortByPriority(shortTerm),
    longTerm: _sortByPriority(longTerm),
    commands: _sortByPriority(commands),
    generatedAt: new Date().toISOString(),
  };
}

/**
 * Add an item to a list only if a key derived from it hasn't been seen.
 * @private
 */
function _addUnique(seen, list, item) {
  const key = item.command || item.action || JSON.stringify(item);
  if (!seen.has(key)) {
    seen.add(key);
    list.push(item);
  }
}

/**
 * Sort suggestion arrays by priority.
 * @private
 */
function _sortByPriority(items) {
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return items.sort((a, b) => {
    const oa = order[a.priority] !== undefined ? order[a.priority] : 99;
    const ob = order[b.priority] !== undefined ? order[b.priority] : 99;
    return oa - ob;
  });
}

// ========================= UTILITIES =======================================

/**
 * Merge multiple scan results into a single consolidated view.
 * Useful when combining multiple nmap runs against the same target.
 *
 * @param {...object} results - Parsed scan results to merge
 * @returns {object} Merged result
 */
function mergeScanResults(...results) {
  const merged = {
    scanner: "nmap",
    scanInfo: { merged: true, sourceCount: results.length },
    hosts: [],
    runStats: { hostsUp: 0, hostsDown: 0, hostsTotal: 0 },
    rawType: "merged",
  };

  const hostMap = new Map();

  for (const result of results) {
    if (!result || !result.hosts) continue;
    for (const host of result.hosts) {
      const key = host.ip;
      if (hostMap.has(key)) {
        const existing = hostMap.get(key);
        // Merge ports
        const portKeys = new Set(existing.ports.map((p) => `${p.portId}/${p.protocol}`));
        for (const port of host.ports || []) {
          const pk = `${port.portId}/${port.protocol}`;
          if (!portKeys.has(pk)) {
            portKeys.add(pk);
            existing.ports.push(port);
          }
        }
        // Merge hostnames
        const hnKeys = new Set(existing.hostnames.map((h) => h.name));
        for (const hn of host.hostnames || []) {
          if (!hnKeys.has(hn.name)) {
            hnKeys.add(hn.name);
            existing.hostnames.push(hn);
          }
        }
        // Merge OS
        const osKeys = new Set(existing.os.map((o) => o.name));
        for (const os of host.os || []) {
          if (!osKeys.has(os.name)) {
            osKeys.add(os.name);
            existing.os.push(os);
          }
        }
        // Merge scripts
        const scriptKeys = new Set(existing.scripts.map((s) => s.id));
        for (const script of host.scripts || []) {
          if (!scriptKeys.has(script.id)) {
            scriptKeys.add(script.id);
            existing.scripts.push(script);
          }
        }
      } else {
        hostMap.set(key, JSON.parse(JSON.stringify(host)));
      }
    }
  }

  merged.hosts = Array.from(hostMap.values());
  // Sort ports within each host
  for (const host of merged.hosts) {
    host.ports.sort((a, b) => a.portId - b.portId);
  }
  merged.runStats.hostsUp = merged.hosts.filter((h) => h.status === "up").length;
  merged.runStats.hostsTotal = merged.hosts.length;
  merged.runStats.hostsDown = merged.runStats.hostsTotal - merged.runStats.hostsUp;

  return merged;
}

/**
 * Filter scan results to only include specific port states.
 *
 * @param {object} data - Parsed scan result
 * @param {string[]} [states=["open"]] - Port states to include
 * @returns {object} Filtered result (deep copy)
 */
function filterByState(data, states) {
  if (!states) states = ["open"];
  const stateSet = new Set(states.map((s) => s.toLowerCase()));
  const filtered = JSON.parse(JSON.stringify(data));
  for (const host of filtered.hosts || []) {
    host.ports = (host.ports || []).filter((p) => stateSet.has((p.state || "").toLowerCase()));
  }
  return filtered;
}

/**
 * Extract a flat list of all open ports across all hosts.
 *
 * @param {object} data - Parsed scan result
 * @returns {Array} Array of {host, port, protocol, service, version}
 */
function listOpenPorts(data) {
  const ports = [];
  for (const host of data.hosts || []) {
    for (const port of host.ports || []) {
      if (port.state === "open") {
        const svc = port.service || {};
        ports.push({
          host: host.ip,
          port: port.portId,
          protocol: port.protocol,
          service: svc.name || "",
          product: svc.product || "",
          version: svc.version || "",
        });
      }
    }
  }
  return ports;
}

/**
 * Convert parsed scan result to a simplified JSON summary.
 *
 * @param {object} data - Parsed scan result
 * @returns {object} Simplified summary
 */
function toSummary(data) {
  return {
    scanTime: (data.scanInfo || {}).startTime || null,
    hostCount: (data.hosts || []).length,
    hostsUp: (data.hosts || []).filter((h) => h.status === "up").length,
    totalOpenPorts: (data.hosts || []).reduce(
      (acc, h) => acc + (h.ports || []).filter((p) => p.state === "open").length,
      0
    ),
    hosts: (data.hosts || []).map((h) => ({
      ip: h.ip,
      hostname: (h.hostnames[0] || {}).name || "",
      status: h.status,
      openPorts: (h.ports || [])
        .filter((p) => p.state === "open")
        .map((p) => ({
          port: p.portId,
          service: (p.service || {}).name || "",
          version: [(p.service || {}).product, (p.service || {}).version].filter(Boolean).join(" "),
        })),
    })),
  };
}

// ========================= MODULE EXPORTS ==================================

module.exports = {
  parseNmapXML,
  parseNmapGrep,
  formatScanResult,
  identifyVulnerableServices,
  suggestNextSteps,
  SERVICE_VULN_DB,
  PORT_SERVICE_MAP,
  SEVERITY_ORDER,
  mergeScanResults,
  filterByState,
  listOpenPorts,
  toSummary,
};
