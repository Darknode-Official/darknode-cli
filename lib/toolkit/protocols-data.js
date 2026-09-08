"use strict";

// ---------------------------------------------------------------------------
// protocols-data.js  --  Comprehensive network protocol reference
// Part of the darknode-cli toolkit.
// ---------------------------------------------------------------------------

// ============================= 1. PROTOCOLS ================================
// 80+ protocols with port, transport, description, security notes,
// common vulnerabilities, and testing commands.
// ===========================================================================

const PROTOCOLS = [
  // ---------- Core TCP/IP & Link Layer ----------
  {
    name: "TCP",
    port: null,
    transport: "TCP",
    description:
      "Transmission Control Protocol -- reliable, ordered, connection-oriented byte stream between hosts. Three-way handshake (SYN, SYN-ACK, ACK) establishes sessions.",
    securityNotes:
      "Susceptible to SYN floods, session hijacking, RST injection, and sequence-number prediction attacks. Use TCP timestamps and SYN cookies to mitigate.",
    commonVulns: [
      "SYN flood DoS",
      "TCP session hijacking",
      "RST injection",
      "TCP sequence prediction",
      "Idle scan / zombie host abuse"
    ],
    testingCommands: [
      "nmap -sS <target>",
      "hping3 -S -p 80 <target>",
      "tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn) != 0'"
    ]
  },
  {
    name: "UDP",
    port: null,
    transport: "UDP",
    description:
      "User Datagram Protocol -- connectionless, best-effort delivery. Used where low latency matters more than reliability (DNS, VoIP, gaming).",
    securityNotes:
      "No handshake makes source-IP spoofing trivial. Amplification attacks exploit services that return large replies to small queries.",
    commonVulns: [
      "UDP flood DoS",
      "Amplification / reflection attacks",
      "IP spoofing",
      "Port scan evasion via UDP"
    ],
    testingCommands: [
      "nmap -sU <target>",
      "hping3 --udp -p 53 <target>",
      "tcpdump -i eth0 udp"
    ]
  },
  {
    name: "ICMP",
    port: null,
    transport: "ICMP",
    description:
      "Internet Control Message Protocol -- diagnostic and error-reporting (ping, traceroute, destination unreachable).",
    securityNotes:
      "Can be used for covert channels, Smurf attacks, ICMP tunneling, and OS fingerprinting via TTL/response patterns.",
    commonVulns: [
      "Smurf attack",
      "Ping of Death",
      "ICMP tunneling / exfiltration",
      "ICMP redirect attacks",
      "Covert channel communication"
    ],
    testingCommands: [
      "ping -c 4 <target>",
      "traceroute <target>",
      "nmap -sn -PE <target>",
      "hping3 -1 <target>"
    ]
  },
  {
    name: "ARP",
    port: null,
    transport: "Link Layer",
    description:
      "Address Resolution Protocol -- maps IPv4 addresses to MAC addresses on a local network segment.",
    securityNotes:
      "No authentication. ARP spoofing / poisoning enables MITM on local segments. Use Dynamic ARP Inspection (DAI) and static ARP entries.",
    commonVulns: [
      "ARP spoofing / poisoning",
      "ARP cache poisoning",
      "MITM via ARP",
      "ARP flood DoS",
      "Gratuitous ARP abuse"
    ],
    testingCommands: [
      "arp -a",
      "arpwatch",
      "ettercap -T -M arp:remote /<target1>// /<target2>//",
      "arping -I eth0 <target>"
    ]
  },
  {
    name: "IPv4",
    port: null,
    transport: "Network Layer",
    description:
      "Internet Protocol version 4 -- 32-bit addressing, packet fragmentation/reassembly, TTL-based loop prevention.",
    securityNotes:
      "No built-in authentication or encryption. IP spoofing, fragmentation attacks, and routing manipulation are common threats.",
    commonVulns: [
      "IP spoofing",
      "Fragmentation overlap attacks",
      "Teardrop attack",
      "Source routing abuse",
      "TTL-based evasion"
    ],
    testingCommands: [
      "nmap -O <target>",
      "traceroute <target>",
      "hping3 -f <target>"
    ]
  },
  {
    name: "IPv6",
    port: null,
    transport: "Network Layer",
    description:
      "Internet Protocol version 6 -- 128-bit addressing, simplified header, built-in IPSec support, no fragmentation by routers.",
    securityNotes:
      "Extension headers can be abused for evasion. Router Advertisement spoofing can redirect traffic. Many firewalls still lack full IPv6 inspection.",
    commonVulns: [
      "Router Advertisement spoofing",
      "Extension header abuse / evasion",
      "IPv6 tunnel exploitation",
      "NDP spoofing",
      "Dual-stack attack surface"
    ],
    testingCommands: [
      "nmap -6 <target>",
      "ping6 <target>",
      "thc-ipv6 tools",
      "ip -6 neigh show"
    ]
  },

  // ---------- Web & Application Layer ----------
  {
    name: "HTTP",
    port: 80,
    transport: "TCP",
    description:
      "HyperText Transfer Protocol -- stateless request/response protocol for web content. Methods: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS.",
    securityNotes:
      "All data transmitted in cleartext including credentials and session tokens. Vulnerable to eavesdropping, MITM, and content injection. Always prefer HTTPS.",
    commonVulns: [
      "Session hijacking via cookie theft",
      "Cross-Site Scripting (XSS)",
      "Cross-Site Request Forgery (CSRF)",
      "HTTP request smuggling",
      "HTTP verb tampering",
      "Host header injection",
      "HTTP response splitting",
      "Click-jacking via missing X-Frame-Options"
    ],
    testingCommands: [
      "curl -v http://<target>/",
      "nikto -h http://<target>/",
      "nmap -sV -p 80 --script=http-enum <target>",
      "gobuster dir -u http://<target>/ -w /usr/share/wordlists/dirb/common.txt"
    ]
  },
  {
    name: "HTTPS",
    port: 443,
    transport: "TCP/TLS",
    description:
      "HTTP over TLS -- encrypted web traffic. Provides confidentiality, integrity, and server authentication via X.509 certificates.",
    securityNotes:
      "Security depends on proper TLS configuration: protocol version, cipher suites, certificate validation, HSTS, and pinning. Misconfigured TLS can be downgraded.",
    commonVulns: [
      "SSL stripping (sslstrip)",
      "Weak cipher suites (RC4, DES, export ciphers)",
      "Certificate pinning bypass",
      "BEAST, POODLE, Heartbleed, CRIME attacks",
      "Expired or self-signed certificates",
      "Missing HSTS header"
    ],
    testingCommands: [
      "sslscan <target>:443",
      "testssl.sh <target>",
      "nmap --script ssl-enum-ciphers -p 443 <target>",
      "openssl s_client -connect <target>:443"
    ]
  },
  {
    name: "HTTP/2",
    port: 443,
    transport: "TCP/TLS",
    description:
      "Major revision of HTTP -- binary framing, multiplexed streams, header compression (HPACK), server push. Backward compatible via ALPN negotiation.",
    securityNotes:
      "Multiplexing can amplify DoS impacts. HPACK compression oracle attacks possible. Implementations must handle stream prioritization carefully.",
    commonVulns: [
      "Rapid Reset DoS (CVE-2023-44487)",
      "HPACK bombing",
      "Stream multiplexing abuse",
      "Server push cache poisoning"
    ],
    testingCommands: [
      "curl --http2 -v https://<target>/",
      "nghttp -v https://<target>/",
      "h2spec https://<target>/"
    ]
  },
  {
    name: "HTTP/3",
    port: 443,
    transport: "QUIC/UDP",
    description:
      "HTTP over QUIC -- UDP-based transport with built-in TLS 1.3, reduced connection setup latency, connection migration across network changes.",
    securityNotes:
      "UDP-based so firewalls/IDS that only inspect TCP may miss traffic. Connection migration can bypass IP-based access controls.",
    commonVulns: [
      "UDP amplification potential",
      "Connection migration abuse",
      "Firewall/IDS bypass via QUIC",
      "Implementation bugs in early deployments"
    ],
    testingCommands: [
      "curl --http3 -v https://<target>/",
      "quiche-client https://<target>/"
    ]
  },
  {
    name: "WebSocket",
    port: 80,
    transport: "TCP",
    description:
      "Full-duplex communication over a single TCP connection, initiated via HTTP Upgrade. Used for real-time applications: chat, notifications, live data feeds.",
    securityNotes:
      "Same-Origin Policy does not apply the same way as HTTP. Must validate Origin header server-side. Susceptible to Cross-Site WebSocket Hijacking (CSWSH).",
    commonVulns: [
      "Cross-Site WebSocket Hijacking",
      "Missing Origin validation",
      "Injection via WebSocket messages",
      "Denial of service via message flooding",
      "Insecure ws:// instead of wss://"
    ],
    testingCommands: [
      "websocat ws://<target>/ws",
      "wscat -c ws://<target>/ws",
      "nmap --script http-websocket -p 80 <target>"
    ]
  },
  {
    name: "gRPC",
    port: 50051,
    transport: "TCP/HTTP2",
    description:
      "Google Remote Procedure Call -- high-performance RPC framework using Protocol Buffers over HTTP/2. Supports unary, server/client/bidirectional streaming.",
    securityNotes:
      "Default plaintext channel. Must configure TLS. Reflection API can leak service definitions. Proper authentication (mTLS, JWT) must be added explicitly.",
    commonVulns: [
      "Unencrypted channels",
      "gRPC reflection information disclosure",
      "Protobuf deserialization issues",
      "Missing authentication / authorization",
      "Large message DoS"
    ],
    testingCommands: [
      "grpcurl -plaintext <target>:50051 list",
      "grpc_health_probe -addr=<target>:50051",
      "grpcui -plaintext <target>:50051"
    ]
  },

  // ---------- DNS ----------
  {
    name: "DNS",
    port: 53,
    transport: "UDP/TCP",
    description:
      "Domain Name System -- hierarchical naming system translating domain names to IP addresses. Uses UDP for queries, TCP for zone transfers and large responses.",
    securityNotes:
      "Classic DNS has no authentication. DNS cache poisoning, spoofing, and amplification attacks are prevalent. Use DNSSEC, DoH, or DoT for integrity and privacy.",
    commonVulns: [
      "DNS cache poisoning (Kaminsky attack)",
      "DNS amplification DDoS",
      "DNS tunneling / data exfiltration",
      "Zone transfer information disclosure",
      "DNS rebinding attacks",
      "Subdomain takeover",
      "NXDOMAIN attack"
    ],
    testingCommands: [
      "dig @<target> <domain> ANY",
      "nslookup -type=ANY <domain> <target>",
      "nmap --script dns-zone-transfer -p 53 <target>",
      "dnsrecon -d <domain>",
      "fierce --domain <domain>"
    ]
  },
  {
    name: "DoH",
    port: 443,
    transport: "TCP/TLS",
    description:
      "DNS over HTTPS -- encrypts DNS queries inside HTTPS requests to prevent eavesdropping and manipulation of DNS traffic.",
    securityNotes:
      "Bypasses traditional DNS monitoring and filtering. Centralization risk with major DoH providers. Can be used to evade network security controls.",
    commonVulns: [
      "Bypasses corporate DNS filtering",
      "Centralization / single-point-of-trust",
      "Covert C2 channel via DoH"
    ],
    testingCommands: [
      "curl -H 'accept: application/dns-json' 'https://dns.google/resolve?name=<domain>&type=A'",
      "kdig +https @dns.google <domain>"
    ]
  },
  {
    name: "DoT",
    port: 853,
    transport: "TCP/TLS",
    description:
      "DNS over TLS -- encrypts DNS queries on a dedicated port (853) using TLS, making DNS traffic confidential and authenticated.",
    securityNotes:
      "Easier to identify and block than DoH since it uses a dedicated port. Requires proper certificate validation.",
    commonVulns: [
      "TLS downgrade if fallback to port 53 is allowed",
      "Certificate validation bypass"
    ],
    testingCommands: [
      "kdig +tls @<target> <domain>",
      "openssl s_client -connect <target>:853"
    ]
  },
  {
    name: "mDNS",
    port: 5353,
    transport: "UDP",
    description:
      "Multicast DNS -- resolves hostnames on local networks without a dedicated DNS server. Used by Bonjour/Avahi for service discovery.",
    securityNotes:
      "No authentication. Can be used for reconnaissance on local networks. Responses can be spoofed to redirect traffic.",
    commonVulns: [
      "mDNS spoofing / poisoning",
      "Local network reconnaissance",
      "Service enumeration"
    ],
    testingCommands: [
      "avahi-browse -at",
      "dns-sd -B _services._dns-sd._udp",
      "nmap --script dns-service-discovery -p 5353 <target>"
    ]
  },

  // ---------- DHCP ----------
  {
    name: "DHCP",
    port: 67,
    transport: "UDP",
    description:
      "Dynamic Host Configuration Protocol -- automatically assigns IP addresses, subnet masks, gateways, and DNS servers to hosts on a network.",
    securityNotes:
      "No authentication between client and server. Rogue DHCP servers can redirect traffic and DNS. Use DHCP snooping on switches.",
    commonVulns: [
      "Rogue DHCP server (MITM)",
      "DHCP starvation attack",
      "DHCP spoofing",
      "Option injection"
    ],
    testingCommands: [
      "nmap --script broadcast-dhcp-discover",
      "dhcpig",
      "yersinia -G (DHCP attacks)",
      "tcpdump -i eth0 port 67 or port 68"
    ]
  },

  // ---------- Email ----------
  {
    name: "SMTP",
    port: 25,
    transport: "TCP",
    description:
      "Simple Mail Transfer Protocol -- sends email between mail servers and from clients to servers. Extended by ESMTP with AUTH, STARTTLS, and SIZE extensions.",
    securityNotes:
      "Plaintext by default. Open relays allow spam. VRFY and EXPN commands can enumerate users. Always require STARTTLS or use port 587 with authentication.",
    commonVulns: [
      "Open relay abuse",
      "User enumeration via VRFY/EXPN/RCPT",
      "Email spoofing (missing SPF/DKIM/DMARC)",
      "STARTTLS stripping",
      "SMTP injection",
      "Cleartext credential interception"
    ],
    testingCommands: [
      "nmap --script smtp-enum-users,smtp-open-relay -p 25 <target>",
      "smtp-user-enum -M VRFY -U users.txt -t <target>",
      "swaks --to test@<domain> --from spoof@evil.com --server <target>",
      "telnet <target> 25"
    ]
  },
  {
    name: "SMTPS",
    port: 465,
    transport: "TCP/TLS",
    description:
      "SMTP over implicit TLS -- encrypted from connection start (unlike STARTTLS on port 25/587). Re-standardized in RFC 8314.",
    securityNotes:
      "More secure than STARTTLS since encryption is mandatory from the start. Still requires proper certificate validation and strong ciphers.",
    commonVulns: [
      "Weak TLS configuration",
      "Certificate validation issues",
      "Fallback to unencrypted SMTP"
    ],
    testingCommands: [
      "openssl s_client -connect <target>:465",
      "sslscan <target>:465",
      "nmap --script ssl-enum-ciphers -p 465 <target>"
    ]
  },
  {
    name: "SMTP Submission",
    port: 587,
    transport: "TCP",
    description:
      "Mail Submission Agent port -- clients submit outgoing email here with mandatory authentication. Supports STARTTLS upgrade.",
    securityNotes:
      "Requires authentication but STARTTLS upgrade can be stripped if not enforced. Brute-force attacks on credentials are common.",
    commonVulns: [
      "STARTTLS stripping",
      "Credential brute-force",
      "Weak authentication mechanisms"
    ],
    testingCommands: [
      "openssl s_client -starttls smtp -connect <target>:587",
      "hydra -l user -P pass.txt smtp://<target>:587"
    ]
  },
  {
    name: "POP3",
    port: 110,
    transport: "TCP",
    description:
      "Post Office Protocol v3 -- retrieves email from a server. Downloads messages and typically deletes them from the server. Simple but limited.",
    securityNotes:
      "Transmits credentials and email in cleartext. Support for STLS (STARTTLS) is inconsistent. Use POP3S (port 995) instead.",
    commonVulns: [
      "Cleartext credential transmission",
      "Credential brute-force",
      "Email content eavesdropping",
      "Buffer overflow in implementations"
    ],
    testingCommands: [
      "nmap --script pop3-capabilities,pop3-brute -p 110 <target>",
      "telnet <target> 110",
      "hydra -l user -P pass.txt pop3://<target>"
    ]
  },
  {
    name: "POP3S",
    port: 995,
    transport: "TCP/TLS",
    description:
      "POP3 over TLS -- encrypted retrieval of email from a server. Implicit TLS from connection start.",
    securityNotes:
      "Encrypts the session but server-side storage and authentication strength still matter. Prefer IMAPS for multi-device access.",
    commonVulns: [
      "Weak TLS ciphers",
      "Credential brute-force",
      "Downgrade attacks"
    ],
    testingCommands: [
      "openssl s_client -connect <target>:995",
      "nmap --script ssl-enum-ciphers -p 995 <target>"
    ]
  },
  {
    name: "IMAP",
    port: 143,
    transport: "TCP",
    description:
      "Internet Message Access Protocol -- retrieves and manages email on the server. Supports folders, flags, search, and multi-device synchronization.",
    securityNotes:
      "Plaintext by default. Credentials and email contents exposed. STARTTLS support is common but must be enforced. Use IMAPS (port 993).",
    commonVulns: [
      "Cleartext credential transmission",
      "Credential brute-force",
      "STARTTLS stripping",
      "Information leakage via LIST/LSUB"
    ],
    testingCommands: [
      "nmap --script imap-capabilities,imap-brute -p 143 <target>",
      "telnet <target> 143",
      "hydra -l user -P pass.txt imap://<target>"
    ]
  },
  {
    name: "IMAPS",
    port: 993,
    transport: "TCP/TLS",
    description:
      "IMAP over TLS -- encrypted email retrieval and management. Implicit TLS from connection start.",
    securityNotes:
      "Preferred over IMAP+STARTTLS. Ensure strong TLS configuration and certificate validation.",
    commonVulns: [
      "Weak TLS configuration",
      "Credential brute-force",
      "Certificate pinning issues"
    ],
    testingCommands: [
      "openssl s_client -connect <target>:993",
      "nmap --script ssl-enum-ciphers -p 993 <target>"
    ]
  },

  // ---------- File Transfer ----------
  {
    name: "FTP",
    port: 21,
    transport: "TCP",
    description:
      "File Transfer Protocol -- transfers files between client and server. Uses separate control (21) and data channels. Active and passive modes.",
    securityNotes:
      "Credentials and data sent in cleartext. Anonymous access often enabled by default. Bounce attacks use the PORT command to proxy connections.",
    commonVulns: [
      "Cleartext credentials",
      "Anonymous login",
      "FTP bounce attack",
      "Directory traversal",
      "Buffer overflow in implementations (ProFTPD, vsftpd)",
      "Writable directories enabling malware upload"
    ],
    testingCommands: [
      "nmap --script ftp-anon,ftp-bounce,ftp-brute -p 21 <target>",
      "ftp <target>",
      "hydra -l user -P pass.txt ftp://<target>",
      "wget -r ftp://anonymous:@<target>/"
    ]
  },
  {
    name: "FTPS",
    port: 990,
    transport: "TCP/TLS",
    description:
      "FTP over TLS -- adds TLS encryption to FTP. Implicit TLS (port 990) or explicit via AUTH TLS on port 21.",
    securityNotes:
      "Better than plain FTP but complex firewall rules needed for data channel. SFTP (SSH) is generally preferred over FTPS.",
    commonVulns: [
      "Fallback to unencrypted FTP",
      "Complex firewall/NAT traversal",
      "Weak TLS configuration"
    ],
    testingCommands: [
      "openssl s_client -connect <target>:990",
      "curl --ftp-ssl ftp://<target>/",
      "lftp -e 'set ftp:ssl-force true' -u user <target>"
    ]
  },
  {
    name: "TFTP",
    port: 69,
    transport: "UDP",
    description:
      "Trivial File Transfer Protocol -- simple, lockstep file transfer with no authentication. Used for PXE boot, firmware updates, and network device configs.",
    securityNotes:
      "No authentication or encryption whatsoever. Anyone who can reach the port can read/write files. Restrict via firewall and directory chroot.",
    commonVulns: [
      "No authentication -- open read/write",
      "Directory traversal",
      "Information disclosure of configs",
      "Used in firmware supply-chain attacks"
    ],
    testingCommands: [
      "nmap -sU --script tftp-enum -p 69 <target>",
      "tftp <target>",
      "atftp --get --remote-file /etc/passwd --local-file passwd <target>"
    ]
  },
  {
    name: "SCP",
    port: 22,
    transport: "TCP/SSH",
    description:
      "Secure Copy Protocol -- file transfer over SSH. Provides encryption and authentication inherited from SSH. Being superseded by SFTP.",
    securityNotes:
      "Security depends on SSH configuration. Inherits all SSH security considerations. Does not support directory listing or resumption.",
    commonVulns: [
      "SSH key management issues",
      "Weak SSH configurations",
      "Command injection via filenames (CVE-2019-6111)"
    ],
    testingCommands: [
      "scp user@<target>:/path/to/file .",
      "nmap --script ssh2-enum-algos -p 22 <target>"
    ]
  },
  {
    name: "SFTP",
    port: 22,
    transport: "TCP/SSH",
    description:
      "SSH File Transfer Protocol -- secure file transfer subsystem of SSH. Not related to FTP despite the name. Supports resume, directory ops, and permissions.",
    securityNotes:
      "Encrypted and authenticated via SSH. Preferred over FTP/FTPS. Ensure SSH is properly hardened (key auth, disable root, strong ciphers).",
    commonVulns: [
      "SSH misconfiguration",
      "Weak credentials / password authentication",
      "Chroot escape in misconfigured setups"
    ],
    testingCommands: [
      "sftp user@<target>",
      "nmap --script ssh-brute -p 22 <target>"
    ]
  },

  // ---------- Remote Access ----------
  {
    name: "SSH",
    port: 22,
    transport: "TCP",
    description:
      "Secure Shell -- encrypted remote login, command execution, tunneling, and file transfer. Replaces Telnet, rlogin, rsh. Supports key-based and password authentication.",
    securityNotes:
      "Disable password auth in favor of key-based auth. Disable root login. Use fail2ban. Monitor for key compromise. Audit authorized_keys files regularly.",
    commonVulns: [
      "Credential brute-force",
      "Weak / default passwords",
      "SSH key theft or reuse",
      "Agent forwarding hijacking",
      "Known_hosts bypass / TOFU issues",
      "Vulnerable implementations (libssh auth bypass)"
    ],
    testingCommands: [
      "nmap --script ssh2-enum-algos,ssh-auth-methods,ssh-brute -p 22 <target>",
      "ssh-audit <target>",
      "hydra -l root -P pass.txt ssh://<target>",
      "ssh -v <target>"
    ]
  },
  {
    name: "Telnet",
    port: 23,
    transport: "TCP",
    description:
      "Teletype Network protocol -- unencrypted remote terminal access. Predates SSH. Still found on legacy systems, IoT devices, and network equipment.",
    securityNotes:
      "Everything is cleartext including credentials. Never use on untrusted networks. Replace with SSH everywhere possible.",
    commonVulns: [
      "Cleartext credentials",
      "Session hijacking",
      "MITM attacks",
      "Default credentials on IoT/network devices",
      "Banner information disclosure"
    ],
    testingCommands: [
      "nmap --script telnet-brute,telnet-encryption -p 23 <target>",
      "telnet <target> 23",
      "hydra -l admin -P pass.txt telnet://<target>"
    ]
  },
  {
    name: "RDP",
    port: 3389,
    transport: "TCP/UDP",
    description:
      "Remote Desktop Protocol -- Microsoft's graphical remote access protocol. Supports encryption via TLS, Network Level Authentication (NLA), and RemoteFX.",
    securityNotes:
      "Major attack surface. Enable NLA, use TLS (not RDP Security Layer), restrict via firewall/VPN. BlueKeep and DejaBlue were critical RCE vulnerabilities.",
    commonVulns: [
      "BlueKeep (CVE-2019-0708)",
      "DejaBlue (CVE-2019-1181/1182)",
      "Credential brute-force",
      "MITM without NLA",
      "Credential theft via RDP session",
      "Pass-the-hash over RDP"
    ],
    testingCommands: [
      "nmap --script rdp-enum-encryption,rdp-vuln-ms12-020 -p 3389 <target>",
      "xfreerdp /v:<target> /u:user /p:pass",
      "hydra -l admin -P pass.txt rdp://<target>",
      "rdp-sec-check <target>"
    ]
  },
  {
    name: "VNC",
    port: 5900,
    transport: "TCP",
    description:
      "Virtual Network Computing -- platform-independent graphical remote access using the RFB (Remote FrameBuffer) protocol.",
    securityNotes:
      "Weak authentication by default (DES-based password, max 8 chars). No user-level auth in many implementations. Always tunnel through SSH or VPN.",
    commonVulns: [
      "Weak / no authentication",
      "DES-limited 8-character passwords",
      "Unencrypted sessions",
      "Authentication bypass vulnerabilities",
      "Screenshot / keylogger exposure"
    ],
    testingCommands: [
      "nmap --script vnc-info,vnc-brute -p 5900 <target>",
      "vncviewer <target>",
      "hydra -P pass.txt vnc://<target>"
    ]
  },
  {
    name: "X11",
    port: 6000,
    transport: "TCP",
    description:
      "X Window System protocol -- provides GUI framework for Unix/Linux. Display servers listen on ports 6000+N where N is the display number.",
    securityNotes:
      "xhost + disables all access control. Network X11 exposes keystrokes and screen content. Always tunnel via SSH X forwarding.",
    commonVulns: [
      "Open X11 server (xhost +)",
      "Keystroke / screen capture",
      "X11 forwarding abuse",
      "Clipboard sniffing"
    ],
    testingCommands: [
      "nmap --script x11-access -p 6000 <target>",
      "xdpyinfo -display <target>:0",
      "xspy <target>"
    ]
  },

  // ---------- Directory & Authentication ----------
  {
    name: "LDAP",
    port: 389,
    transport: "TCP",
    description:
      "Lightweight Directory Access Protocol -- accesses and maintains distributed directory information services (Active Directory, OpenLDAP).",
    securityNotes:
      "Plaintext by default. Anonymous bind often enabled. LDAP injection possible via unsanitized search filters. Use LDAPS (636) or STARTTLS.",
    commonVulns: [
      "Anonymous bind / enumeration",
      "LDAP injection",
      "Cleartext credentials",
      "Password spray attacks",
      "Information disclosure via directory browsing"
    ],
    testingCommands: [
      "nmap --script ldap-rootdse,ldap-search -p 389 <target>",
      "ldapsearch -x -H ldap://<target> -b '' -s base",
      "ldapdomaindump -u '<domain>\\user' -p 'pass' <target>"
    ]
  },
  {
    name: "LDAPS",
    port: 636,
    transport: "TCP/TLS",
    description:
      "LDAP over TLS -- encrypted directory access. Implicit TLS from connection start.",
    securityNotes:
      "Encrypts the session but proper certificate validation and strong authentication are still required. Prefer over plain LDAP.",
    commonVulns: [
      "Weak TLS configuration",
      "Certificate validation bypass",
      "Still vulnerable to LDAP injection at application layer"
    ],
    testingCommands: [
      "openssl s_client -connect <target>:636",
      "ldapsearch -x -H ldaps://<target> -b '' -s base",
      "nmap --script ssl-enum-ciphers -p 636 <target>"
    ]
  },
  {
    name: "Kerberos",
    port: 88,
    transport: "TCP/UDP",
    description:
      "Network authentication protocol using tickets granted by a Key Distribution Center (KDC). Core of Active Directory authentication.",
    securityNotes:
      "Vulnerable to ticket-based attacks. Time synchronization critical (5-min default skew). Protect the KDC -- compromise means domain compromise.",
    commonVulns: [
      "Kerberoasting (service ticket cracking)",
      "AS-REP Roasting (no pre-auth accounts)",
      "Golden Ticket attack",
      "Silver Ticket attack",
      "Pass-the-Ticket",
      "Skeleton Key attack",
      "Unconstrained delegation abuse"
    ],
    testingCommands: [
      "nmap --script krb5-enum-users -p 88 <target>",
      "GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <target>",
      "GetNPUsers.py <domain>/ -dc-ip <target> -no-pass -usersfile users.txt",
      "rubeus.exe kerberoast"
    ]
  },
  {
    name: "RADIUS",
    port: 1812,
    transport: "UDP",
    description:
      "Remote Authentication Dial-In User Service -- centralized authentication, authorization, and accounting (AAA) for network access.",
    securityNotes:
      "Shared secret between client and server must be strong. MD5-based -- consider RADSEC (RADIUS over TLS) for modern deployments.",
    commonVulns: [
      "Weak shared secrets",
      "MD5 hash weakness",
      "Replay attacks",
      "Dictionary attacks on shared secret"
    ],
    testingCommands: [
      "radtest user pass <target> 0 sharedsecret",
      "nmap -sU --script radius-brute -p 1812 <target>"
    ]
  },
  {
    name: "TACACS+",
    port: 49,
    transport: "TCP",
    description:
      "Terminal Access Controller Access-Control System Plus -- Cisco-developed AAA protocol. Encrypts the entire packet body, unlike RADIUS.",
    securityNotes:
      "Full body encryption is better than RADIUS but uses a shared key. Key compromise exposes all traffic. TCP provides reliability over RADIUS's UDP.",
    commonVulns: [
      "Shared key compromise",
      "Weak key selection",
      "Implementation-specific bugs"
    ],
    testingCommands: [
      "nmap -sV -p 49 <target>",
      "tac_plus configuration review"
    ]
  },

  // ---------- Network File Sharing ----------
  {
    name: "SMB",
    port: 445,
    transport: "TCP",
    description:
      "Server Message Block -- network file sharing, printer sharing, and IPC on Windows networks. SMBv1 is deprecated; SMBv2/v3 support encryption and signing.",
    securityNotes:
      "SMBv1 is critically insecure (EternalBlue). Always disable SMBv1. Enable SMB signing and encryption. Restrict access via firewall -- never expose to internet.",
    commonVulns: [
      "EternalBlue (MS17-010)",
      "Null session enumeration",
      "SMB relay attacks (NTLM relay)",
      "Pass-the-Hash",
      "Share enumeration / writable shares",
      "PrintNightmare (CVE-2021-34527)"
    ],
    testingCommands: [
      "nmap --script smb-vuln-ms17-010,smb-enum-shares,smb-os-discovery -p 445 <target>",
      "smbclient -L //<target>/ -N",
      "enum4linux -a <target>",
      "crackmapexec smb <target> -u '' -p '' --shares",
      "smbmap -H <target>"
    ]
  },
  {
    name: "NetBIOS",
    port: 139,
    transport: "TCP",
    description:
      "Network Basic Input/Output System -- legacy name resolution and session service for Windows networking. SMB originally ran over NetBIOS.",
    securityNotes:
      "Exposes hostnames, domain membership, and logged-in users. Should be disabled unless required for legacy compatibility.",
    commonVulns: [
      "Name resolution poisoning (NBNS spoofing)",
      "Host and user enumeration",
      "Null session attacks",
      "MITM via name spoofing"
    ],
    testingCommands: [
      "nbtscan <target>/24",
      "nmap --script nbstat -sU -p 137 <target>",
      "nmblookup -A <target>"
    ]
  },
  {
    name: "NFS",
    port: 2049,
    transport: "TCP/UDP",
    description:
      "Network File System -- Unix/Linux file sharing protocol. NFSv4 uses TCP only and supports Kerberos authentication. NFSv3 relies on host-based trust.",
    securityNotes:
      "NFSv3 trusts client UIDs -- root squashing should be enabled. Exports should be restricted by IP. NFSv4 with Kerberos is strongly preferred.",
    commonVulns: [
      "Misconfigured exports (world-readable)",
      "UID/GID spoofing (NFSv3)",
      "Root squash bypass",
      "Information disclosure via showmount"
    ],
    testingCommands: [
      "showmount -e <target>",
      "nmap --script nfs-ls,nfs-showmount,nfs-statfs -p 2049 <target>",
      "mount -t nfs <target>:/share /mnt"
    ]
  },

  // ---------- Network Management ----------
  {
    name: "SNMP",
    port: 161,
    transport: "UDP",
    description:
      "Simple Network Management Protocol -- monitors and manages network devices. v1/v2c use community strings (passwords); v3 adds encryption and authentication.",
    securityNotes:
      "v1/v2c community strings are transmitted in cleartext. Default 'public' and 'private' strings are extremely common. Always use SNMPv3.",
    commonVulns: [
      "Default community strings (public/private)",
      "Cleartext community strings (v1/v2c)",
      "Information disclosure (system info, routes, ARP tables)",
      "Write access via 'private' community",
      "SNMP amplification DDoS"
    ],
    testingCommands: [
      "nmap -sU --script snmp-brute,snmp-info -p 161 <target>",
      "snmpwalk -v2c -c public <target>",
      "onesixtyone -c community.txt <target>",
      "snmp-check <target>"
    ]
  },
  {
    name: "SNMP Trap",
    port: 162,
    transport: "UDP",
    description:
      "SNMP Trap receiver -- devices send unsolicited notifications (traps) to the management station on this port.",
    securityNotes:
      "Trap receivers can be flooded or spoofed. Ensure trap sources are validated. Use SNMPv3 for authenticated traps.",
    commonVulns: [
      "Trap spoofing",
      "Trap flood DoS",
      "Information leakage in trap data"
    ],
    testingCommands: [
      "snmptrapd -f -Lo",
      "tcpdump -i eth0 udp port 162"
    ]
  },

  // ---------- Time ----------
  {
    name: "NTP",
    port: 123,
    transport: "UDP",
    description:
      "Network Time Protocol -- synchronizes clocks across networks. Critical for Kerberos, logging, TLS certificate validation, and forensics.",
    securityNotes:
      "NTP amplification attacks are common. Monlist command (older versions) returns large responses. Use NTS (Network Time Security) for authenticated time.",
    commonVulns: [
      "NTP amplification DDoS (monlist)",
      "Time-shifting attacks",
      "NTP mode 6 information disclosure",
      "Rogue NTP server injection"
    ],
    testingCommands: [
      "nmap -sU --script ntp-info,ntp-monlist -p 123 <target>",
      "ntpq -c peers <target>",
      "ntpdate -q <target>"
    ]
  },

  // ---------- Logging ----------
  {
    name: "Syslog",
    port: 514,
    transport: "UDP/TCP",
    description:
      "System Logging Protocol -- sends event notification messages. UDP (514) is traditional; TCP and TLS (6514) are more reliable and secure.",
    securityNotes:
      "UDP syslog is unauthenticated and unencrypted. Log injection and spoofing are possible. Use TLS syslog (RFC 5425) for integrity and confidentiality.",
    commonVulns: [
      "Log injection / tampering",
      "Log spoofing via UDP",
      "Information disclosure in log data",
      "DoS via log flooding"
    ],
    testingCommands: [
      "logger -n <target> -P 514 'test message'",
      "tcpdump -i eth0 udp port 514",
      "nmap -sU -p 514 <target>"
    ]
  },

  // ---------- Databases ----------
  {
    name: "MySQL",
    port: 3306,
    transport: "TCP",
    description:
      "MySQL/MariaDB database protocol -- widely used relational database. Supports SSL/TLS connections and various authentication plugins.",
    securityNotes:
      "Never expose to the internet. Use strong passwords and limit user privileges. Disable remote root login. Enable SSL for all connections.",
    commonVulns: [
      "Default / weak credentials",
      "SQL injection (application layer)",
      "Remote root login enabled",
      "Unencrypted connections",
      "Privilege escalation via UDF",
      "Information_schema enumeration"
    ],
    testingCommands: [
      "nmap --script mysql-info,mysql-enum,mysql-brute -p 3306 <target>",
      "mysql -h <target> -u root -p",
      "hydra -l root -P pass.txt mysql://<target>",
      "mysqlshow -h <target> -u root"
    ]
  },
  {
    name: "PostgreSQL",
    port: 5432,
    transport: "TCP",
    description:
      "PostgreSQL database protocol -- advanced open-source relational database. Supports SSL/TLS, SCRAM-SHA-256 auth, and row-level security.",
    securityNotes:
      "Default pg_hba.conf may allow trust authentication locally. Restrict listen_addresses. Use scram-sha-256 over md5 authentication.",
    commonVulns: [
      "Trust authentication misconfiguration",
      "Weak MD5 authentication",
      "SQL injection (application layer)",
      "COPY TO/FROM file read/write",
      "Privilege escalation via extensions",
      "Large object abuse"
    ],
    testingCommands: [
      "nmap --script pgsql-brute -p 5432 <target>",
      "psql -h <target> -U postgres",
      "hydra -l postgres -P pass.txt postgres://<target>"
    ]
  },
  {
    name: "MSSQL",
    port: 1433,
    transport: "TCP",
    description:
      "Microsoft SQL Server protocol (TDS) -- enterprise relational database. Supports Windows and SQL authentication, Always Encrypted, and TDE.",
    securityNotes:
      "sa account with weak password is a top finding. xp_cmdshell can execute OS commands. SQL Server Browser (UDP 1434) can reveal instances.",
    commonVulns: [
      "Weak sa password",
      "xp_cmdshell command execution",
      "SQL injection / stacked queries",
      "Linked server abuse",
      "NTLM hash capture via xp_dirtree",
      "SQL Server Browser instance enumeration"
    ],
    testingCommands: [
      "nmap --script ms-sql-info,ms-sql-brute,ms-sql-empty-password -p 1433 <target>",
      "sqsh -S <target> -U sa -P password",
      "crackmapexec mssql <target> -u sa -p pass",
      "mssqlclient.py <domain>/user:pass@<target>"
    ]
  },
  {
    name: "Oracle DB",
    port: 1521,
    transport: "TCP",
    description:
      "Oracle Database TNS Listener -- manages connections to Oracle database instances. Supports encryption and strong authentication via Oracle Advanced Security.",
    securityNotes:
      "TNS Listener has had many vulnerabilities. Default SIDs (ORCL, XE) are easily guessed. Poisoning attacks can redirect connections.",
    commonVulns: [
      "TNS Listener poisoning",
      "Default SID guessing",
      "Default credentials (scott/tiger, sys/change_on_install)",
      "Privilege escalation via PL/SQL injection",
      "TNS Listener information disclosure"
    ],
    testingCommands: [
      "nmap --script oracle-tns-version,oracle-sid-brute -p 1521 <target>",
      "odat all -s <target> -p 1521",
      "tnscmd10g status -h <target>"
    ]
  },
  {
    name: "MongoDB",
    port: 27017,
    transport: "TCP",
    description:
      "MongoDB wire protocol -- document-oriented NoSQL database. Supports replica sets, sharding, and TLS. Authentication disabled by default in older versions.",
    securityNotes:
      "Historically shipped with no authentication. Thousands of exposed instances have been ransomed. Always enable auth and bind to localhost or trusted interfaces.",
    commonVulns: [
      "No authentication (default in older versions)",
      "NoSQL injection",
      "SSRF via MongoDB protocol",
      "Data exfiltration / ransom",
      "Exposed REST interface"
    ],
    testingCommands: [
      "nmap --script mongodb-info,mongodb-databases -p 27017 <target>",
      "mongosh --host <target>",
      "nmap --script mongodb-brute -p 27017 <target>"
    ]
  },
  {
    name: "Redis",
    port: 6379,
    transport: "TCP",
    description:
      "Redis in-memory data structure store -- used as database, cache, and message broker. Supports Lua scripting, pub/sub, and clustering.",
    securityNotes:
      "No authentication by default. CONFIG SET and SLAVEOF commands can be abused for RCE. Always require password and restrict with ACLs (Redis 6+).",
    commonVulns: [
      "No authentication by default",
      "RCE via CONFIG SET (write webshell/cron/SSH key)",
      "SLAVEOF/REPLICAOF for data theft",
      "Lua sandbox escape",
      "INFO command information disclosure"
    ],
    testingCommands: [
      "nmap --script redis-info,redis-brute -p 6379 <target>",
      "redis-cli -h <target> INFO",
      "redis-cli -h <target> CONFIG GET *"
    ]
  },
  {
    name: "Memcached",
    port: 11211,
    transport: "TCP/UDP",
    description:
      "Distributed memory caching system -- caches database query results, session data, and API responses. No built-in authentication.",
    securityNotes:
      "No authentication or encryption. UDP interface has been used in massive amplification attacks (1.3 Tbps record). Bind to localhost only.",
    commonVulns: [
      "No authentication",
      "UDP amplification DDoS (stats/get commands)",
      "Data exfiltration via cache dumping",
      "Cache poisoning"
    ],
    testingCommands: [
      "nmap --script memcached-info -p 11211 <target>",
      "echo 'stats' | nc <target> 11211",
      "memcstat --servers=<target>"
    ]
  },
  {
    name: "Elasticsearch",
    port: 9200,
    transport: "TCP",
    description:
      "Elasticsearch REST API -- distributed search and analytics engine. JSON-based queries over HTTP. Part of the ELK stack.",
    securityNotes:
      "Historically no authentication (X-Pack Security added later). Exposed instances have been mass-compromised. Enable security features and TLS.",
    commonVulns: [
      "No authentication (older versions)",
      "Remote code execution via scripting",
      "Index data exfiltration",
      "Snapshot repository abuse",
      "SSRF via _search queries"
    ],
    testingCommands: [
      "curl http://<target>:9200/",
      "curl http://<target>:9200/_cat/indices",
      "curl http://<target>:9200/_search?pretty",
      "nmap --script http-elasticsearch -p 9200 <target>"
    ]
  },
  {
    name: "CouchDB",
    port: 5984,
    transport: "TCP",
    description:
      "Apache CouchDB REST API -- document-oriented NoSQL database with HTTP/JSON interface, multi-master replication, and MapReduce views.",
    securityNotes:
      "Admin party mode (no admin password) in older versions. REST API can be probed without authentication. CVE-2017-12635 allowed privilege escalation.",
    commonVulns: [
      "Admin party (no auth by default)",
      "Privilege escalation (CVE-2017-12635/12636)",
      "Remote code execution via query server",
      "Data exfiltration via replication"
    ],
    testingCommands: [
      "curl http://<target>:5984/",
      "curl http://<target>:5984/_all_dbs",
      "curl http://<target>:5984/_users/_all_docs"
    ]
  },

  // ---------- Message Queues & Streaming ----------
  {
    name: "RabbitMQ",
    port: 5672,
    transport: "TCP",
    description:
      "RabbitMQ AMQP broker -- message queuing with exchanges, queues, and bindings. Management UI on port 15672. Supports TLS and various auth backends.",
    securityNotes:
      "Default credentials guest/guest (restricted to localhost in recent versions). Management UI must be protected. Enable TLS for AMQP connections.",
    commonVulns: [
      "Default guest/guest credentials",
      "Management UI exposure",
      "Queue/exchange enumeration",
      "Message interception without TLS",
      "Erlang cookie compromise (cluster takeover)"
    ],
    testingCommands: [
      "nmap -sV -p 5672,15672 <target>",
      "curl -u guest:guest http://<target>:15672/api/overview",
      "rabbitmqadmin -H <target> -u guest -p guest list queues"
    ]
  },
  {
    name: "MQTT",
    port: 1883,
    transport: "TCP",
    description:
      "Message Queuing Telemetry Transport -- lightweight pub/sub messaging for IoT devices. Minimal overhead, QoS levels 0-2. TLS on port 8883.",
    securityNotes:
      "No authentication required by default in many brokers. Topic wildcards (#, +) can subscribe to all messages. Use TLS and require client authentication.",
    commonVulns: [
      "Anonymous access (no auth)",
      "Wildcard topic subscription (#)",
      "Cleartext credentials",
      "Message injection / spoofing",
      "Broker misconfiguration"
    ],
    testingCommands: [
      "mosquitto_sub -h <target> -t '#' -v",
      "mosquitto_pub -h <target> -t 'test' -m 'hello'",
      "nmap -sV -p 1883,8883 <target>",
      "mqtt-pwn"
    ]
  },
  {
    name: "AMQP",
    port: 5672,
    transport: "TCP",
    description:
      "Advanced Message Queuing Protocol -- open standard for message-oriented middleware. Wire-level protocol supporting queuing, routing, pub/sub, and transactions.",
    securityNotes:
      "Authentication via SASL. TLS should be used (AMQPS on port 5671). Proper ACLs on exchanges and queues are essential.",
    commonVulns: [
      "Default credentials",
      "Unencrypted connections",
      "Exchange/queue permission issues",
      "Message injection"
    ],
    testingCommands: [
      "nmap -sV -p 5672 <target>",
      "amqp-tools (amqp-consume, amqp-publish)"
    ]
  },
  {
    name: "Kafka",
    port: 9092,
    transport: "TCP",
    description:
      "Apache Kafka broker -- distributed streaming platform for high-throughput event pipelines. Uses ZooKeeper (port 2181) or KRaft for coordination.",
    securityNotes:
      "No authentication or encryption by default. Supports SASL/SSL. ZooKeeper exposure can allow topic manipulation. Use ACLs and TLS.",
    commonVulns: [
      "No authentication by default",
      "ZooKeeper exposure",
      "Topic enumeration and data theft",
      "Consumer group manipulation",
      "Unencrypted inter-broker traffic"
    ],
    testingCommands: [
      "kafkacat -L -b <target>:9092",
      "kafka-topics.sh --list --bootstrap-server <target>:9092",
      "nmap -sV -p 9092,2181 <target>"
    ]
  },

  // ---------- VoIP & Multimedia ----------
  {
    name: "SIP",
    port: 5060,
    transport: "UDP/TCP",
    description:
      "Session Initiation Protocol -- signaling for VoIP calls, video, and messaging. Uses SDP for media description. SIP over TLS on port 5061.",
    securityNotes:
      "Cleartext by default. SIP scanning and toll fraud are major threats. Use TLS and SRTP for encrypted signaling and media. Implement strong authentication.",
    commonVulns: [
      "SIP enumeration / scanning",
      "Toll fraud / call hijacking",
      "Registration hijacking",
      "Credential brute-force",
      "Eavesdropping on calls",
      "SIP INVITE flooding DoS"
    ],
    testingCommands: [
      "svmap <target>",
      "svwar -m INVITE <target>",
      "sipvicious (svmap, svwar, svcrack)",
      "nmap --script sip-methods,sip-enum-users -sU -p 5060 <target>"
    ]
  },
  {
    name: "RTP",
    port: null,
    transport: "UDP",
    description:
      "Real-time Transport Protocol -- carries audio/video media in VoIP and streaming. Dynamic port range (typically 16384-32767). SRTP adds encryption.",
    securityNotes:
      "Unencrypted by default. Media streams can be captured and reconstructed. Always use SRTP for encryption. Monitor for unauthorized media flows.",
    commonVulns: [
      "Media stream eavesdropping",
      "RTP injection (audio/video)",
      "SRTP key negotiation weaknesses",
      "Codec-based attacks"
    ],
    testingCommands: [
      "tcpdump -i eth0 udp portrange 16384-32767",
      "wireshark: rtp filter",
      "rtpbreak -r <pcap>"
    ]
  },
  {
    name: "RTSP",
    port: 554,
    transport: "TCP",
    description:
      "Real Time Streaming Protocol -- controls streaming media servers (IP cameras, media servers). Similar to HTTP but stateful with session tracking.",
    securityNotes:
      "Often exposed without authentication on IP cameras. Default credentials are extremely common. Streams can be accessed or redirected by attackers.",
    commonVulns: [
      "Default credentials on IP cameras",
      "Unauthenticated stream access",
      "Path traversal to hidden streams",
      "Buffer overflow in implementations",
      "RTSP URL brute-forcing"
    ],
    testingCommands: [
      "nmap --script rtsp-url-brute -p 554 <target>",
      "cameradar <target>",
      "ffplay rtsp://<target>/stream",
      "vlc rtsp://<target>/stream"
    ]
  },

  // ---------- Routing Protocols ----------
  {
    name: "BGP",
    port: 179,
    transport: "TCP",
    description:
      "Border Gateway Protocol -- inter-domain routing protocol of the internet. Exchanges routing information between autonomous systems (AS).",
    securityNotes:
      "BGP hijacking can redirect internet traffic. No built-in authentication (MD5 optional). RPKI and BGPsec add route origin validation.",
    commonVulns: [
      "BGP hijacking / prefix hijacking",
      "Route leaks",
      "TCP RST attacks on BGP sessions",
      "Missing RPKI validation",
      "Peer session spoofing"
    ],
    testingCommands: [
      "nmap -sV -p 179 <target>",
      "bgpq4 -4 -l prefix-list AS<number>",
      "looking glass queries"
    ]
  },
  {
    name: "OSPF",
    port: null,
    transport: "IP Protocol 89",
    description:
      "Open Shortest Path First -- link-state interior routing protocol. Uses Dijkstra's algorithm. Supports areas, authentication (MD5/SHA), and multi-area topologies.",
    securityNotes:
      "Without authentication, rogue routers can inject false LSAs and redirect traffic. Use MD5 or SHA authentication on all OSPF interfaces.",
    commonVulns: [
      "Unauthenticated LSA injection",
      "Rogue OSPF router",
      "Traffic redirection via false routes",
      "Passive eavesdropping of topology"
    ],
    testingCommands: [
      "tcpdump -i eth0 'ip proto 89'",
      "wireshark: ospf filter",
      "Loki OSPF attack tool"
    ]
  },
  {
    name: "RIP",
    port: 520,
    transport: "UDP",
    description:
      "Routing Information Protocol -- distance-vector routing protocol. RIPv1 has no auth; RIPv2 adds MD5. Limited to 15-hop networks.",
    securityNotes:
      "RIPv1 broadcasts routes with no authentication. Even RIPv2 MD5 auth is weak. Easily poisoned to redirect traffic. Largely obsolete.",
    commonVulns: [
      "Route injection (no auth in v1)",
      "Traffic redirection",
      "Network topology discovery",
      "MD5 weakness in v2"
    ],
    testingCommands: [
      "tcpdump -i eth0 udp port 520",
      "wireshark: rip filter"
    ]
  },
  {
    name: "VRRP",
    port: null,
    transport: "IP Protocol 112",
    description:
      "Virtual Router Redundancy Protocol -- provides automatic failover for default gateways using virtual IP addresses shared among routers.",
    securityNotes:
      "Without authentication, an attacker can become the master router and intercept all traffic. Use HMAC-SHA authentication.",
    commonVulns: [
      "Master router takeover",
      "MITM via virtual IP hijacking",
      "Preemption abuse"
    ],
    testingCommands: [
      "tcpdump -i eth0 'ip proto 112'",
      "wireshark: vrrp filter",
      "Loki VRRP attack tool"
    ]
  },
  {
    name: "HSRP",
    port: 1985,
    transport: "UDP",
    description:
      "Hot Standby Router Protocol -- Cisco proprietary gateway redundancy protocol. Similar to VRRP but Cisco-specific with different packet format.",
    securityNotes:
      "v1 sends plaintext auth. v2 supports MD5 but rarely configured. Attackers can become the active router and intercept traffic.",
    commonVulns: [
      "Active router takeover",
      "Plaintext authentication (v1)",
      "MITM via priority manipulation"
    ],
    testingCommands: [
      "tcpdump -i eth0 udp port 1985",
      "yersinia -G (HSRP attacks)",
      "wireshark: hsrp filter"
    ]
  },

  // ---------- Industrial / SCADA ----------
  {
    name: "Modbus",
    port: 502,
    transport: "TCP",
    description:
      "Modbus TCP -- industrial control protocol for PLCs and SCADA systems. Simple request/response with no authentication or encryption. Master/slave architecture.",
    securityNotes:
      "No authentication, authorization, or encryption. Any network access allows reading/writing registers and coils. Never expose to untrusted networks.",
    commonVulns: [
      "No authentication whatsoever",
      "Register/coil read and write",
      "Replay attacks",
      "Device enumeration",
      "Process manipulation"
    ],
    testingCommands: [
      "nmap --script modbus-discover -p 502 <target>",
      "mbtget -a 1 -r 0 -n 10 <target>",
      "modbus-cli read <target> 0 10"
    ]
  },
  {
    name: "DNP3",
    port: 20000,
    transport: "TCP/UDP",
    description:
      "Distributed Network Protocol 3 -- SCADA protocol for electric utilities, water systems, and other critical infrastructure. Supports unsolicited responses.",
    securityNotes:
      "DNP3 Secure Authentication (SA) adds challenge-response but is rarely deployed. Plaintext by default. Critical for infrastructure security.",
    commonVulns: [
      "No authentication (without SA)",
      "Control command injection",
      "Traffic replay",
      "Fuzzing / protocol manipulation",
      "Infrastructure sabotage"
    ],
    testingCommands: [
      "nmap --script dnp3-info -p 20000 <target>",
      "Aegis DNP3 testing tool",
      "wireshark: dnp3 filter"
    ]
  },
  {
    name: "BACnet",
    port: 47808,
    transport: "UDP",
    description:
      "Building Automation and Control Networks -- protocol for HVAC, lighting, access control, and fire detection systems in smart buildings.",
    securityNotes:
      "No encryption or strong authentication. Accessible via broadcast. Attackers can manipulate building systems -- temperature, locks, alarms.",
    commonVulns: [
      "No authentication",
      "Device enumeration",
      "Property read/write",
      "Building system manipulation"
    ],
    testingCommands: [
      "nmap -sU --script bacnet-info -p 47808 <target>",
      "bacnet-tools (bacrp, bacwp)"
    ]
  },
  {
    name: "EtherNet/IP",
    port: 44818,
    transport: "TCP/UDP",
    description:
      "Ethernet/Industrial Protocol -- CIP (Common Industrial Protocol) over Ethernet for industrial automation. Used by Allen-Bradley/Rockwell PLCs.",
    securityNotes:
      "No built-in security. Relies on network segmentation. CIP commands can read/write PLC memory and change configurations.",
    commonVulns: [
      "No authentication",
      "PLC memory read/write",
      "Configuration tampering",
      "Firmware manipulation"
    ],
    testingCommands: [
      "nmap --script enip-info -p 44818 <target>",
      "python-ethernetip library"
    ]
  },
  {
    name: "OPC UA",
    port: 4840,
    transport: "TCP",
    description:
      "Open Platform Communications Unified Architecture -- platform-independent industrial communication. Supports encryption, authentication, and fine-grained access control.",
    securityNotes:
      "Most secure ICS protocol when properly configured. Supports X.509 certificates and secure channels. Misconfigurations can disable security entirely.",
    commonVulns: [
      "Security Mode set to None",
      "Anonymous authentication enabled",
      "Self-signed certificate acceptance",
      "Implementation-specific bugs"
    ],
    testingCommands: [
      "nmap -sV -p 4840 <target>",
      "opcua-client tools",
      "UaExpert OPC UA client"
    ]
  },
  {
    name: "S7comm",
    port: 102,
    transport: "TCP",
    description:
      "Siemens S7 Communication -- proprietary protocol for Siemens S7 PLCs (S7-300, S7-400, S7-1200, S7-1500). Runs over ISO-TSAP (RFC 1006).",
    securityNotes:
      "No authentication in S7comm. S7comm-plus (S7-1200/1500) adds some protections but has been reverse-engineered. Critical infrastructure target.",
    commonVulns: [
      "No authentication",
      "PLC stop/start commands",
      "Memory read/write",
      "Firmware upload",
      "CPU state manipulation"
    ],
    testingCommands: [
      "nmap --script s7-info -p 102 <target>",
      "plcscan -i <target>",
      "snap7 tools"
    ]
  },

  // ---------- Proxy & Tunneling ----------
  {
    name: "SOCKS",
    port: 1080,
    transport: "TCP",
    description:
      "SOCKS proxy protocol -- routes network packets between client and server through a proxy. SOCKS5 supports authentication and UDP relay.",
    securityNotes:
      "Open SOCKS proxies are abused for anonymization and attack pivoting. Always require authentication. Monitor for unauthorized proxy usage.",
    commonVulns: [
      "Open proxy abuse",
      "No authentication",
      "Lateral movement / pivoting",
      "Traffic anonymization for attacks"
    ],
    testingCommands: [
      "nmap --script socks-open-proxy -p 1080 <target>",
      "curl --socks5 <target>:1080 http://ifconfig.me",
      "proxychains nmap <internal-target>"
    ]
  },
  {
    name: "HTTP Proxy",
    port: 3128,
    transport: "TCP",
    description:
      "HTTP forward/reverse proxy -- Squid commonly runs on 3128. Caches content, filters requests, and provides access control.",
    securityNotes:
      "Open proxies enable anonymous browsing and cache poisoning. Misconfigured proxies can expose internal networks. CONNECT method can tunnel any protocol.",
    commonVulns: [
      "Open proxy abuse",
      "Cache poisoning",
      "CONNECT method tunneling to internal hosts",
      "Access control bypass",
      "Information disclosure via X-Forwarded-For"
    ],
    testingCommands: [
      "nmap --script http-open-proxy -p 3128 <target>",
      "curl -x http://<target>:3128 http://ifconfig.me",
      "nmap --script http-proxy-brute -p 3128 <target>"
    ]
  },

  // ---------- VPN ----------
  {
    name: "IPSec/IKE",
    port: 500,
    transport: "UDP",
    description:
      "Internet Key Exchange -- negotiates security associations for IPSec VPN tunnels. IKEv1 and IKEv2. NAT-T uses port 4500.",
    securityNotes:
      "IKEv1 aggressive mode reveals the hash of the pre-shared key. Use IKEv2 or IKEv1 main mode with certificates. Weak PSKs are crackable.",
    commonVulns: [
      "IKEv1 aggressive mode PSK cracking",
      "Weak pre-shared keys",
      "VPN gateway fingerprinting",
      "Dead peer detection information disclosure"
    ],
    testingCommands: [
      "ike-scan -M <target>",
      "nmap -sU --script ike-version -p 500 <target>",
      "ikeforce <target>"
    ]
  },
  {
    name: "OpenVPN",
    port: 1194,
    transport: "UDP/TCP",
    description:
      "Open-source VPN using OpenSSL for encryption. Supports TLS-based key exchange, certificate authentication, and multiple tunneling modes (TUN/TAP).",
    securityNotes:
      "Security depends on certificate management and cipher configuration. Use tls-auth/tls-crypt to prevent unauthorized connection attempts.",
    commonVulns: [
      "Weak cipher configuration",
      "Missing tls-auth (DoS vulnerability)",
      "Certificate validation bypass",
      "Credential brute-force"
    ],
    testingCommands: [
      "nmap -sV -p 1194 <target>",
      "openvpn --remote <target> --dev tun",
      "nmap -sU -sV -p 1194 <target>"
    ]
  },
  {
    name: "WireGuard",
    port: 51820,
    transport: "UDP",
    description:
      "Modern VPN protocol -- minimal attack surface (~4000 lines of code), uses Noise protocol framework, Curve25519, ChaCha20, and Poly1305.",
    securityNotes:
      "Cryptographically sound but does not provide IP hiding (endpoints are visible). No dynamic IP allocation built in. Key management is manual.",
    commonVulns: [
      "Endpoint discovery (no stealth mode)",
      "Key compromise",
      "Missing key rotation",
      "Side-channel timing analysis"
    ],
    testingCommands: [
      "nmap -sU -p 51820 <target>",
      "wg show"
    ]
  },

  // ---------- Miscellaneous ----------
  {
    name: "LLMNR",
    port: 5355,
    transport: "UDP",
    description:
      "Link-Local Multicast Name Resolution -- Windows name resolution fallback when DNS fails. Multicast-based, local subnet only.",
    securityNotes:
      "Responds to any name query on the local network. Attackers use Responder to capture NTLMv2 hashes. Disable LLMNR via Group Policy.",
    commonVulns: [
      "LLMNR spoofing / poisoning",
      "NTLMv2 hash capture",
      "MITM credential relay",
      "Pass-the-hash attacks"
    ],
    testingCommands: [
      "responder -I eth0 -rdwv",
      "Inveigh (PowerShell)",
      "tcpdump -i eth0 udp port 5355"
    ]
  },
  {
    name: "NBT-NS",
    port: 137,
    transport: "UDP",
    description:
      "NetBIOS Name Service -- legacy Windows name resolution. Falls back when DNS and LLMNR fail. Broadcast-based.",
    securityNotes:
      "Same poisoning risks as LLMNR. Attackers spoof responses to capture credentials. Disable via network adapter settings.",
    commonVulns: [
      "Name resolution spoofing",
      "NTLMv2 hash capture",
      "Credential relay attacks"
    ],
    testingCommands: [
      "responder -I eth0 -rdwv",
      "nbtscan <target>/24"
    ]
  },
  {
    name: "WPAD",
    port: 80,
    transport: "TCP",
    description:
      "Web Proxy Auto-Discovery -- automatically configures browser proxy settings via DHCP or DNS lookup of wpad.<domain>. Serves PAC files.",
    securityNotes:
      "Attackers can serve malicious PAC files to redirect all web traffic through their proxy. Disable WPAD if not needed.",
    commonVulns: [
      "WPAD spoofing / hijacking",
      "Malicious PAC file injection",
      "Traffic interception via rogue proxy",
      "NTLM credential capture"
    ],
    testingCommands: [
      "responder -I eth0 -wFb",
      "curl http://wpad.<domain>/wpad.dat"
    ]
  },
  {
    name: "PPTP",
    port: 1723,
    transport: "TCP",
    description:
      "Point-to-Point Tunneling Protocol -- legacy VPN protocol using GRE for tunneling. MS-CHAPv2 authentication is cryptographically broken.",
    securityNotes:
      "MS-CHAPv2 can be cracked to a single DES key. Do not use PPTP for any security-sensitive applications. Migrate to IPSec, OpenVPN, or WireGuard.",
    commonVulns: [
      "MS-CHAPv2 cracking (100% success rate)",
      "GRE-based attacks",
      "Credential capture",
      "DES weakness exploitation"
    ],
    testingCommands: [
      "nmap -sV -p 1723 <target>",
      "thc-pptp-bruter <target>"
    ]
  },
  {
    name: "L2TP",
    port: 1701,
    transport: "UDP",
    description:
      "Layer 2 Tunneling Protocol -- tunneling protocol often combined with IPSec for encryption. No built-in encryption on its own.",
    securityNotes:
      "Must be paired with IPSec for security. L2TP alone provides no confidentiality. IKE/IPSec negotiation adds complexity and potential misconfiguration.",
    commonVulns: [
      "No encryption without IPSec",
      "IPSec misconfiguration",
      "Pre-shared key weakness",
      "Tunnel endpoint spoofing"
    ],
    testingCommands: [
      "nmap -sU -p 1701 <target>",
      "ike-scan <target>"
    ]
  },
  {
    name: "STUN",
    port: 3478,
    transport: "UDP/TCP",
    description:
      "Session Traversal Utilities for NAT -- helps applications discover their public IP and port mappings for NAT traversal in VoIP and WebRTC.",
    securityNotes:
      "STUN servers can be used for amplification. Information disclosure of internal network topology. Used with TURN for relay when direct connection fails.",
    commonVulns: [
      "Amplification attacks",
      "Internal IP disclosure",
      "NAT traversal for unauthorized access"
    ],
    testingCommands: [
      "stun <target>",
      "nmap -sU -p 3478 <target>"
    ]
  },
  {
    name: "TURN",
    port: 3478,
    transport: "UDP/TCP",
    description:
      "Traversal Using Relays around NAT -- provides relay servers when direct peer-to-peer connection is not possible. Used by WebRTC applications.",
    securityNotes:
      "TURN servers relay traffic and consume bandwidth. Require authentication to prevent abuse. Can be used as open proxies if misconfigured.",
    commonVulns: [
      "Open relay abuse",
      "Credential brute-force",
      "Bandwidth exhaustion",
      "Proxy tunneling through TURN"
    ],
    testingCommands: [
      "turnutils_uclient <target>",
      "nmap -sU -p 3478 <target>"
    ]
  },
  {
    name: "XMPP",
    port: 5222,
    transport: "TCP",
    description:
      "Extensible Messaging and Presence Protocol -- open standard for instant messaging, presence, and real-time communication. Used by Jabber clients.",
    securityNotes:
      "Supports STARTTLS but must be enforced. Server-to-server (port 5269) federation can be abused. Ensure proper certificate validation.",
    commonVulns: [
      "STARTTLS stripping",
      "User enumeration",
      "Message interception without TLS",
      "Federation abuse"
    ],
    testingCommands: [
      "nmap --script xmpp-info -p 5222 <target>",
      "xmpp-client connect to <target>"
    ]
  },
  {
    name: "IRC",
    port: 6667,
    transport: "TCP",
    description:
      "Internet Relay Chat -- real-time text messaging protocol. Used for legitimate chat and historically as C2 channels for botnets.",
    securityNotes:
      "Unencrypted by default (TLS on 6697). Frequently used for botnet command and control. DCC file transfers can deliver malware.",
    commonVulns: [
      "Cleartext communication",
      "Botnet C2 channel",
      "DCC file transfer abuse",
      "Channel flooding DoS",
      "Nick/channel takeover"
    ],
    testingCommands: [
      "nmap --script irc-info,irc-brute -p 6667 <target>",
      "irssi -c <target>"
    ]
  },
  {
    name: "rsync",
    port: 873,
    transport: "TCP",
    description:
      "rsync file synchronization -- efficient delta-transfer algorithm for synchronizing files. Can run as daemon or over SSH.",
    securityNotes:
      "Daemon mode can expose modules without authentication. Sensitive files may be accessible. Always use rsync over SSH for security.",
    commonVulns: [
      "Anonymous module access",
      "Sensitive file exposure",
      "No encryption in daemon mode",
      "World-writable modules"
    ],
    testingCommands: [
      "nmap --script rsync-list-modules -p 873 <target>",
      "rsync <target>::",
      "rsync -av rsync://<target>/module ."
    ]
  },
  {
    name: "Docker API",
    port: 2375,
    transport: "TCP",
    description:
      "Docker Engine REST API -- manages containers, images, volumes, and networks. Port 2375 is unencrypted; 2376 uses TLS.",
    securityNotes:
      "Unauthenticated Docker API gives root-equivalent access to the host. Can create privileged containers, mount host filesystem, and execute arbitrary commands.",
    commonVulns: [
      "Unauthenticated API (RCE as root)",
      "Container escape via privileged mode",
      "Host filesystem mount",
      "Image supply chain attacks"
    ],
    testingCommands: [
      "curl http://<target>:2375/version",
      "curl http://<target>:2375/containers/json",
      "docker -H tcp://<target>:2375 ps",
      "nmap -sV -p 2375,2376 <target>"
    ]
  },
  {
    name: "Kubernetes API",
    port: 6443,
    transport: "TCP/TLS",
    description:
      "Kubernetes API Server -- central management endpoint for Kubernetes clusters. All cluster operations go through this RESTful API.",
    securityNotes:
      "Misconfigured RBAC or anonymous access can allow cluster takeover. kubelet API (10250) and etcd (2379) are also critical attack surfaces.",
    commonVulns: [
      "Anonymous authentication enabled",
      "Overly permissive RBAC",
      "Exposed kubelet API",
      "etcd exposure (all cluster secrets)",
      "Service account token abuse"
    ],
    testingCommands: [
      "curl -k https://<target>:6443/api",
      "kubectl --server=https://<target>:6443 get pods",
      "nmap -sV -p 6443,10250,2379 <target>"
    ]
  },
  {
    name: "etcd",
    port: 2379,
    transport: "TCP",
    description:
      "etcd distributed key-value store -- Kubernetes uses it to store all cluster state including secrets. Raft consensus protocol.",
    securityNotes:
      "Contains all Kubernetes secrets in plain. Unauthenticated access means full cluster compromise. Always require client certificate authentication.",
    commonVulns: [
      "Unauthenticated access",
      "Secret exfiltration",
      "Cluster state manipulation",
      "Snapshot theft"
    ],
    testingCommands: [
      "etcdctl --endpoints=http://<target>:2379 get / --prefix",
      "curl http://<target>:2379/v2/keys/",
      "nmap -sV -p 2379 <target>"
    ]
  },
  {
    name: "ZooKeeper",
    port: 2181,
    transport: "TCP",
    description:
      "Apache ZooKeeper -- centralized coordination service for distributed systems. Stores configuration, naming, synchronization, and group services.",
    securityNotes:
      "No authentication by default. Four-letter commands (ruok, dump, envi) can leak sensitive information. SASL authentication available but rarely configured.",
    commonVulns: [
      "No authentication",
      "Four-letter command information disclosure",
      "Configuration manipulation",
      "ZNode data theft"
    ],
    testingCommands: [
      "echo ruok | nc <target> 2181",
      "echo dump | nc <target> 2181",
      "echo envi | nc <target> 2181",
      "nmap -sV -p 2181 <target>"
    ]
  },
  {
    name: "Consul",
    port: 8500,
    transport: "TCP",
    description:
      "HashiCorp Consul -- service discovery, configuration, and orchestration. HTTP API on 8500, DNS on 8600, RPC on 8300.",
    securityNotes:
      "Default configuration has no ACLs. Can read/write KV store, deregister services, and execute scripts. Enable ACL system and TLS.",
    commonVulns: [
      "No ACLs by default",
      "KV store data theft",
      "Service deregistration DoS",
      "Script execution via exec API",
      "Agent API abuse"
    ],
    testingCommands: [
      "curl http://<target>:8500/v1/catalog/services",
      "curl http://<target>:8500/v1/kv/?recurse",
      "curl http://<target>:8500/v1/agent/members"
    ]
  },
  {
    name: "WinRM",
    port: 5985,
    transport: "TCP",
    description:
      "Windows Remote Management -- Microsoft implementation of WS-Management protocol. HTTP on 5985, HTTPS on 5986. Used by PowerShell remoting.",
    securityNotes:
      "Allows remote command execution. Credential relay attacks possible. Restrict to trusted networks. Use HTTPS (5986) with proper certificates.",
    commonVulns: [
      "Credential brute-force",
      "Pass-the-hash",
      "NTLM relay",
      "PowerShell remote code execution",
      "Unencrypted HTTP transport"
    ],
    testingCommands: [
      "evil-winrm -i <target> -u user -p pass",
      "crackmapexec winrm <target> -u user -p pass",
      "nmap -sV -p 5985,5986 <target>"
    ]
  }
];


// ========================== 2. NMAP_SCRIPTS =================================
// 80+ NSE (Nmap Scripting Engine) scripts organized by category.
// ============================================================================

const NMAP_SCRIPTS = [
  // ---------- Discovery ----------
  {
    name: "dns-brute",
    category: "discovery",
    description:
      "Attempts to enumerate DNS hostnames by brute forcing popular subdomain names against a domain.",
    usage: "nmap --script dns-brute --script-args dns-brute.domain=<domain>"
  },
  {
    name: "dns-zone-transfer",
    category: "discovery",
    description:
      "Requests a zone transfer (AXFR) from a DNS server. Successful transfers reveal all DNS records for the domain.",
    usage: "nmap --script dns-zone-transfer -p 53 <target>"
  },
  {
    name: "http-enum",
    category: "discovery",
    description:
      "Enumerates directories, files, and common web application paths on HTTP servers using a fingerprint database.",
    usage: "nmap --script http-enum -p 80,443 <target>"
  },
  {
    name: "http-headers",
    category: "discovery",
    description:
      "Performs a HEAD request and reports the HTTP response headers. Useful for identifying security headers and server information.",
    usage: "nmap --script http-headers -p 80,443 <target>"
  },
  {
    name: "http-methods",
    category: "discovery",
    description:
      "Checks which HTTP methods (GET, POST, PUT, DELETE, TRACE, OPTIONS) are allowed on a web server.",
    usage: "nmap --script http-methods -p 80,443 <target>"
  },
  {
    name: "http-title",
    category: "discovery",
    description:
      "Shows the title of the default page of a web server. Quick way to identify web applications.",
    usage: "nmap --script http-title -p 80,443 <target>"
  },
  {
    name: "http-robots.txt",
    category: "discovery",
    description:
      "Retrieves and parses the robots.txt file, which often reveals hidden directories and sensitive paths.",
    usage: "nmap --script http-robots.txt -p 80,443 <target>"
  },
  {
    name: "http-sitemap-generator",
    category: "discovery",
    description:
      "Spiders a web server and generates a sitemap showing directory structure and file types.",
    usage: "nmap --script http-sitemap-generator -p 80 <target>"
  },
  {
    name: "smb-os-discovery",
    category: "discovery",
    description:
      "Determines the OS, computer name, domain, workgroup, and current time over SMB. Works with SMBv1 and SMBv2.",
    usage: "nmap --script smb-os-discovery -p 445 <target>"
  },
  {
    name: "smb-enum-shares",
    category: "discovery",
    description:
      "Enumerates SMB shares and checks read/write access permissions for each share.",
    usage: "nmap --script smb-enum-shares -p 445 <target>"
  },
  {
    name: "smb-enum-users",
    category: "discovery",
    description:
      "Enumerates users on a Windows system through SMB using SAMR or LSA queries.",
    usage: "nmap --script smb-enum-users -p 445 <target>"
  },
  {
    name: "smb-enum-sessions",
    category: "discovery",
    description:
      "Enumerates active SMB sessions and logged-in users on a target system.",
    usage: "nmap --script smb-enum-sessions -p 445 <target>"
  },
  {
    name: "snmp-info",
    category: "discovery",
    description:
      "Extracts system information from SNMP-enabled devices including sysDescr, sysName, and sysContact.",
    usage: "nmap -sU --script snmp-info -p 161 <target>"
  },
  {
    name: "snmp-interfaces",
    category: "discovery",
    description:
      "Enumerates network interfaces via SNMP including IP addresses, types, and status.",
    usage: "nmap -sU --script snmp-interfaces -p 161 <target>"
  },
  {
    name: "snmp-processes",
    category: "discovery",
    description:
      "Enumerates running processes via SNMP, revealing software installed and services running on the target.",
    usage: "nmap -sU --script snmp-processes -p 161 <target>"
  },
  {
    name: "snmp-sysdescr",
    category: "discovery",
    description:
      "Retrieves SNMP system description string which often reveals device type, OS version, and firmware.",
    usage: "nmap -sU --script snmp-sysdescr -p 161 <target>"
  },
  {
    name: "nbstat",
    category: "discovery",
    description:
      "Queries NetBIOS name service for hostnames, MAC addresses, and logged-in users on Windows systems.",
    usage: "nmap -sU --script nbstat -p 137 <target>"
  },
  {
    name: "broadcast-dhcp-discover",
    category: "discovery",
    description:
      "Sends a DHCP Discover broadcast and reports DHCP server responses including offered IP, gateway, DNS, and lease time.",
    usage: "nmap --script broadcast-dhcp-discover"
  },
  {
    name: "ldap-rootdse",
    category: "discovery",
    description:
      "Retrieves LDAP Root DSE information including naming contexts, supported controls, and server capabilities.",
    usage: "nmap --script ldap-rootdse -p 389 <target>"
  },
  {
    name: "ldap-search",
    category: "discovery",
    description:
      "Performs an LDAP search against a directory server, returning objects matching specified filters.",
    usage: "nmap --script ldap-search -p 389 <target>"
  },
  {
    name: "nfs-showmount",
    category: "discovery",
    description:
      "Shows NFS export list similar to showmount -e. Reveals shared directories and access restrictions.",
    usage: "nmap --script nfs-showmount -p 2049 <target>"
  },
  {
    name: "nfs-ls",
    category: "discovery",
    description:
      "Lists files in NFS exports. Can reveal sensitive files accessible via misconfigured NFS shares.",
    usage: "nmap --script nfs-ls -p 2049 <target>"
  },
  {
    name: "mysql-info",
    category: "discovery",
    description:
      "Connects to MySQL and retrieves version, protocol, capabilities, and server status.",
    usage: "nmap --script mysql-info -p 3306 <target>"
  },
  {
    name: "mysql-enum",
    category: "discovery",
    description:
      "Enumerates valid MySQL usernames using a timing side-channel in the authentication protocol.",
    usage: "nmap --script mysql-enum -p 3306 <target>"
  },
  {
    name: "ms-sql-info",
    category: "discovery",
    description:
      "Queries MSSQL Browser service and extracts instance names, versions, ports, and named pipes.",
    usage: "nmap --script ms-sql-info -p 1433 <target>"
  },
  {
    name: "mongodb-info",
    category: "discovery",
    description:
      "Retrieves MongoDB server information including version, storage engine, and build info.",
    usage: "nmap --script mongodb-info -p 27017 <target>"
  },
  {
    name: "mongodb-databases",
    category: "discovery",
    description:
      "Lists all databases on a MongoDB server when authentication is not required.",
    usage: "nmap --script mongodb-databases -p 27017 <target>"
  },
  {
    name: "redis-info",
    category: "discovery",
    description:
      "Retrieves Redis server information including version, memory usage, connected clients, and configuration.",
    usage: "nmap --script redis-info -p 6379 <target>"
  },
  {
    name: "memcached-info",
    category: "discovery",
    description:
      "Retrieves Memcached server statistics including version, uptime, memory usage, and items stored.",
    usage: "nmap --script memcached-info -p 11211 <target>"
  },
  {
    name: "ssh2-enum-algos",
    category: "discovery",
    description:
      "Reports the encryption, MAC, key exchange, and host key algorithms supported by an SSH server.",
    usage: "nmap --script ssh2-enum-algos -p 22 <target>"
  },
  {
    name: "ssh-auth-methods",
    category: "discovery",
    description:
      "Reports the authentication methods available on an SSH server (publickey, password, keyboard-interactive).",
    usage: "nmap --script ssh-auth-methods -p 22 <target>"
  },
  {
    name: "rdp-enum-encryption",
    category: "discovery",
    description:
      "Determines the encryption level and security layer used by an RDP server.",
    usage: "nmap --script rdp-enum-encryption -p 3389 <target>"
  },
  {
    name: "vnc-info",
    category: "discovery",
    description:
      "Queries a VNC server for protocol version, security types, and desktop name.",
    usage: "nmap --script vnc-info -p 5900 <target>"
  },

  // ---------- Vulnerability ----------
  {
    name: "smb-vuln-ms17-010",
    category: "vuln",
    description:
      "Checks for the EternalBlue SMB vulnerability (MS17-010) which allows remote code execution. Used by WannaCry and NotPetya.",
    usage: "nmap --script smb-vuln-ms17-010 -p 445 <target>"
  },
  {
    name: "smb-vuln-ms08-067",
    category: "vuln",
    description:
      "Checks for the Conficker worm vulnerability (MS08-067) in the Windows Server service.",
    usage: "nmap --script smb-vuln-ms08-067 -p 445 <target>"
  },
  {
    name: "rdp-vuln-ms12-020",
    category: "vuln",
    description:
      "Checks for the RDP vulnerability (MS12-020) that allows remote code execution and denial of service.",
    usage: "nmap --script rdp-vuln-ms12-020 -p 3389 <target>"
  },
  {
    name: "ssl-heartbleed",
    category: "vuln",
    description:
      "Detects the Heartbleed bug (CVE-2014-0160) in OpenSSL which allows reading server memory including private keys.",
    usage: "nmap --script ssl-heartbleed -p 443 <target>"
  },
  {
    name: "ssl-poodle",
    category: "vuln",
    description:
      "Checks if a server is vulnerable to the POODLE attack against SSLv3 (CVE-2014-3566).",
    usage: "nmap --script ssl-poodle -p 443 <target>"
  },
  {
    name: "ssl-ccs-injection",
    category: "vuln",
    description:
      "Detects the OpenSSL CCS injection vulnerability (CVE-2014-0224) allowing MITM attacks on TLS connections.",
    usage: "nmap --script ssl-ccs-injection -p 443 <target>"
  },
  {
    name: "ssl-dh-params",
    category: "vuln",
    description:
      "Checks for weak Diffie-Hellman parameters that enable Logjam attacks against TLS connections.",
    usage: "nmap --script ssl-dh-params -p 443 <target>"
  },
  {
    name: "http-vuln-cve2017-5638",
    category: "vuln",
    description:
      "Checks for Apache Struts2 RCE vulnerability (CVE-2017-5638) used in the Equifax breach.",
    usage: "nmap --script http-vuln-cve2017-5638 -p 80,443 <target>"
  },
  {
    name: "http-shellshock",
    category: "vuln",
    description:
      "Checks for the Shellshock (Bash bug) vulnerability in CGI scripts via the User-Agent header.",
    usage: "nmap --script http-shellshock --script-args uri=/cgi-bin/test.cgi -p 80 <target>"
  },
  {
    name: "http-vuln-cve2014-3704",
    category: "vuln",
    description:
      "Checks for Drupalgeddon SQL injection vulnerability (CVE-2014-3704) allowing remote code execution.",
    usage: "nmap --script http-vuln-cve2014-3704 -p 80 <target>"
  },
  {
    name: "vulners",
    category: "vuln",
    description:
      "Queries the Vulners vulnerability database for known CVEs affecting detected service versions.",
    usage: "nmap -sV --script vulners <target>"
  },
  {
    name: "vulscan",
    category: "vuln",
    description:
      "Advanced vulnerability scanning using multiple databases (CVE, OSVDB, SecurityFocus, etc.) based on detected versions.",
    usage: "nmap -sV --script vulscan <target>"
  },
  {
    name: "http-csrf",
    category: "vuln",
    description:
      "Detects Cross-Site Request Forgery vulnerabilities by checking for missing CSRF tokens in forms.",
    usage: "nmap --script http-csrf -p 80 <target>"
  },
  {
    name: "http-dombased-xss",
    category: "vuln",
    description:
      "Checks for DOM-based Cross-Site Scripting vulnerabilities by analyzing client-side JavaScript.",
    usage: "nmap --script http-dombased-xss -p 80 <target>"
  },
  {
    name: "http-stored-xss",
    category: "vuln",
    description:
      "Detects stored XSS vulnerabilities by injecting test payloads into input fields and checking responses.",
    usage: "nmap --script http-stored-xss -p 80 <target>"
  },
  {
    name: "http-sql-injection",
    category: "vuln",
    description:
      "Attempts to find SQL injection vulnerabilities by injecting SQL syntax into HTTP parameters.",
    usage: "nmap --script http-sql-injection -p 80 <target>"
  },

  // ---------- Authentication ----------
  {
    name: "ftp-anon",
    category: "auth",
    description:
      "Checks whether an FTP server allows anonymous login and lists accessible directories.",
    usage: "nmap --script ftp-anon -p 21 <target>"
  },
  {
    name: "mysql-empty-password",
    category: "auth",
    description:
      "Checks for MySQL accounts with empty passwords, particularly the root account.",
    usage: "nmap --script mysql-empty-password -p 3306 <target>"
  },
  {
    name: "ms-sql-empty-password",
    category: "auth",
    description:
      "Checks for MSSQL sa account with an empty password.",
    usage: "nmap --script ms-sql-empty-password -p 1433 <target>"
  },
  {
    name: "smtp-open-relay",
    category: "auth",
    description:
      "Tests whether an SMTP server is configured as an open relay that will forward mail for arbitrary domains.",
    usage: "nmap --script smtp-open-relay -p 25 <target>"
  },
  {
    name: "socks-open-proxy",
    category: "auth",
    description:
      "Checks if a SOCKS proxy server allows connections from anyone (open proxy).",
    usage: "nmap --script socks-open-proxy -p 1080 <target>"
  },
  {
    name: "http-open-proxy",
    category: "auth",
    description:
      "Tests whether an HTTP server is operating as an open proxy that will relay connections to arbitrary hosts.",
    usage: "nmap --script http-open-proxy -p 3128,8080 <target>"
  },
  {
    name: "x11-access",
    category: "auth",
    description:
      "Checks if X11 server allows unauthenticated connections (xhost +).",
    usage: "nmap --script x11-access -p 6000 <target>"
  },
  {
    name: "rsync-list-modules",
    category: "auth",
    description:
      "Lists modules available on an rsync daemon, showing which file areas are shared.",
    usage: "nmap --script rsync-list-modules -p 873 <target>"
  },

  // ---------- Brute Force ----------
  {
    name: "ssh-brute",
    category: "brute",
    description:
      "Performs brute-force password guessing against SSH servers using username and password lists.",
    usage: "nmap --script ssh-brute -p 22 <target>"
  },
  {
    name: "ftp-brute",
    category: "brute",
    description:
      "Brute-force FTP credentials using configurable username and password lists.",
    usage: "nmap --script ftp-brute -p 21 <target>"
  },
  {
    name: "telnet-brute",
    category: "brute",
    description:
      "Performs brute-force password guessing against Telnet servers.",
    usage: "nmap --script telnet-brute -p 23 <target>"
  },
  {
    name: "smtp-brute",
    category: "brute",
    description:
      "Brute-forces SMTP authentication credentials. Supports PLAIN, LOGIN, and CRAM-MD5 mechanisms.",
    usage: "nmap --script smtp-brute -p 25,587 <target>"
  },
  {
    name: "pop3-brute",
    category: "brute",
    description:
      "Brute-forces POP3 email credentials.",
    usage: "nmap --script pop3-brute -p 110 <target>"
  },
  {
    name: "imap-brute",
    category: "brute",
    description:
      "Brute-forces IMAP email credentials. Supports PLAIN and LOGIN authentication.",
    usage: "nmap --script imap-brute -p 143 <target>"
  },
  {
    name: "mysql-brute",
    category: "brute",
    description:
      "Brute-forces MySQL credentials against native authentication.",
    usage: "nmap --script mysql-brute -p 3306 <target>"
  },
  {
    name: "pgsql-brute",
    category: "brute",
    description:
      "Brute-forces PostgreSQL credentials.",
    usage: "nmap --script pgsql-brute -p 5432 <target>"
  },
  {
    name: "ms-sql-brute",
    category: "brute",
    description:
      "Brute-forces MSSQL credentials against SQL Server and Windows authentication.",
    usage: "nmap --script ms-sql-brute -p 1433 <target>"
  },
  {
    name: "mongodb-brute",
    category: "brute",
    description:
      "Brute-forces MongoDB credentials using SCRAM-SHA-1 authentication.",
    usage: "nmap --script mongodb-brute -p 27017 <target>"
  },
  {
    name: "redis-brute",
    category: "brute",
    description:
      "Brute-forces Redis authentication passwords.",
    usage: "nmap --script redis-brute -p 6379 <target>"
  },
  {
    name: "vnc-brute",
    category: "brute",
    description:
      "Brute-forces VNC authentication passwords (limited to 8-character DES-based passwords in RFB 3.x).",
    usage: "nmap --script vnc-brute -p 5900 <target>"
  },
  {
    name: "snmp-brute",
    category: "brute",
    description:
      "Brute-forces SNMP community strings against v1/v2c targets.",
    usage: "nmap -sU --script snmp-brute -p 161 <target>"
  },
  {
    name: "ldap-brute",
    category: "brute",
    description:
      "Brute-forces LDAP authentication credentials against directory servers.",
    usage: "nmap --script ldap-brute -p 389 <target>"
  },
  {
    name: "http-brute",
    category: "brute",
    description:
      "Brute-forces HTTP Basic and Digest authentication credentials.",
    usage: "nmap --script http-brute -p 80 <target>"
  },
  {
    name: "http-form-brute",
    category: "brute",
    description:
      "Brute-forces web application login forms with configurable parameters.",
    usage: "nmap --script http-form-brute --script-args 'http-form-brute.path=/login' -p 80 <target>"
  },
  {
    name: "krb5-enum-users",
    category: "brute",
    description:
      "Enumerates valid Kerberos usernames by attempting AS-REQ requests and analyzing error responses.",
    usage: "nmap --script krb5-enum-users --script-args krb5-enum-users.realm=<domain> -p 88 <target>"
  },

  // ---------- Exploit ----------
  {
    name: "smb-vuln-conficker",
    category: "exploit",
    description:
      "Detects systems infected with the Conficker worm by checking for its specific SMB signature.",
    usage: "nmap --script smb-vuln-conficker -p 445 <target>"
  },
  {
    name: "http-slowloris",
    category: "exploit",
    description:
      "Tests whether a web server is vulnerable to the Slowloris DoS attack by holding connections open with partial headers.",
    usage: "nmap --script http-slowloris -p 80 <target>"
  },
  {
    name: "smtp-vuln-cve2010-4344",
    category: "exploit",
    description:
      "Checks for Exim heap overflow vulnerability (CVE-2010-4344) allowing remote code execution.",
    usage: "nmap --script smtp-vuln-cve2010-4344 -p 25 <target>"
  },
  {
    name: "ftp-vsftpd-backdoor",
    category: "exploit",
    description:
      "Tests for the vsftpd 2.3.4 backdoor (CVE-2011-2523) which opens a shell on port 6200.",
    usage: "nmap --script ftp-vsftpd-backdoor -p 21 <target>"
  },
  {
    name: "ftp-proftpd-backdoor",
    category: "exploit",
    description:
      "Tests for the ProFTPD 1.3.3c backdoor that allows arbitrary command execution.",
    usage: "nmap --script ftp-proftpd-backdoor -p 21 <target>"
  },
  {
    name: "http-fileupload-exploiter",
    category: "exploit",
    description:
      "Exploits file upload functionality to upload a web shell and gain command execution.",
    usage: "nmap --script http-fileupload-exploiter -p 80 <target>"
  },

  // ---------- Safe / Default ----------
  {
    name: "ssl-enum-ciphers",
    category: "safe",
    description:
      "Enumerates SSL/TLS cipher suites supported by a server and grades them (A through F). Identifies weak ciphers.",
    usage: "nmap --script ssl-enum-ciphers -p 443 <target>"
  },
  {
    name: "ssl-cert",
    category: "safe",
    description:
      "Retrieves and displays the SSL/TLS certificate including subject, issuer, validity dates, and SANs.",
    usage: "nmap --script ssl-cert -p 443 <target>"
  },
  {
    name: "ssl-date",
    category: "safe",
    description:
      "Retrieves the server's date from the TLS handshake. Useful for identifying clock skew.",
    usage: "nmap --script ssl-date -p 443 <target>"
  },
  {
    name: "http-security-headers",
    category: "safe",
    description:
      "Checks for the presence and configuration of HTTP security headers (HSTS, CSP, X-Frame-Options, etc.).",
    usage: "nmap --script http-security-headers -p 80,443 <target>"
  },
  {
    name: "http-server-header",
    category: "safe",
    description:
      "Extracts and reports the Server header from HTTP responses for fingerprinting.",
    usage: "nmap --script http-server-header -p 80,443 <target>"
  },
  {
    name: "banner",
    category: "default",
    description:
      "Grabs and reports the service banner from open ports. Default script that runs with -sV.",
    usage: "nmap --script banner -p <ports> <target>"
  },
  {
    name: "whois-domain",
    category: "safe",
    description:
      "Performs a WHOIS lookup for the target's domain name, returning registration and contact information.",
    usage: "nmap --script whois-domain <target>"
  },
  {
    name: "whois-ip",
    category: "safe",
    description:
      "Performs a WHOIS lookup for the target IP address, returning network block and ASN information.",
    usage: "nmap --script whois-ip <target>"
  },
  {
    name: "traceroute-geolocation",
    category: "safe",
    description:
      "Performs a traceroute and geolocates each hop, showing the geographic path of packets.",
    usage: "nmap --traceroute --script traceroute-geolocation <target>"
  },
  {
    name: "dns-nsid",
    category: "safe",
    description:
      "Retrieves the NSID (Name Server Identifier) from a DNS server, useful for identifying specific servers in anycast.",
    usage: "nmap --script dns-nsid -p 53 <target>"
  },
  {
    name: "ntp-info",
    category: "safe",
    description:
      "Retrieves NTP server information including stratum, reference ID, and system details.",
    usage: "nmap -sU --script ntp-info -p 123 <target>"
  },
  {
    name: "sip-methods",
    category: "safe",
    description:
      "Enumerates supported SIP methods (INVITE, REGISTER, OPTIONS, etc.) on a SIP server.",
    usage: "nmap -sU --script sip-methods -p 5060 <target>"
  },

  // ---------- Intrusive ----------
  {
    name: "http-put",
    category: "intrusive",
    description:
      "Uploads a file to a web server using the HTTP PUT method. Used to test for writable web directories.",
    usage: "nmap --script http-put --script-args http-put.url=/upload/,http-put.file=test.txt -p 80 <target>"
  },
  {
    name: "smtp-enum-users",
    category: "intrusive",
    description:
      "Enumerates SMTP users using VRFY, EXPN, or RCPT TO commands against a mail server.",
    usage: "nmap --script smtp-enum-users -p 25 <target>"
  },
  {
    name: "oracle-sid-brute",
    category: "intrusive",
    description:
      "Brute-forces Oracle database SID (System Identifier) names against the TNS Listener.",
    usage: "nmap --script oracle-sid-brute -p 1521 <target>"
  },
  {
    name: "dns-cache-snoop",
    category: "intrusive",
    description:
      "Checks whether a DNS resolver has specific domains in its cache, revealing browsing patterns.",
    usage: "nmap --script dns-cache-snoop --script-args 'dns-cache-snoop.domains={google.com,facebook.com}' -p 53 <target>"
  },
  {
    name: "ntp-monlist",
    category: "intrusive",
    description:
      "Retrieves the NTP monlist which shows recent clients. Can be used for amplification DDoS in vulnerable servers.",
    usage: "nmap -sU --script ntp-monlist -p 123 <target>"
  },
  {
    name: "modbus-discover",
    category: "intrusive",
    description:
      "Discovers Modbus devices and reads device identification and supported function codes.",
    usage: "nmap --script modbus-discover -p 502 <target>"
  },
  {
    name: "s7-info",
    category: "intrusive",
    description:
      "Enumerates Siemens S7 PLC information including module name, firmware version, and serial number.",
    usage: "nmap --script s7-info -p 102 <target>"
  },
  {
    name: "bacnet-info",
    category: "intrusive",
    description:
      "Discovers BACnet devices and retrieves device information including vendor, model, and firmware.",
    usage: "nmap -sU --script bacnet-info -p 47808 <target>"
  },
  {
    name: "enip-info",
    category: "intrusive",
    description:
      "Queries EtherNet/IP devices for product name, vendor, serial number, and firmware version.",
    usage: "nmap --script enip-info -p 44818 <target>"
  },
  {
    name: "rtsp-url-brute",
    category: "intrusive",
    description:
      "Brute-forces common RTSP stream URLs to discover accessible camera feeds.",
    usage: "nmap --script rtsp-url-brute -p 554 <target>"
  },
  {
    name: "irc-info",
    category: "intrusive",
    description:
      "Retrieves information from an IRC server including server version, user count, and channel count.",
    usage: "nmap --script irc-info -p 6667 <target>"
  },
  {
    name: "tftp-enum",
    category: "intrusive",
    description:
      "Enumerates TFTP filenames by requesting common configuration file names.",
    usage: "nmap -sU --script tftp-enum -p 69 <target>"
  }
];


// ======================== 3. WIRESHARK_FILTERS ==============================
// 100+ Wireshark display filters organized by category.
// ============================================================================

const WIRESHARK_FILTERS = [
  // ---------- Protocol Filters ----------
  { filter: "tcp", description: "All TCP traffic", category: "protocol" },
  { filter: "udp", description: "All UDP traffic", category: "protocol" },
  { filter: "icmp", description: "All ICMP traffic", category: "protocol" },
  { filter: "arp", description: "All ARP traffic", category: "protocol" },
  { filter: "dns", description: "All DNS traffic", category: "protocol" },
  { filter: "http", description: "All HTTP traffic", category: "protocol" },
  { filter: "http2", description: "All HTTP/2 traffic", category: "protocol" },
  { filter: "tls", description: "All TLS traffic (including SSL)", category: "protocol" },
  { filter: "ssl", description: "All SSL/TLS traffic (legacy filter name)", category: "protocol" },
  { filter: "ssh", description: "All SSH traffic", category: "protocol" },
  { filter: "ftp", description: "All FTP control traffic", category: "protocol" },
  { filter: "ftp-data", description: "All FTP data channel traffic", category: "protocol" },
  { filter: "smtp", description: "All SMTP traffic", category: "protocol" },
  { filter: "pop", description: "All POP3 traffic", category: "protocol" },
  { filter: "imap", description: "All IMAP traffic", category: "protocol" },
  { filter: "dhcp", description: "All DHCP traffic (also bootp)", category: "protocol" },
  { filter: "smb", description: "All SMB traffic", category: "protocol" },
  { filter: "smb2", description: "All SMBv2/SMBv3 traffic", category: "protocol" },
  { filter: "ldap", description: "All LDAP traffic", category: "protocol" },
  { filter: "kerberos", description: "All Kerberos traffic", category: "protocol" },
  { filter: "snmp", description: "All SNMP traffic", category: "protocol" },
  { filter: "ntp", description: "All NTP traffic", category: "protocol" },
  { filter: "sip", description: "All SIP traffic", category: "protocol" },
  { filter: "rtp", description: "All RTP media traffic", category: "protocol" },
  { filter: "rtsp", description: "All RTSP traffic", category: "protocol" },
  { filter: "bgp", description: "All BGP traffic", category: "protocol" },
  { filter: "ospf", description: "All OSPF traffic", category: "protocol" },
  { filter: "rip", description: "All RIP traffic", category: "protocol" },
  { filter: "vrrp", description: "All VRRP traffic", category: "protocol" },
  { filter: "hsrp", description: "All HSRP traffic", category: "protocol" },
  { filter: "modbus", description: "All Modbus TCP traffic", category: "protocol" },
  { filter: "dnp3", description: "All DNP3 traffic", category: "protocol" },
  { filter: "bacnet", description: "All BACnet traffic", category: "protocol" },
  { filter: "enip", description: "All EtherNet/IP traffic", category: "protocol" },
  { filter: "s7comm", description: "All Siemens S7 communication traffic", category: "protocol" },
  { filter: "mqtt", description: "All MQTT traffic", category: "protocol" },
  { filter: "amqp", description: "All AMQP traffic", category: "protocol" },
  { filter: "websocket", description: "All WebSocket traffic", category: "protocol" },
  { filter: "grpc", description: "All gRPC traffic", category: "protocol" },
  { filter: "radius", description: "All RADIUS traffic", category: "protocol" },
  { filter: "ipv6", description: "All IPv6 traffic", category: "protocol" },
  { filter: "icmpv6", description: "All ICMPv6 traffic", category: "protocol" },
  { filter: "llmnr", description: "All LLMNR traffic", category: "protocol" },
  { filter: "mdns", description: "All mDNS traffic", category: "protocol" },
  { filter: "nbns", description: "All NetBIOS Name Service traffic", category: "protocol" },
  { filter: "syslog", description: "All Syslog traffic", category: "protocol" },

  // ---------- Attack Detection Filters ----------
  {
    filter: "tcp.flags.syn == 1 && tcp.flags.ack == 0",
    description: "SYN packets only (potential SYN flood detection)",
    category: "attack detection"
  },
  {
    filter: "tcp.flags.syn == 1 && tcp.flags.fin == 1",
    description: "SYN+FIN packets (invalid combination, likely scan or evasion)",
    category: "attack detection"
  },
  {
    filter: "tcp.flags == 0x000",
    description: "NULL scan packets (no TCP flags set)",
    category: "attack detection"
  },
  {
    filter: "tcp.flags.fin == 1 && tcp.flags.push == 1 && tcp.flags.urg == 1",
    description: "XMAS scan packets (FIN+PSH+URG set)",
    category: "attack detection"
  },
  {
    filter: "tcp.flags.fin == 1 && tcp.flags.syn == 0 && tcp.flags.ack == 0",
    description: "FIN scan packets (only FIN set, no ACK)",
    category: "attack detection"
  },
  {
    filter: "arp.duplicate-address-detected",
    description: "Duplicate IP addresses detected via ARP (potential ARP spoofing)",
    category: "attack detection"
  },
  {
    filter: "arp.opcode == 2",
    description: "ARP replies (high volume indicates ARP spoofing)",
    category: "attack detection"
  },
  {
    filter: "icmp.type == 3 && icmp.code == 3",
    description: "ICMP port unreachable (indicates scanning activity)",
    category: "attack detection"
  },
  {
    filter: "dns.qry.type == 255",
    description: "DNS ANY queries (potential amplification attack)",
    category: "attack detection"
  },
  {
    filter: "dns.flags.response == 1 && dns.qry.type == 255 && udp.length > 512",
    description: "Large DNS ANY responses (amplification attack indicator)",
    category: "attack detection"
  },
  {
    filter: "http.request.method == \"TRACE\"",
    description: "HTTP TRACE method requests (XST attack vector)",
    category: "attack detection"
  },
  {
    filter: "http.request.uri contains \"..\"",
    description: "HTTP directory traversal attempts",
    category: "attack detection"
  },
  {
    filter: "http.request.uri matches \"(?i)(union|select|insert|update|delete|drop|exec|xp_)\"",
    description: "Potential SQL injection in HTTP requests",
    category: "attack detection"
  },
  {
    filter: "http.request.uri matches \"(?i)(<script|javascript:|onerror|onload|alert\\()\"",
    description: "Potential XSS attacks in HTTP requests",
    category: "attack detection"
  },
  {
    filter: "http.request.uri contains \"/etc/passwd\"",
    description: "Local file inclusion (LFI) attempts targeting passwd file",
    category: "attack detection"
  },
  {
    filter: "http.request.uri contains \"cmd=\" || http.request.uri contains \"exec=\"",
    description: "Potential command injection via HTTP parameters",
    category: "attack detection"
  },
  {
    filter: "smb.cmd == 0x72 && smb.flags.response == 0",
    description: "SMB negotiate requests (potential scanning for SMB vulns)",
    category: "attack detection"
  },
  {
    filter: "kerberos.error_code == 6",
    description: "Kerberos principal unknown (user enumeration attempt)",
    category: "attack detection"
  },
  {
    filter: "kerberos.error_code == 24",
    description: "Kerberos pre-auth failed (brute-force indicator)",
    category: "attack detection"
  },
  {
    filter: "kerberos.msg_type == 13 && kerberos.cipher contains \"rc4\"",
    description: "Kerberoasting activity (TGS-REQ for RC4 encrypted service tickets)",
    category: "attack detection"
  },
  {
    filter: "ntlmssp.ntlmv2_response",
    description: "NTLMv2 authentication responses (potential relay/capture)",
    category: "attack detection"
  },
  {
    filter: "dhcp.option.dhcp == 2 && dhcp.ip.server != <expected_server>",
    description: "DHCP offers from unexpected servers (rogue DHCP detection)",
    category: "attack detection"
  },
  {
    filter: "dns.flags.rcode == 3",
    description: "DNS NXDOMAIN responses (high volume indicates DGA or tunneling)",
    category: "attack detection"
  },
  {
    filter: "dns.qry.name.len > 50",
    description: "Long DNS query names (potential DNS tunneling/exfiltration)",
    category: "attack detection"
  },
  {
    filter: "dns.qry.type == 16",
    description: "DNS TXT record queries (used in DNS tunneling and C2)",
    category: "attack detection"
  },
  {
    filter: "tls.handshake.type == 1 && tls.handshake.extensions_server_name contains \"\"",
    description: "TLS Client Hello with SNI (monitor for suspicious domains)",
    category: "attack detection"
  },
  {
    filter: "ssl.handshake.version == 0x0300",
    description: "SSLv3 connections (deprecated and vulnerable to POODLE)",
    category: "attack detection"
  },
  {
    filter: "ssl.handshake.version == 0x0301",
    description: "TLS 1.0 connections (deprecated, should be upgraded)",
    category: "attack detection"
  },

  // ---------- Troubleshooting Filters ----------
  {
    filter: "tcp.analysis.retransmission",
    description: "TCP retransmissions (indicates packet loss or network issues)",
    category: "troubleshooting"
  },
  {
    filter: "tcp.analysis.duplicate_ack",
    description: "TCP duplicate ACKs (precursor to fast retransmission)",
    category: "troubleshooting"
  },
  {
    filter: "tcp.analysis.fast_retransmission",
    description: "TCP fast retransmissions (triggered by triple duplicate ACKs)",
    category: "troubleshooting"
  },
  {
    filter: "tcp.analysis.zero_window",
    description: "TCP zero window (receiver buffer full, flow control)",
    category: "troubleshooting"
  },
  {
    filter: "tcp.analysis.window_full",
    description: "TCP window full (sender has filled receiver's window)",
    category: "troubleshooting"
  },
  {
    filter: "tcp.analysis.reset",
    description: "TCP connection resets (abrupt connection termination)",
    category: "troubleshooting"
  },
  {
    filter: "tcp.analysis.out_of_order",
    description: "TCP out-of-order segments (network path issues)",
    category: "troubleshooting"
  },
  {
    filter: "tcp.analysis.lost_segment",
    description: "TCP lost segments (gap in sequence numbers)",
    category: "troubleshooting"
  },
  {
    filter: "tcp.analysis.ack_rtt > 0.5",
    description: "TCP ACK round-trip time > 500ms (high latency)",
    category: "troubleshooting"
  },
  {
    filter: "tcp.analysis.initial_rtt > 1",
    description: "TCP initial RTT > 1 second (connection setup delay)",
    category: "troubleshooting"
  },
  {
    filter: "icmp.type == 3",
    description: "ICMP destination unreachable (routing or firewall issues)",
    category: "troubleshooting"
  },
  {
    filter: "icmp.type == 11",
    description: "ICMP time exceeded (TTL expired -- routing loop or traceroute)",
    category: "troubleshooting"
  },
  {
    filter: "icmp.type == 4",
    description: "ICMP source quench (deprecated congestion notification)",
    category: "troubleshooting"
  },
  {
    filter: "dns.flags.rcode != 0",
    description: "DNS error responses (NXDOMAIN, SERVFAIL, REFUSED, etc.)",
    category: "troubleshooting"
  },
  {
    filter: "dns.flags.rcode == 2",
    description: "DNS SERVFAIL responses (server unable to process query)",
    category: "troubleshooting"
  },
  {
    filter: "dns.time > 1",
    description: "DNS queries taking longer than 1 second to resolve",
    category: "troubleshooting"
  },
  {
    filter: "http.response.code >= 400",
    description: "HTTP error responses (4xx client errors, 5xx server errors)",
    category: "troubleshooting"
  },
  {
    filter: "http.response.code == 500",
    description: "HTTP 500 Internal Server Errors",
    category: "troubleshooting"
  },
  {
    filter: "http.response.code == 502",
    description: "HTTP 502 Bad Gateway (backend server issues)",
    category: "troubleshooting"
  },
  {
    filter: "http.response.code == 503",
    description: "HTTP 503 Service Unavailable (overload or maintenance)",
    category: "troubleshooting"
  },
  {
    filter: "http.time > 5",
    description: "HTTP requests taking longer than 5 seconds (slow responses)",
    category: "troubleshooting"
  },
  {
    filter: "tls.alert_message",
    description: "TLS alert messages (handshake failures, certificate errors)",
    category: "troubleshooting"
  },
  {
    filter: "tls.handshake.type == 2 && tls.handshake.certificate",
    description: "TLS server certificates (check for expired/invalid certs)",
    category: "troubleshooting"
  },

  // ---------- Performance Filters ----------
  {
    filter: "tcp.window_size_value < 1460",
    description: "Small TCP window sizes (potential throughput bottleneck)",
    category: "performance"
  },
  {
    filter: "tcp.len > 0 && tcp.analysis.ack_rtt",
    description: "Data-bearing segments with ACK RTT (latency analysis)",
    category: "performance"
  },
  {
    filter: "frame.time_delta > 1",
    description: "Inter-frame gaps longer than 1 second (stalls)",
    category: "performance"
  },
  {
    filter: "tcp.analysis.bytes_in_flight > 65535",
    description: "High bytes in flight (potential congestion)",
    category: "performance"
  },
  {
    filter: "http.content_length > 10000000",
    description: "HTTP responses larger than 10MB (large transfers)",
    category: "performance"
  },
  {
    filter: "tcp.stream eq <N>",
    description: "Isolate a specific TCP stream for detailed analysis (replace <N> with stream index)",
    category: "performance"
  },
  {
    filter: "ip.src == <IP> && ip.dst == <IP>",
    description: "Traffic between two specific hosts (replace <IP> placeholders)",
    category: "performance"
  },
  {
    filter: "frame.len > 1500",
    description: "Jumbo frames or fragmented packets (MTU issues)",
    category: "performance"
  },
  {
    filter: "ip.fragment",
    description: "Fragmented IP packets (potential MTU or performance issues)",
    category: "performance"
  },
  {
    filter: "tcp.options.mss_val < 1460",
    description: "TCP MSS value below standard (clamped or tunneled connections)",
    category: "performance"
  },

  // ---------- IoT Filters ----------
  {
    filter: "mqtt.msgtype == 1",
    description: "MQTT CONNECT messages (new IoT device connections)",
    category: "IoT"
  },
  {
    filter: "mqtt.msgtype == 3",
    description: "MQTT PUBLISH messages (IoT data being sent)",
    category: "IoT"
  },
  {
    filter: "mqtt.topic contains \"#\"",
    description: "MQTT wildcard subscriptions (potential data harvesting)",
    category: "IoT"
  },
  {
    filter: "mqtt.conack.flags.sp == 0 && mqtt.conack.val == 0",
    description: "Successful MQTT connections without session persistence",
    category: "IoT"
  },
  {
    filter: "coap",
    description: "All CoAP (Constrained Application Protocol) IoT traffic",
    category: "IoT"
  },
  {
    filter: "zigbee",
    description: "All Zigbee wireless IoT traffic",
    category: "IoT"
  },
  {
    filter: "bluetooth",
    description: "All Bluetooth traffic (if captured)",
    category: "IoT"
  },
  {
    filter: "modbus.func_code >= 5 && modbus.func_code <= 16",
    description: "Modbus write function codes (PLC/SCADA write operations)",
    category: "IoT"
  },
  {
    filter: "dnp3.al.func == 2",
    description: "DNP3 write requests (SCADA control commands)",
    category: "IoT"
  },
  {
    filter: "s7comm.param.func == 0x05",
    description: "S7comm write variable requests (Siemens PLC writes)",
    category: "IoT"
  },
  {
    filter: "bacnet.service_request == 15",
    description: "BACnet WriteProperty requests (building automation changes)",
    category: "IoT"
  },
  {
    filter: "udp.port == 5353 && dns.qry.name contains \"_iot\"",
    description: "mDNS queries for IoT service types",
    category: "IoT"
  }
];


// ======================== 4. SERVICE_BANNERS ================================
// Common service banner strings mapped to service/version identification.
// ============================================================================

const SERVICE_BANNERS = {
  // ---------- SSH Banners ----------
  "SSH-2.0-OpenSSH_8.": { service: "OpenSSH", version: "8.x", os: "Linux/Unix" },
  "SSH-2.0-OpenSSH_9.": { service: "OpenSSH", version: "9.x", os: "Linux/Unix" },
  "SSH-2.0-OpenSSH_7.": { service: "OpenSSH", version: "7.x", os: "Linux/Unix" },
  "SSH-2.0-OpenSSH_6.": { service: "OpenSSH", version: "6.x", os: "Linux/Unix" },
  "SSH-2.0-OpenSSH_for_Windows": { service: "OpenSSH", version: "Windows port", os: "Windows" },
  "SSH-2.0-dropbear": { service: "Dropbear SSH", version: "unknown", os: "Embedded/Linux" },
  "SSH-2.0-dropbear_2022": { service: "Dropbear SSH", version: "2022.x", os: "Embedded/Linux" },
  "SSH-2.0-libssh": { service: "libssh", version: "unknown", os: "Various" },
  "SSH-2.0-libssh2": { service: "libssh2", version: "unknown", os: "Various" },
  "SSH-2.0-PuTTY": { service: "PuTTY", version: "unknown", os: "Windows" },
  "SSH-2.0-Cisco": { service: "Cisco SSH", version: "unknown", os: "Cisco IOS" },
  "SSH-2.0-ROSSSH": { service: "MikroTik RouterOS SSH", version: "unknown", os: "RouterOS" },
  "SSH-1.99-": { service: "SSH", version: "1.99 (supports both v1 and v2)", os: "Various" },
  "SSH-1.5-": { service: "SSH", version: "1.5 (legacy, insecure)", os: "Various" },

  // ---------- FTP Banners ----------
  "220 (vsFTPd ": { service: "vsftpd", version: "unknown", os: "Linux" },
  "220 ProFTPD ": { service: "ProFTPD", version: "unknown", os: "Linux/Unix" },
  "220 Pure-FTPd": { service: "Pure-FTPd", version: "unknown", os: "Linux/Unix" },
  "220 FileZilla Server": { service: "FileZilla Server", version: "unknown", os: "Windows" },
  "220 Microsoft FTP Service": { service: "Microsoft IIS FTP", version: "unknown", os: "Windows" },
  "220 Welcome to the FTP service": { service: "Generic FTP", version: "unknown", os: "Various" },
  "220-Serv-U FTP Server": { service: "Serv-U FTP", version: "unknown", os: "Windows" },
  "220 Gene6 FTP Server": { service: "Gene6 FTP", version: "unknown", os: "Windows" },
  "220 NASFTPD Iomega": { service: "NASFTPD", version: "unknown", os: "NAS Device" },

  // ---------- SMTP Banners ----------
  "220 ESMTP Postfix": { service: "Postfix", version: "unknown", os: "Linux/Unix" },
  "220 Microsoft ESMTP MAIL Service": { service: "Microsoft Exchange", version: "unknown", os: "Windows" },
  "220 Exim": { service: "Exim", version: "unknown", os: "Linux/Unix" },
  "220 smtp.gmail.com": { service: "Gmail SMTP", version: "Google MTA", os: "Cloud" },
  "220 sendmail": { service: "Sendmail", version: "unknown", os: "Linux/Unix" },
  "220-mx.google.com": { service: "Google MX", version: "unknown", os: "Cloud" },
  "220 Haraka": { service: "Haraka MTA", version: "unknown", os: "Node.js" },
  "220-mail.example.com ESMTP": { service: "Generic SMTP", version: "unknown", os: "Various" },
  "220 hMailServer": { service: "hMailServer", version: "unknown", os: "Windows" },
  "220 Kerio Connect": { service: "Kerio Connect", version: "unknown", os: "Various" },

  // ---------- HTTP Banners (Server Headers) ----------
  "Apache/2.4": { service: "Apache HTTP Server", version: "2.4.x", os: "Linux/Unix" },
  "Apache/2.2": { service: "Apache HTTP Server", version: "2.2.x (EOL)", os: "Linux/Unix" },
  "nginx": { service: "nginx", version: "unknown", os: "Linux/Unix" },
  "nginx/1.": { service: "nginx", version: "1.x", os: "Linux/Unix" },
  "Microsoft-IIS/10.0": { service: "Microsoft IIS", version: "10.0", os: "Windows Server 2016/2019" },
  "Microsoft-IIS/8.5": { service: "Microsoft IIS", version: "8.5", os: "Windows Server 2012 R2" },
  "Microsoft-IIS/7.5": { service: "Microsoft IIS", version: "7.5", os: "Windows Server 2008 R2" },
  "Microsoft-HTTPAPI/2.0": { service: "Microsoft HTTP API", version: "2.0", os: "Windows" },
  "lighttpd": { service: "lighttpd", version: "unknown", os: "Linux/Unix" },
  "LiteSpeed": { service: "LiteSpeed Web Server", version: "unknown", os: "Linux" },
  "cloudflare": { service: "Cloudflare CDN", version: "N/A", os: "Cloud" },
  "AmazonS3": { service: "Amazon S3", version: "N/A", os: "Cloud (AWS)" },
  "gws": { service: "Google Web Server", version: "unknown", os: "Cloud (Google)" },
  "gunicorn": { service: "Gunicorn", version: "unknown", os: "Linux/Python" },
  "Werkzeug": { service: "Werkzeug (Flask)", version: "unknown", os: "Python" },
  "Express": { service: "Express.js", version: "unknown", os: "Node.js" },
  "Kestrel": { service: "Kestrel (.NET)", version: "unknown", os: "Various" },
  "Jetty": { service: "Eclipse Jetty", version: "unknown", os: "Java" },
  "Apache-Coyote": { service: "Apache Tomcat (Coyote)", version: "unknown", os: "Java" },
  "WildFly": { service: "WildFly (JBoss)", version: "unknown", os: "Java" },
  "Caddy": { service: "Caddy Server", version: "unknown", os: "Various" },
  "Tengine": { service: "Tengine (Alibaba nginx fork)", version: "unknown", os: "Linux" },
  "openresty": { service: "OpenResty (nginx+Lua)", version: "unknown", os: "Linux" },

  // ---------- Database Banners ----------
  "mysql_native_password": { service: "MySQL", version: "5.x+", os: "Various" },
  "caching_sha2_password": { service: "MySQL", version: "8.0+", os: "Various" },
  "MariaDB": { service: "MariaDB", version: "unknown", os: "Linux" },
  "PostgreSQL": { service: "PostgreSQL", version: "unknown", os: "Various" },
  "Microsoft SQL Server": { service: "Microsoft SQL Server", version: "unknown", os: "Windows" },
  "MongoDB": { service: "MongoDB", version: "unknown", os: "Various" },
  "Redis": { service: "Redis", version: "unknown", os: "Linux" },
  "REDIS": { service: "Redis", version: "unknown", os: "Linux" },
  "Memcached": { service: "Memcached", version: "unknown", os: "Linux" },
  "elasticsearch": { service: "Elasticsearch", version: "unknown", os: "Various" },
  "couchdb": { service: "CouchDB", version: "unknown", os: "Various" },

  // ---------- Mail Banners ----------
  "* OK Dovecot": { service: "Dovecot IMAP/POP3", version: "unknown", os: "Linux" },
  "* OK [CAPABILITY IMAP4rev1": { service: "Generic IMAP", version: "IMAP4rev1", os: "Various" },
  "+OK Dovecot ready": { service: "Dovecot POP3", version: "unknown", os: "Linux" },
  "+OK POP3 server ready": { service: "Generic POP3", version: "unknown", os: "Various" },
  "* OK Courier-IMAP": { service: "Courier IMAP", version: "unknown", os: "Linux" },
  "+OK Cyrus POP3": { service: "Cyrus POP3", version: "unknown", os: "Linux/Unix" },
  "* OK [CAPABILITY IMAP4rev1] Cyrus": { service: "Cyrus IMAP", version: "unknown", os: "Linux/Unix" },

  // ---------- Telnet / Network Device Banners ----------
  "User Access Verification": { service: "Cisco IOS", version: "unknown", os: "Cisco" },
  "MikroTik": { service: "MikroTik RouterOS", version: "unknown", os: "RouterOS" },
  "DD-WRT": { service: "DD-WRT Router", version: "unknown", os: "DD-WRT Linux" },
  "OpenWrt": { service: "OpenWrt", version: "unknown", os: "OpenWrt Linux" },
  "HP JetDirect": { service: "HP Printer (JetDirect)", version: "unknown", os: "HP Printer" },
  "BusyBox": { service: "BusyBox Shell", version: "unknown", os: "Embedded Linux" },
  "login:": { service: "Telnet login prompt", version: "unknown", os: "Unix/Linux" },
  "Welcome to Ubuntu": { service: "Ubuntu Login", version: "unknown", os: "Ubuntu Linux" },
  "Debian GNU/Linux": { service: "Debian Login", version: "unknown", os: "Debian Linux" },
  "CentOS": { service: "CentOS Login", version: "unknown", os: "CentOS Linux" },
  "Red Hat Enterprise Linux": { service: "RHEL Login", version: "unknown", os: "RHEL" },
  "FreeBSD": { service: "FreeBSD Login", version: "unknown", os: "FreeBSD" },

  // ---------- VNC Banners ----------
  "RFB 003.003": { service: "VNC", version: "RFB 3.3", os: "Various" },
  "RFB 003.007": { service: "VNC", version: "RFB 3.7", os: "Various" },
  "RFB 003.008": { service: "VNC", version: "RFB 3.8 (latest)", os: "Various" },
  "RFB 004.001": { service: "VNC", version: "RFB 4.1 (extended)", os: "Various" },

  // ---------- Proxy / Load Balancer ----------
  "Varnish": { service: "Varnish Cache", version: "unknown", os: "Linux" },
  "HAProxy": { service: "HAProxy", version: "unknown", os: "Linux" },
  "Squid": { service: "Squid Proxy", version: "unknown", os: "Linux/Unix" },
  "Envoy": { service: "Envoy Proxy", version: "unknown", os: "Various" },
  "Traefik": { service: "Traefik Proxy", version: "unknown", os: "Various" },

  // ---------- Miscellaneous ----------
  "Docker": { service: "Docker API", version: "unknown", os: "Linux" },
  "Kubernetes": { service: "Kubernetes API", version: "unknown", os: "Various" },
  "etcd": { service: "etcd", version: "unknown", os: "Linux" },
  "Consul": { service: "HashiCorp Consul", version: "unknown", os: "Various" },
  "RabbitMQ": { service: "RabbitMQ", version: "unknown", os: "Various" },
  "ActiveMQ": { service: "Apache ActiveMQ", version: "unknown", os: "Java" },
  "Jenkins": { service: "Jenkins CI", version: "unknown", os: "Java" },
  "GitLab": { service: "GitLab", version: "unknown", os: "Linux" },
  "Grafana": { service: "Grafana", version: "unknown", os: "Various" },
  "Prometheus": { service: "Prometheus", version: "unknown", os: "Various" },
  "Kibana": { service: "Kibana", version: "unknown", os: "Various" },
  "Zabbix": { service: "Zabbix", version: "unknown", os: "Linux" },
  "Nagios": { service: "Nagios", version: "unknown", os: "Linux" },
  "SonarQube": { service: "SonarQube", version: "unknown", os: "Java" },
  "Nexus": { service: "Sonatype Nexus", version: "unknown", os: "Java" }
};


// ======================== 5. PACKET_HEADERS =================================
// 15+ protocol header structures with field definitions.
// ============================================================================

const PACKET_HEADERS = [
  {
    protocol: "Ethernet II",
    fields: [
      { name: "Destination MAC", bits: 48, description: "Destination hardware address (6 bytes)" },
      { name: "Source MAC", bits: 48, description: "Source hardware address (6 bytes)" },
      { name: "EtherType", bits: 16, description: "Protocol identifier (0x0800=IPv4, 0x0806=ARP, 0x86DD=IPv6, 0x8100=802.1Q VLAN)" },
      { name: "Payload", bits: null, description: "Encapsulated data (46-1500 bytes)" },
      { name: "FCS", bits: 32, description: "Frame Check Sequence (CRC-32 error detection)" }
    ]
  },
  {
    protocol: "802.1Q VLAN Tag",
    fields: [
      { name: "TPID", bits: 16, description: "Tag Protocol Identifier (always 0x8100)" },
      { name: "PCP", bits: 3, description: "Priority Code Point (802.1p QoS, 0-7)" },
      { name: "DEI", bits: 1, description: "Drop Eligible Indicator (formerly CFI)" },
      { name: "VID", bits: 12, description: "VLAN Identifier (0-4095, 0 and 4095 reserved)" }
    ]
  },
  {
    protocol: "ARP",
    fields: [
      { name: "Hardware Type", bits: 16, description: "Link layer type (1 = Ethernet)" },
      { name: "Protocol Type", bits: 16, description: "Network protocol type (0x0800 = IPv4)" },
      { name: "Hardware Address Length", bits: 8, description: "Length of hardware address (6 for Ethernet MAC)" },
      { name: "Protocol Address Length", bits: 8, description: "Length of protocol address (4 for IPv4)" },
      { name: "Operation", bits: 16, description: "ARP operation (1=Request, 2=Reply, 3=RARP Request, 4=RARP Reply)" },
      { name: "Sender Hardware Address", bits: 48, description: "MAC address of the sender" },
      { name: "Sender Protocol Address", bits: 32, description: "IPv4 address of the sender" },
      { name: "Target Hardware Address", bits: 48, description: "MAC address of the target (zero in requests)" },
      { name: "Target Protocol Address", bits: 32, description: "IPv4 address of the target" }
    ]
  },
  {
    protocol: "IPv4",
    fields: [
      { name: "Version", bits: 4, description: "IP version (always 4)" },
      { name: "IHL", bits: 4, description: "Internet Header Length in 32-bit words (min 5 = 20 bytes)" },
      { name: "DSCP", bits: 6, description: "Differentiated Services Code Point (QoS)" },
      { name: "ECN", bits: 2, description: "Explicit Congestion Notification" },
      { name: "Total Length", bits: 16, description: "Total packet length in bytes (header + data, max 65535)" },
      { name: "Identification", bits: 16, description: "Fragment identification for reassembly" },
      { name: "Flags", bits: 3, description: "Bit 0: Reserved, Bit 1: Don't Fragment (DF), Bit 2: More Fragments (MF)" },
      { name: "Fragment Offset", bits: 13, description: "Offset of this fragment in 8-byte units" },
      { name: "TTL", bits: 8, description: "Time to Live (decremented by each router, prevents loops)" },
      { name: "Protocol", bits: 8, description: "Upper-layer protocol (6=TCP, 17=UDP, 1=ICMP, 89=OSPF)" },
      { name: "Header Checksum", bits: 16, description: "Error-checking for the header only" },
      { name: "Source Address", bits: 32, description: "Source IPv4 address" },
      { name: "Destination Address", bits: 32, description: "Destination IPv4 address" },
      { name: "Options", bits: null, description: "Variable length, rarely used (Record Route, Timestamp, Source Route)" }
    ]
  },
  {
    protocol: "IPv6",
    fields: [
      { name: "Version", bits: 4, description: "IP version (always 6)" },
      { name: "Traffic Class", bits: 8, description: "DSCP (6 bits) + ECN (2 bits) for QoS" },
      { name: "Flow Label", bits: 20, description: "Identifies a flow for QoS handling (unique per source-dest pair)" },
      { name: "Payload Length", bits: 16, description: "Length of the payload including extension headers (max 65535, jumbograms use extension)" },
      { name: "Next Header", bits: 8, description: "Identifies the next header type (6=TCP, 17=UDP, 58=ICMPv6, 43=Routing, 44=Fragment)" },
      { name: "Hop Limit", bits: 8, description: "Equivalent to IPv4 TTL (decremented by each router)" },
      { name: "Source Address", bits: 128, description: "128-bit source IPv6 address" },
      { name: "Destination Address", bits: 128, description: "128-bit destination IPv6 address" }
    ]
  },
  {
    protocol: "TCP",
    fields: [
      { name: "Source Port", bits: 16, description: "Sender's port number (0-65535)" },
      { name: "Destination Port", bits: 16, description: "Receiver's port number (0-65535)" },
      { name: "Sequence Number", bits: 32, description: "Byte-stream position of the first data byte in this segment" },
      { name: "Acknowledgment Number", bits: 32, description: "Next expected byte from the other side (valid when ACK flag set)" },
      { name: "Data Offset", bits: 4, description: "Header length in 32-bit words (min 5 = 20 bytes)" },
      { name: "Reserved", bits: 3, description: "Reserved for future use (must be zero)" },
      { name: "NS", bits: 1, description: "ECN-nonce concealment protection" },
      { name: "CWR", bits: 1, description: "Congestion Window Reduced (sender reduced window)" },
      { name: "ECE", bits: 1, description: "ECN-Echo (received CE-marked packet)" },
      { name: "URG", bits: 1, description: "Urgent pointer field is valid" },
      { name: "ACK", bits: 1, description: "Acknowledgment number field is valid" },
      { name: "PSH", bits: 1, description: "Push -- deliver data to application immediately" },
      { name: "RST", bits: 1, description: "Reset -- abort the connection" },
      { name: "SYN", bits: 1, description: "Synchronize -- initiate connection (three-way handshake)" },
      { name: "FIN", bits: 1, description: "Finish -- no more data from sender (graceful close)" },
      { name: "Window Size", bits: 16, description: "Receive window size in bytes (flow control)" },
      { name: "Checksum", bits: 16, description: "Error-checking for header and data (includes pseudo-header)" },
      { name: "Urgent Pointer", bits: 16, description: "Offset from sequence number of last urgent byte (valid when URG set)" },
      { name: "Options", bits: null, description: "Variable length: MSS, Window Scale, SACK, Timestamps, etc." }
    ]
  },
  {
    protocol: "UDP",
    fields: [
      { name: "Source Port", bits: 16, description: "Sender's port number (0-65535, optional in IPv4)" },
      { name: "Destination Port", bits: 16, description: "Receiver's port number (0-65535)" },
      { name: "Length", bits: 16, description: "Total datagram length (header + data, min 8 bytes)" },
      { name: "Checksum", bits: 16, description: "Error-checking (optional in IPv4, mandatory in IPv6)" }
    ]
  },
  {
    protocol: "ICMP",
    fields: [
      { name: "Type", bits: 8, description: "ICMP message type (0=Echo Reply, 3=Dest Unreachable, 8=Echo Request, 11=Time Exceeded)" },
      { name: "Code", bits: 8, description: "Subtype code providing further detail about the Type" },
      { name: "Checksum", bits: 16, description: "Error-checking for the ICMP message" },
      { name: "Rest of Header", bits: 32, description: "Content varies by Type/Code (Identifier+Sequence for Echo, MTU for Fragmentation Needed, etc.)" },
      { name: "Data", bits: null, description: "Variable: original datagram excerpt for error messages, echo payload for ping" }
    ]
  },
  {
    protocol: "DNS",
    fields: [
      { name: "Transaction ID", bits: 16, description: "Matches requests with responses" },
      { name: "QR", bits: 1, description: "Query (0) or Response (1)" },
      { name: "Opcode", bits: 4, description: "Query type (0=Standard, 1=Inverse, 2=Server Status, 4=Notify, 5=Update)" },
      { name: "AA", bits: 1, description: "Authoritative Answer (response is from the zone's authority)" },
      { name: "TC", bits: 1, description: "Truncated (response was larger than 512 bytes and was truncated)" },
      { name: "RD", bits: 1, description: "Recursion Desired (client wants recursive resolution)" },
      { name: "RA", bits: 1, description: "Recursion Available (server supports recursion)" },
      { name: "Z", bits: 1, description: "Reserved (must be zero)" },
      { name: "AD", bits: 1, description: "Authenticated Data (DNSSEC validated)" },
      { name: "CD", bits: 1, description: "Checking Disabled (DNSSEC validation skipped)" },
      { name: "RCODE", bits: 4, description: "Response code (0=NoError, 1=FormErr, 2=ServFail, 3=NXDomain, 5=Refused)" },
      { name: "QDCOUNT", bits: 16, description: "Number of questions in the Question section" },
      { name: "ANCOUNT", bits: 16, description: "Number of records in the Answer section" },
      { name: "NSCOUNT", bits: 16, description: "Number of records in the Authority section" },
      { name: "ARCOUNT", bits: 16, description: "Number of records in the Additional section" }
    ]
  },
  {
    protocol: "TLS Record",
    fields: [
      { name: "Content Type", bits: 8, description: "Record type (20=ChangeCipherSpec, 21=Alert, 22=Handshake, 23=Application Data)" },
      { name: "Version", bits: 16, description: "TLS version (0x0301=TLS 1.0, 0x0302=TLS 1.1, 0x0303=TLS 1.2/1.3)" },
      { name: "Length", bits: 16, description: "Length of the fragment (max 16384 + 2048 bytes with compression)" },
      { name: "Fragment", bits: null, description: "Encrypted or plaintext payload depending on cipher state" }
    ]
  },
  {
    protocol: "TLS Client Hello",
    fields: [
      { name: "Handshake Type", bits: 8, description: "Handshake message type (1 = ClientHello)" },
      { name: "Length", bits: 24, description: "Length of the ClientHello message" },
      { name: "Client Version", bits: 16, description: "Highest TLS version supported (0x0303 for TLS 1.2; TLS 1.3 uses extension)" },
      { name: "Random", bits: 256, description: "32 bytes of random data (includes 4-byte timestamp in older versions)" },
      { name: "Session ID Length", bits: 8, description: "Length of the Session ID (0 for new sessions)" },
      { name: "Session ID", bits: null, description: "Variable length session identifier for resumption" },
      { name: "Cipher Suites Length", bits: 16, description: "Length of the cipher suites list in bytes" },
      { name: "Cipher Suites", bits: null, description: "List of 2-byte cipher suite identifiers in preference order" },
      { name: "Compression Methods Length", bits: 8, description: "Length of compression methods list" },
      { name: "Compression Methods", bits: null, description: "List of supported compression methods (null=0x00, typically only)" },
      { name: "Extensions Length", bits: 16, description: "Total length of extensions data" },
      { name: "Extensions", bits: null, description: "Variable: SNI, ALPN, supported_versions, key_share, signature_algorithms, etc." }
    ]
  },
  {
    protocol: "HTTP/1.1 Request",
    fields: [
      { name: "Method", bits: null, description: "HTTP method: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE, CONNECT" },
      { name: "Request-URI", bits: null, description: "The resource path being requested (e.g., /index.html)" },
      { name: "HTTP-Version", bits: null, description: "Protocol version (HTTP/1.0 or HTTP/1.1)" },
      { name: "Host", bits: null, description: "Required header -- target hostname (enables virtual hosting)" },
      { name: "User-Agent", bits: null, description: "Client software identification string" },
      { name: "Accept", bits: null, description: "Media types the client can handle (e.g., text/html, application/json)" },
      { name: "Accept-Encoding", bits: null, description: "Supported content encodings (gzip, deflate, br)" },
      { name: "Connection", bits: null, description: "Connection management (keep-alive or close)" },
      { name: "Cookie", bits: null, description: "Previously set cookies sent back to the server" },
      { name: "Authorization", bits: null, description: "Authentication credentials (Basic, Bearer, Digest)" },
      { name: "Content-Type", bits: null, description: "Media type of the request body (for POST/PUT)" },
      { name: "Content-Length", bits: null, description: "Length of the request body in bytes" }
    ]
  },
  {
    protocol: "HTTP/1.1 Response",
    fields: [
      { name: "HTTP-Version", bits: null, description: "Protocol version (HTTP/1.0 or HTTP/1.1)" },
      { name: "Status-Code", bits: null, description: "3-digit status code (200, 301, 403, 404, 500, etc.)" },
      { name: "Reason-Phrase", bits: null, description: "Human-readable status description (OK, Not Found, etc.)" },
      { name: "Server", bits: null, description: "Server software identification (should be minimized for security)" },
      { name: "Content-Type", bits: null, description: "Media type of the response body" },
      { name: "Content-Length", bits: null, description: "Length of the response body in bytes" },
      { name: "Set-Cookie", bits: null, description: "Cookie to store on the client (includes path, domain, expiry, flags)" },
      { name: "Cache-Control", bits: null, description: "Caching directives (no-cache, max-age, private, public)" },
      { name: "Strict-Transport-Security", bits: null, description: "HSTS header -- enforces HTTPS (max-age, includeSubDomains)" },
      { name: "Content-Security-Policy", bits: null, description: "CSP -- controls allowed resource sources to prevent XSS" },
      { name: "X-Frame-Options", bits: null, description: "Clickjacking protection (DENY, SAMEORIGIN)" },
      { name: "X-Content-Type-Options", bits: null, description: "Prevents MIME-type sniffing (nosniff)" }
    ]
  },
  {
    protocol: "DHCP",
    fields: [
      { name: "Op", bits: 8, description: "Message type (1=BOOTREQUEST from client, 2=BOOTREPLY from server)" },
      { name: "HType", bits: 8, description: "Hardware address type (1=Ethernet)" },
      { name: "HLen", bits: 8, description: "Hardware address length (6 for Ethernet)" },
      { name: "Hops", bits: 8, description: "Relay agent hop count" },
      { name: "XID", bits: 32, description: "Transaction ID (random, matches request to response)" },
      { name: "Secs", bits: 16, description: "Seconds elapsed since client started DHCP process" },
      { name: "Flags", bits: 16, description: "Bit 0: Broadcast flag (client cannot receive unicast)" },
      { name: "CIAddr", bits: 32, description: "Client IP address (filled if client has a valid IP)" },
      { name: "YIAddr", bits: 32, description: "Your (client) IP address (offered by server)" },
      { name: "SIAddr", bits: 32, description: "Server IP address (next server in bootstrap)" },
      { name: "GIAddr", bits: 32, description: "Gateway/Relay agent IP address" },
      { name: "CHAddr", bits: 128, description: "Client hardware (MAC) address (16 bytes, padded)" },
      { name: "SName", bits: 512, description: "Optional server hostname (64 bytes)" },
      { name: "File", bits: 1024, description: "Boot filename (128 bytes)" },
      { name: "Magic Cookie", bits: 32, description: "0x63825363 identifies DHCP options follow" },
      { name: "Options", bits: null, description: "Variable: Message Type (53), Subnet Mask (1), Router (3), DNS (6), Lease Time (51), etc." }
    ]
  },
  {
    protocol: "SIP",
    fields: [
      { name: "Request-Line / Status-Line", bits: null, description: "Method + Request-URI + SIP-Version (request) or SIP-Version + Status-Code + Reason (response)" },
      { name: "Via", bits: null, description: "Records the transport path (branch parameter identifies transaction)" },
      { name: "From", bits: null, description: "Logical identity of the message initiator (includes tag parameter)" },
      { name: "To", bits: null, description: "Logical identity of the message recipient" },
      { name: "Call-ID", bits: null, description: "Unique identifier for the SIP dialog/call" },
      { name: "CSeq", bits: null, description: "Command sequence number and method name" },
      { name: "Contact", bits: null, description: "Direct URI for reaching the User Agent" },
      { name: "Max-Forwards", bits: null, description: "Hop limit to prevent loops (typically 70)" },
      { name: "Content-Type", bits: null, description: "Media type of the body (application/sdp for session description)" },
      { name: "Content-Length", bits: null, description: "Length of the message body in bytes" },
      { name: "Authorization / WWW-Authenticate", bits: null, description: "Digest authentication credentials or challenge" }
    ]
  },
  {
    protocol: "MQTT Fixed Header",
    fields: [
      { name: "Packet Type", bits: 4, description: "MQTT control packet type (1=CONNECT, 2=CONNACK, 3=PUBLISH, 4=PUBACK, 8=SUBSCRIBE, etc.)" },
      { name: "Flags", bits: 4, description: "Packet-type-specific flags (DUP, QoS level, RETAIN for PUBLISH)" },
      { name: "Remaining Length", bits: null, description: "Variable-length encoding (1-4 bytes) of the remaining packet length" }
    ]
  },
  {
    protocol: "Modbus TCP/IP",
    fields: [
      { name: "Transaction ID", bits: 16, description: "Matches request with response (incremented by client)" },
      { name: "Protocol ID", bits: 16, description: "Always 0x0000 for Modbus" },
      { name: "Length", bits: 16, description: "Number of remaining bytes in the PDU" },
      { name: "Unit ID", bits: 8, description: "Slave/device address (0xFF for broadcast)" },
      { name: "Function Code", bits: 8, description: "Operation type (1=Read Coils, 2=Read Discrete Inputs, 3=Read Holding Registers, 5=Write Single Coil, 6=Write Single Register, 15=Write Multiple Coils, 16=Write Multiple Registers)" },
      { name: "Data", bits: null, description: "Function-specific data (register addresses, values, counts)" }
    ]
  },
  {
    protocol: "BGP",
    fields: [
      { name: "Marker", bits: 128, description: "16 bytes all ones (0xFF) for synchronization and authentication" },
      { name: "Length", bits: 16, description: "Total message length including header (19-4096 bytes)" },
      { name: "Type", bits: 8, description: "Message type (1=OPEN, 2=UPDATE, 3=NOTIFICATION, 4=KEEPALIVE, 5=ROUTE-REFRESH)" }
    ]
  },
  {
    protocol: "RADIUS",
    fields: [
      { name: "Code", bits: 8, description: "Packet type (1=Access-Request, 2=Access-Accept, 3=Access-Reject, 4=Accounting-Request, 5=Accounting-Response, 11=Access-Challenge)" },
      { name: "Identifier", bits: 8, description: "Matches requests with responses (0-255)" },
      { name: "Length", bits: 16, description: "Total packet length (20-4096 bytes)" },
      { name: "Authenticator", bits: 128, description: "16-byte value: random in requests, MD5 hash in responses (ensures integrity)" },
      { name: "Attributes", bits: null, description: "Variable: Type-Length-Value encoded (User-Name, User-Password, NAS-IP, etc.)" }
    ]
  },
  {
    protocol: "SNMP",
    fields: [
      { name: "Version", bits: null, description: "SNMP version (0=v1, 1=v2c, 3=v3) -- BER/ASN.1 encoded" },
      { name: "Community String", bits: null, description: "Authentication string (v1/v2c only, plaintext, default: public/private)" },
      { name: "PDU Type", bits: null, description: "0=GetRequest, 1=GetNextRequest, 2=GetResponse, 3=SetRequest, 4=Trap (v1), 5=GetBulkRequest, 6=InformRequest, 7=SNMPv2-Trap" },
      { name: "Request ID", bits: 32, description: "Matches requests with responses" },
      { name: "Error Status", bits: null, description: "0=noError, 1=tooBig, 2=noSuchName, 3=badValue, 4=readOnly, 5=genErr" },
      { name: "Error Index", bits: null, description: "Points to the variable binding that caused the error" },
      { name: "Variable Bindings", bits: null, description: "List of OID-value pairs (the actual SNMP data)" }
    ]
  }
];


// ============================================================================
// Module Exports
// ============================================================================

module.exports = {
  PROTOCOLS,
  NMAP_SCRIPTS,
  WIRESHARK_FILTERS,
  SERVICE_BANNERS,
  PACKET_HEADERS
};
