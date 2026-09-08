"use strict";
// Digital forensics artifact catalog and timeline utilities. Provides structured
// reference data for Linux and Windows forensic artifacts, Volatility memory
// analysis plugins, and common log file locations across platforms and services.
// Pure data + helpers -- no I/O, no network calls, safe for offline use.

const crypto = require("crypto");

// ---------------------------------------------------------------------------
// LINUX_ARTIFACTS -- key filesystem paths for Linux forensic investigation
// ---------------------------------------------------------------------------

const LINUX_ARTIFACTS = [
  {
    path: "/var/log/auth.log",
    description: "Authentication log capturing login attempts, sudo usage, SSH sessions, and PAM events",
    category: "authentication",
    forensicValue: "critical",
  },
  {
    path: "/var/log/secure",
    description: "RHEL/CentOS equivalent of auth.log for authentication and authorization events",
    category: "authentication",
    forensicValue: "critical",
  },
  {
    path: "/etc/passwd",
    description: "User account database with UIDs, GIDs, home directories, and login shells",
    category: "user-accounts",
    forensicValue: "high",
  },
  {
    path: "/etc/shadow",
    description: "Hashed passwords and password aging policy for local user accounts",
    category: "user-accounts",
    forensicValue: "critical",
  },
  {
    path: "/etc/group",
    description: "Group membership definitions -- reveals privilege escalation via group additions",
    category: "user-accounts",
    forensicValue: "high",
  },
  {
    path: "/var/log/syslog",
    description: "General system activity log aggregating messages from most daemons and services",
    category: "system",
    forensicValue: "high",
  },
  {
    path: "/var/log/messages",
    description: "RHEL/CentOS general system log equivalent to syslog on Debian-based systems",
    category: "system",
    forensicValue: "high",
  },
  {
    path: "~/.bash_history",
    description: "Per-user command history for bash shell sessions -- shows attacker commands",
    category: "user-activity",
    forensicValue: "critical",
  },
  {
    path: "~/.zsh_history",
    description: "Per-user command history for zsh shell sessions",
    category: "user-activity",
    forensicValue: "critical",
  },
  {
    path: "/tmp",
    description: "World-writable temporary directory often used for staging malware and exploit payloads",
    category: "persistence",
    forensicValue: "high",
  },
  {
    path: "/dev/shm",
    description: "Shared memory tmpfs -- fileless malware staging area that does not touch disk",
    category: "persistence",
    forensicValue: "high",
  },
  {
    path: "/var/spool/cron",
    description: "Per-user crontab files -- persistence mechanism via scheduled task creation",
    category: "persistence",
    forensicValue: "critical",
  },
  {
    path: "/etc/crontab",
    description: "System-wide cron schedule -- check for unauthorized scheduled tasks",
    category: "persistence",
    forensicValue: "critical",
  },
  {
    path: "/etc/cron.d",
    description: "Drop-in cron job directory for system and package cron entries",
    category: "persistence",
    forensicValue: "high",
  },
  {
    path: "/etc/cron.daily",
    description: "Daily cron scripts -- malware may install persistence here",
    category: "persistence",
    forensicValue: "medium",
  },
  {
    path: "/proc",
    description: "Virtual filesystem exposing live process info, network state, and kernel parameters",
    category: "volatile",
    forensicValue: "critical",
  },
  {
    path: "/proc/net/tcp",
    description: "Active TCP connections and listening sockets in hexadecimal notation",
    category: "network",
    forensicValue: "high",
  },
  {
    path: "/etc/hosts",
    description: "Static hostname-to-IP mappings -- DNS hijacking and C2 redirection indicator",
    category: "network",
    forensicValue: "high",
  },
  {
    path: "/etc/resolv.conf",
    description: "DNS resolver configuration -- rogue DNS server insertion indicator",
    category: "network",
    forensicValue: "medium",
  },
  {
    path: "/var/log/wtmp",
    description: "Binary login records (use `last` to read) showing user session history",
    category: "authentication",
    forensicValue: "critical",
  },
  {
    path: "/var/log/btmp",
    description: "Binary failed login records (use `lastb` to read) showing brute-force attempts",
    category: "authentication",
    forensicValue: "critical",
  },
  {
    path: "/var/log/lastlog",
    description: "Most recent login time and source for each user account on the system",
    category: "authentication",
    forensicValue: "high",
  },
  {
    path: "/var/run/utmp",
    description: "Currently logged-in users and their terminal sessions",
    category: "authentication",
    forensicValue: "high",
  },
  {
    path: "/etc/sudoers",
    description: "Sudo privilege configuration -- shows who can run commands as root",
    category: "privilege-escalation",
    forensicValue: "critical",
  },
  {
    path: "/etc/sudoers.d",
    description: "Drop-in sudo configuration directory for modular privilege grants",
    category: "privilege-escalation",
    forensicValue: "critical",
  },
  {
    path: "/var/log/kern.log",
    description: "Kernel messages including module loads, hardware events, and security warnings",
    category: "system",
    forensicValue: "high",
  },
  {
    path: "/var/log/dmesg",
    description: "Kernel ring buffer messages from boot -- hardware and driver initialization events",
    category: "system",
    forensicValue: "medium",
  },
  {
    path: "/etc/ssh/sshd_config",
    description: "SSH daemon configuration -- check for weakened authentication or backdoor settings",
    category: "configuration",
    forensicValue: "high",
  },
  {
    path: "~/.ssh/authorized_keys",
    description: "Per-user authorized SSH public keys -- unauthorized key insertion is a persistence vector",
    category: "persistence",
    forensicValue: "critical",
  },
  {
    path: "~/.ssh/known_hosts",
    description: "Previously connected SSH hosts -- reveals lateral movement targets",
    category: "network",
    forensicValue: "high",
  },
  {
    path: "/etc/ld.so.preload",
    description: "Shared library preload file -- rootkit and library injection indicator",
    category: "persistence",
    forensicValue: "critical",
  },
  {
    path: "/etc/rc.local",
    description: "Legacy boot script executed at the end of init -- persistence mechanism",
    category: "persistence",
    forensicValue: "high",
  },
  {
    path: "/etc/systemd/system",
    description: "Systemd unit files for custom services -- malware may install persistence units here",
    category: "persistence",
    forensicValue: "critical",
  },
  {
    path: "/lib/systemd/system",
    description: "Package-installed systemd unit files -- compare against known-good baselines",
    category: "persistence",
    forensicValue: "high",
  },
  {
    path: "/var/log/apt/history.log",
    description: "APT package installation and removal history on Debian-based systems",
    category: "software",
    forensicValue: "medium",
  },
  {
    path: "/var/log/yum.log",
    description: "YUM/DNF package transaction log on RHEL-based systems",
    category: "software",
    forensicValue: "medium",
  },
  {
    path: "/var/log/audit/audit.log",
    description: "Linux Audit Framework log -- SELinux denials, syscall auditing, file access tracking",
    category: "audit",
    forensicValue: "critical",
  },
  {
    path: "/etc/pam.d",
    description: "PAM module configuration directory -- backdoor PAM modules bypass authentication",
    category: "authentication",
    forensicValue: "critical",
  },
  {
    path: "/var/log/faillog",
    description: "Failed login counter per user -- detects brute-force activity against local accounts",
    category: "authentication",
    forensicValue: "medium",
  },
  {
    path: "/etc/init.d",
    description: "SysVinit startup scripts -- legacy persistence location for malware services",
    category: "persistence",
    forensicValue: "high",
  },
  {
    path: "/var/log/journal",
    description: "Systemd journal binary logs -- persistent structured logging across reboots",
    category: "system",
    forensicValue: "high",
  },
  {
    path: "/etc/environment",
    description: "System-wide environment variables -- LD_PRELOAD or PATH manipulation indicator",
    category: "configuration",
    forensicValue: "medium",
  },
  {
    path: "/etc/profile.d",
    description: "Login shell profile scripts -- executed on every user login, persistence vector",
    category: "persistence",
    forensicValue: "high",
  },
  {
    path: "~/.bashrc",
    description: "Per-user bash configuration -- alias hijacking and command injection persistence",
    category: "persistence",
    forensicValue: "high",
  },
  {
    path: "/var/mail",
    description: "Local mail spool -- may contain alerts, cron output, or exfiltrated data",
    category: "user-activity",
    forensicValue: "medium",
  },
];

// ---------------------------------------------------------------------------
// WINDOWS_ARTIFACTS -- key filesystem and registry paths for Windows forensics
// ---------------------------------------------------------------------------

const WINDOWS_ARTIFACTS = [
  {
    path: "C:\\Users\\<user>\\NTUSER.DAT",
    description: "Per-user registry hive containing desktop settings, recent documents, run keys, and typed paths",
    category: "registry",
    forensicValue: "critical",
  },
  {
    path: "C:\\Windows\\System32\\config\\SAM",
    description: "Security Account Manager registry hive storing local user password hashes",
    category: "registry",
    forensicValue: "critical",
  },
  {
    path: "C:\\Windows\\System32\\config\\SYSTEM",
    description: "SYSTEM registry hive with boot config, services, and the SYSKEY boot key",
    category: "registry",
    forensicValue: "critical",
  },
  {
    path: "C:\\Windows\\System32\\config\\SOFTWARE",
    description: "SOFTWARE registry hive with installed programs, OS version, and network profiles",
    category: "registry",
    forensicValue: "critical",
  },
  {
    path: "C:\\Windows\\System32\\config\\SECURITY",
    description: "SECURITY registry hive containing cached domain credentials and LSA secrets",
    category: "registry",
    forensicValue: "critical",
  },
  {
    path: "C:\\Windows\\System32\\config\\DEFAULT",
    description: "Default user profile registry hive used as template for new user accounts",
    category: "registry",
    forensicValue: "medium",
  },
  {
    path: "C:\\Windows\\Prefetch",
    description: "Prefetch files (.pf) recording application execution history with timestamps and file references",
    category: "execution",
    forensicValue: "critical",
  },
  {
    path: "C:\\Windows\\System32\\winevt\\Logs",
    description: "Windows Event Log directory containing .evtx files for Security, System, Application, etc.",
    category: "event-logs",
    forensicValue: "critical",
  },
  {
    path: "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
    description: "Security event log with logon/logoff events (4624/4625), privilege use, and audit policy changes",
    category: "event-logs",
    forensicValue: "critical",
  },
  {
    path: "C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
    description: "System event log with service state changes, driver loads, and time changes",
    category: "event-logs",
    forensicValue: "high",
  },
  {
    path: "C:\\Windows\\System32\\winevt\\Logs\\Application.evtx",
    description: "Application event log with program crashes, errors, and application-specific entries",
    category: "event-logs",
    forensicValue: "medium",
  },
  {
    path: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
    description: "Sysmon operational log with process creation, network connections, and file creation events",
    category: "event-logs",
    forensicValue: "critical",
  },
  {
    path: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx",
    description: "PowerShell operational log capturing script block logging and module logging events",
    category: "event-logs",
    forensicValue: "critical",
  },
  {
    path: "$MFT",
    description: "NTFS Master File Table recording every file and directory entry with timestamps",
    category: "filesystem",
    forensicValue: "critical",
  },
  {
    path: "$LogFile",
    description: "NTFS transaction journal tracking filesystem metadata changes for crash recovery",
    category: "filesystem",
    forensicValue: "high",
  },
  {
    path: "$UsnJrnl",
    description: "NTFS Update Sequence Number journal recording file creation, deletion, and modification events",
    category: "filesystem",
    forensicValue: "critical",
  },
  {
    path: "C:\\pagefile.sys",
    description: "Virtual memory paging file -- may contain fragments of process memory and decrypted data",
    category: "memory",
    forensicValue: "high",
  },
  {
    path: "C:\\hiberfil.sys",
    description: "Hibernation file containing a compressed memory dump from the last hibernation",
    category: "memory",
    forensicValue: "critical",
  },
  {
    path: "C:\\swapfile.sys",
    description: "Modern app swap file for UWP/Metro suspended application memory pages",
    category: "memory",
    forensicValue: "medium",
  },
  {
    path: "C:\\Windows\\AppCompat\\Programs\\Amcache.hve",
    description: "Application compatibility cache registry hive with SHA1 hashes and execution timestamps",
    category: "execution",
    forensicValue: "critical",
  },
  {
    path: "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache",
    description: "ShimCache registry key recording application execution and file path evidence",
    category: "execution",
    forensicValue: "critical",
  },
  {
    path: "C:\\Windows\\System32\\sru\\SRUDB.dat",
    description: "System Resource Usage Monitor database tracking per-app network, CPU, and energy usage",
    category: "execution",
    forensicValue: "high",
  },
  {
    path: "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\WebCache\\WebCacheV01.dat",
    description: "Internet Explorer and Edge Legacy browsing history, cookies, and download records",
    category: "browser",
    forensicValue: "high",
  },
  {
    path: "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History",
    description: "Chrome SQLite database with browsing history, downloads, and keyword searches",
    category: "browser",
    forensicValue: "high",
  },
  {
    path: "C:\\Users\\<user>\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<profile>\\places.sqlite",
    description: "Firefox SQLite database with browsing history, bookmarks, and download records",
    category: "browser",
    forensicValue: "high",
  },
  {
    path: "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\Explorer\\thumbcache_*.db",
    description: "Thumbnail cache databases preserving image previews even after file deletion",
    category: "user-activity",
    forensicValue: "medium",
  },
  {
    path: "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent",
    description: "Recent files LNK shortcuts revealing accessed documents and their original paths",
    category: "user-activity",
    forensicValue: "high",
  },
  {
    path: "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations",
    description: "Jump List files showing recently and frequently accessed files per application",
    category: "user-activity",
    forensicValue: "high",
  },
  {
    path: "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations",
    description: "Custom Jump List files with pinned and application-defined recent items",
    category: "user-activity",
    forensicValue: "high",
  },
  {
    path: "C:\\$Recycle.Bin",
    description: "Recycle Bin containing deleted files with original path and deletion timestamp in $I files",
    category: "filesystem",
    forensicValue: "high",
  },
  {
    path: "C:\\Windows\\System32\\Tasks",
    description: "Scheduled task XML definitions -- persistence and lateral movement mechanism",
    category: "persistence",
    forensicValue: "critical",
  },
  {
    path: "C:\\Windows\\System32\\drivers\\etc\\hosts",
    description: "Static hostname resolution file -- DNS hijacking and C2 redirection indicator",
    category: "network",
    forensicValue: "high",
  },
  {
    path: "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
    description: "PowerShell command history file recording interactive console commands",
    category: "user-activity",
    forensicValue: "critical",
  },
  {
    path: "C:\\Windows\\System32\\LogFiles\\W3SVC1",
    description: "IIS web server access logs for the default site with request details",
    category: "web-server",
    forensicValue: "high",
  },
  {
    path: "C:\\Windows\\debug\\NetSetup.LOG",
    description: "Domain join and network setup operations log",
    category: "network",
    forensicValue: "medium",
  },
  {
    path: "C:\\Users\\<user>\\NTUSER.DAT.LOG1",
    description: "Registry transaction log for NTUSER.DAT enabling dirty hive recovery",
    category: "registry",
    forensicValue: "medium",
  },
  {
    path: "C:\\Windows\\inf\\setupapi.dev.log",
    description: "Device installation log recording USB device connections with timestamps and serial numbers",
    category: "usb",
    forensicValue: "high",
  },
  {
    path: "SYSTEM\\MountedDevices",
    description: "Registry key mapping drive letters to device signatures -- USB and volume mount history",
    category: "usb",
    forensicValue: "high",
  },
  {
    path: "C:\\Windows\\System32\\wbem\\Repository",
    description: "WMI repository -- check for event subscription persistence and WMI backdoors",
    category: "persistence",
    forensicValue: "high",
  },
  {
    path: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    description: "Auto-start registry key for programs that run at user logon -- common persistence location",
    category: "persistence",
    forensicValue: "critical",
  },
  {
    path: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    description: "One-time auto-start registry key -- may be used for single-execution persistence",
    category: "persistence",
    forensicValue: "high",
  },
  {
    path: "C:\\Windows\\System32\\config\\RegBack",
    description: "Automatic registry backup directory with periodic snapshots of registry hives",
    category: "registry",
    forensicValue: "high",
  },
  {
    path: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
    description: "Registry key mapping SIDs to user profile paths -- reveals all user accounts that have logged in",
    category: "user-accounts",
    forensicValue: "high",
  },
];

// ---------------------------------------------------------------------------
// VOLATILITY_PLUGINS -- Volatility memory forensics framework plugin catalog
// ---------------------------------------------------------------------------

const VOLATILITY_PLUGINS = [
  {
    name: "pslist",
    description: "List running processes by traversing the doubly-linked EPROCESS list",
    category: "processes",
    usage: "vol.py -f <memory_dump> windows.pslist",
  },
  {
    name: "pstree",
    description: "Display process parent-child relationships as a tree structure",
    category: "processes",
    usage: "vol.py -f <memory_dump> windows.pstree",
  },
  {
    name: "psscan",
    description: "Scan physical memory for EPROCESS structures to find hidden/unlinked processes",
    category: "processes",
    usage: "vol.py -f <memory_dump> windows.psscan",
  },
  {
    name: "psxview",
    description: "Cross-reference multiple process listing methods to detect hidden processes",
    category: "processes",
    usage: "vol.py -f <memory_dump> windows.psxview",
  },
  {
    name: "netscan",
    description: "Scan for network artifacts including active connections and listening sockets",
    category: "network",
    usage: "vol.py -f <memory_dump> windows.netscan",
  },
  {
    name: "netstat",
    description: "List active network connections from kernel network structures",
    category: "network",
    usage: "vol.py -f <memory_dump> windows.netstat",
  },
  {
    name: "filescan",
    description: "Scan physical memory for FILE_OBJECT structures to locate open file handles",
    category: "filesystem",
    usage: "vol.py -f <memory_dump> windows.filescan",
  },
  {
    name: "dumpfiles",
    description: "Extract cached files from memory including executables, DLLs, and data files",
    category: "filesystem",
    usage: "vol.py -f <memory_dump> windows.dumpfiles --pid <PID>",
  },
  {
    name: "dlllist",
    description: "List loaded DLLs for each process from the PEB InLoadOrderModuleList",
    category: "modules",
    usage: "vol.py -f <memory_dump> windows.dlllist --pid <PID>",
  },
  {
    name: "ldrmodules",
    description: "Cross-reference DLL lists from PEB to detect injected/unlinked modules",
    category: "modules",
    usage: "vol.py -f <memory_dump> windows.ldrmodules --pid <PID>",
  },
  {
    name: "malfind",
    description: "Find injected code and suspicious memory regions with RWX permissions",
    category: "malware",
    usage: "vol.py -f <memory_dump> windows.malfind",
  },
  {
    name: "yarascan",
    description: "Scan process or kernel memory for YARA rule matches",
    category: "malware",
    usage: "vol.py -f <memory_dump> yarascan.YaraScan --yara-rules <rule>",
  },
  {
    name: "hashdump",
    description: "Extract password hashes from the SAM registry hive in memory",
    category: "credentials",
    usage: "vol.py -f <memory_dump> windows.hashdump",
  },
  {
    name: "lsadump",
    description: "Dump LSA secrets from the registry including cached domain credentials",
    category: "credentials",
    usage: "vol.py -f <memory_dump> windows.lsadump",
  },
  {
    name: "cachedump",
    description: "Extract cached domain password hashes (MS-Cache v1/v2) from memory",
    category: "credentials",
    usage: "vol.py -f <memory_dump> windows.cachedump",
  },
  {
    name: "hivelist",
    description: "List registry hives loaded in memory with their virtual and physical offsets",
    category: "registry",
    usage: "vol.py -f <memory_dump> windows.registry.hivelist",
  },
  {
    name: "hivedump",
    description: "Dump a complete registry hive from memory to disk for offline analysis",
    category: "registry",
    usage: "vol.py -f <memory_dump> windows.registry.hivedump --offset <offset>",
  },
  {
    name: "printkey",
    description: "Print a specific registry key and its subkeys/values from a loaded hive",
    category: "registry",
    usage: "vol.py -f <memory_dump> windows.registry.printkey --key <key_path>",
  },
  {
    name: "cmdscan",
    description: "Scan for command history buffers from cmd.exe (conhost) processes",
    category: "user-activity",
    usage: "vol.py -f <memory_dump> windows.cmdscan",
  },
  {
    name: "consoles",
    description: "Extract full console input/output buffers including command results",
    category: "user-activity",
    usage: "vol.py -f <memory_dump> windows.consoles",
  },
  {
    name: "cmdline",
    description: "Display command-line arguments for each running process",
    category: "processes",
    usage: "vol.py -f <memory_dump> windows.cmdline",
  },
  {
    name: "envars",
    description: "Display environment variables for each process from the PEB",
    category: "processes",
    usage: "vol.py -f <memory_dump> windows.envars",
  },
  {
    name: "handles",
    description: "List open handles (files, registry keys, mutexes, etc.) for processes",
    category: "processes",
    usage: "vol.py -f <memory_dump> windows.handles --pid <PID>",
  },
  {
    name: "svcscan",
    description: "Scan for Windows service records and their configuration in memory",
    category: "services",
    usage: "vol.py -f <memory_dump> windows.svcscan",
  },
  {
    name: "callbacks",
    description: "List registered kernel callbacks for process creation, image loading, and registry operations",
    category: "kernel",
    usage: "vol.py -f <memory_dump> windows.callbacks",
  },
  {
    name: "driverirp",
    description: "List IRP handler functions for loaded drivers to detect hooking",
    category: "kernel",
    usage: "vol.py -f <memory_dump> windows.driverirp",
  },
  {
    name: "ssdt",
    description: "Display the System Service Descriptor Table to detect syscall hooking by rootkits",
    category: "kernel",
    usage: "vol.py -f <memory_dump> windows.ssdt",
  },
  {
    name: "modules",
    description: "List loaded kernel modules/drivers from the PsLoadedModuleList",
    category: "kernel",
    usage: "vol.py -f <memory_dump> windows.modules",
  },
  {
    name: "modscan",
    description: "Scan physical memory for LDR_DATA_TABLE_ENTRY structures to find unlinked drivers",
    category: "kernel",
    usage: "vol.py -f <memory_dump> windows.modscan",
  },
  {
    name: "vadinfo",
    description: "Display Virtual Address Descriptor information including memory protection and mapped files",
    category: "memory",
    usage: "vol.py -f <memory_dump> windows.vadinfo --pid <PID>",
  },
  {
    name: "memmap",
    description: "Show the memory map for a specific process including all mapped regions",
    category: "memory",
    usage: "vol.py -f <memory_dump> windows.memmap --pid <PID> --dump",
  },
  {
    name: "timeliner",
    description: "Generate a comprehensive forensic timeline from all available temporal artifacts",
    category: "timeline",
    usage: "vol.py -f <memory_dump> timeliner.Timeliner",
  },
  {
    name: "strings",
    description: "Map physical-offset strings output back to owning processes",
    category: "analysis",
    usage: "vol.py -f <memory_dump> windows.strings --strings-file <strings.txt>",
  },
  {
    name: "procdump",
    description: "Dump a process executable from memory for static analysis",
    category: "extraction",
    usage: "vol.py -f <memory_dump> windows.pslist --pid <PID> --dump",
  },
];

// ---------------------------------------------------------------------------
// LOG_LOCATIONS -- common log file paths across platforms and services
// ---------------------------------------------------------------------------

const LOG_LOCATIONS = [
  {
    name: "Linux auth log",
    path: "/var/log/auth.log",
    os: "linux-debian",
    description: "Authentication events including SSH logins, sudo commands, and PAM module activity",
    format: "syslog",
  },
  {
    name: "Linux secure log",
    path: "/var/log/secure",
    os: "linux-rhel",
    description: "RHEL/CentOS authentication and authorization events",
    format: "syslog",
  },
  {
    name: "Linux syslog",
    path: "/var/log/syslog",
    os: "linux-debian",
    description: "General system activity log with messages from most system daemons",
    format: "syslog",
  },
  {
    name: "Linux messages",
    path: "/var/log/messages",
    os: "linux-rhel",
    description: "General system log on RHEL-based distributions",
    format: "syslog",
  },
  {
    name: "Linux kernel log",
    path: "/var/log/kern.log",
    os: "linux",
    description: "Kernel ring buffer messages including module loads and hardware events",
    format: "syslog",
  },
  {
    name: "Linux audit log",
    path: "/var/log/audit/audit.log",
    os: "linux",
    description: "Audit framework events including syscall tracing, file access, and SELinux denials",
    format: "audit",
  },
  {
    name: "Linux dpkg log",
    path: "/var/log/dpkg.log",
    os: "linux-debian",
    description: "Debian package manager install/upgrade/remove operations log",
    format: "custom",
  },
  {
    name: "Linux cron log",
    path: "/var/log/cron",
    os: "linux-rhel",
    description: "Cron daemon activity log showing scheduled task execution",
    format: "syslog",
  },
  {
    name: "Linux mail log",
    path: "/var/log/mail.log",
    os: "linux",
    description: "Mail Transfer Agent (Postfix/Sendmail/Exim) message processing logs",
    format: "syslog",
  },
  {
    name: "Linux UFW log",
    path: "/var/log/ufw.log",
    os: "linux-debian",
    description: "Uncomplicated Firewall rule match log with blocked/allowed connection details",
    format: "syslog",
  },
  {
    name: "Windows Security",
    path: "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
    os: "windows",
    description: "Security audit events: logon (4624/4625/4648), account management, privilege use, object access",
    format: "evtx",
  },
  {
    name: "Windows System",
    path: "C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
    os: "windows",
    description: "System component events: services, drivers, time changes, shutdown/startup",
    format: "evtx",
  },
  {
    name: "Windows Application",
    path: "C:\\Windows\\System32\\winevt\\Logs\\Application.evtx",
    os: "windows",
    description: "Application-level events, crashes, and program-specific log entries",
    format: "evtx",
  },
  {
    name: "Windows PowerShell",
    path: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx",
    os: "windows",
    description: "PowerShell script block logging, module logging, and transcription events",
    format: "evtx",
  },
  {
    name: "Windows Sysmon",
    path: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
    os: "windows",
    description: "Sysmon telemetry: process creation, network connections, file hash, registry changes",
    format: "evtx",
  },
  {
    name: "Windows Task Scheduler",
    path: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-TaskScheduler%4Operational.evtx",
    os: "windows",
    description: "Scheduled task creation, modification, execution, and completion events",
    format: "evtx",
  },
  {
    name: "Windows Defender",
    path: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Windows Defender%4Operational.evtx",
    os: "windows",
    description: "Windows Defender detection, remediation, and scan events",
    format: "evtx",
  },
  {
    name: "Apache access log",
    path: "/var/log/apache2/access.log",
    os: "linux",
    description: "Apache HTTP server request log with client IP, method, URI, status, and user-agent",
    format: "combined",
  },
  {
    name: "Apache error log",
    path: "/var/log/apache2/error.log",
    os: "linux",
    description: "Apache HTTP server error and diagnostic messages",
    format: "apache-error",
  },
  {
    name: "Nginx access log",
    path: "/var/log/nginx/access.log",
    os: "linux",
    description: "Nginx HTTP server request log with client details and response information",
    format: "combined",
  },
  {
    name: "Nginx error log",
    path: "/var/log/nginx/error.log",
    os: "linux",
    description: "Nginx server error messages, upstream failures, and configuration problems",
    format: "nginx-error",
  },
  {
    name: "MySQL general log",
    path: "/var/log/mysql/mysql.log",
    os: "linux",
    description: "MySQL server general query log with all SQL statements received from clients",
    format: "mysql",
  },
  {
    name: "MySQL error log",
    path: "/var/log/mysql/error.log",
    os: "linux",
    description: "MySQL server startup, shutdown, and error diagnostic messages",
    format: "mysql",
  },
  {
    name: "PostgreSQL log",
    path: "/var/log/postgresql/postgresql-<version>-main.log",
    os: "linux",
    description: "PostgreSQL server activity log including queries, errors, and connection events",
    format: "postgresql",
  },
  {
    name: "Docker daemon log",
    path: "/var/log/docker.log",
    os: "linux",
    description: "Docker daemon operational events, container lifecycle, and error messages",
    format: "json",
  },
  {
    name: "Docker container logs",
    path: "/var/lib/docker/containers/<id>/<id>-json.log",
    os: "linux",
    description: "Per-container stdout/stderr captured by the Docker JSON file logging driver",
    format: "json",
  },
  {
    name: "Kubernetes API audit",
    path: "/var/log/kubernetes/audit/audit.log",
    os: "linux",
    description: "Kubernetes API server audit log recording all API requests and responses",
    format: "json",
  },
  {
    name: "Kubernetes kubelet",
    path: "/var/log/kubelet.log",
    os: "linux",
    description: "Kubelet agent log with pod lifecycle events, image pulls, and health checks",
    format: "klog",
  },
  {
    name: "IIS access log",
    path: "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex*.log",
    os: "windows",
    description: "IIS web server request log in W3C Extended format with configurable fields",
    format: "w3c",
  },
  {
    name: "SSH daemon log",
    path: "/var/log/auth.log",
    os: "linux",
    description: "SSH connection attempts, key authentication, and session events (within auth.log)",
    format: "syslog",
  },
  {
    name: "Systemd journal",
    path: "/var/log/journal/<machine-id>",
    os: "linux",
    description: "Binary structured journal accessed via journalctl -- survives reboots if persistent",
    format: "journal",
  },
  {
    name: "Suricata EVE log",
    path: "/var/log/suricata/eve.json",
    os: "linux",
    description: "Suricata IDS/IPS event log in JSON format with alerts, flow, DNS, HTTP metadata",
    format: "json",
  },
];

// ---------------------------------------------------------------------------
// timelineEntry -- format a single forensic timeline entry
// ---------------------------------------------------------------------------

/**
 * Create a structured forensic timeline entry. The hash field provides a
 * content-addressable identifier for deduplication across merged timelines.
 *
 * @param {string|number|Date} ts  - A timestamp (ISO string, epoch ms, or Date)
 * @param {string} source          - Label identifying the evidence source
 * @param {string} event           - Human-readable description of the event
 * @returns {{ timestamp: number, isoTime: string, source: string, event: string, hash: string }}
 */
function timelineEntry(ts, source, event) {
  let d;
  if (ts instanceof Date) {
    d = ts;
  } else if (typeof ts === "number") {
    d = new Date(ts);
  } else {
    d = new Date(String(ts));
  }

  const timestamp = d.getTime();
  const isoTime = d.toISOString();
  const raw = `${isoTime}|${source}|${event}`;
  const hash = crypto.createHash("sha256").update(raw).digest("hex").slice(0, 16);

  return { timestamp, isoTime, source, event, hash };
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  LINUX_ARTIFACTS,
  WINDOWS_ARTIFACTS,
  VOLATILITY_PLUGINS,
  LOG_LOCATIONS,
  timelineEntry,
};
