"use strict";

// ---------------------------------------------------------------------------
// commands-data.js  --  Security command reference for Darknode CLI
// ---------------------------------------------------------------------------

const LINUX_COMMANDS = [
  // ---- filesystem ----
  {
    cmd: "ls",
    desc: "List directory contents with detailed attributes",
    examples: [
      { usage: "ls -la /etc/", output: "drwxr-xr-x  2 root root 4096 ... shadow" },
      { usage: "ls -lah --time=atime /var/log/", output: "Shows access times for log files" }
    ],
    category: "filesystem"
  },
  {
    cmd: "find",
    desc: "Search for files and directories matching criteria",
    examples: [
      { usage: "find / -perm -4000 -type f 2>/dev/null", output: "Lists all SUID binaries on the system" },
      { usage: "find /tmp -name '*.sh' -mtime -1", output: "Shell scripts modified in last 24 hours" }
    ],
    category: "filesystem"
  },
  {
    cmd: "locate",
    desc: "Find files by name using a prebuilt database",
    examples: [
      { usage: "locate passwd", output: "/etc/passwd\n/usr/bin/passwd" },
      { usage: "locate -i '*.conf' | head -20", output: "First 20 config files (case-insensitive)" }
    ],
    category: "filesystem"
  },
  {
    cmd: "stat",
    desc: "Display detailed file status including inode and timestamps",
    examples: [
      { usage: "stat /etc/shadow", output: "File: /etc/shadow\nSize: 1234  Blocks: 8  IO Block: 4096" },
      { usage: "stat -c '%a %U %G %n' /etc/passwd", output: "644 root root /etc/passwd" }
    ],
    category: "filesystem"
  },
  {
    cmd: "file",
    desc: "Determine file type by examining contents",
    examples: [
      { usage: "file /usr/bin/nmap", output: "/usr/bin/nmap: ELF 64-bit LSB pie executable" },
      { usage: "file suspicious.pdf", output: "suspicious.pdf: PDF document, version 1.4" }
    ],
    category: "filesystem"
  },
  {
    cmd: "lsof",
    desc: "List open files and associated processes",
    examples: [
      { usage: "lsof -i :80", output: "Shows processes listening on port 80" },
      { usage: "lsof -u www-data", output: "All files opened by the www-data user" }
    ],
    category: "filesystem"
  },
  {
    cmd: "df",
    desc: "Report filesystem disk space usage",
    examples: [
      { usage: "df -hT", output: "Filesystem  Type  Size  Used Avail Use% Mounted" },
      { usage: "df -i", output: "Shows inode usage per filesystem" }
    ],
    category: "filesystem"
  },
  {
    cmd: "du",
    desc: "Estimate file and directory space usage",
    examples: [
      { usage: "du -sh /var/log/*", output: "Summarize size of each item in /var/log" },
      { usage: "du -ah --max-depth=1 / 2>/dev/null | sort -rh | head -20", output: "Top 20 largest dirs" }
    ],
    category: "filesystem"
  },
  {
    cmd: "mount",
    desc: "Mount filesystems or display currently mounted filesystems",
    examples: [
      { usage: "mount | grep -E 'ext4|xfs'", output: "Show mounted ext4/xfs partitions" },
      { usage: "mount -o ro /dev/sdb1 /mnt/evidence", output: "Read-only mount for forensic analysis" }
    ],
    category: "filesystem"
  },
  {
    cmd: "umount",
    desc: "Unmount a mounted filesystem",
    examples: [
      { usage: "umount /mnt/evidence", output: "Unmounts the evidence partition" },
      { usage: "umount -l /mnt/stuck", output: "Lazy unmount for busy filesystem" }
    ],
    category: "filesystem"
  },
  {
    cmd: "ln",
    desc: "Create hard and symbolic links",
    examples: [
      { usage: "ln -s /usr/local/bin/python3 /usr/local/bin/python", output: "Creates symlink" },
      { usage: "ln -sf /etc/alternatives/editor /usr/bin/vim", output: "Force-create symlink" }
    ],
    category: "filesystem"
  },
  {
    cmd: "cp",
    desc: "Copy files and directories",
    examples: [
      { usage: "cp -a /var/log/ /tmp/log-backup/", output: "Archive copy preserving attributes" },
      { usage: "cp --preserve=all evidence.img /mnt/backup/", output: "Copy preserving all metadata" }
    ],
    category: "filesystem"
  },
  {
    cmd: "mv",
    desc: "Move or rename files and directories",
    examples: [
      { usage: "mv suspicious.bin quarantine/", output: "Move file to quarantine directory" },
      { usage: "mv -i /tmp/config /etc/config", output: "Move with interactive overwrite prompt" }
    ],
    category: "filesystem"
  },
  {
    cmd: "rm",
    desc: "Remove files and directories",
    examples: [
      { usage: "rm -rf /tmp/malware-sample/", output: "Recursively remove malware directory" },
      { usage: "rm -i suspicious-*", output: "Interactively remove suspicious files" }
    ],
    category: "filesystem"
  },
  {
    cmd: "mkdir",
    desc: "Create directories",
    examples: [
      { usage: "mkdir -p /opt/forensics/{memory,disk,network}", output: "Create nested forensics dirs" },
      { usage: "mkdir -m 700 /root/.secrets", output: "Create directory with restricted permissions" }
    ],
    category: "filesystem"
  },
  {
    cmd: "tree",
    desc: "Display directory structure as a tree",
    examples: [
      { usage: "tree -L 2 /etc/", output: "Two-level tree of /etc" },
      { usage: "tree -pugsh /var/www/", output: "Tree with permissions, user, group, size" }
    ],
    category: "filesystem"
  },
  {
    cmd: "cat",
    desc: "Concatenate and display file contents",
    examples: [
      { usage: "cat /etc/passwd", output: "root:x:0:0:root:/root:/bin/bash" },
      { usage: "cat -n /var/log/auth.log | tail -50", output: "Last 50 lines with numbers" }
    ],
    category: "filesystem"
  },
  {
    cmd: "head",
    desc: "Output the first part of files",
    examples: [
      { usage: "head -100 /var/log/syslog", output: "First 100 lines of syslog" },
      { usage: "head -c 512 binary.dat | xxd", output: "Hex dump of first 512 bytes" }
    ],
    category: "filesystem"
  },
  {
    cmd: "tail",
    desc: "Output the last part of files or follow live output",
    examples: [
      { usage: "tail -f /var/log/auth.log", output: "Follow authentication log in real-time" },
      { usage: "tail -n +2 data.csv", output: "Print all lines except the header" }
    ],
    category: "filesystem"
  },
  {
    cmd: "less",
    desc: "Page through file contents interactively",
    examples: [
      { usage: "less +F /var/log/syslog", output: "Follow mode, like tail -f with paging" },
      { usage: "less -N /etc/nginx/nginx.conf", output: "View with line numbers" }
    ],
    category: "filesystem"
  },
  {
    cmd: "diff",
    desc: "Compare files line by line",
    examples: [
      { usage: "diff -u original.conf modified.conf", output: "Unified diff format output" },
      { usage: "diff -rq /etc/backup/ /etc/", output: "Recursive comparison of directories" }
    ],
    category: "filesystem"
  },
  {
    cmd: "md5sum",
    desc: "Compute MD5 message digest for file integrity",
    examples: [
      { usage: "md5sum /usr/bin/ssh", output: "a1b2c3d4e5f6...  /usr/bin/ssh" },
      { usage: "md5sum -c checksums.md5", output: "Verify files against stored checksums" }
    ],
    category: "filesystem"
  },
  {
    cmd: "sha256sum",
    desc: "Compute SHA-256 hash for file verification",
    examples: [
      { usage: "sha256sum evidence.img", output: "f3a4b5c6d7e8...  evidence.img" },
      { usage: "sha256sum -c manifest.sha256", output: "Verify all files in manifest" }
    ],
    category: "filesystem"
  },
  {
    cmd: "inotifywait",
    desc: "Watch filesystem events in real-time",
    examples: [
      { usage: "inotifywait -m -r /etc/", output: "Monitor all changes under /etc recursively" },
      { usage: "inotifywait -e modify,create,delete /var/www/", output: "Watch web root for changes" }
    ],
    category: "filesystem"
  },
  {
    cmd: "dd",
    desc: "Low-level copy and conversion of data blocks",
    examples: [
      { usage: "dd if=/dev/sda of=disk.img bs=4M status=progress", output: "Full disk image for forensics" },
      { usage: "dd if=/dev/urandom of=wipe.bin bs=1M count=100", output: "Generate 100MB of random data" }
    ],
    category: "filesystem"
  },
  {
    cmd: "rsync",
    desc: "Efficient file synchronization and transfer",
    examples: [
      { usage: "rsync -avz --progress /data/ user@backup:/data/", output: "Sync with compression" },
      { usage: "rsync -av --delete /var/www/ /backup/www/", output: "Mirror with deletion of extras" }
    ],
    category: "filesystem"
  },
  {
    cmd: "tar",
    desc: "Archive and extract files",
    examples: [
      { usage: "tar czf evidence-$(date +%F).tar.gz /var/log/", output: "Compress logs with date stamp" },
      { usage: "tar xzf payload.tar.gz -C /tmp/analysis/", output: "Extract to analysis directory" }
    ],
    category: "filesystem"
  },
  {
    cmd: "gzip",
    desc: "Compress and decompress files",
    examples: [
      { usage: "gzip -9 access.log", output: "Maximum compression on log file" },
      { usage: "gzip -dk archive.gz", output: "Decompress keeping original" }
    ],
    category: "filesystem"
  },
  {
    cmd: "xattr",
    desc: "Display and manipulate extended file attributes",
    examples: [
      { usage: "xattr -l suspicious_file", output: "List all extended attributes" },
      { usage: "getfattr -d -m '' /tmp/evidence", output: "Dump all extended attributes" }
    ],
    category: "filesystem"
  },

  // ---- processes ----
  {
    cmd: "ps",
    desc: "Report a snapshot of current processes",
    examples: [
      { usage: "ps auxf", output: "Full process tree with all users" },
      { usage: "ps -eo pid,ppid,user,%cpu,%mem,cmd --sort=-%cpu | head -20", output: "Top 20 CPU consumers" }
    ],
    category: "processes"
  },
  {
    cmd: "top",
    desc: "Display real-time process and resource monitor",
    examples: [
      { usage: "top -bn1 | head -20", output: "Single snapshot of top processes" },
      { usage: "top -u www-data", output: "Monitor only www-data user processes" }
    ],
    category: "processes"
  },
  {
    cmd: "htop",
    desc: "Interactive process viewer with color and tree support",
    examples: [
      { usage: "htop -t", output: "Tree view of all processes" },
      { usage: "htop -u root", output: "Filter to root processes only" }
    ],
    category: "processes"
  },
  {
    cmd: "kill",
    desc: "Send signals to processes",
    examples: [
      { usage: "kill -9 1234", output: "Force-kill process with PID 1234" },
      { usage: "kill -STOP 5678", output: "Pause/freeze a suspicious process" }
    ],
    category: "processes"
  },
  {
    cmd: "killall",
    desc: "Kill processes by name",
    examples: [
      { usage: "killall -9 cryptominer", output: "Force-kill all instances by name" },
      { usage: "killall -u attacker", output: "Kill all processes owned by user" }
    ],
    category: "processes"
  },
  {
    cmd: "pkill",
    desc: "Signal processes by pattern matching",
    examples: [
      { usage: "pkill -f 'python.*reverse_shell'", output: "Kill by full command match" },
      { usage: "pkill -STOP -u nobody", output: "Freeze all nobody-owned processes" }
    ],
    category: "processes"
  },
  {
    cmd: "pgrep",
    desc: "Find processes by pattern",
    examples: [
      { usage: "pgrep -la ssh", output: "1234 sshd\n5678 ssh-agent" },
      { usage: "pgrep -u root -c", output: "Count of processes owned by root" }
    ],
    category: "processes"
  },
  {
    cmd: "nice",
    desc: "Run a command with modified scheduling priority",
    examples: [
      { usage: "nice -n 19 ./long_scan.sh", output: "Run scan at lowest priority" },
      { usage: "nice -n -20 tcpdump -i eth0", output: "High priority capture (root)" }
    ],
    category: "processes"
  },
  {
    cmd: "renice",
    desc: "Alter priority of a running process",
    examples: [
      { usage: "renice -n 10 -p 1234", output: "Lower priority of PID 1234" },
      { usage: "renice -n -5 -u scanner", output: "Boost priority for scanner user" }
    ],
    category: "processes"
  },
  {
    cmd: "nohup",
    desc: "Run a command immune to hangups",
    examples: [
      { usage: "nohup ./scan.sh &", output: "Run scan that persists after logout" },
      { usage: "nohup tcpdump -i eth0 -w capture.pcap &", output: "Background capture" }
    ],
    category: "processes"
  },
  {
    cmd: "strace",
    desc: "Trace system calls and signals of a process",
    examples: [
      { usage: "strace -p 1234 -e trace=network", output: "Trace network syscalls of PID" },
      { usage: "strace -f -o trace.log ./suspicious_binary", output: "Full trace with children" }
    ],
    category: "processes"
  },
  {
    cmd: "ltrace",
    desc: "Trace library calls made by a process",
    examples: [
      { usage: "ltrace -p 1234", output: "Trace library calls of running process" },
      { usage: "ltrace -e 'strcmp+strlen' ./binary", output: "Trace specific library functions" }
    ],
    category: "processes"
  },
  {
    cmd: "lsns",
    desc: "List Linux namespaces",
    examples: [
      { usage: "lsns", output: "NS TYPE  NPROCS PID USER  COMMAND" },
      { usage: "lsns -t net", output: "List network namespaces only" }
    ],
    category: "processes"
  },
  {
    cmd: "pstree",
    desc: "Display process hierarchy as a tree",
    examples: [
      { usage: "pstree -p", output: "Tree with PIDs shown" },
      { usage: "pstree -u www-data", output: "Process tree for www-data user" }
    ],
    category: "processes"
  },
  {
    cmd: "jobs",
    desc: "List active background jobs in the current shell",
    examples: [
      { usage: "jobs -l", output: "[1]+ 1234 Running  nmap -sS target &" },
      { usage: "jobs -r", output: "Show only running jobs" }
    ],
    category: "processes"
  },
  {
    cmd: "bg",
    desc: "Resume a suspended job in the background",
    examples: [
      { usage: "bg %1", output: "Resume job 1 in background" },
      { usage: "bg", output: "Resume most recent suspended job" }
    ],
    category: "processes"
  },
  {
    cmd: "fg",
    desc: "Resume a background job in the foreground",
    examples: [
      { usage: "fg %1", output: "Bring job 1 to foreground" },
      { usage: "fg", output: "Bring most recent background job forward" }
    ],
    category: "processes"
  },
  {
    cmd: "watch",
    desc: "Execute a command periodically and display output",
    examples: [
      { usage: "watch -n 2 'netstat -tlnp'", output: "Refresh listening ports every 2s" },
      { usage: "watch -d 'ls -la /tmp/'", output: "Highlight differences in /tmp listing" }
    ],
    category: "processes"
  },
  {
    cmd: "screen",
    desc: "Terminal multiplexer for persistent sessions",
    examples: [
      { usage: "screen -S pentest", output: "Start named screen session" },
      { usage: "screen -r pentest", output: "Reattach to pentest session" }
    ],
    category: "processes"
  },
  {
    cmd: "tmux",
    desc: "Terminal multiplexer with split panes and sessions",
    examples: [
      { usage: "tmux new -s recon", output: "Start new session named recon" },
      { usage: "tmux attach -t recon", output: "Reattach to recon session" }
    ],
    category: "processes"
  },
  {
    cmd: "crontab",
    desc: "Schedule recurring tasks via cron",
    examples: [
      { usage: "crontab -l", output: "List current user cron jobs" },
      { usage: "crontab -l -u www-data", output: "List cron jobs for www-data" }
    ],
    category: "processes"
  },
  {
    cmd: "at",
    desc: "Schedule a one-time command execution",
    examples: [
      { usage: "echo '/opt/scan.sh' | at now + 5 minutes", output: "Schedule scan in 5 minutes" },
      { usage: "atq", output: "List pending at jobs" }
    ],
    category: "processes"
  },
  {
    cmd: "systemd-cgls",
    desc: "Display control group hierarchy",
    examples: [
      { usage: "systemd-cgls", output: "Full cgroup tree" },
      { usage: "systemd-cgls --no-pager", output: "Non-interactive cgroup listing" }
    ],
    category: "processes"
  },
  {
    cmd: "pidof",
    desc: "Find process ID of a running program",
    examples: [
      { usage: "pidof sshd", output: "1234 5678" },
      { usage: "pidof -s nginx", output: "Returns single PID of nginx" }
    ],
    category: "processes"
  },

  // ---- networking ----
  {
    cmd: "ip",
    desc: "Show and manipulate routing, interfaces, and tunnels",
    examples: [
      { usage: "ip addr show", output: "Display all interface addresses" },
      { usage: "ip route show", output: "Display routing table" },
      { usage: "ip neigh show", output: "Display ARP/neighbor table" }
    ],
    category: "networking"
  },
  {
    cmd: "ifconfig",
    desc: "Configure or display network interface parameters (legacy)",
    examples: [
      { usage: "ifconfig -a", output: "Show all interfaces including down" },
      { usage: "ifconfig eth0 promisc", output: "Enable promiscuous mode for sniffing" }
    ],
    category: "networking"
  },
  {
    cmd: "netstat",
    desc: "Print network connections, routing tables, and statistics",
    examples: [
      { usage: "netstat -tlnp", output: "TCP listeners with PIDs" },
      { usage: "netstat -anp | grep ESTABLISHED", output: "All established connections" },
      { usage: "netstat -s", output: "Protocol statistics summary" }
    ],
    category: "networking"
  },
  {
    cmd: "ss",
    desc: "Socket statistics utility (modern netstat replacement)",
    examples: [
      { usage: "ss -tlnp", output: "TCP listening sockets with process info" },
      { usage: "ss -s", output: "Summary of socket statistics" },
      { usage: "ss -o state established '( dport = :443 )'", output: "HTTPS connections with timers" }
    ],
    category: "networking"
  },
  {
    cmd: "ping",
    desc: "Send ICMP echo requests to test connectivity",
    examples: [
      { usage: "ping -c 4 192.168.1.1", output: "4 packets transmitted, 4 received, 0% loss" },
      { usage: "ping -c 1 -W 1 10.0.0.1", output: "Quick alive check with 1s timeout" }
    ],
    category: "networking"
  },
  {
    cmd: "traceroute",
    desc: "Trace the route packets take to a host",
    examples: [
      { usage: "traceroute -n 8.8.8.8", output: "Numeric trace to Google DNS" },
      { usage: "traceroute -T -p 443 target.com", output: "TCP traceroute on port 443" }
    ],
    category: "networking"
  },
  {
    cmd: "mtr",
    desc: "Network diagnostic combining ping and traceroute",
    examples: [
      { usage: "mtr -n --report 8.8.8.8", output: "Report mode with numeric IPs" },
      { usage: "mtr -rwc 50 target.com", output: "50-cycle wide report" }
    ],
    category: "networking"
  },
  {
    cmd: "dig",
    desc: "DNS lookup utility for querying name servers",
    examples: [
      { usage: "dig example.com ANY", output: "Query all record types" },
      { usage: "dig @8.8.8.8 example.com MX +short", output: "MX records via Google DNS" },
      { usage: "dig -x 93.184.216.34", output: "Reverse DNS lookup" }
    ],
    category: "networking"
  },
  {
    cmd: "nslookup",
    desc: "Query DNS name servers interactively or non-interactively",
    examples: [
      { usage: "nslookup example.com", output: "Basic DNS lookup" },
      { usage: "nslookup -type=TXT example.com", output: "Query TXT records (SPF, DKIM)" }
    ],
    category: "networking"
  },
  {
    cmd: "host",
    desc: "Simple DNS lookup utility",
    examples: [
      { usage: "host -t AAAA example.com", output: "Query IPv6 address records" },
      { usage: "host -l example.com ns1.example.com", output: "Attempt zone transfer" }
    ],
    category: "networking"
  },
  {
    cmd: "whois",
    desc: "Query WHOIS database for domain and IP registration info",
    examples: [
      { usage: "whois example.com", output: "Domain registration details" },
      { usage: "whois 93.184.216.34", output: "IP block ownership info" }
    ],
    category: "networking"
  },
  {
    cmd: "nmap",
    desc: "Network exploration and security auditing tool",
    examples: [
      { usage: "nmap -sS -sV -O 192.168.1.0/24", output: "SYN scan with version and OS detection" },
      { usage: "nmap -sn 10.0.0.0/24", output: "Ping sweep for host discovery" },
      { usage: "nmap --script vuln 192.168.1.1", output: "Run vulnerability scripts" }
    ],
    category: "networking"
  },
  {
    cmd: "masscan",
    desc: "High-speed TCP port scanner",
    examples: [
      { usage: "masscan -p1-65535 10.0.0.0/8 --rate=10000", output: "Full port scan at 10k pps" },
      { usage: "masscan -p80,443 192.168.0.0/16 --rate=5000", output: "Web port scan" }
    ],
    category: "networking"
  },
  {
    cmd: "tcpdump",
    desc: "Capture and analyze network traffic",
    examples: [
      { usage: "tcpdump -i eth0 -nn port 53", output: "Capture DNS traffic" },
      { usage: "tcpdump -i any -w capture.pcap -c 10000", output: "Capture 10k packets to file" },
      { usage: "tcpdump -r capture.pcap -A 'tcp port 80'", output: "Read pcap, show ASCII HTTP" }
    ],
    category: "networking"
  },
  {
    cmd: "tshark",
    desc: "Terminal-based Wireshark for packet analysis",
    examples: [
      { usage: "tshark -i eth0 -f 'port 443'", output: "Capture TLS traffic" },
      { usage: "tshark -r capture.pcap -T fields -e ip.src -e ip.dst", output: "Extract source/dest IPs" }
    ],
    category: "networking"
  },
  {
    cmd: "curl",
    desc: "Transfer data from or to a server using various protocols",
    examples: [
      { usage: "curl -I https://example.com", output: "Fetch HTTP headers only" },
      { usage: "curl -x socks5://127.0.0.1:9050 http://target.onion", output: "Request via Tor" },
      { usage: "curl -s -o /dev/null -w '%{http_code}' https://example.com", output: "Get status code only" }
    ],
    category: "networking"
  },
  {
    cmd: "wget",
    desc: "Non-interactive network downloader",
    examples: [
      { usage: "wget -r -l 2 https://example.com/", output: "Recursive download, 2 levels deep" },
      { usage: "wget --mirror --convert-links https://example.com", output: "Mirror entire site" }
    ],
    category: "networking"
  },
  {
    cmd: "nc",
    desc: "Netcat: arbitrary TCP/UDP connections and listeners",
    examples: [
      { usage: "nc -lvnp 4444", output: "Listen on port 4444 for connections" },
      { usage: "nc -zv 192.168.1.1 1-1000", output: "Port scan range 1-1000" },
      { usage: "echo 'test' | nc -w 3 192.168.1.1 80", output: "Send data to port 80" }
    ],
    category: "networking"
  },
  {
    cmd: "socat",
    desc: "Multipurpose relay for bidirectional data transfer",
    examples: [
      { usage: "socat TCP-LISTEN:8080,fork TCP:target:80", output: "TCP port forwarder" },
      { usage: "socat - OPENSSL:server:443", output: "Connect to TLS service" }
    ],
    category: "networking"
  },
  {
    cmd: "ssh",
    desc: "Secure shell remote login and command execution",
    examples: [
      { usage: "ssh -L 8080:internal:80 user@jumpbox", output: "Local port forward through jumpbox" },
      { usage: "ssh -D 9050 user@proxy", output: "Dynamic SOCKS proxy" },
      { usage: "ssh -R 9999:localhost:22 user@attacker", output: "Reverse tunnel" }
    ],
    category: "networking"
  },
  {
    cmd: "scp",
    desc: "Secure copy files between hosts",
    examples: [
      { usage: "scp evidence.tar.gz user@forensics:/cases/", output: "Copy evidence to remote" },
      { usage: "scp -r user@target:/var/log/ ./logs/", output: "Recursive copy logs from remote" }
    ],
    category: "networking"
  },
  {
    cmd: "sftp",
    desc: "Secure FTP for interactive file transfer",
    examples: [
      { usage: "sftp user@target", output: "Start interactive SFTP session" },
      { usage: "sftp -b batch.txt user@target", output: "Batch-mode SFTP transfer" }
    ],
    category: "networking"
  },
  {
    cmd: "arp",
    desc: "Display and manipulate the ARP cache",
    examples: [
      { usage: "arp -a", output: "Display all ARP entries" },
      { usage: "arp -d 192.168.1.1", output: "Delete a specific ARP entry" }
    ],
    category: "networking"
  },
  {
    cmd: "arping",
    desc: "Send ARP requests to discover hosts on LAN",
    examples: [
      { usage: "arping -c 3 192.168.1.1", output: "ARP ping a host" },
      { usage: "arping -D 192.168.1.100", output: "Duplicate address detection" }
    ],
    category: "networking"
  },
  {
    cmd: "route",
    desc: "Show or manipulate the IP routing table (legacy)",
    examples: [
      { usage: "route -n", output: "Numeric routing table" },
      { usage: "route add -net 10.0.0.0/8 gw 192.168.1.1", output: "Add static route" }
    ],
    category: "networking"
  },
  {
    cmd: "iptables",
    desc: "Configure IPv4 packet filter rules",
    examples: [
      { usage: "iptables -L -n -v", output: "List all rules with counters" },
      { usage: "iptables -A INPUT -s 10.0.0.0/8 -j DROP", output: "Block an IP range" },
      { usage: "iptables -t nat -L -n", output: "List NAT table rules" }
    ],
    category: "networking"
  },
  {
    cmd: "nftables",
    desc: "Modern Linux packet classification framework",
    examples: [
      { usage: "nft list ruleset", output: "Show all nftables rules" },
      { usage: "nft add rule inet filter input tcp dport 22 accept", output: "Allow SSH" }
    ],
    category: "networking"
  },
  {
    cmd: "ethtool",
    desc: "Display or change ethernet device settings",
    examples: [
      { usage: "ethtool eth0", output: "Show NIC settings and link status" },
      { usage: "ethtool -S eth0", output: "NIC statistics including errors" }
    ],
    category: "networking"
  },
  {
    cmd: "iwconfig",
    desc: "Configure wireless network interfaces",
    examples: [
      { usage: "iwconfig wlan0", output: "Show wireless interface config" },
      { usage: "iwconfig wlan0 mode monitor", output: "Set interface to monitor mode" }
    ],
    category: "networking"
  },
  {
    cmd: "airmon-ng",
    desc: "Enable monitor mode on wireless interfaces",
    examples: [
      { usage: "airmon-ng start wlan0", output: "Start monitor mode on wlan0" },
      { usage: "airmon-ng check kill", output: "Kill interfering processes" }
    ],
    category: "networking"
  },
  {
    cmd: "airodump-ng",
    desc: "Capture 802.11 frames for wireless analysis",
    examples: [
      { usage: "airodump-ng wlan0mon", output: "Capture all nearby wireless traffic" },
      { usage: "airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF wlan0mon", output: "Target specific AP" }
    ],
    category: "networking"
  },
  {
    cmd: "aireplay-ng",
    desc: "Inject frames into wireless networks",
    examples: [
      { usage: "aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon", output: "Deauth attack" },
      { usage: "aireplay-ng -3 -b AA:BB:CC:DD:EE:FF wlan0mon", output: "ARP request replay" }
    ],
    category: "networking"
  },
  {
    cmd: "hping3",
    desc: "TCP/IP packet assembler and analyzer",
    examples: [
      { usage: "hping3 -S -p 80 --flood target", output: "SYN flood (testing only)" },
      { usage: "hping3 -1 -c 3 192.168.1.1", output: "ICMP ping with hping" }
    ],
    category: "networking"
  },
  {
    cmd: "iftop",
    desc: "Display bandwidth usage by connection",
    examples: [
      { usage: "iftop -i eth0", output: "Real-time bandwidth per connection" },
      { usage: "iftop -nNP -i eth0", output: "Numeric mode with port numbers" }
    ],
    category: "networking"
  },
  {
    cmd: "nethogs",
    desc: "Group bandwidth by process",
    examples: [
      { usage: "nethogs eth0", output: "Per-process bandwidth on eth0" },
      { usage: "nethogs -t", output: "Trace mode with timestamps" }
    ],
    category: "networking"
  },
  {
    cmd: "vnstat",
    desc: "Network traffic monitor with persistent statistics",
    examples: [
      { usage: "vnstat -d", output: "Daily traffic summary" },
      { usage: "vnstat -l -i eth0", output: "Live traffic rate on eth0" }
    ],
    category: "networking"
  },
  {
    cmd: "openssl",
    desc: "Toolkit for TLS/SSL and general cryptography",
    examples: [
      { usage: "openssl s_client -connect example.com:443", output: "Test TLS connection" },
      { usage: "openssl x509 -in cert.pem -text -noout", output: "Display certificate details" },
      { usage: "openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout key.pem -out cert.pem", output: "Generate self-signed cert" }
    ],
    category: "networking"
  },
  {
    cmd: "proxychains",
    desc: "Route TCP connections through proxy chains",
    examples: [
      { usage: "proxychains nmap -sT 192.168.1.1", output: "Nmap through proxy chain" },
      { usage: "proxychains curl http://target.com", output: "cURL through SOCKS proxies" }
    ],
    category: "networking"
  },
  {
    cmd: "tor",
    desc: "Anonymity network daemon and routing",
    examples: [
      { usage: "systemctl start tor", output: "Start Tor service" },
      { usage: "curl --socks5 127.0.0.1:9050 https://check.torproject.org", output: "Verify Tor connectivity" }
    ],
    category: "networking"
  },
  {
    cmd: "ftp",
    desc: "File Transfer Protocol client",
    examples: [
      { usage: "ftp -n target.com", output: "Connect without auto-login" },
      { usage: "ftp -A target.com", output: "Active mode FTP connection" }
    ],
    category: "networking"
  },
  {
    cmd: "telnet",
    desc: "Telnet client for protocol testing and banner grabbing",
    examples: [
      { usage: "telnet target.com 25", output: "Connect to SMTP for banner grab" },
      { usage: "telnet target.com 80", output: "Manual HTTP request testing" }
    ],
    category: "networking"
  },
  {
    cmd: "ipcalc",
    desc: "Calculate IP network ranges and subnets",
    examples: [
      { usage: "ipcalc 192.168.1.0/24", output: "Network, broadcast, host range details" },
      { usage: "ipcalc -b 10.0.0.0/16", output: "Broadcast address calculation" }
    ],
    category: "networking"
  },
  {
    cmd: "resolvectl",
    desc: "Resolve domain names, manage DNS settings (systemd-resolved)",
    examples: [
      { usage: "resolvectl status", output: "Show DNS configuration per interface" },
      { usage: "resolvectl query example.com", output: "Resolve with systemd-resolved" }
    ],
    category: "networking"
  },

  // ---- users ----
  {
    cmd: "whoami",
    desc: "Print the current effective user name",
    examples: [
      { usage: "whoami", output: "root" },
      { usage: "sudo whoami", output: "root (verify sudo access)" }
    ],
    category: "users"
  },
  {
    cmd: "id",
    desc: "Print user and group information",
    examples: [
      { usage: "id", output: "uid=0(root) gid=0(root) groups=0(root)" },
      { usage: "id www-data", output: "uid=33(www-data) gid=33(www-data) groups=33(www-data)" }
    ],
    category: "users"
  },
  {
    cmd: "who",
    desc: "Show who is logged on",
    examples: [
      { usage: "who -a", output: "All login information including dead processes" },
      { usage: "who -u", output: "Show idle time for logged-in users" }
    ],
    category: "users"
  },
  {
    cmd: "w",
    desc: "Show who is logged on and what they are doing",
    examples: [
      { usage: "w", output: "USER  TTY  FROM  LOGIN@  IDLE  JCPU  PCPU  WHAT" },
      { usage: "w -h", output: "Without header line" }
    ],
    category: "users"
  },
  {
    cmd: "last",
    desc: "Show listing of last logged in users",
    examples: [
      { usage: "last -a", output: "Show hostnames in last column" },
      { usage: "last -f /var/log/wtmp.1", output: "Read from rotated wtmp file" }
    ],
    category: "users"
  },
  {
    cmd: "lastb",
    desc: "Show bad (failed) login attempts",
    examples: [
      { usage: "lastb | head -20", output: "Recent 20 failed login attempts" },
      { usage: "lastb -a | awk '{print $NF}' | sort | uniq -c | sort -rn", output: "Count by source IP" }
    ],
    category: "users"
  },
  {
    cmd: "lastlog",
    desc: "Reports the most recent login of all users",
    examples: [
      { usage: "lastlog", output: "Last login times for all users" },
      { usage: "lastlog -u root", output: "Last login for root only" }
    ],
    category: "users"
  },
  {
    cmd: "useradd",
    desc: "Create a new user account",
    examples: [
      { usage: "useradd -m -s /bin/bash analyst", output: "Create analyst with home dir and bash" },
      { usage: "useradd -r -s /usr/sbin/nologin svcaccount", output: "Create service account" }
    ],
    category: "users"
  },
  {
    cmd: "userdel",
    desc: "Delete a user account",
    examples: [
      { usage: "userdel -r compromised_user", output: "Remove user and home directory" },
      { usage: "userdel attacker", output: "Remove user account only" }
    ],
    category: "users"
  },
  {
    cmd: "usermod",
    desc: "Modify a user account",
    examples: [
      { usage: "usermod -L suspect_user", output: "Lock user account" },
      { usage: "usermod -aG sudo analyst", output: "Add analyst to sudo group" },
      { usage: "usermod -s /usr/sbin/nologin compromised", output: "Disable shell access" }
    ],
    category: "users"
  },
  {
    cmd: "passwd",
    desc: "Change user password",
    examples: [
      { usage: "passwd -l suspect_user", output: "Lock user password" },
      { usage: "passwd -e analyst", output: "Force password change at next login" },
      { usage: "passwd --status root", output: "Show password status for root" }
    ],
    category: "users"
  },
  {
    cmd: "groupadd",
    desc: "Create a new group",
    examples: [
      { usage: "groupadd pentesters", output: "Create pentesters group" },
      { usage: "groupadd -g 1337 hackers", output: "Create group with specific GID" }
    ],
    category: "users"
  },
  {
    cmd: "groupdel",
    desc: "Delete a group",
    examples: [
      { usage: "groupdel oldteam", output: "Remove the oldteam group" }
    ],
    category: "users"
  },
  {
    cmd: "groups",
    desc: "Print group memberships for a user",
    examples: [
      { usage: "groups root", output: "root : root" },
      { usage: "groups www-data", output: "www-data : www-data" }
    ],
    category: "users"
  },
  {
    cmd: "getent",
    desc: "Get entries from administrative databases",
    examples: [
      { usage: "getent passwd root", output: "root:x:0:0:root:/root:/bin/bash" },
      { usage: "getent group sudo", output: "sudo:x:27:analyst" },
      { usage: "getent hosts example.com", output: "93.184.216.34  example.com" }
    ],
    category: "users"
  },
  {
    cmd: "chage",
    desc: "Change user password aging policy",
    examples: [
      { usage: "chage -l analyst", output: "Show password aging info" },
      { usage: "chage -E 2025-12-31 contractor", output: "Set account expiration date" }
    ],
    category: "users"
  },
  {
    cmd: "su",
    desc: "Switch to another user account",
    examples: [
      { usage: "su - analyst", output: "Switch to analyst with full login shell" },
      { usage: "su -c 'id' www-data", output: "Run single command as www-data" }
    ],
    category: "users"
  },
  {
    cmd: "sudo",
    desc: "Execute command as another user (typically root)",
    examples: [
      { usage: "sudo -l", output: "List allowed sudo commands for current user" },
      { usage: "sudo -l -U analyst", output: "List allowed commands for analyst" },
      { usage: "sudo -u postgres psql", output: "Run psql as postgres user" }
    ],
    category: "users"
  },
  {
    cmd: "visudo",
    desc: "Safely edit the sudoers file",
    examples: [
      { usage: "visudo", output: "Open sudoers in safe editor" },
      { usage: "visudo -c", output: "Check sudoers syntax without editing" }
    ],
    category: "users"
  },
  {
    cmd: "finger",
    desc: "Display user information",
    examples: [
      { usage: "finger root", output: "Login: root  Name: root  Directory: /root  Shell: /bin/bash" },
      { usage: "finger @target.com", output: "Query remote finger service" }
    ],
    category: "users"
  },
  {
    cmd: "pinky",
    desc: "Lightweight finger replacement",
    examples: [
      { usage: "pinky -l root", output: "Long format user info for root" }
    ],
    category: "users"
  },

  // ---- permissions ----
  {
    cmd: "chmod",
    desc: "Change file mode (permissions) bits",
    examples: [
      { usage: "chmod 700 /root/.ssh/", output: "Restrict SSH directory to owner only" },
      { usage: "chmod u+s /usr/local/bin/tool", output: "Set SUID bit" },
      { usage: "chmod -R go-rwx /opt/secrets/", output: "Remove group/other access recursively" }
    ],
    category: "permissions"
  },
  {
    cmd: "chown",
    desc: "Change file ownership",
    examples: [
      { usage: "chown root:root /etc/shadow", output: "Ensure shadow is owned by root" },
      { usage: "chown -R www-data:www-data /var/www/", output: "Set web root ownership" }
    ],
    category: "permissions"
  },
  {
    cmd: "chgrp",
    desc: "Change group ownership of files",
    examples: [
      { usage: "chgrp pentesters /opt/tools/", output: "Set group ownership" },
      { usage: "chgrp -R developers /opt/project/", output: "Recursive group change" }
    ],
    category: "permissions"
  },
  {
    cmd: "umask",
    desc: "Set default file creation permission mask",
    examples: [
      { usage: "umask", output: "0022 (display current mask)" },
      { usage: "umask 077", output: "Restrictive: owner-only for new files" }
    ],
    category: "permissions"
  },
  {
    cmd: "getfacl",
    desc: "Get file access control lists",
    examples: [
      { usage: "getfacl /var/log/auth.log", output: "# file: var/log/auth.log\n# owner: syslog\n# group: adm" },
      { usage: "getfacl -R /opt/secure/", output: "Recursive ACL listing" }
    ],
    category: "permissions"
  },
  {
    cmd: "setfacl",
    desc: "Set file access control lists",
    examples: [
      { usage: "setfacl -m u:analyst:r /var/log/auth.log", output: "Grant analyst read access" },
      { usage: "setfacl -x u:attacker /opt/data/", output: "Remove ACL entry for attacker" }
    ],
    category: "permissions"
  },
  {
    cmd: "chattr",
    desc: "Change file attributes on Linux filesystems",
    examples: [
      { usage: "chattr +i /etc/resolv.conf", output: "Make file immutable (even root cannot modify)" },
      { usage: "chattr +a /var/log/security.log", output: "Append-only (for tamper-proof logging)" }
    ],
    category: "permissions"
  },
  {
    cmd: "lsattr",
    desc: "List file attributes",
    examples: [
      { usage: "lsattr /etc/resolv.conf", output: "----i--------e-- /etc/resolv.conf" },
      { usage: "lsattr -R /etc/", output: "Recursive attribute listing" }
    ],
    category: "permissions"
  },
  {
    cmd: "namei",
    desc: "Follow a pathname to its ultimate destination showing permissions",
    examples: [
      { usage: "namei -l /var/www/html/index.html", output: "Shows permissions along entire path" }
    ],
    category: "permissions"
  },
  {
    cmd: "capabilities",
    desc: "Get or set Linux capabilities on executables",
    examples: [
      { usage: "getcap -r / 2>/dev/null", output: "Find all binaries with capabilities set" },
      { usage: "setcap cap_net_raw+ep /usr/bin/ping", output: "Grant raw socket capability" }
    ],
    category: "permissions"
  },
  {
    cmd: "selinuxenabled",
    desc: "Check if SELinux is enabled",
    examples: [
      { usage: "getenforce", output: "Enforcing | Permissive | Disabled" },
      { usage: "sestatus", output: "Full SELinux status report" }
    ],
    category: "permissions"
  },
  {
    cmd: "aa-status",
    desc: "Display AppArmor status and enforced profiles",
    examples: [
      { usage: "aa-status", output: "apparmor module is loaded.\n15 profiles in enforce mode" },
      { usage: "aa-complain /usr/sbin/nginx", output: "Set nginx profile to complain mode" }
    ],
    category: "permissions"
  },

  // ---- logging ----
  {
    cmd: "journalctl",
    desc: "Query and display systemd journal logs",
    examples: [
      { usage: "journalctl -u sshd --since '1 hour ago'", output: "Recent SSH logs" },
      { usage: "journalctl -p err -b", output: "Error-level messages since last boot" },
      { usage: "journalctl --disk-usage", output: "Show journal disk usage" }
    ],
    category: "logging"
  },
  {
    cmd: "dmesg",
    desc: "Print kernel ring buffer messages",
    examples: [
      { usage: "dmesg -T | tail -50", output: "Recent kernel messages with timestamps" },
      { usage: "dmesg | grep -i 'usb\\|error\\|fail'", output: "Filter for USB/errors" }
    ],
    category: "logging"
  },
  {
    cmd: "logger",
    desc: "Write entries to the system log",
    examples: [
      { usage: "logger -t darknode 'Scan completed successfully'", output: "Log with custom tag" },
      { usage: "logger -p auth.alert 'Unauthorized access detected'", output: "Log security alert" }
    ],
    category: "logging"
  },
  {
    cmd: "logrotate",
    desc: "Rotate, compress, and manage log files",
    examples: [
      { usage: "logrotate -f /etc/logrotate.conf", output: "Force immediate rotation" },
      { usage: "logrotate -d /etc/logrotate.d/nginx", output: "Debug/dry-run for nginx logs" }
    ],
    category: "logging"
  },
  {
    cmd: "ausearch",
    desc: "Search the Linux audit log",
    examples: [
      { usage: "ausearch -k passwd_changes -ts recent", output: "Recent password change events" },
      { usage: "ausearch -ua root -ts today", output: "Root activity since today" },
      { usage: "ausearch -m execve -ts '10 minutes ago'", output: "Recent command executions" }
    ],
    category: "logging"
  },
  {
    cmd: "aureport",
    desc: "Generate reports from audit logs",
    examples: [
      { usage: "aureport --auth", output: "Authentication attempt report" },
      { usage: "aureport --failed --summary", output: "Summary of failed events" },
      { usage: "aureport --login --start today", output: "Login report for today" }
    ],
    category: "logging"
  },
  {
    cmd: "auditctl",
    desc: "Control the Linux audit system",
    examples: [
      { usage: "auditctl -l", output: "List current audit rules" },
      { usage: "auditctl -w /etc/shadow -p wa -k shadow_watch", output: "Watch shadow file changes" },
      { usage: "auditctl -a always,exit -F arch=b64 -S execve -k cmd_exec", output: "Audit all executions" }
    ],
    category: "logging"
  },
  {
    cmd: "syslog",
    desc: "View system logs in traditional syslog format",
    examples: [
      { usage: "cat /var/log/syslog | grep -i error | tail -20", output: "Recent syslog errors" },
      { usage: "cat /var/log/auth.log | grep 'Failed password'", output: "Failed authentication attempts" }
    ],
    category: "logging"
  },
  {
    cmd: "faillog",
    desc: "Display or set login failure limits",
    examples: [
      { usage: "faillog -a", output: "Show all users with failure counts" },
      { usage: "faillog -u analyst -r", output: "Reset failure count for analyst" }
    ],
    category: "logging"
  },
  {
    cmd: "wtmp",
    desc: "Examine login/logout records via utmpdump",
    examples: [
      { usage: "utmpdump /var/log/wtmp", output: "Dump login records in parseable format" },
      { usage: "utmpdump /var/log/btmp", output: "Dump failed login records" }
    ],
    category: "logging"
  },
  {
    cmd: "logwatch",
    desc: "Analyze and report on system logs",
    examples: [
      { usage: "logwatch --detail High --range Today", output: "Detailed report for today" },
      { usage: "logwatch --service sshd --range 'between -7 days and today'", output: "SSH log summary" }
    ],
    category: "logging"
  },
  {
    cmd: "multitail",
    desc: "Monitor multiple log files simultaneously",
    examples: [
      { usage: "multitail /var/log/auth.log /var/log/syslog", output: "Split view of two logs" },
      { usage: "multitail -ci green /var/log/access.log -ci red /var/log/error.log", output: "Color-coded view" }
    ],
    category: "logging"
  },

  // ---- services ----
  {
    cmd: "systemctl",
    desc: "Control the systemd system and service manager",
    examples: [
      { usage: "systemctl list-units --type=service --state=running", output: "All running services" },
      { usage: "systemctl status sshd", output: "SSH daemon status with recent logs" },
      { usage: "systemctl enable --now nginx", output: "Enable and start nginx" },
      { usage: "systemctl list-timers", output: "List all systemd timers" }
    ],
    category: "services"
  },
  {
    cmd: "service",
    desc: "Run System V init scripts (legacy)",
    examples: [
      { usage: "service --status-all", output: "Status of all SysV services" },
      { usage: "service apache2 restart", output: "Restart Apache web server" }
    ],
    category: "services"
  },
  {
    cmd: "chkconfig",
    desc: "Manage SysV service run levels (RHEL/CentOS)",
    examples: [
      { usage: "chkconfig --list", output: "List services and run levels" },
      { usage: "chkconfig httpd on", output: "Enable httpd at boot" }
    ],
    category: "services"
  },
  {
    cmd: "update-rc.d",
    desc: "Manage SysV service links (Debian/Ubuntu)",
    examples: [
      { usage: "update-rc.d ssh defaults", output: "Enable SSH at boot" },
      { usage: "update-rc.d -f apache2 remove", output: "Remove Apache from boot" }
    ],
    category: "services"
  },
  {
    cmd: "timedatectl",
    desc: "Control the system date and time",
    examples: [
      { usage: "timedatectl status", output: "Show current time and NTP status" },
      { usage: "timedatectl set-ntp true", output: "Enable NTP synchronization" }
    ],
    category: "services"
  },
  {
    cmd: "hostnamectl",
    desc: "Control the system hostname",
    examples: [
      { usage: "hostnamectl", output: "Static hostname: darknode-01" },
      { usage: "hostnamectl set-hostname darknode-02", output: "Change hostname" }
    ],
    category: "services"
  },
  {
    cmd: "loginctl",
    desc: "Control the systemd login manager",
    examples: [
      { usage: "loginctl list-sessions", output: "List active login sessions" },
      { usage: "loginctl show-session 3", output: "Details of session 3" },
      { usage: "loginctl terminate-user attacker", output: "Kill all sessions for user" }
    ],
    category: "services"
  },
  {
    cmd: "resolvconf",
    desc: "Manage DNS resolver configuration",
    examples: [
      { usage: "resolvconf -u", output: "Update resolv.conf" },
      { usage: "cat /etc/resolv.conf", output: "nameserver 8.8.8.8" }
    ],
    category: "services"
  },
  {
    cmd: "ufw",
    desc: "Uncomplicated Firewall management interface",
    examples: [
      { usage: "ufw status verbose", output: "Show firewall status with rules" },
      { usage: "ufw allow from 192.168.1.0/24 to any port 22", output: "Allow SSH from LAN" },
      { usage: "ufw deny from 10.0.0.5", output: "Block specific IP" }
    ],
    category: "services"
  },
  {
    cmd: "firewalld",
    desc: "Dynamic firewall daemon control (RHEL/CentOS)",
    examples: [
      { usage: "firewall-cmd --list-all", output: "Show all firewall rules" },
      { usage: "firewall-cmd --add-port=8080/tcp --permanent", output: "Open port 8080" }
    ],
    category: "services"
  },
  {
    cmd: "fail2ban-client",
    desc: "Control the fail2ban intrusion prevention system",
    examples: [
      { usage: "fail2ban-client status sshd", output: "Show SSH jail status with banned IPs" },
      { usage: "fail2ban-client set sshd banip 10.0.0.5", output: "Manually ban an IP" },
      { usage: "fail2ban-client set sshd unbanip 10.0.0.5", output: "Unban an IP" }
    ],
    category: "services"
  },
  {
    cmd: "snap",
    desc: "Manage snap packages",
    examples: [
      { usage: "snap list", output: "List installed snaps" },
      { usage: "snap install nmap", output: "Install nmap via snap" }
    ],
    category: "services"
  },
  {
    cmd: "apt",
    desc: "Debian/Ubuntu package manager",
    examples: [
      { usage: "apt list --installed", output: "List all installed packages" },
      { usage: "apt-cache policy openssh-server", output: "Show package versions and repos" },
      { usage: "apt update && apt upgrade -y", output: "Update and upgrade all packages" }
    ],
    category: "services"
  },
  {
    cmd: "yum",
    desc: "RHEL/CentOS package manager",
    examples: [
      { usage: "yum list installed", output: "List installed packages" },
      { usage: "yum check-update", output: "Check for available updates" }
    ],
    category: "services"
  },
  {
    cmd: "dpkg",
    desc: "Debian package manager (low-level)",
    examples: [
      { usage: "dpkg -l | grep openssh", output: "Check if openssh is installed" },
      { usage: "dpkg -V", output: "Verify installed packages integrity" }
    ],
    category: "services"
  },
  {
    cmd: "rpm",
    desc: "RPM package manager (low-level)",
    examples: [
      { usage: "rpm -qa | grep ssh", output: "List installed SSH packages" },
      { usage: "rpm -Va", output: "Verify all installed RPMs" }
    ],
    category: "services"
  },
  {
    cmd: "nginx",
    desc: "High-performance HTTP server and reverse proxy",
    examples: [
      { usage: "nginx -t", output: "Test configuration syntax" },
      { usage: "nginx -T", output: "Test and dump full configuration" }
    ],
    category: "services"
  },

  // ---- kernel ----
  {
    cmd: "uname",
    desc: "Print system and kernel information",
    examples: [
      { usage: "uname -a", output: "Linux darknode 5.15.0 #1 SMP x86_64 GNU/Linux" },
      { usage: "uname -r", output: "5.15.0-generic (kernel version only)" }
    ],
    category: "kernel"
  },
  {
    cmd: "sysctl",
    desc: "Configure kernel parameters at runtime",
    examples: [
      { usage: "sysctl -a | grep ip_forward", output: "net.ipv4.ip_forward = 0" },
      { usage: "sysctl -w net.ipv4.ip_forward=1", output: "Enable IP forwarding" },
      { usage: "sysctl -w kernel.randomize_va_space=2", output: "Enable full ASLR" }
    ],
    category: "kernel"
  },
  {
    cmd: "lsmod",
    desc: "Show loaded kernel modules",
    examples: [
      { usage: "lsmod", output: "Module     Size  Used by\nnf_tables  262144  ..." },
      { usage: "lsmod | grep -i usb", output: "Filter for USB modules" }
    ],
    category: "kernel"
  },
  {
    cmd: "modprobe",
    desc: "Add or remove modules from the Linux kernel",
    examples: [
      { usage: "modprobe -r usb_storage", output: "Remove USB storage module" },
      { usage: "modprobe nf_conntrack", output: "Load connection tracking module" }
    ],
    category: "kernel"
  },
  {
    cmd: "modinfo",
    desc: "Show information about a kernel module",
    examples: [
      { usage: "modinfo nf_tables", output: "Filename, description, author, license, etc." },
      { usage: "modinfo -p iwlwifi", output: "Show module parameters" }
    ],
    category: "kernel"
  },
  {
    cmd: "insmod",
    desc: "Insert a module into the Linux kernel (low-level)",
    examples: [
      { usage: "insmod /lib/modules/5.15.0/kernel/net/bridge/bridge.ko", output: "Load bridge module" }
    ],
    category: "kernel"
  },
  {
    cmd: "rmmod",
    desc: "Remove a module from the Linux kernel (low-level)",
    examples: [
      { usage: "rmmod bridge", output: "Unload bridge module" },
      { usage: "rmmod -f suspicious_module", output: "Force removal of suspicious module" }
    ],
    category: "kernel"
  },
  {
    cmd: "lspci",
    desc: "List all PCI devices",
    examples: [
      { usage: "lspci -vv", output: "Verbose PCI device listing" },
      { usage: "lspci | grep -i net", output: "Find network controllers" }
    ],
    category: "kernel"
  },
  {
    cmd: "lsusb",
    desc: "List USB devices",
    examples: [
      { usage: "lsusb -v", output: "Verbose USB device listing" },
      { usage: "lsusb -t", output: "USB device tree" }
    ],
    category: "kernel"
  },
  {
    cmd: "lscpu",
    desc: "Display CPU architecture information",
    examples: [
      { usage: "lscpu", output: "Architecture, cores, threads, cache info" },
      { usage: "lscpu | grep -i vuln", output: "Show CPU vulnerability mitigations" }
    ],
    category: "kernel"
  },
  {
    cmd: "lsblk",
    desc: "List block devices",
    examples: [
      { usage: "lsblk -f", output: "Show filesystems and UUIDs" },
      { usage: "lsblk -o NAME,SIZE,TYPE,MOUNTPOINT", output: "Custom column output" }
    ],
    category: "kernel"
  },
  {
    cmd: "dmidecode",
    desc: "DMI/SMBIOS hardware information",
    examples: [
      { usage: "dmidecode -t bios", output: "BIOS version and vendor info" },
      { usage: "dmidecode -t system", output: "System manufacturer and serial" }
    ],
    category: "kernel"
  },
  {
    cmd: "free",
    desc: "Display memory usage statistics",
    examples: [
      { usage: "free -h", output: "Human-readable memory info" },
      { usage: "free -s 5", output: "Continuous display every 5 seconds" }
    ],
    category: "kernel"
  },
  {
    cmd: "vmstat",
    desc: "Report virtual memory statistics",
    examples: [
      { usage: "vmstat 1 10", output: "Report every 1s for 10 iterations" },
      { usage: "vmstat -s", output: "Summary of memory statistics" }
    ],
    category: "kernel"
  },
  {
    cmd: "iostat",
    desc: "Report CPU and I/O statistics",
    examples: [
      { usage: "iostat -xz 1", output: "Extended I/O stats every second" },
      { usage: "iostat -d sda", output: "Disk statistics for sda" }
    ],
    category: "kernel"
  },
  {
    cmd: "uptime",
    desc: "Show system uptime and load averages",
    examples: [
      { usage: "uptime", output: "14:23:05 up 45 days, 2:15, 3 users, load average: 0.15, 0.20, 0.18" },
      { usage: "uptime -s", output: "2025-07-25 12:08:00 (boot time)" }
    ],
    category: "kernel"
  },
  {
    cmd: "sar",
    desc: "Collect and report system activity information",
    examples: [
      { usage: "sar -n DEV 1 5", output: "Network device stats for 5 seconds" },
      { usage: "sar -u 1 10", output: "CPU utilization every second, 10 times" }
    ],
    category: "kernel"
  },
  {
    cmd: "perf",
    desc: "Performance profiling and tracing tool",
    examples: [
      { usage: "perf top", output: "Real-time function profiling" },
      { usage: "perf stat -p 1234", output: "Performance counters for PID" }
    ],
    category: "kernel"
  },
  {
    cmd: "bpftrace",
    desc: "High-level tracing language for Linux eBPF",
    examples: [
      { usage: "bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf(\"%s %s\\n\", comm, str(args->filename)); }'", output: "Trace file opens by process" },
      { usage: "bpftrace -e 'tracepoint:syscalls:sys_enter_connect { printf(\"%s\\n\", comm); }'", output: "Trace network connects" }
    ],
    category: "kernel"
  },

  // ---- containers ----
  {
    cmd: "docker",
    desc: "Container management platform",
    examples: [
      { usage: "docker ps -a", output: "List all containers including stopped" },
      { usage: "docker images", output: "List all local images" },
      { usage: "docker inspect <container>", output: "Detailed container metadata as JSON" },
      { usage: "docker logs -f <container>", output: "Follow container logs" },
      { usage: "docker exec -it <container> /bin/bash", output: "Interactive shell in container" }
    ],
    category: "containers"
  },
  {
    cmd: "docker-compose",
    desc: "Define and run multi-container Docker applications",
    examples: [
      { usage: "docker-compose up -d", output: "Start services in detached mode" },
      { usage: "docker-compose ps", output: "List compose project containers" },
      { usage: "docker-compose logs -f", output: "Follow all service logs" }
    ],
    category: "containers"
  },
  {
    cmd: "docker network",
    desc: "Manage Docker networks",
    examples: [
      { usage: "docker network ls", output: "List all Docker networks" },
      { usage: "docker network inspect bridge", output: "Inspect default bridge network" },
      { usage: "docker network create --driver bridge isolated", output: "Create isolated network" }
    ],
    category: "containers"
  },
  {
    cmd: "docker volume",
    desc: "Manage Docker volumes",
    examples: [
      { usage: "docker volume ls", output: "List all volumes" },
      { usage: "docker volume inspect data_vol", output: "Inspect volume metadata" }
    ],
    category: "containers"
  },
  {
    cmd: "docker build",
    desc: "Build Docker images from Dockerfile",
    examples: [
      { usage: "docker build -t myapp:latest .", output: "Build image from current directory" },
      { usage: "docker build --no-cache -t scanner .", output: "Build without layer caching" }
    ],
    category: "containers"
  },
  {
    cmd: "docker save",
    desc: "Save Docker image to tar archive",
    examples: [
      { usage: "docker save -o evidence.tar suspicious_image", output: "Export image for forensics" },
      { usage: "docker load -i evidence.tar", output: "Import saved image" }
    ],
    category: "containers"
  },
  {
    cmd: "docker export",
    desc: "Export container filesystem as tar archive",
    examples: [
      { usage: "docker export container_id > container_fs.tar", output: "Export container filesystem" },
      { usage: "docker import container_fs.tar analysis:latest", output: "Import as new image" }
    ],
    category: "containers"
  },
  {
    cmd: "docker history",
    desc: "Show the history of an image",
    examples: [
      { usage: "docker history --no-trunc myimage", output: "Full layer history" }
    ],
    category: "containers"
  },
  {
    cmd: "docker stats",
    desc: "Display live container resource usage statistics",
    examples: [
      { usage: "docker stats --no-stream", output: "One-shot resource snapshot" },
      { usage: "docker stats <container>", output: "Live stats for specific container" }
    ],
    category: "containers"
  },
  {
    cmd: "docker top",
    desc: "Display running processes within a container",
    examples: [
      { usage: "docker top <container>", output: "Process list inside container" }
    ],
    category: "containers"
  },
  {
    cmd: "docker diff",
    desc: "Inspect changes to files or directories on a container filesystem",
    examples: [
      { usage: "docker diff <container>", output: "C /etc\nA /tmp/backdoor.sh" }
    ],
    category: "containers"
  },
  {
    cmd: "docker scan",
    desc: "Scan Docker images for vulnerabilities",
    examples: [
      { usage: "docker scan myapp:latest", output: "Vulnerability report for image" }
    ],
    category: "containers"
  },
  {
    cmd: "kubectl",
    desc: "Kubernetes cluster management tool",
    examples: [
      { usage: "kubectl get pods -A", output: "List all pods across namespaces" },
      { usage: "kubectl get secrets -n default", output: "List secrets in default namespace" },
      { usage: "kubectl describe pod <pod>", output: "Detailed pod information" },
      { usage: "kubectl logs -f <pod>", output: "Follow pod logs" }
    ],
    category: "containers"
  },
  {
    cmd: "kubectl exec",
    desc: "Execute commands in Kubernetes containers",
    examples: [
      { usage: "kubectl exec -it <pod> -- /bin/bash", output: "Interactive shell in pod" },
      { usage: "kubectl exec <pod> -- cat /etc/passwd", output: "Read file in pod" }
    ],
    category: "containers"
  },
  {
    cmd: "kubectl auth",
    desc: "Inspect Kubernetes authorization",
    examples: [
      { usage: "kubectl auth can-i --list", output: "List all permissions for current user" },
      { usage: "kubectl auth can-i create pods", output: "Check if you can create pods" }
    ],
    category: "containers"
  },
  {
    cmd: "crictl",
    desc: "CLI for CRI-compatible container runtimes",
    examples: [
      { usage: "crictl ps", output: "List running containers" },
      { usage: "crictl inspect <container_id>", output: "Inspect container details" }
    ],
    category: "containers"
  },
  {
    cmd: "podman",
    desc: "Daemonless container engine (Docker-compatible)",
    examples: [
      { usage: "podman ps -a", output: "List all containers" },
      { usage: "podman run -it --rm alpine sh", output: "Run interactive alpine container" }
    ],
    category: "containers"
  },
  {
    cmd: "nsenter",
    desc: "Enter Linux namespaces of another process",
    examples: [
      { usage: "nsenter -t <pid> -n ip addr", output: "Run ip addr in target net namespace" },
      { usage: "nsenter -t <pid> -m -u -i -n -p -- /bin/bash", output: "Enter all namespaces" }
    ],
    category: "containers"
  },
  {
    cmd: "unshare",
    desc: "Run a program in new namespaces",
    examples: [
      { usage: "unshare -n /bin/bash", output: "Shell with isolated network namespace" },
      { usage: "unshare --mount --pid --fork /bin/bash", output: "Isolated mount and PID" }
    ],
    category: "containers"
  },
  {
    cmd: "ctr",
    desc: "Containerd CLI for managing containers and images",
    examples: [
      { usage: "ctr images ls", output: "List containerd images" },
      { usage: "ctr containers ls", output: "List containerd containers" }
    ],
    category: "containers"
  },
  {
    cmd: "helm",
    desc: "Kubernetes package manager",
    examples: [
      { usage: "helm list -A", output: "List all Helm releases across namespaces" },
      { usage: "helm get values <release>", output: "Show deployed values" }
    ],
    category: "containers"
  },

  // ---- crypto ----
  {
    cmd: "gpg",
    desc: "GNU Privacy Guard for encryption and signing",
    examples: [
      { usage: "gpg --list-keys", output: "List all public keys in keyring" },
      { usage: "gpg -c sensitive.txt", output: "Symmetric encrypt a file" },
      { usage: "gpg --verify file.sig file.tar.gz", output: "Verify detached signature" },
      { usage: "gpg -d encrypted.gpg > decrypted.txt", output: "Decrypt a file" }
    ],
    category: "crypto"
  },
  {
    cmd: "openssl-enc",
    desc: "OpenSSL symmetric cipher encryption",
    examples: [
      { usage: "openssl enc -aes-256-cbc -salt -in plain.txt -out encrypted.bin", output: "AES-256 encrypt" },
      { usage: "openssl enc -d -aes-256-cbc -in encrypted.bin -out plain.txt", output: "Decrypt" }
    ],
    category: "crypto"
  },
  {
    cmd: "openssl-dgst",
    desc: "OpenSSL message digest and signing",
    examples: [
      { usage: "openssl dgst -sha256 file.bin", output: "SHA256(file.bin)= a1b2c3..." },
      { usage: "openssl dgst -sha256 -sign key.pem -out sig.bin file.bin", output: "Sign with private key" }
    ],
    category: "crypto"
  },
  {
    cmd: "openssl-rsa",
    desc: "OpenSSL RSA key management",
    examples: [
      { usage: "openssl genrsa -out private.pem 4096", output: "Generate 4096-bit RSA key" },
      { usage: "openssl rsa -in private.pem -pubout -out public.pem", output: "Extract public key" }
    ],
    category: "crypto"
  },
  {
    cmd: "ssh-keygen",
    desc: "Generate, manage, and convert SSH keys",
    examples: [
      { usage: "ssh-keygen -t ed25519 -C 'analyst@darknode'", output: "Generate Ed25519 key" },
      { usage: "ssh-keygen -lf /etc/ssh/ssh_host_rsa_key.pub", output: "Show key fingerprint" },
      { usage: "ssh-keygen -R target.com", output: "Remove known_hosts entry" }
    ],
    category: "crypto"
  },
  {
    cmd: "ssh-agent",
    desc: "Authentication agent for SSH keys",
    examples: [
      { usage: "eval $(ssh-agent -s)", output: "Start SSH agent" },
      { usage: "ssh-add ~/.ssh/id_ed25519", output: "Add key to agent" },
      { usage: "ssh-add -l", output: "List loaded keys" }
    ],
    category: "crypto"
  },
  {
    cmd: "age",
    desc: "Modern file encryption tool (age-encryption.org)",
    examples: [
      { usage: "age -r age1publickey... -o secret.age secret.txt", output: "Encrypt with public key" },
      { usage: "age -d -i key.txt secret.age > secret.txt", output: "Decrypt with private key" }
    ],
    category: "crypto"
  },
  {
    cmd: "certbot",
    desc: "Let's Encrypt certificate management",
    examples: [
      { usage: "certbot certonly --standalone -d example.com", output: "Obtain standalone TLS cert" },
      { usage: "certbot renew --dry-run", output: "Test certificate renewal" }
    ],
    category: "crypto"
  },
  {
    cmd: "hashcat",
    desc: "Advanced password recovery and hash cracking",
    examples: [
      { usage: "hashcat -m 0 hashes.txt wordlist.txt", output: "MD5 dictionary attack" },
      { usage: "hashcat -m 1800 shadow.hashes rockyou.txt", output: "SHA-512crypt from /etc/shadow" },
      { usage: "hashcat --show hashes.txt", output: "Display cracked passwords" }
    ],
    category: "crypto"
  },
  {
    cmd: "john",
    desc: "John the Ripper password cracker",
    examples: [
      { usage: "john --wordlist=rockyou.txt hashes.txt", output: "Dictionary attack" },
      { usage: "john --show hashes.txt", output: "Show cracked passwords" },
      { usage: "john --format=raw-sha256 hashes.txt", output: "Crack SHA-256 hashes" }
    ],
    category: "crypto"
  },
  {
    cmd: "hydra",
    desc: "Network login cracker supporting many protocols",
    examples: [
      { usage: "hydra -l admin -P wordlist.txt ssh://192.168.1.1", output: "SSH brute force" },
      { usage: "hydra -L users.txt -P passes.txt ftp://target", output: "FTP credential spray" }
    ],
    category: "crypto"
  },
  {
    cmd: "medusa",
    desc: "Parallel network login auditor",
    examples: [
      { usage: "medusa -h target -u admin -P wordlist.txt -M ssh", output: "SSH brute force" },
      { usage: "medusa -H hosts.txt -u root -P passes.txt -M mysql", output: "MySQL audit" }
    ],
    category: "crypto"
  },
  {
    cmd: "steghide",
    desc: "Steganography tool for hiding data in images/audio",
    examples: [
      { usage: "steghide embed -cf image.jpg -ef secret.txt", output: "Hide text in image" },
      { usage: "steghide extract -sf image.jpg", output: "Extract hidden data" }
    ],
    category: "crypto"
  },
  {
    cmd: "binwalk",
    desc: "Firmware analysis and extraction tool",
    examples: [
      { usage: "binwalk firmware.bin", output: "Scan for embedded files and signatures" },
      { usage: "binwalk -e firmware.bin", output: "Extract embedded content" }
    ],
    category: "crypto"
  },
  {
    cmd: "veracrypt",
    desc: "Disk encryption software",
    examples: [
      { usage: "veracrypt -t -c /dev/sdb1", output: "Create encrypted volume (text mode)" },
      { usage: "veracrypt -t /dev/sdb1 /mnt/encrypted", output: "Mount encrypted volume" }
    ],
    category: "crypto"
  },
  {
    cmd: "cryptsetup",
    desc: "LUKS disk encryption management",
    examples: [
      { usage: "cryptsetup luksFormat /dev/sdb1", output: "Initialize LUKS partition" },
      { usage: "cryptsetup open /dev/sdb1 secure_vol", output: "Open/unlock LUKS volume" },
      { usage: "cryptsetup luksDump /dev/sdb1", output: "Show LUKS header information" }
    ],
    category: "crypto"
  },
  {
    cmd: "ccrypt",
    desc: "Encrypt and decrypt files using Rijndael cipher",
    examples: [
      { usage: "ccrypt sensitive.txt", output: "Encrypt file (prompts for passphrase)" },
      { usage: "ccdecrypt sensitive.txt.cpt", output: "Decrypt file" }
    ],
    category: "crypto"
  },
  {
    cmd: "shred",
    desc: "Securely overwrite file data before deletion",
    examples: [
      { usage: "shred -vfz -n 5 sensitive.txt", output: "5-pass overwrite then zero-fill" },
      { usage: "shred -u sensitive.txt", output: "Overwrite and delete file" }
    ],
    category: "crypto"
  },
  {
    cmd: "wipe",
    desc: "Securely erase files from magnetic media",
    examples: [
      { usage: "wipe -rfi /tmp/sensitive/", output: "Recursive force wipe directory" }
    ],
    category: "crypto"
  },
  {
    cmd: "srm",
    desc: "Secure remove with overwrite passes",
    examples: [
      { usage: "srm -sz evidence.txt", output: "Simple zero-fill removal" }
    ],
    category: "crypto"
  }
];


// ---------------------------------------------------------------------------
// Windows Commands
// ---------------------------------------------------------------------------

const WINDOWS_COMMANDS = [
  // ---- reconnaissance ----
  {
    cmd: "systeminfo",
    desc: "Display detailed system configuration including hotfixes",
    examples: [
      { usage: "systeminfo", output: "OS Name, Version, Hotfixes, Network Cards" },
      { usage: "systeminfo | findstr /B /C:\"OS\"", output: "Filter OS-related lines" }
    ],
    category: "reconnaissance"
  },
  {
    cmd: "hostname",
    desc: "Display the computer name",
    examples: [
      { usage: "hostname", output: "WORKSTATION01" }
    ],
    category: "reconnaissance"
  },
  {
    cmd: "whoami",
    desc: "Display current user and privilege information",
    examples: [
      { usage: "whoami /all", output: "User SID, group memberships, and privileges" },
      { usage: "whoami /priv", output: "List all privileges and their status" }
    ],
    category: "reconnaissance"
  },
  {
    cmd: "net user",
    desc: "Manage user accounts",
    examples: [
      { usage: "net user", output: "List all local user accounts" },
      { usage: "net user administrator", output: "Detailed info for administrator" },
      { usage: "net user /domain", output: "List domain user accounts" }
    ],
    category: "reconnaissance"
  },
  {
    cmd: "net group",
    desc: "Manage domain groups",
    examples: [
      { usage: "net group /domain", output: "List all domain groups" },
      { usage: "net group \"Domain Admins\" /domain", output: "List Domain Admin members" }
    ],
    category: "reconnaissance"
  },
  {
    cmd: "net localgroup",
    desc: "Manage local groups",
    examples: [
      { usage: "net localgroup", output: "List all local groups" },
      { usage: "net localgroup Administrators", output: "Members of Administrators group" }
    ],
    category: "reconnaissance"
  },
  {
    cmd: "net share",
    desc: "Display or manage shared resources",
    examples: [
      { usage: "net share", output: "List all shared resources" },
      { usage: "net view \\\\server", output: "List shared resources on remote server" }
    ],
    category: "reconnaissance"
  },
  {
    cmd: "net session",
    desc: "Display current sessions to the machine",
    examples: [
      { usage: "net session", output: "List active SMB sessions" }
    ],
    category: "reconnaissance"
  },
  {
    cmd: "net use",
    desc: "Connect or disconnect from shared resources",
    examples: [
      { usage: "net use", output: "Show current connections" },
      { usage: "net use Z: \\\\server\\share", output: "Map network drive" }
    ],
    category: "reconnaissance"
  },
  {
    cmd: "qwinsta",
    desc: "Display information about Remote Desktop sessions",
    examples: [
      { usage: "qwinsta", output: "SESSIONNAME  USERNAME  ID  STATE" },
      { usage: "qwinsta /server:target", output: "Remote RDP sessions" }
    ],
    category: "reconnaissance"
  },
  {
    cmd: "klist",
    desc: "Display cached Kerberos tickets",
    examples: [
      { usage: "klist", output: "Current LogonId, cached tickets" },
      { usage: "klist sessions", output: "List all logon sessions" }
    ],
    category: "reconnaissance"
  },
  {
    cmd: "nltest",
    desc: "Network diagnostics for domain trust relationships",
    examples: [
      { usage: "nltest /dclist:domain.com", output: "List domain controllers" },
      { usage: "nltest /domain_trusts", output: "Show all trust relationships" }
    ],
    category: "reconnaissance"
  },
  {
    cmd: "dsquery",
    desc: "Query Active Directory for objects",
    examples: [
      { usage: "dsquery user -name *admin*", output: "Find users with admin in name" },
      { usage: "dsquery computer -stalepwd 90", output: "Computers with stale passwords" }
    ],
    category: "reconnaissance"
  },
  {
    cmd: "gpresult",
    desc: "Display Resultant Set of Policy for user/computer",
    examples: [
      { usage: "gpresult /r", output: "Summary of applied group policies" },
      { usage: "gpresult /h gpreport.html", output: "HTML report of GPO" }
    ],
    category: "reconnaissance"
  },
  {
    cmd: "wmic",
    desc: "Windows Management Instrumentation command-line",
    examples: [
      { usage: "wmic process list brief", output: "Brief process listing" },
      { usage: "wmic service get name,startmode,state", output: "Service status listing" },
      { usage: "wmic qfe list brief", output: "List installed hotfixes" },
      { usage: "wmic startup list full", output: "Startup programs with details" }
    ],
    category: "reconnaissance"
  },
  {
    cmd: "reg query",
    desc: "Query Windows registry keys and values",
    examples: [
      { usage: "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", output: "Startup programs" },
      { usage: "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services", output: "Registered services" }
    ],
    category: "reconnaissance"
  },

  // ---- networking ----
  {
    cmd: "ipconfig",
    desc: "Display IP configuration for all adapters",
    examples: [
      { usage: "ipconfig /all", output: "Full TCP/IP configuration" },
      { usage: "ipconfig /displaydns", output: "Display DNS resolver cache" },
      { usage: "ipconfig /flushdns", output: "Flush DNS cache" }
    ],
    category: "networking"
  },
  {
    cmd: "netstat",
    desc: "Display active connections and listening ports",
    examples: [
      { usage: "netstat -ano", output: "All connections with PIDs" },
      { usage: "netstat -anob", output: "With owning process names (admin)" },
      { usage: "netstat -r", output: "Display routing table" }
    ],
    category: "networking"
  },
  {
    cmd: "nslookup",
    desc: "DNS name resolution utility",
    examples: [
      { usage: "nslookup example.com", output: "Default DNS lookup" },
      { usage: "nslookup -type=MX example.com 8.8.8.8", output: "MX records via Google DNS" }
    ],
    category: "networking"
  },
  {
    cmd: "ping",
    desc: "Test connectivity using ICMP echo",
    examples: [
      { usage: "ping -n 4 192.168.1.1", output: "Send 4 ICMP echo requests" },
      { usage: "ping -t 10.0.0.1", output: "Continuous ping until stopped" }
    ],
    category: "networking"
  },
  {
    cmd: "tracert",
    desc: "Trace route to destination",
    examples: [
      { usage: "tracert -d 8.8.8.8", output: "Trace without DNS resolution" },
      { usage: "tracert -h 30 target.com", output: "Trace with max 30 hops" }
    ],
    category: "networking"
  },
  {
    cmd: "pathping",
    desc: "Combination of ping and tracert with statistics",
    examples: [
      { usage: "pathping -n 8.8.8.8", output: "Path analysis with per-hop loss stats" }
    ],
    category: "networking"
  },
  {
    cmd: "arp",
    desc: "Display and modify the ARP cache",
    examples: [
      { usage: "arp -a", output: "Display all ARP entries" },
      { usage: "arp -d *", output: "Clear entire ARP cache" }
    ],
    category: "networking"
  },
  {
    cmd: "route",
    desc: "Display or modify the routing table",
    examples: [
      { usage: "route print", output: "Display full routing table" },
      { usage: "route add 10.0.0.0 mask 255.0.0.0 192.168.1.1", output: "Add static route" }
    ],
    category: "networking"
  },
  {
    cmd: "netsh",
    desc: "Network configuration scripting utility",
    examples: [
      { usage: "netsh advfirewall show allprofiles", output: "Show firewall status" },
      { usage: "netsh wlan show profiles", output: "List saved WiFi profiles" },
      { usage: "netsh wlan show profile name=\"WiFiName\" key=clear", output: "Show WiFi password" },
      { usage: "netsh advfirewall firewall add rule name=\"Block\" dir=in action=block remoteip=10.0.0.5", output: "Block IP" }
    ],
    category: "networking"
  },
  {
    cmd: "nbtstat",
    desc: "NetBIOS statistics and name resolution",
    examples: [
      { usage: "nbtstat -A 192.168.1.1", output: "NetBIOS name table for remote IP" },
      { usage: "nbtstat -n", output: "Local NetBIOS names" }
    ],
    category: "networking"
  },
  {
    cmd: "Test-NetConnection",
    desc: "PowerShell network connectivity and port testing",
    examples: [
      { usage: "Test-NetConnection -ComputerName server -Port 443", output: "TCP port test" },
      { usage: "Test-NetConnection -ComputerName 8.8.8.8 -TraceRoute", output: "Traceroute" }
    ],
    category: "networking"
  },

  // ---- processes ----
  {
    cmd: "tasklist",
    desc: "Display list of running processes",
    examples: [
      { usage: "tasklist /v", output: "Verbose process list with status" },
      { usage: "tasklist /svc", output: "Processes with associated services" },
      { usage: "tasklist /fi \"USERNAME ne NT AUTHORITY\\SYSTEM\"", output: "Non-system processes" }
    ],
    category: "processes"
  },
  {
    cmd: "taskkill",
    desc: "Terminate processes by PID or image name",
    examples: [
      { usage: "taskkill /PID 1234 /F", output: "Force-kill process by PID" },
      { usage: "taskkill /IM malware.exe /F /T", output: "Kill process and child tree" }
    ],
    category: "processes"
  },
  {
    cmd: "wmic process",
    desc: "WMI process management and querying",
    examples: [
      { usage: "wmic process where name=\"cmd.exe\" get processid,commandline", output: "CMD instances" },
      { usage: "wmic process get name,processid,parentprocessid /format:csv", output: "CSV output" }
    ],
    category: "processes"
  },
  {
    cmd: "sc",
    desc: "Service Control manager command",
    examples: [
      { usage: "sc query type= service state= all", output: "List all services" },
      { usage: "sc qc sshd", output: "Query service configuration" },
      { usage: "sc queryex eventlog", output: "Extended status for Event Log" }
    ],
    category: "processes"
  },
  {
    cmd: "schtasks",
    desc: "Create, delete, query, and manage scheduled tasks",
    examples: [
      { usage: "schtasks /query /fo TABLE /v", output: "Verbose scheduled task list" },
      { usage: "schtasks /query /tn \"\\Microsoft\\Windows\\\" /fo LIST", output: "System tasks" }
    ],
    category: "processes"
  },

  // ---- filesystem ----
  {
    cmd: "dir",
    desc: "List directory contents",
    examples: [
      { usage: "dir /a /s C:\\Users\\", output: "Recursive listing including hidden files" },
      { usage: "dir /a:h C:\\", output: "List hidden files at root" }
    ],
    category: "filesystem"
  },
  {
    cmd: "attrib",
    desc: "Display or change file attributes",
    examples: [
      { usage: "attrib +h +s +r secret.txt", output: "Set hidden, system, read-only" },
      { usage: "attrib -h -s C:\\Users\\*.*  /S /D", output: "Reveal hidden files recursively" }
    ],
    category: "filesystem"
  },
  {
    cmd: "icacls",
    desc: "Display or modify file access control lists",
    examples: [
      { usage: "icacls C:\\sensitive\\", output: "Display ACLs for directory" },
      { usage: "icacls C:\\data /grant analyst:(OI)(CI)R", output: "Grant read access recursively" },
      { usage: "icacls C:\\data /remove attacker", output: "Remove user permissions" }
    ],
    category: "filesystem"
  },
  {
    cmd: "takeown",
    desc: "Take ownership of files or directories",
    examples: [
      { usage: "takeown /f C:\\locked_file.txt", output: "Take ownership of file" },
      { usage: "takeown /f C:\\locked\\ /r /d y", output: "Recursive ownership" }
    ],
    category: "filesystem"
  },
  {
    cmd: "robocopy",
    desc: "Robust file copy with advanced options",
    examples: [
      { usage: "robocopy C:\\source D:\\backup /MIR /LOG:copy.log", output: "Mirror with logging" },
      { usage: "robocopy C:\\evidence \\\\forensics\\share /E /COPYALL /R:0", output: "Copy with all attributes" }
    ],
    category: "filesystem"
  },
  {
    cmd: "xcopy",
    desc: "Extended copy command for files and directories",
    examples: [
      { usage: "xcopy C:\\data D:\\backup /E /H /K", output: "Copy including hidden and attributes" }
    ],
    category: "filesystem"
  },
  {
    cmd: "cipher",
    desc: "Display or alter encryption of directories/files on NTFS",
    examples: [
      { usage: "cipher /c C:\\Users\\", output: "Display encryption state" },
      { usage: "cipher /w:C:\\sensitive\\", output: "Wipe deleted file remnants" }
    ],
    category: "filesystem"
  },
  {
    cmd: "fsutil",
    desc: "File system utility for advanced operations",
    examples: [
      { usage: "fsutil usn queryjournal C:", output: "Query USN change journal" },
      { usage: "fsutil fsinfo drives", output: "List all drives" }
    ],
    category: "filesystem"
  },
  {
    cmd: "compact",
    desc: "Display or alter file compression on NTFS",
    examples: [
      { usage: "compact /c /s:C:\\logs\\", output: "Compress log directory" },
      { usage: "compact /q C:\\", output: "Query compression ratio" }
    ],
    category: "filesystem"
  },
  {
    cmd: "findstr",
    desc: "Search for strings in files (like grep)",
    examples: [
      { usage: "findstr /s /i \"password\" C:\\Users\\*.txt", output: "Search for password in text files" },
      { usage: "findstr /r /c:\"[0-9][0-9]*\\.[0-9]\" *.log", output: "Regex search in logs" }
    ],
    category: "filesystem"
  },
  {
    cmd: "where",
    desc: "Locate executables in PATH (like which)",
    examples: [
      { usage: "where cmd.exe", output: "C:\\Windows\\System32\\cmd.exe" },
      { usage: "where /r C:\\ *.exe", output: "Recursive search for executables" }
    ],
    category: "filesystem"
  },
  {
    cmd: "forfiles",
    desc: "Select files based on date for batch processing",
    examples: [
      { usage: "forfiles /p C:\\logs /s /d -30 /c \"cmd /c del @path\"", output: "Delete files older than 30 days" },
      { usage: "forfiles /p C:\\ /s /m *.exe /d +01/01/2025 /c \"cmd /c echo @path\"", output: "Find new executables" }
    ],
    category: "filesystem"
  },

  // ---- security ----
  {
    cmd: "wevtutil",
    desc: "Windows Events command-line utility",
    examples: [
      { usage: "wevtutil qe Security /c:50 /f:text /rd:true", output: "Recent 50 security events" },
      { usage: "wevtutil el", output: "List all event log channels" },
      { usage: "wevtutil gli Security", output: "Security log information" }
    ],
    category: "security"
  },
  {
    cmd: "auditpol",
    desc: "Display or modify audit policy settings",
    examples: [
      { usage: "auditpol /get /category:*", output: "Show all audit categories" },
      { usage: "auditpol /set /subcategory:\"Logon\" /success:enable /failure:enable", output: "Enable logon auditing" }
    ],
    category: "security"
  },
  {
    cmd: "secedit",
    desc: "Security configuration and analysis tool",
    examples: [
      { usage: "secedit /analyze /db analysis.sdb /cfg security.inf", output: "Analyze security config" },
      { usage: "secedit /export /cfg current.inf", output: "Export current security settings" }
    ],
    category: "security"
  },
  {
    cmd: "certutil",
    desc: "Certificate management and cryptographic utility",
    examples: [
      { usage: "certutil -hashfile file.exe SHA256", output: "Compute SHA-256 hash" },
      { usage: "certutil -store My", output: "List certificates in personal store" },
      { usage: "certutil -urlcache -split -f http://url/file output", output: "Download file (LOLBin)" }
    ],
    category: "security"
  },
  {
    cmd: "sfc",
    desc: "System File Checker - scan and repair system files",
    examples: [
      { usage: "sfc /scannow", output: "Scan and repair all protected system files" },
      { usage: "sfc /verifyonly", output: "Scan only without repair" }
    ],
    category: "security"
  },
  {
    cmd: "DISM",
    desc: "Deployment Image Servicing and Management",
    examples: [
      { usage: "DISM /Online /Cleanup-Image /CheckHealth", output: "Quick health check" },
      { usage: "DISM /Online /Cleanup-Image /RestoreHealth", output: "Repair component store" }
    ],
    category: "security"
  },
  {
    cmd: "bcdedit",
    desc: "Boot Configuration Data editor",
    examples: [
      { usage: "bcdedit /enum", output: "Display boot configuration entries" },
      { usage: "bcdedit /set testsigning on", output: "Enable test-signed drivers" }
    ],
    category: "security"
  },
  {
    cmd: "sigcheck",
    desc: "Sysinternals tool to verify file digital signatures",
    examples: [
      { usage: "sigcheck -u -e C:\\Windows\\System32\\", output: "Find unsigned system files" },
      { usage: "sigcheck -vt suspicious.exe", output: "Verify signature and VirusTotal check" }
    ],
    category: "security"
  },
  {
    cmd: "accesschk",
    desc: "Sysinternals tool to check effective permissions",
    examples: [
      { usage: "accesschk -uwcqv \"Authenticated Users\" *", output: "Check service permissions" },
      { usage: "accesschk -uwdqs Users C:\\", output: "Writable directories for Users" }
    ],
    category: "security"
  },
  {
    cmd: "procdump",
    desc: "Sysinternals process dump utility",
    examples: [
      { usage: "procdump -ma lsass.exe lsass.dmp", output: "Full memory dump of LSASS" },
      { usage: "procdump -e 1 -f \"\" -x C:\\ app.exe", output: "Dump on first exception" }
    ],
    category: "security"
  },
  {
    cmd: "handle",
    desc: "Sysinternals tool to list open handles",
    examples: [
      { usage: "handle -a -u", output: "All handles with owning user" },
      { usage: "handle -p explorer.exe", output: "Handles for explorer process" }
    ],
    category: "security"
  },
  {
    cmd: "strings",
    desc: "Sysinternals tool to extract printable strings from binaries",
    examples: [
      { usage: "strings suspicious.exe | findstr /i url", output: "Extract URLs from binary" },
      { usage: "strings -n 10 malware.dll", output: "Strings with min length 10" }
    ],
    category: "security"
  },
  {
    cmd: "autoruns",
    desc: "Sysinternals tool to list auto-starting programs",
    examples: [
      { usage: "autorunsc -a * -c -h -s -v -vt", output: "All autoruns with VirusTotal check" },
      { usage: "autorunsc -a l -c", output: "Logon autoruns in CSV format" }
    ],
    category: "security"
  },

  // ---- PowerShell built-in ----
  {
    cmd: "Get-Process",
    desc: "Get running processes with details",
    examples: [
      { usage: "Get-Process | Sort-Object CPU -Descending | Select -First 20", output: "Top 20 CPU consumers" },
      { usage: "Get-Process -IncludeUserName", output: "Processes with owning user" }
    ],
    category: "processes"
  },
  {
    cmd: "Get-Service",
    desc: "Get status of system services",
    examples: [
      { usage: "Get-Service | Where-Object {$_.Status -eq 'Running'}", output: "Running services" },
      { usage: "Get-Service -Name *ssh*", output: "SSH-related services" }
    ],
    category: "services"
  },
  {
    cmd: "Get-EventLog",
    desc: "Get entries from classic event logs",
    examples: [
      { usage: "Get-EventLog -LogName Security -Newest 50", output: "Recent 50 security events" },
      { usage: "Get-EventLog -LogName System -EntryType Error -After (Get-Date).AddDays(-1)", output: "Errors in last day" }
    ],
    category: "logging"
  },
  {
    cmd: "Get-WinEvent",
    desc: "Get events from event logs and ETW trace logs",
    examples: [
      { usage: "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 50", output: "Failed logon events" },
      { usage: "Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 100", output: "Sysmon events" }
    ],
    category: "logging"
  },
  {
    cmd: "Get-NetTCPConnection",
    desc: "Get TCP connection information",
    examples: [
      { usage: "Get-NetTCPConnection -State Established", output: "Active TCP connections" },
      { usage: "Get-NetTCPConnection | Where-Object {$_.RemotePort -eq 443}", output: "HTTPS connections" }
    ],
    category: "networking"
  },
  {
    cmd: "Get-NetFirewallRule",
    desc: "Get firewall rules",
    examples: [
      { usage: "Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True'}", output: "Active firewall rules" }
    ],
    category: "networking"
  },
  {
    cmd: "Get-ScheduledTask",
    desc: "Get scheduled tasks",
    examples: [
      { usage: "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'}", output: "Active tasks" }
    ],
    category: "processes"
  },
  {
    cmd: "Get-Acl",
    desc: "Get security descriptor (ACL) for a resource",
    examples: [
      { usage: "Get-Acl C:\\sensitive | Format-List", output: "Detailed ACL information" },
      { usage: "(Get-Acl C:\\).Access", output: "Access rules for C: drive root" }
    ],
    category: "permissions"
  },
  {
    cmd: "Get-ADUser",
    desc: "Get Active Directory user objects",
    examples: [
      { usage: "Get-ADUser -Filter * -Properties LastLogonDate | Sort LastLogonDate", output: "Users by last logon" },
      { usage: "Get-ADUser -Filter {Enabled -eq $false}", output: "Disabled user accounts" }
    ],
    category: "reconnaissance"
  },
  {
    cmd: "Get-ADComputer",
    desc: "Get Active Directory computer objects",
    examples: [
      { usage: "Get-ADComputer -Filter * -Properties OperatingSystem", output: "All computers with OS" },
      { usage: "Get-ADComputer -Filter {OperatingSystem -like '*Server*'}", output: "Server computers only" }
    ],
    category: "reconnaissance"
  },
  {
    cmd: "Get-ADGroupMember",
    desc: "Get members of an Active Directory group",
    examples: [
      { usage: "Get-ADGroupMember -Identity 'Domain Admins' -Recursive", output: "All domain admins" }
    ],
    category: "reconnaissance"
  },
  {
    cmd: "Get-ItemProperty",
    desc: "Get properties of a registry key or file",
    examples: [
      { usage: "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'", output: "Startup entries" },
      { usage: "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\*' | Select PSChildName,Start,ImagePath", output: "Service paths" }
    ],
    category: "reconnaissance"
  },
  {
    cmd: "Get-FileHash",
    desc: "Compute hash of a file",
    examples: [
      { usage: "Get-FileHash suspicious.exe -Algorithm SHA256", output: "SHA-256 hash of file" },
      { usage: "Get-ChildItem C:\\*.exe | Get-FileHash -Algorithm MD5", output: "Hash all executables" }
    ],
    category: "filesystem"
  },
  {
    cmd: "Get-Content",
    desc: "Read file contents (PowerShell cat equivalent)",
    examples: [
      { usage: "Get-Content C:\\Windows\\System32\\drivers\\etc\\hosts", output: "Display hosts file" },
      { usage: "Get-Content C:\\log.txt -Tail 50 -Wait", output: "Follow last 50 lines (like tail -f)" }
    ],
    category: "filesystem"
  },
  {
    cmd: "ConvertTo-SecureString",
    desc: "Convert plaintext to encrypted secure string",
    examples: [
      { usage: "ConvertTo-SecureString 'P@ssword' -AsPlainText -Force", output: "Create secure string object" }
    ],
    category: "security"
  },
  {
    cmd: "Get-CimInstance",
    desc: "WMI/CIM instance query (modern replacement for wmic)",
    examples: [
      { usage: "Get-CimInstance Win32_OperatingSystem", output: "OS information" },
      { usage: "Get-CimInstance Win32_LogicalDisk", output: "Disk information" }
    ],
    category: "reconnaissance"
  },
  {
    cmd: "Invoke-WebRequest",
    desc: "PowerShell HTTP client (like curl/wget)",
    examples: [
      { usage: "Invoke-WebRequest -Uri https://example.com -OutFile file.html", output: "Download file" },
      { usage: "(Invoke-WebRequest -Uri https://api.example.com).Content", output: "Get response body" }
    ],
    category: "networking"
  },
  {
    cmd: "Start-BitsTransfer",
    desc: "Background Intelligent Transfer Service file download",
    examples: [
      { usage: "Start-BitsTransfer -Source https://url/file -Destination C:\\file", output: "BITS download" }
    ],
    category: "networking"
  },
  {
    cmd: "Set-ExecutionPolicy",
    desc: "Set PowerShell script execution policy",
    examples: [
      { usage: "Set-ExecutionPolicy Bypass -Scope Process", output: "Allow scripts for this session" },
      { usage: "Get-ExecutionPolicy -List", output: "Show all scope policies" }
    ],
    category: "security"
  },
  {
    cmd: "Get-MpThreatDetection",
    desc: "Get Windows Defender threat detections",
    examples: [
      { usage: "Get-MpThreatDetection", output: "List all detected threats" },
      { usage: "Get-MpComputerStatus", output: "Defender status and definitions" }
    ],
    category: "security"
  },
  {
    cmd: "Add-MpPreference",
    desc: "Configure Windows Defender preferences",
    examples: [
      { usage: "Add-MpPreference -ExclusionPath C:\\Tools\\", output: "Add scan exclusion" },
      { usage: "Get-MpPreference | Select ExclusionPath", output: "List exclusions" }
    ],
    category: "security"
  }
];


// ---------------------------------------------------------------------------
// Bash One-Liners
// ---------------------------------------------------------------------------

const BASH_ONELINERS = [
  // ---- reconnaissance / discovery ----
  { desc: "Find all SUID binaries on the system", cmd: "find / -perm -4000 -type f 2>/dev/null" },
  { desc: "Find all SGID binaries on the system", cmd: "find / -perm -2000 -type f 2>/dev/null" },
  { desc: "Find world-writable files", cmd: "find / -perm -o+w -type f 2>/dev/null | grep -v '/proc\\|/sys'" },
  { desc: "Find world-writable directories", cmd: "find / -perm -o+w -type d 2>/dev/null | grep -v '/proc\\|/sys'" },
  { desc: "Find files with no owner", cmd: "find / -nouser -o -nogroup 2>/dev/null" },
  { desc: "Find recently modified files (last 24h)", cmd: "find / -mtime -1 -type f 2>/dev/null | grep -v '/proc\\|/sys'" },
  { desc: "Find files modified in the last 10 minutes", cmd: "find / -mmin -10 -type f 2>/dev/null | grep -v '/proc\\|/sys'" },
  { desc: "List all cron jobs for all users", cmd: "for u in $(cut -f1 -d: /etc/passwd); do echo \"--- $u ---\"; crontab -l -u \"$u\" 2>/dev/null; done" },
  { desc: "List all open ports with associated PIDs", cmd: "ss -tlnp | awk 'NR>1 {print $4, $6}'" },
  { desc: "List all established connections grouped by remote IP", cmd: "ss -tn state established | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn" },
  { desc: "Show all users with UID 0 (root equivalent)", cmd: "awk -F: '$3 == 0 {print $1}' /etc/passwd" },
  { desc: "Show users with login shells", cmd: "grep -v '/nologin\\|/false' /etc/passwd" },
  { desc: "Find .bash_history files for all users", cmd: "find /home -name '.bash_history' -exec echo '--- {} ---' \; -exec cat {} \; 2>/dev/null" },
  { desc: "Check for password-less sudo access", cmd: "grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null" },
  { desc: "List all SSH authorized_keys files", cmd: "find / -name 'authorized_keys' -type f 2>/dev/null" },
  { desc: "Enumerate all network interfaces and addresses", cmd: "ip -o addr show | awk '{print $2, $4}'" },
  { desc: "Find all config files containing passwords or secrets", cmd: "grep -rli 'password\\|secret\\|api_key\\|token' /etc/ 2>/dev/null" },
  { desc: "List listening services with their binary paths", cmd: "ss -tlnp | grep LISTEN | awk '{print $4, $6}' | sed 's/.*users:((\"//' | sed 's/\".*//' | sort -u" },

  // ---- network analysis ----
  { desc: "Quick port scan of a host (no nmap needed)", cmd: "for p in $(seq 1 1024); do (echo > /dev/tcp/TARGET/\"$p\") 2>/dev/null && echo \"Port $p open\"; done" },
  { desc: "Scan a /24 subnet for live hosts", cmd: "for i in $(seq 1 254); do ping -c 1 -W 1 192.168.1.\"$i\" &>/dev/null && echo \"192.168.1.$i is up\"; done" },
  { desc: "ARP scan the local subnet", cmd: "arp-scan -l 2>/dev/null || ip neigh show" },
  { desc: "Monitor DNS queries in real-time", cmd: "tcpdump -i any -nn port 53 2>/dev/null" },
  { desc: "Capture HTTP headers from network traffic", cmd: "tcpdump -i any -A -s 0 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)' 2>/dev/null | grep -E '^(GET|POST|HTTP|Host|Content)'" },
  { desc: "List all unique remote IPs from current connections", cmd: "ss -tn | awk 'NR>1 {print $5}' | cut -d: -f1 | sort -u" },
  { desc: "Count connections per state", cmd: "ss -tan | awk 'NR>1 {print $1}' | sort | uniq -c | sort -rn" },
  { desc: "Monitor new TCP connections in real-time", cmd: "watch -n 1 'ss -tn state established'" },
  { desc: "Show bandwidth usage per interface", cmd: "cat /proc/net/dev | awk 'NR>2 {print $1, \"RX:\" $2, \"TX:\" $10}'" },
  { desc: "Extract all IP addresses from a file", cmd: "grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}' FILE" },
  { desc: "Resolve a list of IPs to hostnames", cmd: "while read ip; do echo -n \"$ip -> \"; host \"$ip\" | awk '/pointer/ {print $NF}'; done < ips.txt" },
  { desc: "Check if a domain has a wildcard DNS record", cmd: "dig A random-nonexistent-sub.example.com +short" },

  // ---- log analysis ----
  { desc: "Count failed SSH login attempts by IP", cmd: "grep 'Failed password' /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20" },
  { desc: "Show successful SSH logins", cmd: "grep 'Accepted' /var/log/auth.log | awk '{print $1,$2,$3,$9,$11}'" },
  { desc: "Find brute-force attempts (more than 10 failures)", cmd: "grep 'Failed password' /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | awk '$1 > 10'" },
  { desc: "Monitor auth.log for new entries in real-time", cmd: "tail -f /var/log/auth.log | grep --line-buffered -E 'Failed|Accepted|Invalid'" },
  { desc: "Extract unique user agents from Apache access log", cmd: "awk -F'\"' '{print $6}' /var/log/apache2/access.log | sort -u" },
  { desc: "Show top 20 requested URLs", cmd: "awk '{print $7}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -20" },
  { desc: "Find 404 errors with source IPs", cmd: "awk '$9 == 404 {print $1, $7}' /var/log/apache2/access.log | sort | uniq -c | sort -rn" },
  { desc: "Show HTTP status code distribution", cmd: "awk '{print $9}' /var/log/apache2/access.log | sort | uniq -c | sort -rn" },
  { desc: "Find SQL injection attempts in web logs", cmd: "grep -iE '(union.*select|or.*1.*=.*1|drop.*table|insert.*into|;.*--)' /var/log/apache2/access.log" },
  { desc: "Find path traversal attempts in web logs", cmd: "grep -E '(\\.\\./|\\.\\.\\\\|%2e%2e)' /var/log/apache2/access.log" },
  { desc: "Extract timestamps of sudo usage", cmd: "grep 'sudo:' /var/log/auth.log | awk '{print $1, $2, $3, $5, $6}'" },

  // ---- system hardening / audit ----
  { desc: "Check for empty password fields in shadow", cmd: "awk -F: '($2 == \"\" || $2 == \"!\") {print $1}' /etc/shadow 2>/dev/null" },
  { desc: "Verify no duplicate UIDs exist", cmd: "awk -F: '{print $3}' /etc/passwd | sort -n | uniq -d" },
  { desc: "Verify no duplicate GIDs exist", cmd: "awk -F: '{print $3}' /etc/group | sort -n | uniq -d" },
  { desc: "Check SSH config for weak settings", cmd: "grep -E '(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|X11Forwarding)' /etc/ssh/sshd_config" },
  { desc: "List all installed packages (Debian)", cmd: "dpkg -l | awk '/^ii/ {print $2, $3}'" },
  { desc: "List all installed packages (RHEL)", cmd: "rpm -qa --qf '%{NAME}-%{VERSION}\\n' | sort" },
  { desc: "Find all files changed in the last 7 days in /etc", cmd: "find /etc -mtime -7 -type f 2>/dev/null" },
  { desc: "Check if IP forwarding is enabled", cmd: "sysctl net.ipv4.ip_forward" },
  { desc: "Show all environment variables that might leak secrets", cmd: "env | grep -iE '(key|secret|token|pass|api|auth)'" },
  { desc: "List loaded kernel modules sorted by size", cmd: "lsmod | sort -k2 -n -r" },
  { desc: "Check for common backdoor user accounts", cmd: "grep -E '^(daemon|nobody|www-data)' /etc/passwd | awk -F: '$7 != \"/usr/sbin/nologin\" && $7 != \"/bin/false\" {print $1, $7}'" },

  // ---- file / forensics ----
  { desc: "Generate SHA-256 hashes for all files in directory", cmd: "find /path -type f -exec sha256sum {} \; > hashes.txt" },
  { desc: "Find files larger than 100MB", cmd: "find / -size +100M -type f 2>/dev/null" },
  { desc: "Find hidden files and directories", cmd: "find / -name '.*' -type f 2>/dev/null | grep -v '/proc\\|/sys'" },
  { desc: "Find executable files in /tmp", cmd: "find /tmp -type f -executable 2>/dev/null" },
  { desc: "Extract strings from a binary with minimum length", cmd: "strings -n 8 suspicious_binary | sort -u" },
  { desc: "Find files with embedded IPs", cmd: "grep -rlE '([0-9]{1,3}\\.){3}[0-9]{1,3}' /var/www/ 2>/dev/null" },
  { desc: "Compare two directories recursively", cmd: "diff -rq /dir1/ /dir2/" },
  { desc: "Create a forensic disk image with progress", cmd: "dd if=/dev/sda bs=4M status=progress | gzip > disk_image.gz" },
  { desc: "Mount a disk image read-only with offset", cmd: "mount -o ro,loop,offset=1048576 disk.img /mnt/analysis" },
  { desc: "Recursively count files by extension", cmd: "find . -type f | sed 's/.*\\.//' | sort | uniq -c | sort -rn | head -20" },
  { desc: "Find recently accessed files", cmd: "find / -atime -1 -type f 2>/dev/null | head -50" },
  { desc: "Hex dump first 256 bytes of a file", cmd: "xxd -l 256 suspicious_file" },
  { desc: "Extract base64-encoded strings from a file", cmd: "grep -oE '[A-Za-z0-9+/]{20,}={0,2}' file.txt" },
  { desc: "Find duplicate files by hash", cmd: "find . -type f -exec md5sum {} \; | sort | uniq -w 32 -d" },

  // ---- process / runtime ----
  { desc: "Show process tree for a specific PID", cmd: "pstree -p PID" },
  { desc: "List all processes with their open network connections", cmd: "for pid in /proc/[0-9]*; do echo \"PID: $(basename $pid)\"; ls -l $pid/fd 2>/dev/null | grep socket; done" },
  { desc: "Find processes running from /tmp or deleted binaries", cmd: "ls -la /proc/*/exe 2>/dev/null | grep -E '(tmp|deleted)'" },
  { desc: "Show memory map of a process", cmd: "cat /proc/PID/maps" },
  { desc: "List all processes with their command lines", cmd: "ps -eo pid,user,args --sort=-pcpu | head -30" },
  { desc: "Find processes with the most open files", cmd: "for pid in /proc/[0-9]*; do echo \"$(ls $pid/fd 2>/dev/null | wc -l) $(basename $pid) $(cat $pid/comm 2>/dev/null)\"; done | sort -rn | head -20" },
  { desc: "Check for processes running as root that should not be", cmd: "ps -eo user,pid,cmd | awk '$1 == \"root\"' | grep -vE '(\\[|/usr/lib|/sbin|/usr/sbin)'" },
  { desc: "Kill all connections from a specific IP using ss", cmd: "ss -K dst TARGET_IP" },
  { desc: "Watch for new process creation", cmd: "watch -n 0.5 'ps -eo pid,ppid,user,start,cmd --sort=-start_time | head -20'" },
  { desc: "Find zombie processes", cmd: "ps aux | awk '$8 ~ /Z/ {print}'" },

  // ---- encoding / payload helpers ----
  { desc: "Base64 encode a string", cmd: "echo -n 'payload' | base64" },
  { desc: "Base64 decode a string", cmd: "echo 'cGF5bG9hZA==' | base64 -d" },
  { desc: "URL encode a string", cmd: "python3 -c \"import urllib.parse; print(urllib.parse.quote('string to encode'))\"" },
  { desc: "URL decode a string", cmd: "python3 -c \"import urllib.parse; print(urllib.parse.unquote('string%20to%20decode'))\"" },
  { desc: "Generate a random 32-char hex string", cmd: "openssl rand -hex 16" },
  { desc: "Generate a random alphanumeric password", cmd: "tr -dc 'A-Za-z0-9!@#$%' < /dev/urandom | head -c 32; echo" },
  { desc: "Convert hex to ASCII", cmd: "echo '48656c6c6f' | xxd -r -p" },
  { desc: "Calculate the entropy of a file", cmd: "cat file | fold -w1 | sort | uniq -c | sort -rn | awk '{p=$1/NR; e+=-p*log(p)/log(2)} END {print e}'" },
  { desc: "ROT13 encode/decode a string", cmd: "echo 'Hello World' | tr 'A-Za-z' 'N-ZA-Mn-za-m'" }
];


// ---------------------------------------------------------------------------
// PowerShell One-Liners
// ---------------------------------------------------------------------------

const POWERSHELL_ONELINERS = [
  // ---- reconnaissance ----
  { desc: "Get all local user accounts with details", cmd: "Get-LocalUser | Select Name, Enabled, LastLogon, PasswordLastSet" },
  { desc: "Get all local group memberships", cmd: "Get-LocalGroup | ForEach-Object { Write-Host \"`n--- $($_.Name) ---\"; Get-LocalGroupMember $_ 2>$null }" },
  { desc: "Find Domain Admins", cmd: "Get-ADGroupMember -Identity 'Domain Admins' -Recursive | Select Name, SamAccountName" },
  { desc: "Get all domain computers with OS info", cmd: "Get-ADComputer -Filter * -Properties OperatingSystem | Select Name, OperatingSystem" },
  { desc: "Find disabled AD accounts that still have sessions", cmd: "Get-ADUser -Filter {Enabled -eq $false} | ForEach-Object { quser /server:$($_.Name) 2>$null }" },
  { desc: "Get system information summary", cmd: "Get-CimInstance Win32_OperatingSystem | Select Caption, Version, BuildNumber, LastBootUpTime" },
  { desc: "List installed software", cmd: "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select DisplayName, DisplayVersion, Publisher | Sort DisplayName" },
  { desc: "Get all environment variables", cmd: "[System.Environment]::GetEnvironmentVariables() | Format-Table -AutoSize" },
  { desc: "Find GPO settings applied to this machine", cmd: "gpresult /r /scope:computer" },
  { desc: "List all startup programs", cmd: "Get-CimInstance Win32_StartupCommand | Select Name, Command, Location, User" },
  { desc: "Find Kerberos tickets in memory", cmd: "klist" },
  { desc: "Get BIOS information", cmd: "Get-CimInstance Win32_BIOS | Select Manufacturer, SMBIOSBIOSVersion, ReleaseDate" },
  { desc: "Check for pending reboots", cmd: "Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending'" },
  { desc: "Get all network shares", cmd: "Get-SmbShare | Select Name, Path, Description" },
  { desc: "Get USB device history", cmd: "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USB\\*\\*' | Select FriendlyName, DeviceDesc" },

  // ---- networking ----
  { desc: "Get all active TCP connections with process names", cmd: "Get-NetTCPConnection -State Established | Select LocalAddress, LocalPort, RemoteAddress, RemotePort, @{N='Process';E={(Get-Process -Id $_.OwningProcess).Name}}" },
  { desc: "Find listening ports with associated processes", cmd: "Get-NetTCPConnection -State Listen | Select LocalAddress, LocalPort, @{N='Process';E={(Get-Process -Id $_.OwningProcess).Name}} | Sort LocalPort" },
  { desc: "Get DNS cache entries", cmd: "Get-DnsClientCache | Select Entry, Name, Data" },
  { desc: "Test multiple ports on a host", cmd: "@(22,80,443,3389,445) | ForEach-Object { $r = Test-NetConnection -ComputerName TARGET -Port $_ -WarningAction SilentlyContinue; \"$_`: $($r.TcpTestSucceeded)\" }" },
  { desc: "Get all firewall rules allowing inbound traffic", cmd: "Get-NetFirewallRule -Direction Inbound -Enabled True | Get-NetFirewallPortFilter | Where-Object LocalPort -ne $null | Select @{N='Rule';E={(Get-NetFirewallRule -AssociatedNetFirewallPortFilter $_).DisplayName}}, Protocol, LocalPort" },
  { desc: "Trace route with latency", cmd: "Test-NetConnection -ComputerName 8.8.8.8 -TraceRoute | Select -ExpandProperty TraceRoute" },
  { desc: "Get WiFi profiles and passwords", cmd: "netsh wlan show profiles | Select-String 'All User Profile' | ForEach-Object { $name = ($_ -split ':')[1].Trim(); $detail = netsh wlan show profile name=$name key=clear; \"$name`: $(($detail | Select-String 'Key Content').ToString().Split(':')[1].Trim())\" }" },
  { desc: "Monitor network adapter statistics", cmd: "Get-NetAdapterStatistics | Select Name, ReceivedBytes, SentBytes" },
  { desc: "Get ARP table", cmd: "Get-NetNeighbor | Where-Object State -ne 'Unreachable' | Select IPAddress, LinkLayerAddress, State" },
  { desc: "Download a file from URL", cmd: "Invoke-WebRequest -Uri 'https://example.com/file' -OutFile 'C:\\file'" },
  { desc: "Check SSL certificate expiration for a domain", cmd: "$req = [Net.HttpWebRequest]::Create('https://example.com'); $req.GetResponse() | Out-Null; $req.ServicePoint.Certificate.GetExpirationDateString()" },

  // ---- security / event logs ----
  { desc: "Find failed logon events (Event ID 4625)", cmd: "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 50 | ForEach-Object { $_.TimeCreated, ($_.Properties[5].Value), ($_.Properties[19].Value) }" },
  { desc: "Find successful logon events (Event ID 4624)", cmd: "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 50 | ForEach-Object { $_.TimeCreated, ($_.Properties[5].Value), ($_.Properties[18].Value) }" },
  { desc: "Find account lockout events (Event ID 4740)", cmd: "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4740} -MaxEvents 20" },
  { desc: "Find new service installations (Event ID 7045)", cmd: "Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 20 | ForEach-Object { $_.TimeCreated, $_.Properties[0].Value, $_.Properties[1].Value }" },
  { desc: "Find PowerShell script block logging events", cmd: "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 20 | Select TimeCreated, Message" },
  { desc: "Find process creation events (Sysmon Event ID 1)", cmd: "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 50" },
  { desc: "Find network connections (Sysmon Event ID 3)", cmd: "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} -MaxEvents 50" },
  { desc: "Get Windows Defender threat history", cmd: "Get-MpThreatDetection | Select DetectionID, ThreatID, ProcessName, DomainUser, InitialDetectionTime" },
  { desc: "Check for unsigned drivers", cmd: "Get-WmiObject Win32_PnPSignedDriver | Where-Object IsSigned -eq $false | Select DeviceName, DriverVersion" },
  { desc: "List all certificates in local machine store", cmd: "Get-ChildItem Cert:\\LocalMachine\\My | Select Subject, NotAfter, Thumbprint" },
  { desc: "Find scheduled tasks created by non-system users", cmd: "Get-ScheduledTask | Where-Object { $_.Principal.UserId -ne 'SYSTEM' -and $_.State -ne 'Disabled' } | Select TaskName, @{N='User';E={$_.Principal.UserId}}" },
  { desc: "Check for running anti-virus products", cmd: "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select displayName, productState" },

  // ---- file system ----
  { desc: "Find files modified in the last 24 hours", cmd: "Get-ChildItem -Path C:\\ -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) } | Select FullName, LastWriteTime" },
  { desc: "Find large files (over 100MB)", cmd: "Get-ChildItem -Path C:\\ -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 100MB } | Select FullName, @{N='SizeMB';E={[math]::Round($_.Length/1MB,2)}} | Sort SizeMB -Descending" },
  { desc: "Find hidden files", cmd: "Get-ChildItem -Path C:\\ -Recurse -Hidden -ErrorAction SilentlyContinue | Select FullName, Length, LastWriteTime" },
  { desc: "Compute SHA-256 hash of all executables in a directory", cmd: "Get-ChildItem -Path C:\\Windows\\System32 -Filter *.exe | Get-FileHash -Algorithm SHA256 | Select Hash, Path" },
  { desc: "Find files containing a specific string", cmd: "Get-ChildItem -Path C:\\ -Recurse -Include *.txt,*.log,*.config -ErrorAction SilentlyContinue | Select-String -Pattern 'password' | Select Path, LineNumber, Line" },
  { desc: "List alternate data streams on files", cmd: "Get-ChildItem -Path C:\\Users -Recurse -ErrorAction SilentlyContinue | Get-Item -Stream * -ErrorAction SilentlyContinue | Where-Object Stream -ne ':$DATA'" },
  { desc: "Find executable files in temp directories", cmd: "Get-ChildItem -Path $env:TEMP, C:\\Windows\\Temp -Recurse -Include *.exe,*.dll,*.ps1,*.bat,*.cmd -ErrorAction SilentlyContinue | Select FullName, CreationTime" },
  { desc: "Get NTFS permissions for a path", cmd: "(Get-Acl 'C:\\sensitive').Access | Select IdentityReference, FileSystemRights, AccessControlType" },
  { desc: "Find recently created user profiles", cmd: "Get-ChildItem C:\\Users -Directory | Select Name, CreationTime | Sort CreationTime -Descending" },
  { desc: "Check file signature / digital signature", cmd: "Get-AuthenticodeSignature C:\\path\\to\\file.exe | Select Status, SignerCertificate" },

  // ---- processes / services ----
  { desc: "Get processes with their network connections", cmd: "Get-NetTCPConnection | Select @{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}}, LocalPort, RemoteAddress, RemotePort, State | Where-Object Process -ne $null" },
  { desc: "Find processes running from unusual paths", cmd: "Get-Process | Where-Object { $_.Path -and $_.Path -notmatch 'Windows|Program Files' } | Select Name, Path, Id" },
  { desc: "Get service binary paths for privilege escalation check", cmd: "Get-WmiObject Win32_Service | Where-Object { $_.PathName -match '\\s' -and $_.PathName -notmatch '\"' } | Select Name, PathName, StartMode" },
  { desc: "Find services running as non-standard accounts", cmd: "Get-WmiObject Win32_Service | Where-Object { $_.StartName -and $_.StartName -notmatch 'LocalSystem|LocalService|NetworkService' } | Select Name, StartName, State" },
  { desc: "Kill a process and all children", cmd: "Stop-Process -Name 'process_name' -Force -ErrorAction SilentlyContinue; Get-CimInstance Win32_Process | Where-Object ParentProcessId -eq PID | Stop-Process -Force" },
  { desc: "List DLLs loaded by a process", cmd: "Get-Process -Name 'process' | Select -ExpandProperty Modules | Select FileName" },
  { desc: "Get process command lines", cmd: "Get-CimInstance Win32_Process | Select ProcessId, Name, CommandLine" },
  { desc: "Find auto-start services that are stopped", cmd: "Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' } | Select Name, Status, StartType" },

  // ---- Active Directory ----
  { desc: "Find AD users who have not logged in for 90 days", cmd: "Get-ADUser -Filter * -Properties LastLogonDate | Where-Object { $_.LastLogonDate -lt (Get-Date).AddDays(-90) } | Select Name, LastLogonDate, Enabled" },
  { desc: "Find AD users with password never expires", cmd: "Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires | Select Name, Enabled" },
  { desc: "Get all OUs in the domain", cmd: "Get-ADOrganizationalUnit -Filter * | Select Name, DistinguishedName" },
  { desc: "Find AD users with ServicePrincipalName set (Kerberoastable)", cmd: "Get-ADUser -Filter {ServicePrincipalName -ne '$null'} -Properties ServicePrincipalName | Select Name, ServicePrincipalName" },
  { desc: "Get all GPOs in the domain", cmd: "Get-GPO -All | Select DisplayName, GpoStatus, ModificationTime" },
  { desc: "Find computers with unconstrained delegation", cmd: "Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | Select Name" },
  { desc: "Get all domain trusts", cmd: "Get-ADTrust -Filter *" },
  { desc: "Find users in privileged groups", cmd: "@('Domain Admins','Enterprise Admins','Schema Admins','Administrators') | ForEach-Object { Write-Host \"`n--- $_ ---\"; Get-ADGroupMember -Identity $_ | Select Name }" },

  // ---- persistence / forensics ----
  { desc: "Get all registry Run keys (startup persistence)", cmd: "@('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run','HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run','HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce') | ForEach-Object { Write-Host \"`n--- $_ ---\"; Get-ItemProperty $_ -ErrorAction SilentlyContinue }" },
  { desc: "Find WMI event subscriptions (persistence mechanism)", cmd: "Get-WMIObject -Namespace root\\Subscription -Class __EventFilter; Get-WMIObject -Namespace root\\Subscription -Class CommandLineEventConsumer" },
  { desc: "Check for DLL search order hijacking opportunities", cmd: "Get-Process | ForEach-Object { $_.Modules } | Where-Object { $_.FileName -match 'C:\\\\Users|C:\\\\Temp' } | Select FileName -Unique" },
  { desc: "Get recent PowerShell execution history", cmd: "Get-Content (Get-PSReadLineOption).HistorySavePath" },
  { desc: "Find COM object hijacking opportunities", cmd: "Get-ItemProperty 'HKCU:\\SOFTWARE\\Classes\\CLSID\\*\\InprocServer32' -ErrorAction SilentlyContinue | Where-Object '(default)' -ne $null | Select PSChildName, '(default)'" },
  { desc: "Check for suspicious named pipes", cmd: "Get-ChildItem \\\\.\\pipe\\ | Select Name | Sort Name" },
  { desc: "Get prefetch files (evidence of execution)", cmd: "Get-ChildItem C:\\Windows\\Prefetch -Filter *.pf | Select Name, CreationTime, LastWriteTime | Sort LastWriteTime -Descending" },
  { desc: "Find files created around a specific date", cmd: "$target = Get-Date '2025-01-15'; Get-ChildItem C:\\ -Recurse -ErrorAction SilentlyContinue | Where-Object { [math]::Abs(($_.CreationTime - $target).TotalHours) -lt 24 } | Select FullName, CreationTime" },
  { desc: "Check Windows Defender exclusions", cmd: "Get-MpPreference | Select -ExpandProperty ExclusionPath; Get-MpPreference | Select -ExpandProperty ExclusionProcess; Get-MpPreference | Select -ExpandProperty ExclusionExtension" },
  { desc: "Get BitLocker status for all drives", cmd: "Get-BitLockerVolume | Select MountPoint, VolumeStatus, EncryptionPercentage, ProtectionStatus" }
];

