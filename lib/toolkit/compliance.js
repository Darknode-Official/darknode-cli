"use strict";
// Compliance reference data -- security framework controls, benchmarks, and
// verification standards used by the audit and hardening modules. All entries
// are reference-only (no live API calls, no credentials). Covers NIST 800-53,
// CIS Benchmarks, PCI DSS v4.0, and OWASP ASVS 4.0.

// ---------------------------------------------------------------------------
// NIST 800-53 Rev 5 -- Selected controls across multiple families
// ---------------------------------------------------------------------------
const NIST_CONTROLS = [
  {
    id: "AC-1",
    family: "Access Control",
    title: "Access Control Policy and Procedures",
    description:
      "Develop, document, and disseminate an access control policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance; and procedures to facilitate the implementation of the access control policy and the associated access controls.",
    priority: "P1",
    implementation:
      "Establish a formal access control policy document reviewed annually. Assign an owner responsible for updates. Distribute to all personnel with system access and maintain acknowledgment records.",
  },
  {
    id: "AC-2",
    family: "Access Control",
    title: "Account Management",
    description:
      "Define and document the types of information system accounts allowed and specifically prohibited. Assign account managers. Establish conditions for group and role membership. Specify authorized users, group and role membership, and access authorizations for each account.",
    priority: "P1",
    implementation:
      "Implement automated account provisioning tied to HR on-boarding/off-boarding workflows. Enforce periodic access reviews every 90 days. Disable accounts after 45 days of inactivity. Log all account creation and modification events.",
  },
  {
    id: "AC-3",
    family: "Access Control",
    title: "Access Enforcement",
    description:
      "Enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.",
    priority: "P1",
    implementation:
      "Use role-based access control (RBAC) or attribute-based access control (ABAC) mechanisms. Implement least-privilege enforcement at the OS, application, and database layers. Test access enforcement quarterly.",
  },
  {
    id: "AC-6",
    family: "Access Control",
    title: "Least Privilege",
    description:
      "Employ the principle of least privilege, allowing only authorized accesses for users and processes that are necessary to accomplish assigned organizational tasks.",
    priority: "P1",
    implementation:
      "Remove administrative privileges from standard user accounts. Implement just-in-time (JIT) privilege elevation with approval workflows. Audit privileged account usage monthly and revoke excessive permissions.",
  },
  {
    id: "AC-17",
    family: "Access Control",
    title: "Remote Access",
    description:
      "Establish and document usage restrictions, configuration/connection requirements, and implementation guidance for each type of remote access allowed. Authorize remote access to the system prior to allowing such connections.",
    priority: "P1",
    implementation:
      "Require VPN with multi-factor authentication for all remote access. Encrypt remote sessions end-to-end. Monitor and log remote access sessions. Restrict remote access to approved devices only.",
  },
  {
    id: "AU-1",
    family: "Audit and Accountability",
    title: "Audit and Accountability Policy and Procedures",
    description:
      "Develop, document, and disseminate an audit and accountability policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance.",
    priority: "P1",
    implementation:
      "Define auditable events, audit record content, and retention periods. Assign responsibility for audit log review. Establish procedures for audit log protection and backup.",
  },
  {
    id: "AU-2",
    family: "Audit and Accountability",
    title: "Audit Events",
    description:
      "Identify the types of events that the system is capable of auditing. Coordinate the audit event selection with other organizational entities requiring audit-related information.",
    priority: "P1",
    implementation:
      "Audit logon/logoff events, privilege escalation, object access, policy changes, account management, and system events. Review and update the auditable event list annually. Correlate logs across systems using a SIEM.",
  },
  {
    id: "AU-3",
    family: "Audit and Accountability",
    title: "Content of Audit Records",
    description:
      "Ensure that audit records contain information that establishes the type of event, when and where the event occurred, the source of the event, the outcome, and the identity of subjects or objects associated with the event.",
    priority: "P1",
    implementation:
      "Configure logging to capture: event type, timestamp (UTC), source IP, destination, user identity, action performed, and outcome (success/failure). Use structured log formats (JSON or CEF) for machine parsing.",
  },
  {
    id: "AU-6",
    family: "Audit and Accountability",
    title: "Audit Review, Analysis, and Reporting",
    description:
      "Review and analyze information system audit records for indications of inappropriate or unusual activity. Report findings to designated organizational officials.",
    priority: "P1",
    implementation:
      "Perform automated log analysis with alerting thresholds. Conduct manual review of flagged events within 24 hours. Generate weekly audit summary reports for management. Investigate anomalies within defined SLAs.",
  },
  {
    id: "CM-1",
    family: "Configuration Management",
    title: "Configuration Management Policy and Procedures",
    description:
      "Develop, document, and disseminate a configuration management policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance.",
    priority: "P1",
    implementation:
      "Maintain a configuration management plan covering baseline configurations, change control boards, and deviation handling. Use infrastructure-as-code (IaC) for reproducible deployments. Track all configuration items in a CMDB.",
  },
  {
    id: "CM-6",
    family: "Configuration Management",
    title: "Configuration Settings",
    description:
      "Establish and document configuration settings for components employed within the system that reflect the most restrictive mode consistent with operational requirements.",
    priority: "P1",
    implementation:
      "Apply CIS benchmarks or DISA STIGs as baseline configurations. Scan for configuration drift weekly using automated tools. Remediate deviations within 30 days or document risk acceptance.",
  },
  {
    id: "CM-7",
    family: "Configuration Management",
    title: "Least Functionality",
    description:
      "Configure the system to provide only mission-essential capabilities. Prohibit or restrict the use of functions, ports, protocols, and services not required for operations.",
    priority: "P1",
    implementation:
      "Disable unnecessary services, ports, and protocols on all systems. Maintain an approved software whitelist. Remove or disable default accounts and sample applications. Review system functionality quarterly.",
  },
  {
    id: "IA-1",
    family: "Identification and Authentication",
    title: "Identification and Authentication Policy and Procedures",
    description:
      "Develop, document, and disseminate an identification and authentication policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance.",
    priority: "P1",
    implementation:
      "Define approved authentication mechanisms (passwords, MFA tokens, certificates, biometrics). Establish password complexity and rotation requirements. Document identity proofing procedures for account issuance.",
  },
  {
    id: "IA-2",
    family: "Identification and Authentication",
    title: "Identification and Authentication (Organizational Users)",
    description:
      "Uniquely identify and authenticate organizational users and associate that unique identification with processes acting on behalf of those users.",
    priority: "P1",
    implementation:
      "Assign unique user IDs to all personnel. Enforce multi-factor authentication for privileged and remote access. Integrate with a centralized identity provider (IdP). Prohibit shared or generic accounts.",
  },
  {
    id: "IA-5",
    family: "Identification and Authentication",
    title: "Authenticator Management",
    description:
      "Manage system authenticators by verifying the identity of the individual, group, role, service, or device receiving the authenticator. Establish initial authenticator content, administrative procedures for lost/compromised authenticators, and revoking authenticators.",
    priority: "P1",
    implementation:
      "Enforce minimum 14-character passwords with complexity requirements. Implement automated password expiration (90 days for standard, 60 days for privileged). Hash stored passwords with bcrypt or Argon2. Distribute hardware tokens through verified channels.",
  },
  {
    id: "IR-1",
    family: "Incident Response",
    title: "Incident Response Policy and Procedures",
    description:
      "Develop, document, and disseminate an incident response policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance.",
    priority: "P1",
    implementation:
      "Create an incident response plan with defined severity levels, escalation paths, and communication templates. Identify incident response team members and alternates. Conduct tabletop exercises semi-annually.",
  },
  {
    id: "IR-4",
    family: "Incident Response",
    title: "Incident Handling",
    description:
      "Implement an incident handling capability for incidents that includes preparation, detection and analysis, containment, eradication, and recovery.",
    priority: "P1",
    implementation:
      "Deploy automated detection and alerting. Maintain runbooks for common incident types (malware, unauthorized access, data exfiltration, DDoS). Preserve forensic evidence with chain-of-custody documentation. Conduct post-incident reviews within 5 business days.",
  },
  {
    id: "SC-1",
    family: "System and Communications Protection",
    title: "System and Communications Protection Policy and Procedures",
    description:
      "Develop, document, and disseminate a system and communications protection policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance.",
    priority: "P1",
    implementation:
      "Define approved encryption algorithms and key lengths. Document network segmentation architecture. Establish boundary protection requirements for all system interconnections.",
  },
  {
    id: "SC-7",
    family: "System and Communications Protection",
    title: "Boundary Protection",
    description:
      "Monitor and control communications at the external managed interfaces to the system and at key internal managed interfaces within the system.",
    priority: "P1",
    implementation:
      "Deploy firewalls at all trust boundaries. Implement DMZ architecture for public-facing services. Use intrusion detection/prevention systems (IDS/IPS) at network boundaries. Restrict outbound traffic to approved destinations and protocols.",
  },
  {
    id: "SC-8",
    family: "System and Communications Protection",
    title: "Transmission Confidentiality and Integrity",
    description:
      "Protect the confidentiality and integrity of transmitted information using cryptographic mechanisms.",
    priority: "P1",
    implementation:
      "Enforce TLS 1.2 or higher for all network transmissions. Use IPsec or WireGuard for site-to-site connections. Disable SSLv3, TLS 1.0, and TLS 1.1. Verify certificate chains and revocation status.",
  },
  {
    id: "SI-1",
    family: "System and Information Integrity",
    title: "System and Information Integrity Policy and Procedures",
    description:
      "Develop, document, and disseminate a system and information integrity policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance.",
    priority: "P1",
    implementation:
      "Define patch management timelines (critical: 72 hours, high: 7 days, medium: 30 days). Establish malware protection requirements. Document integrity monitoring procedures and acceptable thresholds for false positives.",
  },
  {
    id: "SI-2",
    family: "System and Information Integrity",
    title: "Flaw Remediation",
    description:
      "Identify, report, and correct system flaws. Install security-relevant software and firmware updates within organization-defined time periods.",
    priority: "P1",
    implementation:
      "Subscribe to vendor security advisories and CVE feeds. Test patches in a staging environment before production deployment. Track remediation status in a vulnerability management dashboard. Escalate overdue patches to management.",
  },
  {
    id: "SI-3",
    family: "System and Information Integrity",
    title: "Malicious Code Protection",
    description:
      "Implement malicious code protection mechanisms at system entry and exit points. Update malicious code protection mechanisms whenever new releases are available.",
    priority: "P1",
    implementation:
      "Deploy endpoint detection and response (EDR) on all endpoints. Enable real-time scanning and automatic signature updates. Block execution of unauthorized file types. Monitor for fileless malware techniques using behavioral analysis.",
  },
  {
    id: "SI-4",
    family: "System and Information Integrity",
    title: "System Monitoring",
    description:
      "Monitor the system to detect attacks and indicators of potential attacks, unauthorized local, network, and remote connections, and unusual or unauthorized activities.",
    priority: "P1",
    implementation:
      "Deploy network and host-based monitoring sensors. Aggregate logs in a centralized SIEM. Configure correlation rules for known attack patterns. Maintain a 90-day minimum log retention period for hot storage and 1 year for cold storage.",
  },
];

// ---------------------------------------------------------------------------
// CIS Benchmarks -- Selected controls across multiple platforms
// ---------------------------------------------------------------------------
const CIS_BENCHMARKS = [
  {
    id: "CIS-LIN-1.1.1",
    title: "Ensure mounting of cramfs filesystems is disabled",
    level: 1,
    description:
      "The cramfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems. Disabling cramfs reduces the attack surface by removing unnecessary filesystem drivers.",
    rationale:
      "Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it.",
    audit:
      "Run: modprobe -n -v cramfs | grep -E '(cramfs|install)' and lsmod | grep cramfs. Output should show 'install /bin/true' and no module loaded.",
    remediation:
      "Add 'install cramfs /bin/true' to /etc/modprobe.d/cramfs.conf. Run 'rmmod cramfs' if the module is currently loaded.",
  },
  {
    id: "CIS-LIN-1.3.1",
    title: "Ensure AIDE is installed",
    level: 1,
    description:
      "AIDE (Advanced Intrusion Detection Environment) takes a snapshot of filesystem state including modification times, permissions, and file hashes, which can then be used to compare against the current state of the filesystem to detect modifications.",
    rationale:
      "By monitoring the filesystem state, an organization can detect if unauthorized changes have been made to important files, which may indicate a compromise.",
    audit:
      "Run: dpkg-query -W -f='${binary:Package}\\t${Status}\\t${db:Status-Status}\\n' aide aide-common. Verify AIDE packages are installed.",
    remediation:
      "Install AIDE: apt install aide aide-common. Initialize the database: aideinit. Configure a cron job for daily checks.",
  },
  {
    id: "CIS-LIN-1.4.1",
    title: "Ensure bootloader password is set",
    level: 1,
    description:
      "Setting the boot loader password protects against unauthorized users booting into single-user mode or changing the boot parameters, which could allow them to gain root access.",
    rationale:
      "Requiring a boot password upon execution of the boot loader prevents an unauthorized user from entering boot parameters or changing the boot partition, which could compromise system security.",
    audit:
      "Run: grep '^set superusers' /boot/grub/grub.cfg. Verify a superuser entry exists. Run: grep '^password' /boot/grub/grub.cfg to verify a password hash is set.",
    remediation:
      "Create an encrypted password with grub-mkpasswd-pbkdf2. Add the superuser and password entries to /etc/grub.d/00_header. Run update-grub.",
  },
  {
    id: "CIS-LIN-3.4.1",
    title: "Ensure firewall package is installed",
    level: 1,
    description:
      "A firewall utility is required to configure the Linux kernel packet filtering framework (netfilter). Common utilities include iptables, nftables, and ufw.",
    rationale:
      "A firewall is necessary to limit network traffic to and from the system, reducing the attack surface and preventing unauthorized access to system services.",
    audit:
      "Run: dpkg-query -W -f='${binary:Package}\\t${Status}\\n' ufw nftables iptables. At least one firewall package should be installed.",
    remediation:
      "Install the preferred firewall package: apt install ufw. Enable and configure appropriate rules for organizational requirements.",
  },
  {
    id: "CIS-LIN-5.2.1",
    title: "Ensure permissions on /etc/ssh/sshd_config are configured",
    level: 1,
    description:
      "The /etc/ssh/sshd_config file contains configuration specifications for sshd. The sshd_config file must have correct ownership and permissions to prevent unauthorized modifications.",
    rationale:
      "Incorrect permissions or ownership of the sshd configuration file could allow unauthorized users to modify the SSH daemon, potentially opening security holes.",
    audit:
      "Run: stat /etc/ssh/sshd_config. Verify Uid is 0/root, Gid is 0/root, and Access is 0600 or more restrictive.",
    remediation:
      "Run: chown root:root /etc/ssh/sshd_config && chmod og-rwx /etc/ssh/sshd_config",
  },
  {
    id: "CIS-LIN-5.2.4",
    title: "Ensure SSH access is limited",
    level: 1,
    description:
      "Restrict which users and groups can access the system via SSH by using AllowUsers, AllowGroups, DenyUsers, or DenyGroups directives in the sshd configuration.",
    rationale:
      "Restricting SSH access to only authorized users reduces the risk of unauthorized access from compromised accounts or brute-force attacks.",
    audit:
      "Run: sshd -T -C user=root | grep -Ei '(allow|deny)(users|groups)'. Verify that allow/deny directives are configured.",
    remediation:
      "Edit /etc/ssh/sshd_config and add AllowUsers or AllowGroups directives with the appropriate user/group list. Restart sshd.",
  },
  {
    id: "CIS-WIN-1.1.1",
    title: "Ensure Enforce password history is set to 24 or more passwords",
    level: 1,
    description:
      "This policy setting determines the number of renewed, unique passwords that have to be associated with a user account before an old password can be reused.",
    rationale:
      "The longer a user uses the same password, the greater the chance that an attacker can determine the password through brute-force attacks. Requiring password history prevents cycling through a small set of passwords.",
    audit:
      "Navigate to Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > Password Policy. Verify 'Enforce password history' is set to 24 or more.",
    remediation:
      "Set the policy value to 24 or higher via Group Policy or by running: net accounts /uniquepw:24",
  },
  {
    id: "CIS-WIN-2.2.1",
    title: "Ensure Access Credential Manager as a trusted caller is set to No One",
    level: 1,
    description:
      "This security setting determines which users and groups can access the Credential Manager as a trusted caller during backup and restore operations.",
    rationale:
      "If an account is given this right, the user may be able to retrieve and manipulate credentials stored in Credential Manager, potentially compromising other user accounts.",
    audit:
      "Navigate to Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > User Rights Assignment. Verify 'Access Credential Manager as a trusted caller' is set to 'No One'.",
    remediation:
      "Configure the policy via Group Policy to set the value to No One (empty). Ensure no accounts or groups are listed.",
  },
  {
    id: "CIS-WIN-9.1.1",
    title: "Ensure Windows Firewall Domain Profile is enabled",
    level: 1,
    description:
      "Windows Firewall profiles provide different levels of protection based on the network connection type. The Domain profile applies when a computer is connected to its domain.",
    rationale:
      "A firewall provides a first line of defense against network-based attacks. Ensuring the Domain profile is enabled helps protect systems while connected to organizational networks.",
    audit:
      "Run: netsh advfirewall show domainprofile. Verify State is ON.",
    remediation:
      "Run: netsh advfirewall set domainprofile state on. Or configure via Group Policy under Windows Firewall with Advanced Security.",
  },
  {
    id: "CIS-DOCKER-2.1",
    title: "Ensure network traffic is restricted between containers on the default bridge",
    level: 1,
    description:
      "By default, all network traffic is allowed between containers on the same host on the default bridge network. This should be restricted to prevent unnecessary inter-container communication.",
    rationale:
      "Unrestricted inter-container communication could allow a compromised container to attack other containers on the same host, facilitating lateral movement.",
    audit:
      "Run: docker network inspect bridge | jq '.[0].Options[\"com.docker.network.bridge.enable_icc\"]'. Verify the value is 'false'.",
    remediation:
      "Edit the Docker daemon configuration /etc/docker/daemon.json and add: {\"icc\": false}. Restart the Docker daemon.",
  },
  {
    id: "CIS-DOCKER-2.5",
    title: "Ensure aufs storage driver is not used",
    level: 1,
    description:
      "The aufs storage driver is an older driver that has known issues with stability and performance. Modern alternatives like overlay2 should be used instead.",
    rationale:
      "The aufs driver is not supported on many modern distributions and has known stability issues. Using overlay2 provides better performance and security characteristics.",
    audit:
      "Run: docker info --format '{{ .Driver }}'. Verify the output is not 'aufs'.",
    remediation:
      "Configure Docker to use overlay2 by adding {\"storage-driver\": \"overlay2\"} to /etc/docker/daemon.json. Migrate existing containers and images before changing the driver.",
  },
  {
    id: "CIS-DOCKER-4.1",
    title: "Ensure that a user for the container has been created",
    level: 1,
    description:
      "Containers should run as a non-root user. Create a non-root user for the container in the Dockerfile and use the USER directive to switch to that user.",
    rationale:
      "Running containers as root increases the risk of container breakout attacks. A non-root user limits the damage that can be done if a container is compromised.",
    audit:
      "Run: docker inspect --format '{{.Config.User}}' <container_id>. Verify a non-root user is configured.",
    remediation:
      "Add a USER directive in the Dockerfile after installing packages: RUN useradd -r appuser && USER appuser. Rebuild the container image.",
  },
  {
    id: "CIS-K8S-1.1.1",
    title: "Ensure that the API server pod specification file permissions are set to 600 or more restrictive",
    level: 1,
    description:
      "The API server pod specification file controls the configuration of the Kubernetes API server. File permissions must be restrictive to prevent unauthorized modifications.",
    rationale:
      "Unrestricted access to the API server pod spec could allow unauthorized modification of the API server configuration, potentially granting cluster-wide admin access.",
    audit:
      "Run: stat -c %a /etc/kubernetes/manifests/kube-apiserver.yaml. Verify the permissions are 600 or more restrictive.",
    remediation:
      "Run: chmod 600 /etc/kubernetes/manifests/kube-apiserver.yaml. Ensure the file is owned by root:root.",
  },
  {
    id: "CIS-K8S-1.2.6",
    title: "Ensure that the --kubelet-certificate-authority argument is set as appropriate",
    level: 1,
    description:
      "The apiserver, by default, does not authenticate itself to the kubelet HTTPS endpoints. Configure the apiserver to authenticate to kubelets by setting the --kubelet-certificate-authority flag.",
    rationale:
      "Without proper certificate verification, the API server may connect to compromised kubelets without detecting the impersonation, enabling man-in-the-middle attacks.",
    audit:
      "Run: ps -ef | grep kube-apiserver | grep kubelet-certificate-authority. Verify the flag is set with a valid CA bundle path.",
    remediation:
      "Edit the API server pod spec and set --kubelet-certificate-authority=<path/to/ca-bundle>. Restart the API server.",
  },
  {
    id: "CIS-K8S-4.2.1",
    title: "Ensure that the --anonymous-auth argument is set to false for kubelet",
    level: 1,
    description:
      "When enabled, requests to the kubelet that are not rejected by other configured authentication methods are treated as anonymous requests. These requests are then served by the kubelet server.",
    rationale:
      "Anonymous access to the kubelet API could allow unauthorized users to execute commands in containers, view logs, or access sensitive information about the node.",
    audit:
      "Run: ps -ef | grep kubelet | grep anonymous-auth. Verify --anonymous-auth=false is set. Check /var/lib/kubelet/config.yaml for authentication.anonymous.enabled: false.",
    remediation:
      "Set --anonymous-auth=false in the kubelet command line arguments or set authentication.anonymous.enabled to false in the kubelet config file.",
  },
  {
    id: "CIS-AWS-1.1",
    title: "Ensure IAM policies that allow full administrative privileges are not attached",
    level: 1,
    description:
      "IAM policies are the means by which privileges are granted to users, groups, or roles. It is recommended to apply the principle of least privilege and not use policies that grant full administrative access.",
    rationale:
      "Providing full administrative privileges when not needed increases the blast radius of a compromised credential. Following least privilege limits the potential impact of a security incident.",
    audit:
      "Run: aws iam list-policies --only-attached --output json | jq '.Policies[].Arn' and check for policies with Action:* and Resource:*.",
    remediation:
      "Create specific IAM policies that grant only the permissions required for each role. Remove or detach any policies granting full administrative access (Action: *, Resource: *).",
  },
  {
    id: "CIS-AWS-1.4",
    title: "Ensure no root account access key exists",
    level: 1,
    description:
      "The root account is the most privileged user in an AWS account. AWS access keys provide programmatic access to a given AWS account. It is recommended that all access keys associated with the root account be deleted.",
    rationale:
      "Root access keys provide unrestricted access to all resources in the AWS account. If compromised, an attacker would have complete control over the account with no ability to restrict their access.",
    audit:
      "Run: aws iam get-account-summary | grep AccountAccessKeysPresent. The value should be 0.",
    remediation:
      "Navigate to the IAM console, select the root user, and delete all access keys. Use IAM users with appropriate policies for programmatic access instead.",
  },
  {
    id: "CIS-AWS-2.1.1",
    title: "Ensure CloudTrail is enabled in all regions",
    level: 1,
    description:
      "AWS CloudTrail is a web service that records AWS API calls for your account and delivers log files to you. Enable CloudTrail in all regions to ensure complete visibility into account activity.",
    rationale:
      "Without CloudTrail enabled in all regions, an attacker could perform actions in an unmonitored region without generating audit logs, making incident investigation significantly harder.",
    audit:
      "Run: aws cloudtrail describe-trails --query 'trailList[*].{Name:Name,IsMulti:IsMultiRegionTrail}'. At least one trail should have IsMultiRegionTrail set to true.",
    remediation:
      "Create or update a CloudTrail trail with --is-multi-region-trail flag enabled. Ensure log file validation is enabled and logs are stored in an encrypted S3 bucket.",
  },
  {
    id: "CIS-AWS-3.5",
    title: "Ensure VPC flow logging is enabled in all VPCs",
    level: 2,
    description:
      "VPC Flow Logs capture information about IP traffic going to and from network interfaces in your VPC. Enable flow logs for all VPCs to maintain visibility into network traffic patterns.",
    rationale:
      "Flow logs provide visibility into network traffic patterns and can be used to detect anomalous traffic, investigate security incidents, and verify network access controls are functioning as intended.",
    audit:
      "Run: aws ec2 describe-vpcs --query 'Vpcs[*].VpcId' to get VPC IDs, then check each with aws ec2 describe-flow-logs --filter Name=resource-id,Values=<vpc-id>.",
    remediation:
      "Enable VPC flow logs for each VPC: aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name vpc-flow-logs.",
  },
  {
    id: "CIS-AWS-4.1",
    title: "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
    level: 1,
    description:
      "Security groups should not allow unrestricted inbound access to SSH (port 22) from any IPv4 address. Restrict SSH access to known IP ranges.",
    rationale:
      "Allowing unrestricted SSH access exposes the system to brute-force attacks and exploitation of SSH vulnerabilities from any source on the internet.",
    audit:
      "Run: aws ec2 describe-security-groups --filters Name=ip-permission.from-port,Values=22 Name=ip-permission.to-port,Values=22 Name=ip-permission.cidr,Values='0.0.0.0/0'. No results should be returned.",
    remediation:
      "Modify security group rules to restrict SSH access to specific CIDR ranges. Use Systems Manager Session Manager or EC2 Instance Connect as alternatives to direct SSH.",
  },
];

// ---------------------------------------------------------------------------
// PCI DSS v4.0 -- All 12 high-level requirements
// ---------------------------------------------------------------------------
const PCI_REQUIREMENTS = [
  {
    id: "PCI-1",
    title: "Install and Maintain Network Security Controls",
    description:
      "Network security controls (NSCs) such as firewalls and other network filtering technologies are points of policy enforcement controlling network traffic between two or more logical or physical network segments. NSCs must be installed, configured, and maintained to protect the cardholder data environment.",
    controls: [
      "Define and document firewall and router configuration standards",
      "Build firewall configurations that restrict connections between untrusted networks and the CDE",
      "Prohibit direct public access between the internet and the CDE",
      "Install personal firewall software on portable computing devices",
      "Document and implement security policies and operational procedures for managing NSCs",
    ],
    testingProcedures: [
      "Review firewall and router rule sets quarterly",
      "Verify network diagrams are accurate and reflect current topology",
      "Test that inbound and outbound traffic rules are properly restrictive",
      "Confirm DMZ implementation isolates the CDE from untrusted networks",
    ],
  },
  {
    id: "PCI-2",
    title: "Apply Secure Configurations to All System Components",
    description:
      "Malicious individuals often use vendor default passwords and other vendor default settings to compromise systems. These passwords and settings are well known by hacker communities and are easily determined through public information.",
    controls: [
      "Change all vendor-supplied defaults before installing a system on the network",
      "Remove or disable unnecessary default accounts",
      "Encrypt all non-console administrative access using strong cryptography",
      "Maintain an inventory of system components that are in scope for PCI DSS",
      "Develop configuration standards for all system components consistent with industry-accepted hardening standards",
    ],
    testingProcedures: [
      "Verify all default passwords have been changed on system components",
      "Verify unnecessary services, protocols, and daemons are disabled",
      "Confirm non-console administrative access is encrypted",
      "Review system configuration standards against CIS or vendor hardening guides",
    ],
  },
  {
    id: "PCI-3",
    title: "Protect Stored Account Data",
    description:
      "Protection methods such as encryption, truncation, masking, and hashing are critical components of cardholder data protection. If an intruder circumvents other security controls, the data remains unreadable without proper cryptographic keys.",
    controls: [
      "Implement data retention and disposal policies limiting storage amount and time",
      "Do not store sensitive authentication data after authorization",
      "Mask PAN when displayed, showing at most first six and last four digits",
      "Render PAN unreadable anywhere it is stored using strong cryptography",
      "Document and implement key management processes and procedures",
    ],
    testingProcedures: [
      "Verify data retention policies are implemented and data exceeding retention is purged",
      "Examine data stores to confirm sensitive authentication data is not stored post-authorization",
      "Review displays of PAN to verify proper masking",
      "Examine repositories and backup media to verify PAN is rendered unreadable",
    ],
  },
  {
    id: "PCI-4",
    title: "Protect Cardholder Data with Strong Cryptography During Transmission Over Open, Public Networks",
    description:
      "Sensitive information must be encrypted during transmission over networks that are easily accessed by malicious individuals. Misconfigured wireless networks and vulnerabilities in legacy encryption protocols continue to be targets for attackers.",
    controls: [
      "Use strong cryptography and security protocols to safeguard sensitive cardholder data during transmission",
      "Never send unprotected PANs by end-user messaging technologies",
      "Document and implement security policies for encrypting transmissions of cardholder data",
      "Ensure wireless networks transmitting cardholder data use industry best practices for strong encryption",
      "Maintain an inventory of trusted keys and certificates",
    ],
    testingProcedures: [
      "Verify that TLS 1.2 or higher is used for all cardholder data transmissions",
      "Verify that only trusted certificates are accepted",
      "Test that strong cipher suites are configured and weak ciphers are disabled",
      "Review messaging policies to confirm PAN is never sent via email, chat, or SMS",
    ],
  },
  {
    id: "PCI-5",
    title: "Protect All Systems and Networks from Malicious Software",
    description:
      "Malicious software (malware) enters the network through numerous business-approved activities including employee email and use of the internet, mobile computers, and storage devices. Anti-malware solutions must protect systems against current and evolving threats.",
    controls: [
      "Deploy anti-malware solutions on all systems commonly affected by malware",
      "Ensure anti-malware mechanisms are kept current and perform periodic scans",
      "Ensure anti-malware solutions are actively running and cannot be disabled by users",
      "Implement anti-phishing mechanisms to protect users against phishing attacks",
      "Evaluate systems not commonly affected by malware periodically to confirm no malware threat",
    ],
    testingProcedures: [
      "Verify anti-malware is deployed on all applicable system components",
      "Verify automatic updates are enabled and definitions are current",
      "Confirm real-time scanning is enabled and audit logs are generated",
      "Test that anti-malware cannot be disabled or altered by standard users",
    ],
  },
  {
    id: "PCI-6",
    title: "Develop and Maintain Secure Systems and Software",
    description:
      "Security vulnerabilities in custom and third-party software are constantly being discovered by attackers and researchers. Organizations must manage these vulnerabilities through timely patching and secure development practices.",
    controls: [
      "Establish a process to identify and assign risk rankings to newly discovered security vulnerabilities",
      "Install vendor-supplied security patches within an appropriate time frame",
      "Develop software applications in accordance with PCI DSS and secure coding guidelines",
      "Follow change management procedures for all changes to system components",
      "Address common coding vulnerabilities in software development processes",
    ],
    testingProcedures: [
      "Verify a process exists to identify and rank new vulnerabilities",
      "Confirm critical patches are installed within one month of release",
      "Review code changes for security impact before deployment to production",
      "Verify web applications are protected against OWASP Top 10 vulnerabilities",
    ],
  },
  {
    id: "PCI-7",
    title: "Restrict Access to System Components and Cardholder Data by Business Need to Know",
    description:
      "To ensure critical data can only be accessed by authorized personnel, systems and processes must be in place to limit access based on need to know and according to job responsibilities.",
    controls: [
      "Limit access to system components and cardholder data to only those individuals whose job requires such access",
      "Establish an access control system that restricts access based on a user's need to know",
      "Ensure the access control system is set to deny all unless specifically allowed",
      "Document and communicate access control policies to all affected parties",
      "Review access rights at least every six months",
    ],
    testingProcedures: [
      "Verify access policies define access needs for each role",
      "Confirm access control systems restrict access to need-to-know basis",
      "Test that default deny rules are in effect across all systems",
      "Review access control lists to verify they match documented policies",
    ],
  },
  {
    id: "PCI-8",
    title: "Identify Users and Authenticate Access to System Components",
    description:
      "Assigning a unique identification to each person with access ensures that actions taken on critical data and systems are performed by and can be traced to known and authorized users. Requirements apply to all accounts with access to the cardholder data environment.",
    controls: [
      "Assign all users a unique ID before allowing access to system components or cardholder data",
      "Implement multi-factor authentication for all remote network access",
      "Implement multi-factor authentication for all non-console administrative access",
      "Document and communicate authentication policies and procedures to all users",
      "Do not use group, shared, or generic accounts or other shared authentication credentials",
    ],
    testingProcedures: [
      "Verify each user has a unique ID for system access",
      "Confirm MFA is required for all remote and administrative access",
      "Test password parameters meet minimum complexity requirements",
      "Verify inactive accounts are disabled within 90 days",
    ],
  },
  {
    id: "PCI-9",
    title: "Restrict Physical Access to Cardholder Data",
    description:
      "Any physical access to cardholder data or systems that store, process, or transmit cardholder data provides the opportunity for individuals to access and remove devices, data, systems, or hardcopies, and should be appropriately restricted.",
    controls: [
      "Use appropriate facility entry controls to limit and monitor physical access to systems in the CDE",
      "Develop procedures to easily distinguish between onsite personnel and visitors",
      "Control physical access to sensitive areas for onsite personnel",
      "Implement procedures to identify and authorize visitors",
      "Physically secure all media containing cardholder data",
    ],
    testingProcedures: [
      "Verify physical access controls such as badge readers or locked doors are in place",
      "Test visitor management procedures including escorts and badge expiration",
      "Verify media destruction procedures render cardholder data unrecoverable",
      "Confirm video cameras or access control mechanisms monitor sensitive areas",
    ],
  },
  {
    id: "PCI-10",
    title: "Log and Monitor All Access to System Components and Cardholder Data",
    description:
      "Logging mechanisms and the ability to track user activities are critical in preventing, detecting, and minimizing the impact of a data compromise. Logs are essential to forensic investigation after a security incident.",
    controls: [
      "Implement audit trails to link all access to system components to each individual user",
      "Implement automated audit trails for all system components to reconstruct events",
      "Record audit trail entries for all system components for each event",
      "Synchronize all critical system clocks and times using time-synchronization technology",
      "Secure audit trails so they cannot be altered",
    ],
    testingProcedures: [
      "Verify audit logging is enabled and active on all system components",
      "Confirm audit logs record user identification, event type, date/time, success/failure, and affected data",
      "Test that audit trails are tamper-resistant and access is restricted",
      "Verify daily log reviews are performed either manually or via automated mechanisms",
    ],
  },
  {
    id: "PCI-11",
    title: "Test Security of Systems and Networks Regularly",
    description:
      "Vulnerabilities are being discovered continually by malicious individuals and researchers, and being introduced by new software. System components, processes, and custom software should be tested frequently to ensure security controls continue to be effective.",
    controls: [
      "Implement processes to test for the presence of wireless access points quarterly",
      "Run internal and external network vulnerability scans at least quarterly",
      "Implement a methodology for penetration testing",
      "Use network intrusion detection and/or prevention techniques to detect and/or prevent intrusions",
      "Deploy a change-detection mechanism to alert on unauthorized modification of critical files",
    ],
    testingProcedures: [
      "Verify quarterly internal vulnerability scans are performed and rescanned until passing results",
      "Confirm external scans are performed by a PCI SSC Approved Scanning Vendor (ASV)",
      "Review penetration test results and verify remediation of exploitable vulnerabilities",
      "Test IDS/IPS to confirm it is monitoring all traffic in the CDE",
    ],
  },
  {
    id: "PCI-12",
    title: "Support Information Security with Organizational Policies and Programs",
    description:
      "A strong security policy sets the security tone for the whole entity and informs personnel what is expected of them. All personnel should be aware of the sensitivity of cardholder data and their responsibilities for protecting it.",
    controls: [
      "Establish, publish, maintain, and disseminate a security policy",
      "Implement a risk assessment process that is performed at least annually",
      "Develop usage policies for critical technologies and define proper use",
      "Ensure the security policy and procedures clearly define information security responsibilities for all personnel",
      "Implement a formal security awareness program for all personnel",
    ],
    testingProcedures: [
      "Verify the information security policy is published and accessible to all relevant personnel",
      "Confirm annual risk assessments are conducted and documented",
      "Review the incident response plan and verify it is tested at least annually",
      "Verify security awareness training is provided upon hire and at least annually thereafter",
    ],
  },
];

// ---------------------------------------------------------------------------
// OWASP ASVS 4.0 -- Application Security Verification Standard
// ---------------------------------------------------------------------------
const OWASP_ASVS = [
  {
    id: "V2.1.1",
    category: "Authentication",
    title: "Verify that user set passwords are at least 12 characters in length",
    level: 1,
    description:
      "User-set passwords must be at least 12 characters in length after combining, trimming, and normalizing multiple spaces. Longer passwords provide significantly greater resistance against offline brute-force attacks.",
    verification:
      "Test password registration and change forms to confirm they reject passwords shorter than 12 characters. Verify server-side validation enforces the minimum independently of client-side checks.",
  },
  {
    id: "V2.1.2",
    category: "Authentication",
    title: "Verify that passwords of at least 64 characters are permitted",
    level: 1,
    description:
      "Applications must allow passwords of at least 64 characters. There must be no arbitrary maximum password length restriction that would prevent users from choosing strong passphrases.",
    verification:
      "Attempt to set a password of 64 characters and verify it is accepted. Test that passwords exceeding the maximum storage capacity are handled gracefully without truncation.",
  },
  {
    id: "V2.1.7",
    category: "Authentication",
    title: "Verify that passwords submitted during account registration and update are checked against a set of breached passwords",
    level: 1,
    description:
      "New passwords must be checked against a list of commonly breached passwords (such as the Have I Been Pwned dataset) and rejected if found. This prevents users from choosing passwords that are already known to attackers.",
    verification:
      "Register a new account using a known breached password (e.g., 'Password123!') and verify it is rejected with an appropriate error message explaining why.",
  },
  {
    id: "V2.2.1",
    category: "Authentication",
    title: "Verify that anti-automation controls are effective at mitigating breached credential testing and brute-force attacks",
    level: 1,
    description:
      "The application must implement anti-automation controls such as rate limiting, CAPTCHA, account lockout, or increasing delays to prevent automated attacks against authentication endpoints.",
    verification:
      "Attempt rapid successive login attempts with invalid credentials and verify that rate limiting or lockout mechanisms are triggered after a reasonable number of failed attempts.",
  },
  {
    id: "V2.8.1",
    category: "Authentication",
    title: "Verify that time-based OTP can be used as a second authentication factor",
    level: 1,
    description:
      "Support time-based one-time passwords (TOTP) as a multi-factor authentication option. The application should support standard TOTP implementations compatible with authenticator applications.",
    verification:
      "Enable TOTP for a test account and verify successful authentication using a standards-compliant authenticator app. Test that the OTP is validated server-side and that replay of used OTPs is rejected.",
  },
  {
    id: "V3.2.1",
    category: "Session Management",
    title: "Verify that the application generates a new session token on user authentication",
    level: 1,
    description:
      "The application must generate a new session token upon successful authentication and must not reuse pre-authentication session identifiers. This prevents session fixation attacks.",
    verification:
      "Record the session token before authentication. Authenticate and compare the session token after login. Verify it has changed. Test that the old session token is invalidated.",
  },
  {
    id: "V3.3.1",
    category: "Session Management",
    title: "Verify that logout and expiration invalidate the session token",
    level: 1,
    description:
      "When a user logs out or a session times out, the session token must be invalidated on the server side. Subsequent requests using the old session token must be rejected.",
    verification:
      "Capture a valid session token. Log out. Attempt to reuse the captured session token in a new request. Verify the server rejects the request with an appropriate error.",
  },
  {
    id: "V3.5.1",
    category: "Session Management",
    title: "Verify that the application allows users to revoke OAuth tokens that form trust relationships with linked applications",
    level: 1,
    description:
      "Users must have the ability to review and revoke OAuth access tokens that have been granted to third-party applications. This gives users control over which applications can access their data.",
    verification:
      "Navigate to account settings and verify a list of authorized applications is displayed. Revoke access for one application and verify subsequent API calls from that application are rejected.",
  },
  {
    id: "V4.1.1",
    category: "Access Control",
    title: "Verify that the application enforces access control rules on a trusted service layer",
    level: 1,
    description:
      "Access control enforcement must occur on the server side or a trusted service layer where it cannot be bypassed by the client. Client-side access control checks are insufficient.",
    verification:
      "Attempt to access protected resources by directly crafting HTTP requests, bypassing client-side controls. Verify the server enforces authorization independently of client-side logic.",
  },
  {
    id: "V4.1.2",
    category: "Access Control",
    title: "Verify that all user and data attributes and policy information used by access controls cannot be manipulated by end users unless specifically authorized",
    level: 1,
    description:
      "Access control attributes such as user roles, permissions, and security labels must not be modifiable by end users through parameter tampering, forced browsing, or other manipulation techniques.",
    verification:
      "Attempt to modify role parameters in requests (e.g., changing role=user to role=admin in POST data or cookies). Verify the server rejects unauthorized role escalation attempts.",
  },
  {
    id: "V4.2.1",
    category: "Access Control",
    title: "Verify that sensitive data and APIs are protected against Insecure Direct Object Reference (IDOR) attacks",
    level: 1,
    description:
      "The application must validate that the authenticated user has permission to access each requested resource. Sequential or guessable resource identifiers must not allow unauthorized access.",
    verification:
      "Authenticate as User A. Attempt to access resources belonging to User B by modifying object identifiers in API requests. Verify the server returns a 403 Forbidden or 404 Not Found response.",
  },
  {
    id: "V5.1.1",
    category: "Input Validation",
    title: "Verify that the application has defenses against HTTP parameter pollution attacks",
    level: 1,
    description:
      "The application must handle duplicate HTTP parameters consistently and securely. Parameter pollution can lead to logic bypasses when different application layers interpret duplicate parameters differently.",
    verification:
      "Submit requests with duplicate parameter names (e.g., ?amount=100&amount=1). Verify the application handles them consistently and does not allow logic bypass through parameter duplication.",
  },
  {
    id: "V5.2.1",
    category: "Input Validation",
    title: "Verify that all untrusted HTML input from WYSIWYG editors or similar is properly sanitized with an HTML sanitizer library",
    level: 1,
    description:
      "Rich text input from WYSIWYG editors or Markdown converters must be sanitized to remove dangerous HTML elements and attributes. Use a well-tested HTML sanitization library rather than custom regex-based filtering.",
    verification:
      "Submit HTML content containing script tags, event handlers (onerror, onload), and other XSS vectors through rich text input fields. Verify dangerous elements are stripped or escaped in the output.",
  },
  {
    id: "V5.3.1",
    category: "Input Validation",
    title: "Verify that output encoding is relevant for the interpreter and context required",
    level: 1,
    description:
      "Output encoding must be appropriate for the context where data is rendered (HTML body, HTML attribute, JavaScript, CSS, URL). Using the wrong encoding for a context fails to prevent injection attacks.",
    verification:
      "Inject context-specific payloads (HTML entities in HTML context, JavaScript encoding in JS context) and verify appropriate encoding is applied for each output context.",
  },
  {
    id: "V6.1.1",
    category: "Cryptography",
    title: "Verify that regulated private data is stored encrypted while at rest",
    level: 1,
    description:
      "Sensitive data subject to regulatory requirements must be encrypted when stored. Encryption at rest protects data in the event of unauthorized access to storage media, backups, or database dumps.",
    verification:
      "Examine database schemas and file storage for regulated data. Verify encryption is applied at the application, database, or filesystem level. Confirm encryption keys are managed separately from the encrypted data.",
  },
  {
    id: "V6.2.1",
    category: "Cryptography",
    title: "Verify that all cryptographic modules fail securely and errors are handled in a way that does not enable oracle attacks",
    level: 1,
    description:
      "Cryptographic operations must fail securely by not revealing information about the nature of the failure. Error messages must not differentiate between padding errors, decryption errors, or verification errors.",
    verification:
      "Submit malformed ciphertexts and observe error responses. Verify that error messages are generic and do not reveal whether the error was due to padding, key mismatch, or data corruption.",
  },
  {
    id: "V7.1.1",
    category: "Error Handling and Logging",
    title: "Verify that the application does not log credentials or payment details",
    level: 1,
    description:
      "Application logs must not contain sensitive data such as passwords, credit card numbers, tokens, or session identifiers. Logging sensitive data creates an additional attack vector and may violate compliance requirements.",
    verification:
      "Review application log output during authentication, payment processing, and error conditions. Search logs for patterns matching credentials, card numbers, or session tokens. Verify none are present.",
  },
  {
    id: "V7.1.2",
    category: "Error Handling and Logging",
    title: "Verify that the application does not log other sensitive data as defined under local privacy laws or relevant security policy",
    level: 1,
    description:
      "Beyond credentials, the application must not log personally identifiable information (PII) or other data classified as sensitive under applicable privacy regulations (GDPR, CCPA, HIPAA, etc.).",
    verification:
      "Review log output for PII such as social security numbers, dates of birth, medical records, or biometric data. Verify sensitive data is either excluded from logs or masked/tokenized.",
  },
  {
    id: "V8.1.1",
    category: "Data Protection",
    title: "Verify that the application protects sensitive data from being cached in server components such as load balancers and application caches",
    level: 1,
    description:
      "Responses containing sensitive data must include appropriate cache-control headers to prevent caching by intermediaries. Sensitive data cached in shared components may be accessible to unauthorized users.",
    verification:
      "Examine HTTP response headers for pages containing sensitive data. Verify Cache-Control: no-store and Pragma: no-cache headers are present. Test that intermediary caches do not serve stale sensitive content.",
  },
  {
    id: "V8.3.1",
    category: "Data Protection",
    title: "Verify that sensitive data is sent to the server in the HTTP message body or headers and that query string parameters do not contain sensitive data",
    level: 2,
    description:
      "Sensitive data such as credentials, tokens, and PII must not be transmitted in URL query strings. Query strings may be logged by web servers, proxy servers, and browser history, exposing sensitive data.",
    verification:
      "Review all forms and API calls that transmit sensitive data. Verify POST method is used instead of GET for sensitive data submission. Check server logs for sensitive query parameters.",
  },
  {
    id: "V9.1.1",
    category: "Communications",
    title: "Verify that TLS is used for all client connectivity and does not fall back to insecure or unencrypted communications",
    level: 1,
    description:
      "All client-server communications must use TLS. The application must not fall back to unencrypted HTTP or other insecure protocols. HTTP-to-HTTPS redirects must occur before any sensitive data is transmitted.",
    verification:
      "Test all application endpoints over HTTP and verify they redirect to HTTPS before processing the request. Verify HSTS headers are present. Test that the application rejects SSLv3, TLS 1.0, and TLS 1.1 connections.",
  },
  {
    id: "V9.1.2",
    category: "Communications",
    title: "Verify that connections to and from the server use trusted TLS certificates",
    level: 1,
    description:
      "The server must present a valid, non-expired TLS certificate issued by a trusted certificate authority. The application must validate server certificates when making outbound connections and reject self-signed or invalid certificates.",
    verification:
      "Verify the server certificate is valid and issued by a trusted CA. Attempt to connect using an expired or self-signed certificate and verify the connection is rejected. Check certificate chain completeness.",
  },
  {
    id: "V14.2.1",
    category: "HTTP Security",
    title: "Verify that all responses contain a Content-Type header with a safe character set",
    level: 1,
    description:
      "All HTTP responses must include a Content-Type header specifying the correct MIME type and character set. Missing or incorrect Content-Type headers can lead to MIME-sniffing vulnerabilities and XSS attacks.",
    verification:
      "Inspect HTTP response headers for all endpoints. Verify Content-Type is present with an appropriate MIME type and charset=utf-8 (or appropriate charset). Verify X-Content-Type-Options: nosniff is present.",
  },
  {
    id: "V14.4.1",
    category: "HTTP Security",
    title: "Verify that every HTTP response contains a Content-Security-Policy header",
    level: 1,
    description:
      "A Content-Security-Policy (CSP) header must be present in all HTTP responses to mitigate cross-site scripting and data injection attacks. The policy should restrict script sources and object sources to trusted origins.",
    verification:
      "Inspect HTTP response headers and verify a Content-Security-Policy header is present. Verify the policy does not include 'unsafe-inline' or 'unsafe-eval' for script-src. Test that inline scripts are blocked by the policy.",
  },
];

module.exports = { NIST_CONTROLS, CIS_BENCHMARKS, PCI_REQUIREMENTS, OWASP_ASVS };
