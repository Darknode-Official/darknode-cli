"use strict";
// ---------------------------------------------------------------------------
// compliance-data.js -- Comprehensive compliance framework reference data
// ---------------------------------------------------------------------------
// Covers NIST CSF, CIS Controls v8, PCI DSS v4, ISO 27001:2022,
// SOC 2 TSC, HIPAA Safeguards, and GDPR key articles.
// Each control entry carries: id, title, description, implementation, evidence.
// Helpers at the bottom: checkCompliance(), generateComplianceReport().
// ---------------------------------------------------------------------------

// ===================================================================
//  1. NIST CYBERSECURITY FRAMEWORK (CSF) v1.1
//     5 Functions  ->  23 Categories  ->  108 Subcategory controls
// ===================================================================

const NIST_CSF = {
  version: "1.1",
  name: "NIST Cybersecurity Framework",
  description: "Voluntary framework consisting of standards, guidelines, and best practices to manage cybersecurity-related risk.",
  functions: [
    // -----------------------------------------------------------------
    //  IDENTIFY (ID)
    // -----------------------------------------------------------------
    {
      id: "ID",
      name: "Identify",
      description: "Develop organizational understanding to manage cybersecurity risk to systems, people, assets, data, and capabilities.",
      categories: [
        {
          id: "ID.AM",
          name: "Asset Management",
          description: "The data, personnel, devices, systems, and facilities that enable the organization to achieve business purposes are identified and managed consistent with their relative importance to organizational objectives and the organization's risk strategy.",
          controls: [
            {
              id: "ID.AM-1",
              title: "Physical Device Inventory",
              description: "Physical devices and systems within the organization are inventoried.",
              implementation: "Deploy automated asset discovery tools that continuously scan the network for physical devices. Maintain a centralized Configuration Management Database (CMDB) with fields for device type, owner, location, firmware version, and criticality rating. Reconcile discovered devices against the inventory on a weekly basis and investigate any discrepancies.",
              evidence: "Asset inventory database exports, network scan results, reconciliation reports, CMDB change logs, and device onboarding/offboarding records."
            },
            {
              id: "ID.AM-2",
              title: "Software Platform Inventory",
              description: "Software platforms and applications within the organization are inventoried.",
              implementation: "Use software asset management (SAM) tools to discover and catalog all installed software across endpoints and servers. Track license entitlements, version numbers, vendor support status, and deployment counts. Flag unauthorized or end-of-life software for remediation.",
              evidence: "SAM tool reports, software license records, approved software baseline lists, and exception request forms for non-standard software."
            },
            {
              id: "ID.AM-3",
              title: "Communication and Data Flow Mapping",
              description: "Organizational communication and data flows are mapped.",
              implementation: "Create and maintain data flow diagrams (DFDs) for all critical business processes. Document network segmentation boundaries, data classification labels at each transit point, and external data sharing agreements. Use network traffic analysis to validate documented flows against actual behavior.",
              evidence: "Data flow diagrams, network topology maps, traffic analysis reports, data sharing agreements, and boundary protection device configurations."
            },
            {
              id: "ID.AM-4",
              title: "External Information System Catalog",
              description: "External information systems are catalogued.",
              implementation: "Maintain a register of all third-party services, cloud platforms, SaaS applications, and external APIs consumed by the organization. Record data classification of information shared, contractual obligations, SLA details, and last assessment date for each entry.",
              evidence: "Third-party service register, vendor risk assessment records, contract summaries, API integration documentation, and cloud service inventories."
            },
            {
              id: "ID.AM-5",
              title: "Resource Prioritization",
              description: "Resources (e.g., hardware, devices, data, time, personnel, and software) are prioritized based on their classification, criticality, and business value.",
              implementation: "Establish a classification scheme (e.g., Public, Internal, Confidential, Restricted) and apply it to all inventoried assets. Conduct business impact analysis (BIA) to determine criticality tiers. Align resource allocation, patching priority, and incident response playbooks with these classifications.",
              evidence: "Asset classification records, BIA reports, criticality tier assignments, resource allocation matrices, and classification policy documents."
            },
            {
              id: "ID.AM-6",
              title: "Cybersecurity Roles and Responsibilities",
              description: "Cybersecurity roles and responsibilities for the entire workforce and third-party stakeholders are established.",
              implementation: "Define cybersecurity responsibilities in job descriptions, RACI matrices, and organizational charts. Ensure third-party contracts include security responsibility clauses. Conduct annual reviews of role assignments and update as organizational structure changes.",
              evidence: "Job descriptions with security duties, RACI matrices, organizational charts, third-party contract security clauses, and annual role review records."
            }
          ]
        },
        {
          id: "ID.BE",
          name: "Business Environment",
          description: "The organization's mission, objectives, stakeholders, and activities are understood and prioritized; this information is used to inform cybersecurity roles, responsibilities, and risk management decisions.",
          controls: [
            {
              id: "ID.BE-1",
              title: "Supply Chain Role Identification",
              description: "The organization's role in the supply chain is identified and communicated.",
              implementation: "Document the organization's position within its supply chain ecosystem, including upstream suppliers and downstream customers. Identify critical dependencies and single points of failure. Communicate cybersecurity expectations to supply chain partners through formal agreements.",
              evidence: "Supply chain maps, dependency analysis documents, partner communication records, contractual security requirements, and supply chain risk assessments."
            },
            {
              id: "ID.BE-2",
              title: "Critical Infrastructure Role",
              description: "The organization's place in critical infrastructure and its industry sector is identified and communicated.",
              implementation: "Determine whether the organization operates within or supports critical infrastructure sectors as defined by national frameworks. Register with relevant sector-specific ISACs. Align security practices with sector-specific guidelines and regulations.",
              evidence: "Sector classification documentation, ISAC membership records, sector-specific compliance assessments, and regulatory correspondence."
            },
            {
              id: "ID.BE-3",
              title: "Mission and Objectives Priority",
              description: "Priorities for organizational mission, objectives, and activities are established and communicated.",
              implementation: "Document organizational mission and strategic objectives. Establish how cybersecurity supports and enables these objectives. Create a priority matrix that aligns security investments with business goals and communicate priorities across the organization.",
              evidence: "Strategic planning documents, mission statements, cybersecurity strategy alignment papers, priority matrices, and board-level security briefings."
            },
            {
              id: "ID.BE-4",
              title: "Critical Service Dependencies",
              description: "Dependencies and critical functions for delivery of critical services are established.",
              implementation: "Perform dependency mapping for all critical services, identifying technology, personnel, supplier, and facility dependencies. Establish minimum viable service definitions and document recovery priorities. Test dependency assumptions through tabletop exercises.",
              evidence: "Service dependency maps, critical function registers, minimum viable service documents, tabletop exercise reports, and business continuity plans."
            },
            {
              id: "ID.BE-5",
              title: "Resilience Requirements",
              description: "Resilience requirements to support delivery of critical services are established for all operating states.",
              implementation: "Define recovery time objectives (RTO) and recovery point objectives (RPO) for critical services. Establish resilience requirements for normal operations, during an attack, and during recovery. Ensure infrastructure design meets these requirements through redundancy, failover, and backup strategies.",
              evidence: "RTO/RPO documentation, resilience requirement specifications, infrastructure design reviews, failover test results, and backup verification reports."
            }
          ]
        },
        {
          id: "ID.GV",
          name: "Governance",
          description: "The policies, procedures, and processes to manage and monitor the organization's regulatory, legal, risk, environmental, and operational requirements are understood and inform the management of cybersecurity risk.",
          controls: [
            {
              id: "ID.GV-1",
              title: "Security Policy Establishment",
              description: "Organizational cybersecurity policy is established and communicated.",
              implementation: "Develop a comprehensive information security policy framework including an overarching security policy and supporting topic-specific policies (access control, data protection, incident response, etc.). Obtain executive approval, publish policies to all personnel, and require acknowledgment. Review and update policies at least annually.",
              evidence: "Approved policy documents, policy acknowledgment records, policy review schedules, executive approval signatures, and policy distribution logs."
            },
            {
              id: "ID.GV-2",
              title: "Regulatory Alignment",
              description: "Cybersecurity roles and responsibilities are coordinated and aligned with internal roles and external partners.",
              implementation: "Map cybersecurity responsibilities across internal teams and external partners using RACI charts. Ensure alignment between legal, compliance, IT, security, and business units. Establish joint operating procedures with key external partners and review alignment quarterly.",
              evidence: "RACI matrices, joint operating procedures, coordination meeting minutes, inter-departmental agreements, and quarterly alignment review records."
            },
            {
              id: "ID.GV-3",
              title: "Legal and Regulatory Compliance",
              description: "Legal and regulatory requirements regarding cybersecurity, including privacy and civil liberties obligations, are understood and managed.",
              implementation: "Maintain a register of all applicable legal, regulatory, and contractual cybersecurity requirements. Map each requirement to specific controls and responsible parties. Monitor for regulatory changes and assess impact. Engage legal counsel for interpretation of complex requirements.",
              evidence: "Regulatory requirement register, control mapping documents, regulatory change monitoring logs, legal counsel opinions, and compliance assessment reports."
            },
            {
              id: "ID.GV-4",
              title: "Governance and Risk Process",
              description: "Governance and risk management processes address cybersecurity risks.",
              implementation: "Integrate cybersecurity risk into the enterprise risk management (ERM) framework. Establish a risk governance committee with cybersecurity representation. Define risk appetite, tolerance levels, and escalation procedures. Report cybersecurity risk metrics to executive leadership and the board regularly.",
              evidence: "ERM framework documentation, risk committee charters, risk appetite statements, risk register entries, board risk reports, and meeting minutes."
            }
          ]
        },
        {
          id: "ID.RA",
          name: "Risk Assessment",
          description: "The organization understands the cybersecurity risk to organizational operations, assets, and individuals.",
          controls: [
            {
              id: "ID.RA-1",
              title: "Vulnerability Identification",
              description: "Asset vulnerabilities are identified and documented.",
              implementation: "Conduct regular vulnerability scanning of all network-connected assets using authenticated scans. Perform penetration testing at least annually and after significant changes. Maintain a vulnerability database with severity ratings, affected assets, and remediation status. Integrate vulnerability data with the asset inventory.",
              evidence: "Vulnerability scan reports, penetration test reports, vulnerability database exports, remediation tracking records, and scan coverage metrics."
            },
            {
              id: "ID.RA-2",
              title: "Threat Intelligence",
              description: "Cyber threat intelligence is received from information sharing forums and sources.",
              implementation: "Subscribe to threat intelligence feeds relevant to the organization's industry and technology stack. Participate in ISACs and threat sharing communities. Establish processes to ingest, analyze, and operationalize threat intelligence. Correlate threat data with organizational assets and vulnerabilities.",
              evidence: "Threat intelligence feed subscriptions, ISAC membership records, threat intelligence analysis reports, indicator of compromise (IOC) databases, and threat briefing records."
            },
            {
              id: "ID.RA-3",
              title: "Threat Identification",
              description: "Threats, both internal and external, are identified and documented.",
              implementation: "Maintain a threat catalog documenting known threat actors, tactics, techniques, and procedures (TTPs) relevant to the organization. Conduct threat modeling for critical systems and applications. Assess insider threat risks through behavioral analysis and access pattern monitoring.",
              evidence: "Threat catalogs, threat modeling outputs, MITRE ATT&CK mapping documents, insider threat assessment reports, and threat landscape briefings."
            },
            {
              id: "ID.RA-4",
              title: "Business Impact Identification",
              description: "Potential business impacts and likelihoods are identified.",
              implementation: "Conduct business impact analysis for identified threats and vulnerabilities. Quantify potential financial, operational, reputational, and legal impacts. Estimate likelihood using historical data, threat intelligence, and expert judgment. Maintain impact and likelihood matrices for risk prioritization.",
              evidence: "Business impact analysis reports, impact quantification worksheets, likelihood assessment records, risk matrices, and scenario analysis documentation."
            },
            {
              id: "ID.RA-5",
              title: "Risk Determination",
              description: "Threats, vulnerabilities, likelihoods, and impacts are used to determine risk.",
              implementation: "Apply a consistent risk scoring methodology (e.g., CVSS, FAIR, or custom qualitative/quantitative model) combining threat, vulnerability, likelihood, and impact data. Rank risks by severity. Present risk determinations to the risk governance committee for acceptance, mitigation, transfer, or avoidance decisions.",
              evidence: "Risk assessment reports, risk scoring calculations, risk register with rankings, risk treatment decisions, and risk governance committee meeting records."
            },
            {
              id: "ID.RA-6",
              title: "Risk Response Identification",
              description: "Risk responses are identified and prioritized.",
              implementation: "For each identified risk above the tolerance threshold, develop response options: accept, mitigate, transfer, or avoid. Cost-benefit analysis informs prioritization. Document risk response plans with owners, timelines, and success criteria. Track implementation of risk responses and reassess residual risk.",
              evidence: "Risk response plans, cost-benefit analyses, risk treatment registers, response implementation tracking, and residual risk assessments."
            }
          ]
        },
        {
          id: "ID.RM",
          name: "Risk Management Strategy",
          description: "The organization's priorities, constraints, risk tolerances, and assumptions are established and used to support operational risk decisions.",
          controls: [
            {
              id: "ID.RM-1",
              title: "Risk Management Process",
              description: "Risk management processes are established, managed, and agreed to by organizational stakeholders.",
              implementation: "Document and formally approve a risk management process that covers risk identification, assessment, treatment, monitoring, and communication. Ensure stakeholder buy-in from executive leadership, business units, and IT. Review the process annually and after significant organizational changes.",
              evidence: "Risk management process documentation, stakeholder approval records, process review logs, and organizational change assessment records."
            },
            {
              id: "ID.RM-2",
              title: "Risk Tolerance Determination",
              description: "Organizational risk tolerance is determined and clearly expressed.",
              implementation: "Define risk tolerance levels for different risk categories (financial, operational, reputational, compliance). Express tolerances in measurable terms where possible. Communicate risk tolerance to all decision-makers and integrate into risk assessment processes.",
              evidence: "Risk tolerance statements, risk appetite framework documents, board-approved risk tolerance levels, and communication records."
            },
            {
              id: "ID.RM-3",
              title: "Risk Tolerance Informed by Role",
              description: "The organization's determination of risk tolerance is informed by its role in critical infrastructure and sector-specific risk analysis.",
              implementation: "Consider the organization's critical infrastructure role when setting risk tolerance. Incorporate sector-specific threat landscapes and regulatory expectations. Adjust tolerance levels to reflect the potential cascading effects of cyber incidents on the broader ecosystem.",
              evidence: "Sector-specific risk analysis reports, critical infrastructure dependency assessments, risk tolerance adjustment justifications, and regulatory alignment documentation."
            }
          ]
        },
        {
          id: "ID.SC",
          name: "Supply Chain Risk Management",
          description: "The organization's priorities, constraints, risk tolerances, and assumptions are established and used to support risk decisions associated with managing supply chain risk.",
          controls: [
            {
              id: "ID.SC-1",
              title: "Supply Chain Risk Process",
              description: "Cyber supply chain risk management processes are identified, established, assessed, managed, and agreed to by organizational stakeholders.",
              implementation: "Establish a formal supply chain risk management (SCRM) program with executive sponsorship. Define processes for identifying, assessing, and mitigating supply chain cybersecurity risks. Include SCRM considerations in procurement and vendor management workflows.",
              evidence: "SCRM program charter, process documentation, executive approval records, procurement policy updates, and vendor management procedure revisions."
            },
            {
              id: "ID.SC-2",
              title: "Supplier Assessment",
              description: "Suppliers and third-party partners of information systems, components, and services are identified, prioritized, and assessed using a cyber supply chain risk assessment process.",
              implementation: "Maintain a comprehensive supplier registry with criticality ratings. Conduct cybersecurity due diligence assessments for all suppliers based on criticality tier. Assess suppliers at onboarding and at least annually thereafter. Use standardized questionnaires, certifications review, and where warranted, on-site assessments.",
              evidence: "Supplier registry, criticality tier assignments, due diligence assessment reports, questionnaire responses, certification copies, and on-site assessment records."
            },
            {
              id: "ID.SC-3",
              title: "Contractual Requirements",
              description: "Contracts with suppliers and third-party partners are used to implement appropriate measures designed to meet the objectives of an organization's cybersecurity program and Cyber Supply Chain Risk Management Plan.",
              implementation: "Include cybersecurity requirements in all supplier contracts covering data protection, incident notification, audit rights, compliance obligations, and termination provisions. Define service level agreements (SLAs) for security-related metrics. Review and update contractual language as requirements evolve.",
              evidence: "Contract templates with security clauses, executed contracts, SLA documentation, contract review records, and legal counsel approval of security terms."
            },
            {
              id: "ID.SC-4",
              title: "Supplier Monitoring",
              description: "Suppliers and third-party partners are routinely assessed using audits, test results, or other forms of evaluations to confirm they are meeting their contractual obligations.",
              implementation: "Implement continuous or periodic monitoring of supplier security posture. Review SOC reports, penetration test results, and compliance certifications. Conduct periodic audits of high-criticality suppliers. Track and follow up on identified deficiencies.",
              evidence: "Supplier monitoring reports, SOC report reviews, audit findings, corrective action plans, certification tracking records, and deficiency follow-up logs."
            },
            {
              id: "ID.SC-5",
              title: "Supply Chain Testing",
              description: "Response and recovery planning and testing are conducted with suppliers and third-party providers.",
              implementation: "Include critical suppliers in incident response and business continuity testing exercises. Conduct joint tabletop exercises simulating supply chain disruption scenarios. Validate supplier recovery capabilities and communication procedures. Document lessons learned and update plans accordingly.",
              evidence: "Joint exercise plans, exercise participation records, exercise after-action reports, lessons learned documentation, and updated response/recovery plans."
            }
          ]
        }
      ]
    },
    // -----------------------------------------------------------------
    //  PROTECT (PR)
    // -----------------------------------------------------------------
    {
      id: "PR",
      name: "Protect",
      description: "Develop and implement appropriate safeguards to ensure delivery of critical services.",
      categories: [
        {
          id: "PR.AC",
          name: "Identity Management, Authentication, and Access Control",
          description: "Access to physical and logical assets and associated facilities is limited to authorized users, processes, and devices, and is managed consistent with the assessed risk of unauthorized access.",
          controls: [
            {
              id: "PR.AC-1",
              title: "Identity and Credential Management",
              description: "Identities and credentials are issued, managed, verified, revoked, and audited for authorized devices, users, and processes.",
              implementation: "Implement a centralized identity management system (e.g., Active Directory, LDAP, or cloud IdP). Enforce unique identity assignment for all users and service accounts. Establish credential lifecycle procedures covering issuance, rotation, suspension, and revocation. Conduct quarterly access reviews.",
              evidence: "Identity management system configurations, credential lifecycle procedure documents, access review reports, account provisioning/deprovisioning logs, and orphaned account audit results."
            },
            {
              id: "PR.AC-2",
              title: "Physical Access Control",
              description: "Physical access to assets is managed and protected.",
              implementation: "Implement physical access controls including badge readers, biometric authentication, visitor management, and security cameras for sensitive areas. Maintain physical access logs. Conduct periodic reviews of physical access privileges and investigate unauthorized access attempts.",
              evidence: "Physical access control system configurations, access badge assignment records, visitor logs, security camera footage retention policies, physical access review reports, and incident reports for unauthorized access."
            },
            {
              id: "PR.AC-3",
              title: "Remote Access Management",
              description: "Remote access is managed.",
              implementation: "Implement VPN or zero-trust network access (ZTNA) solutions for remote connectivity. Require multi-factor authentication for all remote access. Monitor remote sessions for anomalous activity. Restrict remote access to approved devices meeting security baseline requirements.",
              evidence: "Remote access solution configurations, MFA enrollment records, remote access policies, session monitoring logs, device compliance check results, and remote access usage reports."
            },
            {
              id: "PR.AC-4",
              title: "Access Permissions Management",
              description: "Access permissions and authorizations are managed, incorporating the principles of least privilege and separation of duties.",
              implementation: "Implement role-based access control (RBAC) with documented role definitions. Apply least privilege principles to all access grants. Enforce separation of duties for critical functions. Conduct periodic access certification campaigns where managers verify subordinate access appropriateness.",
              evidence: "RBAC role definitions, access provisioning procedures, least privilege policy documents, separation of duties matrices, access certification campaign results, and privilege escalation logs."
            },
            {
              id: "PR.AC-5",
              title: "Network Integrity Protection",
              description: "Network integrity is protected (e.g., network segregation, network segmentation).",
              implementation: "Implement network segmentation using VLANs, firewalls, and micro-segmentation technologies. Isolate sensitive environments (PCI, HIPAA) from general-purpose networks. Deploy DMZs for internet-facing services. Validate segmentation effectiveness through penetration testing and traffic analysis.",
              evidence: "Network architecture diagrams, firewall rule sets, VLAN configurations, micro-segmentation policies, penetration test results validating segmentation, and traffic analysis reports."
            },
            {
              id: "PR.AC-6",
              title: "Identity Proofing",
              description: "Identities are proofed and bound to credentials and asserted in interactions.",
              implementation: "Establish identity proofing procedures appropriate to the risk level of the access being granted. Verify identity through government-issued documentation, background checks, or trusted referral processes. Bind verified identities to strong credentials (certificates, hardware tokens, biometrics).",
              evidence: "Identity proofing procedure documents, verification records, background check results, credential binding records, and identity assurance level classifications."
            },
            {
              id: "PR.AC-7",
              title: "Authentication Mechanisms",
              description: "Users, devices, and other assets are authenticated (e.g., single-factor, multi-factor) commensurate with the risk of the transaction.",
              implementation: "Implement multi-factor authentication (MFA) for all privileged access, remote access, and access to sensitive data. Deploy risk-adaptive authentication that increases assurance requirements for higher-risk transactions. Support passwordless authentication methods where feasible.",
              evidence: "MFA configuration records, authentication policy documents, risk-adaptive authentication rule sets, authentication success/failure logs, and passwordless enrollment statistics."
            }
          ]
        },
        {
          id: "PR.AT",
          name: "Awareness and Training",
          description: "The organization's personnel and partners are provided cybersecurity awareness education and are trained to perform their cybersecurity-related duties and responsibilities consistent with related policies, procedures, and agreements.",
          controls: [
            {
              id: "PR.AT-1",
              title: "User Awareness Training",
              description: "All users are informed and trained.",
              implementation: "Deliver annual cybersecurity awareness training to all employees covering phishing, social engineering, password hygiene, data handling, and incident reporting. Supplement with monthly micro-learning modules and simulated phishing campaigns. Track completion rates and remediate non-compliance.",
              evidence: "Training curriculum documents, training completion records, phishing simulation results, awareness campaign materials, and non-compliance remediation records."
            },
            {
              id: "PR.AT-2",
              title: "Privileged User Training",
              description: "Privileged users understand their roles and responsibilities.",
              implementation: "Provide specialized security training for privileged users covering secure administration practices, credential protection, change management, and audit log review. Require certification in relevant technologies. Conduct annual refresher training with updated threat scenarios.",
              evidence: "Privileged user training materials, completion certificates, role-specific training records, technology certification copies, and refresher training attendance logs."
            },
            {
              id: "PR.AT-3",
              title: "Stakeholder Training",
              description: "Third-party stakeholders (e.g., suppliers, customers, partners) understand their roles and responsibilities.",
              implementation: "Communicate security expectations to third-party stakeholders through onboarding materials, contractual requirements, and periodic updates. Provide access to relevant security awareness resources. Verify stakeholder understanding through acknowledgment forms or assessments.",
              evidence: "Third-party onboarding materials, security expectation communications, stakeholder acknowledgment forms, assessment results, and contractual training requirements."
            },
            {
              id: "PR.AT-4",
              title: "Executive Training",
              description: "Senior executives understand their roles and responsibilities.",
              implementation: "Provide executive-level cybersecurity briefings covering organizational risk posture, regulatory obligations, fiduciary responsibilities, and current threat landscape. Conduct tabletop exercises involving executive leadership. Ensure executives understand their role in incident response and crisis communication.",
              evidence: "Executive briefing materials, tabletop exercise records, executive participation logs, board presentation materials, and executive acknowledgment forms."
            },
            {
              id: "PR.AT-5",
              title: "Security Personnel Training",
              description: "Physical and cybersecurity personnel understand their roles and responsibilities.",
              implementation: "Provide advanced technical training for security operations personnel covering threat detection, incident response, forensics, and security tool administration. Support professional development through certification programs (CISSP, CEH, GCIH). Conduct red team/blue team exercises for skills development.",
              evidence: "Technical training records, certification tracking, exercise participation logs, professional development plans, and skills assessment results."
            }
          ]
        },
        {
          id: "PR.DS",
          name: "Data Security",
          description: "Information and records (data) are managed consistent with the organization's risk strategy to protect the confidentiality, integrity, and availability of information.",
          controls: [
            {
              id: "PR.DS-1",
              title: "Data-at-Rest Protection",
              description: "Data-at-rest is protected.",
              implementation: "Encrypt all sensitive data at rest using AES-256 or equivalent algorithms. Implement full-disk encryption on endpoints and servers. Use database-level encryption for sensitive fields. Manage encryption keys through a centralized key management system with proper key rotation schedules.",
              evidence: "Encryption policy documents, encryption configuration records, key management system audit logs, key rotation records, and encryption coverage reports."
            },
            {
              id: "PR.DS-2",
              title: "Data-in-Transit Protection",
              description: "Data-in-transit is protected.",
              implementation: "Enforce TLS 1.2 or higher for all data transmissions. Implement certificate management processes for internal and external services. Use VPN tunnels for site-to-site and remote access connections. Disable legacy protocols (SSLv3, TLS 1.0/1.1) across all systems.",
              evidence: "TLS configuration audits, certificate inventory records, VPN configuration documentation, protocol scan results, and legacy protocol disablement records."
            },
            {
              id: "PR.DS-3",
              title: "Asset Lifecycle Management",
              description: "Assets are formally managed throughout removal, transfers, and disposition.",
              implementation: "Establish procedures for secure asset transfer and disposition including data sanitization (NIST SP 800-88), physical destruction, and chain of custody documentation. Maintain records of all asset movements. Verify data sanitization through spot checks or certificates of destruction.",
              evidence: "Asset disposition procedures, data sanitization records, certificates of destruction, chain of custody logs, asset transfer forms, and spot check audit reports."
            },
            {
              id: "PR.DS-4",
              title: "Availability Assurance",
              description: "Adequate capacity to ensure availability is maintained.",
              implementation: "Implement capacity monitoring and planning for all critical systems. Set alerting thresholds for CPU, memory, storage, and network utilization. Use auto-scaling where applicable. Conduct regular capacity planning reviews aligned with business growth projections.",
              evidence: "Capacity monitoring dashboards, alert configuration records, auto-scaling policies, capacity planning reports, and utilization trend analyses."
            },
            {
              id: "PR.DS-5",
              title: "Data Leak Prevention",
              description: "Protections against data leaks are implemented.",
              implementation: "Deploy Data Loss Prevention (DLP) solutions monitoring email, web, endpoints, and cloud services. Define DLP policies based on data classification and regulatory requirements. Implement content inspection, contextual analysis, and user behavior analytics. Establish incident response procedures for DLP alerts.",
              evidence: "DLP solution configurations, DLP policy documents, alert statistics, incident response records for data leak events, and DLP effectiveness metrics."
            },
            {
              id: "PR.DS-6",
              title: "Integrity Checking",
              description: "Integrity checking mechanisms are used to verify software, firmware, and information integrity.",
              implementation: "Implement file integrity monitoring (FIM) on critical system files, configurations, and application binaries. Use code signing for internal software distributions. Verify firmware integrity through secure boot and attestation mechanisms. Hash-validate downloads and patches before deployment.",
              evidence: "FIM tool configurations, FIM alert logs, code signing certificates, firmware attestation records, and hash verification logs."
            },
            {
              id: "PR.DS-7",
              title: "Development and Testing Environment Protection",
              description: "The development and testing environment(s) are separate from the production environment.",
              implementation: "Maintain separate network segments, accounts, and infrastructure for development, testing, staging, and production environments. Prohibit use of production data in non-production environments unless anonymized or tokenized. Implement access controls limiting cross-environment access.",
              evidence: "Environment architecture diagrams, network segmentation validation records, data masking policies, cross-environment access control configurations, and compliance audit reports."
            },
            {
              id: "PR.DS-8",
              title: "Hardware Integrity Verification",
              description: "Integrity checking mechanisms are used to verify hardware integrity.",
              implementation: "Implement hardware attestation and integrity verification using TPM modules, secure boot processes, and firmware validation. Verify hardware provenance in the supply chain. Conduct periodic hardware integrity audits and monitor for unauthorized hardware modifications.",
              evidence: "TPM configuration records, secure boot validation logs, hardware provenance documentation, integrity audit reports, and unauthorized modification detection logs."
            }
          ]
        },
        {
          id: "PR.IP",
          name: "Information Protection Processes and Procedures",
          description: "Security policies, processes, and procedures are maintained and used to manage protection of information systems and assets.",
          controls: [
            {
              id: "PR.IP-1",
              title: "Baseline Configuration",
              description: "A baseline configuration of information technology/industrial control systems is created and maintained incorporating security principles.",
              implementation: "Develop and document security baseline configurations for all system types (servers, workstations, network devices, cloud instances). Use configuration management tools (Ansible, Puppet, Chef) to enforce baselines. Benchmark against CIS Benchmarks or DISA STIGs. Scan for configuration drift monthly.",
              evidence: "Baseline configuration documents, CIS Benchmark compliance reports, configuration management tool outputs, drift detection scan results, and baseline exception records."
            },
            {
              id: "PR.IP-2",
              title: "System Development Life Cycle",
              description: "A System Development Life Cycle to manage systems is implemented.",
              implementation: "Adopt a formal SDLC methodology incorporating security at each phase: requirements (security requirements), design (threat modeling), implementation (secure coding), testing (security testing), deployment (hardening), and maintenance (patch management). Conduct security gate reviews at phase transitions.",
              evidence: "SDLC methodology documentation, security requirements specifications, threat models, secure code review records, security test results, gate review records, and deployment checklists."
            },
            {
              id: "PR.IP-3",
              title: "Configuration Change Control",
              description: "Configuration change control processes are in place.",
              implementation: "Implement a formal change management process with request, review, approval, implementation, and verification stages. Require security impact assessment for all changes. Maintain a change advisory board (CAB) for significant changes. Log all changes and enable rollback capabilities.",
              evidence: "Change management policy, change request records, CAB meeting minutes, security impact assessments, change implementation logs, and rollback procedure documentation."
            },
            {
              id: "PR.IP-4",
              title: "Backup Management",
              description: "Backups of information are conducted, maintained, and tested.",
              implementation: "Implement automated backup processes for all critical data and systems following the 3-2-1 rule (3 copies, 2 media types, 1 offsite). Encrypt backup data. Test backup restoration quarterly for critical systems and annually for all systems. Document and monitor backup success rates.",
              evidence: "Backup policy documents, backup job configurations, backup success/failure logs, restoration test results, encryption configuration records, and offsite storage arrangements."
            },
            {
              id: "PR.IP-5",
              title: "Physical Operating Environment",
              description: "Policy and regulations regarding the physical operating environment for organizational assets are met.",
              implementation: "Implement environmental controls for data centers and server rooms including HVAC, fire suppression, water detection, and uninterruptible power supplies (UPS). Monitor environmental conditions continuously. Maintain compliance with local building codes and fire safety regulations.",
              evidence: "Environmental monitoring logs, HVAC maintenance records, fire suppression system inspection reports, UPS test records, building code compliance certificates, and environmental incident reports."
            },
            {
              id: "PR.IP-6",
              title: "Data Destruction",
              description: "Data is destroyed according to policy.",
              implementation: "Establish data retention and destruction policies aligned with legal, regulatory, and business requirements. Implement automated data lifecycle management where feasible. Use approved destruction methods (cryptographic erasure, degaussing, shredding) appropriate to data sensitivity. Maintain destruction certificates.",
              evidence: "Data retention policy documents, destruction procedure documentation, automated lifecycle management configurations, destruction certificates, and destruction audit logs."
            },
            {
              id: "PR.IP-7",
              title: "Protection Process Improvement",
              description: "Protection processes are improved.",
              implementation: "Establish continuous improvement processes for security controls. Conduct periodic effectiveness assessments. Incorporate lessons learned from incidents, audits, and exercises. Benchmark against industry peers and emerging best practices. Track improvement initiatives through a formal program.",
              evidence: "Improvement program documentation, effectiveness assessment reports, lessons learned records, benchmarking analyses, improvement initiative tracking, and metrics trend reports."
            },
            {
              id: "PR.IP-8",
              title: "Protection Technology Sharing",
              description: "Effectiveness of protection technologies is shared.",
              implementation: "Participate in information sharing communities to both contribute and receive intelligence on protection technology effectiveness. Share (non-sensitive) security metrics and lessons learned with industry peers. Contribute to open-source security projects and community defense initiatives.",
              evidence: "Information sharing community participation records, shared intelligence records, metrics shared with peers, open-source contribution records, and community defense initiative participation."
            },
            {
              id: "PR.IP-9",
              title: "Response and Recovery Plans",
              description: "Response plans (Incident Response and Business Continuity) and recovery plans (Incident Recovery and Disaster Recovery) are in place and managed.",
              implementation: "Develop and maintain incident response, business continuity, disaster recovery, and crisis communication plans. Ensure plans are coordinated and aligned. Review plans at least annually. Distribute plans to relevant personnel and maintain accessible copies in multiple locations.",
              evidence: "Incident response plan, business continuity plan, disaster recovery plan, crisis communication plan, plan review records, distribution records, and plan storage location documentation."
            },
            {
              id: "PR.IP-10",
              title: "Response and Recovery Plan Testing",
              description: "Response and recovery plans are tested.",
              implementation: "Conduct regular testing of all response and recovery plans including tabletop exercises, functional exercises, and full-scale drills. Test at least annually for each plan type. Document test results, identify gaps, and update plans based on findings. Track remediation of identified deficiencies.",
              evidence: "Exercise plans, exercise execution records, after-action reports, gap analysis documents, plan update records, and deficiency remediation tracking."
            },
            {
              id: "PR.IP-11",
              title: "Human Resources Security",
              description: "Cybersecurity is included in human resources practices (e.g., deprovisioning, personnel screening).",
              implementation: "Integrate cybersecurity into HR processes: conduct background checks for security-sensitive positions, include security responsibilities in job descriptions, enforce security training as condition of employment, implement timely access deprovisioning upon role change or termination. Conduct exit interviews addressing security obligations.",
              evidence: "Background check policy, security-inclusive job descriptions, training completion records, deprovisioning procedure documentation, access revocation logs, and exit interview records."
            },
            {
              id: "PR.IP-12",
              title: "Vulnerability Management Plan",
              description: "A vulnerability management plan is developed and implemented.",
              implementation: "Establish a formal vulnerability management program with defined scanning cadence, severity classification scheme, remediation SLAs, and exception processes. Prioritize remediation based on exploitability, asset criticality, and threat intelligence. Track metrics including mean time to remediate (MTTR) and vulnerability aging.",
              evidence: "Vulnerability management plan, scanning schedule, severity classification scheme, remediation SLA documentation, exception records, MTTR metrics, and aging reports."
            }
          ]
        },
        {
          id: "PR.MA",
          name: "Maintenance",
          description: "Maintenance and repairs of industrial control and information system components are performed consistent with policies and procedures.",
          controls: [
            {
              id: "PR.MA-1",
              title: "Maintenance Scheduling",
              description: "Maintenance and repair of organizational assets are performed and logged, with approved and controlled tools.",
              implementation: "Establish a preventive maintenance schedule for all critical hardware and software. Use approved maintenance tools and procedures. Log all maintenance activities including date, technician, actions performed, and verification of proper function. Restrict maintenance tool access to authorized personnel.",
              evidence: "Maintenance schedule documentation, maintenance activity logs, approved tool lists, technician authorization records, and post-maintenance verification records."
            },
            {
              id: "PR.MA-2",
              title: "Remote Maintenance",
              description: "Remote maintenance of organizational assets is approved, logged, and performed in a manner that prevents unauthorized access.",
              implementation: "Establish remote maintenance policies requiring prior approval, multi-factor authentication, session recording, and supervision for sensitive systems. Use encrypted connections for all remote maintenance. Audit remote maintenance sessions and investigate anomalies.",
              evidence: "Remote maintenance policy, approval records, session recordings, authentication logs, encrypted connection configurations, and audit reports."
            }
          ]
        },
        {
          id: "PR.PT",
          name: "Protective Technology",
          description: "Technical security solutions are managed to ensure the security and resilience of systems and assets, consistent with related policies, procedures, and agreements.",
          controls: [
            {
              id: "PR.PT-1",
              title: "Audit Log Management",
              description: "Audit/log records are determined, documented, implemented, and reviewed in accordance with policy.",
              implementation: "Define logging requirements for all system types specifying events to capture, log format, retention period, and protection mechanisms. Centralize log collection using a SIEM platform. Implement log integrity protections (write-once storage, hash chaining). Review logs regularly for security-relevant events.",
              evidence: "Logging policy documents, SIEM configuration records, log retention configurations, log integrity verification reports, log review records, and log coverage assessments."
            },
            {
              id: "PR.PT-2",
              title: "Removable Media Protection",
              description: "Removable media is protected and its use restricted according to policy.",
              implementation: "Implement technical controls restricting removable media usage to authorized devices and users. Enforce encryption on approved removable media. Deploy endpoint protection that scans removable media on connection. Disable auto-run functionality across all endpoints.",
              evidence: "Removable media policy, device control configurations, encryption enforcement records, endpoint protection scan logs, and auto-run disablement verification."
            },
            {
              id: "PR.PT-3",
              title: "Least Functionality",
              description: "The principle of least functionality is incorporated by configuring systems to provide only essential capabilities.",
              implementation: "Disable unnecessary services, ports, and protocols on all systems. Remove or disable default accounts. Uninstall unnecessary software packages. Apply application whitelisting on critical systems. Validate least functionality through periodic configuration audits.",
              evidence: "Hardening standards documentation, service/port configuration records, default account disablement logs, software removal records, application whitelist configurations, and configuration audit results."
            },
            {
              id: "PR.PT-4",
              title: "Communications Protection",
              description: "Communications and control networks are protected.",
              implementation: "Implement network security controls including firewalls, intrusion prevention systems (IPS), web application firewalls (WAF), and DNS security. Segment communications networks from control networks. Monitor network traffic for anomalies. Implement network access control (NAC) for device authentication.",
              evidence: "Firewall configurations, IPS rule sets, WAF configurations, DNS security settings, network segmentation diagrams, traffic monitoring reports, and NAC configuration records."
            },
            {
              id: "PR.PT-5",
              title: "Resilience Mechanisms",
              description: "Mechanisms (e.g., failsafe, load balancing, hot swap) are implemented to achieve resilience requirements in normal and adverse situations.",
              implementation: "Design and implement resilience mechanisms including load balancers, failover clusters, hot standby systems, and geographic redundancy. Test failover mechanisms regularly. Ensure resilience mechanisms meet defined RTO and RPO requirements. Monitor resilience system health continuously.",
              evidence: "Resilience architecture documentation, load balancer configurations, failover test results, geographic redundancy arrangements, RTO/RPO validation records, and health monitoring dashboards."
            }
          ]
        }
      ]
    },
    // -----------------------------------------------------------------
    //  DETECT (DE)
    // -----------------------------------------------------------------
    {
      id: "DE",
      name: "Detect",
      description: "Develop and implement appropriate activities to identify the occurrence of a cybersecurity event.",
      categories: [
        {
          id: "DE.AE",
          name: "Anomalies and Events",
          description: "Anomalous activity is detected and the potential impact of events is understood.",
          controls: [
            {
              id: "DE.AE-1",
              title: "Network Operations Baseline",
              description: "A baseline of network operations and expected data flows for users and systems is established and managed.",
              implementation: "Establish baselines for normal network traffic patterns, user behavior, and system activity using network monitoring and UEBA tools. Define deviation thresholds that trigger alerts. Update baselines periodically to reflect legitimate changes in operations.",
              evidence: "Network baseline documentation, UEBA configuration records, threshold definitions, baseline update logs, and deviation alert configurations."
            },
            {
              id: "DE.AE-2",
              title: "Event Analysis",
              description: "Detected events are analyzed to understand attack targets and methods.",
              implementation: "Implement event correlation and analysis capabilities within the SIEM. Develop correlation rules mapping to known attack patterns (MITRE ATT&CK). Employ threat hunting procedures to proactively identify sophisticated threats. Document analysis findings and feed into threat intelligence.",
              evidence: "SIEM correlation rule sets, MITRE ATT&CK mapping documentation, threat hunting reports, analysis finding records, and threat intelligence feed updates."
            },
            {
              id: "DE.AE-3",
              title: "Event Data Collection",
              description: "Event data are collected and correlated from multiple sources and sensors.",
              implementation: "Aggregate security event data from network devices, endpoints, applications, cloud services, and physical security systems into a centralized SIEM. Normalize data formats for consistent correlation. Ensure time synchronization across all event sources using NTP.",
              evidence: "SIEM data source inventory, log ingestion configurations, data normalization rules, NTP configuration records, and data source coverage reports."
            },
            {
              id: "DE.AE-4",
              title: "Event Impact Determination",
              description: "Impact of events is determined.",
              implementation: "Develop impact assessment procedures for security events considering affected assets, data sensitivity, business process impact, and regulatory implications. Use automated enrichment to add asset context to events. Define impact severity levels with clear criteria.",
              evidence: "Impact assessment procedures, severity level definitions, automated enrichment configuration, impact assessment records, and event triage documentation."
            },
            {
              id: "DE.AE-5",
              title: "Alert Thresholds",
              description: "Incident alert thresholds are established.",
              implementation: "Define alert thresholds based on event severity, frequency, and correlation patterns. Implement tiered alerting with escalation procedures. Tune thresholds regularly to minimize false positives while maintaining detection sensitivity. Document threshold rationale and tuning history.",
              evidence: "Alert threshold documentation, escalation procedures, threshold tuning records, false positive rate tracking, and alert volume metrics."
            }
          ]
        },
        {
          id: "DE.CM",
          name: "Security Continuous Monitoring",
          description: "The information system and assets are monitored to identify cybersecurity events and verify the effectiveness of protective measures.",
          controls: [
            {
              id: "DE.CM-1",
              title: "Network Monitoring",
              description: "The network is monitored to detect potential cybersecurity events.",
              implementation: "Deploy network monitoring tools including IDS/IPS, netflow analysis, packet capture, and network traffic analysis (NTA) solutions. Monitor all network segments including internal, DMZ, and cloud environments. Implement 24/7 monitoring through a SOC or managed service.",
              evidence: "Network monitoring tool deployment records, IDS/IPS configurations, netflow analysis reports, SOC operational records, and monitoring coverage assessments."
            },
            {
              id: "DE.CM-2",
              title: "Physical Environment Monitoring",
              description: "The physical environment is monitored to detect potential cybersecurity events.",
              implementation: "Implement physical security monitoring through CCTV, motion detection, door/window sensors, and environmental sensors. Integrate physical security events with cyber event monitoring. Establish response procedures for physical security alerts.",
              evidence: "Physical security system configurations, CCTV placement maps, sensor deployment records, integration configuration with SIEM, alert response procedures, and physical security incident logs."
            },
            {
              id: "DE.CM-3",
              title: "Personnel Activity Monitoring",
              description: "Personnel activity is monitored to detect potential cybersecurity events.",
              implementation: "Implement user activity monitoring (UAM) for privileged users and users with access to sensitive data. Deploy UEBA solutions to detect anomalous user behavior. Ensure monitoring complies with privacy regulations and is disclosed in acceptable use policies. Investigate anomalous activity promptly.",
              evidence: "UAM tool configurations, UEBA deployment records, privacy compliance assessments, acceptable use policy with monitoring disclosure, investigation records, and anomaly detection reports."
            },
            {
              id: "DE.CM-4",
              title: "Malicious Code Detection",
              description: "Malicious code is detected.",
              implementation: "Deploy endpoint protection platforms (EPP) with anti-malware, behavioral analysis, and exploit prevention capabilities on all endpoints and servers. Implement email security gateways with attachment sandboxing. Deploy web proxies with malware scanning. Ensure signature updates are automated and timely.",
              evidence: "EPP deployment records, email gateway configurations, web proxy configurations, signature update logs, malware detection statistics, and endpoint coverage reports."
            },
            {
              id: "DE.CM-5",
              title: "Unauthorized Mobile Code Detection",
              description: "Unauthorized mobile code is detected.",
              implementation: "Implement controls to detect and prevent unauthorized mobile code execution including browser security policies, application whitelisting, and script execution controls. Monitor for unauthorized code execution on endpoints and servers. Block known malicious mobile code signatures.",
              evidence: "Browser security policy configurations, application whitelist records, script execution control configurations, mobile code detection logs, and blocking records."
            },
            {
              id: "DE.CM-6",
              title: "External Service Provider Monitoring",
              description: "External service provider activity is monitored to detect potential cybersecurity events.",
              implementation: "Monitor third-party service provider connections and activities. Implement API monitoring for cloud service integrations. Review service provider security logs and reports. Establish automated alerts for anomalous provider activity patterns.",
              evidence: "Provider connection monitoring configurations, API monitoring records, provider security log review reports, anomaly alert configurations, and provider activity audit trails."
            },
            {
              id: "DE.CM-7",
              title: "Unauthorized Entity Monitoring",
              description: "Monitoring for unauthorized personnel, connections, devices, and software is performed.",
              implementation: "Implement network access control to detect unauthorized devices. Use software inventory tools to identify unauthorized applications. Monitor for rogue access points and unauthorized network connections. Conduct periodic sweeps for unauthorized personnel in restricted areas.",
              evidence: "NAC configuration and detection records, unauthorized software detection reports, rogue device detection logs, physical sweep records, and unauthorized connection alert logs."
            },
            {
              id: "DE.CM-8",
              title: "Vulnerability Scan Monitoring",
              description: "Vulnerability scans are performed.",
              implementation: "Conduct authenticated vulnerability scans on all network-connected assets at least monthly. Perform targeted scans after significant changes. Integrate scan results with asset inventory and SIEM. Track remediation progress against defined SLAs.",
              evidence: "Vulnerability scan schedules, scan result reports, scan coverage metrics, SIEM integration records, remediation tracking dashboards, and SLA compliance reports."
            }
          ]
        },
        {
          id: "DE.DP",
          name: "Detection Processes",
          description: "Detection processes and procedures are maintained and tested to ensure awareness of anomalous events.",
          controls: [
            {
              id: "DE.DP-1",
              title: "Detection Role Definition",
              description: "Roles and responsibilities for detection are well defined to ensure accountability.",
              implementation: "Define clear roles and responsibilities for security event detection, triage, escalation, and investigation. Document these in SOC operating procedures. Ensure adequate staffing for 24/7 detection coverage. Establish performance metrics for detection activities.",
              evidence: "SOC operating procedures, role and responsibility documents, staffing schedules, detection performance metrics, and accountability assignment records."
            },
            {
              id: "DE.DP-2",
              title: "Detection Compliance",
              description: "Detection activities comply with all applicable requirements.",
              implementation: "Ensure detection activities comply with legal, regulatory, privacy, and contractual requirements. Conduct periodic compliance assessments of detection processes. Maintain documentation demonstrating compliance. Address identified gaps promptly.",
              evidence: "Compliance assessment reports, regulatory requirement mappings, privacy impact assessments for monitoring activities, and gap remediation records."
            },
            {
              id: "DE.DP-3",
              title: "Detection Process Testing",
              description: "Detection processes are tested.",
              implementation: "Conduct regular testing of detection capabilities through purple team exercises, detection rule validation, and simulated attack scenarios. Measure detection rates, mean time to detect (MTTD), and false positive rates. Use testing results to improve detection coverage and accuracy.",
              evidence: "Purple team exercise reports, detection rule validation results, simulated attack test records, MTTD metrics, false positive rate tracking, and detection improvement plans."
            },
            {
              id: "DE.DP-4",
              title: "Detection Information Communication",
              description: "Event detection information is communicated.",
              implementation: "Establish communication procedures for detection findings including escalation paths, notification timelines, and reporting formats. Ensure detection information reaches appropriate decision-makers promptly. Integrate detection findings into situational awareness dashboards.",
              evidence: "Communication procedure documents, escalation path diagrams, notification timeline requirements, reporting templates, dashboard configurations, and communication audit trails."
            },
            {
              id: "DE.DP-5",
              title: "Detection Process Improvement",
              description: "Detection processes are continuously improved.",
              implementation: "Implement continuous improvement cycles for detection capabilities. Conduct post-incident detection effectiveness reviews. Track detection coverage against the MITRE ATT&CK framework. Incorporate new threat intelligence into detection rules. Benchmark detection metrics against industry standards.",
              evidence: "Detection improvement plans, post-incident review records, ATT&CK coverage maps, new detection rule deployment logs, benchmarking reports, and detection maturity assessments."
            }
          ]
        }
      ]
    },
    // -----------------------------------------------------------------
    //  RESPOND (RS)
    // -----------------------------------------------------------------
    {
      id: "RS",
      name: "Respond",
      description: "Develop and implement appropriate activities to take action regarding a detected cybersecurity incident.",
      categories: [
        {
          id: "RS.RP",
          name: "Response Planning",
          description: "Response processes and procedures are executed and maintained, to ensure response to detected cybersecurity incidents.",
          controls: [
            {
              id: "RS.RP-1",
              title: "Incident Response Execution",
              description: "Response plan is executed during or after an incident.",
              implementation: "Maintain and execute a documented incident response plan covering detection, containment, eradication, recovery, and lessons learned phases. Assign incident commander and response team roles. Activate the plan promptly upon incident declaration. Document all response actions with timestamps.",
              evidence: "Incident response plan, incident declaration records, response team assignment logs, action logs with timestamps, and incident timeline documentation."
            }
          ]
        },
        {
          id: "RS.CO",
          name: "Communications",
          description: "Response activities are coordinated with internal and external stakeholders.",
          controls: [
            {
              id: "RS.CO-1",
              title: "Personnel Knowledge",
              description: "Personnel know their roles and order of operations when a response is needed.",
              implementation: "Distribute incident response roles and procedures to all relevant personnel. Conduct regular training on response procedures. Maintain updated contact lists and escalation procedures. Ensure response documentation is accessible during incidents including offline copies.",
              evidence: "Role distribution records, training completion logs, contact lists, escalation procedure documents, and documentation accessibility verification records."
            },
            {
              id: "RS.CO-2",
              title: "Incident Reporting",
              description: "Incidents are reported consistent with established criteria.",
              implementation: "Define incident reporting criteria and timelines based on severity, regulatory requirements, and contractual obligations. Implement reporting workflows within the incident management system. Ensure compliance with mandatory reporting requirements (e.g., breach notification laws).",
              evidence: "Reporting criteria documentation, reporting workflow configurations, mandatory reporting compliance records, and incident notification logs."
            },
            {
              id: "RS.CO-3",
              title: "Information Sharing",
              description: "Information is shared consistent with response plans.",
              implementation: "Establish information sharing procedures for incident response including internal stakeholders, law enforcement, ISACs, regulators, and affected parties. Define information classification and handling for incident data. Use TLP (Traffic Light Protocol) designations for shared intelligence.",
              evidence: "Information sharing procedures, stakeholder communication records, TLP-designated intelligence sharing records, and law enforcement coordination documentation."
            },
            {
              id: "RS.CO-4",
              title: "Stakeholder Coordination",
              description: "Coordination with stakeholders occurs consistent with response plans.",
              implementation: "Establish pre-arranged coordination mechanisms with key stakeholders including legal counsel, public relations, executive leadership, regulators, and law enforcement. Conduct joint exercises with external stakeholders. Maintain current contact information and communication channels.",
              evidence: "Stakeholder coordination plans, joint exercise records, contact directory maintenance logs, communication channel documentation, and coordination meeting records."
            },
            {
              id: "RS.CO-5",
              title: "External Stakeholder Sharing",
              description: "Voluntary information sharing occurs with external stakeholders to achieve broader cybersecurity situational awareness.",
              implementation: "Participate in voluntary information sharing through ISACs, industry groups, and government partnerships. Share anonymized incident indicators and lessons learned. Contribute to community defense by sharing detection signatures and mitigation strategies.",
              evidence: "ISAC participation records, shared indicator logs, lessons learned publications, detection signature contributions, and community defense initiative records."
            }
          ]
        },
        {
          id: "RS.AN",
          name: "Analysis",
          description: "Analysis is conducted to ensure effective response and support recovery activities.",
          controls: [
            {
              id: "RS.AN-1",
              title: "Investigation Notifications",
              description: "Notifications from detection systems are investigated.",
              implementation: "Establish triage procedures for all detection system notifications. Prioritize investigations based on severity and potential impact. Document investigation steps, findings, and conclusions. Ensure timely escalation when investigations reveal confirmed incidents.",
              evidence: "Triage procedure documentation, investigation records, prioritization criteria, escalation records, and investigation closure reports."
            },
            {
              id: "RS.AN-2",
              title: "Incident Impact Understanding",
              description: "The impact of the incident is understood.",
              implementation: "Conduct thorough impact assessment for confirmed incidents covering affected systems, compromised data, business process disruption, regulatory implications, and reputational exposure. Use forensic analysis to determine the full scope of compromise. Update impact assessments as new information emerges.",
              evidence: "Impact assessment reports, forensic analysis reports, scope of compromise documentation, regulatory impact analyses, and assessment update records."
            },
            {
              id: "RS.AN-3",
              title: "Forensic Analysis",
              description: "Forensics are performed.",
              implementation: "Maintain digital forensics capability through trained personnel, forensic tools, and documented procedures. Preserve evidence using forensically sound methods (chain of custody, write blockers, imaging). Conduct forensic analysis to determine root cause, attack vector, and full timeline of compromise.",
              evidence: "Forensic procedure documents, evidence chain of custody logs, forensic tool inventory, forensic analysis reports, and root cause determination records."
            },
            {
              id: "RS.AN-4",
              title: "Incident Categorization",
              description: "Incidents are categorized consistent with response plans.",
              implementation: "Define incident categorization taxonomy (e.g., malware, unauthorized access, data breach, denial of service, insider threat). Categorize incidents at triage and update as investigation progresses. Use categorization to drive appropriate response procedures and reporting requirements.",
              evidence: "Incident categorization taxonomy, categorized incident records, category-specific response procedure mappings, and categorization accuracy reviews."
            },
            {
              id: "RS.AN-5",
              title: "Vulnerability Disclosure",
              description: "Processes are established to receive, analyze and respond to vulnerabilities disclosed to the organization from internal and external sources.",
              implementation: "Establish a vulnerability disclosure program with clear intake channels, response timelines, and analysis procedures. Implement a coordinated vulnerability disclosure policy. Acknowledge vulnerability reports promptly and provide status updates to reporters.",
              evidence: "Vulnerability disclosure policy, intake channel documentation, response timeline SLAs, vulnerability report records, status update communications, and remediation tracking."
            }
          ]
        },
        {
          id: "RS.MI",
          name: "Mitigation",
          description: "Activities are performed to prevent expansion of an event, mitigate its effects, and resolve the incident.",
          controls: [
            {
              id: "RS.MI-1",
              title: "Incident Containment",
              description: "Incidents are contained.",
              implementation: "Develop and maintain containment strategies for each incident category (network isolation, account disablement, system quarantine, DNS sinkholing). Implement containment promptly to prevent lateral movement and data exfiltration. Document containment actions and verify effectiveness.",
              evidence: "Containment strategy documentation, containment action logs, effectiveness verification records, and lateral movement prevention validation."
            },
            {
              id: "RS.MI-2",
              title: "Incident Mitigation",
              description: "Incidents are mitigated.",
              implementation: "Implement mitigation measures to reduce incident impact including patching exploited vulnerabilities, updating security controls, modifying detection rules, and implementing compensating controls. Validate mitigation effectiveness through testing and monitoring.",
              evidence: "Mitigation action records, patch deployment logs, security control update records, detection rule modifications, compensating control documentation, and validation test results."
            },
            {
              id: "RS.MI-3",
              title: "Vulnerability Mitigation",
              description: "Newly identified vulnerabilities are mitigated or documented as accepted risks.",
              implementation: "Assess newly identified vulnerabilities from incidents for broader organizational impact. Implement remediation or compensating controls. Document accepted risk decisions with appropriate authority approval. Track remediation to completion.",
              evidence: "Vulnerability assessment records, remediation action plans, compensating control documentation, risk acceptance records with approvals, and remediation completion tracking."
            }
          ]
        },
        {
          id: "RS.IM",
          name: "Improvements",
          description: "Organizational response activities are improved by incorporating lessons learned from current and previous detection/response activities.",
          controls: [
            {
              id: "RS.IM-1",
              title: "Lessons Learned",
              description: "Response plans incorporate lessons learned.",
              implementation: "Conduct post-incident reviews (PIRs) for all significant incidents. Document lessons learned covering detection, response, and recovery effectiveness. Update response plans, detection rules, and security controls based on findings. Track implementation of improvement actions.",
              evidence: "Post-incident review reports, lessons learned documents, plan update records, detection rule update logs, and improvement action tracking records."
            },
            {
              id: "RS.IM-2",
              title: "Response Strategy Update",
              description: "Response strategies are updated.",
              implementation: "Review and update response strategies based on lessons learned, emerging threats, organizational changes, and exercise findings. Conduct annual comprehensive review of all response strategies. Communicate strategy updates to all relevant personnel.",
              evidence: "Strategy review records, update change logs, annual review reports, communication records for strategy updates, and strategy version control documentation."
            }
          ]
        }
      ]
    },
    // -----------------------------------------------------------------
    //  RECOVER (RC)
    // -----------------------------------------------------------------
    {
      id: "RC",
      name: "Recover",
      description: "Develop and implement appropriate activities to maintain plans for resilience and to restore any capabilities or services that were impaired due to a cybersecurity incident.",
      categories: [
        {
          id: "RC.RP",
          name: "Recovery Planning",
          description: "Recovery processes and procedures are executed and maintained to ensure restoration of systems or assets affected by cybersecurity incidents.",
          controls: [
            {
              id: "RC.RP-1",
              title: "Recovery Plan Execution",
              description: "Recovery plan is executed during or after a cybersecurity incident.",
              implementation: "Execute documented recovery procedures following incident containment and eradication. Prioritize recovery based on business impact and service criticality. Validate system integrity before returning to production. Conduct phased recovery with verification at each stage.",
              evidence: "Recovery execution records, prioritization documentation, system integrity validation results, phased recovery checkpoints, and return-to-production authorization records."
            }
          ]
        },
        {
          id: "RC.IM",
          name: "Improvements",
          description: "Recovery planning and processes are improved by incorporating lessons learned into future activities.",
          controls: [
            {
              id: "RC.IM-1",
              title: "Recovery Lessons Learned",
              description: "Recovery plans incorporate lessons learned.",
              implementation: "Conduct post-recovery reviews to assess the effectiveness of recovery processes. Document gaps in recovery capabilities, tool deficiencies, and process improvements. Update recovery plans based on findings. Track implementation of improvement actions to completion.",
              evidence: "Post-recovery review reports, gap analysis documents, plan update records, improvement action tracking, and updated recovery plan versions."
            },
            {
              id: "RC.IM-2",
              title: "Recovery Strategy Update",
              description: "Recovery strategies are updated.",
              implementation: "Review and update recovery strategies based on lessons learned, technology changes, organizational restructuring, and evolving threat landscape. Validate updated strategies through testing. Communicate changes to all stakeholders involved in recovery operations.",
              evidence: "Strategy review records, updated strategy documents, validation test results, stakeholder communication records, and strategy change management logs."
            }
          ]
        },
        {
          id: "RC.CO",
          name: "Communications",
          description: "Restoration activities are coordinated with internal and external parties.",
          controls: [
            {
              id: "RC.CO-1",
              title: "Public Relations Management",
              description: "Public relations are managed.",
              implementation: "Coordinate with public relations and communications teams during recovery to manage public messaging. Prepare holding statements and press releases as needed. Monitor public and social media sentiment. Ensure consistent messaging aligned with legal counsel guidance.",
              evidence: "Communication plans, press releases, public statements, media monitoring reports, legal review records, and social media sentiment analysis reports."
            },
            {
              id: "RC.CO-2",
              title: "Reputation Recovery",
              description: "Reputation is repaired after an incident.",
              implementation: "Develop reputation recovery strategies addressing customer confidence, partner trust, and public perception. Communicate remediation actions and security improvements transparently. Engage with affected stakeholders directly. Monitor reputation metrics and adjust strategies as needed.",
              evidence: "Reputation recovery strategy documents, stakeholder communication records, remediation action communications, reputation metric tracking, and customer feedback analysis."
            },
            {
              id: "RC.CO-3",
              title: "Recovery Communication",
              description: "Recovery activities are communicated to internal and external stakeholders and executive and management teams.",
              implementation: "Provide regular recovery status updates to all stakeholders including executive leadership, affected business units, customers, regulators, and partners. Define communication frequency and channels. Ensure updates include progress, timeline estimates, and any changes to recovery scope.",
              evidence: "Recovery status reports, stakeholder communication logs, communication schedule documentation, timeline estimate records, and stakeholder feedback records."
            }
          ]
        }
      ]
    }
  ]
};
