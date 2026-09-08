"use strict";

// ---------------------------------------------------------------------------
// report-generator.js -- Security assessment report generator for Darknode
//                        Nexus.  Produces structured Markdown reports from
//                        scan findings with multiple template styles,
//                        risk scoring, CVSS calculation, and professional
//                        formatting.
// ---------------------------------------------------------------------------

// ============================= CONSTANTS ===================================

/**
 * RISK_MATRIX -- 5x5 likelihood vs impact matrix.
 *
 * Axes (1-5):
 *   Likelihood: 1=Rare, 2=Unlikely, 3=Possible, 4=Likely, 5=Almost Certain
 *   Impact:     1=Negligible, 2=Minor, 3=Moderate, 4=Major, 5=Catastrophic
 *
 * Cell values represent overall risk level.
 */
const RISK_MATRIX = {
  labels: {
    likelihood: ["Rare", "Unlikely", "Possible", "Likely", "Almost Certain"],
    impact: ["Negligible", "Minor", "Moderate", "Major", "Catastrophic"],
    risk: ["Low", "Low-Medium", "Medium", "High", "Critical"],
  },
  // matrix[likelihood-1][impact-1] = risk score (1-25)
  matrix: [
    [1, 2, 3, 4, 5],
    [2, 4, 6, 8, 10],
    [3, 6, 9, 12, 15],
    [4, 8, 12, 16, 20],
    [5, 10, 15, 20, 25],
  ],
  // Map numeric score to qualitative label
  scoreToLabel(score) {
    if (score <= 3) return "Low";
    if (score <= 6) return "Low-Medium";
    if (score <= 12) return "Medium";
    if (score <= 19) return "High";
    return "Critical";
  },
  // Get risk for given likelihood and impact (1-5 each)
  getRisk(likelihood, impact) {
    const l = Math.max(1, Math.min(5, Math.round(likelihood))) - 1;
    const i = Math.max(1, Math.min(5, Math.round(impact))) - 1;
    const score = RISK_MATRIX.matrix[l][i];
    return {
      score,
      label: RISK_MATRIX.scoreToLabel(score),
      likelihood: RISK_MATRIX.labels.likelihood[l],
      impact: RISK_MATRIX.labels.impact[i],
    };
  },
  // Render the matrix as a Markdown table
  toMarkdown() {
    const lines = [];
    lines.push("### Risk Matrix (Likelihood x Impact)");
    lines.push("");
    lines.push("| Likelihood \\\\ Impact | Negligible | Minor | Moderate | Major | Catastrophic |");
    lines.push("|---|---|---|---|---|---|");
    for (let l = 4; l >= 0; l--) {
      const label = RISK_MATRIX.labels.likelihood[l];
      const cells = RISK_MATRIX.matrix[l].map((s) => {
        const rl = RISK_MATRIX.scoreToLabel(s);
        return `${s} (${rl})`;
      });
      lines.push(`| **${label}** | ${cells.join(" | ")} |`);
    }
    lines.push("");
    return lines.join("\n");
  },
};

/**
 * CVSS_CALCULATOR -- Simplified CVSS v3.1 scoring implementation.
 *
 * Supports the base metric group only (no temporal or environmental).
 * Input is an object with the 8 base metrics; output is a score 0.0-10.0
 * plus a qualitative severity string.
 */
const CVSS_CALCULATOR = {
  // Metric value mappings to numeric weights (CVSS v3.1 spec)
  weights: {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.20 },
    AC: { L: 0.77, H: 0.44 },
    PR: {
      unchanged: { N: 0.85, L: 0.62, H: 0.27 },
      changed: { N: 0.85, L: 0.68, H: 0.50 },
    },
    UI: { N: 0.85, R: 0.62 },
    C: { H: 0.56, L: 0.22, N: 0 },
    I: { H: 0.56, L: 0.22, N: 0 },
    A: { H: 0.56, L: 0.22, N: 0 },
  },

  metricNames: {
    AV: "Attack Vector",
    AC: "Attack Complexity",
    PR: "Privileges Required",
    UI: "User Interaction",
    S: "Scope",
    C: "Confidentiality Impact",
    I: "Integrity Impact",
    A: "Availability Impact",
  },

  metricValues: {
    AV: { N: "Network", A: "Adjacent", L: "Local", P: "Physical" },
    AC: { L: "Low", H: "High" },
    PR: { N: "None", L: "Low", H: "High" },
    UI: { N: "None", R: "Required" },
    S: { U: "Unchanged", C: "Changed" },
    C: { N: "None", L: "Low", H: "High" },
    I: { N: "None", L: "Low", H: "High" },
    A: { N: "None", L: "Low", H: "High" },
  },

  /**
   * Calculate a CVSS v3.1 base score.
   *
   * @param {object} metrics - Base metrics { AV, AC, PR, UI, S, C, I, A }
   *   Each value is a single uppercase letter per CVSS v3.1 spec.
   * @returns {object} { score, severity, vector, breakdown }
   */
  calculate(metrics) {
    const m = metrics || {};
    const AV = m.AV || "N";
    const AC = m.AC || "L";
    const PR = m.PR || "N";
    const UI = m.UI || "N";
    const S = m.S || "U";
    const C = m.C || "N";
    const I = m.I || "N";
    const A = m.A || "N";

    const w = CVSS_CALCULATOR.weights;
    const scopeChanged = S === "C";

    const avW = w.AV[AV] || 0.85;
    const acW = w.AC[AC] || 0.77;
    const prMap = scopeChanged ? w.PR.changed : w.PR.unchanged;
    const prW = prMap[PR] || 0.85;
    const uiW = w.UI[UI] || 0.85;

    const cW = w.C[C] || 0;
    const iW = w.I[I] || 0;
    const aW = w.A[A] || 0;

    // ISS -- Impact Sub-Score
    const iss = 1 - ((1 - cW) * (1 - iW) * (1 - aW));

    // Impact
    let impact;
    if (scopeChanged) {
      impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
    } else {
      impact = 6.42 * iss;
    }

    // Exploitability
    const exploitability = 8.22 * avW * acW * prW * uiW;

    // Base Score
    let score;
    if (impact <= 0) {
      score = 0;
    } else if (scopeChanged) {
      score = Math.min(1.08 * (impact + exploitability), 10);
    } else {
      score = Math.min(impact + exploitability, 10);
    }

    // Round up to 1 decimal
    score = Math.ceil(score * 10) / 10;

    // Qualitative severity
    let severity;
    if (score === 0) severity = "None";
    else if (score <= 3.9) severity = "Low";
    else if (score <= 6.9) severity = "Medium";
    else if (score <= 8.9) severity = "High";
    else severity = "Critical";

    // Build vector string
    const vector = `CVSS:3.1/AV:${AV}/AC:${AC}/PR:${PR}/UI:${UI}/S:${S}/C:${C}/I:${I}/A:${A}`;

    return {
      score,
      severity,
      vector,
      breakdown: {
        impactSubScore: Math.round(iss * 1000) / 1000,
        impact: Math.round(impact * 100) / 100,
        exploitability: Math.round(exploitability * 100) / 100,
        scopeChanged,
      },
      metrics: {
        AV: { key: AV, label: CVSS_CALCULATOR.metricValues.AV[AV] || AV },
        AC: { key: AC, label: CVSS_CALCULATOR.metricValues.AC[AC] || AC },
        PR: { key: PR, label: CVSS_CALCULATOR.metricValues.PR[PR] || PR },
        UI: { key: UI, label: CVSS_CALCULATOR.metricValues.UI[UI] || UI },
        S: { key: S, label: CVSS_CALCULATOR.metricValues.S[S] || S },
        C: { key: C, label: CVSS_CALCULATOR.metricValues.C[C] || C },
        I: { key: I, label: CVSS_CALCULATOR.metricValues.I[I] || I },
        A: { key: A, label: CVSS_CALCULATOR.metricValues.A[A] || A },
      },
    };
  },

  /**
   * Parse a CVSS v3.1 vector string and calculate the score.
   *
   * @param {string} vectorStr - e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
   * @returns {object} Same as calculate()
   */
  fromVector(vectorStr) {
    const metrics = {};
    const parts = (vectorStr || "").split("/");
    for (const part of parts) {
      const kv = part.split(":");
      if (kv.length === 2 && CVSS_CALCULATOR.metricNames[kv[0]]) {
        metrics[kv[0]] = kv[1];
      }
    }
    return CVSS_CALCULATOR.calculate(metrics);
  },

  /**
   * Generate a Markdown representation of a CVSS calculation.
   *
   * @param {object} result - Output of calculate() or fromVector()
   * @returns {string} Markdown block
   */
  toMarkdown(result) {
    if (!result) return "";
    const lines = [];
    lines.push(`**CVSS v3.1 Base Score: ${result.score} (${result.severity})**`);
    lines.push("");
    lines.push(`Vector: \`${result.vector}\``);
    lines.push("");
    lines.push("| Metric | Value |");
    lines.push("|---|---|");
    for (const [key, val] of Object.entries(result.metrics)) {
      const name = CVSS_CALCULATOR.metricNames[key] || key;
      lines.push(`| ${name} | ${val.label} (${val.key}) |`);
    }
    lines.push("");
    lines.push(`| Component | Score |`);
    lines.push(`|---|---|`);
    lines.push(`| Impact Sub-Score | ${result.breakdown.impactSubScore} |`);
    lines.push(`| Impact | ${result.breakdown.impact} |`);
    lines.push(`| Exploitability | ${result.breakdown.exploitability} |`);
    lines.push(`| Scope Changed | ${result.breakdown.scopeChanged ? "Yes" : "No"} |`);
    lines.push("");
    return lines.join("\n");
  },
};

// ========================= SEVERITY HELPERS ================================

const SEVERITY_CONFIG = {
  critical: { order: 0, color: "#FF0000", label: "CRITICAL", badge: "[!]" },
  high:     { order: 1, color: "#FF6600", label: "HIGH",     badge: "[!]" },
  medium:   { order: 2, color: "#FFAA00", label: "MEDIUM",   badge: "[*]" },
  low:      { order: 3, color: "#00AA00", label: "LOW",      badge: "[-]" },
  info:     { order: 4, color: "#0066FF", label: "INFO",     badge: "[i]" },
};

function _severityOrder(sev) {
  const cfg = SEVERITY_CONFIG[(sev || "").toLowerCase()];
  return cfg ? cfg.order : 99;
}

function _severityBadge(sev) {
  const cfg = SEVERITY_CONFIG[(sev || "").toLowerCase()];
  return cfg ? cfg.badge : "[?]";
}

function _severityLabel(sev) {
  const cfg = SEVERITY_CONFIG[(sev || "").toLowerCase()];
  return cfg ? cfg.label : "UNKNOWN";
}

// ========================= REPORT TEMPLATES ================================

/**
 * REPORT_TEMPLATES -- Five professional report templates.
 *
 * Each template defines:
 *   - id          : Template identifier
 *   - name        : Human-readable name
 *   - description : What the template is for
 *   - sections    : Array of section definitions
 *   - options     : Default rendering options
 */
const REPORT_TEMPLATES = {
  executive: {
    id: "executive",
    name: "Executive Summary Report",
    description: "High-level overview for management and stakeholders. Focuses on business risk, key metrics, and strategic recommendations without technical details.",
    sections: [
      { id: "cover", title: "Cover Page", generator: "generateCoverPage" },
      { id: "toc", title: "Table of Contents", generator: "generateTOC" },
      { id: "exec_summary", title: "Executive Summary", generator: "_genExecSummary" },
      { id: "risk_overview", title: "Risk Overview", generator: "_genRiskOverview" },
      { id: "key_findings", title: "Key Findings", generator: "_genKeyFindings" },
      { id: "risk_matrix", title: "Risk Assessment Matrix", generator: "_genRiskMatrix" },
      { id: "recommendations", title: "Strategic Recommendations", generator: "_genStrategicRecommendations" },
      { id: "timeline", title: "Remediation Timeline", generator: "_genRemediationTimeline" },
      { id: "conclusion", title: "Conclusion", generator: "_genConclusion" },
    ],
    options: {
      maxFindings: 10,
      showTechnicalDetails: false,
      showCVSS: false,
      showCommands: false,
    },
  },

  technical: {
    id: "technical",
    name: "Technical Assessment Report",
    description: "Detailed technical report for security engineers and system administrators. Includes full finding details, proof-of-concept guidance, and specific remediation steps.",
    sections: [
      { id: "cover", title: "Cover Page", generator: "generateCoverPage" },
      { id: "toc", title: "Table of Contents", generator: "generateTOC" },
      { id: "exec_summary", title: "Executive Summary", generator: "_genExecSummary" },
      { id: "scope", title: "Scope and Methodology", generator: "_genScope" },
      { id: "tool_config", title: "Tools and Configuration", generator: "_genToolConfig" },
      { id: "findings_detail", title: "Detailed Findings", generator: "_genDetailedFindings" },
      { id: "vuln_analysis", title: "Vulnerability Analysis", generator: "_genVulnAnalysis" },
      { id: "risk_matrix", title: "Risk Assessment Matrix", generator: "_genRiskMatrix" },
      { id: "remediation", title: "Remediation Plan", generator: "_genRemediationPlan" },
      { id: "appendix_hosts", title: "Appendix A: Host Details", generator: "_genAppendixHosts" },
      { id: "appendix_ports", title: "Appendix B: Port Listing", generator: "_genAppendixPorts" },
      { id: "appendix_refs", title: "Appendix C: References", generator: "_genAppendixRefs" },
    ],
    options: {
      maxFindings: -1,
      showTechnicalDetails: true,
      showCVSS: true,
      showCommands: true,
    },
  },

  vuln_assessment: {
    id: "vuln_assessment",
    name: "Vulnerability Assessment Report",
    description: "Focused vulnerability report cataloging all identified vulnerabilities with severity ratings, CVE references, and prioritized remediation guidance.",
    sections: [
      { id: "cover", title: "Cover Page", generator: "generateCoverPage" },
      { id: "toc", title: "Table of Contents", generator: "generateTOC" },
      { id: "vuln_summary", title: "Vulnerability Summary", generator: "_genVulnSummary" },
      { id: "severity_breakdown", title: "Severity Breakdown", generator: "_genSeverityBreakdown" },
      { id: "vuln_catalog", title: "Vulnerability Catalog", generator: "_genVulnCatalog" },
      { id: "risk_matrix", title: "Risk Assessment Matrix", generator: "_genRiskMatrix" },
      { id: "remediation", title: "Remediation Priorities", generator: "_genRemediationPriorities" },
      { id: "appendix_refs", title: "Appendix: CVE References", generator: "_genAppendixRefs" },
    ],
    options: {
      maxFindings: -1,
      showTechnicalDetails: true,
      showCVSS: true,
      showCommands: false,
    },
  },

  compliance: {
    id: "compliance",
    name: "Compliance Audit Report",
    description: "Maps findings to common compliance frameworks (PCI-DSS, HIPAA, NIST, CIS). Identifies compliance gaps and provides framework-specific remediation.",
    sections: [
      { id: "cover", title: "Cover Page", generator: "generateCoverPage" },
      { id: "toc", title: "Table of Contents", generator: "generateTOC" },
      { id: "audit_scope", title: "Audit Scope", generator: "_genAuditScope" },
      { id: "compliance_summary", title: "Compliance Summary", generator: "_genComplianceSummary" },
      { id: "framework_mapping", title: "Framework Mapping", generator: "_genFrameworkMapping" },
      { id: "gaps", title: "Compliance Gaps", generator: "_genComplianceGaps" },
      { id: "risk_matrix", title: "Risk Assessment Matrix", generator: "_genRiskMatrix" },
      { id: "remediation", title: "Remediation for Compliance", generator: "_genComplianceRemediation" },
      { id: "attestation", title: "Attestation", generator: "_genAttestation" },
    ],
    options: {
      maxFindings: -1,
      showTechnicalDetails: false,
      showCVSS: true,
      showCommands: false,
    },
  },

  incident: {
    id: "incident",
    name: "Incident Response Report",
    description: "Post-incident report documenting timeline, indicators of compromise, affected systems, containment actions, and lessons learned.",
    sections: [
      { id: "cover", title: "Cover Page", generator: "generateCoverPage" },
      { id: "toc", title: "Table of Contents", generator: "generateTOC" },
      { id: "incident_summary", title: "Incident Summary", generator: "_genIncidentSummary" },
      { id: "timeline", title: "Incident Timeline", generator: "_genIncidentTimeline" },
      { id: "ioc", title: "Indicators of Compromise", generator: "_genIOC" },
      { id: "affected_systems", title: "Affected Systems", generator: "_genAffectedSystems" },
      { id: "containment", title: "Containment Actions", generator: "_genContainmentActions" },
      { id: "root_cause", title: "Root Cause Analysis", generator: "_genRootCause" },
      { id: "lessons", title: "Lessons Learned", generator: "_genLessonsLearned" },
      { id: "recommendations", title: "Recommendations", generator: "_genIncidentRecommendations" },
    ],
    options: {
      maxFindings: -1,
      showTechnicalDetails: true,
      showCVSS: false,
      showCommands: false,
    },
  },
};

// ========================= COMPLIANCE FRAMEWORK DATA =======================

const COMPLIANCE_FRAMEWORKS = {
  "PCI-DSS": {
    name: "PCI-DSS v4.0",
    requirements: {
      "1.1": "Install and maintain network security controls",
      "1.2": "Network security controls are configured and maintained",
      "2.1": "Secure configurations are applied to all system components",
      "2.2": "System components are configured and managed securely",
      "4.1": "Strong cryptography protects cardholder data during transmission",
      "6.1": "Security vulnerabilities are identified and addressed",
      "6.2": "Bespoke and custom software is developed securely",
      "8.1": "Processes for identification and authentication are defined",
      "8.3": "Strong authentication for users and administrators",
      "10.1": "Logging mechanisms are in place",
      "11.3": "External and internal vulnerabilities are regularly tested",
    },
    findingToRequirement(finding) {
      const mappings = [];
      const sev = (finding.severity || "").toLowerCase();
      const summary = (finding.summary || "").toLowerCase();
      // Every vulnerability finding maps to requirement 6.1
      mappings.push("6.1");
      // Cleartext protocols violate 4.1
      if (summary.includes("cleartext") || summary.includes("plain")) {
        mappings.push("4.1");
      }
      // Authentication issues map to 8.1 and 8.3
      if (summary.includes("auth") || summary.includes("password") || summary.includes("credential")) {
        mappings.push("8.1");
        mappings.push("8.3");
      }
      // EOL software is a configuration issue (2.2)
      if (summary.includes("end-of-life") || summary.includes("eol")) {
        mappings.push("2.2");
      }
      // Network-exposed services map to 1.1
      if (sev === "critical" || sev === "high") {
        mappings.push("1.1");
      }
      return [...new Set(mappings)];
    },
  },

  "NIST-800-53": {
    name: "NIST SP 800-53 Rev 5",
    requirements: {
      "AC-3": "Access Enforcement",
      "AC-17": "Remote Access",
      "AU-2": "Event Logging",
      "CA-8": "Penetration Testing",
      "CM-6": "Configuration Settings",
      "CM-7": "Least Functionality",
      "IA-2": "Identification and Authentication",
      "IA-5": "Authenticator Management",
      "RA-5": "Vulnerability Monitoring and Scanning",
      "SC-7": "Boundary Protection",
      "SC-8": "Transmission Confidentiality",
      "SC-13": "Cryptographic Protection",
      "SI-2": "Flaw Remediation",
      "SI-5": "Security Alerts and Advisories",
    },
    findingToRequirement(finding) {
      const mappings = ["RA-5", "SI-2"];
      const summary = (finding.summary || "").toLowerCase();
      if (summary.includes("cleartext") || summary.includes("plain")) {
        mappings.push("SC-8");
        mappings.push("SC-13");
      }
      if (summary.includes("auth") || summary.includes("password")) {
        mappings.push("IA-2");
        mappings.push("IA-5");
      }
      if (summary.includes("end-of-life") || summary.includes("eol")) {
        mappings.push("CM-6");
        mappings.push("CM-7");
      }
      if (summary.includes("remote") || summary.includes("rce")) {
        mappings.push("AC-17");
        mappings.push("SC-7");
      }
      return [...new Set(mappings)];
    },
  },

  "HIPAA": {
    name: "HIPAA Security Rule",
    requirements: {
      "164.308(a)(1)": "Security Management Process",
      "164.308(a)(5)": "Security Awareness and Training",
      "164.310(a)(1)": "Facility Access Controls",
      "164.310(d)(1)": "Device and Media Controls",
      "164.312(a)(1)": "Access Control",
      "164.312(c)(1)": "Integrity Controls",
      "164.312(d)": "Person or Entity Authentication",
      "164.312(e)(1)": "Transmission Security",
    },
    findingToRequirement(finding) {
      const mappings = ["164.308(a)(1)"];
      const summary = (finding.summary || "").toLowerCase();
      if (summary.includes("cleartext") || summary.includes("plain")) {
        mappings.push("164.312(e)(1)");
      }
      if (summary.includes("auth") || summary.includes("password")) {
        mappings.push("164.312(d)");
        mappings.push("164.312(a)(1)");
      }
      return [...new Set(mappings)];
    },
  },

  "CIS": {
    name: "CIS Controls v8",
    requirements: {
      "1": "Inventory and Control of Enterprise Assets",
      "2": "Inventory and Control of Software Assets",
      "3": "Data Protection",
      "4": "Secure Configuration of Enterprise Assets and Software",
      "5": "Account Management",
      "6": "Access Control Management",
      "7": "Continuous Vulnerability Management",
      "8": "Audit Log Management",
      "9": "Email and Web Browser Protections",
      "12": "Network Infrastructure Management",
      "13": "Network Monitoring and Defense",
      "16": "Application Software Security",
    },
    findingToRequirement(finding) {
      const mappings = ["7"];
      const summary = (finding.summary || "").toLowerCase();
      if (summary.includes("cleartext") || summary.includes("plain")) {
        mappings.push("3");
      }
      if (summary.includes("auth") || summary.includes("password")) {
        mappings.push("5");
        mappings.push("6");
      }
      if (summary.includes("end-of-life") || summary.includes("eol")) {
        mappings.push("2");
        mappings.push("4");
      }
      if (summary.includes("web") || summary.includes("http")) {
        mappings.push("9");
        mappings.push("16");
      }
      return [...new Set(mappings)];
    },
  },
};

// ========================= CORE GENERATORS =================================

/**
 * generateCoverPage -- Generate a report cover page in Markdown.
 *
 * @param {object} meta - Report metadata
 * @param {string} meta.title - Report title
 * @param {string} [meta.subtitle] - Subtitle
 * @param {string} [meta.organization] - Client organization
 * @param {string} [meta.assessor] - Assessor name
 * @param {string} [meta.assessorOrg] - Assessor organization
 * @param {string} [meta.classification] - Document classification
 * @param {string} [meta.version] - Document version
 * @param {string} [meta.date] - Report date
 * @param {string} [meta.reportId] - Unique report identifier
 * @returns {string} Markdown cover page
 */
function generateCoverPage(meta) {
  const m = meta || {};
  const title = m.title || "Security Assessment Report";
  const subtitle = m.subtitle || "";
  const org = m.organization || "Target Organization";
  const assessor = m.assessor || "Security Assessor";
  const assessorOrg = m.assessorOrg || "Darknode Security";
  const classification = m.classification || "CONFIDENTIAL";
  const version = m.version || "1.0";
  const date = m.date || new Date().toISOString().split("T")[0];
  const reportId = m.reportId || _generateReportId();

  const lines = [];
  lines.push("---");
  lines.push("");
  lines.push(`# ${title}`);
  if (subtitle) {
    lines.push("");
    lines.push(`## ${subtitle}`);
  }
  lines.push("");
  lines.push("---");
  lines.push("");
  lines.push("| Field | Value |");
  lines.push("|---|---|");
  lines.push(`| **Client** | ${org} |`);
  lines.push(`| **Prepared By** | ${assessor} |`);
  lines.push(`| **Organization** | ${assessorOrg} |`);
  lines.push(`| **Date** | ${date} |`);
  lines.push(`| **Version** | ${version} |`);
  lines.push(`| **Report ID** | ${reportId} |`);
  lines.push(`| **Classification** | ${classification} |`);
  lines.push("");
  lines.push("---");
  lines.push("");
  lines.push(`> **${classification}** -- This document contains sensitive security information.`);
  lines.push("> Distribution is restricted to authorized personnel only.");
  lines.push("> Unauthorized disclosure may compromise the security of the assessed systems.");
  lines.push("");
  lines.push("---");
  lines.push("");

  return lines.join("\n");
}

/**
 * generateTOC -- Generate a table of contents from section definitions.
 *
 * @param {Array} sections - Array of { id, title } objects
 * @returns {string} Markdown TOC
 */
function generateTOC(sections) {
  if (!sections || sections.length === 0) return "";

  const lines = [];
  lines.push("## Table of Contents");
  lines.push("");

  let num = 1;
  for (const section of sections) {
    if (section.id === "cover" || section.id === "toc") continue;
    const anchor = section.title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
    lines.push(`${num}. [${section.title}](#${anchor})`);
    num++;
  }

  lines.push("");
  lines.push("---");
  lines.push("");

  return lines.join("\n");
}

/**
 * formatFinding -- Format a single vulnerability finding as a Markdown block.
 *
 * @param {object} finding - Finding object
 * @param {object} [options] - Formatting options
 * @param {boolean} [options.showCVSS=false] - Include CVSS breakdown
 * @param {boolean} [options.showRemediation=true] - Include remediation
 * @param {boolean} [options.numbered=false] - Prefix with a number
 * @param {number} [options.number=1] - Finding number
 * @returns {string} Markdown finding block
 */
function formatFinding(finding, options) {
  const opts = options || {};
  const f = finding || {};
  const showCVSS = opts.showCVSS || false;
  const showRemediation = opts.showRemediation !== false;
  const numbered = opts.numbered || false;
  const num = opts.number || 1;

  const sev = _severityLabel(f.severity);
  const badge = _severityBadge(f.severity);

  const lines = [];
  const prefix = numbered ? `${num}. ` : "";
  lines.push(`### ${prefix}${badge} ${f.summary || "Untitled Finding"}`);
  lines.push("");
  lines.push(`**Severity:** ${sev}`);
  lines.push("");

  // Affected target
  if (f.host || f.port) {
    lines.push("| Detail | Value |");
    lines.push("|---|---|");
    if (f.host) lines.push(`| Host | ${f.host}${f.hostname ? ` (${f.hostname})` : ""} |`);
    if (f.port) lines.push(`| Port | ${f.port}/${f.protocol || "tcp"} |`);
    if (f.service) lines.push(`| Service | ${f.service} |`);
    if (f.product) lines.push(`| Product | ${f.product}${f.version ? ` ${f.version}` : ""} |`);
    if (f.cve && f.cve.length > 0) {
      lines.push(`| CVE | ${f.cve.join(", ")} |`);
    }
    lines.push("");
  }

  // Description
  if (f.description) {
    lines.push("**Description:**");
    lines.push("");
    lines.push(f.description);
    lines.push("");
  }

  // Evidence
  if (f.evidence) {
    lines.push("**Evidence:**");
    lines.push("");
    lines.push("```");
    lines.push(f.evidence);
    lines.push("```");
    lines.push("");
  }

  // CVSS
  if (showCVSS && f.cvssVector) {
    const cvssResult = CVSS_CALCULATOR.fromVector(f.cvssVector);
    lines.push(CVSS_CALCULATOR.toMarkdown(cvssResult));
  } else if (showCVSS && f.cvssMetrics) {
    const cvssResult = CVSS_CALCULATOR.calculate(f.cvssMetrics);
    lines.push(CVSS_CALCULATOR.toMarkdown(cvssResult));
  }

  // Remediation
  if (showRemediation && f.remediation) {
    lines.push("**Remediation:**");
    lines.push("");
    lines.push(f.remediation);
    lines.push("");
  }

  // References
  if (f.references && f.references.length > 0) {
    lines.push("**References:**");
    lines.push("");
    for (const ref of f.references) {
      lines.push(`- ${ref}`);
    }
    lines.push("");
  }

  lines.push("---");
  lines.push("");

  return lines.join("\n");
}

/**
 * calculateOverallRisk -- Compute an aggregate risk score from findings.
 *
 * Uses a weighted severity model:
 *   critical=10, high=7, medium=4, low=1, info=0
 * Calculates both raw aggregate and normalized (0-100) scores.
 *
 * @param {Array} findings - Array of finding objects
 * @returns {object} Risk assessment
 */
function calculateOverallRisk(findings) {
  if (!findings || findings.length === 0) {
    return {
      score: 0,
      normalizedScore: 0,
      label: "None",
      counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      weightedTotal: 0,
      maxPossible: 0,
      details: "No findings to assess.",
    };
  }

  const weights = { critical: 10, high: 7, medium: 4, low: 1, info: 0 };
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  let weightedTotal = 0;
  for (const f of findings) {
    const sev = (f.severity || "info").toLowerCase();
    if (counts[sev] !== undefined) {
      counts[sev]++;
    }
    weightedTotal += weights[sev] || 0;
  }

  // Max possible = all findings being critical
  const maxPossible = findings.length * weights.critical;

  // Normalized score (0-100)
  const normalizedScore = maxPossible > 0 ? Math.round((weightedTotal / maxPossible) * 100) : 0;

  // Qualitative label
  let label;
  if (counts.critical > 0) {
    label = "Critical";
  } else if (normalizedScore >= 70) {
    label = "Critical";
  } else if (normalizedScore >= 50) {
    label = "High";
  } else if (normalizedScore >= 30) {
    label = "Medium";
  } else if (normalizedScore >= 10) {
    label = "Low";
  } else {
    label = "Informational";
  }

  // Override: any critical finding makes overall risk at least Critical
  if (counts.critical > 0) {
    label = "Critical";
  }

  // Build detail string
  const parts = [];
  if (counts.critical > 0) parts.push(`${counts.critical} critical`);
  if (counts.high > 0) parts.push(`${counts.high} high`);
  if (counts.medium > 0) parts.push(`${counts.medium} medium`);
  if (counts.low > 0) parts.push(`${counts.low} low`);
  if (counts.info > 0) parts.push(`${counts.info} informational`);

  return {
    score: weightedTotal,
    normalizedScore,
    label,
    counts,
    weightedTotal,
    maxPossible,
    details: `${findings.length} findings: ${parts.join(", ")}`,
    breakdown: {
      criticalWeight: counts.critical * weights.critical,
      highWeight: counts.high * weights.high,
      mediumWeight: counts.medium * weights.medium,
      lowWeight: counts.low * weights.low,
    },
  };
}

// ========================= SECTION GENERATORS ==============================

function _genExecSummary(data, meta, opts) {
  const lines = [];
  lines.push("## Executive Summary");
  lines.push("");

  const hostCount = (data.hosts || []).length;
  const findings = data.findings || [];
  const risk = calculateOverallRisk(findings);

  lines.push(`This report presents the results of a security assessment conducted against ${meta.organization || "the target environment"}. The assessment identified **${findings.length}** security findings across **${hostCount}** host(s).`);
  lines.push("");
  lines.push(`**Overall Risk Level: ${risk.label}** (Score: ${risk.normalizedScore}/100)`);
  lines.push("");
  lines.push(`${risk.details}`);
  lines.push("");

  if (risk.counts.critical > 0) {
    lines.push(`**Immediate attention is required.** ${risk.counts.critical} critical-severity finding(s) were identified that may allow unauthorized access, data exfiltration, or system compromise.`);
    lines.push("");
  }

  if (findings.length > 0) {
    lines.push("### Finding Summary");
    lines.push("");
    lines.push("| Severity | Count |");
    lines.push("|---|---|");
    lines.push(`| Critical | ${risk.counts.critical} |`);
    lines.push(`| High | ${risk.counts.high} |`);
    lines.push(`| Medium | ${risk.counts.medium} |`);
    lines.push(`| Low | ${risk.counts.low} |`);
    lines.push(`| Informational | ${risk.counts.info} |`);
    lines.push(`| **Total** | **${findings.length}** |`);
    lines.push("");
  }

  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

function _genRiskOverview(data, meta, opts) {
  const lines = [];
  lines.push("## Risk Overview");
  lines.push("");

  const findings = data.findings || [];
  const risk = calculateOverallRisk(findings);

  lines.push("The following chart summarizes risk distribution across the assessed environment:");
  lines.push("");

  // ASCII bar chart
  const maxBar = 40;
  const maxCount = Math.max(
    risk.counts.critical, risk.counts.high,
    risk.counts.medium, risk.counts.low, risk.counts.info, 1
  );

  for (const sev of ["critical", "high", "medium", "low", "info"]) {
    const count = risk.counts[sev];
    const barLen = Math.round((count / maxCount) * maxBar);
    const bar = "#".repeat(barLen) || (count > 0 ? "#" : "");
    const label = _severityLabel(sev).padEnd(12);
    lines.push(`    ${label} ${bar} ${count}`);
  }

  lines.push("");
  lines.push(`**Normalized Risk Score:** ${risk.normalizedScore}/100`);
  lines.push("");
  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

function _genKeyFindings(data, meta, opts) {
  const lines = [];
  lines.push("## Key Findings");
  lines.push("");

  const findings = data.findings || [];
  const maxFindings = (opts && opts.maxFindings > 0) ? opts.maxFindings : 10;
  const sorted = findings
    .slice()
    .sort((a, b) => _severityOrder(a.severity) - _severityOrder(b.severity));
  const top = sorted.slice(0, maxFindings);

  if (top.length === 0) {
    lines.push("No significant findings were identified during this assessment.");
    lines.push("");
  } else {
    lines.push(`The top ${top.length} findings by severity are presented below:`);
    lines.push("");
    lines.push("| # | Severity | Finding | Affected Host |");
    lines.push("|---|---|---|---|");
    for (let i = 0; i < top.length; i++) {
      const f = top[i];
      lines.push(
        `| ${i + 1} | ${_severityLabel(f.severity)} | ${f.summary || "N/A"} | ${f.host || "N/A"}:${f.port || "N/A"} |`
      );
    }
    lines.push("");
  }

  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

function _genRiskMatrix(data, meta, opts) {
  const lines = [];
  lines.push(RISK_MATRIX.toMarkdown());
  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

function _genStrategicRecommendations(data, meta, opts) {
  const lines = [];
  lines.push("## Strategic Recommendations");
  lines.push("");

  const findings = data.findings || [];
  const risk = calculateOverallRisk(findings);

  lines.push("Based on the assessment results, the following strategic actions are recommended:");
  lines.push("");

  let num = 1;

  if (risk.counts.critical > 0) {
    lines.push(`${num}. **Immediate Remediation of Critical Vulnerabilities** -- Address all critical-severity findings within 24-48 hours. These represent the highest risk to the organization and may be actively exploitable.`);
    lines.push("");
    num++;
  }

  if (risk.counts.high > 0) {
    lines.push(`${num}. **Expedited Patching of High-Risk Systems** -- Schedule patching for high-severity findings within 7 days. Coordinate with system owners to minimize service disruption.`);
    lines.push("");
    num++;
  }

  lines.push(`${num}. **Vulnerability Management Program** -- Establish or enhance a continuous vulnerability management process that includes regular scanning, prioritized remediation, and tracking metrics.`);
  lines.push("");
  num++;

  lines.push(`${num}. **Network Segmentation Review** -- Evaluate current network architecture to ensure adequate segmentation between critical systems, user networks, and internet-facing services.`);
  lines.push("");
  num++;

  lines.push(`${num}. **Security Awareness Training** -- Conduct training for IT staff on secure configuration practices and patch management procedures.`);
  lines.push("");
  num++;

  lines.push(`${num}. **Incident Response Planning** -- Review and update incident response procedures to ensure readiness for security events related to the identified vulnerabilities.`);
  lines.push("");
  num++;

  // EOL software
  const eolFindings = findings.filter((f) =>
    (f.summary || "").toLowerCase().includes("end-of-life") ||
    (f.summary || "").toLowerCase().includes("eol")
  );
  if (eolFindings.length > 0) {
    lines.push(`${num}. **End-of-Life Software Migration** -- ${eolFindings.length} system(s) are running end-of-life software that no longer receives security updates. Plan migration to supported versions.`);
    lines.push("");
    num++;
  }

  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

function _genRemediationTimeline(data, meta, opts) {
  const lines = [];
  lines.push("## Remediation Timeline");
  lines.push("");
  lines.push("The following timeline provides recommended remediation windows based on finding severity:");
  lines.push("");
  lines.push("| Priority | Severity | Timeline | Action |");
  lines.push("|---|---|---|---|");
  lines.push("| P1 | Critical | 0-48 hours | Immediate patching or mitigation |");
  lines.push("| P2 | High | 1-7 days | Expedited remediation |");
  lines.push("| P3 | Medium | 7-30 days | Scheduled maintenance window |");
  lines.push("| P4 | Low | 30-90 days | Next scheduled update cycle |");
  lines.push("| P5 | Informational | As resources allow | Best practice improvement |");
  lines.push("");

  const findings = data.findings || [];
  const risk = calculateOverallRisk(findings);

  if (findings.length > 0) {
    lines.push("### Current Remediation Workload");
    lines.push("");
    if (risk.counts.critical > 0) {
      lines.push(`- **P1 (Critical):** ${risk.counts.critical} item(s) -- target completion within 48 hours`);
    }
    if (risk.counts.high > 0) {
      lines.push(`- **P2 (High):** ${risk.counts.high} item(s) -- target completion within 7 days`);
    }
    if (risk.counts.medium > 0) {
      lines.push(`- **P3 (Medium):** ${risk.counts.medium} item(s) -- target completion within 30 days`);
    }
    if (risk.counts.low > 0) {
      lines.push(`- **P4 (Low):** ${risk.counts.low} item(s) -- target completion within 90 days`);
    }
    if (risk.counts.info > 0) {
      lines.push(`- **P5 (Info):** ${risk.counts.info} item(s) -- schedule as resources allow`);
    }
    lines.push("");
  }

  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

function _genConclusion(data, meta, opts) {
  const lines = [];
  lines.push("## Conclusion");
  lines.push("");

  const findings = data.findings || [];
  const risk = calculateOverallRisk(findings);

  lines.push(`The security assessment of ${meta.organization || "the target environment"} identified ${findings.length} finding(s) with an overall risk level of **${risk.label}**.`);
  lines.push("");

  if (risk.label === "Critical" || risk.label === "High") {
    lines.push("The current security posture requires urgent attention. Critical and high-severity vulnerabilities present immediate risk of exploitation that could result in unauthorized access, data loss, or service disruption.");
  } else if (risk.label === "Medium") {
    lines.push("The security posture is moderate. While no immediately critical issues were found, the identified medium-severity findings should be addressed in a timely manner to prevent escalation.");
  } else {
    lines.push("The security posture is acceptable for the current assessment scope. Continue monitoring and maintaining systems to preserve this status.");
  }

  lines.push("");
  lines.push("A follow-up assessment is recommended after remediation activities are completed to verify the effectiveness of applied fixes.");
  lines.push("");
  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

function _genScope(data, meta, opts) {
  const lines = [];
  lines.push("## Scope and Methodology");
  lines.push("");
  lines.push("### Assessment Scope");
  lines.push("");
  lines.push(`The assessment targeted the following environment: ${meta.organization || "Target Environment"}`);
  lines.push("");

  const hosts = data.hosts || [];
  if (hosts.length > 0) {
    lines.push("**In-Scope Hosts:**");
    lines.push("");
    for (const host of hosts) {
      const hn = (host.hostnames && host.hostnames[0]) ? ` (${host.hostnames[0].name})` : "";
      const portCount = (host.ports || []).filter((p) => p.state === "open").length;
      lines.push(`- ${host.ip}${hn} -- ${portCount} open port(s)`);
    }
    lines.push("");
  }

  lines.push("### Methodology");
  lines.push("");
  lines.push("The assessment followed a structured methodology including:");
  lines.push("");
  lines.push("1. **Reconnaissance** -- Network discovery and port scanning");
  lines.push("2. **Enumeration** -- Service identification and version detection");
  lines.push("3. **Vulnerability Identification** -- Matching services against known vulnerability databases");
  lines.push("4. **Analysis** -- Risk rating and impact assessment");
  lines.push("5. **Reporting** -- Documentation and remediation guidance");
  lines.push("");
  lines.push("### Limitations");
  lines.push("");
  lines.push("- This assessment was performed from an external/unauthenticated perspective unless otherwise noted.");
  lines.push("- Results are point-in-time and may not reflect changes made after the scan date.");
  lines.push("- Absence of findings does not guarantee absence of vulnerabilities.");
  lines.push("");
  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

function _genToolConfig(data, meta, opts) {
  const lines = [];
  lines.push("## Tools and Configuration");
  lines.push("");
  lines.push("The following tools and configurations were used during the assessment:");
  lines.push("");
  lines.push("| Tool | Purpose |");
  lines.push("|---|---|");
  lines.push("| Nmap | Network discovery and port scanning |");
  lines.push("| Nmap NSE Scripts | Service enumeration and vulnerability checks |");
  lines.push("| Darknode Nexus | Scan parsing, analysis, and report generation |");
  lines.push("");

  if (data.scanInfo) {
    lines.push("### Scan Configuration");
    lines.push("");
    if (data.scanInfo.args) lines.push(`- **Command:** \`${data.scanInfo.args}\``);
    if (data.scanInfo.version) lines.push(`- **Nmap Version:** ${data.scanInfo.version}`);
    if (data.scanInfo.type) lines.push(`- **Scan Type:** ${data.scanInfo.type}`);
    if (data.scanInfo.protocol) lines.push(`- **Protocol:** ${data.scanInfo.protocol}`);
    if (data.scanInfo.startTime) lines.push(`- **Start Time:** ${data.scanInfo.startTime}`);
    lines.push("");
  }

  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

function _genDetailedFindings(data, meta, opts) {
  const lines = [];
  lines.push("## Detailed Findings");
  lines.push("");

  const findings = data.findings || [];
  if (findings.length === 0) {
    lines.push("No vulnerabilities were identified during this assessment.");
    lines.push("");
    lines.push("---");
    lines.push("");
    return lines.join("\n");
  }

  const sorted = findings
    .slice()
    .sort((a, b) => _severityOrder(a.severity) - _severityOrder(b.severity));

  for (let i = 0; i < sorted.length; i++) {
    lines.push(formatFinding(sorted[i], {
      showCVSS: opts.showCVSS,
      showRemediation: true,
      numbered: true,
      number: i + 1,
    }));
  }

  return lines.join("\n");
}

function _genVulnAnalysis(data, meta, opts) {
  const lines = [];
  lines.push("## Vulnerability Analysis");
  lines.push("");

  const findings = data.findings || [];
  if (findings.length === 0) {
    lines.push("No vulnerabilities to analyze.");
    lines.push("");
    lines.push("---");
    lines.push("");
    return lines.join("\n");
  }

  // Group by severity
  const bySeverity = {};
  for (const f of findings) {
    const sev = (f.severity || "info").toLowerCase();
    if (!bySeverity[sev]) bySeverity[sev] = [];
    bySeverity[sev].push(f);
  }

  // Group by host
  const byHost = {};
  for (const f of findings) {
    const h = f.host || "unknown";
    if (!byHost[h]) byHost[h] = [];
    byHost[h].push(f);
  }

  // Group by service
  const byService = {};
  for (const f of findings) {
    const s = f.service || f.product || "unknown";
    if (!byService[s]) byService[s] = [];
    byService[s].push(f);
  }

  lines.push("### By Severity");
  lines.push("");
  for (const sev of ["critical", "high", "medium", "low", "info"]) {
    const group = bySeverity[sev];
    if (group && group.length > 0) {
      lines.push(`**${_severityLabel(sev)}** (${group.length}):`);
      for (const f of group) {
        lines.push(`- ${f.host}:${f.port} -- ${f.summary}`);
      }
      lines.push("");
    }
  }

  lines.push("### By Host");
  lines.push("");
  for (const [host, group] of Object.entries(byHost)) {
    const critCount = group.filter((f) => f.severity === "critical").length;
    const highCount = group.filter((f) => f.severity === "high").length;
    lines.push(`**${host}** (${group.length} findings: ${critCount} critical, ${highCount} high):`);
    for (const f of group) {
      lines.push(`- [${_severityLabel(f.severity)}] Port ${f.port}: ${f.summary}`);
    }
    lines.push("");
  }

  lines.push("### By Service Category");
  lines.push("");
  for (const [service, group] of Object.entries(byService)) {
    lines.push(`**${service}** (${group.length} findings):`);
    for (const f of group) {
      lines.push(`- ${f.host}:${f.port} [${_severityLabel(f.severity)}] ${f.summary}`);
    }
    lines.push("");
  }

  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

function _genRemediationPlan(data, meta, opts) {
  const lines = [];
  lines.push("## Remediation Plan");
  lines.push("");

  const findings = data.findings || [];
  if (findings.length === 0) {
    lines.push("No remediation actions required.");
    lines.push("");
    lines.push("---");
    lines.push("");
    return lines.join("\n");
  }

  // Group remediation actions and deduplicate
  const actions = new Map();
  for (const f of findings) {
    const rem = f.remediation || "Review and address finding";
    if (!actions.has(rem)) {
      actions.set(rem, { remediation: rem, severity: f.severity, affected: [], findings: [] });
    }
    const entry = actions.get(rem);
    entry.affected.push(`${f.host}:${f.port}`);
    entry.findings.push(f);
    // Keep highest severity
    if (_severityOrder(f.severity) < _severityOrder(entry.severity)) {
      entry.severity = f.severity;
    }
  }

  const sortedActions = Array.from(actions.values()).sort(
    (a, b) => _severityOrder(a.severity) - _severityOrder(b.severity)
  );

  lines.push("| Priority | Action | Severity | Affected Systems |");
  lines.push("|---|---|---|---|");

  for (let i = 0; i < sortedActions.length; i++) {
    const a = sortedActions[i];
    const uniqueAffected = [...new Set(a.affected)];
    lines.push(
      `| ${i + 1} | ${a.remediation} | ${_severityLabel(a.severity)} | ${uniqueAffected.join(", ")} |`
    );
  }

  lines.push("");

  // Detailed steps
  lines.push("### Detailed Remediation Steps");
  lines.push("");

  for (let i = 0; i < sortedActions.length; i++) {
    const a = sortedActions[i];
    lines.push(`#### ${i + 1}. ${a.remediation}`);
    lines.push("");
    lines.push(`- **Priority:** ${_severityLabel(a.severity)}`);
    lines.push(`- **Affected:** ${[...new Set(a.affected)].join(", ")}`);
    lines.push(`- **Findings addressed:** ${a.findings.length}`);
    lines.push("");

    // Per-finding details
    for (const f of a.findings) {
      lines.push(`  - ${f.host}:${f.port} -- ${f.summary}`);
      if (f.cve && f.cve.length > 0) {
        lines.push(`    References: ${f.cve.join(", ")}`);
      }
    }
    lines.push("");
  }

  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

function _genAppendixHosts(data, meta, opts) {
  const lines = [];
  lines.push("## Appendix A: Host Details");
  lines.push("");

  const hosts = data.hosts || [];
  if (hosts.length === 0) {
    lines.push("No host data available.");
    lines.push("");
    lines.push("---");
    lines.push("");
    return lines.join("\n");
  }

  for (const host of hosts) {
    const hn = (host.hostnames && host.hostnames[0]) ? host.hostnames[0].name : "";
    lines.push(`### ${host.ip}${hn ? ` (${hn})` : ""}`);
    lines.push("");
    lines.push(`- **Status:** ${host.status || "unknown"}`);
    if (host.mac) lines.push(`- **MAC Address:** ${host.mac}`);
    if (host.os && host.os.length > 0) {
      lines.push(`- **OS Detection:** ${host.os[0].name} (${host.os[0].accuracy}% confidence)`);
    }
    if (host.distance) lines.push(`- **Hops:** ${host.distance}`);
    if (host.uptime) {
      const days = Math.floor(host.uptime.seconds / 86400);
      lines.push(`- **Uptime:** ~${days} days`);
    }
    lines.push("");

    // Port table
    const openPorts = (host.ports || []).filter((p) => p.state === "open");
    if (openPorts.length > 0) {
      lines.push("| Port | Protocol | State | Service | Version |");
      lines.push("|---|---|---|---|---|");
      for (const port of openPorts) {
        const svc = port.service || {};
        const version = [svc.product, svc.version].filter(Boolean).join(" ");
        lines.push(
          `| ${port.portId} | ${port.protocol} | ${port.state} | ${svc.name || ""} | ${version} |`
        );
      }
      lines.push("");
    }
  }

  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

function _genAppendixPorts(data, meta, opts) {
  const lines = [];
  lines.push("## Appendix B: Port Listing");
  lines.push("");

  const allPorts = [];
  for (const host of data.hosts || []) {
    for (const port of host.ports || []) {
      if (port.state === "open") {
        const svc = port.service || {};
        allPorts.push({
          host: host.ip,
          port: port.portId,
          protocol: port.protocol,
          service: svc.name || "",
          version: [svc.product, svc.version].filter(Boolean).join(" "),
        });
      }
    }
  }

  if (allPorts.length === 0) {
    lines.push("No open ports detected.");
    lines.push("");
    lines.push("---");
    lines.push("");
    return lines.join("\n");
  }

  // Sort by port number
  allPorts.sort((a, b) => a.port - b.port || a.host.localeCompare(b.host));

  lines.push(`Total open ports: ${allPorts.length}`);
  lines.push("");
  lines.push("| Host | Port | Protocol | Service | Version |");
  lines.push("|---|---|---|---|---|");

  for (const p of allPorts) {
    lines.push(`| ${p.host} | ${p.port} | ${p.protocol} | ${p.service} | ${p.version} |`);
  }

  lines.push("");
  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

function _genAppendixRefs(data, meta, opts) {
  const lines = [];
  lines.push("## Appendix: References");
  lines.push("");

  // Collect all unique CVEs
  const findings = data.findings || [];
  const cveSet = new Set();
  for (const f of findings) {
    if (f.cve) {
      for (const c of f.cve) {
        cveSet.add(c);
      }
    }
  }

  const cves = Array.from(cveSet).sort();

  if (cves.length === 0) {
    lines.push("No CVE references in this report.");
    lines.push("");
    lines.push("---");
    lines.push("");
    return lines.join("\n");
  }

  lines.push("### CVE References");
  lines.push("");
  lines.push("| CVE ID | NVD Link |");
  lines.push("|---|---|");
  for (const cve of cves) {
    lines.push(`| ${cve} | https://nvd.nist.gov/vuln/detail/${cve} |`);
  }
  lines.push("");

  lines.push("### Additional Resources");
  lines.push("");
  lines.push("- [NIST National Vulnerability Database](https://nvd.nist.gov/)");
  lines.push("- [MITRE CVE List](https://cve.mitre.org/)");
  lines.push("- [FIRST CVSS v3.1 Calculator](https://www.first.org/cvss/calculator/3.1)");
  lines.push("- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)");
  lines.push("- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)");
  lines.push("");

  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

// Vulnerability Assessment specific sections

function _genVulnSummary(data, meta, opts) {
  const lines = [];
  lines.push("## Vulnerability Summary");
  lines.push("");

  const findings = data.findings || [];
  const risk = calculateOverallRisk(findings);

  lines.push(`A total of **${findings.length}** vulnerabilities were identified during this assessment.`);
  lines.push("");
  lines.push(`**Overall Risk: ${risk.label}** (Normalized Score: ${risk.normalizedScore}/100)`);
  lines.push("");
  lines.push(`Findings breakdown: ${risk.details}`);
  lines.push("");
  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

function _genSeverityBreakdown(data, meta, opts) {
  const lines = [];
  lines.push("## Severity Breakdown");
  lines.push("");

  const findings = data.findings || [];
  const risk = calculateOverallRisk(findings);

  lines.push("| Severity | Count | Percentage | Weighted Score |");
  lines.push("|---|---|---|---|");

  const weights = { critical: 10, high: 7, medium: 4, low: 1, info: 0 };
  for (const sev of ["critical", "high", "medium", "low", "info"]) {
    const count = risk.counts[sev];
    const pct = findings.length > 0 ? Math.round((count / findings.length) * 100) : 0;
    const weighted = count * weights[sev];
    lines.push(`| ${_severityLabel(sev)} | ${count} | ${pct}% | ${weighted} |`);
  }

  lines.push(`| **Total** | **${findings.length}** | **100%** | **${risk.weightedTotal}** |`);
  lines.push("");
  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

function _genVulnCatalog(data, meta, opts) {
  const lines = [];
  lines.push("## Vulnerability Catalog");
  lines.push("");

  const findings = data.findings || [];
  const sorted = findings
    .slice()
    .sort((a, b) => _severityOrder(a.severity) - _severityOrder(b.severity));

  for (let i = 0; i < sorted.length; i++) {
    lines.push(formatFinding(sorted[i], {
      showCVSS: opts.showCVSS,
      showRemediation: true,
      numbered: true,
      number: i + 1,
    }));
  }

  if (sorted.length === 0) {
    lines.push("No vulnerabilities cataloged.");
    lines.push("");
  }

  return lines.join("\n");
}

function _genRemediationPriorities(data, meta, opts) {
  const lines = [];
  lines.push("## Remediation Priorities");
  lines.push("");

  const findings = data.findings || [];
  if (findings.length === 0) {
    lines.push("No remediation required.");
    lines.push("");
    lines.push("---");
    lines.push("");
    return lines.join("\n");
  }

  const sorted = findings
    .slice()
    .sort((a, b) => _severityOrder(a.severity) - _severityOrder(b.severity));

  lines.push("Findings are listed in order of remediation priority (highest severity first):");
  lines.push("");

  let currentSev = null;
  let num = 1;
  for (const f of sorted) {
    if (f.severity !== currentSev) {
      currentSev = f.severity;
      lines.push(`### ${_severityLabel(currentSev)} Priority`);
      lines.push("");
    }
    lines.push(`${num}. **${f.host}:${f.port}** -- ${f.summary}`);
    if (f.remediation) {
      lines.push(`   - Action: ${f.remediation}`);
    }
    if (f.cve && f.cve.length > 0) {
      lines.push(`   - CVE: ${f.cve.join(", ")}`);
    }
    lines.push("");
    num++;
  }

  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

// Compliance specific sections

function _genAuditScope(data, meta, opts) {
  const lines = [];
  lines.push("## Audit Scope");
  lines.push("");
  lines.push(`This compliance audit evaluates the security posture of ${meta.organization || "the target environment"} against the following frameworks:`);
  lines.push("");
  for (const [key, fw] of Object.entries(COMPLIANCE_FRAMEWORKS)) {
    lines.push(`- **${fw.name}**`);
  }
  lines.push("");

  const hosts = data.hosts || [];
  lines.push(`**Systems Assessed:** ${hosts.length} host(s)`);
  lines.push("");
  for (const host of hosts) {
    const openPorts = (host.ports || []).filter((p) => p.state === "open").length;
    lines.push(`- ${host.ip} (${openPorts} open ports)`);
  }
  lines.push("");
  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

function _genComplianceSummary(data, meta, opts) {
  const lines = [];
  lines.push("## Compliance Summary");
  lines.push("");

  const findings = data.findings || [];

  for (const [fwKey, fw] of Object.entries(COMPLIANCE_FRAMEWORKS)) {
    const affectedReqs = new Set();
    for (const f of findings) {
      const reqs = fw.findingToRequirement(f);
      for (const r of reqs) affectedReqs.add(r);
    }
    const totalReqs = Object.keys(fw.requirements).length;
    const failedReqs = affectedReqs.size;
    const passRate = totalReqs > 0 ? Math.round(((totalReqs - failedReqs) / totalReqs) * 100) : 100;

    lines.push(`### ${fw.name}`);
    lines.push("");
    lines.push(`- Requirements evaluated: ${totalReqs}`);
    lines.push(`- Requirements with findings: ${failedReqs}`);
    lines.push(`- Preliminary pass rate: ${passRate}%`);
    lines.push("");
  }

  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

function _genFrameworkMapping(data, meta, opts) {
  const lines = [];
  lines.push("## Framework Mapping");
  lines.push("");

  const findings = data.findings || [];

  for (const [fwKey, fw] of Object.entries(COMPLIANCE_FRAMEWORKS)) {
    lines.push(`### ${fw.name}`);
    lines.push("");
    lines.push("| Requirement | Description | Status | Related Findings |");
    lines.push("|---|---|---|---|");

    for (const [reqId, reqDesc] of Object.entries(fw.requirements)) {
      const relatedFindings = findings.filter((f) => {
        const reqs = fw.findingToRequirement(f);
        return reqs.includes(reqId);
      });
      const status = relatedFindings.length > 0 ? "FINDING" : "PASS";
      const findingList = relatedFindings.length > 0
        ? relatedFindings.map((f) => `${f.host}:${f.port}`).slice(0, 3).join("; ")
        : "--";
      lines.push(`| ${reqId} | ${reqDesc} | ${status} | ${findingList} |`);
    }

    lines.push("");
  }

  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

function _genComplianceGaps(data, meta, opts) {
  const lines = [];
  lines.push("## Compliance Gaps");
  lines.push("");

  const findings = data.findings || [];
  if (findings.length === 0) {
    lines.push("No compliance gaps identified.");
    lines.push("");
    lines.push("---");
    lines.push("");
    return lines.join("\n");
  }

  for (const [fwKey, fw] of Object.entries(COMPLIANCE_FRAMEWORKS)) {
    const gaps = {};
    for (const f of findings) {
      const reqs = fw.findingToRequirement(f);
      for (const r of reqs) {
        if (!gaps[r]) gaps[r] = [];
        gaps[r].push(f);
      }
    }

    if (Object.keys(gaps).length === 0) continue;

    lines.push(`### ${fw.name} Gaps`);
    lines.push("");

    for (const [reqId, gapFindings] of Object.entries(gaps)) {
      const reqDesc = fw.requirements[reqId] || reqId;
      lines.push(`#### ${reqId}: ${reqDesc}`);
      lines.push("");
      lines.push(`**${gapFindings.length} related finding(s):**`);
      lines.push("");
      for (const f of gapFindings) {
        lines.push(`- [${_severityLabel(f.severity)}] ${f.host}:${f.port} -- ${f.summary}`);
      }
      lines.push("");
    }
  }

  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

function _genComplianceRemediation(data, meta, opts) {
  const lines = [];
  lines.push("## Remediation for Compliance");
  lines.push("");
  lines.push("The following actions are recommended to address identified compliance gaps:");
  lines.push("");

  const findings = data.findings || [];
  const sorted = findings
    .slice()
    .sort((a, b) => _severityOrder(a.severity) - _severityOrder(b.severity));

  // Deduplicate remediation actions
  const seen = new Set();
  let num = 1;
  for (const f of sorted) {
    const rem = f.remediation || "Address finding";
    if (seen.has(rem)) continue;
    seen.add(rem);
    lines.push(`${num}. **${rem}**`);
    lines.push(`   - Severity: ${_severityLabel(f.severity)}`);
    if (f.cve && f.cve.length > 0) {
      lines.push(`   - Related CVE(s): ${f.cve.join(", ")}`);
    }
    // Map to frameworks
    for (const [fwKey, fw] of Object.entries(COMPLIANCE_FRAMEWORKS)) {
      const reqs = fw.findingToRequirement(f);
      if (reqs.length > 0) {
        lines.push(`   - ${fw.name}: ${reqs.join(", ")}`);
      }
    }
    lines.push("");
    num++;
  }

  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

function _genAttestation(data, meta, opts) {
  const lines = [];
  lines.push("## Attestation");
  lines.push("");
  lines.push("This compliance audit report has been prepared based on the information gathered during the assessment period. The findings and recommendations herein reflect the state of the assessed systems at the time of evaluation.");
  lines.push("");
  lines.push("| Field | Value |");
  lines.push("|---|---|");
  lines.push(`| Assessor | ${meta.assessor || "Security Assessor"} |`);
  lines.push(`| Organization | ${meta.assessorOrg || "Darknode Security"} |`);
  lines.push(`| Date | ${meta.date || new Date().toISOString().split("T")[0]} |`);
  lines.push(`| Report Version | ${meta.version || "1.0"} |`);
  lines.push("");
  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

// Incident Response specific sections

function _genIncidentSummary(data, meta, opts) {
  const lines = [];
  lines.push("## Incident Summary");
  lines.push("");

  const incident = meta.incident || {};
  lines.push("| Field | Value |");
  lines.push("|---|---|");
  lines.push(`| Incident ID | ${incident.id || meta.reportId || _generateReportId()} |`);
  lines.push(`| Classification | ${incident.classification || "Security Incident"} |`);
  lines.push(`| Severity | ${incident.severity || "Under Investigation"} |`);
  lines.push(`| Status | ${incident.status || "Open"} |`);
  lines.push(`| Detection Date | ${incident.detectionDate || meta.date || new Date().toISOString().split("T")[0]} |`);
  lines.push(`| Detection Method | ${incident.detectionMethod || "Automated scan"} |`);
  lines.push(`| Reporter | ${incident.reporter || meta.assessor || "Security Team"} |`);
  lines.push("");

  if (incident.description) {
    lines.push("### Description");
    lines.push("");
    lines.push(incident.description);
    lines.push("");
  }

  const findings = data.findings || [];
  const hosts = data.hosts || [];
  lines.push(`**Affected Systems:** ${hosts.length} host(s)`);
  lines.push(`**Related Findings:** ${findings.length}`);
  lines.push("");
  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

function _genIncidentTimeline(data, meta, opts) {
  const lines = [];
  lines.push("## Incident Timeline");
  lines.push("");

  const timeline = (meta.incident && meta.incident.timeline) || [];

  if (timeline.length > 0) {
    lines.push("| Timestamp | Event | Detail |");
    lines.push("|---|---|---|");
    for (const event of timeline) {
      lines.push(`| ${event.time || "TBD"} | ${event.event || ""} | ${event.detail || ""} |`);
    }
  } else {
    lines.push("| Timestamp | Event | Detail |");
    lines.push("|---|---|---|");
    lines.push(`| ${meta.date || new Date().toISOString().split("T")[0]} | Initial detection | Anomalous activity detected |`);
    lines.push("| TBD | Investigation initiated | Security team notified |");
    lines.push("| TBD | Scope determined | Affected systems identified |");
    lines.push("| TBD | Containment applied | Mitigation measures deployed |");
    lines.push("| TBD | Recovery initiated | Systems restoration in progress |");
    lines.push("| TBD | Post-incident review | Lessons learned documented |");
  }

  lines.push("");
  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

function _genIOC(data, meta, opts) {
  const lines = [];
  lines.push("## Indicators of Compromise");
  lines.push("");

  const iocs = (meta.incident && meta.incident.iocs) || [];

  if (iocs.length > 0) {
    lines.push("| Type | Indicator | Context |");
    lines.push("|---|---|---|");
    for (const ioc of iocs) {
      lines.push(`| ${ioc.type || "Unknown"} | \`${ioc.value || ""}\` | ${ioc.context || ""} |`);
    }
  } else {
    lines.push("No indicators of compromise have been cataloged at this time.");
    lines.push("");
    lines.push("IOC categories to investigate:");
    lines.push("");
    lines.push("- **IP Addresses** -- Suspicious source/destination IPs");
    lines.push("- **Domains** -- Malicious or C2 domains");
    lines.push("- **File Hashes** -- MD5/SHA256 of suspicious files");
    lines.push("- **URLs** -- Malicious URLs accessed");
    lines.push("- **Email Addresses** -- Phishing sender addresses");
    lines.push("- **Registry Keys** -- Persistence mechanisms (Windows)");
    lines.push("- **Process Names** -- Suspicious running processes");
  }

  lines.push("");
  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

function _genAffectedSystems(data, meta, opts) {
  const lines = [];
  lines.push("## Affected Systems");
  lines.push("");

  const hosts = data.hosts || [];
  const findings = data.findings || [];

  if (hosts.length === 0) {
    lines.push("No affected systems identified.");
    lines.push("");
    lines.push("---");
    lines.push("");
    return lines.join("\n");
  }

  lines.push("| Host | Hostname | Open Ports | Findings | Highest Severity |");
  lines.push("|---|---|---|---|---|");

  for (const host of hosts) {
    const hn = (host.hostnames && host.hostnames[0]) ? host.hostnames[0].name : "--";
    const openPorts = (host.ports || []).filter((p) => p.state === "open").length;
    const hostFindings = findings.filter((f) => f.host === host.ip);
    const highest = hostFindings.length > 0
      ? hostFindings.reduce((a, b) => _severityOrder(a.severity) < _severityOrder(b.severity) ? a : b).severity
      : "none";
    lines.push(`| ${host.ip} | ${hn} | ${openPorts} | ${hostFindings.length} | ${_severityLabel(highest)} |`);
  }

  lines.push("");
  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

function _genContainmentActions(data, meta, opts) {
  const lines = [];
  lines.push("## Containment Actions");
  lines.push("");

  const actions = (meta.incident && meta.incident.containmentActions) || [];

  if (actions.length > 0) {
    for (let i = 0; i < actions.length; i++) {
      const a = actions[i];
      lines.push(`${i + 1}. **${a.action || "Action"}**`);
      if (a.detail) lines.push(`   ${a.detail}`);
      if (a.status) lines.push(`   Status: ${a.status}`);
      lines.push("");
    }
  } else {
    lines.push("### Recommended Containment Actions");
    lines.push("");
    lines.push("1. **Network Isolation** -- Disconnect affected systems from the network to prevent lateral movement.");
    lines.push("");
    lines.push("2. **Account Lockout** -- Disable compromised accounts and force password resets for affected users.");
    lines.push("");
    lines.push("3. **Firewall Rules** -- Block identified malicious IP addresses and domains at the perimeter.");
    lines.push("");
    lines.push("4. **Service Shutdown** -- Stop vulnerable services identified in the scan until patches can be applied.");
    lines.push("");
    lines.push("5. **Evidence Preservation** -- Capture disk images and memory dumps before making changes to affected systems.");
    lines.push("");
    lines.push("6. **Log Collection** -- Centralize and preserve logs from affected systems, firewalls, and related infrastructure.");
    lines.push("");
  }

  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

function _genRootCause(data, meta, opts) {
  const lines = [];
  lines.push("## Root Cause Analysis");
  lines.push("");

  if (meta.incident && meta.incident.rootCause) {
    lines.push(meta.incident.rootCause);
  } else {
    lines.push("Root cause analysis is in progress. The following factors are under investigation:");
    lines.push("");

    const findings = data.findings || [];
    if (findings.length > 0) {
      lines.push("### Potential Contributing Factors");
      lines.push("");
      const criticalFindings = findings.filter((f) => f.severity === "critical" || f.severity === "high");
      for (const f of criticalFindings.slice(0, 5)) {
        lines.push(`- **${f.host}:${f.port}** -- ${f.summary}`);
        if (f.remediation) lines.push(`  Remediation: ${f.remediation}`);
      }
      lines.push("");
    }

    lines.push("### Investigation Areas");
    lines.push("");
    lines.push("- Unpatched vulnerabilities in exposed services");
    lines.push("- Misconfigured access controls or authentication");
    lines.push("- Weak or compromised credentials");
    lines.push("- Missing or inadequate network segmentation");
    lines.push("- Delayed patch application for known CVEs");
    lines.push("");
  }

  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

function _genLessonsLearned(data, meta, opts) {
  const lines = [];
  lines.push("## Lessons Learned");
  lines.push("");

  if (meta.incident && meta.incident.lessonsLearned) {
    for (const lesson of meta.incident.lessonsLearned) {
      lines.push(`- ${lesson}`);
    }
  } else {
    lines.push("The following areas should be reviewed as part of the post-incident process:");
    lines.push("");
    lines.push("1. **Detection Capability** -- Was the incident detected promptly? What monitoring gaps existed?");
    lines.push("");
    lines.push("2. **Response Time** -- How quickly was the security team able to respond and contain the incident?");
    lines.push("");
    lines.push("3. **Communication** -- Were stakeholders notified appropriately and in a timely manner?");
    lines.push("");
    lines.push("4. **Patch Management** -- Were systems up to date? What prevented timely patching?");
    lines.push("");
    lines.push("5. **Access Controls** -- Were least privilege principles applied? Were unnecessary services exposed?");
    lines.push("");
    lines.push("6. **Documentation** -- Was the incident response plan adequate? What updates are needed?");
    lines.push("");
    lines.push("7. **Training** -- Do team members need additional training in incident response procedures?");
    lines.push("");
  }

  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

function _genIncidentRecommendations(data, meta, opts) {
  const lines = [];
  lines.push("## Recommendations");
  lines.push("");

  const findings = data.findings || [];
  const risk = calculateOverallRisk(findings);

  lines.push("### Immediate Actions");
  lines.push("");
  lines.push("1. Complete containment of all affected systems.");
  lines.push("2. Apply emergency patches for all critical and high-severity findings.");
  lines.push("3. Conduct credential rotation for all accounts on affected systems.");
  lines.push("4. Review and update firewall rules to restrict unnecessary access.");
  lines.push("");

  lines.push("### Short-Term Actions (1-4 weeks)");
  lines.push("");
  lines.push("1. Complete forensic analysis of affected systems.");
  lines.push("2. Remediate all identified vulnerabilities per the findings in this report.");
  lines.push("3. Implement enhanced monitoring for previously identified indicators of compromise.");
  lines.push("4. Conduct a focused security review of systems adjacent to affected hosts.");
  lines.push("");

  lines.push("### Long-Term Actions (1-6 months)");
  lines.push("");
  lines.push("1. Review and update the incident response plan based on lessons learned.");
  lines.push("2. Implement or enhance vulnerability management program.");
  lines.push("3. Deploy network segmentation to limit blast radius of future incidents.");
  lines.push("4. Conduct security awareness training for all staff.");
  lines.push("5. Schedule a follow-up penetration test to validate remediation effectiveness.");
  lines.push("");

  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

// ========================= MAIN GENERATOR ==================================

// Map generator names to functions
const SECTION_GENERATORS = {
  generateCoverPage: (data, meta, opts) => generateCoverPage(meta),
  generateTOC: (data, meta, opts, template) => generateTOC(template.sections),
  _genExecSummary,
  _genRiskOverview,
  _genKeyFindings,
  _genRiskMatrix,
  _genStrategicRecommendations,
  _genRemediationTimeline,
  _genConclusion,
  _genScope,
  _genToolConfig,
  _genDetailedFindings,
  _genVulnAnalysis,
  _genRemediationPlan,
  _genAppendixHosts,
  _genAppendixPorts,
  _genAppendixRefs,
  _genVulnSummary,
  _genSeverityBreakdown,
  _genVulnCatalog,
  _genRemediationPriorities,
  _genAuditScope,
  _genComplianceSummary,
  _genFrameworkMapping,
  _genComplianceGaps,
  _genComplianceRemediation,
  _genAttestation,
  _genIncidentSummary,
  _genIncidentTimeline,
  _genIOC,
  _genAffectedSystems,
  _genContainmentActions,
  _genRootCause,
  _genLessonsLearned,
  _genIncidentRecommendations,
};

/**
 * generateReport -- Generate a complete security report from a template and data.
 *
 * @param {string|object} template - Template ID string or template object
 * @param {object} data - Report data (parsed scan result + findings)
 * @param {object} [meta] - Report metadata (title, org, assessor, etc.)
 * @returns {string} Complete Markdown report
 */
function generateReport(template, data, meta) {
  // Resolve template
  let tmpl;
  if (typeof template === "string") {
    tmpl = REPORT_TEMPLATES[template];
    if (!tmpl) {
      throw new Error(`Unknown report template: "${template}". Available: ${Object.keys(REPORT_TEMPLATES).join(", ")}`);
    }
  } else if (template && template.sections) {
    tmpl = template;
  } else {
    throw new Error("generateReport: template must be a template ID string or a template object with sections");
  }

  const reportMeta = meta || {};
  const reportData = data || {};
  const opts = tmpl.options || {};

  // Ensure findings array exists
  if (!reportData.findings) {
    reportData.findings = [];
  }

  const parts = [];

  for (const section of tmpl.sections) {
    const generatorName = section.generator;
    const generator = SECTION_GENERATORS[generatorName];

    if (generator) {
      try {
        const content = generator(reportData, reportMeta, opts, tmpl);
        if (content) {
          parts.push(content);
        }
      } catch (err) {
        parts.push(`## ${section.title}\n\n*Error generating section: ${err.message}*\n\n---\n\n`);
      }
    } else {
      parts.push(`## ${section.title}\n\n*Section content not available.*\n\n---\n\n`);
    }
  }

  // Footer
  parts.push("");
  parts.push("---");
  parts.push(`*Report generated by Darknode Nexus on ${new Date().toISOString()}*`);
  parts.push("");

  return parts.join("\n");
}

// ========================= UTILITIES =======================================

/**
 * Generate a unique report identifier.
 * @private
 */
function _generateReportId() {
  const date = new Date();
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, "0");
  const d = String(date.getDate()).padStart(2, "0");
  const rand = Math.random().toString(36).substring(2, 8).toUpperCase();
  return `DN-${y}${m}${d}-${rand}`;
}

/**
 * List available report templates.
 *
 * @returns {Array} Array of { id, name, description }
 */
function listTemplates() {
  return Object.values(REPORT_TEMPLATES).map((t) => ({
    id: t.id,
    name: t.name,
    description: t.description,
    sectionCount: t.sections.length,
  }));
}

/**
 * Get a specific template by ID.
 *
 * @param {string} id - Template identifier
 * @returns {object|null} Template or null
 */
function getTemplate(id) {
  return REPORT_TEMPLATES[id] || null;
}

/**
 * Create a custom template by extending an existing one.
 *
 * @param {string} baseId - Base template ID
 * @param {object} overrides - Override properties
 * @returns {object} New template object
 */
function extendTemplate(baseId, overrides) {
  const base = REPORT_TEMPLATES[baseId];
  if (!base) {
    throw new Error(`Base template not found: "${baseId}"`);
  }
  return {
    ...JSON.parse(JSON.stringify(base)),
    ...overrides,
    id: overrides.id || `${baseId}-custom`,
    options: { ...base.options, ...(overrides.options || {}) },
  };
}

// ========================= MODULE EXPORTS ==================================

module.exports = {
  generateReport,
  REPORT_TEMPLATES,
  formatFinding,
  calculateOverallRisk,
  generateCoverPage,
  generateTOC,
  RISK_MATRIX,
  CVSS_CALCULATOR,
  COMPLIANCE_FRAMEWORKS,
  SEVERITY_CONFIG,
  listTemplates,
  getTemplate,
  extendTemplate,
};
