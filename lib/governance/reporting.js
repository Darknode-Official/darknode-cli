"use strict";
// Report generation module -- transforms raw findings, compliance checks,
// and scan results into structured, presentation-ready reports.  Supports
// multiple output formats (markdown, JSON, CSV) and multiple report types
// (pentest, vulnerability assessment, compliance, incident response, risk).

const crypto = require("crypto");

// ---------------------------------------------------------------------------
// CVSS-like risk scoring -- simplified for internal use.  Maps common
// finding attributes to a 0-10 severity score.
// ---------------------------------------------------------------------------

// Attack vector values (network is worst, physical is best).
const ATTACK_VECTORS = Object.freeze({
  network:  0.85,
  adjacent: 0.62,
  local:    0.55,
  physical: 0.20,
});

// Attack complexity (low is worse -- easier to exploit).
const ATTACK_COMPLEXITY = Object.freeze({
  low:  0.77,
  high: 0.44,
});

// Privileges required.
const PRIVILEGES_REQUIRED = Object.freeze({
  none: 0.85,
  low:  0.62,
  high: 0.27,
});

// User interaction.
const USER_INTERACTION = Object.freeze({
  none:     0.85,
  required: 0.62,
});

// Impact values for confidentiality, integrity, availability.
const IMPACT_VALUES = Object.freeze({
  none: 0.00,
  low:  0.22,
  high: 0.56,
});

// Scope change modifier.
const SCOPE_MODIFIER = Object.freeze({
  unchanged: 1.0,
  changed:   1.08,
});

function calculateRiskScore(finding) {
  if (!finding) return { score: 0, severity: "none", vector: "" };

  // If a numeric score is already provided, just classify it.
  if (typeof finding.score === "number") {
    return {
      score: Math.round(finding.score * 10) / 10,
      severity: classifySeverity(finding.score),
      vector: finding.vector || "",
    };
  }

  // Calculate from component metrics.
  const av = ATTACK_VECTORS[finding.attackVector || "network"] || 0.85;
  const ac = ATTACK_COMPLEXITY[finding.attackComplexity || "low"] || 0.77;
  const pr = PRIVILEGES_REQUIRED[finding.privilegesRequired || "none"] || 0.85;
  const ui = USER_INTERACTION[finding.userInteraction || "none"] || 0.85;

  const ci = IMPACT_VALUES[finding.confidentialityImpact || "none"] || 0;
  const ii = IMPACT_VALUES[finding.integrityImpact || "none"] || 0;
  const ai = IMPACT_VALUES[finding.availabilityImpact || "none"] || 0;

  const scope = SCOPE_MODIFIER[finding.scope || "unchanged"] || 1.0;

  // Exploitability sub-score.
  const exploitability = 8.22 * av * ac * pr * ui;

  // Impact sub-score.
  const impactBase = 1 - ((1 - ci) * (1 - ii) * (1 - ai));
  let impact;
  if (scope > 1.0) {
    impact = 7.52 * (impactBase - 0.029) - 3.25 * Math.pow(impactBase - 0.02, 15);
  } else {
    impact = 6.42 * impactBase;
  }

  if (impact <= 0) {
    return { score: 0, severity: "none", vector: buildVector(finding) };
  }

  let score;
  if (scope > 1.0) {
    score = Math.min(10, scope * (impact + exploitability));
  } else {
    score = Math.min(10, impact + exploitability);
  }

  // Round up to nearest 0.1.
  score = Math.ceil(score * 10) / 10;

  return {
    score,
    severity: classifySeverity(score),
    vector: buildVector(finding),
    exploitability: Math.round(exploitability * 100) / 100,
    impact: Math.round(impact * 100) / 100,
  };
}

function classifySeverity(score) {
  if (score === 0) return "none";
  if (score <= 3.9) return "low";
  if (score <= 6.9) return "medium";
  if (score <= 8.9) return "high";
  return "critical";
}

function buildVector(finding) {
  const parts = [
    "AV:" + (finding.attackVector || "N").charAt(0).toUpperCase(),
    "AC:" + (finding.attackComplexity || "L").charAt(0).toUpperCase(),
    "PR:" + (finding.privilegesRequired || "N").charAt(0).toUpperCase(),
    "UI:" + (finding.userInteraction || "N").charAt(0).toUpperCase(),
    "S:" + (finding.scope || "U").charAt(0).toUpperCase(),
    "C:" + (finding.confidentialityImpact || "N").charAt(0).toUpperCase(),
    "I:" + (finding.integrityImpact || "N").charAt(0).toUpperCase(),
    "A:" + (finding.availabilityImpact || "N").charAt(0).toUpperCase(),
  ];
  return parts.join("/");
}

// ---------------------------------------------------------------------------
// Severity color / label helpers (for terminal and markdown).
// ---------------------------------------------------------------------------

const SEVERITY_LABELS = Object.freeze({
  critical: { label: "CRITICAL", badge: "[!]", color: "red" },
  high:     { label: "HIGH",     badge: "[H]", color: "red" },
  medium:   { label: "MEDIUM",   badge: "[M]", color: "yellow" },
  low:      { label: "LOW",      badge: "[L]", color: "blue" },
  info:     { label: "INFO",     badge: "[i]", color: "gray" },
  none:     { label: "NONE",     badge: "[-]", color: "gray" },
});

function severityLabel(severity) {
  const s = (severity || "none").toLowerCase();
  return SEVERITY_LABELS[s] || SEVERITY_LABELS.none;
}

// ---------------------------------------------------------------------------
// formatFinding(finding) -- render a single finding into a markdown block.
//
// Expected finding shape:
//   {
//     id:           string,
//     title:        string,
//     severity:     "critical" | "high" | "medium" | "low" | "info",
//     description:  string,
//     evidence:     string,        -- proof of concept or evidence
//     impact:       string,        -- business impact description
//     remediation:  string,        -- recommended fix
//     references:   string[],      -- CVE IDs, URLs
//     affectedHost: string,        -- target host
//     affectedPort: number,        -- target port
//     service:      string,        -- service name
//     tool:         string,        -- tool that found it
//     cwe:          string,        -- CWE identifier
//     cvss:         object,        -- CVSS metric components (optional)
//     tags:         string[],      -- categorization tags
//     status:       string,        -- "open" | "remediated" | "accepted" | "false_positive"
//   }
// ---------------------------------------------------------------------------

function formatFinding(finding) {
  if (!finding) return "";
  const lines = [];
  const sev = severityLabel(finding.severity);
  const risk = finding.cvss ? calculateRiskScore(finding.cvss) : null;

  // Header.
  lines.push(`### ${sev.badge} ${finding.title || "Untitled Finding"}`);
  lines.push("");

  // Metadata table.
  lines.push("| Field | Value |");
  lines.push("|-------|-------|");
  if (finding.id) lines.push(`| ID | ${finding.id} |`);
  lines.push(`| Severity | **${sev.label}** |`);
  if (risk) lines.push(`| CVSS Score | ${risk.score} (${risk.severity}) |`);
  if (risk && risk.vector) lines.push(`| CVSS Vector | \`${risk.vector}\` |`);
  if (finding.cwe) lines.push(`| CWE | ${finding.cwe} |`);
  if (finding.affectedHost) lines.push(`| Host | ${finding.affectedHost} |`);
  if (finding.affectedPort) lines.push(`| Port | ${finding.affectedPort} |`);
  if (finding.service) lines.push(`| Service | ${finding.service} |`);
  if (finding.tool) lines.push(`| Tool | ${finding.tool} |`);
  if (finding.status) lines.push(`| Status | ${finding.status} |`);
  if (finding.tags && finding.tags.length > 0) {
    lines.push(`| Tags | ${finding.tags.join(", ")} |`);
  }
  lines.push("");

  // Description.
  if (finding.description) {
    lines.push("**Description:**");
    lines.push("");
    lines.push(finding.description);
    lines.push("");
  }

  // Evidence.
  if (finding.evidence) {
    lines.push("**Evidence:**");
    lines.push("");
    lines.push("```");
    lines.push(finding.evidence);
    lines.push("```");
    lines.push("");
  }

  // Impact.
  if (finding.impact) {
    lines.push("**Impact:**");
    lines.push("");
    lines.push(finding.impact);
    lines.push("");
  }

  // Remediation.
  if (finding.remediation) {
    lines.push("**Remediation:**");
    lines.push("");
    lines.push(finding.remediation);
    lines.push("");
  }

  // References.
  if (finding.references && finding.references.length > 0) {
    lines.push("**References:**");
    lines.push("");
    for (const ref of finding.references) {
      lines.push(`- ${ref}`);
    }
    lines.push("");
  }

  lines.push("---");
  lines.push("");
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Report templates -- reusable structure definitions for different report types.
// ---------------------------------------------------------------------------

const TEMPLATE_PENTEST = {
  id: "pentest",
  name: "Penetration Test Report",
  sections: [
    "title_page",
    "executive_summary",
    "scope",
    "methodology",
    "findings_summary",
    "detailed_findings",
    "risk_matrix",
    "remediation_roadmap",
    "appendix_tools",
    "appendix_evidence",
  ],
  description: "Full penetration test engagement report with methodology, findings, and remediation guidance.",
};

const TEMPLATE_VULN_ASSESSMENT = {
  id: "vuln_assessment",
  name: "Vulnerability Assessment Report",
  sections: [
    "title_page",
    "executive_summary",
    "scope",
    "scan_results",
    "findings_by_severity",
    "affected_hosts",
    "remediation_priorities",
    "appendix_raw_output",
  ],
  description: "Automated vulnerability scan results with prioritized remediation.",
};

const TEMPLATE_COMPLIANCE = {
  id: "compliance",
  name: "Compliance Assessment Report",
  sections: [
    "title_page",
    "executive_summary",
    "framework_overview",
    "control_status",
    "gap_analysis",
    "evidence_mapping",
    "remediation_plan",
    "risk_acceptance",
  ],
  description: "Compliance posture assessment against a security framework.",
};

const TEMPLATE_INCIDENT = {
  id: "incident",
  name: "Incident Response Report",
  sections: [
    "title_page",
    "executive_summary",
    "timeline",
    "scope_of_impact",
    "root_cause_analysis",
    "containment_actions",
    "eradication_steps",
    "recovery_status",
    "lessons_learned",
    "indicators_of_compromise",
  ],
  description: "Post-incident analysis and response documentation.",
};

const TEMPLATE_RISK = {
  id: "risk",
  name: "Risk Assessment Report",
  sections: [
    "title_page",
    "executive_summary",
    "asset_inventory",
    "threat_landscape",
    "vulnerability_overview",
    "risk_matrix",
    "risk_register",
    "mitigation_recommendations",
    "residual_risk",
  ],
  description: "Organizational risk assessment with threat modeling.",
};

const REPORT_TEMPLATES = Object.freeze({
  pentest: TEMPLATE_PENTEST,
  vuln_assessment: TEMPLATE_VULN_ASSESSMENT,
  compliance: TEMPLATE_COMPLIANCE,
  incident: TEMPLATE_INCIDENT,
  risk: TEMPLATE_RISK,
});

// ---------------------------------------------------------------------------
// generateFindingReport(findings, options) -- produce a complete pentest-style
// markdown report from an array of findings.
//
// Options:
//   - title:        report title (default "Penetration Test Report")
//   - client:       client / organization name
//   - assessor:     assessor / tester name
//   - dateRange:    { start, end } of the engagement
//   - scope:        array of in-scope targets
//   - methodology:  description of methodology used
//   - classification: "confidential" | "internal" | "public"
// ---------------------------------------------------------------------------

function generateFindingReport(findings, options) {
  if (!findings) findings = [];
  if (!options) options = {};

  const title = options.title || "Penetration Test Report";
  const client = options.client || "Target Organization";
  const assessor = options.assessor || process.env.USER || "Security Assessor";
  const dateRange = options.dateRange || { start: "N/A", end: "N/A" };
  const classification = options.classification || "CONFIDENTIAL";
  const reportId = crypto.randomBytes(8).toString("hex").toUpperCase();
  const generatedAt = new Date().toISOString();

  // Sort findings by severity (critical first).
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...findings].sort((a, b) => {
    const sa = severityOrder[a.severity] !== undefined ? severityOrder[a.severity] : 5;
    const sb = severityOrder[b.severity] !== undefined ? severityOrder[b.severity] : 5;
    return sa - sb;
  });

  // Count by severity.
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of sorted) {
    const s = (f.severity || "info").toLowerCase();
    if (counts[s] !== undefined) counts[s]++;
  }
  const totalFindings = sorted.length;

  const lines = [];

  // --- Title Page ---
  lines.push(`# ${title}`);
  lines.push("");
  lines.push(`**Classification:** ${classification}`);
  lines.push(`**Report ID:** ${reportId}`);
  lines.push(`**Generated:** ${generatedAt.replace("T", " ").slice(0, 19)}`);
  lines.push("");
  lines.push("| Field | Detail |");
  lines.push("|-------|--------|");
  lines.push(`| Client | ${client} |`);
  lines.push(`| Assessor | ${assessor} |`);
  lines.push(`| Engagement Period | ${dateRange.start} to ${dateRange.end} |`);
  lines.push(`| Total Findings | ${totalFindings} |`);
  lines.push(`| Critical | ${counts.critical} |`);
  lines.push(`| High | ${counts.high} |`);
  lines.push(`| Medium | ${counts.medium} |`);
  lines.push(`| Low | ${counts.low} |`);
  lines.push(`| Informational | ${counts.info} |`);
  lines.push("");
  lines.push("---");
  lines.push("");

  // --- Executive Summary ---
  lines.push("## Executive Summary");
  lines.push("");
  lines.push(generateExecSummaryParagraph(counts, totalFindings, client));
  lines.push("");

  // --- Scope ---
  if (options.scope && options.scope.length > 0) {
    lines.push("## Scope");
    lines.push("");
    lines.push("The following targets were included in the assessment:");
    lines.push("");
    for (const target of options.scope) {
      lines.push(`- ${target}`);
    }
    lines.push("");
  }

  // --- Methodology ---
  lines.push("## Methodology");
  lines.push("");
  if (options.methodology) {
    lines.push(options.methodology);
  } else {
    lines.push("The assessment followed industry-standard penetration testing methodology:");
    lines.push("");
    lines.push("1. **Reconnaissance** -- Passive and active information gathering");
    lines.push("2. **Enumeration** -- Service discovery, version detection, and fingerprinting");
    lines.push("3. **Vulnerability Analysis** -- Automated scanning and manual testing");
    lines.push("4. **Exploitation** -- Controlled exploitation of identified vulnerabilities");
    lines.push("5. **Post-Exploitation** -- Privilege escalation, lateral movement, data access");
    lines.push("6. **Reporting** -- Documentation of findings with evidence and remediation");
  }
  lines.push("");

  // --- Findings Summary ---
  lines.push("## Findings Summary");
  lines.push("");
  lines.push("| # | Severity | Title | Host | Status |");
  lines.push("|---|----------|-------|------|--------|");
  for (let i = 0; i < sorted.length; i++) {
    const f = sorted[i];
    const sev = severityLabel(f.severity);
    const host = f.affectedHost || "N/A";
    const status = f.status || "open";
    lines.push(`| ${i + 1} | ${sev.badge} ${sev.label} | ${f.title || "Untitled"} | ${host} | ${status} |`);
  }
  lines.push("");

  // --- Risk Matrix ---
  lines.push("## Risk Matrix");
  lines.push("");
  lines.push(generateRiskMatrix(sorted));
  lines.push("");

  // --- Detailed Findings ---
  lines.push("## Detailed Findings");
  lines.push("");
  for (let i = 0; i < sorted.length; i++) {
    lines.push(`#### Finding ${i + 1} of ${sorted.length}`);
    lines.push("");
    lines.push(formatFinding(sorted[i]));
  }

  // --- Remediation Roadmap ---
  lines.push("## Remediation Roadmap");
  lines.push("");
  lines.push(generateRemediationRoadmap(sorted));
  lines.push("");

  // --- Appendix: Tools ---
  lines.push("## Appendix A: Tools Used");
  lines.push("");
  const toolSet = new Set();
  for (const f of sorted) {
    if (f.tool) toolSet.add(f.tool);
  }
  if (toolSet.size > 0) {
    for (const tool of Array.from(toolSet).sort()) {
      lines.push(`- ${tool}`);
    }
  } else {
    lines.push("No specific tools recorded in findings.");
  }
  lines.push("");

  // --- Footer ---
  lines.push("---");
  lines.push("");
  lines.push(`*Report generated by darknode governance reporting module.*`);
  lines.push(`*Report ID: ${reportId} | Classification: ${classification}*`);
  lines.push("");

  return {
    content: lines.join("\n"),
    reportId,
    format: "markdown",
    template: "pentest",
    findings: totalFindings,
    counts,
    generatedAt,
  };
}

// Helper: generate an executive summary paragraph from counts.
function generateExecSummaryParagraph(counts, total, client) {
  if (total === 0) {
    return `The security assessment of ${client} identified no vulnerabilities during the engagement period. The assessed systems appear to be well-configured and maintained. Continued monitoring and regular assessments are recommended to maintain this posture.`;
  }

  const critHigh = counts.critical + counts.high;
  let urgency;
  if (counts.critical > 0) {
    urgency = `The assessment identified **${counts.critical} critical** finding(s) that require immediate attention. These represent severe risks that could lead to full system compromise, data breach, or significant operational disruption.`;
  } else if (counts.high > 0) {
    urgency = `The assessment identified **${counts.high} high-severity** finding(s) that should be addressed as a priority. While no critical vulnerabilities were found, the high-severity issues present significant risk to the organization.`;
  } else {
    urgency = `No critical or high-severity vulnerabilities were identified. The findings consist primarily of medium and low-severity issues that should be addressed as part of regular security maintenance.`;
  }

  const breakdown = `In total, **${total}** finding(s) were identified: ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low, and ${counts.info} informational.`;

  const recommendation = critHigh > 0
    ? `It is strongly recommended that the ${critHigh} critical/high finding(s) be remediated within 30 days, with medium findings addressed within 90 days.`
    : `The identified findings should be incorporated into the regular patching and hardening cycle.`;

  return [urgency, "", breakdown, "", recommendation].join("\n");
}

// Helper: generate a risk matrix visualization.
function generateRiskMatrix(findings) {
  // Likelihood vs Impact grid.
  const lines = [];
  lines.push("```");
  lines.push("Likelihood      | Low Impact | Med Impact | High Impact");
  lines.push("----------------|------------|------------|------------");

  // Categorize findings into the matrix.
  const matrix = {
    "High Likelihood":   { low: 0, med: 0, high: 0 },
    "Medium Likelihood": { low: 0, med: 0, high: 0 },
    "Low Likelihood":    { low: 0, med: 0, high: 0 },
  };

  for (const f of findings) {
    const sev = (f.severity || "info").toLowerCase();
    let likelihood = "Medium Likelihood";
    let impact = "med";

    if (sev === "critical") { likelihood = "High Likelihood"; impact = "high"; }
    else if (sev === "high") { likelihood = "High Likelihood"; impact = "med"; }
    else if (sev === "medium") { likelihood = "Medium Likelihood"; impact = "med"; }
    else if (sev === "low") { likelihood = "Low Likelihood"; impact = "low"; }
    else { likelihood = "Low Likelihood"; impact = "low"; }

    matrix[likelihood][impact]++;
  }

  for (const [row, cols] of Object.entries(matrix)) {
    const padRow = row.padEnd(16);
    const low = String(cols.low).padStart(5).padEnd(10);
    const med = String(cols.med).padStart(5).padEnd(10);
    const high = String(cols.high).padStart(5).padEnd(10);
    lines.push(`${padRow}| ${low} | ${med} | ${high}`);
  }

  lines.push("```");
  return lines.join("\n");
}

// Helper: generate a remediation roadmap.
function generateRemediationRoadmap(findings) {
  const lines = [];
  const immediate = findings.filter((f) => f.severity === "critical");
  const shortTerm = findings.filter((f) => f.severity === "high");
  const mediumTerm = findings.filter((f) => f.severity === "medium");
  const longTerm = findings.filter((f) => f.severity === "low" || f.severity === "info");

  if (immediate.length > 0) {
    lines.push("### Immediate (0-7 days)");
    lines.push("");
    for (const f of immediate) {
      lines.push(`- [ ] **${f.title || "Untitled"}** -- ${f.remediation || "See detailed finding for remediation steps."}`);
    }
    lines.push("");
  }

  if (shortTerm.length > 0) {
    lines.push("### Short-Term (7-30 days)");
    lines.push("");
    for (const f of shortTerm) {
      lines.push(`- [ ] **${f.title || "Untitled"}** -- ${f.remediation || "See detailed finding for remediation steps."}`);
    }
    lines.push("");
  }

  if (mediumTerm.length > 0) {
    lines.push("### Medium-Term (30-90 days)");
    lines.push("");
    for (const f of mediumTerm) {
      lines.push(`- [ ] **${f.title || "Untitled"}** -- ${f.remediation || "See detailed finding for remediation steps."}`);
    }
    lines.push("");
  }

  if (longTerm.length > 0) {
    lines.push("### Long-Term (90+ days)");
    lines.push("");
    for (const f of longTerm) {
      lines.push(`- [ ] **${f.title || "Untitled"}** -- ${f.remediation || "See detailed finding for remediation steps."}`);
    }
    lines.push("");
  }

  if (lines.length === 0) {
    lines.push("No findings to remediate.");
  }

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// generateComplianceReport(checks, options) -- produce a compliance status
// report from an array of control checks.
//
// Check structure:
//   {
//     controlId:    string,      -- e.g. "AC-1", "CIS 1.1"
//     title:        string,      -- control title
//     framework:    string,      -- "NIST 800-53", "CIS", "PCI-DSS", etc.
//     category:     string,      -- control family / category
//     status:       "pass" | "fail" | "partial" | "not_applicable" | "not_tested",
//     evidence:     string,      -- supporting evidence
//     gap:          string,      -- gap description (for fail/partial)
//     remediation:  string,      -- recommended remediation
//     priority:     "critical" | "high" | "medium" | "low",
//     owner:        string,      -- responsible party
//     dueDate:      string,      -- remediation due date
//   }
// ---------------------------------------------------------------------------

function generateComplianceReport(checks, options) {
  if (!checks) checks = [];
  if (!options) options = {};

  const title = options.title || "Compliance Assessment Report";
  const framework = options.framework || "Security Controls";
  const client = options.client || "Organization";
  const assessor = options.assessor || process.env.USER || "Assessor";
  const classification = options.classification || "CONFIDENTIAL";
  const reportId = crypto.randomBytes(8).toString("hex").toUpperCase();
  const generatedAt = new Date().toISOString();

  // Tally statuses.
  const statusCounts = { pass: 0, fail: 0, partial: 0, not_applicable: 0, not_tested: 0 };
  for (const c of checks) {
    const s = c.status || "not_tested";
    if (statusCounts[s] !== undefined) statusCounts[s]++;
  }
  const totalChecks = checks.length;
  const applicable = totalChecks - statusCounts.not_applicable;
  const complianceRate = applicable > 0
    ? Math.round((statusCounts.pass / applicable) * 100)
    : 0;

  const lines = [];

  // --- Title Page ---
  lines.push(`# ${title}`);
  lines.push("");
  lines.push(`**Framework:** ${framework}`);
  lines.push(`**Classification:** ${classification}`);
  lines.push(`**Report ID:** ${reportId}`);
  lines.push(`**Generated:** ${generatedAt.replace("T", " ").slice(0, 19)}`);
  lines.push("");
  lines.push("| Field | Detail |");
  lines.push("|-------|--------|");
  lines.push(`| Organization | ${client} |`);
  lines.push(`| Assessor | ${assessor} |`);
  lines.push(`| Total Controls | ${totalChecks} |`);
  lines.push(`| Applicable | ${applicable} |`);
  lines.push(`| Passing | ${statusCounts.pass} |`);
  lines.push(`| Failing | ${statusCounts.fail} |`);
  lines.push(`| Partial | ${statusCounts.partial} |`);
  lines.push(`| Not Tested | ${statusCounts.not_tested} |`);
  lines.push(`| Compliance Rate | **${complianceRate}%** |`);
  lines.push("");
  lines.push("---");
  lines.push("");

  // --- Executive Summary ---
  lines.push("## Executive Summary");
  lines.push("");
  lines.push(generateComplianceSummary(statusCounts, complianceRate, framework, client));
  lines.push("");

  // --- Compliance Overview ---
  lines.push("## Compliance Overview");
  lines.push("");
  lines.push("```");
  lines.push(`Compliance Rate: ${complianceRate}%`);
  lines.push(`${"#".repeat(Math.floor(complianceRate / 2))}${"_".repeat(50 - Math.floor(complianceRate / 2))} ${complianceRate}%`);
  lines.push("```");
  lines.push("");

  // --- Control Status Table ---
  lines.push("## Control Status");
  lines.push("");
  lines.push("| Control ID | Title | Category | Status | Priority | Owner |");
  lines.push("|------------|-------|----------|--------|----------|-------|");
  for (const c of checks) {
    const status = formatStatus(c.status);
    const prio = c.priority || "-";
    const owner = c.owner || "-";
    const cat = c.category || "-";
    lines.push(`| ${c.controlId || "-"} | ${c.title || "-"} | ${cat} | ${status} | ${prio} | ${owner} |`);
  }
  lines.push("");

  // --- Gap Analysis ---
  const gaps = checks.filter((c) => c.status === "fail" || c.status === "partial");
  if (gaps.length > 0) {
    lines.push("## Gap Analysis");
    lines.push("");
    for (const g of gaps) {
      lines.push(`### ${g.controlId}: ${g.title || "Untitled"}`);
      lines.push("");
      lines.push(`**Status:** ${formatStatus(g.status)}`);
      if (g.priority) lines.push(`**Priority:** ${g.priority}`);
      lines.push("");
      if (g.gap) {
        lines.push("**Gap Description:**");
        lines.push("");
        lines.push(g.gap);
        lines.push("");
      }
      if (g.evidence) {
        lines.push("**Current Evidence:**");
        lines.push("");
        lines.push(g.evidence);
        lines.push("");
      }
      if (g.remediation) {
        lines.push("**Remediation:**");
        lines.push("");
        lines.push(g.remediation);
        lines.push("");
      }
      if (g.owner) lines.push(`**Owner:** ${g.owner}`);
      if (g.dueDate) lines.push(`**Due Date:** ${g.dueDate}`);
      lines.push("");
      lines.push("---");
      lines.push("");
    }
  }

  // --- Evidence Mapping ---
  const withEvidence = checks.filter((c) => c.evidence);
  if (withEvidence.length > 0) {
    lines.push("## Evidence Mapping");
    lines.push("");
    lines.push("| Control | Status | Evidence |");
    lines.push("|---------|--------|----------|");
    for (const c of withEvidence) {
      const evidence = c.evidence.length > 60 ? c.evidence.slice(0, 57) + "..." : c.evidence;
      lines.push(`| ${c.controlId} | ${formatStatus(c.status)} | ${evidence} |`);
    }
    lines.push("");
  }

  // --- Remediation Plan ---
  const remediation = checks.filter((c) =>
    (c.status === "fail" || c.status === "partial") && c.remediation
  );
  if (remediation.length > 0) {
    lines.push("## Remediation Plan");
    lines.push("");
    lines.push("| # | Control | Priority | Remediation | Owner | Due |");
    lines.push("|---|---------|----------|-------------|-------|-----|");
    for (let i = 0; i < remediation.length; i++) {
      const c = remediation[i];
      const rem = c.remediation.length > 50 ? c.remediation.slice(0, 47) + "..." : c.remediation;
      lines.push(`| ${i + 1} | ${c.controlId} | ${c.priority || "-"} | ${rem} | ${c.owner || "-"} | ${c.dueDate || "-"} |`);
    }
    lines.push("");
  }

  // --- Footer ---
  lines.push("---");
  lines.push("");
  lines.push(`*Report generated by darknode governance reporting module.*`);
  lines.push(`*Report ID: ${reportId} | Framework: ${framework} | Classification: ${classification}*`);
  lines.push("");

  return {
    content: lines.join("\n"),
    reportId,
    format: "markdown",
    template: "compliance",
    controls: totalChecks,
    statusCounts,
    complianceRate,
    generatedAt,
  };
}

function formatStatus(status) {
  const map = {
    pass: "PASS",
    fail: "FAIL",
    partial: "PARTIAL",
    not_applicable: "N/A",
    not_tested: "NOT TESTED",
  };
  return map[status] || status || "UNKNOWN";
}

function generateComplianceSummary(counts, rate, framework, client) {
  const lines = [];

  if (rate >= 90) {
    lines.push(`${client} demonstrates a strong compliance posture against ${framework}, achieving a **${rate}%** compliance rate across applicable controls.`);
  } else if (rate >= 70) {
    lines.push(`${client} has achieved a **${rate}%** compliance rate against ${framework}. While the majority of controls are met, several gaps remain that require attention.`);
  } else if (rate >= 50) {
    lines.push(`${client} has achieved a **${rate}%** compliance rate against ${framework}. Significant gaps exist that present risk to the organization and should be addressed with priority.`);
  } else {
    lines.push(`${client} has achieved a **${rate}%** compliance rate against ${framework}. The compliance posture requires substantial improvement. A dedicated remediation program is recommended.`);
  }

  lines.push("");

  if (counts.fail > 0) {
    lines.push(`**${counts.fail}** control(s) are currently failing and require remediation.`);
  }
  if (counts.partial > 0) {
    lines.push(`**${counts.partial}** control(s) are partially implemented and need additional work.`);
  }
  if (counts.not_tested > 0) {
    lines.push(`**${counts.not_tested}** control(s) were not tested during this assessment and should be evaluated in follow-up.`);
  }

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// generateExecutiveSummary(data) -- produce a high-level summary suitable
// for non-technical stakeholders.
//
// data: {
//   title:         string,
//   client:        string,
//   dateRange:     { start, end },
//   findings:      finding[],      -- optional: from pentest
//   checks:        check[],        -- optional: from compliance
//   risks:         risk[],         -- optional: from risk assessment
//   highlights:    string[],       -- key takeaways
//   recommendations: string[],    -- top recommendations
// }
// ---------------------------------------------------------------------------

function generateExecutiveSummary(data) {
  if (!data) data = {};
  const title = data.title || "Executive Summary";
  const client = data.client || "Organization";
  const reportId = crypto.randomBytes(8).toString("hex").toUpperCase();
  const generatedAt = new Date().toISOString();

  const lines = [];

  lines.push(`# ${title}`);
  lines.push("");
  lines.push(`**Prepared for:** ${client}`);
  lines.push(`**Date:** ${generatedAt.replace("T", " ").slice(0, 10)}`);
  if (data.dateRange) {
    lines.push(`**Assessment Period:** ${data.dateRange.start} to ${data.dateRange.end}`);
  }
  lines.push(`**Report ID:** ${reportId}`);
  lines.push("");
  lines.push("---");
  lines.push("");

  // Overall posture assessment.
  lines.push("## Security Posture Overview");
  lines.push("");

  if (data.findings && data.findings.length > 0) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of data.findings) {
      const s = (f.severity || "info").toLowerCase();
      if (counts[s] !== undefined) counts[s]++;
    }

    const overallRisk = counts.critical > 0 ? "Critical"
      : counts.high > 0 ? "High"
      : counts.medium > 0 ? "Medium"
      : "Low";

    lines.push(`**Overall Risk Level:** ${overallRisk}`);
    lines.push("");
    lines.push("### Vulnerability Distribution");
    lines.push("");
    lines.push("| Severity | Count |");
    lines.push("|----------|-------|");
    lines.push(`| Critical | ${counts.critical} |`);
    lines.push(`| High | ${counts.high} |`);
    lines.push(`| Medium | ${counts.medium} |`);
    lines.push(`| Low | ${counts.low} |`);
    lines.push(`| Informational | ${counts.info} |`);
    lines.push(`| **Total** | **${data.findings.length}** |`);
    lines.push("");
  }

  if (data.checks && data.checks.length > 0) {
    const statusCounts = { pass: 0, fail: 0, partial: 0, not_applicable: 0, not_tested: 0 };
    for (const c of data.checks) {
      const s = c.status || "not_tested";
      if (statusCounts[s] !== undefined) statusCounts[s]++;
    }
    const applicable = data.checks.length - statusCounts.not_applicable;
    const rate = applicable > 0 ? Math.round((statusCounts.pass / applicable) * 100) : 0;

    lines.push("### Compliance Status");
    lines.push("");
    lines.push(`**Compliance Rate:** ${rate}%`);
    lines.push(`**Controls Assessed:** ${data.checks.length}`);
    lines.push(`**Passing:** ${statusCounts.pass} | **Failing:** ${statusCounts.fail} | **Partial:** ${statusCounts.partial}`);
    lines.push("");
  }

  // Key highlights.
  if (data.highlights && data.highlights.length > 0) {
    lines.push("## Key Findings");
    lines.push("");
    for (const h of data.highlights) {
      lines.push(`- ${h}`);
    }
    lines.push("");
  }

  // Top recommendations.
  if (data.recommendations && data.recommendations.length > 0) {
    lines.push("## Recommendations");
    lines.push("");
    for (let i = 0; i < data.recommendations.length; i++) {
      lines.push(`${i + 1}. ${data.recommendations[i]}`);
    }
    lines.push("");
  }

  // Risk highlights from findings (top 5 critical/high).
  if (data.findings && data.findings.length > 0) {
    const topRisks = data.findings
      .filter((f) => f.severity === "critical" || f.severity === "high")
      .slice(0, 5);
    if (topRisks.length > 0) {
      lines.push("## Top Risk Items");
      lines.push("");
      lines.push("| # | Finding | Severity | Impact |");
      lines.push("|---|---------|----------|--------|");
      for (let i = 0; i < topRisks.length; i++) {
        const f = topRisks[i];
        const impact = f.impact
          ? (f.impact.length > 50 ? f.impact.slice(0, 47) + "..." : f.impact)
          : "See detailed report";
        lines.push(`| ${i + 1} | ${f.title || "Untitled"} | ${(f.severity || "").toUpperCase()} | ${impact} |`);
      }
      lines.push("");
    }
  }

  // Next steps.
  lines.push("## Next Steps");
  lines.push("");
  lines.push("1. Review this summary and the accompanying detailed report");
  lines.push("2. Prioritize remediation of critical and high-severity findings");
  lines.push("3. Assign owners and due dates for each remediation item");
  lines.push("4. Schedule follow-up assessment to verify remediation effectiveness");
  lines.push("5. Update risk register and security roadmap accordingly");
  lines.push("");

  lines.push("---");
  lines.push("");
  lines.push(`*Executive summary generated by darknode governance reporting module.*`);
  lines.push(`*Report ID: ${reportId}*`);
  lines.push("");

  return {
    content: lines.join("\n"),
    reportId,
    format: "markdown",
    template: "executive_summary",
    generatedAt,
  };
}

// ---------------------------------------------------------------------------
// Utility: convert a markdown report to a structured JSON object.
// ---------------------------------------------------------------------------

function reportToJSON(report) {
  if (!report) return null;
  return {
    reportId: report.reportId,
    format: "json",
    template: report.template,
    generatedAt: report.generatedAt,
    findings: report.findings || 0,
    counts: report.counts || report.statusCounts || {},
    complianceRate: report.complianceRate,
    content: report.content,
  };
}

// ---------------------------------------------------------------------------
// Utility: convert findings to CSV format.
// ---------------------------------------------------------------------------

function findingsToCSV(findings) {
  if (!findings || findings.length === 0) return "";
  const columns = [
    "id", "title", "severity", "description", "evidence", "impact",
    "remediation", "affectedHost", "affectedPort", "service", "tool",
    "cwe", "status", "tags",
  ];
  const lines = [columns.join(",")];
  for (const f of findings) {
    const row = columns.map((col) => {
      let val = f[col];
      if (val === undefined || val === null) return "";
      if (Array.isArray(val)) val = val.join("; ");
      const s = String(val).replace(/\r?\n/g, " ");
      if (s.includes(",") || s.includes('"') || s.includes("\n")) {
        return '"' + s.replace(/"/g, '""') + '"';
      }
      return s;
    });
    lines.push(row.join(","));
  }
  return lines.join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// Utility: generate a finding ID from its content (deterministic).
// ---------------------------------------------------------------------------

function generateFindingId(finding) {
  const content = [
    finding.title || "",
    finding.severity || "",
    finding.affectedHost || "",
    finding.affectedPort || "",
    finding.cwe || "",
  ].join("|");
  return "FIND-" + crypto.createHash("sha256").update(content).digest("hex").slice(0, 12).toUpperCase();
}

// ---------------------------------------------------------------------------
// Utility: merge duplicate findings by title+host.
// ---------------------------------------------------------------------------

function deduplicateFindings(findings) {
  const seen = new Map();
  const result = [];
  for (const f of findings) {
    const key = (f.title || "") + "|" + (f.affectedHost || "");
    if (seen.has(key)) {
      // Merge: keep the higher severity, append evidence.
      const existing = seen.get(key);
      const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      const existingSev = sevOrder[existing.severity] !== undefined ? sevOrder[existing.severity] : 5;
      const newSev = sevOrder[f.severity] !== undefined ? sevOrder[f.severity] : 5;
      if (newSev < existingSev) {
        existing.severity = f.severity;
      }
      if (f.evidence && f.evidence !== existing.evidence) {
        existing.evidence = (existing.evidence || "") + "\n---\n" + f.evidence;
      }
      if (f.references) {
        existing.references = [...new Set([...(existing.references || []), ...f.references])];
      }
    } else {
      const copy = { ...f };
      seen.set(key, copy);
      result.push(copy);
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Utility: sort findings by multiple criteria.
// ---------------------------------------------------------------------------

function sortFindings(findings, criteria) {
  if (!criteria) criteria = "severity";
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  const comparators = {
    severity: (a, b) => {
      const sa = sevOrder[a.severity] !== undefined ? sevOrder[a.severity] : 5;
      const sb = sevOrder[b.severity] !== undefined ? sevOrder[b.severity] : 5;
      return sa - sb;
    },
    title: (a, b) => (a.title || "").localeCompare(b.title || ""),
    host: (a, b) => (a.affectedHost || "").localeCompare(b.affectedHost || ""),
    status: (a, b) => (a.status || "").localeCompare(b.status || ""),
    tool: (a, b) => (a.tool || "").localeCompare(b.tool || ""),
  };

  const cmp = comparators[criteria] || comparators.severity;
  return [...findings].sort(cmp);
}

// ---------------------------------------------------------------------------
// Utility: filter findings by various criteria.
// ---------------------------------------------------------------------------

function filterFindings(findings, filters) {
  if (!filters) return findings;
  let result = [...findings];

  if (filters.severity) {
    const sevs = Array.isArray(filters.severity) ? filters.severity : [filters.severity];
    result = result.filter((f) => sevs.includes(f.severity));
  }
  if (filters.status) {
    const statuses = Array.isArray(filters.status) ? filters.status : [filters.status];
    result = result.filter((f) => statuses.includes(f.status));
  }
  if (filters.tool) {
    result = result.filter((f) => f.tool === filters.tool);
  }
  if (filters.host) {
    result = result.filter((f) => f.affectedHost === filters.host);
  }
  if (filters.cwe) {
    result = result.filter((f) => f.cwe === filters.cwe);
  }
  if (filters.search) {
    const needle = filters.search.toLowerCase();
    result = result.filter((f) =>
      (f.title || "").toLowerCase().includes(needle) ||
      (f.description || "").toLowerCase().includes(needle)
    );
  }
  if (filters.tags) {
    const tags = Array.isArray(filters.tags) ? filters.tags : [filters.tags];
    result = result.filter((f) =>
      f.tags && tags.some((t) => f.tags.includes(t))
    );
  }

  return result;
}

// ---------------------------------------------------------------------------
// Utility: compute aggregate statistics for a set of findings.
// ---------------------------------------------------------------------------

function findingStats(findings) {
  if (!findings || findings.length === 0) {
    return {
      total: 0,
      bySeverity: {},
      byStatus: {},
      byTool: {},
      byHost: {},
      byCWE: {},
      averageScore: 0,
    };
  }

  const bySeverity = {};
  const byStatus = {};
  const byTool = {};
  const byHost = {};
  const byCWE = {};
  let totalScore = 0;
  let scored = 0;

  for (const f of findings) {
    const sev = f.severity || "info";
    bySeverity[sev] = (bySeverity[sev] || 0) + 1;

    const status = f.status || "open";
    byStatus[status] = (byStatus[status] || 0) + 1;

    if (f.tool) byTool[f.tool] = (byTool[f.tool] || 0) + 1;
    if (f.affectedHost) byHost[f.affectedHost] = (byHost[f.affectedHost] || 0) + 1;
    if (f.cwe) byCWE[f.cwe] = (byCWE[f.cwe] || 0) + 1;

    if (f.cvss) {
      const risk = calculateRiskScore(f.cvss);
      totalScore += risk.score;
      scored++;
    }
  }

  return {
    total: findings.length,
    bySeverity,
    byStatus,
    byTool,
    byHost,
    byCWE,
    averageScore: scored > 0 ? Math.round((totalScore / scored) * 10) / 10 : 0,
  };
}

// ---------------------------------------------------------------------------
// Utility: generate a report filename from metadata.
// ---------------------------------------------------------------------------

function reportFilename(template, format, options) {
  const client = (options && options.client) || "report";
  const date = new Date().toISOString().slice(0, 10);
  const slug = client.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  const ext = format === "markdown" || format === "md" ? "md" : format;
  return `${slug}-${template}-${date}.${ext}`;
}

// ---------------------------------------------------------------------------
// Module exports
// ---------------------------------------------------------------------------

module.exports = {
  // Core report generators
  generateFindingReport,
  generateComplianceReport,
  generateExecutiveSummary,

  // Templates
  REPORT_TEMPLATES,

  // Finding utilities
  formatFinding,
  calculateRiskScore,
  classifySeverity,
  generateFindingId,
  deduplicateFindings,
  sortFindings,
  filterFindings,
  findingStats,
  findingsToCSV,

  // Report utilities
  reportToJSON,
  reportFilename,

  // Scoring constants
  ATTACK_VECTORS,
  ATTACK_COMPLEXITY,
  PRIVILEGES_REQUIRED,
  USER_INTERACTION,
  IMPACT_VALUES,
  SCOPE_MODIFIER,
  SEVERITY_LABELS,
  severityLabel,
};
