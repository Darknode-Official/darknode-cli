"use strict";
// NX-005 C3 — finding validation.
//
// Unvalidated findings are the #1 failure mode of this product category, so every
// reported finding is re-confirmed against the actual evidence before it is kept:
//   - normalise its label to a canonical kind (scanners/agents emit synonyms),
//   - dedup,
//   - RE-RUN detection at the cited path and drop anything that no longer
//     reproduces (wrong path, or no such secret there).
// This cuts false positives deterministically — no model needed — which is why it
// is the first capability built (NX-005 build order) and why its logic is pure and
// unit-tested here. The file content is injected (readFile) so there is no I/O in
// the tested core.
const { scanSecrets } = require("../governance/security");

// Canonical finding kinds, with the synonyms agents and scanners actually emit —
// including the exact strings scanSecrets returns ("AWS access key id", …).
const KIND_ALIASES = {
  "aws": "aws-key", "aws-key": "aws-key", "aws access key id": "aws-key", "aws_access_key": "aws-key",
  "github": "github-token", "github-token": "github-token", "gh-token": "github-token", "github token": "github-token",
  "slack": "slack-token", "slack-token": "slack-token", "slack token": "slack-token",
  "openai": "api-key", "api-key": "api-key", "apikey": "api-key", "openai-style api key": "api-key",
  "google": "google-key", "google-key": "google-key", "google api key": "google-key",
  "jwt": "jwt",
  "private-key": "private-key", "private key": "private-key",
  "hardcoded credential": "credential", "credential": "credential", "password": "credential",
};

function normKind(k) { const s = String(k == null ? "" : k).trim().toLowerCase(); return KIND_ALIASES[s] || s; }

// findings: [{ kind, path }]. readFile(path) -> string | null (null = not found).
// -> { validated: [{kind, path, reproduced:true}], dropped: [{kind?, path?, reason}] }
function validateFindings(findings, readFile) {
  const seen = new Set(), validated = [], dropped = [];
  for (const f of (findings || [])) {
    const kind = normKind(f && f.kind), p = String((f && f.path) || "");
    if (!kind || !p) { dropped.push({ kind: kind || null, path: p || null, reason: "missing kind or path" }); continue; }
    const key = kind + "|" + p;
    if (seen.has(key)) { dropped.push({ kind, path: p, reason: "duplicate" }); continue; }
    let content = null; try { content = readFile(p); } catch (_) { content = null; }
    if (content == null) { dropped.push({ kind, path: p, reason: "path not found (does not reproduce)" }); continue; }
    const detected = scanSecrets(content).map(normKind);
    if (detected.indexOf(kind) === -1) { dropped.push({ kind, path: p, reason: "no matching " + kind + " at path (does not reproduce)" }); continue; }
    seen.add(key); validated.push({ kind, path: p, reproduced: true });
  }
  return { validated, dropped };
}

// Parse "<kind>: <path>" agent output lines into finding objects. Tolerates
// whitespace around the colon (agents format inconsistently); prose lines that
// are not a single kind:path pair are ignored.
function parseFindingLines(text) {
  const out = [];
  for (const raw of String(text || "").split("\n")) {
    const m = raw.trim().match(/^([\w .-]+?)\s*:\s*(\S+)$/);
    if (m) out.push({ kind: m[1], path: m[2] });
  }
  return out;
}

module.exports = { validateFindings, parseFindingLines, normKind, KIND_ALIASES };
