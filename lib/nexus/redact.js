"use strict";
// ============================================================================
// Central sink redaction (NSAFE-060) + stable keyed placeholders (NSAFE-061).
//
// Leaks happen at the sink nobody thought of, so there is ONE redactor and the
// sinks call it: audit log, the on-disk transcript (session.json), terminal
// rendering, and — only when enabled — the text sent to the model. Matches are
// replaced with a typed placeholder:
//
//     [REDACTED:<rule>:<tag>]
//
// where <tag> is the first 4 hex of HMAC-SHA256(installKey, secret). The same
// secret therefore redacts to the same tag everywhere, so an investigator can
// see "this token appeared in 4 places" WITHOUT the value ever being written.
// The tag is not invertible (no substring of the secret appears) and never
// leaves the operator's machine. Low-entropy findings (short quoted credentials)
// use a fixed tag so a 4-hex HMAC can't be brute-forced back to a weak password.
//
// The install key reuses audit-log.deriveKey (host+user+cwd → sha256), the same
// derivation the tamper-evident audit chain uses, so no new key material or file
// is introduced. redact() is pure given ctx.key; the key is resolved lazily (and
// memoised) only when a caller omits it, so module scope stays side-effect-free.
// ============================================================================

const crypto = require("crypto");

// Rule table — ids match the governance/security scanner. `group`, when set,
// names the capture group that holds the secret (the rest of the match, e.g. a
// key= prefix and the quotes, is preserved). `lowEntropy` rules use a fixed tag.
const RULES = [
  { id: "aws-access-key", re: /\bAKIA[0-9A-Z]{16}\b/g },
  { id: "private-key", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g },
  { id: "github-token", re: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g },
  { id: "slack-token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { id: "api-key", re: /\bsk-[A-Za-z0-9]{20,}\b/g },
  { id: "google-key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: "jwt", re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\b/g },
  // 3 capture groups, the match is exactly g1+g2+g3 (prefix, secret, closing
  // quote), so only the secret group is replaced and the rest is preserved.
  { id: "credential", re: /((?:password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*['"])([^'"\s]{6,})(['"])/ig, ngroups: 3, secretGroup: 2, lowEntropy: true },
];

const FIXED_TAG = "0000";

// Short, non-invertible correlation tag for a secret value.
function tagFor(secret, key) {
  return crypto.createHmac("sha256", key).update(String(secret)).digest("hex").slice(0, 4);
}

let _defaultKey = null;
function defaultKey() {
  if (_defaultKey) return _defaultKey;
  try { _defaultKey = require("../governance/audit-log").deriveKey(process.cwd()); } // same derivation as the audit chain
  catch (_) { _defaultKey = crypto.createHash("sha256").update("nexus-redact-fallback").digest(); }
  return _defaultKey;
}

// redact(text, ctx) -> { text, findings }
//   ctx.sink : "audit" | "transcript" | "screen" | "model"
//   ctx.key  : install key (Buffer/string); defaults to the audit-chain key
//   ctx.modelRedaction : when sink === "model", redact only if truthy (off by
//                        default: the model may need the surrounding text, and a
//                        separate privacy-mode masking already guards the wire).
function redact(text, ctx) {
  ctx = ctx || {};
  const s = String(text == null ? "" : text);
  const key = ctx.key || defaultKey();
  let findings = 0;
  if (ctx.sink === "model" && !ctx.modelRedaction) {
    // Count (for telemetry) but do not alter model-bound text by default.
    for (const rule of RULES) { const m = s.match(rule.re); if (m) findings += m.length; }
    return { text: s, findings };
  }
  let out = s;
  for (const rule of RULES) {
    out = out.replace(rule.re, (match, ...groups) => {
      findings++;
      const secret = rule.secretGroup ? groups[rule.secretGroup - 1] : match;
      const tag = rule.lowEntropy ? FIXED_TAG : tagFor(secret, key);
      const placeholder = "[REDACTED:" + rule.id + ":" + tag + "]";
      if (!rule.secretGroup) return placeholder; // whole match is the secret
      const caps = groups.slice(0, rule.ngroups); // capture groups only (drop offset + full string)
      caps[rule.secretGroup - 1] = placeholder;
      return caps.join(""); // the match is exactly the concatenation of its groups
    });
  }
  return { text: out, findings };
}

// emit(kind, text, ctx) — the one call a sink makes. Returns the redacted text
// to write/render. A thin wrapper so every sink is grep-able and the static
// sink-coverage test can enumerate callers.
function emit(kind, text, ctx) {
  return redact(text, Object.assign({ sink: kind }, ctx || {})).text;
}

module.exports = { redact, emit, tagFor, RULES };
