"use strict";
// Governance audit logging system -- maintains an append-only HMAC-chained
// log of every significant action taken through the toolkit.  Each entry is
// a self-contained JSON line in .nexus/audit.jsonl, linked to its predecessor
// by a keyed hash so tampering with any record breaks the chain.

const fs   = require("fs");
const path = require("path");
const crypto = require("crypto");
const os   = require("os");

// ---------------------------------------------------------------------------
// Action type constants -- every auditable operation gets a symbolic name.
// Grouped by domain so callers can import just the ones they need.
// ---------------------------------------------------------------------------

// File operations
const FILE_READ           = "FILE_READ";
const FILE_WRITE          = "FILE_WRITE";
const FILE_DELETE         = "FILE_DELETE";
const FILE_RENAME         = "FILE_RENAME";
const FILE_COPY           = "FILE_COPY";
const FILE_MOVE           = "FILE_MOVE";
const FILE_CHMOD          = "FILE_CHMOD";
const FILE_CHOWN          = "FILE_CHOWN";
const FILE_CREATE         = "FILE_CREATE";
const FILE_TRUNCATE       = "FILE_TRUNCATE";
const FILE_APPEND         = "FILE_APPEND";
const FILE_LINK           = "FILE_LINK";
const FILE_SYMLINK        = "FILE_SYMLINK";

// Directory operations
const DIR_CREATE          = "DIR_CREATE";
const DIR_DELETE          = "DIR_DELETE";
const DIR_LIST            = "DIR_LIST";
const DIR_TRAVERSE        = "DIR_TRAVERSE";

// Command execution
const COMMAND_RUN         = "COMMAND_RUN";
const COMMAND_SPAWN       = "COMMAND_SPAWN";
const COMMAND_KILL        = "COMMAND_KILL";
const COMMAND_PIPE        = "COMMAND_PIPE";
const COMMAND_TIMEOUT     = "COMMAND_TIMEOUT";

// Network operations
const NET_CONNECT         = "NET_CONNECT";
const NET_LISTEN          = "NET_LISTEN";
const NET_SCAN            = "NET_SCAN";
const NET_DNS_LOOKUP      = "NET_DNS_LOOKUP";
const NET_HTTP_REQUEST    = "NET_HTTP_REQUEST";
const NET_HTTP_RESPONSE   = "NET_HTTP_RESPONSE";
const NET_DOWNLOAD        = "NET_DOWNLOAD";
const NET_UPLOAD          = "NET_UPLOAD";

// Authentication and access
const AUTH_LOGIN          = "AUTH_LOGIN";
const AUTH_LOGOUT         = "AUTH_LOGOUT";
const AUTH_FAIL           = "AUTH_FAIL";
const AUTH_TOKEN_CREATE   = "AUTH_TOKEN_CREATE";
const AUTH_TOKEN_REVOKE   = "AUTH_TOKEN_REVOKE";
const AUTH_ESCALATE       = "AUTH_ESCALATE";
const AUTH_MFA_VERIFY     = "AUTH_MFA_VERIFY";

// Policy and configuration
const CONFIG_READ         = "CONFIG_READ";
const CONFIG_WRITE        = "CONFIG_WRITE";
const CONFIG_DELETE       = "CONFIG_DELETE";
const POLICY_CREATE       = "POLICY_CREATE";
const POLICY_UPDATE       = "POLICY_UPDATE";
const POLICY_DELETE       = "POLICY_DELETE";
const POLICY_EVALUATE     = "POLICY_EVALUATE";

// Session and lifecycle
const SESSION_START       = "SESSION_START";
const SESSION_END         = "SESSION_END";
const SESSION_RESUME      = "SESSION_RESUME";
const TOOL_INVOKE         = "TOOL_INVOKE";
const TOOL_RESULT         = "TOOL_RESULT";
const PIPELINE_START      = "PIPELINE_START";
const PIPELINE_END        = "PIPELINE_END";
const REPORT_GENERATE     = "REPORT_GENERATE";
const EXPORT_DATA         = "EXPORT_DATA";

// Security events
const SEC_VULN_FOUND      = "SEC_VULN_FOUND";
const SEC_SCAN_START      = "SEC_SCAN_START";
const SEC_SCAN_END        = "SEC_SCAN_END";
const SEC_ALERT           = "SEC_ALERT";
const SEC_QUARANTINE      = "SEC_QUARANTINE";

// All action types collected into a frozen set for validation.
const ALL_ACTION_TYPES = Object.freeze([
  FILE_READ, FILE_WRITE, FILE_DELETE, FILE_RENAME, FILE_COPY, FILE_MOVE,
  FILE_CHMOD, FILE_CHOWN, FILE_CREATE, FILE_TRUNCATE, FILE_APPEND,
  FILE_LINK, FILE_SYMLINK,
  DIR_CREATE, DIR_DELETE, DIR_LIST, DIR_TRAVERSE,
  COMMAND_RUN, COMMAND_SPAWN, COMMAND_KILL, COMMAND_PIPE, COMMAND_TIMEOUT,
  NET_CONNECT, NET_LISTEN, NET_SCAN, NET_DNS_LOOKUP, NET_HTTP_REQUEST,
  NET_HTTP_RESPONSE, NET_DOWNLOAD, NET_UPLOAD,
  AUTH_LOGIN, AUTH_LOGOUT, AUTH_FAIL, AUTH_TOKEN_CREATE, AUTH_TOKEN_REVOKE,
  AUTH_ESCALATE, AUTH_MFA_VERIFY,
  CONFIG_READ, CONFIG_WRITE, CONFIG_DELETE,
  POLICY_CREATE, POLICY_UPDATE, POLICY_DELETE, POLICY_EVALUATE,
  SESSION_START, SESSION_END, SESSION_RESUME,
  TOOL_INVOKE, TOOL_RESULT,
  PIPELINE_START, PIPELINE_END,
  REPORT_GENERATE, EXPORT_DATA,
  SEC_VULN_FOUND, SEC_SCAN_START, SEC_SCAN_END, SEC_ALERT, SEC_QUARANTINE,
]);

// ---------------------------------------------------------------------------
// Validation schema -- describes the shape of every audit entry.  Used by
// createEntry / validateEntry to ensure nothing malformed reaches the log.
// ---------------------------------------------------------------------------

const AUDIT_SCHEMA = Object.freeze({
  version: { type: "number", required: true, enum: [1] },
  id:      { type: "string", required: true, pattern: /^[a-f0-9]{32}$/ },
  seq:     { type: "number", required: true, min: 0 },
  timestamp: { type: "string", required: true, pattern: /^\d{4}-\d{2}-\d{2}T/ },
  user:    { type: "string", required: true, minLength: 1, maxLength: 256 },
  host:    { type: "string", required: true, minLength: 1, maxLength: 256 },
  pid:     { type: "number", required: true, min: 1 },
  action:  { type: "string", required: true, enum: ALL_ACTION_TYPES },
  tool:    { type: "string", required: false, maxLength: 128 },
  resource: { type: "string", required: false, maxLength: 4096 },
  detail:  { type: "object", required: false },
  pathHash: { type: "string", required: false, pattern: /^[a-f0-9]{64}$/ },
  outcome: { type: "string", required: true, enum: ["success", "failure", "denied", "error"] },
  duration: { type: "number", required: false, min: 0 },
  prevHash: { type: "string", required: true, pattern: /^[a-f0-9]{64}$/ },
  hash:    { type: "string", required: true, pattern: /^[a-f0-9]{64}$/ },
});

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// HMAC key derivation -- we derive a per-project key from the project path
// and a machine-specific salt so the chain is bound to this installation.
function deriveKey(cwd) {
  const salt = os.hostname() + ":" + (process.env.USER || process.env.USERNAME || "unknown");
  return crypto.createHash("sha256").update(salt + ":" + cwd).digest();
}

// Compute the HMAC-SHA256 of a canonical entry string.
function hmac(key, data) {
  return crypto.createHmac("sha256", key).update(data).digest("hex");
}

// Build a canonical string for hashing: deterministic key ordering.
function canonicalize(entry) {
  const keys = [
    "version", "id", "seq", "timestamp", "user", "host", "pid",
    "action", "tool", "resource", "detail", "pathHash", "outcome", "duration",
    "prevHash",
  ];
  const parts = [];
  for (const k of keys) {
    if (entry[k] !== undefined) {
      const val = typeof entry[k] === "object" ? JSON.stringify(entry[k]) : String(entry[k]);
      parts.push(k + "=" + val);
    }
  }
  return parts.join("|");
}

// Generate a random 128-bit hex id.
function genId() {
  return crypto.randomBytes(16).toString("hex");
}

// SHA-256 of a file path, used to redact paths in sensitive contexts while
// still allowing correlation.
function hashPath(filePath) {
  if (!filePath) return undefined;
  return crypto.createHash("sha256").update(filePath).digest("hex");
}

// Resolve the audit log path for a project directory.
function auditPath(cwd) {
  return path.join(cwd, ".nexus", "audit.jsonl");
}

// Resolve the metadata sidecar path -- stores seq counter and last hash.
function metaPath(cwd) {
  return path.join(cwd, ".nexus", "audit-meta.json");
}

// Read metadata or return defaults.
function readMeta(cwd) {
  const mp = metaPath(cwd);
  if (fs.existsSync(mp)) {
    try {
      return JSON.parse(fs.readFileSync(mp, "utf8"));
    } catch (_) {
      // Corrupted meta -- start fresh from log scan.
    }
  }
  return null;
}

// Write metadata atomically.
function writeMeta(cwd, meta) {
  const mp = metaPath(cwd);
  const dir = path.dirname(mp);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const tmp = mp + ".tmp." + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(meta, null, 2) + "\n");
  fs.renameSync(tmp, mp);
}

// Read all log lines, parsed.
function readAllEntries(cwd) {
  const lp = auditPath(cwd);
  if (!fs.existsSync(lp)) return [];
  const raw = fs.readFileSync(lp, "utf8").trim();
  if (!raw) return [];
  const entries = [];
  for (const line of raw.split("\n")) {
    if (!line.trim()) continue;
    try {
      entries.push(JSON.parse(line));
    } catch (err) {
      entries.push({ _parseError: true, _raw: line, _error: err.message });
    }
  }
  return entries;
}

// Rebuild metadata by scanning the log (recovery path).
function rebuildMeta(cwd) {
  const entries = readAllEntries(cwd);
  if (entries.length === 0) {
    return { seq: 0, lastHash: "0".repeat(64) };
  }
  const last = entries[entries.length - 1];
  if (last._parseError) {
    // Best effort -- use the last parseable entry.
    for (let i = entries.length - 2; i >= 0; i--) {
      if (!entries[i]._parseError) {
        return { seq: entries[i].seq, lastHash: entries[i].hash };
      }
    }
    return { seq: 0, lastHash: "0".repeat(64) };
  }
  return { seq: last.seq, lastHash: last.hash };
}

// ---------------------------------------------------------------------------
// Validate a single field against its schema descriptor.
// ---------------------------------------------------------------------------

function validateField(name, value, descriptor) {
  const errors = [];
  if (descriptor.required && (value === undefined || value === null)) {
    errors.push(`${name}: required but missing`);
    return errors;
  }
  if (value === undefined || value === null) return errors;

  if (descriptor.type === "number" && typeof value !== "number") {
    errors.push(`${name}: expected number, got ${typeof value}`);
  }
  if (descriptor.type === "string" && typeof value !== "string") {
    errors.push(`${name}: expected string, got ${typeof value}`);
  }
  if (descriptor.type === "object" && (typeof value !== "object" || Array.isArray(value))) {
    errors.push(`${name}: expected object, got ${typeof value}`);
  }
  if (descriptor.enum && !descriptor.enum.includes(value)) {
    errors.push(`${name}: value "${value}" not in allowed set`);
  }
  if (descriptor.pattern && typeof value === "string" && !descriptor.pattern.test(value)) {
    errors.push(`${name}: value does not match required pattern`);
  }
  if (descriptor.minLength !== undefined && typeof value === "string" && value.length < descriptor.minLength) {
    errors.push(`${name}: length ${value.length} below minimum ${descriptor.minLength}`);
  }
  if (descriptor.maxLength !== undefined && typeof value === "string" && value.length > descriptor.maxLength) {
    errors.push(`${name}: length ${value.length} exceeds maximum ${descriptor.maxLength}`);
  }
  if (descriptor.min !== undefined && typeof value === "number" && value < descriptor.min) {
    errors.push(`${name}: value ${value} below minimum ${descriptor.min}`);
  }
  return errors;
}

// Validate an entire entry against AUDIT_SCHEMA.
function validateEntry(entry) {
  const errors = [];
  for (const [name, desc] of Object.entries(AUDIT_SCHEMA)) {
    errors.push(...validateField(name, entry[name], desc));
  }
  // Check for unexpected fields.
  const known = new Set(Object.keys(AUDIT_SCHEMA));
  for (const k of Object.keys(entry)) {
    if (!known.has(k)) {
      errors.push(`unexpected field: ${k}`);
    }
  }
  return errors;
}

// ---------------------------------------------------------------------------
// createAuditLog(cwd) -- initialize the audit infrastructure for a project.
// Creates .nexus/ if needed, writes the initial metadata sidecar, and
// appends a SESSION_START genesis entry so the chain has a root.
// ---------------------------------------------------------------------------

function createAuditLog(cwd) {
  const dir = path.join(cwd, ".nexus");
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  const lp = auditPath(cwd);
  const logExists = fs.existsSync(lp) && fs.statSync(lp).size > 0;
  if (logExists) {
    // Log already exists -- ensure metadata is consistent.
    let meta = readMeta(cwd);
    if (!meta) {
      meta = rebuildMeta(cwd);
      writeMeta(cwd, meta);
    }
    return {
      created: false,
      path: lp,
      entries: meta.seq,
      message: "Audit log already exists; metadata synchronized.",
    };
  }

  // Fresh log -- write genesis entry.
  const key = deriveKey(cwd);
  const genesisId = genId();
  const prevHash = "0".repeat(64);
  const entry = {
    version: 1,
    id: genesisId,
    seq: 1,
    timestamp: new Date().toISOString(),
    user: process.env.USER || process.env.USERNAME || "unknown",
    host: os.hostname(),
    pid: process.pid,
    action: SESSION_START,
    tool: "audit-log",
    resource: cwd,
    detail: { event: "audit_log_initialized" },
    pathHash: hashPath(cwd),
    outcome: "success",
    prevHash,
  };
  entry.hash = hmac(key, canonicalize(entry));
  const validation = validateEntry(entry);
  if (validation.length > 0) {
    throw new Error("Genesis entry validation failed: " + validation.join("; "));
  }
  fs.writeFileSync(lp, JSON.stringify(entry) + "\n");
  writeMeta(cwd, { seq: 1, lastHash: entry.hash });

  return {
    created: true,
    path: lp,
    entries: 1,
    message: "Audit log initialized with genesis entry.",
  };
}

// ---------------------------------------------------------------------------
// logAction(cwd, action) -- append a structured entry to the audit log.
//
// `action` is an object with:
//   - type:     one of the action type constants (required)
//   - tool:     tool name (optional)
//   - resource: file path, URL, or target (optional)
//   - detail:   arbitrary metadata object (optional)
//   - outcome:  "success" | "failure" | "denied" | "error"  (default "success")
//   - duration: milliseconds (optional)
//   - user:     override the current user (optional)
// ---------------------------------------------------------------------------

function logAction(cwd, action) {
  if (!action || typeof action !== "object") {
    throw new Error("logAction requires an action object");
  }
  if (!action.type) {
    throw new Error("logAction requires action.type");
  }
  if (!ALL_ACTION_TYPES.includes(action.type)) {
    throw new Error(`Unknown action type: ${action.type}`);
  }

  const lp = auditPath(cwd);
  if (!fs.existsSync(lp)) {
    createAuditLog(cwd);
  }

  let meta = readMeta(cwd);
  if (!meta) {
    meta = rebuildMeta(cwd);
  }

  const key = deriveKey(cwd);
  const seq = meta.seq + 1;
  const entry = {
    version: 1,
    id: genId(),
    seq,
    timestamp: new Date().toISOString(),
    user: action.user || process.env.USER || process.env.USERNAME || "unknown",
    host: os.hostname(),
    pid: process.pid,
    action: action.type,
    tool: action.tool || undefined,
    resource: action.resource || undefined,
    detail: action.detail || undefined,
    pathHash: action.resource ? hashPath(action.resource) : undefined,
    outcome: action.outcome || "success",
    duration: action.duration || undefined,
    prevHash: meta.lastHash,
  };

  // Strip undefined values to keep the JSONL clean.
  for (const k of Object.keys(entry)) {
    if (entry[k] === undefined) delete entry[k];
  }
  // Re-add required fields that may have been stripped.
  if (!entry.tool) entry.tool = "";
  if (!entry.resource) entry.resource = "";
  if (entry.pathHash === undefined) entry.pathHash = hashPath("");

  entry.hash = hmac(key, canonicalize(entry));
  const validation = validateEntry(entry);
  if (validation.length > 0) {
    throw new Error("Entry validation failed: " + validation.join("; "));
  }

  fs.appendFileSync(lp, JSON.stringify(entry) + "\n");
  writeMeta(cwd, { seq, lastHash: entry.hash });

  return { id: entry.id, seq, hash: entry.hash };
}

// ---------------------------------------------------------------------------
// verifyIntegrity(cwd) -- walk every entry and check:
//   1. Each entry's hash matches its canonical content.
//   2. Each entry's prevHash matches the prior entry's hash.
//   3. The sequence numbers are strictly increasing from 1.
// Returns { valid, entries, errors[] }.
// ---------------------------------------------------------------------------

function verifyIntegrity(cwd) {
  const entries = readAllEntries(cwd);
  const key = deriveKey(cwd);
  const errors = [];
  let prevHash = "0".repeat(64);

  if (entries.length === 0) {
    return { valid: true, entries: 0, errors: [], message: "Empty log -- nothing to verify." };
  }

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const lineNum = i + 1;

    // Parse errors from readAllEntries.
    if (entry._parseError) {
      errors.push({
        line: lineNum,
        type: "parse_error",
        message: `Line ${lineNum}: JSON parse error -- ${entry._error}`,
      });
      continue;
    }

    // Sequence check.
    if (entry.seq !== lineNum) {
      errors.push({
        line: lineNum,
        type: "sequence_gap",
        message: `Line ${lineNum}: expected seq=${lineNum}, got seq=${entry.seq}`,
      });
    }

    // prevHash chain check.
    if (entry.prevHash !== prevHash) {
      errors.push({
        line: lineNum,
        type: "chain_break",
        message: `Line ${lineNum}: prevHash mismatch (expected ${prevHash.slice(0, 16)}..., got ${(entry.prevHash || "").slice(0, 16)}...)`,
      });
    }

    // Recompute the hash and compare.
    const savedHash = entry.hash;
    const computedHash = hmac(key, canonicalize(entry));
    if (computedHash !== savedHash) {
      errors.push({
        line: lineNum,
        type: "hash_mismatch",
        message: `Line ${lineNum}: hash mismatch -- entry may have been tampered with`,
      });
    }

    // Schema validation.
    const schemaErrors = validateEntry(entry);
    for (const se of schemaErrors) {
      errors.push({
        line: lineNum,
        type: "schema_violation",
        message: `Line ${lineNum}: ${se}`,
      });
    }

    prevHash = savedHash;
  }

  // Cross-check metadata.
  const meta = readMeta(cwd);
  if (meta) {
    const lastEntry = entries[entries.length - 1];
    if (!lastEntry._parseError) {
      if (meta.seq !== lastEntry.seq) {
        errors.push({
          line: entries.length,
          type: "meta_desync",
          message: `Metadata seq (${meta.seq}) does not match last entry seq (${lastEntry.seq})`,
        });
      }
      if (meta.lastHash !== lastEntry.hash) {
        errors.push({
          line: entries.length,
          type: "meta_desync",
          message: "Metadata lastHash does not match last entry hash",
        });
      }
    }
  }

  return {
    valid: errors.length === 0,
    entries: entries.length,
    errors,
    message: errors.length === 0
      ? `All ${entries.length} entries verified -- chain intact.`
      : `Found ${errors.length} integrity error(s) across ${entries.length} entries.`,
  };
}

// ---------------------------------------------------------------------------
// queryLog(cwd, filters) -- search the audit log.
//
// Supported filters:
//   - startDate / endDate:  ISO date strings, inclusive range
//   - action:               single action type or array
//   - tool:                 tool name (exact match)
//   - user:                 username (exact match)
//   - resource:             substring match on resource field
//   - outcome:              "success" | "failure" | "denied" | "error"
//   - minSeq / maxSeq:      sequence number range
//   - limit:                max results (default 100)
//   - offset:               skip N results (for pagination)
//   - sort:                 "asc" (default) or "desc"
// ---------------------------------------------------------------------------

function queryLog(cwd, filters) {
  if (!filters) filters = {};
  const entries = readAllEntries(cwd);
  let results = entries.filter((e) => !e._parseError);

  // Date range filtering.
  if (filters.startDate) {
    const start = new Date(filters.startDate).getTime();
    if (!isNaN(start)) {
      results = results.filter((e) => new Date(e.timestamp).getTime() >= start);
    }
  }
  if (filters.endDate) {
    const end = new Date(filters.endDate).getTime();
    if (!isNaN(end)) {
      results = results.filter((e) => new Date(e.timestamp).getTime() <= end);
    }
  }

  // Action type filtering.
  if (filters.action) {
    const actions = Array.isArray(filters.action) ? filters.action : [filters.action];
    results = results.filter((e) => actions.includes(e.action));
  }

  // Tool filtering.
  if (filters.tool) {
    results = results.filter((e) => e.tool === filters.tool);
  }

  // User filtering.
  if (filters.user) {
    results = results.filter((e) => e.user === filters.user);
  }

  // Resource substring filtering.
  if (filters.resource) {
    const needle = filters.resource.toLowerCase();
    results = results.filter((e) => e.resource && e.resource.toLowerCase().includes(needle));
  }

  // Outcome filtering.
  if (filters.outcome) {
    results = results.filter((e) => e.outcome === filters.outcome);
  }

  // Sequence range filtering.
  if (filters.minSeq !== undefined) {
    results = results.filter((e) => e.seq >= filters.minSeq);
  }
  if (filters.maxSeq !== undefined) {
    results = results.filter((e) => e.seq <= filters.maxSeq);
  }

  // Sort.
  const sortDir = filters.sort === "desc" ? -1 : 1;
  results.sort((a, b) => sortDir * (a.seq - b.seq));

  // Pagination.
  const total = results.length;
  const offset = Math.max(0, filters.offset || 0);
  const limit = Math.min(1000, Math.max(1, filters.limit || 100));
  results = results.slice(offset, offset + limit);

  return {
    total,
    offset,
    limit,
    count: results.length,
    entries: results,
  };
}

// ---------------------------------------------------------------------------
// exportLog(cwd, format) -- export the audit log in a human-readable format.
//
// Supported formats:
//   - "json"     -- pretty-printed JSON array
//   - "csv"      -- RFC 4180 CSV with headers
//   - "markdown" -- markdown table
//   - "jsonl"    -- raw JSONL (copy of the log file)
//
// Returns { content, format, entries, bytes }.
// ---------------------------------------------------------------------------

function exportLog(cwd, format, filters) {
  if (!format) format = "json";
  const qr = queryLog(cwd, filters || {});
  const entries = qr.entries;

  let content;

  switch (format) {
    case "json":
      content = exportAsJSON(entries);
      break;
    case "csv":
      content = exportAsCSV(entries);
      break;
    case "markdown":
    case "md":
      content = exportAsMarkdown(entries);
      break;
    case "jsonl":
      content = exportAsJSONL(entries);
      break;
    default:
      throw new Error(`Unsupported export format: ${format}`);
  }

  return {
    content,
    format,
    entries: entries.length,
    bytes: Buffer.byteLength(content, "utf8"),
  };
}

// --- Export format implementations ---

function exportAsJSON(entries) {
  return JSON.stringify(entries, null, 2) + "\n";
}

function exportAsCSV(entries) {
  const columns = [
    "seq", "timestamp", "user", "host", "pid", "action",
    "tool", "resource", "outcome", "duration", "id", "hash",
  ];
  const lines = [columns.join(",")];
  for (const e of entries) {
    const row = columns.map((col) => {
      const val = e[col];
      if (val === undefined || val === null) return "";
      const s = String(val);
      // Quote fields that contain commas, quotes, or newlines.
      if (s.includes(",") || s.includes('"') || s.includes("\n")) {
        return '"' + s.replace(/"/g, '""') + '"';
      }
      return s;
    });
    lines.push(row.join(","));
  }
  return lines.join("\n") + "\n";
}

function exportAsMarkdown(entries) {
  const lines = [];
  lines.push("# Audit Log Export");
  lines.push("");
  lines.push(`Exported: ${new Date().toISOString()}`);
  lines.push(`Entries: ${entries.length}`);
  lines.push("");
  lines.push("| Seq | Timestamp | User | Action | Tool | Resource | Outcome |");
  lines.push("|-----|-----------|------|--------|------|----------|---------|");
  for (const e of entries) {
    const ts = e.timestamp ? e.timestamp.replace("T", " ").slice(0, 19) : "";
    const resource = e.resource
      ? (e.resource.length > 40 ? e.resource.slice(0, 37) + "..." : e.resource)
      : "";
    const tool = e.tool || "";
    lines.push(`| ${e.seq} | ${ts} | ${e.user} | ${e.action} | ${tool} | ${resource} | ${e.outcome} |`);
  }
  lines.push("");
  return lines.join("\n") + "\n";
}

function exportAsJSONL(entries) {
  return entries.map((e) => JSON.stringify(e)).join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// Utility: get summary statistics for the log.
// ---------------------------------------------------------------------------

function summarize(cwd) {
  const entries = readAllEntries(cwd).filter((e) => !e._parseError);
  if (entries.length === 0) {
    return {
      entries: 0,
      users: [],
      actions: {},
      outcomes: {},
      firstEntry: null,
      lastEntry: null,
      tools: [],
    };
  }

  const users = new Set();
  const tools = new Set();
  const actions = {};
  const outcomes = { success: 0, failure: 0, denied: 0, error: 0 };

  for (const e of entries) {
    users.add(e.user);
    if (e.tool) tools.add(e.tool);
    actions[e.action] = (actions[e.action] || 0) + 1;
    if (outcomes[e.outcome] !== undefined) outcomes[e.outcome]++;
  }

  return {
    entries: entries.length,
    users: Array.from(users).sort(),
    actions,
    outcomes,
    firstEntry: entries[0].timestamp,
    lastEntry: entries[entries.length - 1].timestamp,
    tools: Array.from(tools).sort(),
  };
}

// ---------------------------------------------------------------------------
// Utility: rotate / archive the log when it exceeds a size threshold.
// ---------------------------------------------------------------------------

function rotateLog(cwd, maxSizeMB) {
  if (!maxSizeMB) maxSizeMB = 50;
  const lp = auditPath(cwd);
  if (!fs.existsSync(lp)) return { rotated: false, reason: "No log file found." };

  const stat = fs.statSync(lp);
  const sizeMB = stat.size / (1024 * 1024);
  if (sizeMB < maxSizeMB) {
    return { rotated: false, reason: `Log is ${sizeMB.toFixed(2)} MB, below threshold of ${maxSizeMB} MB.` };
  }

  const archiveName = `audit-${new Date().toISOString().replace(/[:.]/g, "-")}.jsonl`;
  const archivePath = path.join(cwd, ".nexus", "archive", archiveName);
  const archiveDir = path.dirname(archivePath);
  if (!fs.existsSync(archiveDir)) fs.mkdirSync(archiveDir, { recursive: true });

  // Copy current log to archive.
  fs.copyFileSync(lp, archivePath);

  // Record the archive event, then truncate.
  logAction(cwd, {
    type: EXPORT_DATA,
    tool: "audit-log",
    resource: archivePath,
    detail: { event: "log_rotated", originalSize: stat.size, archivePath },
    outcome: "success",
  });

  // Truncate the main log and restart with a fresh genesis.
  fs.writeFileSync(lp, "");
  writeMeta(cwd, { seq: 0, lastHash: "0".repeat(64) });
  createAuditLog(cwd);

  return {
    rotated: true,
    archivePath,
    originalSizeMB: sizeMB.toFixed(2),
    message: `Log rotated. Archive: ${archivePath}`,
  };
}

// ---------------------------------------------------------------------------
// Utility: tail the log (last N entries).
// ---------------------------------------------------------------------------

function tailLog(cwd, n) {
  if (!n || n < 1) n = 20;
  const entries = readAllEntries(cwd).filter((e) => !e._parseError);
  return entries.slice(-n);
}

// ---------------------------------------------------------------------------
// Utility: count entries by action type for histogram display.
// ---------------------------------------------------------------------------

function histogram(cwd) {
  const entries = readAllEntries(cwd).filter((e) => !e._parseError);
  const counts = {};
  for (const e of entries) {
    counts[e.action] = (counts[e.action] || 0) + 1;
  }
  // Sort descending by count.
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  return sorted.map(([action, count]) => ({ action, count }));
}

// ---------------------------------------------------------------------------
// Utility: search log entries by full-text on the detail field.
// ---------------------------------------------------------------------------

function searchDetail(cwd, query) {
  if (!query) return [];
  const entries = readAllEntries(cwd).filter((e) => !e._parseError);
  const needle = query.toLowerCase();
  return entries.filter((e) => {
    if (!e.detail) return false;
    const text = JSON.stringify(e.detail).toLowerCase();
    return text.includes(needle);
  });
}

// ---------------------------------------------------------------------------
// Utility: purge entries older than N days (destructive -- for compliance).
// ---------------------------------------------------------------------------

function purgeOlderThan(cwd, days) {
  if (!days || days < 1) throw new Error("purgeOlderThan requires a positive number of days");
  const cutoff = Date.now() - (days * 24 * 60 * 60 * 1000);
  const entries = readAllEntries(cwd).filter((e) => !e._parseError);
  const kept = entries.filter((e) => new Date(e.timestamp).getTime() >= cutoff);
  const removed = entries.length - kept.length;

  if (removed === 0) {
    return { purged: 0, remaining: entries.length, message: "No entries older than the cutoff." };
  }

  // Rewrite the log and rechain.
  const key = deriveKey(cwd);
  const lp = auditPath(cwd);
  let prevHash = "0".repeat(64);
  const rechained = [];

  for (let i = 0; i < kept.length; i++) {
    const e = { ...kept[i] };
    e.seq = i + 1;
    e.prevHash = prevHash;
    e.hash = hmac(key, canonicalize(e));
    rechained.push(e);
    prevHash = e.hash;
  }

  // Atomic rewrite.
  const tmp = lp + ".tmp." + process.pid;
  fs.writeFileSync(tmp, rechained.map((e) => JSON.stringify(e)).join("\n") + "\n");
  fs.renameSync(tmp, lp);
  writeMeta(cwd, {
    seq: rechained.length,
    lastHash: rechained.length > 0 ? rechained[rechained.length - 1].hash : "0".repeat(64),
  });

  return {
    purged: removed,
    remaining: rechained.length,
    message: `Purged ${removed} entries older than ${days} days. ${rechained.length} remain.`,
  };
}

// ---------------------------------------------------------------------------
// Utility: find entries with mismatched hashes (quick integrity spot-check
// that returns only the broken entries, unlike verifyIntegrity which walks
// the full chain).
// ---------------------------------------------------------------------------

function findTampered(cwd) {
  const entries = readAllEntries(cwd).filter((e) => !e._parseError);
  const key = deriveKey(cwd);
  const tampered = [];
  for (const e of entries) {
    const recomputed = hmac(key, canonicalize(e));
    if (recomputed !== e.hash) {
      tampered.push({ seq: e.seq, id: e.id, expected: recomputed, actual: e.hash });
    }
  }
  return tampered;
}

// ---------------------------------------------------------------------------
// Utility: generate a chain-of-custody report for a specific resource.
// ---------------------------------------------------------------------------

function chainOfCustody(cwd, resourcePath) {
  if (!resourcePath) throw new Error("chainOfCustody requires a resource path");
  const entries = readAllEntries(cwd).filter((e) => !e._parseError);
  const ph = hashPath(resourcePath);
  const related = entries.filter((e) =>
    e.resource === resourcePath || e.pathHash === ph
  );

  const lines = [];
  lines.push(`Chain of Custody: ${resourcePath}`);
  lines.push(`Path Hash: ${ph}`);
  lines.push(`Total Events: ${related.length}`);
  lines.push("");

  for (const e of related) {
    const ts = e.timestamp.replace("T", " ").slice(0, 19);
    lines.push(`[${ts}] ${e.action} by ${e.user} via ${e.tool || "direct"} -- ${e.outcome}`);
    if (e.detail) {
      lines.push(`  Detail: ${JSON.stringify(e.detail)}`);
    }
  }

  return {
    resource: resourcePath,
    pathHash: ph,
    events: related,
    report: lines.join("\n"),
  };
}

// ---------------------------------------------------------------------------
// Utility: format a single entry for human-readable display.
// ---------------------------------------------------------------------------

function formatEntry(entry) {
  if (!entry) return "(empty entry)";
  if (entry._parseError) return `[PARSE ERROR] ${entry._raw}`;

  const ts = (entry.timestamp || "").replace("T", " ").slice(0, 19);
  const parts = [
    `#${entry.seq}`,
    ts,
    entry.user,
    entry.action,
  ];
  if (entry.tool) parts.push(`tool=${entry.tool}`);
  if (entry.resource) parts.push(`resource=${entry.resource}`);
  parts.push(`[${entry.outcome}]`);
  if (entry.duration !== undefined) parts.push(`${entry.duration}ms`);
  return parts.join(" | ");
}

// ---------------------------------------------------------------------------
// Utility: compute a digest of the entire log for external verification.
// ---------------------------------------------------------------------------

function computeDigest(cwd) {
  const lp = auditPath(cwd);
  if (!fs.existsSync(lp)) return null;
  const content = fs.readFileSync(lp);
  return {
    sha256: crypto.createHash("sha256").update(content).digest("hex"),
    size: content.length,
    entries: readAllEntries(cwd).filter((e) => !e._parseError).length,
    timestamp: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Module exports
// ---------------------------------------------------------------------------

module.exports = {
  // Core API
  createAuditLog,
  logAction,
  verifyIntegrity,
  queryLog,
  exportLog,

  // Utilities
  summarize,
  rotateLog,
  tailLog,
  histogram,
  searchDetail,
  purgeOlderThan,
  findTampered,
  chainOfCustody,
  formatEntry,
  computeDigest,
  validateEntry,

  // Schema
  AUDIT_SCHEMA,

  // Action type constants
  FILE_READ,
  FILE_WRITE,
  FILE_DELETE,
  FILE_RENAME,
  FILE_COPY,
  FILE_MOVE,
  FILE_CHMOD,
  FILE_CHOWN,
  FILE_CREATE,
  FILE_TRUNCATE,
  FILE_APPEND,
  FILE_LINK,
  FILE_SYMLINK,
  DIR_CREATE,
  DIR_DELETE,
  DIR_LIST,
  DIR_TRAVERSE,
  COMMAND_RUN,
  COMMAND_SPAWN,
  COMMAND_KILL,
  COMMAND_PIPE,
  COMMAND_TIMEOUT,
  NET_CONNECT,
  NET_LISTEN,
  NET_SCAN,
  NET_DNS_LOOKUP,
  NET_HTTP_REQUEST,
  NET_HTTP_RESPONSE,
  NET_DOWNLOAD,
  NET_UPLOAD,
  AUTH_LOGIN,
  AUTH_LOGOUT,
  AUTH_FAIL,
  AUTH_TOKEN_CREATE,
  AUTH_TOKEN_REVOKE,
  AUTH_ESCALATE,
  AUTH_MFA_VERIFY,
  CONFIG_READ,
  CONFIG_WRITE,
  CONFIG_DELETE,
  POLICY_CREATE,
  POLICY_UPDATE,
  POLICY_DELETE,
  POLICY_EVALUATE,
  SESSION_START,
  SESSION_END,
  SESSION_RESUME,
  TOOL_INVOKE,
  TOOL_RESULT,
  PIPELINE_START,
  PIPELINE_END,
  REPORT_GENERATE,
  EXPORT_DATA,
  SEC_VULN_FOUND,
  SEC_SCAN_START,
  SEC_SCAN_END,
  SEC_ALERT,
  SEC_QUARANTINE,
  ALL_ACTION_TYPES,
};
