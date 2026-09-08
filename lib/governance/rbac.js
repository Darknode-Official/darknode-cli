"use strict";
// Role-Based Access Control (RBAC) -- defines roles, permissions, and policy
// evaluation for the governance layer.  Every tool invocation, file access, and
// network operation can be gated through this module before execution.
//
// Design:
//   - Permissions are fine-grained strings like "file:read" or "net:scan".
//   - Roles bundle permissions into named sets (admin, operator, viewer, ...).
//   - Policies are ordered lists of rules evaluated top-to-bottom; the first
//     match wins.  Rules can allow or deny, and can constrain by resource
//     pattern, time window, or rate limit.

const path = require("path");
const fs   = require("fs");

// ---------------------------------------------------------------------------
// Permission constants -- every gatable action in the system.
// Namespaced with a colon:  domain:verb
// ---------------------------------------------------------------------------

// File permissions
const PERM_FILE_READ           = "file:read";
const PERM_FILE_WRITE          = "file:write";
const PERM_FILE_DELETE         = "file:delete";
const PERM_FILE_RENAME         = "file:rename";
const PERM_FILE_COPY           = "file:copy";
const PERM_FILE_MOVE           = "file:move";
const PERM_FILE_CHMOD          = "file:chmod";
const PERM_FILE_CHOWN          = "file:chown";
const PERM_FILE_CREATE         = "file:create";
const PERM_FILE_EXECUTE        = "file:execute";

// Directory permissions
const PERM_DIR_CREATE          = "dir:create";
const PERM_DIR_DELETE          = "dir:delete";
const PERM_DIR_LIST            = "dir:list";
const PERM_DIR_TRAVERSE        = "dir:traverse";

// Command permissions
const PERM_CMD_RUN             = "cmd:run";
const PERM_CMD_SPAWN           = "cmd:spawn";
const PERM_CMD_KILL            = "cmd:kill";
const PERM_CMD_PIPE            = "cmd:pipe";
const PERM_CMD_SUDO            = "cmd:sudo";

// Network permissions
const PERM_NET_CONNECT         = "net:connect";
const PERM_NET_LISTEN          = "net:listen";
const PERM_NET_SCAN            = "net:scan";
const PERM_NET_DNS             = "net:dns";
const PERM_NET_HTTP            = "net:http";
const PERM_NET_DOWNLOAD        = "net:download";
const PERM_NET_UPLOAD          = "net:upload";

// Auth / session permissions
const PERM_AUTH_LOGIN          = "auth:login";
const PERM_AUTH_MANAGE_USERS   = "auth:manage_users";
const PERM_AUTH_MANAGE_ROLES   = "auth:manage_roles";
const PERM_AUTH_ESCALATE       = "auth:escalate";
const PERM_AUTH_TOKEN_CREATE   = "auth:token_create";
const PERM_AUTH_TOKEN_REVOKE   = "auth:token_revoke";

// Config / policy permissions
const PERM_CONFIG_READ         = "config:read";
const PERM_CONFIG_WRITE        = "config:write";
const PERM_POLICY_CREATE       = "policy:create";
const PERM_POLICY_UPDATE       = "policy:update";
const PERM_POLICY_DELETE       = "policy:delete";
const PERM_POLICY_EVALUATE     = "policy:evaluate";

// Audit permissions
const PERM_AUDIT_READ          = "audit:read";
const PERM_AUDIT_EXPORT        = "audit:export";
const PERM_AUDIT_PURGE         = "audit:purge";
const PERM_AUDIT_VERIFY        = "audit:verify";

// Report permissions
const PERM_REPORT_GENERATE     = "report:generate";
const PERM_REPORT_EXPORT       = "report:export";
const PERM_REPORT_VIEW         = "report:view";

// Frozen list of all permissions.
const PERMISSIONS = Object.freeze([
  PERM_FILE_READ, PERM_FILE_WRITE, PERM_FILE_DELETE, PERM_FILE_RENAME,
  PERM_FILE_COPY, PERM_FILE_MOVE, PERM_FILE_CHMOD, PERM_FILE_CHOWN,
  PERM_FILE_CREATE, PERM_FILE_EXECUTE,
  PERM_DIR_CREATE, PERM_DIR_DELETE, PERM_DIR_LIST, PERM_DIR_TRAVERSE,
  PERM_CMD_RUN, PERM_CMD_SPAWN, PERM_CMD_KILL, PERM_CMD_PIPE, PERM_CMD_SUDO,
  PERM_NET_CONNECT, PERM_NET_LISTEN, PERM_NET_SCAN, PERM_NET_DNS,
  PERM_NET_HTTP, PERM_NET_DOWNLOAD, PERM_NET_UPLOAD,
  PERM_AUTH_LOGIN, PERM_AUTH_MANAGE_USERS, PERM_AUTH_MANAGE_ROLES,
  PERM_AUTH_ESCALATE, PERM_AUTH_TOKEN_CREATE, PERM_AUTH_TOKEN_REVOKE,
  PERM_CONFIG_READ, PERM_CONFIG_WRITE,
  PERM_POLICY_CREATE, PERM_POLICY_UPDATE, PERM_POLICY_DELETE, PERM_POLICY_EVALUATE,
  PERM_AUDIT_READ, PERM_AUDIT_EXPORT, PERM_AUDIT_PURGE, PERM_AUDIT_VERIFY,
  PERM_REPORT_GENERATE, PERM_REPORT_EXPORT, PERM_REPORT_VIEW,
]);

// ---------------------------------------------------------------------------
// Permission metadata -- human-readable descriptions and risk levels.
// ---------------------------------------------------------------------------

const PERMISSION_META = Object.freeze({
  [PERM_FILE_READ]:          { description: "Read file contents",                risk: "low" },
  [PERM_FILE_WRITE]:         { description: "Write or modify file contents",     risk: "medium" },
  [PERM_FILE_DELETE]:        { description: "Delete files",                      risk: "high" },
  [PERM_FILE_RENAME]:        { description: "Rename files",                      risk: "medium" },
  [PERM_FILE_COPY]:          { description: "Copy files",                        risk: "low" },
  [PERM_FILE_MOVE]:          { description: "Move files between directories",    risk: "medium" },
  [PERM_FILE_CHMOD]:         { description: "Change file permissions",           risk: "high" },
  [PERM_FILE_CHOWN]:         { description: "Change file ownership",             risk: "high" },
  [PERM_FILE_CREATE]:        { description: "Create new files",                  risk: "medium" },
  [PERM_FILE_EXECUTE]:       { description: "Execute files as programs",         risk: "critical" },
  [PERM_DIR_CREATE]:         { description: "Create directories",                risk: "low" },
  [PERM_DIR_DELETE]:         { description: "Delete directories",                risk: "high" },
  [PERM_DIR_LIST]:           { description: "List directory contents",           risk: "low" },
  [PERM_DIR_TRAVERSE]:       { description: "Traverse directory trees",          risk: "low" },
  [PERM_CMD_RUN]:            { description: "Run shell commands",                risk: "critical" },
  [PERM_CMD_SPAWN]:          { description: "Spawn child processes",             risk: "critical" },
  [PERM_CMD_KILL]:           { description: "Kill running processes",            risk: "high" },
  [PERM_CMD_PIPE]:           { description: "Pipe data between commands",        risk: "medium" },
  [PERM_CMD_SUDO]:           { description: "Run commands with elevated privileges", risk: "critical" },
  [PERM_NET_CONNECT]:        { description: "Establish outbound connections",    risk: "medium" },
  [PERM_NET_LISTEN]:         { description: "Listen on network ports",           risk: "high" },
  [PERM_NET_SCAN]:           { description: "Scan network hosts and ports",      risk: "high" },
  [PERM_NET_DNS]:            { description: "Perform DNS lookups",               risk: "low" },
  [PERM_NET_HTTP]:           { description: "Make HTTP requests",                risk: "medium" },
  [PERM_NET_DOWNLOAD]:       { description: "Download files from network",       risk: "medium" },
  [PERM_NET_UPLOAD]:         { description: "Upload files to network",           risk: "high" },
  [PERM_AUTH_LOGIN]:         { description: "Authenticate to the system",        risk: "low" },
  [PERM_AUTH_MANAGE_USERS]:  { description: "Create and manage user accounts",   risk: "critical" },
  [PERM_AUTH_MANAGE_ROLES]:  { description: "Create and modify roles",           risk: "critical" },
  [PERM_AUTH_ESCALATE]:      { description: "Escalate privileges",               risk: "critical" },
  [PERM_AUTH_TOKEN_CREATE]:  { description: "Create authentication tokens",      risk: "high" },
  [PERM_AUTH_TOKEN_REVOKE]:  { description: "Revoke authentication tokens",      risk: "medium" },
  [PERM_CONFIG_READ]:        { description: "Read configuration files",          risk: "low" },
  [PERM_CONFIG_WRITE]:       { description: "Modify configuration files",        risk: "high" },
  [PERM_POLICY_CREATE]:      { description: "Create access policies",            risk: "high" },
  [PERM_POLICY_UPDATE]:      { description: "Update access policies",            risk: "high" },
  [PERM_POLICY_DELETE]:      { description: "Delete access policies",            risk: "critical" },
  [PERM_POLICY_EVALUATE]:    { description: "Evaluate policy decisions",         risk: "low" },
  [PERM_AUDIT_READ]:         { description: "Read audit log entries",            risk: "low" },
  [PERM_AUDIT_EXPORT]:       { description: "Export audit log data",             risk: "medium" },
  [PERM_AUDIT_PURGE]:        { description: "Purge old audit log entries",       risk: "critical" },
  [PERM_AUDIT_VERIFY]:       { description: "Verify audit log integrity",        risk: "low" },
  [PERM_REPORT_GENERATE]:    { description: "Generate security reports",         risk: "low" },
  [PERM_REPORT_EXPORT]:      { description: "Export reports to external formats", risk: "medium" },
  [PERM_REPORT_VIEW]:        { description: "View generated reports",            risk: "low" },
});

// ---------------------------------------------------------------------------
// Role definitions -- each role maps to a set of permissions.
// ---------------------------------------------------------------------------

const ROLE_ADMIN    = "admin";
const ROLE_OPERATOR = "operator";
const ROLE_VIEWER   = "viewer";
const ROLE_AUDITOR  = "auditor";
const ROLE_ANALYST  = "analyst";

// The admin gets everything.
const ADMIN_PERMISSIONS = Object.freeze([...PERMISSIONS]);

// Operator: can do most things but not manage auth/policy infrastructure.
const OPERATOR_PERMISSIONS = Object.freeze([
  PERM_FILE_READ, PERM_FILE_WRITE, PERM_FILE_DELETE, PERM_FILE_RENAME,
  PERM_FILE_COPY, PERM_FILE_MOVE, PERM_FILE_CREATE, PERM_FILE_EXECUTE,
  PERM_DIR_CREATE, PERM_DIR_DELETE, PERM_DIR_LIST, PERM_DIR_TRAVERSE,
  PERM_CMD_RUN, PERM_CMD_SPAWN, PERM_CMD_KILL, PERM_CMD_PIPE,
  PERM_NET_CONNECT, PERM_NET_LISTEN, PERM_NET_SCAN, PERM_NET_DNS,
  PERM_NET_HTTP, PERM_NET_DOWNLOAD, PERM_NET_UPLOAD,
  PERM_AUTH_LOGIN, PERM_AUTH_TOKEN_CREATE,
  PERM_CONFIG_READ, PERM_CONFIG_WRITE,
  PERM_POLICY_EVALUATE,
  PERM_AUDIT_READ, PERM_AUDIT_VERIFY,
  PERM_REPORT_GENERATE, PERM_REPORT_EXPORT, PERM_REPORT_VIEW,
]);

// Viewer: read-only across the board.
const VIEWER_PERMISSIONS = Object.freeze([
  PERM_FILE_READ, PERM_FILE_COPY,
  PERM_DIR_LIST, PERM_DIR_TRAVERSE,
  PERM_NET_DNS, PERM_NET_HTTP,
  PERM_AUTH_LOGIN,
  PERM_CONFIG_READ,
  PERM_POLICY_EVALUATE,
  PERM_AUDIT_READ,
  PERM_REPORT_VIEW,
]);

// Auditor: full audit access, limited operational access.
const AUDITOR_PERMISSIONS = Object.freeze([
  PERM_FILE_READ,
  PERM_DIR_LIST, PERM_DIR_TRAVERSE,
  PERM_AUTH_LOGIN,
  PERM_CONFIG_READ,
  PERM_POLICY_EVALUATE,
  PERM_AUDIT_READ, PERM_AUDIT_EXPORT, PERM_AUDIT_VERIFY,
  PERM_REPORT_GENERATE, PERM_REPORT_EXPORT, PERM_REPORT_VIEW,
]);

// Analyst: security analysis focus, no write operations on infrastructure.
const ANALYST_PERMISSIONS = Object.freeze([
  PERM_FILE_READ, PERM_FILE_CREATE, PERM_FILE_WRITE,
  PERM_DIR_CREATE, PERM_DIR_LIST, PERM_DIR_TRAVERSE,
  PERM_CMD_RUN, PERM_CMD_SPAWN, PERM_CMD_PIPE,
  PERM_NET_CONNECT, PERM_NET_SCAN, PERM_NET_DNS, PERM_NET_HTTP,
  PERM_NET_DOWNLOAD,
  PERM_AUTH_LOGIN,
  PERM_CONFIG_READ,
  PERM_POLICY_EVALUATE,
  PERM_AUDIT_READ,
  PERM_REPORT_GENERATE, PERM_REPORT_EXPORT, PERM_REPORT_VIEW,
]);

const ROLES = Object.freeze({
  [ROLE_ADMIN]:    { name: ROLE_ADMIN,    description: "Full system access",                 permissions: ADMIN_PERMISSIONS },
  [ROLE_OPERATOR]: { name: ROLE_OPERATOR, description: "Operational access without policy management", permissions: OPERATOR_PERMISSIONS },
  [ROLE_VIEWER]:   { name: ROLE_VIEWER,   description: "Read-only access",                   permissions: VIEWER_PERMISSIONS },
  [ROLE_AUDITOR]:  { name: ROLE_AUDITOR,  description: "Audit and compliance review access",  permissions: AUDITOR_PERMISSIONS },
  [ROLE_ANALYST]:  { name: ROLE_ANALYST,  description: "Security analysis and reporting",     permissions: ANALYST_PERMISSIONS },
});

// ---------------------------------------------------------------------------
// checkPermission(role, action, resource) -- evaluate whether a role grants
// access to perform `action` (a permission string) on `resource`.
//
// Returns { allowed: bool, reason: string }.
// ---------------------------------------------------------------------------

function checkPermission(role, action, resource) {
  if (!role) {
    return { allowed: false, reason: "No role specified." };
  }
  if (!action) {
    return { allowed: false, reason: "No action specified." };
  }

  // Validate the role exists.
  const roleDef = ROLES[role];
  if (!roleDef) {
    return { allowed: false, reason: `Unknown role: ${role}` };
  }

  // Validate the permission exists.
  if (!PERMISSIONS.includes(action)) {
    return { allowed: false, reason: `Unknown permission: ${action}` };
  }

  // Check if the role grants this permission.
  if (!roleDef.permissions.includes(action)) {
    return {
      allowed: false,
      reason: `Role "${role}" does not include permission "${action}".`,
    };
  }

  // Permission granted.
  return {
    allowed: true,
    reason: `Role "${role}" grants "${action}"${resource ? ` on "${resource}"` : ""}.`,
  };
}

// ---------------------------------------------------------------------------
// Policy engine -- policies are ordered rule sets that override the basic
// role checks with fine-grained resource-level controls.
//
// Rule structure:
//   {
//     id:        string,           -- unique rule identifier
//     effect:    "allow" | "deny", -- what happens when matched
//     roles:     string[],         -- which roles this applies to ("*" for all)
//     actions:   string[],         -- which permissions ("*" for all)
//     resources: string[],         -- glob patterns for resources ("*" for all)
//     conditions: { ... },         -- optional time/rate/ip constraints
//     priority:  number,           -- lower = evaluated first (default 100)
//     description: string,         -- human-readable explanation
//   }
// ---------------------------------------------------------------------------

// Validate a single policy rule.
function validateRule(rule) {
  const errors = [];
  if (!rule.id || typeof rule.id !== "string") {
    errors.push("Rule must have a string id.");
  }
  if (!["allow", "deny"].includes(rule.effect)) {
    errors.push(`Rule ${rule.id || "?"}: effect must be "allow" or "deny".`);
  }
  if (!Array.isArray(rule.roles) || rule.roles.length === 0) {
    errors.push(`Rule ${rule.id || "?"}: roles must be a non-empty array.`);
  }
  if (!Array.isArray(rule.actions) || rule.actions.length === 0) {
    errors.push(`Rule ${rule.id || "?"}: actions must be a non-empty array.`);
  }
  if (!Array.isArray(rule.resources) || rule.resources.length === 0) {
    errors.push(`Rule ${rule.id || "?"}: resources must be a non-empty array.`);
  }
  // Validate that non-wildcard actions are real permissions.
  if (rule.actions) {
    for (const a of rule.actions) {
      if (a !== "*" && !PERMISSIONS.includes(a)) {
        errors.push(`Rule ${rule.id || "?"}: unknown permission "${a}".`);
      }
    }
  }
  // Validate that non-wildcard roles are real roles.
  if (rule.roles) {
    for (const r of rule.roles) {
      if (r !== "*" && !ROLES[r]) {
        errors.push(`Rule ${rule.id || "?"}: unknown role "${r}".`);
      }
    }
  }
  return errors;
}

// Create a policy from an array of rules.
function createPolicy(rules) {
  if (!Array.isArray(rules)) {
    throw new Error("createPolicy expects an array of rules.");
  }
  const allErrors = [];
  for (const rule of rules) {
    const errs = validateRule(rule);
    allErrors.push(...errs);
  }
  if (allErrors.length > 0) {
    throw new Error("Policy validation failed:\n  " + allErrors.join("\n  "));
  }

  // Sort by priority (lower first), then by array order for ties.
  const sorted = rules.map((r, i) => ({ ...r, _order: i }))
    .sort((a, b) => {
      const pa = a.priority !== undefined ? a.priority : 100;
      const pb = b.priority !== undefined ? b.priority : 100;
      if (pa !== pb) return pa - pb;
      return a._order - b._order;
    });

  return {
    version: 1,
    createdAt: new Date().toISOString(),
    rules: sorted.map((r) => {
      const { _order, ...rest } = r;
      return rest;
    }),
    ruleCount: sorted.length,
  };
}

// Match a resource string against a glob-like pattern.
// Supports:
//   "*"       -- matches everything
//   "*.ext"   -- suffix match
//   "/path/*" -- prefix match
//   "exact"   -- exact match
function matchResource(pattern, resource) {
  if (pattern === "*") return true;
  if (!resource) return pattern === "*";

  // Prefix glob: "/some/path/*"
  if (pattern.endsWith("/*")) {
    const prefix = pattern.slice(0, -2);
    return resource === prefix || resource.startsWith(prefix + "/");
  }

  // Suffix glob: "*.ext"
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(1); // ".ext"
    return resource.endsWith(suffix);
  }

  // Double-star recursive glob: "/path/**"
  if (pattern.endsWith("/**")) {
    const prefix = pattern.slice(0, -3);
    return resource === prefix || resource.startsWith(prefix + "/");
  }

  // Exact match.
  return resource === pattern;
}

// Check time-of-day conditions.
function checkTimeCondition(condition) {
  if (!condition) return true;
  const now = new Date();

  // Time window: { after: "09:00", before: "17:00" }
  if (condition.after || condition.before) {
    const hours = now.getHours();
    const minutes = now.getMinutes();
    const currentMinutes = hours * 60 + minutes;

    if (condition.after) {
      const [h, m] = condition.after.split(":").map(Number);
      if (currentMinutes < h * 60 + m) return false;
    }
    if (condition.before) {
      const [h, m] = condition.before.split(":").map(Number);
      if (currentMinutes >= h * 60 + m) return false;
    }
  }

  // Day-of-week restriction: { daysOfWeek: [1,2,3,4,5] }  (1=Mon, 7=Sun)
  if (condition.daysOfWeek) {
    const day = now.getDay(); // 0=Sun, 1=Mon, ..., 6=Sat
    const isoDay = day === 0 ? 7 : day; // Convert to ISO (1=Mon, 7=Sun)
    if (!condition.daysOfWeek.includes(isoDay)) return false;
  }

  // Date range: { notBefore: "2024-01-01", notAfter: "2024-12-31" }
  if (condition.notBefore) {
    if (now < new Date(condition.notBefore)) return false;
  }
  if (condition.notAfter) {
    if (now > new Date(condition.notAfter)) return false;
  }

  return true;
}

// In-memory rate limit tracker: { ruleId -> { count, windowStart } }
const rateLimitState = {};

// Check rate-limit conditions.
function checkRateLimit(ruleId, condition) {
  if (!condition || !condition.maxRequests || !condition.windowSeconds) {
    return true;
  }
  const now = Date.now();
  const windowMs = condition.windowSeconds * 1000;

  if (!rateLimitState[ruleId]) {
    rateLimitState[ruleId] = { count: 0, windowStart: now };
  }

  const state = rateLimitState[ruleId];
  if (now - state.windowStart > windowMs) {
    // Window expired -- reset.
    state.count = 0;
    state.windowStart = now;
  }

  state.count++;
  return state.count <= condition.maxRequests;
}

// Check IP-based conditions.
function checkIpCondition(condition, requestIp) {
  if (!condition) return true;
  if (!requestIp) return true; // No IP to check against -- pass.

  if (condition.allowedIps) {
    if (!condition.allowedIps.includes(requestIp)) return false;
  }
  if (condition.deniedIps) {
    if (condition.deniedIps.includes(requestIp)) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// evaluatePolicy(policy, request) -- check a request against a policy.
//
// Request structure:
//   {
//     role:     string,       -- the requesting role
//     action:   string,       -- the permission being requested
//     resource: string,       -- the target resource (file path, URL, etc.)
//     ip:       string,       -- optional: requesting IP
//     metadata: object,       -- optional: additional context
//   }
//
// Returns:
//   {
//     decision: "allow" | "deny" | "no_match",
//     rule:     object | null,  -- the matching rule (if any)
//     reason:   string,
//   }
// ---------------------------------------------------------------------------

function evaluatePolicy(policy, request) {
  if (!policy || !policy.rules) {
    return { decision: "no_match", rule: null, reason: "No policy provided." };
  }
  if (!request || !request.role || !request.action) {
    return { decision: "deny", rule: null, reason: "Invalid request: role and action required." };
  }

  for (const rule of policy.rules) {
    // Check role match.
    const roleMatch = rule.roles.includes("*") || rule.roles.includes(request.role);
    if (!roleMatch) continue;

    // Check action match.
    const actionMatch = rule.actions.includes("*") || rule.actions.includes(request.action);
    if (!actionMatch) continue;

    // Check resource match.
    let resourceMatch = false;
    for (const pattern of rule.resources) {
      if (matchResource(pattern, request.resource)) {
        resourceMatch = true;
        break;
      }
    }
    if (!resourceMatch) continue;

    // Check conditions.
    if (rule.conditions) {
      if (rule.conditions.time && !checkTimeCondition(rule.conditions.time)) continue;
      if (rule.conditions.rateLimit && !checkRateLimit(rule.id, rule.conditions.rateLimit)) {
        return {
          decision: "deny",
          rule,
          reason: `Rate limit exceeded for rule "${rule.id}".`,
        };
      }
      if (rule.conditions.ip && !checkIpCondition(rule.conditions.ip, request.ip)) continue;
    }

    // Match found.
    return {
      decision: rule.effect,
      rule,
      reason: rule.description || `Matched rule "${rule.id}" (${rule.effect}).`,
    };
  }

  // No rule matched -- fall through to default deny.
  return {
    decision: "no_match",
    rule: null,
    reason: "No matching policy rule found.",
  };
}

// ---------------------------------------------------------------------------
// Convenience: combine role-check + policy evaluation.
// ---------------------------------------------------------------------------

function authorize(role, action, resource, policy) {
  // First check the basic role permission.
  const roleCheck = checkPermission(role, action, resource);
  if (!roleCheck.allowed) {
    return {
      allowed: false,
      source: "role",
      reason: roleCheck.reason,
    };
  }

  // If a policy is provided, evaluate it for overrides.
  if (policy) {
    const policyResult = evaluatePolicy(policy, { role, action, resource });
    if (policyResult.decision === "deny") {
      return {
        allowed: false,
        source: "policy",
        reason: policyResult.reason,
      };
    }
    if (policyResult.decision === "allow") {
      return {
        allowed: true,
        source: "policy",
        reason: policyResult.reason,
      };
    }
    // no_match: fall through to role-based decision.
  }

  return {
    allowed: true,
    source: "role",
    reason: roleCheck.reason,
  };
}

// ---------------------------------------------------------------------------
// Policy persistence -- save/load policies to .nexus/policies/
// ---------------------------------------------------------------------------

function policyDir(cwd) {
  return path.join(cwd, ".nexus", "policies");
}

function savePolicy(cwd, name, policy) {
  const dir = policyDir(cwd);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const filePath = path.join(dir, name + ".json");
  fs.writeFileSync(filePath, JSON.stringify(policy, null, 2) + "\n");
  return filePath;
}

function loadPolicy(cwd, name) {
  const filePath = path.join(policyDir(cwd), name + ".json");
  if (!fs.existsSync(filePath)) return null;
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function listPolicies(cwd) {
  const dir = policyDir(cwd);
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => f.replace(/\.json$/, ""));
}

function deletePolicy(cwd, name) {
  const filePath = path.join(policyDir(cwd), name + ".json");
  if (!fs.existsSync(filePath)) return false;
  fs.unlinkSync(filePath);
  return true;
}

// ---------------------------------------------------------------------------
// Role hierarchy -- determine if one role is "higher" than another.
// ---------------------------------------------------------------------------

const ROLE_HIERARCHY = Object.freeze({
  [ROLE_ADMIN]:    4,
  [ROLE_OPERATOR]: 3,
  [ROLE_ANALYST]:  2,
  [ROLE_AUDITOR]:  2,
  [ROLE_VIEWER]:   1,
});

function isRoleAbove(role1, role2) {
  const level1 = ROLE_HIERARCHY[role1] || 0;
  const level2 = ROLE_HIERARCHY[role2] || 0;
  return level1 > level2;
}

function isRoleAtLeast(role, minRole) {
  const level = ROLE_HIERARCHY[role] || 0;
  const minLevel = ROLE_HIERARCHY[minRole] || 0;
  return level >= minLevel;
}

// ---------------------------------------------------------------------------
// User-role assignment persistence -- .nexus/rbac-assignments.json
// ---------------------------------------------------------------------------

function assignmentsPath(cwd) {
  return path.join(cwd, ".nexus", "rbac-assignments.json");
}

function readAssignments(cwd) {
  const ap = assignmentsPath(cwd);
  if (!fs.existsSync(ap)) return {};
  try {
    return JSON.parse(fs.readFileSync(ap, "utf8"));
  } catch (_) {
    return {};
  }
}

function writeAssignments(cwd, assignments) {
  const dir = path.dirname(assignmentsPath(cwd));
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(assignmentsPath(cwd), JSON.stringify(assignments, null, 2) + "\n");
}

function assignRole(cwd, user, role) {
  if (!ROLES[role]) throw new Error(`Unknown role: ${role}`);
  const assignments = readAssignments(cwd);
  assignments[user] = {
    role,
    assignedAt: new Date().toISOString(),
    assignedBy: process.env.USER || "system",
  };
  writeAssignments(cwd, assignments);
  return assignments[user];
}

function revokeRole(cwd, user) {
  const assignments = readAssignments(cwd);
  if (!assignments[user]) return false;
  delete assignments[user];
  writeAssignments(cwd, assignments);
  return true;
}

function getUserRole(cwd, user) {
  const assignments = readAssignments(cwd);
  if (!assignments[user]) return null;
  return assignments[user].role;
}

function listAssignments(cwd) {
  return readAssignments(cwd);
}

// ---------------------------------------------------------------------------
// Utility: describe what a role can do (human-readable).
// ---------------------------------------------------------------------------

function describeRole(role) {
  const roleDef = ROLES[role];
  if (!roleDef) return null;
  const lines = [];
  lines.push(`Role: ${roleDef.name}`);
  lines.push(`Description: ${roleDef.description}`);
  lines.push(`Permissions (${roleDef.permissions.length}):`);
  for (const perm of roleDef.permissions) {
    const meta = PERMISSION_META[perm];
    const risk = meta ? ` [${meta.risk}]` : "";
    const desc = meta ? ` -- ${meta.description}` : "";
    lines.push(`  ${perm}${risk}${desc}`);
  }
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Utility: diff two roles to see permission differences.
// ---------------------------------------------------------------------------

function diffRoles(role1, role2) {
  const r1 = ROLES[role1];
  const r2 = ROLES[role2];
  if (!r1 || !r2) return null;
  const set1 = new Set(r1.permissions);
  const set2 = new Set(r2.permissions);
  const onlyIn1 = r1.permissions.filter((p) => !set2.has(p));
  const onlyIn2 = r2.permissions.filter((p) => !set1.has(p));
  const shared = r1.permissions.filter((p) => set2.has(p));
  return {
    role1: role1,
    role2: role2,
    onlyInRole1: onlyIn1,
    onlyInRole2: onlyIn2,
    shared,
    totalRole1: r1.permissions.length,
    totalRole2: r2.permissions.length,
  };
}

// ---------------------------------------------------------------------------
// Utility: check if a permission is classified as high-risk or critical.
// ---------------------------------------------------------------------------

function isHighRisk(permission) {
  const meta = PERMISSION_META[permission];
  if (!meta) return false;
  return meta.risk === "high" || meta.risk === "critical";
}

function isCritical(permission) {
  const meta = PERMISSION_META[permission];
  if (!meta) return false;
  return meta.risk === "critical";
}

// ---------------------------------------------------------------------------
// Utility: get all critical permissions for a role.
// ---------------------------------------------------------------------------

function getCriticalPermissions(role) {
  const roleDef = ROLES[role];
  if (!roleDef) return [];
  return roleDef.permissions.filter(isCritical);
}

// ---------------------------------------------------------------------------
// Utility: generate a policy from a set of deny rules (convenience builder).
// ---------------------------------------------------------------------------

function denyPolicy(role, actions, resources, description) {
  return createPolicy([{
    id: "deny-" + Date.now(),
    effect: "deny",
    roles: Array.isArray(role) ? role : [role],
    actions: Array.isArray(actions) ? actions : [actions],
    resources: Array.isArray(resources) ? resources : [resources],
    description: description || "Deny rule",
    priority: 10,
  }]);
}

function allowPolicy(role, actions, resources, description) {
  return createPolicy([{
    id: "allow-" + Date.now(),
    effect: "allow",
    roles: Array.isArray(role) ? role : [role],
    actions: Array.isArray(actions) ? actions : [actions],
    resources: Array.isArray(resources) ? resources : [resources],
    description: description || "Allow rule",
    priority: 50,
  }]);
}

// ---------------------------------------------------------------------------
// Utility: merge multiple policies into one, preserving priority ordering.
// ---------------------------------------------------------------------------

function mergePolicies(...policies) {
  const allRules = [];
  for (const p of policies) {
    if (p && p.rules) {
      allRules.push(...p.rules);
    }
  }
  return createPolicy(allRules);
}

// ---------------------------------------------------------------------------
// Utility: format a policy for human-readable display.
// ---------------------------------------------------------------------------

function formatPolicy(policy) {
  if (!policy || !policy.rules) return "(empty policy)";
  const lines = [];
  lines.push(`Policy (${policy.ruleCount} rules, created ${policy.createdAt})`);
  lines.push("---");
  for (const rule of policy.rules) {
    const prio = rule.priority !== undefined ? rule.priority : 100;
    lines.push(`[${prio}] ${rule.id}: ${rule.effect.toUpperCase()}`);
    lines.push(`  Roles:     ${rule.roles.join(", ")}`);
    lines.push(`  Actions:   ${rule.actions.join(", ")}`);
    lines.push(`  Resources: ${rule.resources.join(", ")}`);
    if (rule.description) lines.push(`  Note:      ${rule.description}`);
    if (rule.conditions) {
      if (rule.conditions.time) {
        const t = rule.conditions.time;
        const parts = [];
        if (t.after) parts.push(`after ${t.after}`);
        if (t.before) parts.push(`before ${t.before}`);
        if (t.daysOfWeek) parts.push(`days ${t.daysOfWeek.join(",")}`);
        lines.push(`  Time:      ${parts.join(", ")}`);
      }
      if (rule.conditions.rateLimit) {
        const rl = rule.conditions.rateLimit;
        lines.push(`  Rate:      ${rl.maxRequests} per ${rl.windowSeconds}s`);
      }
      if (rule.conditions.ip) {
        const ip = rule.conditions.ip;
        if (ip.allowedIps) lines.push(`  Allowed IPs: ${ip.allowedIps.join(", ")}`);
        if (ip.deniedIps)  lines.push(`  Denied IPs:  ${ip.deniedIps.join(", ")}`);
      }
    }
    lines.push("");
  }
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Module exports
// ---------------------------------------------------------------------------

module.exports = {
  // Permission constants
  PERM_FILE_READ,
  PERM_FILE_WRITE,
  PERM_FILE_DELETE,
  PERM_FILE_RENAME,
  PERM_FILE_COPY,
  PERM_FILE_MOVE,
  PERM_FILE_CHMOD,
  PERM_FILE_CHOWN,
  PERM_FILE_CREATE,
  PERM_FILE_EXECUTE,
  PERM_DIR_CREATE,
  PERM_DIR_DELETE,
  PERM_DIR_LIST,
  PERM_DIR_TRAVERSE,
  PERM_CMD_RUN,
  PERM_CMD_SPAWN,
  PERM_CMD_KILL,
  PERM_CMD_PIPE,
  PERM_CMD_SUDO,
  PERM_NET_CONNECT,
  PERM_NET_LISTEN,
  PERM_NET_SCAN,
  PERM_NET_DNS,
  PERM_NET_HTTP,
  PERM_NET_DOWNLOAD,
  PERM_NET_UPLOAD,
  PERM_AUTH_LOGIN,
  PERM_AUTH_MANAGE_USERS,
  PERM_AUTH_MANAGE_ROLES,
  PERM_AUTH_ESCALATE,
  PERM_AUTH_TOKEN_CREATE,
  PERM_AUTH_TOKEN_REVOKE,
  PERM_CONFIG_READ,
  PERM_CONFIG_WRITE,
  PERM_POLICY_CREATE,
  PERM_POLICY_UPDATE,
  PERM_POLICY_DELETE,
  PERM_POLICY_EVALUATE,
  PERM_AUDIT_READ,
  PERM_AUDIT_EXPORT,
  PERM_AUDIT_PURGE,
  PERM_AUDIT_VERIFY,
  PERM_REPORT_GENERATE,
  PERM_REPORT_EXPORT,
  PERM_REPORT_VIEW,
  PERMISSIONS,
  PERMISSION_META,

  // Role constants and definitions
  ROLE_ADMIN,
  ROLE_OPERATOR,
  ROLE_VIEWER,
  ROLE_AUDITOR,
  ROLE_ANALYST,
  ROLES,
  ROLE_HIERARCHY,

  // Core API
  checkPermission,
  createPolicy,
  evaluatePolicy,
  authorize,

  // Policy management
  savePolicy,
  loadPolicy,
  listPolicies,
  deletePolicy,
  mergePolicies,

  // User-role assignments
  assignRole,
  revokeRole,
  getUserRole,
  listAssignments,

  // Utilities
  validateRule,
  matchResource,
  isRoleAbove,
  isRoleAtLeast,
  describeRole,
  diffRoles,
  isHighRisk,
  isCritical,
  getCriticalPermissions,
  denyPolicy,
  allowPolicy,
  formatPolicy,
};
