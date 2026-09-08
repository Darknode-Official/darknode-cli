"use strict";
// ============================================================================
// vuln-scanner.js -- Security header, SSL/TLS, and DNS configuration scanner
//
// Performs passive reconnaissance against web targets to evaluate their
// security posture. Checks HTTP response headers against best practices,
// validates TLS configuration, and audits DNS security records (SPF, DMARC,
// DKIM, CAA, DNSSEC). Produces graded reports with prioritized remediation
// guidance. Uses only Node.js built-ins (http, https, tls, dns, url, crypto).
// ============================================================================

const https = require("https");
const http  = require("http");
const tls   = require("tls");
const dns   = require("dns");
const { URL } = require("url");
const crypto = require("crypto");

// ---------------------------------------------------------------------------
// Severity weights -- used for composite scoring
// ---------------------------------------------------------------------------
const SEVERITY_WEIGHTS = {
  critical: 10,
  high:     7,
  medium:   4,
  low:      2,
  info:     1,
};

// ---------------------------------------------------------------------------
// Grade thresholds -- map numeric score to letter grade
// ---------------------------------------------------------------------------
const GRADE_THRESHOLDS = [
  { min: 95, grade: "A+" },
  { min: 85, grade: "A"  },
  { min: 75, grade: "B+" },
  { min: 65, grade: "B"  },
  { min: 55, grade: "C+" },
  { min: 45, grade: "C"  },
  { min: 35, grade: "D"  },
  { min: 0,  grade: "F"  },
];

function scoreToGrade(score) {
  for (const t of GRADE_THRESHOLDS) {
    if (score >= t.min) return t.grade;
  }
  return "F";
}

// ---------------------------------------------------------------------------
// HEADER_CHECKS -- 22 security header validations
// ---------------------------------------------------------------------------
const HEADER_CHECKS = [
  {
    name: "Strict-Transport-Security",
    description: "Enforces HTTPS connections via HSTS, preventing protocol downgrade attacks and cookie hijacking.",
    expected: "max-age >= 31536000; includeSubDomains; preload",
    severity: "critical",
    weight: 10,
    checkFn(value) {
      if (!value) return { pass: false, detail: "HSTS header is missing entirely.", recommendation: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses." };
      const maxAgeMatch = value.match(/max-age=(\d+)/i);
      if (!maxAgeMatch) return { pass: false, detail: "HSTS header present but max-age directive is missing.", recommendation: "Set max-age to at least 31536000 (one year)." };
      const maxAge = parseInt(maxAgeMatch[1], 10);
      if (maxAge < 31536000) return { pass: false, detail: `HSTS max-age is ${maxAge} seconds (less than one year).`, recommendation: "Increase max-age to at least 31536000 seconds." };
      const hasSub = /includeSubDomains/i.test(value);
      const hasPreload = /preload/i.test(value);
      if (!hasSub || !hasPreload) return { pass: true, detail: `HSTS is set with max-age=${maxAge}.${hasSub ? "" : " Missing includeSubDomains."}${hasPreload ? "" : " Missing preload."}`, recommendation: "Add includeSubDomains and preload directives for maximum protection." };
      return { pass: true, detail: `HSTS is properly configured: max-age=${maxAge}, includeSubDomains, preload.`, recommendation: null };
    },
  },
  {
    name: "Content-Security-Policy",
    description: "Mitigates XSS, clickjacking, and code injection attacks by controlling resource loading origins.",
    expected: "Restrictive policy without 'unsafe-inline' or 'unsafe-eval'",
    severity: "critical",
    weight: 10,
    checkFn(value) {
      if (!value) return { pass: false, detail: "Content-Security-Policy header is missing.", recommendation: "Implement a CSP that restricts script-src, style-src, and default-src to trusted origins." };
      const hasUnsafeInline = /unsafe-inline/i.test(value);
      const hasUnsafeEval = /unsafe-eval/i.test(value);
      const hasWildcard = /\s\*[\s;]|default-src\s+\*/.test(value);
      if (hasWildcard) return { pass: false, detail: "CSP uses wildcard (*) which defeats the purpose of the policy.", recommendation: "Replace wildcard sources with specific trusted origins." };
      if (hasUnsafeInline && hasUnsafeEval) return { pass: false, detail: "CSP allows both 'unsafe-inline' and 'unsafe-eval', significantly reducing protection.", recommendation: "Remove unsafe-inline (use nonces or hashes) and unsafe-eval (refactor code to avoid eval)." };
      if (hasUnsafeInline) return { pass: false, detail: "CSP allows 'unsafe-inline' which weakens XSS protection.", recommendation: "Replace unsafe-inline with nonce-based or hash-based CSP directives." };
      if (hasUnsafeEval) return { pass: false, detail: "CSP allows 'unsafe-eval' which permits dynamic code execution.", recommendation: "Remove unsafe-eval and refactor JavaScript to avoid eval(), new Function(), etc." };
      return { pass: true, detail: "CSP is present and does not use unsafe directives.", recommendation: null };
    },
  },
  {
    name: "X-Content-Type-Options",
    description: "Prevents MIME-type sniffing attacks by forcing the browser to respect the declared Content-Type.",
    expected: "nosniff",
    severity: "high",
    weight: 7,
    checkFn(value) {
      if (!value) return { pass: false, detail: "X-Content-Type-Options header is missing.", recommendation: "Add 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing." };
      if (value.trim().toLowerCase() !== "nosniff") return { pass: false, detail: `X-Content-Type-Options is set to '${value}' instead of 'nosniff'.`, recommendation: "Set the value to 'nosniff'." };
      return { pass: true, detail: "X-Content-Type-Options is correctly set to nosniff.", recommendation: null };
    },
  },
  {
    name: "X-Frame-Options",
    description: "Controls whether the page can be embedded in frames, preventing clickjacking attacks.",
    expected: "DENY or SAMEORIGIN",
    severity: "high",
    weight: 7,
    checkFn(value) {
      if (!value) return { pass: false, detail: "X-Frame-Options header is missing.", recommendation: "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' to prevent clickjacking." };
      const v = value.trim().toUpperCase();
      if (v === "DENY" || v === "SAMEORIGIN") return { pass: true, detail: `X-Frame-Options is set to ${v}.`, recommendation: null };
      if (v.startsWith("ALLOW-FROM")) return { pass: true, detail: `X-Frame-Options uses ALLOW-FROM (deprecated in modern browsers).`, recommendation: "Consider migrating to CSP frame-ancestors directive for better browser support." };
      return { pass: false, detail: `X-Frame-Options has an invalid value: '${value}'.`, recommendation: "Set to DENY or SAMEORIGIN." };
    },
  },
  {
    name: "X-XSS-Protection",
    description: "Legacy XSS filter control. Modern best practice is to disable it and rely on CSP.",
    expected: "0 (disabled, rely on CSP) or 1; mode=block",
    severity: "medium",
    weight: 4,
    checkFn(value) {
      if (!value) return { pass: true, detail: "X-XSS-Protection is absent (acceptable if CSP is present).", recommendation: "Consider adding 'X-XSS-Protection: 0' to explicitly disable the flawed XSS auditor." };
      if (value.trim() === "0") return { pass: true, detail: "X-XSS-Protection is explicitly disabled (modern best practice when CSP is in use).", recommendation: null };
      if (/1;\s*mode=block/i.test(value)) return { pass: true, detail: "X-XSS-Protection is set to block mode.", recommendation: "Consider setting to 0 and relying on CSP instead, as the XSS auditor has known bypasses." };
      if (value.trim() === "1") return { pass: false, detail: "X-XSS-Protection is enabled without mode=block, which can introduce vulnerabilities.", recommendation: "Set to '1; mode=block' or preferably '0' with a strong CSP." };
      return { pass: false, detail: `Unexpected X-XSS-Protection value: '${value}'.`, recommendation: "Set to '0' with a strong CSP or '1; mode=block'." };
    },
  },
  {
    name: "Referrer-Policy",
    description: "Controls how much referrer information is sent with requests, protecting user privacy.",
    expected: "strict-origin-when-cross-origin or no-referrer",
    severity: "medium",
    weight: 4,
    checkFn(value) {
      if (!value) return { pass: false, detail: "Referrer-Policy header is missing.", recommendation: "Add 'Referrer-Policy: strict-origin-when-cross-origin' to limit referrer leakage." };
      const safe = ["no-referrer", "no-referrer-when-downgrade", "strict-origin", "strict-origin-when-cross-origin", "same-origin", "origin", "origin-when-cross-origin"];
      const v = value.trim().toLowerCase();
      if (v === "unsafe-url") return { pass: false, detail: "Referrer-Policy is set to 'unsafe-url' which leaks the full URL to all origins.", recommendation: "Change to 'strict-origin-when-cross-origin' or 'no-referrer'." };
      if (safe.includes(v)) return { pass: true, detail: `Referrer-Policy is set to '${v}'.`, recommendation: null };
      return { pass: false, detail: `Unknown Referrer-Policy value: '${value}'.`, recommendation: "Use a standard value like 'strict-origin-when-cross-origin'." };
    },
  },
  {
    name: "Permissions-Policy",
    description: "Controls which browser features (camera, microphone, geolocation, etc.) the page can use.",
    expected: "Restrictive policy disabling unnecessary features",
    severity: "medium",
    weight: 4,
    checkFn(value) {
      if (!value) return { pass: false, detail: "Permissions-Policy header is missing.", recommendation: "Add Permissions-Policy to disable unnecessary browser features (camera, microphone, geolocation, etc.)." };
      const features = value.split(",").map(f => f.trim());
      if (features.length < 3) return { pass: true, detail: `Permissions-Policy is set but only restricts ${features.length} feature(s).`, recommendation: "Consider restricting additional features: camera, microphone, geolocation, payment, usb, magnetometer." };
      return { pass: true, detail: `Permissions-Policy restricts ${features.length} features.`, recommendation: null };
    },
  },
  {
    name: "Cache-Control",
    description: "Controls caching behavior. Sensitive pages should not be cached to prevent information leakage.",
    expected: "no-store, no-cache for sensitive content",
    severity: "medium",
    weight: 4,
    checkFn(value) {
      if (!value) return { pass: false, detail: "Cache-Control header is missing.", recommendation: "Add appropriate Cache-Control directives. For sensitive content: 'no-store, no-cache, must-revalidate'." };
      const hasNoStore = /no-store/i.test(value);
      const hasNoCache = /no-cache/i.test(value);
      const hasPublic = /\bpublic\b/i.test(value);
      if (hasPublic && !hasNoStore) return { pass: true, detail: "Cache-Control allows public caching. Ensure no sensitive data is served with this header.", recommendation: "For pages containing sensitive data, use 'no-store, no-cache, must-revalidate, private'." };
      if (hasNoStore || hasNoCache) return { pass: true, detail: `Cache-Control: ${value} -- caching is restricted.`, recommendation: null };
      return { pass: true, detail: `Cache-Control: ${value}`, recommendation: "Review caching policy to ensure sensitive responses are not cached." };
    },
  },
  {
    name: "Pragma",
    description: "HTTP/1.0 cache control directive. Should complement Cache-Control for backward compatibility.",
    expected: "no-cache (for sensitive content)",
    severity: "low",
    weight: 2,
    checkFn(value) {
      if (!value) return { pass: true, detail: "Pragma header is absent (normal for HTTP/1.1 only sites).", recommendation: "For backward compatibility with HTTP/1.0 caches, consider adding 'Pragma: no-cache' for sensitive pages." };
      if (/no-cache/i.test(value)) return { pass: true, detail: "Pragma is set to no-cache for backward compatibility.", recommendation: null };
      return { pass: true, detail: `Pragma: ${value}`, recommendation: null };
    },
  },
  {
    name: "X-Permitted-Cross-Domain-Policies",
    description: "Controls Flash and PDF cross-domain data loading via crossdomain.xml policy files.",
    expected: "none",
    severity: "low",
    weight: 2,
    checkFn(value) {
      if (!value) return { pass: false, detail: "X-Permitted-Cross-Domain-Policies header is missing.", recommendation: "Add 'X-Permitted-Cross-Domain-Policies: none' to prevent Adobe products from loading cross-domain data." };
      if (value.trim().toLowerCase() === "none") return { pass: true, detail: "X-Permitted-Cross-Domain-Policies is set to none.", recommendation: null };
      if (value.trim().toLowerCase() === "master-only") return { pass: true, detail: "X-Permitted-Cross-Domain-Policies allows master policy only.", recommendation: "Consider using 'none' for maximum restriction." };
      return { pass: false, detail: `X-Permitted-Cross-Domain-Policies is set to '${value}'.`, recommendation: "Set to 'none' unless cross-domain Flash/PDF loading is required." };
    },
  },
  {
    name: "Cross-Origin-Embedder-Policy",
    description: "Prevents loading cross-origin resources without explicit permission, enabling cross-origin isolation.",
    expected: "require-corp",
    severity: "medium",
    weight: 4,
    checkFn(value) {
      if (!value) return { pass: false, detail: "Cross-Origin-Embedder-Policy header is missing.", recommendation: "Add 'Cross-Origin-Embedder-Policy: require-corp' to enable cross-origin isolation." };
      if (value.trim().toLowerCase() === "require-corp") return { pass: true, detail: "COEP is set to require-corp.", recommendation: null };
      if (value.trim().toLowerCase() === "credentialless") return { pass: true, detail: "COEP is set to credentialless (less restrictive than require-corp).", recommendation: null };
      return { pass: false, detail: `COEP has unexpected value: '${value}'.`, recommendation: "Set to 'require-corp' for full cross-origin isolation." };
    },
  },
  {
    name: "Cross-Origin-Opener-Policy",
    description: "Isolates the browsing context to prevent cross-origin attacks like Spectre.",
    expected: "same-origin",
    severity: "medium",
    weight: 4,
    checkFn(value) {
      if (!value) return { pass: false, detail: "Cross-Origin-Opener-Policy header is missing.", recommendation: "Add 'Cross-Origin-Opener-Policy: same-origin' to isolate the browsing context." };
      if (value.trim().toLowerCase() === "same-origin") return { pass: true, detail: "COOP is set to same-origin.", recommendation: null };
      if (value.trim().toLowerCase() === "same-origin-allow-popups") return { pass: true, detail: "COOP allows popups from same origin.", recommendation: "Consider using 'same-origin' for stricter isolation if popups are not needed." };
      return { pass: false, detail: `COOP has unexpected value: '${value}'.`, recommendation: "Set to 'same-origin'." };
    },
  },
  {
    name: "Cross-Origin-Resource-Policy",
    description: "Controls which origins can load this resource, preventing cross-origin data leaks.",
    expected: "same-origin or same-site",
    severity: "medium",
    weight: 4,
    checkFn(value) {
      if (!value) return { pass: false, detail: "Cross-Origin-Resource-Policy header is missing.", recommendation: "Add 'Cross-Origin-Resource-Policy: same-origin' to prevent cross-origin resource loading." };
      const v = value.trim().toLowerCase();
      if (v === "same-origin" || v === "same-site") return { pass: true, detail: `CORP is set to ${v}.`, recommendation: null };
      if (v === "cross-origin") return { pass: true, detail: "CORP allows cross-origin loading (intentionally permissive).", recommendation: "Restrict to 'same-origin' or 'same-site' unless cross-origin access is required." };
      return { pass: false, detail: `CORP has unexpected value: '${value}'.`, recommendation: "Set to 'same-origin' or 'same-site'." };
    },
  },
  {
    name: "Content-Type",
    description: "Declares the media type and charset. Should include charset=utf-8 to prevent encoding attacks.",
    expected: "Includes charset=utf-8",
    severity: "medium",
    weight: 4,
    checkFn(value) {
      if (!value) return { pass: false, detail: "Content-Type header is missing.", recommendation: "Always set Content-Type with an explicit charset (e.g. 'text/html; charset=utf-8')." };
      if (/charset\s*=\s*utf-?8/i.test(value)) return { pass: true, detail: `Content-Type: ${value} (charset specified).`, recommendation: null };
      if (/text\/html|application\/json|text\/xml/i.test(value)) return { pass: false, detail: `Content-Type is '${value}' without charset specification.`, recommendation: "Add 'charset=utf-8' to prevent encoding-based attacks." };
      return { pass: true, detail: `Content-Type: ${value}`, recommendation: null };
    },
  },
  {
    name: "Set-Cookie",
    description: "Cookie security attributes: Secure, HttpOnly, SameSite flags should be present.",
    expected: "Secure; HttpOnly; SameSite=Strict or Lax",
    severity: "high",
    weight: 7,
    checkFn(value) {
      if (!value) return { pass: true, detail: "No Set-Cookie header found (no cookies set on this response).", recommendation: null };
      const issues = [];
      if (!/;\s*Secure/i.test(value)) issues.push("Missing Secure flag (cookie sent over HTTP)");
      if (!/;\s*HttpOnly/i.test(value)) issues.push("Missing HttpOnly flag (cookie accessible via JavaScript)");
      if (!/;\s*SameSite\s*=/i.test(value)) issues.push("Missing SameSite attribute (vulnerable to CSRF)");
      if (/SameSite\s*=\s*None/i.test(value) && !/;\s*Secure/i.test(value)) issues.push("SameSite=None requires Secure flag");
      if (issues.length === 0) return { pass: true, detail: "Set-Cookie includes Secure, HttpOnly, and SameSite attributes.", recommendation: null };
      return { pass: false, detail: `Cookie security issues: ${issues.join("; ")}.`, recommendation: "Set cookies with 'Secure; HttpOnly; SameSite=Strict' (or SameSite=Lax if cross-site access is needed)." };
    },
  },
  {
    name: "X-DNS-Prefetch-Control",
    description: "Controls DNS prefetching behavior. Disabling prevents information leakage via DNS lookups.",
    expected: "off",
    severity: "low",
    weight: 2,
    checkFn(value) {
      if (!value) return { pass: true, detail: "X-DNS-Prefetch-Control is absent (browser default applies).", recommendation: "Add 'X-DNS-Prefetch-Control: off' to prevent DNS prefetch information leakage." };
      if (value.trim().toLowerCase() === "off") return { pass: true, detail: "DNS prefetching is disabled.", recommendation: null };
      return { pass: true, detail: "DNS prefetching is enabled.", recommendation: "Consider setting to 'off' for sensitive applications to prevent DNS-based tracking." };
    },
  },
  {
    name: "Expect-CT",
    description: "Enforces Certificate Transparency, detecting misissued certificates. Deprecated but still useful.",
    expected: "max-age=86400, enforce",
    severity: "low",
    weight: 2,
    checkFn(value) {
      if (!value) return { pass: true, detail: "Expect-CT is absent (deprecated as of June 2021, CT is now required by default in most browsers).", recommendation: null };
      if (/enforce/i.test(value)) return { pass: true, detail: "Expect-CT is set with enforce mode.", recommendation: "Note: Expect-CT is deprecated; modern browsers enforce CT by default." };
      return { pass: true, detail: `Expect-CT: ${value}`, recommendation: null };
    },
  },
  {
    name: "Feature-Policy",
    description: "Deprecated predecessor to Permissions-Policy. Should be migrated to Permissions-Policy.",
    expected: "Migrated to Permissions-Policy",
    severity: "info",
    weight: 1,
    checkFn(value) {
      if (!value) return { pass: true, detail: "Feature-Policy is absent (expected -- use Permissions-Policy instead).", recommendation: null };
      return { pass: true, detail: "Feature-Policy is present but deprecated.", recommendation: "Migrate to the Permissions-Policy header for continued browser support." };
    },
  },
  {
    name: "Access-Control-Allow-Origin",
    description: "CORS header controlling which origins can access the resource. Wildcard is risky for authenticated endpoints.",
    expected: "Specific origin, not wildcard (*) for authenticated resources",
    severity: "high",
    weight: 7,
    checkFn(value) {
      if (!value) return { pass: true, detail: "No CORS Access-Control-Allow-Origin header (resource not shared cross-origin).", recommendation: null };
      if (value.trim() === "*") return { pass: false, detail: "CORS allows all origins (*). This is dangerous for endpoints that handle authenticated requests.", recommendation: "Restrict to specific trusted origins instead of wildcard. If the API is truly public, ensure no credentials are involved." };
      if (/null/i.test(value)) return { pass: false, detail: "CORS allows 'null' origin, which can be spoofed via sandboxed iframes.", recommendation: "Never whitelist the 'null' origin." };
      return { pass: true, detail: `CORS restricted to: ${value}`, recommendation: null };
    },
  },
  {
    name: "Server",
    description: "Reveals web server software and version. Should be removed or obscured to reduce information leakage.",
    expected: "Absent or generic (no version numbers)",
    severity: "low",
    weight: 2,
    checkFn(value) {
      if (!value) return { pass: true, detail: "Server header is absent (good -- no server information disclosed).", recommendation: null };
      if (/\d+\.\d+/i.test(value)) return { pass: false, detail: `Server header discloses version info: '${value}'.`, recommendation: "Remove version numbers from the Server header or suppress it entirely." };
      return { pass: true, detail: `Server: ${value} (no version disclosed).`, recommendation: "Consider removing the Server header entirely to minimize information leakage." };
    },
  },
  {
    name: "X-Powered-By",
    description: "Reveals backend technology. Should always be removed to prevent targeted attacks.",
    expected: "Absent",
    severity: "medium",
    weight: 4,
    checkFn(value) {
      if (!value) return { pass: true, detail: "X-Powered-By is absent (good -- no backend technology disclosed).", recommendation: null };
      return { pass: false, detail: `X-Powered-By discloses backend technology: '${value}'.`, recommendation: "Remove the X-Powered-By header. In Express.js: app.disable('x-powered-by')." };
    },
  },
  {
    name: "X-Download-Options",
    description: "Prevents IE from executing downloads in the site context (IE-specific).",
    expected: "noopen",
    severity: "low",
    weight: 1,
    checkFn(value) {
      if (!value) return { pass: true, detail: "X-Download-Options is absent (IE-specific header, low impact).", recommendation: "Optionally add 'X-Download-Options: noopen' for defense-in-depth." };
      if (value.trim().toLowerCase() === "noopen") return { pass: true, detail: "X-Download-Options is set to noopen.", recommendation: null };
      return { pass: false, detail: `Unexpected X-Download-Options value: '${value}'.`, recommendation: "Set to 'noopen'." };
    },
  },
];

// ---------------------------------------------------------------------------
// SSL/TLS cipher suite classifications
// ---------------------------------------------------------------------------
const WEAK_CIPHERS = [
  "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon", "RC2",
  "IDEA", "SEED", "CAMELLIA128",
];

const STRONG_CIPHERS = [
  "AES256-GCM", "AES128-GCM", "CHACHA20", "ECDHE", "DHE",
];

const PROTOCOL_GRADES = {
  "TLSv1.3": { grade: "A", secure: true },
  "TLSv1.2": { grade: "B+", secure: true },
  "TLSv1.1": { grade: "D", secure: false },
  "TLSv1":   { grade: "F", secure: false },
  "SSLv3":   { grade: "F", secure: false },
};

// ---------------------------------------------------------------------------
// DNS record type constants
// ---------------------------------------------------------------------------
const DNS_RECORD_TYPES = {
  A:     "IPv4 address record",
  AAAA:  "IPv6 address record",
  MX:    "Mail exchange record",
  TXT:   "Text record (SPF, DMARC, DKIM, verification)",
  NS:    "Name server record",
  CNAME: "Canonical name record",
  CAA:   "Certificate Authority Authorization record",
  SOA:   "Start of Authority record",
};

// ---------------------------------------------------------------------------
// scanHeaders(url) -- HTTP security header scanner
// ---------------------------------------------------------------------------
async function scanHeaders(url) {
  const startTime = Date.now();
  let parsed;
  try {
    parsed = new URL(url.startsWith("http") ? url : `https://${url}`);
  } catch (e) {
    throw new Error(`Invalid URL: ${url} -- ${e.message}`);
  }

  const responseHeaders = await new Promise((resolve, reject) => {
    const mod = parsed.protocol === "https:" ? https : http;
    const opts = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: "GET",
      headers: { "User-Agent": "DarknodeScanner/1.0" },
      timeout: 15000,
      rejectUnauthorized: false,
    };
    const req = mod.request(opts, (res) => {
      // Consume the body to avoid memory leak
      res.on("data", () => {});
      res.on("end", () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          rawHeaders: res.rawHeaders,
        });
      });
    });
    req.on("error", (err) => reject(new Error(`Connection failed: ${err.message}`)));
    req.on("timeout", () => { req.destroy(); reject(new Error("Connection timed out after 15 seconds.")); });
    req.end();
  });

  const results = {
    url: parsed.href,
    hostname: parsed.hostname,
    timestamp: new Date().toISOString(),
    statusCode: responseHeaders.statusCode,
    responseHeaders: responseHeaders.headers,
    checks: [],
    passed: 0,
    failed: 0,
    warnings: 0,
    totalWeight: 0,
    earnedWeight: 0,
    score: 0,
    grade: "F",
    scanDuration: 0,
  };

  for (const check of HEADER_CHECKS) {
    const headerValue = responseHeaders.headers[check.name.toLowerCase()] || null;
    const result = check.checkFn(headerValue);
    const entry = {
      header: check.name,
      description: check.description,
      present: headerValue !== null,
      value: headerValue,
      severity: check.severity,
      weight: check.weight,
      pass: result.pass,
      detail: result.detail,
      recommendation: result.recommendation,
    };
    results.checks.push(entry);
    results.totalWeight += check.weight;
    if (result.pass) {
      results.passed++;
      results.earnedWeight += check.weight;
    } else if (result.recommendation) {
      results.failed++;
    } else {
      results.warnings++;
    }
  }

  results.score = results.totalWeight > 0 ? Math.round((results.earnedWeight / results.totalWeight) * 100) : 0;
  results.grade = scoreToGrade(results.score);
  results.scanDuration = Date.now() - startTime;

  return results;
}

// ---------------------------------------------------------------------------
// scanSSL(host, port) -- TLS configuration scanner
// ---------------------------------------------------------------------------
async function scanSSL(host, port) {
  port = port || 443;
  const startTime = Date.now();

  const tlsResult = await new Promise((resolve, reject) => {
    const socket = tls.connect({
      host,
      port,
      rejectUnauthorized: false,
      servername: host,
      timeout: 15000,
    }, () => {
      const cert = socket.getPeerCertificate(true);
      const cipher = socket.getCipher();
      const protocol = socket.getProtocol();
      const authorized = socket.authorized;
      const authError = socket.authorizationError;

      socket.end();

      resolve({
        connected: true,
        protocol,
        cipher,
        cert,
        authorized,
        authorizationError: authError || null,
      });
    });

    socket.on("error", (err) => {
      reject(new Error(`TLS connection failed: ${err.message}`));
    });
    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error("TLS connection timed out after 15 seconds."));
    });
  });

  const results = {
    host,
    port,
    timestamp: new Date().toISOString(),
    connected: tlsResult.connected,
    protocol: {
      version: tlsResult.protocol,
      secure: false,
      detail: "",
    },
    cipher: {
      name: "",
      version: "",
      bits: 0,
      secure: false,
      detail: "",
    },
    certificate: {
      subject: null,
      issuer: null,
      validFrom: null,
      validTo: null,
      daysRemaining: 0,
      serialNumber: null,
      fingerprint: null,
      keySize: 0,
      selfSigned: false,
      expired: false,
      authorized: false,
      authorizationError: null,
      subjectAltNames: [],
    },
    findings: [],
    score: 0,
    grade: "F",
    scanDuration: 0,
  };

  // Protocol analysis
  const protoInfo = PROTOCOL_GRADES[tlsResult.protocol] || { grade: "F", secure: false };
  results.protocol.version = tlsResult.protocol;
  results.protocol.secure = protoInfo.secure;
  if (protoInfo.secure) {
    results.protocol.detail = `${tlsResult.protocol} is supported and secure.`;
  } else {
    results.protocol.detail = `${tlsResult.protocol} is outdated and insecure.`;
    results.findings.push({ severity: "critical", finding: `Insecure TLS protocol: ${tlsResult.protocol}`, recommendation: "Upgrade to TLS 1.2 or preferably TLS 1.3." });
  }

  // Cipher analysis
  if (tlsResult.cipher) {
    results.cipher.name = tlsResult.cipher.name || "Unknown";
    results.cipher.version = tlsResult.cipher.version || "";
    results.cipher.bits = tlsResult.cipher.bits || 0;
    const cipherName = (tlsResult.cipher.name || "").toUpperCase();
    const isWeak = WEAK_CIPHERS.some(w => cipherName.includes(w));
    const isStrong = STRONG_CIPHERS.some(s => cipherName.includes(s));
    results.cipher.secure = !isWeak;
    if (isWeak) {
      results.cipher.detail = `Weak cipher suite: ${tlsResult.cipher.name}`;
      results.findings.push({ severity: "high", finding: `Weak cipher suite in use: ${tlsResult.cipher.name}`, recommendation: "Configure the server to use only strong cipher suites (AES-GCM, ChaCha20-Poly1305) with ECDHE key exchange." });
    } else if (isStrong) {
      results.cipher.detail = `Strong cipher suite: ${tlsResult.cipher.name} (${tlsResult.cipher.bits} bits)`;
    } else {
      results.cipher.detail = `Cipher suite: ${tlsResult.cipher.name} (${tlsResult.cipher.bits} bits)`;
    }
    if (tlsResult.cipher.bits && tlsResult.cipher.bits < 128) {
      results.findings.push({ severity: "high", finding: `Cipher key length is only ${tlsResult.cipher.bits} bits.`, recommendation: "Use cipher suites with at least 128-bit keys (256-bit preferred)." });
    }
  }

  // Certificate analysis
  if (tlsResult.cert && tlsResult.cert.subject) {
    const cert = tlsResult.cert;
    results.certificate.subject = cert.subject ? formatCertField(cert.subject) : "Unknown";
    results.certificate.issuer = cert.issuer ? formatCertField(cert.issuer) : "Unknown";
    results.certificate.validFrom = cert.valid_from || null;
    results.certificate.validTo = cert.valid_to || null;
    results.certificate.serialNumber = cert.serialNumber || null;
    results.certificate.fingerprint = cert.fingerprint256 || cert.fingerprint || null;
    results.certificate.authorized = tlsResult.authorized;
    results.certificate.authorizationError = tlsResult.authorizationError;

    // Key size from modulus or bits
    if (cert.bits) {
      results.certificate.keySize = cert.bits;
    } else if (cert.modulus) {
      results.certificate.keySize = cert.modulus.length * 4; // hex chars to bits
    }

    // SAN (Subject Alternative Names)
    if (cert.subjectaltname) {
      results.certificate.subjectAltNames = cert.subjectaltname.split(",").map(s => s.trim());
    }

    // Expiry check
    if (cert.valid_to) {
      const expiry = new Date(cert.valid_to);
      const now = new Date();
      const daysRemaining = Math.floor((expiry - now) / (1000 * 60 * 60 * 24));
      results.certificate.daysRemaining = daysRemaining;
      results.certificate.expired = daysRemaining < 0;

      if (daysRemaining < 0) {
        results.findings.push({ severity: "critical", finding: `Certificate expired ${Math.abs(daysRemaining)} days ago.`, recommendation: "Renew the SSL/TLS certificate immediately." });
      } else if (daysRemaining < 14) {
        results.findings.push({ severity: "high", finding: `Certificate expires in ${daysRemaining} days.`, recommendation: "Renew the certificate before expiry to avoid service disruption." });
      } else if (daysRemaining < 30) {
        results.findings.push({ severity: "medium", finding: `Certificate expires in ${daysRemaining} days.`, recommendation: "Plan certificate renewal within the next two weeks." });
      }
    }

    // Self-signed check
    const subj = JSON.stringify(cert.subject || {});
    const iss = JSON.stringify(cert.issuer || {});
    if (subj === iss) {
      results.certificate.selfSigned = true;
      results.findings.push({ severity: "high", finding: "Certificate is self-signed.", recommendation: "Use a certificate from a trusted Certificate Authority (CA). Let's Encrypt provides free certificates." });
    }

    // Key size check
    if (results.certificate.keySize > 0 && results.certificate.keySize < 2048) {
      results.findings.push({ severity: "high", finding: `Certificate key size is only ${results.certificate.keySize} bits.`, recommendation: "Use at least a 2048-bit RSA key or a 256-bit ECDSA key." });
    }

    // Authorization error
    if (tlsResult.authorizationError) {
      results.findings.push({ severity: "medium", finding: `Certificate authorization error: ${tlsResult.authorizationError}`, recommendation: "Ensure the certificate chain is complete and trusted." });
    }
  } else {
    results.findings.push({ severity: "critical", finding: "No certificate information available.", recommendation: "Verify the server is properly configured with a valid SSL/TLS certificate." });
  }

  // Scoring
  let sslScore = 100;
  for (const f of results.findings) {
    const w = SEVERITY_WEIGHTS[f.severity] || 1;
    sslScore -= w * 5;
  }
  if (!protoInfo.secure) sslScore -= 20;
  results.score = Math.max(0, Math.min(100, sslScore));
  results.grade = scoreToGrade(results.score);
  results.scanDuration = Date.now() - startTime;

  return results;
}

function formatCertField(field) {
  if (typeof field === "string") return field;
  if (typeof field === "object") {
    const parts = [];
    if (field.CN) parts.push(`CN=${field.CN}`);
    if (field.O) parts.push(`O=${field.O}`);
    if (field.OU) parts.push(`OU=${field.OU}`);
    if (field.L) parts.push(`L=${field.L}`);
    if (field.ST) parts.push(`ST=${field.ST}`);
    if (field.C) parts.push(`C=${field.C}`);
    return parts.join(", ") || "Unknown";
  }
  return String(field);
}

// ---------------------------------------------------------------------------
// scanDNS(domain) -- DNS security record scanner
// ---------------------------------------------------------------------------
async function scanDNS(domain) {
  const startTime = Date.now();
  domain = domain.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/:\d+$/, "");

  const results = {
    domain,
    timestamp: new Date().toISOString(),
    records: {
      A: [],
      AAAA: [],
      MX: [],
      NS: [],
      TXT: [],
      CAA: [],
      SOA: null,
    },
    security: {
      spf: { found: false, record: null, valid: false, detail: "", issues: [] },
      dmarc: { found: false, record: null, valid: false, detail: "", issues: [] },
      dkim: { found: false, detail: "" },
      caa: { found: false, records: [], detail: "" },
      dnssec: { detail: "DNSSEC validation requires external tools (dig +dnssec)." },
    },
    findings: [],
    score: 0,
    grade: "F",
    scanDuration: 0,
  };

  // Helper to wrap dns.resolve in a promise
  function dnsResolve(name, type) {
    return new Promise((resolve) => {
      dns.resolve(name, type, (err, records) => {
        if (err) resolve([]);
        else resolve(records || []);
      });
    });
  }

  // Parallel DNS lookups
  const [aRecords, aaaaRecords, mxRecords, nsRecords, txtRecords, caaRecords] = await Promise.all([
    dnsResolve(domain, "A"),
    dnsResolve(domain, "AAAA"),
    dnsResolve(domain, "MX"),
    dnsResolve(domain, "NS"),
    dnsResolve(domain, "TXT"),
    dnsResolve(domain, "CAA"),
  ]);

  // Also look up DMARC and common DKIM selectors
  const [dmarcRecords, dkimDefault, dkimGoogle, dkimSelector1, dkimSelector2] = await Promise.all([
    dnsResolve(`_dmarc.${domain}`, "TXT"),
    dnsResolve(`default._domainkey.${domain}`, "TXT"),
    dnsResolve(`google._domainkey.${domain}`, "TXT"),
    dnsResolve(`selector1._domainkey.${domain}`, "TXT"),
    dnsResolve(`selector2._domainkey.${domain}`, "TXT"),
  ]);

  // SOA lookup
  const soaRecord = await new Promise((resolve) => {
    dns.resolveSoa(domain, (err, soa) => {
      if (err) resolve(null);
      else resolve(soa);
    });
  });

  // Store records
  results.records.A = aRecords;
  results.records.AAAA = aaaaRecords;
  results.records.MX = mxRecords;
  results.records.NS = nsRecords;
  results.records.TXT = txtRecords.map(t => Array.isArray(t) ? t.join("") : String(t));
  results.records.CAA = caaRecords;
  results.records.SOA = soaRecord;

  // A/AAAA records check
  if (aRecords.length === 0 && aaaaRecords.length === 0) {
    results.findings.push({ severity: "info", finding: "No A or AAAA records found.", recommendation: "Verify the domain resolves correctly." });
  }
  if (aaaaRecords.length === 0 && aRecords.length > 0) {
    results.findings.push({ severity: "info", finding: "No IPv6 (AAAA) records found.", recommendation: "Consider adding AAAA records for IPv6 support." });
  }

  // NS records check
  if (nsRecords.length < 2) {
    results.findings.push({ severity: "medium", finding: `Only ${nsRecords.length} nameserver(s) found.`, recommendation: "Use at least two nameservers from different networks for redundancy." });
  }

  // SPF analysis
  const spfRecords = results.records.TXT.filter(t => /^v=spf1\b/i.test(t));
  if (spfRecords.length === 0) {
    results.security.spf.found = false;
    results.security.spf.detail = "No SPF record found.";
    results.findings.push({ severity: "high", finding: "No SPF record found.", recommendation: "Add an SPF TXT record to prevent email spoofing (e.g. 'v=spf1 include:_spf.google.com -all')." });
  } else if (spfRecords.length > 1) {
    results.security.spf.found = true;
    results.security.spf.record = spfRecords[0];
    results.security.spf.issues.push("Multiple SPF records found (only one is allowed per RFC 7208).");
    results.findings.push({ severity: "high", finding: "Multiple SPF records found.", recommendation: "Merge into a single SPF record. Multiple SPF records cause unpredictable behavior." });
  } else {
    results.security.spf.found = true;
    results.security.spf.record = spfRecords[0];
    const spf = spfRecords[0];
    // Check for overly permissive SPF
    if (/\+all/i.test(spf)) {
      results.security.spf.issues.push("SPF uses '+all' which allows any server to send email.");
      results.findings.push({ severity: "critical", finding: "SPF record uses '+all', allowing any server to send email as this domain.", recommendation: "Change '+all' to '-all' (hard fail) or '~all' (soft fail)." });
    } else if (/\?all/i.test(spf)) {
      results.security.spf.issues.push("SPF uses '?all' (neutral) which provides no protection.");
      results.findings.push({ severity: "high", finding: "SPF record uses '?all' (neutral), providing no real protection.", recommendation: "Change '?all' to '-all' (hard fail) or '~all' (soft fail)." });
    } else if (/~all/i.test(spf)) {
      results.security.spf.valid = true;
      results.security.spf.detail = "SPF record found with soft fail (~all).";
      results.findings.push({ severity: "low", finding: "SPF uses '~all' (soft fail) instead of '-all' (hard fail).", recommendation: "Consider changing to '-all' for stricter enforcement once you are confident in your SPF configuration." });
    } else if (/-all/i.test(spf)) {
      results.security.spf.valid = true;
      results.security.spf.detail = "SPF record found with hard fail (-all). Good.";
    }
    // Count DNS lookups (max 10 allowed)
    const lookups = (spf.match(/\b(include|a|mx|ptr|exists|redirect)\b/gi) || []).length;
    if (lookups > 10) {
      results.security.spf.issues.push(`SPF record requires ${lookups} DNS lookups (maximum is 10).`);
      results.findings.push({ severity: "medium", finding: `SPF record requires ${lookups} DNS lookups, exceeding the 10-lookup limit.`, recommendation: "Flatten the SPF record to reduce DNS lookups below 10." });
    }
  }

  // DMARC analysis
  const dmarcTxt = dmarcRecords.map(t => Array.isArray(t) ? t.join("") : String(t)).filter(t => /^v=DMARC1/i.test(t));
  if (dmarcTxt.length === 0) {
    results.security.dmarc.found = false;
    results.security.dmarc.detail = "No DMARC record found.";
    results.findings.push({ severity: "high", finding: "No DMARC record found.", recommendation: "Add a DMARC TXT record at _dmarc." + domain + " (e.g. 'v=DMARC1; p=reject; rua=mailto:dmarc@" + domain + "')." });
  } else {
    results.security.dmarc.found = true;
    results.security.dmarc.record = dmarcTxt[0];
    const dmarc = dmarcTxt[0];
    const policyMatch = dmarc.match(/;\s*p=(\w+)/i);
    const policy = policyMatch ? policyMatch[1].toLowerCase() : "none";
    if (policy === "none") {
      results.security.dmarc.valid = false;
      results.security.dmarc.detail = "DMARC policy is set to 'none' (monitor only, no enforcement).";
      results.security.dmarc.issues.push("Policy is set to 'none' -- emails failing authentication are still delivered.");
      results.findings.push({ severity: "medium", finding: "DMARC policy is 'none' (no enforcement).", recommendation: "After monitoring, upgrade to 'p=quarantine' or 'p=reject' for actual protection." });
    } else if (policy === "quarantine") {
      results.security.dmarc.valid = true;
      results.security.dmarc.detail = "DMARC policy is set to 'quarantine'.";
      results.findings.push({ severity: "low", finding: "DMARC policy is 'quarantine'.", recommendation: "Consider upgrading to 'p=reject' for maximum protection once monitoring confirms no legitimate mail is affected." });
    } else if (policy === "reject") {
      results.security.dmarc.valid = true;
      results.security.dmarc.detail = "DMARC policy is set to 'reject'. Strong.";
    }
    // Check for rua (aggregate reporting)
    if (!/rua=/i.test(dmarc)) {
      results.security.dmarc.issues.push("No aggregate reporting URI (rua) configured.");
      results.findings.push({ severity: "low", finding: "DMARC record has no aggregate reporting (rua) configured.", recommendation: "Add 'rua=mailto:dmarc-reports@" + domain + "' to receive DMARC aggregate reports." });
    }
  }

  // DKIM check (common selectors)
  const dkimSelectors = [
    { name: "default", records: dkimDefault },
    { name: "google", records: dkimGoogle },
    { name: "selector1", records: dkimSelector1 },
    { name: "selector2", records: dkimSelector2 },
  ];
  let dkimFound = false;
  for (const sel of dkimSelectors) {
    const recs = sel.records.map(t => Array.isArray(t) ? t.join("") : String(t));
    if (recs.some(r => /DKIM|v=DKIM1|p=/i.test(r))) {
      dkimFound = true;
      results.security.dkim.found = true;
      results.security.dkim.detail = `DKIM record found for selector '${sel.name}'.`;
      break;
    }
  }
  if (!dkimFound) {
    results.security.dkim.found = false;
    results.security.dkim.detail = "No DKIM records found for common selectors (default, google, selector1, selector2).";
    results.findings.push({ severity: "medium", finding: "No DKIM records found for common selectors.", recommendation: "Configure DKIM signing for your email service and publish the public key as a TXT record." });
  }

  // CAA records check
  if (caaRecords.length === 0) {
    results.security.caa.found = false;
    results.security.caa.detail = "No CAA records found.";
    results.findings.push({ severity: "low", finding: "No CAA records found.", recommendation: "Add CAA records to restrict which Certificate Authorities can issue certificates for this domain." });
  } else {
    results.security.caa.found = true;
    results.security.caa.records = caaRecords;
    results.security.caa.detail = `${caaRecords.length} CAA record(s) found.`;
  }

  // MX records check (if domain has MX)
  if (mxRecords.length > 0) {
    // Check if any MX points to localhost or suspicious values
    for (const mx of mxRecords) {
      const exchange = (mx.exchange || mx || "").toString().toLowerCase();
      if (exchange === "localhost" || exchange === "." || /^127\.|^0\./.test(exchange)) {
        results.findings.push({ severity: "medium", finding: `Suspicious MX record: ${exchange}`, recommendation: "Review MX records for correct mail server configuration." });
      }
    }
  }

  // Scoring
  let dnsScore = 100;
  for (const f of results.findings) {
    const w = SEVERITY_WEIGHTS[f.severity] || 1;
    dnsScore -= w * 3;
  }
  results.score = Math.max(0, Math.min(100, dnsScore));
  results.grade = scoreToGrade(results.score);
  results.scanDuration = Date.now() - startTime;

  return results;
}

// ---------------------------------------------------------------------------
// generateReport(results) -- produce formatted markdown report
// ---------------------------------------------------------------------------
function generateReport(results) {
  const lines = [];
  const timestamp = new Date().toISOString();
  const scanId = crypto.randomBytes(4).toString("hex").toUpperCase();

  lines.push("# Security Scan Report");
  lines.push(`**Scan ID:** ${scanId}`);
  lines.push(`**Generated:** ${timestamp}`);
  lines.push("");

  // ---- Executive Summary ----
  lines.push("## Executive Summary");
  lines.push("");

  const allFindings = [];
  const grades = [];
  const scores = [];

  if (results.headers) {
    grades.push({ type: "HTTP Headers", grade: results.headers.grade, score: results.headers.score });
    scores.push(results.headers.score);
    for (const c of results.headers.checks) {
      if (!c.pass) allFindings.push({ source: "Headers", severity: c.severity, finding: c.detail, recommendation: c.recommendation });
    }
  }
  if (results.ssl) {
    grades.push({ type: "SSL/TLS", grade: results.ssl.grade, score: results.ssl.score });
    scores.push(results.ssl.score);
    for (const f of results.ssl.findings) {
      allFindings.push({ source: "SSL/TLS", severity: f.severity, finding: f.finding, recommendation: f.recommendation });
    }
  }
  if (results.dns) {
    grades.push({ type: "DNS Security", grade: results.dns.grade, score: results.dns.score });
    scores.push(results.dns.score);
    for (const f of results.dns.findings) {
      allFindings.push({ source: "DNS", severity: f.severity, finding: f.finding, recommendation: f.recommendation });
    }
  }

  const overallScore = scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
  const overallGrade = scoreToGrade(overallScore);

  lines.push(`**Overall Grade: ${overallGrade} (${overallScore}/100)**`);
  lines.push("");

  if (grades.length > 0) {
    lines.push("| Scan Component | Grade | Score |");
    lines.push("|----------------|-------|-------|");
    for (const g of grades) {
      lines.push(`| ${g.type} | ${g.grade} | ${g.score}/100 |`);
    }
    lines.push("");
  }

  const critCount = allFindings.filter(f => f.severity === "critical").length;
  const highCount = allFindings.filter(f => f.severity === "high").length;
  const medCount = allFindings.filter(f => f.severity === "medium").length;
  const lowCount = allFindings.filter(f => f.severity === "low").length;
  const infoCount = allFindings.filter(f => f.severity === "info").length;

  lines.push(`Total findings: ${allFindings.length} (${critCount} critical, ${highCount} high, ${medCount} medium, ${lowCount} low, ${infoCount} informational)`);
  lines.push("");

  // ---- Score Breakdown ----
  lines.push("## Score Breakdown");
  lines.push("");
  lines.push("```");
  const barWidth = 40;
  for (const g of grades) {
    const filled = Math.round((g.score / 100) * barWidth);
    const bar = "#".repeat(filled) + "-".repeat(barWidth - filled);
    lines.push(`${(g.type + ":").padEnd(16)} [${bar}] ${g.score}% (${g.grade})`);
  }
  if (grades.length > 0) {
    const oFilled = Math.round((overallScore / 100) * barWidth);
    const oBar = "#".repeat(oFilled) + "-".repeat(barWidth - oFilled);
    lines.push(`${"OVERALL:".padEnd(16)} [${oBar}] ${overallScore}% (${overallGrade})`);
  }
  lines.push("```");
  lines.push("");

  // ---- Detailed Findings ----
  if (allFindings.length > 0) {
    lines.push("## Detailed Findings");
    lines.push("");
    lines.push("| # | Source | Severity | Finding | Recommendation |");
    lines.push("|---|--------|----------|---------|----------------|");
    // Sort by severity weight (critical first)
    const sorted = allFindings.sort((a, b) => (SEVERITY_WEIGHTS[b.severity] || 0) - (SEVERITY_WEIGHTS[a.severity] || 0));
    sorted.forEach((f, i) => {
      const rec = f.recommendation || "N/A";
      const finding = (f.finding || "").replace(/\|/g, "\\|").replace(/\n/g, " ");
      const recClean = rec.replace(/\|/g, "\\|").replace(/\n/g, " ");
      lines.push(`| ${i + 1} | ${f.source} | ${f.severity.toUpperCase()} | ${finding} | ${recClean} |`);
    });
    lines.push("");
  }

  // ---- HTTP Headers Detail ----
  if (results.headers) {
    lines.push("## HTTP Header Analysis");
    lines.push("");
    lines.push(`**URL:** ${results.headers.url}`);
    lines.push(`**Status Code:** ${results.headers.statusCode}`);
    lines.push(`**Grade:** ${results.headers.grade} (${results.headers.score}/100)`);
    lines.push(`**Passed:** ${results.headers.passed} | **Failed:** ${results.headers.failed} | **Warnings:** ${results.headers.warnings}`);
    lines.push("");

    lines.push("### Pass/Fail Breakdown");
    lines.push("");
    lines.push("| Header | Present | Status | Severity |");
    lines.push("|--------|---------|--------|----------|");
    for (const c of results.headers.checks) {
      const status = c.pass ? "PASS" : "FAIL";
      const present = c.present ? "Yes" : "No";
      lines.push(`| ${c.header} | ${present} | ${status} | ${c.severity.toUpperCase()} |`);
    }
    lines.push("");
  }

  // ---- SSL/TLS Detail ----
  if (results.ssl) {
    lines.push("## SSL/TLS Analysis");
    lines.push("");
    lines.push(`**Host:** ${results.ssl.host}:${results.ssl.port}`);
    lines.push(`**Grade:** ${results.ssl.grade} (${results.ssl.score}/100)`);
    lines.push("");
    lines.push("### Protocol");
    lines.push(`- Version: ${results.ssl.protocol.version}`);
    lines.push(`- Secure: ${results.ssl.protocol.secure ? "Yes" : "No"}`);
    lines.push(`- Detail: ${results.ssl.protocol.detail}`);
    lines.push("");
    lines.push("### Cipher Suite");
    lines.push(`- Name: ${results.ssl.cipher.name}`);
    lines.push(`- Bits: ${results.ssl.cipher.bits}`);
    lines.push(`- Secure: ${results.ssl.cipher.secure ? "Yes" : "No"}`);
    lines.push("");
    lines.push("### Certificate");
    const cert = results.ssl.certificate;
    lines.push(`- Subject: ${cert.subject || "N/A"}`);
    lines.push(`- Issuer: ${cert.issuer || "N/A"}`);
    lines.push(`- Valid From: ${cert.validFrom || "N/A"}`);
    lines.push(`- Valid To: ${cert.validTo || "N/A"}`);
    lines.push(`- Days Remaining: ${cert.daysRemaining}`);
    lines.push(`- Key Size: ${cert.keySize || "N/A"} bits`);
    lines.push(`- Self-Signed: ${cert.selfSigned ? "Yes" : "No"}`);
    lines.push(`- Expired: ${cert.expired ? "Yes" : "No"}`);
    lines.push(`- Trusted: ${cert.authorized ? "Yes" : "No"}`);
    if (cert.subjectAltNames.length > 0) {
      lines.push(`- SANs: ${cert.subjectAltNames.join(", ")}`);
    }
    lines.push("");
  }

  // ---- DNS Detail ----
  if (results.dns) {
    lines.push("## DNS Security Analysis");
    lines.push("");
    lines.push(`**Domain:** ${results.dns.domain}`);
    lines.push(`**Grade:** ${results.dns.grade} (${results.dns.score}/100)`);
    lines.push("");
    lines.push("### DNS Records");
    const rec = results.dns.records;
    if (rec.A.length > 0) lines.push(`- A: ${rec.A.join(", ")}`);
    if (rec.AAAA.length > 0) lines.push(`- AAAA: ${rec.AAAA.join(", ")}`);
    if (rec.NS.length > 0) lines.push(`- NS: ${rec.NS.join(", ")}`);
    if (rec.MX.length > 0) lines.push(`- MX: ${rec.MX.map(m => `${m.exchange || m} (pri ${m.priority || "?"})`).join(", ")}`);
    if (rec.CAA.length > 0) lines.push(`- CAA: ${JSON.stringify(rec.CAA)}`);
    if (rec.SOA) lines.push(`- SOA: ${rec.SOA.nsname} (${rec.SOA.hostmaster})`);
    lines.push("");
    lines.push("### Email Security");
    lines.push(`- SPF: ${results.dns.security.spf.found ? results.dns.security.spf.detail : "Not configured"}`);
    lines.push(`- DMARC: ${results.dns.security.dmarc.found ? results.dns.security.dmarc.detail : "Not configured"}`);
    lines.push(`- DKIM: ${results.dns.security.dkim.detail}`);
    lines.push(`- CAA: ${results.dns.security.caa.detail}`);
    lines.push("");
  }

  // ---- Prioritized Recommendations ----
  if (allFindings.length > 0) {
    lines.push("## Prioritized Recommendations");
    lines.push("");
    const prioritized = allFindings
      .filter(f => f.recommendation && f.recommendation !== "N/A")
      .sort((a, b) => (SEVERITY_WEIGHTS[b.severity] || 0) - (SEVERITY_WEIGHTS[a.severity] || 0));

    let pri = 1;
    for (const f of prioritized) {
      lines.push(`${pri}. **[${f.severity.toUpperCase()}]** ${f.recommendation}`);
      pri++;
    }
    lines.push("");
  }

  lines.push("---");
  lines.push(`*Report generated by Darknode Security Scanner on ${timestamp}*`);
  lines.push("");

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// runFullScan(target) -- convenience: run all scans and generate report
// ---------------------------------------------------------------------------
async function runFullScan(target) {
  let hostname;
  try {
    const parsed = new URL(target.startsWith("http") ? target : `https://${target}`);
    hostname = parsed.hostname;
  } catch {
    hostname = target.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/:\d+$/, "");
  }

  const scanResults = {};
  const errors = [];

  // Run scans in parallel
  const [headerResult, sslResult, dnsResult] = await Promise.allSettled([
    scanHeaders(target),
    scanSSL(hostname),
    scanDNS(hostname),
  ]);

  if (headerResult.status === "fulfilled") {
    scanResults.headers = headerResult.value;
  } else {
    errors.push(`Header scan failed: ${headerResult.reason.message}`);
  }

  if (sslResult.status === "fulfilled") {
    scanResults.ssl = sslResult.value;
  } else {
    errors.push(`SSL scan failed: ${sslResult.reason.message}`);
  }

  if (dnsResult.status === "fulfilled") {
    scanResults.dns = dnsResult.value;
  } else {
    errors.push(`DNS scan failed: ${dnsResult.reason.message}`);
  }

  const report = generateReport(scanResults);
  return { results: scanResults, report, errors };
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
module.exports = {
  SEVERITY_WEIGHTS,
  GRADE_THRESHOLDS,
  HEADER_CHECKS,
  WEAK_CIPHERS,
  STRONG_CIPHERS,
  PROTOCOL_GRADES,
  DNS_RECORD_TYPES,
  scoreToGrade,
  scanHeaders,
  scanSSL,
  scanDNS,
  generateReport,
  runFullScan,
};
