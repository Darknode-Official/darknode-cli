"use strict";
// Web security scanning utilities -- offline reference data and helper functions for
// auditing HTTP security headers, SSL/TLS configuration, CORS policies, CSP directives,
// cookie flags, DNS security records, subresource integrity, HTTP methods, and common
// misconfigurations. Each data set is self-contained: no network I/O at import time.
// The helper functions (gradeHeaders, checkSSL, analyzeCORS, validateCSP) accept raw
// inputs and return structured audit results suitable for CLI display or JSON export.

// ---------------------------------------------------------------------------
// 1. SECURITY_HEADERS -- 30 HTTP response headers that matter for security
// ---------------------------------------------------------------------------
const SECURITY_HEADERS = [
  {
    name: "Strict-Transport-Security",
    recommended: "max-age=31536000; includeSubDomains; preload",
    severity: "high",
    description: "Forces browsers to use HTTPS for all future requests to the domain.",
    impact: "Without HSTS, users are vulnerable to SSL-stripping MITM attacks on first visit.",
    check: (val) => {
      if (!val) return { pass: false, reason: "Header missing" };
      const ma = val.match(/max-age=(\d+)/i);
      if (!ma) return { pass: false, reason: "No max-age directive found" };
      const age = parseInt(ma[1], 10);
      if (age < 31536000) return { pass: false, reason: `max-age ${age} is below recommended 31536000 (1 year)` };
      const sub = /includeSubDomains/i.test(val);
      const preload = /preload/i.test(val);
      return { pass: true, maxAge: age, includeSubDomains: sub, preload, reason: "Adequate HSTS policy" };
    },
  },
  {
    name: "Content-Security-Policy",
    recommended: "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    severity: "high",
    description: "Controls which resources the browser is allowed to load, mitigating XSS and data injection.",
    impact: "Missing or weak CSP leaves the application open to cross-site scripting attacks.",
    check: (val) => {
      if (!val) return { pass: false, reason: "Header missing" };
      const issues = [];
      if (/unsafe-inline/i.test(val) && !/nonce-/i.test(val) && !/sha256-/i.test(val)) {
        issues.push("'unsafe-inline' without nonce or hash weakens script-src");
      }
      if (/unsafe-eval/i.test(val)) issues.push("'unsafe-eval' allows dynamic code execution");
      if (val.includes("*") && !val.includes("*.")) issues.push("Wildcard source '*' is overly permissive");
      if (!/default-src/i.test(val)) issues.push("No default-src fallback directive");
      return { pass: issues.length === 0, issues, reason: issues.length ? issues.join("; ") : "CSP looks reasonable" };
    },
  },
  {
    name: "X-Content-Type-Options",
    recommended: "nosniff",
    severity: "medium",
    description: "Prevents browsers from MIME-sniffing a response away from the declared content-type.",
    impact: "Without nosniff, browsers may interpret files as executable scripts.",
    check: (val) => {
      if (!val) return { pass: false, reason: "Header missing" };
      return { pass: val.trim().toLowerCase() === "nosniff", reason: val.trim().toLowerCase() === "nosniff" ? "Correctly set to nosniff" : `Unexpected value: ${val}` };
    },
  },
  {
    name: "X-Frame-Options",
    recommended: "DENY",
    severity: "medium",
    description: "Prevents the page from being embedded in frames, blocking clickjacking attacks.",
    impact: "Missing X-Frame-Options allows attackers to embed the page in a malicious iframe.",
    check: (val) => {
      if (!val) return { pass: false, reason: "Header missing (use frame-ancestors in CSP as modern alternative)" };
      const v = val.trim().toUpperCase();
      const valid = ["DENY", "SAMEORIGIN"];
      return { pass: valid.includes(v), reason: valid.includes(v) ? `Set to ${v}` : `Unexpected value: ${val}` };
    },
  },
  {
    name: "X-XSS-Protection",
    recommended: "0",
    severity: "low",
    description: "Legacy header for the browser XSS filter. Modern best practice is to disable it and rely on CSP.",
    impact: "Enabling the XSS auditor can introduce information leakage in some browsers.",
    check: (val) => {
      if (!val) return { pass: true, reason: "Header absent; acceptable when CSP is present" };
      return { pass: val.trim() === "0", reason: val.trim() === "0" ? "Correctly disabled" : "Recommend setting to '0' and relying on CSP instead" };
    },
  },
  {
    name: "Referrer-Policy",
    recommended: "strict-origin-when-cross-origin",
    severity: "medium",
    description: "Controls how much referrer information is sent with requests.",
    impact: "Without a policy, full URLs (including tokens and parameters) may leak to third parties.",
    check: (val) => {
      if (!val) return { pass: false, reason: "Header missing" };
      const safe = ["no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin"];
      const v = val.trim().toLowerCase();
      return { pass: safe.includes(v), reason: safe.includes(v) ? `Good policy: ${v}` : `Policy '${v}' may leak sensitive URL data` };
    },
  },
  {
    name: "Permissions-Policy",
    recommended: "geolocation=(), camera=(), microphone=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()",
    severity: "medium",
    description: "Restricts access to browser features and APIs (successor to Feature-Policy).",
    impact: "Without restrictions, embedded content may access sensitive device capabilities.",
    check: (val) => {
      if (!val) return { pass: false, reason: "Header missing" };
      const blocked = (val.match(/=\(\)/g) || []).length;
      return { pass: blocked >= 3, reason: `${blocked} features explicitly blocked` };
    },
  },
  {
    name: "Cross-Origin-Opener-Policy",
    recommended: "same-origin",
    severity: "medium",
    description: "Isolates the browsing context group to prevent cross-origin window references.",
    impact: "Without COOP, cross-origin pages opened via window.open can access the opener.",
    check: (val) => {
      if (!val) return { pass: false, reason: "Header missing" };
      const v = val.trim().toLowerCase();
      return { pass: v === "same-origin", reason: v === "same-origin" ? "Correctly set" : `Value '${v}' is weaker than same-origin` };
    },
  },
  {
    name: "Cross-Origin-Embedder-Policy",
    recommended: "require-corp",
    severity: "medium",
    description: "Prevents a document from loading cross-origin resources without explicit permission.",
    impact: "Needed alongside COOP for cross-origin isolation (SharedArrayBuffer, high-res timers).",
    check: (val) => {
      if (!val) return { pass: false, reason: "Header missing" };
      const v = val.trim().toLowerCase();
      return { pass: v === "require-corp" || v === "credentialless", reason: v === "require-corp" || v === "credentialless" ? "Adequate policy" : `Unexpected value: ${v}` };
    },
  },
  {
    name: "Cross-Origin-Resource-Policy",
    recommended: "same-origin",
    severity: "medium",
    description: "Declares whether a resource can be loaded by other origins.",
    impact: "Without CORP, resources may be embedded by any origin, enabling speculative side-channel attacks.",
    check: (val) => {
      if (!val) return { pass: false, reason: "Header missing" };
      const v = val.trim().toLowerCase();
      const ok = ["same-origin", "same-site"];
      return { pass: ok.includes(v), reason: ok.includes(v) ? `Set to ${v}` : `Value '${v}' may be overly permissive` };
    },
  },
  {
    name: "Cache-Control",
    recommended: "no-store, no-cache, must-revalidate, private",
    severity: "medium",
    description: "Controls caching behavior for sensitive responses.",
    impact: "Caching authenticated responses may expose private data to subsequent users on shared devices.",
    check: (val) => {
      if (!val) return { pass: false, reason: "Header missing" };
      const v = val.toLowerCase();
      const hasNoStore = v.includes("no-store");
      const hasPrivate = v.includes("private");
      return { pass: hasNoStore || hasPrivate, reason: hasNoStore ? "no-store present" : hasPrivate ? "private present" : "Consider adding no-store or private for sensitive pages" };
    },
  },
  {
    name: "Pragma",
    recommended: "no-cache",
    severity: "low",
    description: "HTTP/1.0 cache-control fallback for older clients.",
    impact: "Without Pragma, HTTP/1.0 caches may store sensitive responses.",
    check: (val) => {
      if (!val) return { pass: true, reason: "Header absent; acceptable when Cache-Control is set" };
      return { pass: val.trim().toLowerCase() === "no-cache", reason: val.trim().toLowerCase() === "no-cache" ? "Correctly set" : `Unexpected value: ${val}` };
    },
  },
  {
    name: "X-Permitted-Cross-Domain-Policies",
    recommended: "none",
    severity: "low",
    description: "Controls whether Flash and Acrobat can load data from the domain.",
    impact: "Without restriction, legacy plugins may read cross-domain data.",
    check: (val) => {
      if (!val) return { pass: false, reason: "Header missing" };
      return { pass: val.trim().toLowerCase() === "none", reason: val.trim().toLowerCase() === "none" ? "Correctly set to none" : `Value '${val}' allows some cross-domain access` };
    },
  },
  {
    name: "X-DNS-Prefetch-Control",
    recommended: "off",
    severity: "low",
    description: "Controls DNS prefetching, which can leak information about which links a user views.",
    impact: "DNS prefetch can reveal browsing intent to third-party DNS resolvers.",
    check: (val) => {
      if (!val) return { pass: false, reason: "Header missing" };
      return { pass: val.trim().toLowerCase() === "off", reason: val.trim().toLowerCase() === "off" ? "Prefetching disabled" : "DNS prefetching is enabled" };
    },
  },
  {
    name: "Expect-CT",
    recommended: "max-age=86400, enforce",
    severity: "low",
    description: "Enforces Certificate Transparency requirements (deprecated in modern browsers).",
    impact: "Without CT enforcement, misissued certificates may go undetected.",
    check: (val) => {
      if (!val) return { pass: true, reason: "Header absent; CT is now enforced by default in modern browsers" };
      const enforce = /enforce/i.test(val);
      return { pass: enforce, reason: enforce ? "Enforce mode active" : "Present but not enforcing" };
    },
  },
  {
    name: "X-Download-Options",
    recommended: "noopen",
    severity: "low",
    description: "Prevents IE from opening downloaded files directly in the browser context.",
    impact: "Without noopen, downloaded HTML files execute in the site security context.",
    check: (val) => {
      if (!val) return { pass: false, reason: "Header missing" };
      return { pass: val.trim().toLowerCase() === "noopen", reason: val.trim().toLowerCase() === "noopen" ? "Correctly set" : `Unexpected value: ${val}` };
    },
  },
  {
    name: "Content-Type",
    recommended: "text/html; charset=utf-8",
    severity: "medium",
    description: "Specifies the media type and character encoding of the response.",
    impact: "Missing charset enables UTF-7 XSS in older browsers; wrong type causes MIME confusion.",
    check: (val) => {
      if (!val) return { pass: false, reason: "Header missing" };
      const hasCharset = /charset\s*=/i.test(val);
      return { pass: hasCharset, reason: hasCharset ? "Charset specified" : "No charset declaration -- add charset=utf-8" };
    },
  },
  {
    name: "Access-Control-Allow-Origin",
    recommended: "<specific-origin>",
    severity: "high",
    description: "Controls which origins may read the response via CORS.",
    impact: "A wildcard or reflected origin bypasses the same-origin policy for sensitive data.",
    check: (val) => {
      if (!val) return { pass: true, reason: "Header absent; CORS not enabled (may be intentional)" };
      if (val.trim() === "*") return { pass: false, reason: "Wildcard '*' allows any origin to read responses" };
      return { pass: true, reason: `Restricted to origin: ${val}` };
    },
  },
  {
    name: "Access-Control-Allow-Credentials",
    recommended: "false (or omit)",
    severity: "high",
    description: "Indicates whether the response can be exposed when the credentials flag is true.",
    impact: "When combined with a reflected origin, this enables full cross-origin session hijacking.",
    check: (val) => {
      if (!val) return { pass: true, reason: "Header absent; credentials not exposed" };
      return { pass: val.trim().toLowerCase() !== "true", reason: val.trim().toLowerCase() === "true" ? "Credentials exposed -- verify origin restrictions" : "Credentials not exposed" };
    },
  },
  {
    name: "Server",
    recommended: "(omit or generic)",
    severity: "low",
    description: "Reveals the web server software and version.",
    impact: "Detailed server banners help attackers identify known vulnerabilities.",
    check: (val) => {
      if (!val) return { pass: true, reason: "Header absent; good information hygiene" };
      const detailed = /\/\d/.test(val);
      return { pass: !detailed, reason: detailed ? `Reveals version info: ${val}` : "Generic server string" };
    },
  },
  {
    name: "X-Powered-By",
    recommended: "(remove)",
    severity: "low",
    description: "Reveals the backend framework or language.",
    impact: "Technology disclosure helps attackers select targeted exploits.",
    check: (val) => {
      if (!val) return { pass: true, reason: "Header absent; no technology leaked" };
      return { pass: false, reason: `Leaks technology: ${val}` };
    },
  },
  {
    name: "X-AspNet-Version",
    recommended: "(remove)",
    severity: "low",
    description: "Reveals the ASP.NET framework version.",
    impact: "Specific version disclosure aids targeted exploitation.",
    check: (val) => {
      if (!val) return { pass: true, reason: "Header absent" };
      return { pass: false, reason: `Leaks ASP.NET version: ${val}` };
    },
  },
  {
    name: "X-AspNetMvc-Version",
    recommended: "(remove)",
    severity: "low",
    description: "Reveals the ASP.NET MVC framework version.",
    impact: "Framework version disclosure narrows the attack surface for an attacker.",
    check: (val) => {
      if (!val) return { pass: true, reason: "Header absent" };
      return { pass: false, reason: `Leaks MVC version: ${val}` };
    },
  },
  {
    name: "X-Request-ID",
    recommended: "(ensure not leaked to client in production)",
    severity: "info",
    description: "Internal tracing identifier that may leak infrastructure details.",
    impact: "Request IDs can reveal backend topology and tracing infrastructure.",
    check: (val) => {
      if (!val) return { pass: true, reason: "Header absent" };
      return { pass: false, reason: "Internal request ID exposed to client" };
    },
  },
  {
    name: "X-Runtime",
    recommended: "(remove)",
    severity: "low",
    description: "Reveals server-side processing time, enabling timing attacks.",
    impact: "Precise timing data can be used for side-channel attacks against authentication.",
    check: (val) => {
      if (!val) return { pass: true, reason: "Header absent" };
      return { pass: false, reason: `Leaks processing time: ${val}s` };
    },
  },
  {
    name: "Content-Disposition",
    recommended: "attachment (for downloads)",
    severity: "medium",
    description: "Controls whether the browser displays the response inline or as a download.",
    impact: "Inline rendering of user-uploaded content can lead to stored XSS.",
    check: (val) => {
      if (!val) return { pass: true, reason: "Header absent; check context" };
      return { pass: /attachment/i.test(val), reason: /attachment/i.test(val) ? "Forces download" : "Inline rendering -- verify content is safe" };
    },
  },
  {
    name: "NEL",
    recommended: '{"report_to":"default","max_age":31536000,"include_subdomains":true}',
    severity: "info",
    description: "Network Error Logging reports network-level failures back to the origin.",
    impact: "Helps detect MITM attacks and connectivity issues, but may leak user browsing data.",
    check: (val) => {
      if (!val) return { pass: true, reason: "Header absent; NEL is optional" };
      try { JSON.parse(val); return { pass: true, reason: "Valid NEL configuration" }; }
      catch (_) { return { pass: false, reason: "Malformed NEL JSON" }; }
    },
  },
  {
    name: "Report-To",
    recommended: '{"group":"default","max_age":31536000,"endpoints":[{"url":"https://example.com/report"}]}',
    severity: "info",
    description: "Defines reporting endpoints for CSP violations, NEL, and other browser reports.",
    impact: "Without reporting, security violations go undetected.",
    check: (val) => {
      if (!val) return { pass: true, reason: "Header absent; reporting is optional but recommended" };
      try { JSON.parse(val); return { pass: true, reason: "Valid Report-To configuration" }; }
      catch (_) { return { pass: false, reason: "Malformed Report-To JSON" }; }
    },
  },
  {
    name: "Reporting-Endpoints",
    recommended: 'default="https://example.com/reports"',
    severity: "info",
    description: "Modern replacement for Report-To, defines endpoints for security reports.",
    impact: "Enables receiving CSP violation reports and deprecation warnings.",
    check: (val) => {
      if (!val) return { pass: true, reason: "Header absent; reporting endpoints are optional" };
      return { pass: val.includes("="), reason: val.includes("=") ? "Endpoint(s) defined" : "Malformed endpoint declaration" };
    },
  },
  {
    name: "Clear-Site-Data",
    recommended: '"cache", "cookies", "storage"',
    severity: "medium",
    description: "Instructs the browser to clear cached data on logout or session end.",
    impact: "Use on logout endpoints to ensure no residual session data remains in the browser.",
    check: (val) => {
      if (!val) return { pass: true, reason: "Header absent; only needed on logout/deauth endpoints" };
      const types = ["cache", "cookies", "storage", "executionContexts", "*"];
      const found = types.filter((t) => val.includes(t));
      return { pass: found.length > 0, reason: `Clearing: ${found.join(", ")}` };
    },
  },
];

// ---------------------------------------------------------------------------
// 2. COOKIE_FLAGS -- security-relevant cookie attributes
// ---------------------------------------------------------------------------
const COOKIE_FLAGS = [
  {
    flag: "Secure",
    description: "Cookie is only sent over HTTPS connections.",
    risk: "Without Secure, cookies transmit over plain HTTP and can be intercepted by network attackers.",
  },
  {
    flag: "HttpOnly",
    description: "Cookie is inaccessible to JavaScript via document.cookie.",
    risk: "Without HttpOnly, XSS attacks can steal session cookies directly.",
  },
  {
    flag: "SameSite=Strict",
    description: "Cookie is never sent on cross-site requests.",
    risk: "Without SameSite, cookies are sent on cross-origin requests enabling CSRF.",
  },
  {
    flag: "SameSite=Lax",
    description: "Cookie is sent on top-level navigations but not on cross-site subrequests.",
    risk: "Lax is the browser default; safe for most cases but does not block GET-based CSRF.",
  },
  {
    flag: "SameSite=None",
    description: "Cookie is sent on all cross-site requests (requires Secure flag).",
    risk: "Explicitly permits cross-site cookie usage; must be paired with Secure to function.",
  },
  {
    flag: "__Secure- prefix",
    description: "Browser enforces that the cookie has the Secure flag and was set over HTTPS.",
    risk: "Without the prefix, a non-HTTPS subdomain can overwrite the cookie.",
  },
  {
    flag: "__Host- prefix",
    description: "Browser enforces Secure, no Domain attribute, and Path=/. Strongest cookie isolation.",
    risk: "Prevents domain-scoped cookie injection from subdomains.",
  },
  {
    flag: "Max-Age / Expires",
    description: "Controls cookie lifetime. Session cookies have no explicit expiry.",
    risk: "Long-lived cookies expand the window for session hijacking after credential theft.",
  },
  {
    flag: "Domain",
    description: "Specifies which hosts receive the cookie. Omitting it restricts to the exact origin host.",
    risk: "Setting Domain broadly (e.g., .example.com) exposes the cookie to all subdomains.",
  },
  {
    flag: "Path",
    description: "Restricts cookie transmission to a URL path prefix.",
    risk: "Broad paths (Path=/) send the cookie with every request; narrow paths limit exposure.",
  },
  {
    flag: "Partitioned (CHIPS)",
    description: "Cookie is partitioned by top-level site, preventing cross-site tracking.",
    risk: "Without partitioning, third-party cookies enable cross-site user tracking.",
  },
];

// ---------------------------------------------------------------------------
// 3. SSL_CHECKS -- TLS/SSL configuration audit points
// ---------------------------------------------------------------------------
const SSL_CHECKS = [
  {
    name: "SSLv2",
    description: "SSL version 2.0 is severely broken and must be disabled.",
    severity: "critical",
    check: (protocols) => !protocols.includes("SSLv2"),
  },
  {
    name: "SSLv3",
    description: "SSL version 3.0 is vulnerable to POODLE and must be disabled.",
    severity: "critical",
    check: (protocols) => !protocols.includes("SSLv3"),
  },
  {
    name: "TLSv1.0",
    description: "TLS 1.0 is deprecated (PCI DSS, NIST). Should be disabled.",
    severity: "high",
    check: (protocols) => !protocols.includes("TLSv1.0"),
  },
  {
    name: "TLSv1.1",
    description: "TLS 1.1 is deprecated by all major browsers and standards bodies.",
    severity: "high",
    check: (protocols) => !protocols.includes("TLSv1.1"),
  },
  {
    name: "TLSv1.2",
    description: "TLS 1.2 is acceptable when configured with strong cipher suites.",
    severity: "info",
    check: (protocols) => protocols.includes("TLSv1.2"),
  },
  {
    name: "TLSv1.3",
    description: "TLS 1.3 provides the strongest security and performance. Preferred.",
    severity: "info",
    check: (protocols) => protocols.includes("TLSv1.3"),
  },
  {
    name: "RC4 cipher",
    description: "RC4 is broken; all RC4 cipher suites must be removed.",
    severity: "critical",
    check: (_, ciphers) => !(ciphers || []).some((c) => /RC4/i.test(c)),
  },
  {
    name: "3DES cipher",
    description: "Triple-DES (SWEET32) is weak due to 64-bit block size.",
    severity: "high",
    check: (_, ciphers) => !(ciphers || []).some((c) => /3DES|DES-CBC3/i.test(c)),
  },
  {
    name: "NULL cipher",
    description: "NULL ciphers provide no encryption at all.",
    severity: "critical",
    check: (_, ciphers) => !(ciphers || []).some((c) => /NULL/i.test(c)),
  },
  {
    name: "EXPORT cipher",
    description: "EXPORT-grade ciphers use intentionally weakened key sizes (FREAK, Logjam).",
    severity: "critical",
    check: (_, ciphers) => !(ciphers || []).some((c) => /EXPORT/i.test(c)),
  },
  {
    name: "Forward Secrecy",
    description: "ECDHE or DHE key exchange provides forward secrecy for session keys.",
    severity: "high",
    check: (_, ciphers) => (ciphers || []).some((c) => /ECDHE|DHE/i.test(c)),
  },
  {
    name: "Certificate expiry",
    description: "Certificates must not be expired; check notAfter date.",
    severity: "critical",
    check: (_, __, cert) => {
      if (!cert || !cert.notAfter) return false;
      return new Date(cert.notAfter) > new Date();
    },
  },
  {
    name: "Certificate self-signed",
    description: "Self-signed certificates are not trusted by browsers.",
    severity: "high",
    check: (_, __, cert) => {
      if (!cert) return false;
      return cert.issuer !== cert.subject;
    },
  },
  {
    name: "Key size (RSA >= 2048)",
    description: "RSA keys shorter than 2048 bits are considered weak.",
    severity: "high",
    check: (_, __, cert) => {
      if (!cert || !cert.keySize) return true;
      if (cert.keyType === "RSA") return cert.keySize >= 2048;
      if (cert.keyType === "EC") return cert.keySize >= 256;
      return true;
    },
  },
  {
    name: "SHA-1 signature",
    description: "SHA-1 signed certificates are deprecated and rejected by modern browsers.",
    severity: "high",
    check: (_, __, cert) => {
      if (!cert || !cert.signatureAlgorithm) return true;
      return !/sha1|sha-1/i.test(cert.signatureAlgorithm);
    },
  },
  {
    name: "OCSP Stapling",
    description: "OCSP stapling improves performance and privacy of certificate revocation checks.",
    severity: "medium",
    check: (_, __, cert) => {
      if (!cert) return false;
      return !!cert.ocspStapling;
    },
  },
  {
    name: "Certificate Transparency SCTs",
    description: "Signed Certificate Timestamps prove the cert was logged in public CT logs.",
    severity: "medium",
    check: (_, __, cert) => {
      if (!cert) return false;
      return !!cert.scts || !!cert.certificateTransparency;
    },
  },
  {
    name: "Weak DH parameters",
    description: "Diffie-Hellman parameters below 2048 bits are vulnerable to Logjam.",
    severity: "high",
    check: (_, ciphers, __, dhParams) => {
      if (!dhParams || !dhParams.size) return true;
      return dhParams.size >= 2048;
    },
  },
];

// ---------------------------------------------------------------------------
// 4. DNS_SECURITY -- DNS record types relevant to security
// ---------------------------------------------------------------------------
const DNS_SECURITY = [
  {
    record: "SPF (TXT)",
    description: "Sender Policy Framework specifies which mail servers are authorized to send email for the domain.",
    check: (records) => {
      const spf = (records || []).find((r) => /^v=spf1/i.test(r));
      if (!spf) return { pass: false, reason: "No SPF record found" };
      const issues = [];
      if (spf.includes("+all")) issues.push("'+all' allows any server to send -- should be '-all' or '~all'");
      if (spf.includes("?all")) issues.push("'?all' is neutral -- no enforcement");
      if ((spf.match(/include:/g) || []).length > 10) issues.push("More than 10 DNS lookups risk exceeding SPF limit");
      return { pass: issues.length === 0, reason: issues.length ? issues.join("; ") : "SPF record present and properly configured", value: spf };
    },
  },
  {
    record: "DKIM (TXT)",
    description: "DomainKeys Identified Mail provides cryptographic authentication of email messages.",
    check: (records, selector) => {
      const dkim = (records || []).find((r) => /v=DKIM1/i.test(r));
      if (!dkim) return { pass: false, reason: `No DKIM record found${selector ? ` for selector '${selector}'` : ""}` };
      const issues = [];
      if (/k=rsa/i.test(dkim)) {
        const pMatch = dkim.match(/p=([A-Za-z0-9+/=]+)/);
        if (pMatch && pMatch[1].length < 300) issues.push("RSA key appears to be shorter than 2048 bits");
      }
      return { pass: issues.length === 0, reason: issues.length ? issues.join("; ") : "DKIM record present", value: dkim };
    },
  },
  {
    record: "DMARC (TXT)",
    description: "Domain-based Message Authentication, Reporting and Conformance coordinates SPF and DKIM enforcement.",
    check: (records) => {
      const dmarc = (records || []).find((r) => /^v=DMARC1/i.test(r));
      if (!dmarc) return { pass: false, reason: "No DMARC record found at _dmarc subdomain" };
      const issues = [];
      if (/p=none/i.test(dmarc)) issues.push("Policy is 'none' -- no enforcement, monitor only");
      if (!/rua=/i.test(dmarc)) issues.push("No aggregate report URI (rua) specified");
      if (!/ruf=/i.test(dmarc)) issues.push("No forensic report URI (ruf) specified");
      const pctMatch = dmarc.match(/pct=(\d+)/i);
      if (pctMatch && parseInt(pctMatch[1], 10) < 100) issues.push(`Only ${pctMatch[1]}% of messages subject to policy`);
      return { pass: issues.length === 0, reason: issues.length ? issues.join("; ") : "DMARC record properly configured", value: dmarc };
    },
  },
  {
    record: "MTA-STS (TXT)",
    description: "Mail Transfer Agent Strict Transport Security enforces TLS for inbound SMTP.",
    check: (records) => {
      const sts = (records || []).find((r) => /^v=STSv1/i.test(r));
      if (!sts) return { pass: false, reason: "No MTA-STS record found at _mta-sts subdomain" };
      return { pass: true, reason: "MTA-STS record present", value: sts };
    },
  },
  {
    record: "TLSRPT (TXT)",
    description: "TLS Reporting enables receiving reports about SMTP TLS failures.",
    check: (records) => {
      const rpt = (records || []).find((r) => /^v=TLSRPTv1/i.test(r));
      if (!rpt) return { pass: false, reason: "No TLSRPT record found at _smtp._tls subdomain" };
      return { pass: /rua=/i.test(rpt), reason: /rua=/i.test(rpt) ? "TLSRPT with reporting URI" : "TLSRPT present but no rua", value: rpt };
    },
  },
  {
    record: "CAA",
    description: "Certificate Authority Authorization restricts which CAs can issue certificates for the domain.",
    check: (records) => {
      if (!records || records.length === 0) return { pass: false, reason: "No CAA records -- any CA can issue certificates" };
      const hasIssue = records.some((r) => /issue\s/i.test(r));
      const hasWild = records.some((r) => /issuewild/i.test(r));
      const hasIodef = records.some((r) => /iodef/i.test(r));
      const issues = [];
      if (!hasIssue) issues.push("No 'issue' tag restricting certificate issuance");
      if (!hasWild) issues.push("No 'issuewild' tag restricting wildcard certificates");
      if (!hasIodef) issues.push("No 'iodef' tag for violation reporting");
      return { pass: hasIssue, reason: issues.length ? issues.join("; ") : "CAA records properly restrict certificate issuance" };
    },
  },
  {
    record: "DNSSEC",
    description: "DNS Security Extensions provide cryptographic authentication of DNS responses.",
    check: (records) => {
      const hasDnskey = (records || []).some((r) => /DNSKEY/i.test(r));
      const hasDs = (records || []).some((r) => /DS\s/i.test(r));
      if (!hasDnskey && !hasDs) return { pass: false, reason: "No DNSSEC records found -- DNS responses are unauthenticated" };
      return { pass: true, reason: "DNSSEC appears to be configured" };
    },
  },
  {
    record: "DANE / TLSA",
    description: "DNS-based Authentication of Named Entities pins TLS certificates in DNS.",
    check: (records) => {
      const tlsa = (records || []).find((r) => /TLSA/i.test(r));
      if (!tlsa) return { pass: false, reason: "No TLSA record found -- DANE not configured" };
      return { pass: true, reason: "DANE/TLSA record present for certificate pinning", value: tlsa };
    },
  },
  {
    record: "BIMI (TXT)",
    description: "Brand Indicators for Message Identification displays a brand logo in email clients.",
    check: (records) => {
      const bimi = (records || []).find((r) => /^v=BIMI1/i.test(r));
      if (!bimi) return { pass: false, reason: "No BIMI record found at default._bimi subdomain" };
      const hasLogo = /l=/i.test(bimi);
      return { pass: hasLogo, reason: hasLogo ? "BIMI record with logo URL" : "BIMI record present but no logo URL", value: bimi };
    },
  },
  {
    record: "SRV / service discovery",
    description: "SRV records expose internal service topology when over-shared.",
    check: (records) => {
      const internal = (records || []).filter((r) => /internal|staging|dev|test|local/i.test(r));
      if (internal.length > 0) return { pass: false, reason: `SRV records expose internal hostnames: ${internal.join(", ")}` };
      return { pass: true, reason: "No internal service names leaked in SRV records" };
    },
  },
  {
    record: "Zone Transfer (AXFR)",
    description: "Zone transfer should be restricted to authorized secondary nameservers only.",
    check: (result) => {
      if (!result) return { pass: true, reason: "Zone transfer test not performed" };
      return { pass: !result.allowed, reason: result.allowed ? "AXFR zone transfer is allowed -- entire zone can be enumerated" : "Zone transfer properly restricted" };
    },
  },
];

// ---------------------------------------------------------------------------
// 5. CORS_CHECKS -- cross-origin resource sharing audit scenarios
// ---------------------------------------------------------------------------
const CORS_CHECKS = [
  {
    scenario: "Wildcard Origin",
    description: "Access-Control-Allow-Origin set to '*' allows any site to read responses.",
    risk: "high",
    test: (acao) => {
      return { vulnerable: acao === "*", detail: acao === "*" ? "Wildcard origin permits any cross-origin read" : "Origin is not wildcard" };
    },
  },
  {
    scenario: "Origin Reflection",
    description: "Server reflects the request Origin header back as the allowed origin.",
    risk: "critical",
    test: (acao, requestOrigin) => {
      const reflected = acao === requestOrigin && requestOrigin !== undefined;
      return { vulnerable: reflected, detail: reflected ? `Origin '${requestOrigin}' reflected without validation` : "Origin not reflected" };
    },
  },
  {
    scenario: "Null Origin Allowed",
    description: "Server allows the 'null' origin, which can be triggered from sandboxed iframes.",
    risk: "high",
    test: (acao) => {
      return { vulnerable: acao === "null", detail: acao === "null" ? "null origin is allowed -- sandboxed iframe bypass" : "null origin not allowed" };
    },
  },
  {
    scenario: "Credentials with Wildcard",
    description: "Access-Control-Allow-Credentials with wildcard origin is rejected by browsers but indicates misconfiguration.",
    risk: "medium",
    test: (acao, _, acac) => {
      const bad = acao === "*" && acac === "true";
      return { vulnerable: bad, detail: bad ? "Credentials + wildcard is invalid but shows config weakness" : "No credentials+wildcard combo" };
    },
  },
  {
    scenario: "Credentials with Reflected Origin",
    description: "Credentials exposed with a reflected origin allows full cross-origin session access.",
    risk: "critical",
    test: (acao, requestOrigin, acac) => {
      const bad = acao === requestOrigin && acac === "true" && requestOrigin !== undefined;
      return { vulnerable: bad, detail: bad ? "Critical: reflected origin with credentials -- full session hijack possible" : "Not vulnerable" };
    },
  },
  {
    scenario: "Subdomain Wildcard",
    description: "Origin validation allows any subdomain (e.g., *.example.com) including compromised ones.",
    risk: "medium",
    test: (acao, requestOrigin) => {
      if (!acao || !requestOrigin) return { vulnerable: false, detail: "Not testable" };
      const acaoDomain = acao.replace(/^https?:\/\//, "").replace(/:\d+$/, "");
      const reqDomain = requestOrigin.replace(/^https?:\/\//, "").replace(/:\d+$/, "");
      const acoBase = acaoDomain.split(".").slice(-2).join(".");
      const reqBase = reqDomain.split(".").slice(-2).join(".");
      const vulnerable = acoBase === reqBase && acaoDomain !== reqDomain;
      return { vulnerable, detail: vulnerable ? "Subdomain allowed -- compromised subdomain can exfiltrate data" : "Same domain or unrelated" };
    },
  },
  {
    scenario: "Pre-flight Cache Duration",
    description: "Access-Control-Max-Age controls how long preflight results are cached.",
    risk: "low",
    test: (_, __, ___, maxAge) => {
      if (!maxAge) return { vulnerable: false, detail: "No max-age set; browser defaults apply" };
      const age = parseInt(maxAge, 10);
      if (age > 86400) return { vulnerable: true, detail: `Max-age ${age}s exceeds 24h -- stale preflight policies` };
      return { vulnerable: false, detail: `Max-age ${age}s is reasonable` };
    },
  },
  {
    scenario: "Exposed Headers",
    description: "Access-Control-Expose-Headers may leak sensitive custom headers to cross-origin scripts.",
    risk: "medium",
    test: (_, __, ___, ____, exposeHeaders) => {
      if (!exposeHeaders) return { vulnerable: false, detail: "No extra headers exposed" };
      const sensitive = ["authorization", "x-api-key", "x-csrf-token", "set-cookie"];
      const exposed = exposeHeaders.split(",").map((h) => h.trim().toLowerCase());
      const leaked = exposed.filter((h) => sensitive.includes(h));
      return { vulnerable: leaked.length > 0, detail: leaked.length ? `Sensitive headers exposed: ${leaked.join(", ")}` : "No sensitive headers in expose list" };
    },
  },
  {
    scenario: "Allowed Methods",
    description: "Access-Control-Allow-Methods may permit dangerous HTTP methods cross-origin.",
    risk: "medium",
    test: (_, __, ___, ____, _____, allowMethods) => {
      if (!allowMethods) return { vulnerable: false, detail: "No extra methods advertised" };
      const dangerous = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"];
      const methods = allowMethods.split(",").map((m) => m.trim().toUpperCase());
      const found = methods.filter((m) => dangerous.includes(m));
      return { vulnerable: found.length > 0, detail: found.length ? `Dangerous methods allowed: ${found.join(", ")}` : "Only safe methods allowed" };
    },
  },
  {
    scenario: "Vary Origin Header",
    description: "Server should include 'Vary: Origin' to prevent cache poisoning of CORS responses.",
    risk: "medium",
    test: (acao, _, __, ___, ____, _____, vary) => {
      if (!acao || acao === "*") return { vulnerable: false, detail: "Not applicable for missing/wildcard CORS" };
      const hasVary = vary && /origin/i.test(vary);
      return { vulnerable: !hasVary, detail: hasVary ? "Vary: Origin header present" : "Missing 'Vary: Origin' -- responses may be cached incorrectly" };
    },
  },
  {
    scenario: "HTTP vs HTTPS Origin",
    description: "Allowing HTTP origins for an HTTPS site enables MITM to exploit CORS.",
    risk: "high",
    test: (acao) => {
      if (!acao) return { vulnerable: false, detail: "No CORS origin" };
      return { vulnerable: /^http:\/\//i.test(acao), detail: /^http:\/\//i.test(acao) ? "HTTP origin allowed on HTTPS resource" : "Origin uses HTTPS" };
    },
  },
  {
    scenario: "Internal Origin Exposure",
    description: "CORS allows an internal/private origin that should not be referenced publicly.",
    risk: "high",
    test: (acao) => {
      if (!acao) return { vulnerable: false, detail: "No CORS origin" };
      const internal = /\.(internal|local|corp|intranet|private|staging|dev)\b/i.test(acao) || /^https?:\/\/(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/i.test(acao) || /^https?:\/\/localhost/i.test(acao);
      return { vulnerable: internal, detail: internal ? `Internal origin exposed: ${acao}` : "No internal origins" };
    },
  },
];

// ---------------------------------------------------------------------------
// 6. CSP_DIRECTIVES -- Content Security Policy directives reference
// ---------------------------------------------------------------------------
const CSP_DIRECTIVES = [
  {
    directive: "default-src",
    recommended: "'self'",
    description: "Fallback for all fetch directives that are not explicitly set.",
    risk: "Without default-src, unspecified resource types fall back to allowing everything.",
  },
  {
    directive: "script-src",
    recommended: "'self'",
    description: "Controls which scripts can execute. The most critical CSP directive.",
    risk: "Allowing 'unsafe-inline' or 'unsafe-eval' defeats the purpose of CSP against XSS.",
  },
  {
    directive: "script-src-elem",
    recommended: "'self'",
    description: "Controls script elements specifically (separate from inline event handlers).",
    risk: "Allows fine-grained control over <script> tags vs. event handler attributes.",
  },
  {
    directive: "script-src-attr",
    recommended: "'none'",
    description: "Controls inline event handlers (onclick, onload, etc.).",
    risk: "Inline event handlers are a common XSS vector; block them when possible.",
  },
  {
    directive: "style-src",
    recommended: "'self'",
    description: "Controls which stylesheets can be applied.",
    risk: "Injected styles can exfiltrate data via CSS selectors and background-image URLs.",
  },
  {
    directive: "style-src-elem",
    recommended: "'self'",
    description: "Controls <style> and <link rel=stylesheet> elements specifically.",
    risk: "Fine-grained style control separate from inline style attributes.",
  },
  {
    directive: "style-src-attr",
    recommended: "'unsafe-inline'",
    description: "Controls inline style attributes. Often must allow unsafe-inline for frameworks.",
    risk: "Inline styles are lower risk than inline scripts but can still exfiltrate data.",
  },
  {
    directive: "img-src",
    recommended: "'self' data:",
    description: "Controls which images can be loaded.",
    risk: "Image loads can be used for tracking pixels and data exfiltration via URL parameters.",
  },
  {
    directive: "font-src",
    recommended: "'self'",
    description: "Controls which fonts can be loaded.",
    risk: "Malicious fonts have historically exploited font parsing vulnerabilities.",
  },
  {
    directive: "connect-src",
    recommended: "'self'",
    description: "Controls origins for fetch, XMLHttpRequest, WebSocket, and EventSource.",
    risk: "Overly permissive connect-src allows data exfiltration to attacker-controlled servers.",
  },
  {
    directive: "media-src",
    recommended: "'self'",
    description: "Controls which audio and video sources can be loaded.",
    risk: "Media elements can be used for tracking and may have codec vulnerabilities.",
  },
  {
    directive: "object-src",
    recommended: "'none'",
    description: "Controls <object>, <embed>, and <applet> elements. Should be 'none' for modern sites.",
    risk: "Plugin content (Flash, Java) is a classic exploitation vector.",
  },
  {
    directive: "frame-src",
    recommended: "'self'",
    description: "Controls which origins can be embedded in iframes.",
    risk: "Untrusted framed content can phish users or exploit browser vulnerabilities.",
  },
  {
    directive: "frame-ancestors",
    recommended: "'none'",
    description: "Controls which origins can embed this page in a frame. Replaces X-Frame-Options.",
    risk: "Without frame-ancestors, the page can be clickjacked via malicious iframes.",
  },
  {
    directive: "child-src",
    recommended: "'self'",
    description: "Controls workers and embedded frame content (fallback for worker-src and frame-src).",
    risk: "Workers can perform background operations; untrusted workers are a persistence vector.",
  },
  {
    directive: "worker-src",
    recommended: "'self'",
    description: "Controls which scripts can be instantiated as workers (Web, Shared, Service).",
    risk: "Service workers can intercept all traffic; compromised workers persist across sessions.",
  },
  {
    directive: "manifest-src",
    recommended: "'self'",
    description: "Controls which manifests can be applied to the page.",
    risk: "Malicious manifests can redirect app start URLs and modify display properties.",
  },
  {
    directive: "base-uri",
    recommended: "'self'",
    description: "Restricts the URLs that can be used in a <base> element.",
    risk: "An injected <base> tag redirects all relative URLs to an attacker-controlled origin.",
  },
  {
    directive: "form-action",
    recommended: "'self'",
    description: "Restricts which URLs can be used as the action of <form> elements.",
    risk: "Without form-action, injected forms can submit credentials to attacker servers.",
  },
  {
    directive: "navigate-to",
    recommended: "'self'",
    description: "Restricts URLs that the document can navigate to (experimental).",
    risk: "Unrestricted navigation allows open redirect exploitation via injected links.",
  },
  {
    directive: "sandbox",
    recommended: "(context-dependent)",
    description: "Applies sandbox restrictions similar to the iframe sandbox attribute.",
    risk: "Sandbox limits capabilities but breaks features -- use only when isolation is needed.",
  },
  {
    directive: "report-uri",
    recommended: "/csp-report",
    description: "Deprecated endpoint for CSP violation reports (use report-to instead).",
    risk: "Without reporting, CSP violations go undetected and policy gaps remain hidden.",
  },
  {
    directive: "report-to",
    recommended: "csp-endpoint",
    description: "Modern reporting group name for CSP violations (defined via Report-To header).",
    risk: "No visibility into policy violations without a reporting mechanism.",
  },
  {
    directive: "require-trusted-types-for",
    recommended: "'script'",
    description: "Requires Trusted Types for DOM XSS sinks like innerHTML, document.write.",
    risk: "DOM XSS is the most common XSS variant; Trusted Types enforces safe API usage.",
  },
  {
    directive: "trusted-types",
    recommended: "default",
    description: "Restricts creation of Trusted Types policies to prevent DOM XSS.",
    risk: "Unlimited Trusted Types policies can be bypassed by creating permissive ones.",
  },
  {
    directive: "upgrade-insecure-requests",
    recommended: "(include when migrating to HTTPS)",
    description: "Instructs the browser to upgrade all HTTP resource URLs to HTTPS.",
    risk: "Mixed content warnings and blocked resources during HTTP-to-HTTPS migration.",
  },
  {
    directive: "block-all-mixed-content",
    recommended: "(deprecated in favor of upgrade-insecure-requests)",
    description: "Prevents loading any mixed content (HTTP resources on an HTTPS page).",
    risk: "Mixed active content can be used for MITM code injection.",
  },
];

// ---------------------------------------------------------------------------
// 7. SUBRESOURCE_INTEGRITY -- SRI checking utilities
// ---------------------------------------------------------------------------
const SUBRESOURCE_INTEGRITY = {
  algorithms: ["sha256", "sha384", "sha512"],
  description: "Subresource Integrity allows browsers to verify that fetched resources have not been tampered with.",

  // Validate an integrity attribute value
  validateHash: (integrity) => {
    if (!integrity || typeof integrity !== "string") return { valid: false, reason: "No integrity value provided" };
    const parts = integrity.trim().split(/\s+/);
    const results = [];
    for (const part of parts) {
      const match = part.match(/^(sha256|sha384|sha512)-([A-Za-z0-9+/=]+)$/);
      if (!match) {
        results.push({ hash: part, valid: false, reason: "Invalid format: must be algorithm-base64hash" });
        continue;
      }
      const [, algo, hash] = match;
      const expectedLengths = { sha256: 44, sha384: 64, sha512: 88 };
      const validLen = hash.length === expectedLengths[algo];
      results.push({ hash: part, algorithm: algo, valid: validLen, reason: validLen ? "Valid hash" : `Expected ${expectedLengths[algo]} chars for ${algo}, got ${hash.length}` });
    }
    const bestAlgo = parts.some((p) => p.startsWith("sha512")) ? "sha512" : parts.some((p) => p.startsWith("sha384")) ? "sha384" : "sha256";
    return { valid: results.every((r) => r.valid), hashes: results, strongestAlgorithm: bestAlgo, reason: results.every((r) => r.valid) ? "All hashes valid" : "One or more hashes invalid" };
  },

  // Check if a <script> or <link> tag has SRI attributes
  auditTag: (tag) => {
    if (!tag || typeof tag !== "string") return { pass: false, reason: "No tag provided" };
    const issues = [];
    const hasSrc = /\bsrc\s*=\s*["'][^"']+["']/i.test(tag) || /\bhref\s*=\s*["'][^"']+["']/i.test(tag);
    if (!hasSrc) return { pass: true, reason: "Inline resource -- SRI not applicable" };
    const srcMatch = tag.match(/(?:src|href)\s*=\s*["']([^"']+)["']/i);
    const src = srcMatch ? srcMatch[1] : "";
    const isExternal = /^(https?:)?\/\//i.test(src) && !/localhost|127\.0\.0\.1/i.test(src);
    if (!isExternal) return { pass: true, reason: "Same-origin resource -- SRI optional" };
    const integrityMatch = tag.match(/\bintegrity\s*=\s*["']([^"']+)["']/i);
    if (!integrityMatch) {
      issues.push("Missing integrity attribute on external resource");
    } else {
      const validation = SUBRESOURCE_INTEGRITY.validateHash(integrityMatch[1]);
      if (!validation.valid) issues.push(`Invalid integrity hash: ${validation.reason}`);
      if (validation.strongestAlgorithm === "sha256") issues.push("Consider using sha384 or sha512 for stronger protection");
    }
    const crossoriginMatch = tag.match(/\bcrossorigin\s*=\s*["']([^"']+)["']/i);
    if (!crossoriginMatch) {
      issues.push("Missing crossorigin attribute (required for SRI on cross-origin resources)");
    } else if (crossoriginMatch[1] !== "anonymous" && crossoriginMatch[1] !== "use-credentials") {
      issues.push(`Invalid crossorigin value: ${crossoriginMatch[1]}`);
    }
    return { pass: issues.length === 0, issues, src, reason: issues.length ? issues.join("; ") : "SRI properly configured" };
  },

  // Scan HTML for all external scripts and links, report SRI coverage
  scanHTML: (html) => {
    if (!html || typeof html !== "string") return { total: 0, external: 0, withSRI: 0, coverage: 0, findings: [] };
    const tagPattern = /<(?:script|link)[^>]*(?:src|href)\s*=\s*["'][^"']+["'][^>]*>/gi;
    const tags = html.match(tagPattern) || [];
    const findings = [];
    let external = 0, withSRI = 0;
    for (const tag of tags) {
      const audit = SUBRESOURCE_INTEGRITY.auditTag(tag);
      if (audit.reason === "Same-origin resource -- SRI optional" || audit.reason === "Inline resource -- SRI not applicable") continue;
      external++;
      if (audit.pass) withSRI++;
      findings.push({ tag: tag.substring(0, 120), ...audit });
    }
    return { total: tags.length, external, withSRI, coverage: external > 0 ? Math.round((withSRI / external) * 100) : 100, findings };
  },

  // Generate an integrity attribute value from a known hash
  formatIntegrity: (algorithm, base64Hash) => {
    if (!SUBRESOURCE_INTEGRITY.algorithms.includes(algorithm)) return null;
    return `${algorithm}-${base64Hash}`;
  },
};

// ---------------------------------------------------------------------------
// 8. HTTP_METHODS_CHECK -- dangerous HTTP methods to test
// ---------------------------------------------------------------------------
const HTTP_METHODS_CHECK = [
  {
    method: "TRACE",
    description: "Echoes back the request; enables Cross-Site Tracing (XST) attacks to steal cookies and auth headers.",
    severity: "high",
    shouldBeDisabled: true,
  },
  {
    method: "TRACK",
    description: "Microsoft IIS variant of TRACE with the same XST risks.",
    severity: "high",
    shouldBeDisabled: true,
  },
  {
    method: "PUT",
    description: "Uploads or replaces a resource at the target URI. If unauthenticated, allows file upload.",
    severity: "high",
    shouldBeDisabled: true,
  },
  {
    method: "DELETE",
    description: "Removes the resource at the target URI. Unauthenticated DELETE allows data destruction.",
    severity: "high",
    shouldBeDisabled: true,
  },
  {
    method: "CONNECT",
    description: "Establishes a tunnel through the proxy. Can be abused for port scanning and pivoting.",
    severity: "high",
    shouldBeDisabled: true,
  },
  {
    method: "OPTIONS",
    description: "Reveals supported methods and CORS configuration. Information disclosure risk.",
    severity: "low",
    shouldBeDisabled: false,
  },
  {
    method: "PATCH",
    description: "Applies partial modifications. Should require authentication and authorization.",
    severity: "medium",
    shouldBeDisabled: false,
  },
  {
    method: "PROPFIND",
    description: "WebDAV method that retrieves properties and directory listings from the server.",
    severity: "medium",
    shouldBeDisabled: true,
  },
  {
    method: "PROPPATCH",
    description: "WebDAV method that modifies properties of a resource.",
    severity: "medium",
    shouldBeDisabled: true,
  },
  {
    method: "MKCOL",
    description: "WebDAV method that creates a new collection (directory) on the server.",
    severity: "medium",
    shouldBeDisabled: true,
  },
  {
    method: "COPY",
    description: "WebDAV method that duplicates a resource on the server.",
    severity: "medium",
    shouldBeDisabled: true,
  },
  {
    method: "MOVE",
    description: "WebDAV method that relocates a resource on the server.",
    severity: "medium",
    shouldBeDisabled: true,
  },
  {
    method: "LOCK",
    description: "WebDAV method that locks a resource for exclusive editing.",
    severity: "low",
    shouldBeDisabled: true,
  },
  {
    method: "UNLOCK",
    description: "WebDAV method that releases a lock on a resource.",
    severity: "low",
    shouldBeDisabled: true,
  },
  {
    method: "SEARCH",
    description: "WebDAV search method that may expose directory structure and file metadata.",
    severity: "medium",
    shouldBeDisabled: true,
  },
  {
    method: "REPORT",
    description: "WebDAV reporting method that can reveal server configuration details.",
    severity: "low",
    shouldBeDisabled: true,
  },
];

// ---------------------------------------------------------------------------
// 9. COMMON_MISCONFIGS -- 35 common web server / application misconfigurations
// ---------------------------------------------------------------------------
const COMMON_MISCONFIGS = [
  {
    name: "Directory Listing Enabled",
    description: "Web server displays directory contents when no index file is present.",
    detection: "Request a directory URL without an index file; check for file listing in response.",
    remediation: "Disable directory listing: Apache 'Options -Indexes', Nginx 'autoindex off'.",
    severity: "medium",
  },
  {
    name: "Default Credentials",
    description: "Administrative interfaces using vendor-default usernames and passwords.",
    detection: "Attempt login with common defaults: admin/admin, admin/password, root/root.",
    remediation: "Change all default credentials before deployment; enforce strong password policies.",
    severity: "critical",
  },
  {
    name: "Exposed .git Directory",
    description: "The .git directory is accessible via HTTP, leaking source code and commit history.",
    detection: "Request /.git/HEAD or /.git/config and check for valid git content.",
    remediation: "Block access to .git in web server config; ensure deployment does not include .git.",
    severity: "critical",
  },
  {
    name: "Exposed .env File",
    description: "Environment configuration file containing secrets is publicly accessible.",
    detection: "Request /.env and check for key=value pairs with database credentials or API keys.",
    remediation: "Move .env outside the webroot; block access in server config; use .gitignore.",
    severity: "critical",
  },
  {
    name: "Exposed phpinfo()",
    description: "PHP info page reveals server configuration, modules, and environment variables.",
    detection: "Request /phpinfo.php, /info.php, or /test.php and check for PHP configuration output.",
    remediation: "Remove phpinfo files from production; disable phpinfo() in php.ini.",
    severity: "high",
  },
  {
    name: "Exposed Admin Panel",
    description: "Administrative interface accessible without IP restriction or multi-factor auth.",
    detection: "Check /admin, /administrator, /wp-admin, /wp-login.php, /manage, /dashboard.",
    remediation: "Restrict admin access by IP, add MFA, use non-default admin URLs.",
    severity: "high",
  },
  {
    name: "Backup Files Accessible",
    description: "Backup copies of files (.bak, .old, .swp, ~) are served by the web server.",
    detection: "Append .bak, .old, .orig, .swp, ~ to known file paths and check for content.",
    remediation: "Remove backup files from webroot; configure server to block backup file extensions.",
    severity: "high",
  },
  {
    name: "Server Version Disclosure",
    description: "Server response headers or error pages reveal specific software versions.",
    detection: "Check Server, X-Powered-By, X-AspNet-Version headers; trigger 404/500 error pages.",
    remediation: "Remove version strings: Apache 'ServerTokens Prod', Nginx 'server_tokens off'.",
    severity: "low",
  },
  {
    name: "Verbose Error Messages",
    description: "Application error messages expose stack traces, SQL queries, or internal paths.",
    detection: "Submit malformed input and examine error responses for debug information.",
    remediation: "Implement generic error pages; log details server-side only; disable debug mode.",
    severity: "medium",
  },
  {
    name: "Missing Rate Limiting",
    description: "No rate limiting on authentication endpoints allows brute-force attacks.",
    detection: "Send rapid authentication requests and observe if responses are rate-limited.",
    remediation: "Implement rate limiting, account lockout, CAPTCHA on auth endpoints.",
    severity: "high",
  },
  {
    name: "Open Redirect",
    description: "Application redirects users to arbitrary external URLs based on user input.",
    detection: "Set redirect/url/next/return parameters to an external domain; check Location header.",
    remediation: "Validate redirect targets against an allowlist; reject external URLs.",
    severity: "medium",
  },
  {
    name: "CORS Wildcard with Credentials",
    description: "CORS policy allows any origin with credentials, enabling session hijacking.",
    detection: "Send request with Origin header; check if reflected with Allow-Credentials: true.",
    remediation: "Validate origins against a strict allowlist; never combine wildcard with credentials.",
    severity: "critical",
  },
  {
    name: "Missing CSRF Protection",
    description: "State-changing forms lack anti-CSRF tokens or SameSite cookie protection.",
    detection: "Submit forms without CSRF token from a cross-origin page; check if accepted.",
    remediation: "Implement CSRF tokens (synchronizer pattern) or use SameSite=Strict cookies.",
    severity: "high",
  },
  {
    name: "Insecure Cookie Configuration",
    description: "Session cookies lack Secure, HttpOnly, or SameSite attributes.",
    detection: "Inspect Set-Cookie headers for missing security flags.",
    remediation: "Add Secure, HttpOnly, SameSite=Strict or Lax to all session cookies.",
    severity: "high",
  },
  {
    name: "HTTP Enabled (No HTTPS Redirect)",
    description: "Application accepts HTTP requests without redirecting to HTTPS.",
    detection: "Request the site over HTTP and check for 301/302 redirect to HTTPS.",
    remediation: "Configure HTTP-to-HTTPS redirect; enable HSTS with includeSubDomains.",
    severity: "high",
  },
  {
    name: "Mixed Content",
    description: "HTTPS page loads resources (scripts, styles, images) over insecure HTTP.",
    detection: "Inspect page source for http:// resource URLs on an https:// page.",
    remediation: "Use protocol-relative URLs or HTTPS for all resources; add upgrade-insecure-requests CSP.",
    severity: "medium",
  },
  {
    name: "Exposed Debug Endpoints",
    description: "Debug or profiling endpoints accessible in production.",
    detection: "Check /debug, /trace, /actuator, /metrics, /health, /__debug__, /api/debug.",
    remediation: "Disable debug endpoints in production; restrict to internal networks only.",
    severity: "high",
  },
  {
    name: "Exposed .htaccess",
    description: "Apache .htaccess file is downloadable, revealing rewrite rules and auth config.",
    detection: "Request /.htaccess directly and check for Apache configuration directives.",
    remediation: "Configure Apache to deny access to .ht* files (default in modern Apache).",
    severity: "medium",
  },
  {
    name: "Exposed web.config",
    description: "IIS web.config file is downloadable, revealing application configuration.",
    detection: "Request /web.config and check for XML configuration content.",
    remediation: "Ensure IIS is configured to deny access to .config files (default behavior).",
    severity: "high",
  },
  {
    name: "Exposed Docker/Compose Files",
    description: "Docker configuration files reveal architecture, secrets, and internal hostnames.",
    detection: "Request /docker-compose.yml, /Dockerfile, /.dockerenv.",
    remediation: "Exclude Docker files from deployment; block access in web server configuration.",
    severity: "high",
  },
  {
    name: "JWT None Algorithm",
    description: "JWT implementation accepts the 'none' algorithm, allowing token forgery.",
    detection: "Modify a JWT to use alg:'none', strip the signature, and test if accepted.",
    remediation: "Explicitly reject the 'none' algorithm; validate algorithm in token verification.",
    severity: "critical",
  },
  {
    name: "JWT Weak Secret",
    description: "HMAC-signed JWTs use a weak, guessable, or default secret key.",
    detection: "Attempt offline brute-force of JWT signature with common secrets and wordlists.",
    remediation: "Use strong random secrets (256+ bits); prefer asymmetric algorithms (RS256, ES256).",
    severity: "critical",
  },
  {
    name: "API Key in URL",
    description: "API keys transmitted as URL query parameters are logged in server logs and browser history.",
    detection: "Inspect URLs for api_key, apikey, key, token, access_token parameters.",
    remediation: "Send API keys in Authorization header or request body; never in URL parameters.",
    severity: "medium",
  },
  {
    name: "Exposed Swagger/OpenAPI",
    description: "API documentation endpoint is publicly accessible without authentication.",
    detection: "Check /swagger, /swagger-ui, /api-docs, /openapi.json, /v2/api-docs.",
    remediation: "Restrict API documentation to authenticated users or internal networks.",
    severity: "medium",
  },
  {
    name: "Exposed Source Maps",
    description: "JavaScript source maps expose original source code including comments and variable names.",
    detection: "Check for .map files referenced in sourceMappingURL comments in JS/CSS files.",
    remediation: "Remove source maps from production builds; block .map file access in server config.",
    severity: "medium",
  },
  {
    name: "Clickjacking Vulnerability",
    description: "Page can be embedded in an iframe by any origin, enabling UI redress attacks.",
    detection: "Check for missing X-Frame-Options and CSP frame-ancestors directives.",
    remediation: "Set X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
    severity: "medium",
  },
  {
    name: "Host Header Injection",
    description: "Application trusts the Host header for URL generation, enabling phishing and cache poisoning.",
    detection: "Send request with modified Host header; check if reflected in response links/redirects.",
    remediation: "Validate Host header against allowed values; use a fixed server name for URL generation.",
    severity: "high",
  },
  {
    name: "SSRF via User Input",
    description: "Application fetches URLs from user input without validation, enabling internal network access.",
    detection: "Submit internal IP addresses or cloud metadata URLs in URL input fields.",
    remediation: "Validate and sanitize URLs; block private IP ranges; use allowlists for allowed domains.",
    severity: "critical",
  },
  {
    name: "Exposed Cloud Metadata",
    description: "Cloud instance metadata endpoint (169.254.169.254) is accessible via SSRF.",
    detection: "Attempt to access http://169.254.169.254/latest/meta-data/ through application.",
    remediation: "Block metadata IP in application; use IMDSv2 (AWS); restrict metadata access.",
    severity: "critical",
  },
  {
    name: "GraphQL Introspection Enabled",
    description: "GraphQL introspection query reveals the entire API schema and types.",
    detection: "Send introspection query { __schema { types { name } } } to GraphQL endpoint.",
    remediation: "Disable introspection in production; use schema-aware authorization.",
    severity: "medium",
  },
  {
    name: "WebSocket Origin Bypass",
    description: "WebSocket endpoint does not validate the Origin header, allowing cross-site hijacking.",
    detection: "Connect to WebSocket from a different origin page; check if handshake succeeds.",
    remediation: "Validate Origin header in WebSocket upgrade handler; require authentication tokens.",
    severity: "high",
  },
  {
    name: "Exposed Kubernetes Dashboard",
    description: "Kubernetes dashboard is publicly accessible without authentication.",
    detection: "Check common paths: /api, /api/v1, /dashboard, port 8001, 10250.",
    remediation: "Restrict dashboard access to internal network; require RBAC authentication.",
    severity: "critical",
  },
  {
    name: "S3 Bucket Misconfiguration",
    description: "AWS S3 bucket allows public listing or has overly permissive ACLs.",
    detection: "Attempt to list bucket contents anonymously; check bucket ACL and policy.",
    remediation: "Enable S3 Block Public Access; review bucket policies and ACLs.",
    severity: "high",
  },
  {
    name: "DNS Rebinding Vulnerability",
    description: "Application does not validate Host header, allowing DNS rebinding attacks to access internal services.",
    detection: "Use a DNS rebinding service that alternates between external and internal IPs.",
    remediation: "Validate Host header; bind services to specific interfaces; use authentication.",
    severity: "high",
  },
  {
    name: "Exposed Prometheus Metrics",
    description: "Prometheus metrics endpoint reveals internal system and application metrics.",
    detection: "Request /metrics and check for Prometheus text format output.",
    remediation: "Restrict /metrics to internal networks; require authentication.",
    severity: "medium",
  },
  {
    name: "Cache Poisoning via Unkeyed Headers",
    description: "CDN or cache includes unkeyed headers in response, allowing cache poisoning.",
    detection: "Add custom headers (X-Forwarded-Host, X-Original-URL) and check if reflected in cached response.",
    remediation: "Review cache key configuration; strip unkeyed headers before caching.",
    severity: "high",
  },
];

// ---------------------------------------------------------------------------
// 10. OWASP_HEADERS_GRADE -- grading function for security headers
// ---------------------------------------------------------------------------

// Weight map: how many points each header contributes when present and correct.
const HEADER_WEIGHTS = {
  "Strict-Transport-Security": 15,
  "Content-Security-Policy": 20,
  "X-Content-Type-Options": 8,
  "X-Frame-Options": 8,
  "Referrer-Policy": 7,
  "Permissions-Policy": 7,
  "Cross-Origin-Opener-Policy": 5,
  "Cross-Origin-Embedder-Policy": 5,
  "Cross-Origin-Resource-Policy": 5,
  "Cache-Control": 5,
  "X-Permitted-Cross-Domain-Policies": 3,
  "X-DNS-Prefetch-Control": 2,
  "Content-Type": 5,
  "Clear-Site-Data": 2,
  // Negative markers: presence is bad
  "Server": -3,
  "X-Powered-By": -3,
};

// Grade letter from raw score (0-100).
function scoreLetter(score) {
  if (score >= 90) return "A+";
  if (score >= 80) return "A";
  if (score >= 70) return "B";
  if (score >= 60) return "C";
  if (score >= 50) return "D";
  if (score >= 35) return "E";
  return "F";
}

// Internal: run all header checks against a response-headers map.
function _evaluateHeaders(headers) {
  const results = [];
  let earned = 0;
  let possible = 0;
  const hmap = {};
  // Normalize header names to lower case for lookup, keep original values
  if (headers) {
    for (const key of Object.keys(headers)) {
      hmap[key.toLowerCase()] = headers[key];
    }
  }

  for (const hdr of SECURITY_HEADERS) {
    const val = hmap[hdr.name.toLowerCase()] || null;
    const result = hdr.check(val);
    const weight = HEADER_WEIGHTS[hdr.name] || 0;
    if (weight > 0) {
      possible += weight;
      if (result.pass) earned += weight;
    } else if (weight < 0 && !result.pass) {
      // For negative markers, failing the check (header present) subtracts points
      earned += weight; // weight is already negative
    }
    results.push({ header: hdr.name, severity: hdr.severity, value: val, ...result, weight });
  }

  // Normalize to 0-100 scale
  const rawScore = possible > 0 ? Math.max(0, Math.min(100, Math.round((earned / possible) * 100))) : 0;
  return { score: rawScore, grade: scoreLetter(rawScore), results, earned, possible };
}

const OWASP_HEADERS_GRADE = {
  weights: HEADER_WEIGHTS,
  scoreLetter,
  evaluate: _evaluateHeaders,
  description: "Grades HTTP security headers on a 0-100 scale (A+ through F) based on OWASP recommendations.",
};

// ---------------------------------------------------------------------------
// 11. Helper functions
// ---------------------------------------------------------------------------

/**
 * gradeHeaders(headers) -- Accept a map of HTTP response headers and return
 * a structured grade with per-header findings.
 * @param {Object} headers - { "Header-Name": "value", ... }
 * @returns {Object} { score, grade, findings[], summary }
 */
function gradeHeaders(headers) {
  if (!headers || typeof headers !== "object") {
    return { score: 0, grade: "F", findings: [], summary: "No headers provided for analysis" };
  }
  const evaluation = OWASP_HEADERS_GRADE.evaluate(headers);
  const missing = evaluation.results.filter((r) => !r.pass && r.weight > 0);
  const present = evaluation.results.filter((r) => r.pass && r.weight > 0);
  const leaks = evaluation.results.filter((r) => !r.pass && r.weight < 0);
  const summary = [
    `Score: ${evaluation.score}/100 (${evaluation.grade})`,
    `${present.length} security headers properly configured`,
    missing.length ? `${missing.length} security headers missing or misconfigured` : null,
    leaks.length ? `${leaks.length} information leakage headers detected` : null,
  ].filter(Boolean).join(". ");

  return {
    score: evaluation.score,
    grade: evaluation.grade,
    findings: evaluation.results.map((r) => ({
      header: r.header,
      severity: r.severity,
      pass: r.pass,
      value: r.value,
      reason: r.reason,
      weight: r.weight,
    })),
    missing: missing.map((r) => r.header),
    leaks: leaks.map((r) => r.header),
    summary,
  };
}

/**
 * checkSSL(info) -- Analyze SSL/TLS configuration data.
 * @param {Object} info - { protocols: [], ciphers: [], cert: {}, dhParams: {} }
 * @returns {Object} { score, grade, findings[], summary }
 */
function checkSSL(info) {
  if (!info || typeof info !== "object") {
    return { score: 0, grade: "F", findings: [], summary: "No SSL information provided" };
  }
  const protocols = info.protocols || [];
  const ciphers = info.ciphers || [];
  const cert = info.cert || null;
  const dhParams = info.dhParams || null;

  const findings = [];
  let totalChecks = 0;
  let passedChecks = 0;

  for (const check of SSL_CHECKS) {
    totalChecks++;
    let pass = false;
    try {
      pass = check.check(protocols, ciphers, cert, dhParams);
    } catch (_) {
      pass = false;
    }
    if (pass) passedChecks++;
    findings.push({
      name: check.name,
      description: check.description,
      severity: check.severity,
      pass,
    });
  }

  const score = totalChecks > 0 ? Math.round((passedChecks / totalChecks) * 100) : 0;
  const criticalFails = findings.filter((f) => !f.pass && f.severity === "critical");
  const highFails = findings.filter((f) => !f.pass && f.severity === "high");

  // Penalize heavily for critical failures
  let adjustedScore = score;
  if (criticalFails.length > 0) adjustedScore = Math.min(adjustedScore, 30);
  if (highFails.length > 2) adjustedScore = Math.min(adjustedScore, 50);

  const hasTLS13 = protocols.includes("TLSv1.3");
  const hasTLS12 = protocols.includes("TLSv1.2");
  const hasLegacy = protocols.some((p) => /SSLv|TLSv1\.[01]/.test(p));

  const summary = [
    `SSL Score: ${adjustedScore}/100 (${scoreLetter(adjustedScore)})`,
    `Protocols: ${protocols.join(", ") || "none detected"}`,
    hasTLS13 ? "TLS 1.3 supported (excellent)" : hasTLS12 ? "TLS 1.2 supported" : "No modern TLS version found",
    hasLegacy ? "WARNING: Legacy protocols detected" : null,
    criticalFails.length ? `${criticalFails.length} critical issues` : null,
    highFails.length ? `${highFails.length} high-severity issues` : null,
    cert ? (cert.notAfter && new Date(cert.notAfter) < new Date() ? "CERTIFICATE EXPIRED" : `Certificate valid until ${cert.notAfter || "unknown"}`) : "No certificate information",
  ].filter(Boolean).join(". ");

  return {
    score: adjustedScore,
    grade: scoreLetter(adjustedScore),
    findings,
    criticalIssues: criticalFails.map((f) => f.name),
    highIssues: highFails.map((f) => f.name),
    protocols: { detected: protocols, hasTLS13, hasTLS12, hasLegacy },
    summary,
  };
}

/**
 * analyzeCORS(responseHeaders, requestOrigin) -- Analyze CORS configuration.
 * @param {Object} responseHeaders - Response headers from a CORS-aware request
 * @param {string} requestOrigin - The Origin header sent in the request
 * @returns {Object} { score, findings[], summary }
 */
function analyzeCORS(responseHeaders, requestOrigin) {
  if (!responseHeaders || typeof responseHeaders !== "object") {
    return { score: 100, findings: [], summary: "No CORS headers present -- same-origin policy enforced" };
  }
  const normalize = (obj) => {
    const out = {};
    for (const k of Object.keys(obj)) out[k.toLowerCase()] = obj[k];
    return out;
  };
  const h = normalize(responseHeaders);

  const acao = h["access-control-allow-origin"] || null;
  const acac = h["access-control-allow-credentials"] || null;
  const maxAge = h["access-control-max-age"] || null;
  const exposeHeaders = h["access-control-expose-headers"] || null;
  const allowMethods = h["access-control-allow-methods"] || null;
  const vary = h["vary"] || null;

  if (!acao) {
    return { score: 100, corsEnabled: false, findings: [], summary: "CORS not enabled -- relying on same-origin policy" };
  }

  const findings = [];
  let vulnerabilities = 0;
  let warnings = 0;

  for (const check of CORS_CHECKS) {
    const result = check.test(acao, requestOrigin, acac, maxAge, exposeHeaders, allowMethods, vary);
    const severity = check.risk;
    if (result.vulnerable) {
      if (severity === "critical" || severity === "high") vulnerabilities++;
      else warnings++;
    }
    findings.push({
      scenario: check.scenario,
      risk: check.risk,
      vulnerable: result.vulnerable,
      detail: result.detail,
    });
  }

  // Score: start at 100, deduct for issues
  let score = 100;
  score -= vulnerabilities * 20;
  score -= warnings * 5;
  score = Math.max(0, Math.min(100, score));

  const vulnFindings = findings.filter((f) => f.vulnerable);
  const summary = [
    `CORS Score: ${score}/100`,
    `Origin: ${acao}`,
    acac === "true" ? "Credentials: EXPOSED" : "Credentials: not exposed",
    vulnFindings.length ? `${vulnFindings.length} CORS issue(s) detected` : "No CORS issues detected",
    vulnFindings.filter((f) => f.risk === "critical").length ? "CRITICAL CORS vulnerability found" : null,
  ].filter(Boolean).join(". ");

  return {
    score,
    grade: scoreLetter(score),
    corsEnabled: true,
    origin: acao,
    credentials: acac === "true",
    findings,
    vulnerabilities: vulnFindings,
    summary,
  };
}

/**
 * validateCSP(policy) -- Parse and validate a Content-Security-Policy string.
 * @param {string} policy - The CSP header value
 * @returns {Object} { score, grade, directives, findings[], summary }
 */
function validateCSP(policy) {
  if (!policy || typeof policy !== "string") {
    return { score: 0, grade: "F", directives: {}, findings: [], summary: "No CSP policy provided" };
  }

  // Parse directives
  const parsed = {};
  const parts = policy.split(";").map((d) => d.trim()).filter(Boolean);
  for (const part of parts) {
    const tokens = part.split(/\s+/);
    const directive = tokens[0].toLowerCase();
    const values = tokens.slice(1);
    parsed[directive] = values;
  }

  const findings = [];
  let totalPoints = 0;
  let earnedPoints = 0;

  // Check each known directive
  for (const def of CSP_DIRECTIVES) {
    const dir = def.directive.toLowerCase();
    const values = parsed[dir];
    totalPoints += 4; // Each directive worth 4 points for being properly configured

    if (!values) {
      // Check if covered by default-src fallback
      const fetchDirectives = [
        "script-src", "style-src", "img-src", "font-src", "connect-src",
        "media-src", "object-src", "frame-src", "child-src", "worker-src",
        "manifest-src", "script-src-elem", "script-src-attr", "style-src-elem", "style-src-attr",
      ];
      const isFetch = fetchDirectives.includes(dir);
      const hasDefault = !!parsed["default-src"];

      if (dir === "default-src") {
        findings.push({ directive: dir, severity: "high", pass: false, reason: "Missing default-src -- no fallback for unspecified directives" });
      } else if (isFetch && hasDefault) {
        earnedPoints += 2; // Partial credit for fallback coverage
        findings.push({ directive: dir, severity: "info", pass: true, reason: `Not specified; falls back to default-src: ${(parsed["default-src"] || []).join(" ")}` });
      } else if (dir === "frame-ancestors" || dir === "base-uri" || dir === "form-action") {
        findings.push({ directive: dir, severity: "medium", pass: false, reason: `Missing ${dir} -- not covered by default-src fallback` });
      } else {
        earnedPoints += 1;
        findings.push({ directive: dir, severity: "low", pass: true, reason: "Not specified (optional directive)" });
      }
      continue;
    }

    // Directive is present -- evaluate its value
    const issues = [];

    // General unsafe checks
    if (values.includes("'unsafe-inline'")) {
      const hasNonce = values.some((v) => /^'nonce-/.test(v));
      const hasHash = values.some((v) => /^'sha(256|384|512)-/.test(v));
      if (!hasNonce && !hasHash) {
        issues.push(`'unsafe-inline' without nonce or hash in ${dir}`);
      }
    }
    if (values.includes("'unsafe-eval'")) {
      issues.push(`'unsafe-eval' in ${dir} allows dynamic code execution`);
    }
    if (values.includes("'unsafe-hashes'")) {
      issues.push(`'unsafe-hashes' in ${dir} -- ensure hashes are explicitly listed`);
    }

    // Wildcard checks
    if (values.includes("*")) {
      issues.push(`Wildcard '*' in ${dir} allows loading from any origin`);
    }

    // data: URI checks (risky in script-src)
    if (values.includes("data:") && (dir === "script-src" || dir === "script-src-elem")) {
      issues.push(`data: URI in ${dir} can be used to inject executable scripts`);
    }

    // blob: URI checks
    if (values.includes("blob:") && (dir === "script-src" || dir === "script-src-elem" || dir === "worker-src")) {
      issues.push(`blob: URI in ${dir} can be used to create executable content`);
    }

    // http: scheme in script sources
    if (values.some((v) => /^http:/i.test(v)) && (dir === "script-src" || dir === "script-src-elem")) {
      issues.push(`HTTP source in ${dir} allows scripts over unencrypted connection`);
    }

    // Overly broad domains
    const broadDomains = values.filter((v) => /^\*\.[a-z]+$/.test(v));
    if (broadDomains.length) {
      issues.push(`Broad domain wildcards in ${dir}: ${broadDomains.join(", ")}`);
    }

    // Known dangerous CDN domains that host user content
    const riskyHosts = ["cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com", "raw.githubusercontent.com", "gist.githubusercontent.com", "pastebin.com"];
    const foundRisky = values.filter((v) => riskyHosts.some((h) => v.includes(h)));
    if (foundRisky.length && (dir === "script-src" || dir === "script-src-elem" || dir === "default-src")) {
      issues.push(`CDN hosts with user-uploadable content in ${dir}: ${foundRisky.join(", ")} -- potential script gadget bypass`);
    }

    if (issues.length === 0) {
      earnedPoints += 4;
      findings.push({ directive: dir, severity: "info", pass: true, values, reason: "Properly configured" });
    } else {
      earnedPoints += 1; // Some credit for at least having the directive
      findings.push({ directive: dir, severity: "medium", pass: false, values, issues, reason: issues.join("; ") });
    }
  }

  // Check for unknown / typo directives
  const knownDirs = new Set(CSP_DIRECTIVES.map((d) => d.directive.toLowerCase()));
  for (const dir of Object.keys(parsed)) {
    if (!knownDirs.has(dir)) {
      findings.push({ directive: dir, severity: "low", pass: false, reason: `Unknown directive '${dir}' -- possible typo` });
    }
  }

  // Specific high-value checks
  const hasDefaultSrc = !!parsed["default-src"];
  const hasScriptSrc = !!parsed["script-src"];
  const hasObjectNone = parsed["object-src"] && parsed["object-src"].includes("'none'");
  const hasBaseUri = !!parsed["base-uri"];
  const hasFormAction = !!parsed["form-action"];
  const hasFrameAncestors = !!parsed["frame-ancestors"];

  // Bonus points for best-practice directives
  if (hasObjectNone) earnedPoints += 5;
  if (hasBaseUri) earnedPoints += 3;
  if (hasFormAction) earnedPoints += 3;
  if (hasFrameAncestors) earnedPoints += 5;
  totalPoints += 16; // bonus pool

  const score = totalPoints > 0 ? Math.max(0, Math.min(100, Math.round((earnedPoints / totalPoints) * 100))) : 0;
  const issueFindings = findings.filter((f) => !f.pass);

  const summary = [
    `CSP Score: ${score}/100 (${scoreLetter(score)})`,
    `${Object.keys(parsed).length} directives defined`,
    hasDefaultSrc ? "default-src present" : "WARNING: no default-src",
    hasScriptSrc ? "script-src present" : (hasDefaultSrc ? "script-src inherits from default-src" : "WARNING: no script-src"),
    hasObjectNone ? "object-src 'none' (good)" : "object-src not restricted to 'none'",
    hasFrameAncestors ? "frame-ancestors present" : "WARNING: no frame-ancestors (clickjacking risk)",
    issueFindings.length ? `${issueFindings.length} issue(s) found` : "No issues detected",
  ].filter(Boolean).join(". ");

  return {
    score,
    grade: scoreLetter(score),
    directives: parsed,
    findings,
    issues: issueFindings,
    bestPractices: {
      hasDefaultSrc,
      hasScriptSrc,
      hasObjectNone: !!hasObjectNone,
      hasBaseUri,
      hasFormAction,
      hasFrameAncestors,
    },
    summary,
  };
}

// ---------------------------------------------------------------------------
// Supplementary: parseCookieString -- parse a Set-Cookie header and audit it
// ---------------------------------------------------------------------------
function parseCookieString(setCookie) {
  if (!setCookie || typeof setCookie !== "string") return null;
  const parts = setCookie.split(";").map((p) => p.trim());
  if (parts.length === 0) return null;

  const [nameVal, ...attrs] = parts;
  const eqIdx = nameVal.indexOf("=");
  if (eqIdx < 0) return null;
  const name = nameVal.substring(0, eqIdx).trim();
  const value = nameVal.substring(eqIdx + 1).trim();

  const flags = {};
  for (const attr of attrs) {
    const lower = attr.toLowerCase();
    if (lower === "secure") flags.secure = true;
    else if (lower === "httponly") flags.httpOnly = true;
    else if (lower.startsWith("samesite=")) flags.sameSite = attr.split("=")[1].trim();
    else if (lower.startsWith("domain=")) flags.domain = attr.split("=")[1].trim();
    else if (lower.startsWith("path=")) flags.path = attr.split("=")[1].trim();
    else if (lower.startsWith("max-age=")) flags.maxAge = parseInt(attr.split("=")[1].trim(), 10);
    else if (lower.startsWith("expires=")) flags.expires = attr.split("=")[1].trim();
    else if (lower === "partitioned") flags.partitioned = true;
  }

  const issues = [];
  if (!flags.secure) issues.push("Missing Secure flag");
  if (!flags.httpOnly) issues.push("Missing HttpOnly flag");
  if (!flags.sameSite) issues.push("Missing SameSite attribute");
  else if (flags.sameSite.toLowerCase() === "none" && !flags.secure) issues.push("SameSite=None requires Secure flag");
  if (name.startsWith("__Secure-") && !flags.secure) issues.push("__Secure- prefix requires Secure flag");
  if (name.startsWith("__Host-")) {
    if (!flags.secure) issues.push("__Host- prefix requires Secure flag");
    if (flags.domain) issues.push("__Host- prefix must not have Domain attribute");
    if (flags.path !== "/") issues.push("__Host- prefix requires Path=/");
  }
  if (flags.maxAge && flags.maxAge > 31536000) issues.push(`Max-Age ${flags.maxAge}s exceeds 1 year`);
  if (flags.domain && flags.domain.startsWith(".")) issues.push(`Broad domain scope: ${flags.domain}`);

  return {
    name,
    value: value.length > 20 ? value.substring(0, 20) + "..." : value,
    flags,
    issues,
    secure: issues.length === 0,
  };
}

// ---------------------------------------------------------------------------
// Supplementary: generateReport -- produce a combined security audit report
// ---------------------------------------------------------------------------
function generateReport(opts) {
  const { headers, ssl, cors, csp, cookies } = opts || {};
  const sections = [];

  if (headers) {
    const headerGrade = gradeHeaders(headers);
    sections.push({ section: "HTTP Security Headers", ...headerGrade });
  }

  if (ssl) {
    const sslGrade = checkSSL(ssl);
    sections.push({ section: "SSL/TLS Configuration", ...sslGrade });
  }

  if (cors) {
    const corsResult = analyzeCORS(cors.responseHeaders, cors.requestOrigin);
    sections.push({ section: "CORS Configuration", ...corsResult });
  }

  if (csp) {
    const cspResult = validateCSP(csp);
    sections.push({ section: "Content Security Policy", ...cspResult });
  }

  if (cookies && Array.isArray(cookies)) {
    const cookieResults = cookies.map(parseCookieString).filter(Boolean);
    const insecure = cookieResults.filter((c) => !c.secure);
    sections.push({
      section: "Cookie Security",
      score: cookieResults.length > 0 ? Math.round(((cookieResults.length - insecure.length) / cookieResults.length) * 100) : 100,
      grade: scoreLetter(cookieResults.length > 0 ? Math.round(((cookieResults.length - insecure.length) / cookieResults.length) * 100) : 100),
      findings: cookieResults,
      summary: `${cookieResults.length} cookies analyzed, ${insecure.length} with issues`,
    });
  }

  // Overall score is average of section scores
  const scores = sections.map((s) => s.score).filter((s) => typeof s === "number");
  const overallScore = scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;

  return {
    overallScore,
    overallGrade: scoreLetter(overallScore),
    sections,
    timestamp: new Date().toISOString(),
    summary: `Overall Security Score: ${overallScore}/100 (${scoreLetter(overallScore)}). ${sections.length} sections analyzed.`,
  };
}

// ---------------------------------------------------------------------------
// Supplementary: common probe paths for misconfiguration detection
// ---------------------------------------------------------------------------
const PROBE_PATHS = {
  gitExposure: ["/.git/HEAD", "/.git/config", "/.git/index", "/.gitignore"],
  envFiles: ["/.env", "/.env.local", "/.env.production", "/.env.staging", "/.env.backup"],
  configFiles: ["/web.config", "/wp-config.php", "/wp-config.php.bak", "/config.php", "/configuration.php", "/settings.py", "/config.yml", "/config.yaml", "/application.yml"],
  adminPanels: ["/admin", "/administrator", "/wp-admin", "/wp-login.php", "/manage", "/dashboard", "/cpanel", "/phpmyadmin", "/adminer", "/webmin"],
  debugEndpoints: ["/debug", "/trace", "/actuator", "/actuator/health", "/actuator/env", "/metrics", "/health", "/__debug__", "/api/debug", "/server-status", "/server-info", "/_profiler"],
  apiDocs: ["/swagger", "/swagger-ui", "/swagger-ui.html", "/api-docs", "/openapi.json", "/v2/api-docs", "/v3/api-docs", "/graphql", "/graphiql", "/playground"],
  backupFiles: ["/backup.zip", "/backup.tar.gz", "/backup.sql", "/dump.sql", "/database.sql", "/db.sql", "/site.zip", "/www.zip"],
  infoDisclosure: ["/phpinfo.php", "/info.php", "/test.php", "/readme.html", "/README.md", "/CHANGELOG.md", "/LICENSE", "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml"],
  cloudMetadata: [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/v1/",
  ],
  cicd: ["/.github/workflows/", "/.gitlab-ci.yml", "/.circleci/config.yml", "/Jenkinsfile", "/.travis.yml", "/azure-pipelines.yml", "/bitbucket-pipelines.yml"],
  docker: ["/docker-compose.yml", "/docker-compose.yaml", "/Dockerfile", "/.dockerenv", "/.docker/config.json"],
  kubernetes: ["/api/v1/namespaces", "/api/v1/pods", "/api/v1/secrets", "/healthz", "/readyz"],
};

// ---------------------------------------------------------------------------
// Supplementary: HTTP response code security implications
// ---------------------------------------------------------------------------
const STATUS_CODE_NOTES = {
  200: { note: "OK -- verify response body is expected content, not an error page masquerading as 200" },
  201: { note: "Created -- ensure resource creation is properly authorized" },
  301: { note: "Permanent redirect -- verify destination is not an open redirect" },
  302: { note: "Temporary redirect -- check for open redirect via Location header manipulation" },
  304: { note: "Not Modified -- cache hit; ensure sensitive responses have proper cache controls" },
  400: { note: "Bad Request -- check that error details do not reveal input validation logic" },
  401: { note: "Unauthorized -- verify consistent timing to prevent user enumeration" },
  403: { note: "Forbidden -- resource exists but access denied; useful for directory enumeration" },
  404: { note: "Not Found -- verify 404 page does not leak server technology or paths" },
  405: { note: "Method Not Allowed -- confirms the endpoint exists; check Allow header for permitted methods" },
  500: { note: "Internal Server Error -- check for stack traces or debug information in response body" },
  502: { note: "Bad Gateway -- may reveal backend architecture and proxy configuration" },
  503: { note: "Service Unavailable -- check for retry-after and ensure no sensitive data in error" },
};

// ---------------------------------------------------------------------------
// Supplementary: WAF detection signatures
// ---------------------------------------------------------------------------
const WAF_SIGNATURES = [
  { name: "Cloudflare", headers: ["cf-ray", "cf-cache-status", "__cfduid"], serverPattern: /cloudflare/i },
  { name: "AWS WAF", headers: ["x-amzn-requestid", "x-amz-cf-id"], serverPattern: /awselb|amazons3/i },
  { name: "Akamai", headers: ["x-akamai-transformed", "akamai-origin-hop"], serverPattern: /akamaighost/i },
  { name: "Imperva / Incapsula", headers: ["x-iinfo", "x-cdn"], serverPattern: /incapsula|imperva/i },
  { name: "Sucuri", headers: ["x-sucuri-id", "x-sucuri-cache"], serverPattern: /sucuri/i },
  { name: "F5 BIG-IP", headers: ["x-cnection", "x-wa-info"], serverPattern: /bigip|f5/i },
  { name: "Barracuda", headers: ["barra_counter_session"], serverPattern: /barracuda/i },
  { name: "ModSecurity", headers: ["x-mod-security"], serverPattern: /mod_security/i },
  { name: "Fastly", headers: ["x-fastly-request-id", "fastly-restarts"], serverPattern: /fastly/i },
  { name: "Varnish", headers: ["x-varnish", "via"], serverPattern: /varnish/i },
  { name: "Azure Front Door", headers: ["x-azure-ref", "x-fd-healthprobe"], serverPattern: /azure/i },
  { name: "Google Cloud Armor", headers: ["x-goog-request-params"], serverPattern: /gfe|google/i },
];

/**
 * detectWAF(headers) -- Attempt to identify a WAF/CDN from response headers.
 * @param {Object} headers - HTTP response headers
 * @returns {Object} { detected: boolean, waf: string|null, confidence: string, indicators: [] }
 */
function detectWAF(headers) {
  if (!headers || typeof headers !== "object") return { detected: false, waf: null, confidence: "none", indicators: [] };
  const hkeys = Object.keys(headers).map((k) => k.toLowerCase());
  const server = (headers["server"] || headers["Server"] || "").toLowerCase();

  for (const sig of WAF_SIGNATURES) {
    const indicators = [];
    for (const hdr of sig.headers) {
      if (hkeys.includes(hdr.toLowerCase())) indicators.push(`Header: ${hdr}`);
    }
    if (sig.serverPattern && sig.serverPattern.test(server)) indicators.push(`Server: ${server}`);
    if (indicators.length > 0) {
      return {
        detected: true,
        waf: sig.name,
        confidence: indicators.length >= 2 ? "high" : "medium",
        indicators,
      };
    }
  }
  return { detected: false, waf: null, confidence: "none", indicators: [] };
}

// ---------------------------------------------------------------------------
// Supplementary: technology fingerprinting from response headers
// ---------------------------------------------------------------------------
const TECH_FINGERPRINTS = [
  { tech: "PHP", indicators: ["x-powered-by:php", "set-cookie:PHPSESSID"], headerPatterns: { "x-powered-by": /php/i } },
  { tech: "ASP.NET", indicators: ["x-aspnet-version", "x-aspnetmvc-version", "set-cookie:ASP.NET_SessionId"], headerPatterns: { "x-powered-by": /asp\.net/i } },
  { tech: "Express.js", indicators: ["x-powered-by:Express"], headerPatterns: { "x-powered-by": /express/i } },
  { tech: "Django", indicators: ["set-cookie:csrftoken", "set-cookie:django"], headerPatterns: { "x-frame-options": /SAMEORIGIN/i } },
  { tech: "Ruby on Rails", indicators: ["x-powered-by:Phusion", "set-cookie:_session_id", "x-runtime"], headerPatterns: { "x-powered-by": /phusion|passenger/i } },
  { tech: "Spring Framework", indicators: ["x-application-context"], headerPatterns: {} },
  { tech: "Apache", indicators: [], headerPatterns: { "server": /^apache/i } },
  { tech: "Nginx", indicators: [], headerPatterns: { "server": /^nginx/i } },
  { tech: "IIS", indicators: ["x-aspnet-version"], headerPatterns: { "server": /microsoft-iis/i } },
  { tech: "LiteSpeed", indicators: [], headerPatterns: { "server": /litespeed/i } },
  { tech: "Caddy", indicators: [], headerPatterns: { "server": /^caddy$/i } },
  { tech: "Envoy", indicators: ["x-envoy-upstream-service-time"], headerPatterns: { "server": /envoy/i } },
];

/**
 * fingerprintTech(headers) -- Identify backend technologies from response headers.
 * @param {Object} headers - HTTP response headers
 * @returns {Object[]} Array of { tech, confidence, evidence[] }
 */
function fingerprintTech(headers) {
  if (!headers || typeof headers !== "object") return [];
  const hmap = {};
  for (const k of Object.keys(headers)) hmap[k.toLowerCase()] = String(headers[k]);

  const results = [];
  for (const fp of TECH_FINGERPRINTS) {
    const evidence = [];

    // Check header patterns
    for (const [hdr, pattern] of Object.entries(fp.headerPatterns)) {
      if (hmap[hdr] && pattern.test(hmap[hdr])) evidence.push(`${hdr}: ${hmap[hdr]}`);
    }

    // Check indicator strings
    for (const indicator of fp.indicators) {
      const [hdr, val] = indicator.split(":");
      if (hmap[hdr.toLowerCase()] && (!val || hmap[hdr.toLowerCase()].toLowerCase().includes(val.toLowerCase()))) {
        evidence.push(`${hdr}: ${hmap[hdr.toLowerCase()]}`);
      }
    }

    if (evidence.length > 0) {
      results.push({ tech: fp.tech, confidence: evidence.length >= 2 ? "high" : "medium", evidence });
    }
  }
  return results;
}

// ---------------------------------------------------------------------------
// Supplementary: security-relevant regex patterns for response body scanning
// ---------------------------------------------------------------------------
const BODY_PATTERNS = {
  emailAddresses: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  ipAddresses: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
  privateIPs: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g,
  awsKeys: /(?:AKIA|ASIA)[A-Z0-9]{16}/g,
  jwtTokens: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
  sqlErrors: /(?:sql syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|Microsoft SQL.*Driver|SQLite3::|SQLSTATE\[)/gi,
  stackTraces: /(?:at\s+[\w.$]+\([\w./:]+:\d+:\d+\)|Traceback \(most recent call last\)|Exception in thread|java\.\w+\.[\w.]+Exception|System\.(?:Null)?(?:Reference)?Exception)/g,
  absolutePaths: /(?:[A-Z]:\\[\w\\.-]+|\/(?:home|var|etc|usr|opt|srv|tmp)\/[\w/.-]+)/g,
  htmlComments: /<!--[\s\S]*?-->/g,
  phpErrors: /(?:Fatal error|Warning|Notice|Parse error):\s+.*?\s+in\s+\/[\w/.-]+\s+on\s+line\s+\d+/g,
  cryptoKeys: /-----BEGIN (?:RSA |DSA |EC |OPENSSH )?(?:PRIVATE|PUBLIC) KEY-----/g,
  apiKeys: /(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['"]?[A-Za-z0-9_-]{20,}['"]?/gi,
  sourceMapRefs: /\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)/g,
  debugFlags: /(?:debug\s*[:=]\s*(?:true|1|on)|DEBUG_MODE|DEVELOPMENT_MODE|console\.\w+\()/gi,
  versionStrings: /(?:version|ver|v)[\s:=]*['"]?\d+\.\d+(?:\.\d+)?['"]?/gi,
};

/**
 * scanResponseBody(body) -- Scan an HTTP response body for sensitive patterns.
 * @param {string} body - Response body text
 * @returns {Object} { findings[], riskLevel, summary }
 */
function scanResponseBody(body) {
  if (!body || typeof body !== "string") return { findings: [], riskLevel: "none", summary: "No body to scan" };
  const findings = [];

  const checks = [
    { name: "Email Addresses", pattern: BODY_PATTERNS.emailAddresses, severity: "low", max: 10 },
    { name: "Private IP Addresses", pattern: BODY_PATTERNS.privateIPs, severity: "medium", max: 10 },
    { name: "AWS Access Keys", pattern: BODY_PATTERNS.awsKeys, severity: "critical", max: 5 },
    { name: "JWT Tokens", pattern: BODY_PATTERNS.jwtTokens, severity: "high", max: 5 },
    { name: "SQL Error Messages", pattern: BODY_PATTERNS.sqlErrors, severity: "high", max: 5 },
    { name: "Stack Traces", pattern: BODY_PATTERNS.stackTraces, severity: "high", max: 5 },
    { name: "Absolute File Paths", pattern: BODY_PATTERNS.absolutePaths, severity: "medium", max: 10 },
    { name: "PHP Errors", pattern: BODY_PATTERNS.phpErrors, severity: "high", max: 5 },
    { name: "Cryptographic Keys", pattern: BODY_PATTERNS.cryptoKeys, severity: "critical", max: 3 },
    { name: "API Keys / Tokens", pattern: BODY_PATTERNS.apiKeys, severity: "critical", max: 5 },
    { name: "Source Map References", pattern: BODY_PATTERNS.sourceMapRefs, severity: "medium", max: 10 },
    { name: "Debug Indicators", pattern: BODY_PATTERNS.debugFlags, severity: "medium", max: 10 },
  ];

  let maxSeverity = "none";
  const severityOrder = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };

  for (const check of checks) {
    const matches = body.match(check.pattern);
    if (matches && matches.length > 0) {
      const unique = [...new Set(matches)].slice(0, check.max);
      findings.push({
        name: check.name,
        severity: check.severity,
        count: matches.length,
        samples: unique.map((m) => m.length > 80 ? m.substring(0, 80) + "..." : m),
      });
      if (severityOrder[check.severity] > severityOrder[maxSeverity]) {
        maxSeverity = check.severity;
      }
    }
  }

  return {
    findings,
    riskLevel: maxSeverity,
    summary: findings.length ? `${findings.length} pattern types found, highest severity: ${maxSeverity}` : "No sensitive patterns detected",
  };
}

// ---------------------------------------------------------------------------
// Supplementary: URL analysis utilities
// ---------------------------------------------------------------------------

/**
 * analyzeURL(url) -- Break down a URL and identify security concerns.
 * @param {string} url
 * @returns {Object}
 */
function analyzeURL(url) {
  if (!url || typeof url !== "string") return { valid: false, reason: "No URL provided" };
  let parsed;
  try {
    parsed = new URL(url);
  } catch (_) {
    return { valid: false, reason: "Malformed URL" };
  }

  const issues = [];
  if (parsed.protocol === "http:") issues.push("Uses HTTP instead of HTTPS -- traffic is unencrypted");
  if (parsed.username || parsed.password) issues.push("Contains embedded credentials in URL");
  if (parsed.port && !["80", "443", ""].includes(parsed.port)) issues.push(`Non-standard port: ${parsed.port}`);

  // Check for suspicious parameters
  const sensitiveParams = ["password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "access_token", "auth", "session", "ssn", "credit_card", "cc"];
  const paramKeys = [...parsed.searchParams.keys()].map((k) => k.toLowerCase());
  const foundSensitive = paramKeys.filter((k) => sensitiveParams.some((s) => k.includes(s)));
  if (foundSensitive.length) issues.push(`Sensitive data in URL parameters: ${foundSensitive.join(", ")}`);

  // Check for path traversal indicators
  if (/\.\.[\\/]/.test(parsed.pathname)) issues.push("Path traversal sequences detected");
  if (/%2e%2e/i.test(url) || /%252e/i.test(url)) issues.push("Encoded path traversal detected");

  // Check for open redirect patterns
  const redirectParams = ["url", "redirect", "next", "return", "returnto", "goto", "destination", "redir", "redirect_uri", "continue"];
  for (const param of redirectParams) {
    const val = parsed.searchParams.get(param);
    if (val && /^https?:\/\//i.test(val)) issues.push(`Potential open redirect via '${param}' parameter`);
  }

  return {
    valid: true,
    protocol: parsed.protocol,
    hostname: parsed.hostname,
    port: parsed.port || (parsed.protocol === "https:" ? "443" : "80"),
    pathname: parsed.pathname,
    search: parsed.search,
    hash: parsed.hash,
    hasCredentials: !!(parsed.username || parsed.password),
    isHTTPS: parsed.protocol === "https:",
    issues,
    secure: issues.length === 0,
  };
}

// ---------------------------------------------------------------------------
// Supplementary: Content-Security-Policy-Report-Only analyzer
// ---------------------------------------------------------------------------
function analyzeCSPReport(report) {
  if (!report || typeof report !== "object") return null;
  const r = report["csp-report"] || report;
  return {
    documentURI: r["document-uri"] || r.documentURL || "",
    violatedDirective: r["violated-directive"] || r.effectiveDirective || "",
    blockedURI: r["blocked-uri"] || r.blockedURL || "",
    sourceFile: r["source-file"] || r.sourceFile || "",
    lineNumber: r["line-number"] || r.lineNumber || 0,
    columnNumber: r["column-number"] || r.columnNumber || 0,
    originalPolicy: r["original-policy"] || r.originalPolicy || "",
    disposition: r.disposition || "enforce",
    statusCode: r["status-code"] || r.statusCode || 0,
    summary: `CSP ${r.disposition || "violation"}: ${r["violated-directive"] || r.effectiveDirective || "unknown"} blocked ${r["blocked-uri"] || r.blockedURL || "unknown resource"}`,
  };
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------
module.exports = {
  // Data sets
  SECURITY_HEADERS,
  COOKIE_FLAGS,
  SSL_CHECKS,
  DNS_SECURITY,
  CORS_CHECKS,
  CSP_DIRECTIVES,
  SUBRESOURCE_INTEGRITY,
  HTTP_METHODS_CHECK,
  COMMON_MISCONFIGS,
  OWASP_HEADERS_GRADE,

  // Primary helper functions
  gradeHeaders,
  checkSSL,
  analyzeCORS,
  validateCSP,

  // Supplementary utilities
  parseCookieString,
  generateReport,
  detectWAF,
  fingerprintTech,
  scanResponseBody,
  analyzeURL,
  analyzeCSPReport,
  scoreLetter,

  // Reference data
  PROBE_PATHS,
  STATUS_CODE_NOTES,
  WAF_SIGNATURES,
  TECH_FINGERPRINTS,
  BODY_PATTERNS,
  HEADER_WEIGHTS,
};
