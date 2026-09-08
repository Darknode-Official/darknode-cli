"use strict";
// STRIDE threat modeling engine — Darknode Nexus.
//
// Provides a self-contained, dependency-free threat modeling toolkit built
// around Microsoft's STRIDE taxonomy (Spoofing, Tampering, Repudiation,
// Information Disclosure, Denial of Service, Elevation of Privilege).
//
// WHAT THIS MODULE DOES:
//   - Ships a curated library of 100+ pre-defined threats, each tagged with
//     a STRIDE category, severity/likelihood/impact, affected component
//     types, and concrete mitigations.
//   - Given a described architecture (components + data flows + trust
//     boundaries), matches applicable threats from the library and scores
//     them.
//   - Produces a full threat model: threats grouped by STRIDE category, a
//     risk matrix, and summary statistics.
//   - Renders the resulting model as a readable Markdown report, including
//     an ASCII risk heat map and a prioritized mitigation backlog.
//
// WHAT THIS MODULE DOES NOT DO:
//   - It does not perform live scanning, network probing, or code analysis.
//     It is a reasoning/reporting layer over a structured description of a
//     system's architecture, meant to accelerate manual threat modeling
//     sessions (e.g. STRIDE workshops, design reviews, PR risk triage).
//
// Only Node.js built-ins are used (crypto for deterministic threat IDs).

const crypto = require("crypto");

// ---------------------------------------------------------------------------
// STRIDE_CATEGORIES
// ---------------------------------------------------------------------------
// Canonical description of each STRIDE category: what it means, example
// attack scenarios, and a broad mitigation checklist (20+ entries each).

const STRIDE_CATEGORIES = {
  S: {
    key: "S",
    name: "Spoofing",
    description:
      "An attacker impersonates a user, process, device, or system component " +
      "in order to gain access to resources or trust they should not have. " +
      "Spoofing threats violate the security property of authentication.",
    examples: [
      "Attacker replays a stolen session cookie to impersonate a logged-in user",
      "Forged sender address in an email used for a phishing campaign",
      "Rogue Wi-Fi access point impersonating a legitimate corporate SSID",
      "DNS cache poisoning redirecting clients to an attacker-controlled host",
      "ARP spoofing to impersonate a gateway on a local network",
      "Fake TLS certificate accepted due to missing certificate pinning",
      "IP address spoofing to bypass IP allow-lists",
      "Service-to-service call using a stolen or guessed API key",
      "Attacker impersonates a CI/CD runner to push malicious artifacts",
      "Credential stuffing using leaked username/password pairs",
      "Man-in-the-middle attacker impersonating both endpoints of a connection",
      "Cloned mobile app impersonating the legitimate client to a backend API",
      "Fake OAuth consent screen harvesting tokens for a legitimate app",
      "Attacker impersonates a webhook sender without signature verification",
      "Container image impersonating a trusted base image via typosquatting",
    ],
    mitigations: [
      "Enforce strong, phishing-resistant multi-factor authentication (FIDO2/WebAuthn)",
      "Use mutual TLS (mTLS) for service-to-service authentication",
      "Bind sessions to client fingerprints and rotate session identifiers after login",
      "Implement short-lived, signed tokens (JWT/PASETO) instead of long-lived static keys",
      "Validate and pin TLS certificates for critical outbound connections",
      "Use DNSSEC to protect against DNS spoofing and cache poisoning",
      "Deploy 802.1X or WPA3-Enterprise for network access control",
      "Verify HMAC signatures on all inbound webhooks",
      "Adopt SPF, DKIM, and DMARC to reduce email spoofing",
      "Use hardware-backed identity for CI/CD runners (workload identity, OIDC federation)",
      "Rate-limit and lock out accounts after repeated failed authentication attempts",
      "Require re-authentication for sensitive/step-up operations",
      "Use mutually authenticated, signed artifacts (Sigstore/cosign) in the build pipeline",
      "Pin dependency and base image digests, not mutable tags",
      "Implement anti-replay nonces and timestamps in authentication protocols",
      "Monitor for anomalous login geography/velocity (impossible travel detection)",
      "Use certificate transparency monitoring for domains and subdomains",
      "Disable legacy authentication protocols (NTLMv1, basic auth over plaintext)",
      "Enforce mutual authentication for VPN and remote access endpoints",
      "Educate users to recognize spoofed domains and lookalike URLs",
      "Use device attestation for mobile and IoT clients",
      "Segregate trust zones so a spoofed identity in one zone cannot cross into another",
      "Rotate and vault API keys with strict scoping and expiry",
    ],
  },
  T: {
    key: "T",
    name: "Tampering",
    description:
      "An attacker maliciously modifies data at rest, in transit, or in " +
      "memory. Tampering threats violate the security property of " +
      "integrity.",
    examples: [
      "Attacker modifies request parameters to bypass server-side price checks",
      "Man-in-the-middle alters unencrypted traffic between client and server",
      "Malicious insider edits audit logs to hide unauthorized activity",
      "Supply-chain attacker injects malicious code into an npm package",
      "Attacker tampers with a firmware update package before it is applied",
      "SQL injection used to modify database records directly",
      "Attacker modifies a cookie to escalate privileges (role=admin)",
      "Cache poisoning that serves tampered content to future requesters",
      "Tampering with backup files to embed a persistence mechanism",
      "Attacker rewrites Git history to hide a malicious commit",
      "Binary patching of a signed executable after signature verification is bypassed",
      "Attacker tampers with environment variables in a shared container host",
      "Message queue payloads modified in transit due to lack of integrity checks",
      "Attacker modifies infrastructure-as-code templates to open unintended ports",
      "Tampering with a software bill of materials (SBOM) to hide malicious components",
    ],
    mitigations: [
      "Use TLS 1.2+ everywhere to protect data in transit from tampering",
      "Validate all input server-side, never trust client-supplied values",
      "Sign and verify integrity of software artifacts (checksums, code signing)",
      "Use parameterized queries / prepared statements to prevent injection",
      "Implement write-once, append-only audit logs with cryptographic chaining",
      "Enforce least privilege on write access to production data stores",
      "Use HMAC or digital signatures on messages passed through queues/buses",
      "Adopt infrastructure-as-code review gates and drift detection",
      "Enable database row-level integrity checks and change auditing",
      "Use immutable infrastructure patterns (rebuild rather than patch in place)",
      "Verify SBOM and dependency provenance (SLSA levels, in-toto attestations)",
      "Protect CI/CD pipelines with branch protection and required code review",
      "Use file integrity monitoring (FIM) on critical system and config files",
      "Encrypt and authenticate backups (AEAD ciphers, not encryption alone)",
      "Disable direct write access to logs from the systems being logged",
      "Use content-addressable storage/hashes to detect tampering in artifacts",
      "Apply the principle of separation of duties for sensitive changes",
      "Use tamper-evident seals or attestation for hardware supply chains",
      "Validate integrity of firmware updates with signed manifests",
      "Restrict and audit direct database access, favor application-layer APIs",
      "Use git commit signing (GPG/SSH) and enforce verified commits on protected branches",
      "Apply checksums to configuration files loaded at runtime",
    ],
  },
  R: {
    key: "R",
    name: "Repudiation",
    description:
      "A user or system denies having performed an action, and there is " +
      "insufficient evidence to prove otherwise. Repudiation threats " +
      "violate the security property of non-repudiation / accountability.",
    examples: [
      "User deletes a resource and denies doing so due to lack of audit trail",
      "Administrator disables logging before performing unauthorized changes",
      "Attacker clears shell history and system logs after a breach",
      "Shared service account makes it impossible to attribute an action to a person",
      "Transaction lacks a cryptographic receipt, enabling later dispute",
      "Log timestamps are not synchronized, making event correlation unreliable",
      "API allows actions without recording the calling identity",
      "Email spoofing enables a sender to deny having sent a message",
      "Log storage is mutable, allowing after-the-fact edits",
      "No digital signature on financial transactions, enabling dispute of authorization",
      "Insufficient retention of logs prevents forensic reconstruction of an incident",
      "Privileged actions performed via a break-glass account with no attribution",
    ],
    mitigations: [
      "Log all security-relevant actions with user identity, timestamp, and outcome",
      "Use centralized, tamper-evident logging (write-once storage, log signing)",
      "Synchronize clocks across systems using NTP with authenticated time sources",
      "Avoid shared/service accounts for interactive human actions",
      "Require digital signatures on high-value transactions",
      "Implement non-repudiation via cryptographic receipts for critical operations",
      "Protect log pipelines from being disabled or modified by the same accounts they audit",
      "Retain logs per compliance/regulatory requirements with defined retention policies",
      "Forward logs off-host in near real time to a separate trust domain",
      "Use SIEM correlation rules to detect log tampering or gaps",
      "Require justification and approval workflow for break-glass account usage",
      "Enable detailed audit trails on all admin consoles and control planes",
      "Use blockchain or hash-chaining techniques for high-assurance audit logs",
      "Alert on log volume anomalies (sudden drop may indicate log tampering)",
      "Ensure API gateways log caller identity, not just source IP",
      "Apply strong session-to-identity binding to prevent attribution ambiguity",
      "Require multi-party approval for irreversible or destructive actions",
      "Periodically test log integrity with independent verification",
      "Use append-only cloud storage (object lock/WORM) for compliance logs",
      "Correlate authentication logs with application logs for full action traceability",
    ],
  },
  I: {
    key: "I",
    name: "Information Disclosure",
    description:
      "Data is exposed to individuals or systems that are not authorized to " +
      "see it. Information Disclosure threats violate the security " +
      "property of confidentiality.",
    examples: [
      "Verbose error messages leak stack traces or internal paths",
      "Misconfigured S3 bucket exposes customer data publicly",
      "Sensitive data logged in plaintext (passwords, tokens, PII)",
      "Side-channel timing attack reveals whether a username exists",
      "API returns more fields than the UI displays, leaking internal data",
      "Unencrypted backups stored in a shared or public location",
      "Directory listing enabled on a web server exposing source files",
      "Debug endpoints left enabled in production revealing internals",
      "Sensitive data cached by a CDN and served to unauthorized users",
      "Insecure direct object references (IDOR) exposing other users' records",
      "Source maps deployed to production revealing application internals",
      "Secrets committed to a public git repository",
      "Cross-tenant data leakage in a multi-tenant SaaS due to missing tenant scoping",
      "Memory dumps or core dumps containing sensitive data written to disk",
      "Metadata service (cloud instance metadata) exposed via SSRF",
    ],
    mitigations: [
      "Encrypt sensitive data at rest using strong, vetted algorithms (AES-256-GCM)",
      "Encrypt data in transit with TLS 1.2+ and disable weak cipher suites",
      "Return generic error messages to clients; log details server-side only",
      "Apply data classification and handle PII/secrets per classification policy",
      "Redact or mask sensitive fields in logs and telemetry",
      "Enforce least-privilege access controls on storage buckets and databases",
      "Scan repositories continuously for committed secrets (pre-commit and CI)",
      "Disable directory listing and remove debug endpoints before production deploy",
      "Implement field-level authorization checks, not just endpoint-level",
      "Use tenant isolation (separate schemas/keys) in multi-tenant architectures",
      "Strip source maps and debug symbols from production builds",
      "Restrict cloud instance metadata access (IMDSv2, network policies) to prevent SSRF abuse",
      "Apply object-level authorization checks to prevent IDOR",
      "Use secrets managers/vaults instead of embedding secrets in code or config",
      "Set strict cache-control headers on responses containing sensitive data",
      "Perform regular access reviews on data stores and shared drives",
      "Apply data loss prevention (DLP) tooling on egress channels",
      "Sanitize crash/core dumps or disable them in production",
      "Use constant-time comparison for secrets to avoid timing side-channels",
      "Apply row-level security in databases for multi-tenant data isolation",
      "Classify and encrypt backups with access controls equal to production data",
      "Conduct regular penetration testing focused on data exposure paths",
    ],
  },
  D: {
    key: "D",
    name: "Denial of Service",
    description:
      "An attacker degrades or denies availability of a system or service " +
      "to legitimate users. Denial of Service threats violate the " +
      "security property of availability.",
    examples: [
      "Volumetric DDoS flood exhausts network bandwidth",
      "Application-layer flood (HTTP GET/POST flood) exhausts server resources",
      "Algorithmic complexity attack (ReDoS) causes CPU exhaustion",
      "Unbounded resource allocation from user input exhausts memory",
      "Amplification attack via misconfigured open DNS/NTP resolvers",
      "Account lockout policy abused to lock out legitimate users",
      "Slowloris-style attack holds connections open to exhaust connection pools",
      "Malicious job floods a queue causing worker starvation",
      "Attacker exhausts rate-limited third-party API quotas shared by the app",
      "Log flooding fills disk space, crashing the logging pipeline",
      "Recursive or deeply nested payloads exhaust parser stack/heap",
      "Zip bomb or decompression bomb exhausts disk/memory on upload processing",
    ],
    mitigations: [
      "Deploy DDoS protection/scrubbing services in front of public endpoints",
      "Implement rate limiting and throttling per user/IP/API key",
      "Set request size limits and timeouts on all network-facing services",
      "Use circuit breakers and bulkheads to isolate failing dependencies",
      "Validate and bound recursive/nested input structures (JSON depth limits)",
      "Guard regular expressions against catastrophic backtracking (ReDoS)",
      "Enforce quotas and backpressure on message queues and job workers",
      "Use autoscaling with sane upper bounds to absorb legitimate traffic spikes",
      "Apply connection limits and idle timeouts to prevent slow-connection attacks",
      "Limit decompression ratios and validate archive contents before extraction",
      "Separate critical control-plane traffic from bulk data-plane traffic",
      "Use CDN caching to absorb read-heavy traffic away from origin servers",
      "Design idempotent, resumable operations to reduce retry storm impact",
      "Apply exponential backoff and jitter on client retries",
      "Monitor and alert on resource saturation (CPU, memory, disk, connections)",
      "Isolate noisy-neighbor tenants with resource quotas in shared infrastructure",
      "Harden DNS infrastructure against amplification abuse (response rate limiting)",
      "Implement graceful degradation for non-critical features under load",
      "Pre-provision incident response runbooks for DDoS scenarios",
      "Use anycast routing to distribute and absorb traffic geographically",
    ],
  },
  E: {
    key: "E",
    name: "Elevation of Privilege",
    description:
      "An attacker gains capabilities or access beyond what they are " +
      "authorized for, often moving from unprivileged to privileged " +
      "context. Elevation of Privilege threats violate the security " +
      "property of authorization.",
    examples: [
      "Vertical privilege escalation from regular user to administrator",
      "Horizontal privilege escalation accessing another user's resources",
      "Container escape granting host-level access from within a container",
      "Exploiting a setuid binary vulnerability to gain root",
      "Insecure deserialization leading to remote code execution",
      "Missing authorization checks on an internal admin API",
      "Path traversal used to overwrite a privileged configuration file",
      "Kernel vulnerability exploited for local privilege escalation",
      "Misconfigured IAM role allows assuming a more privileged role",
      "SQL injection used to grant a database user elevated permissions",
      "Exploiting a CI/CD pipeline to gain access to production credentials",
      "JWT algorithm confusion (alg=none) bypassing signature verification",
      "Improper access control on GraphQL introspection exposing admin mutations",
      "Sudo misconfiguration allowing arbitrary command execution",
    ],
    mitigations: [
      "Enforce the principle of least privilege for all users, services, and roles",
      "Perform authorization checks on every request, not just authentication",
      "Use role-based or attribute-based access control (RBAC/ABAC) consistently",
      "Run containers as non-root with read-only file systems where possible",
      "Apply seccomp, AppArmor, or SELinux profiles to restrict syscalls",
      "Patch and monitor for kernel and container runtime vulnerabilities",
      "Avoid insecure deserialization; use safe, schema-validated formats",
      "Explicitly reject weak or 'none' algorithms when verifying JWTs",
      "Audit IAM policies regularly for privilege escalation paths (policy graph analysis)",
      "Isolate CI/CD credentials with short-lived, scoped tokens per job",
      "Disable GraphQL introspection and restrict admin mutations in production",
      "Use sandboxing/virtualization to contain untrusted code execution",
      "Apply just-in-time (JIT) privileged access instead of standing admin rights",
      "Validate and canonicalize file paths to prevent path traversal",
      "Regularly review sudoers files and remove unnecessary NOPASSWD entries",
      "Segment networks so compromised low-privilege hosts cannot reach sensitive tiers",
      "Use hardware security modules (HSMs) or TPMs to protect signing keys",
      "Apply defense-in-depth so a single control failure does not grant full access",
      "Conduct regular privilege escalation testing as part of penetration tests",
      "Enforce mandatory access control on multi-tenant compute platforms",
      "Require approval workflows for privilege grants and role assignments",
    ],
  },
};

// ---------------------------------------------------------------------------
// Helpers for deterministic IDs and scoring
// ---------------------------------------------------------------------------

function hashId(seed) {
  return crypto.createHash("sha1").update(String(seed)).digest("hex").slice(0, 8);
}

function makeThreatId(category, index) {
  return "THREAT-" + category + "-" + String(index).padStart(3, "0");
}

// ---------------------------------------------------------------------------
// THREAT_LIBRARY
// ---------------------------------------------------------------------------
// 100+ curated, pre-defined threats. Each entry:
//   id, category, name, description, severity, likelihood, impact,
//   affectedComponents, mitigations
//
// affectedComponents uses generic component-type tags that callers are
// expected to use when describing their architecture, e.g.:
//   "web-app", "api", "database", "auth-service", "load-balancer",
//   "cache", "message-queue", "file-storage", "mobile-client",
//   "third-party-service", "ci-cd", "container", "vm", "network",
//   "identity-provider", "admin-console", "logging", "backup",
//   "iot-device", "dns", "cdn", "reverse-proxy", "secrets-manager",
//   "queue-worker", "webhook", "email-service", "search-index"

function T(category, name, description, severity, likelihood, impact, affectedComponents, mitigations) {
  return {
    category,
    name,
    description,
    severity,
    likelihood,
    impact,
    affectedComponents,
    mitigations,
  };
}

const RAW_THREATS = [
  // ---- Spoofing (S) ----
  T("S", "Credential Stuffing Against Login Endpoint",
    "Attacker uses leaked username/password pairs from other breaches to attempt authentication en masse.",
    "high", "high", "high", ["web-app", "api", "auth-service"],
    ["Rate limit login attempts", "Require MFA", "Detect and block known-breached credentials", "Use CAPTCHA on repeated failures"]),
  T("S", "Session Cookie Theft via XSS",
    "Cross-site scripting is used to exfiltrate session cookies, allowing full session takeover.",
    "critical", "medium", "high", ["web-app"],
    ["Set HttpOnly and Secure flags on cookies", "Implement Content-Security-Policy", "Sanitize and encode all user-controlled output"]),
  T("S", "API Key Theft and Reuse",
    "A static API key is leaked (e.g. via client-side code or logs) and reused by an attacker to impersonate the legitimate caller.",
    "high", "medium", "high", ["api", "third-party-service"],
    ["Rotate API keys regularly", "Scope keys to minimum required permissions", "Prefer short-lived tokens over static keys"]),
  T("S", "DNS Spoofing / Cache Poisoning",
    "Attacker poisons DNS responses to redirect clients to a malicious server impersonating the legitimate one.",
    "high", "low", "high", ["dns", "network"],
    ["Enable DNSSEC", "Use DNS over HTTPS/TLS for resolution", "Monitor for unexpected DNS record changes"]),
  T("S", "Rogue Access Point Impersonation",
    "Attacker sets up a fake Wi-Fi access point mimicking a trusted SSID to intercept client traffic.",
    "medium", "medium", "medium", ["network", "mobile-client"],
    ["Use WPA3-Enterprise with certificate-based auth", "Enable 802.1X", "Educate users about rogue AP risks"]),
  T("S", "Forged Webhook Payloads",
    "Attacker sends forged webhook requests to an endpoint that does not verify sender signatures.",
    "high", "medium", "medium", ["webhook", "api"],
    ["Verify HMAC signature on all inbound webhooks", "Use a shared secret per integration", "Reject requests without valid timestamps (anti-replay)"]),
  T("S", "TLS Certificate Impersonation",
    "Attacker presents a fraudulent certificate to impersonate a trusted server due to missing certificate pinning or lax validation.",
    "high", "low", "high", ["mobile-client", "web-app", "api"],
    ["Implement certificate pinning for critical connections", "Use certificate transparency monitoring", "Reject self-signed or expired certificates"]),
  T("S", "Service Identity Spoofing in Microservices Mesh",
    "A compromised or malicious pod impersonates another service's identity to call internal APIs.",
    "high", "medium", "high", ["container", "api"],
    ["Enforce mutual TLS between services", "Use workload identity (SPIFFE/SPIRE)", "Apply network policies restricting service-to-service calls"]),
  T("S", "Email Spoofing for Phishing",
    "Attacker sends email that appears to originate from a trusted domain to trick recipients.",
    "medium", "high", "medium", ["email-service"],
    ["Implement SPF, DKIM, and DMARC", "Train users to recognize phishing", "Flag external senders in the mail client UI"]),
  T("S", "OAuth Consent Phishing",
    "Attacker tricks users into granting OAuth permissions to a malicious application that mimics a legitimate one.",
    "high", "medium", "high", ["identity-provider", "web-app"],
    ["Verify and display application publisher identity", "Restrict scopes available to unverified apps", "Monitor for suspicious OAuth grants"]),
  T("S", "CI/CD Runner Impersonation",
    "An attacker registers a rogue runner or hijacks credentials to impersonate a legitimate CI/CD worker.",
    "high", "low", "high", ["ci-cd"],
    ["Use ephemeral, attested runners", "Scope pipeline credentials narrowly", "Require signed runner registration tokens"]),
  T("S", "IP Address Spoofing to Bypass Allow-Lists",
    "Attacker spoofs source IP addresses to bypass network-layer allow-list controls.",
    "medium", "low", "medium", ["network", "load-balancer"],
    ["Use ingress filtering (BCP38)", "Prefer identity-based access control over IP allow-listing", "Validate source routing is disabled"]),
  T("S", "Cloned Mobile App Impersonation",
    "A cloned or repackaged mobile app impersonates the legitimate client when calling backend APIs.",
    "medium", "medium", "medium", ["mobile-client", "api"],
    ["Use app attestation (Play Integrity/App Attest)", "Bind API tokens to device identity", "Detect and block known cloned app signatures"]),
  T("S", "NTLM Relay Attack",
    "Attacker relays captured NTLM authentication to impersonate a user against another service.",
    "high", "medium", "high", ["network", "identity-provider"],
    ["Disable NTLM in favor of Kerberos", "Enable SMB/LDAP signing", "Enforce Extended Protection for Authentication"]),
  T("S", "Container Image Typosquatting",
    "Attacker publishes a malicious image with a name similar to a popular base image to trick developers into pulling it.",
    "medium", "medium", "medium", ["container", "ci-cd"],
    ["Pin images by digest, not tag", "Use a curated internal registry", "Scan images for provenance and signatures"]),
  T("S", "Replay of Captured Authentication Tokens",
    "Attacker captures and replays a valid authentication token or request to impersonate the original sender.",
    "high", "medium", "high", ["api", "auth-service"],
    ["Use nonces and timestamps in auth protocols", "Bind tokens to a single session/IP where feasible", "Use short token expiry"]),
  T("S", "Fake SMS/OTP Delivery Interception",
    "Attacker performs SIM swap or SS7 exploitation to intercept OTP codes and impersonate the victim.",
    "high", "low", "high", ["auth-service", "identity-provider"],
    ["Prefer app-based or hardware MFA over SMS OTP", "Monitor for SIM swap indicators", "Offer phishing-resistant WebAuthn as primary MFA"]),
  T("S", "Lookalike Domain Phishing",
    "Attacker registers a visually similar domain to host a phishing site impersonating the legitimate service.",
    "medium", "high", "medium", ["web-app"],
    ["Register common typo-domains defensively", "Monitor certificate transparency logs for lookalikes", "Deploy browser warning integrations"]),

  // ---- Tampering (T) ----
  T("T", "SQL Injection Modifying Records",
    "Unsanitized input allows an attacker to inject SQL that modifies or deletes database records.",
    "critical", "medium", "critical", ["database", "api", "web-app"],
    ["Use parameterized queries", "Apply least-privilege database accounts", "Deploy a web application firewall"]),
  T("T", "Client-Side Price/Parameter Tampering",
    "Attacker modifies hidden form fields or request parameters (e.g. price, quantity) that are trusted server-side.",
    "high", "high", "high", ["web-app", "api"],
    ["Re-validate all business logic server-side", "Never trust client-supplied pricing or entitlement data", "Sign sensitive parameters"]),
  T("T", "Man-in-the-Middle Traffic Modification",
    "Unencrypted traffic is intercepted and modified in transit between client and server.",
    "critical", "medium", "critical", ["network", "api", "web-app"],
    ["Enforce TLS 1.2+ with HSTS", "Disable plaintext fallback protocols", "Use certificate pinning on mobile clients"]),
  T("T", "Malicious Package Injection in Supply Chain",
    "Attacker compromises or typosquats a dependency to inject malicious code into the build.",
    "critical", "medium", "critical", ["ci-cd", "third-party-service"],
    ["Pin dependency versions with lockfiles", "Use software composition analysis (SCA)", "Verify package signatures/provenance (SLSA)"]),
  T("T", "Firmware Update Tampering",
    "Attacker intercepts or modifies firmware update packages before they are applied to a device.",
    "critical", "low", "critical", ["iot-device"],
    ["Sign firmware images and verify signatures before flashing", "Use secure boot chains", "Deliver updates over authenticated channels"]),
  T("T", "Cookie/Token Tampering for Privilege Change",
    "Attacker modifies a client-side cookie or token value to escalate role or bypass restrictions.",
    "high", "medium", "high", ["web-app", "api"],
    ["Sign and encrypt session tokens server-side", "Never store authorization decisions client-side unsigned", "Validate token integrity on every request"]),
  T("T", "Audit Log Tampering by Insider",
    "A malicious insider with elevated access modifies or deletes audit logs to conceal unauthorized activity.",
    "high", "low", "high", ["logging"],
    ["Use write-once/append-only log storage", "Forward logs to a separate trust domain in real time", "Restrict log-deletion permissions from operational accounts"]),
  T("T", "Cache Poisoning Serving Tampered Content",
    "Attacker manipulates cache keys or headers to poison a shared cache, serving malicious content to other users.",
    "high", "medium", "high", ["cdn", "cache"],
    ["Normalize and validate cache keys", "Restrict which headers influence caching", "Segregate caches per tenant/user where appropriate"]),
  T("T", "Backup Tampering for Persistence",
    "Attacker modifies backup files to embed a persistence mechanism that survives restoration.",
    "high", "low", "high", ["backup"],
    ["Encrypt and sign backups", "Verify backup integrity before restoration", "Store backups in immutable/WORM storage"]),
  T("T", "Git History Rewriting to Hide Malicious Commit",
    "Attacker with repository access force-pushes rewritten history to conceal a malicious change.",
    "medium", "low", "medium", ["ci-cd"],
    ["Enable branch protection disallowing force-push", "Require signed commits", "Mirror repository history to an external audit log"]),
  T("T", "Signed Binary Patched Post-Verification",
    "Attacker patches a binary after signature verification occurs but before execution (TOCTOU).",
    "high", "low", "high", ["vm", "container"],
    ["Verify signatures immediately before execution, not earlier in the pipeline", "Use read-only, immutable artifact storage", "Apply runtime integrity attestation"]),
  T("T", "Message Queue Payload Tampering",
    "Messages in transit through a queue or bus are modified due to lack of integrity protection.",
    "medium", "medium", "medium", ["message-queue"],
    ["Sign or HMAC message payloads", "Use TLS between producers/consumers and the broker", "Validate message schema on consumption"]),
  T("T", "Infrastructure-as-Code Drift/Tampering",
    "Attacker or misconfigured pipeline modifies IaC templates to open unintended network access.",
    "high", "medium", "high", ["ci-cd"],
    ["Require peer review on IaC changes", "Run drift detection against deployed state", "Use policy-as-code gates (OPA/Sentinel)"]),
  T("T", "SBOM Tampering to Hide Malicious Components",
    "Attacker modifies a software bill of materials to conceal the presence of malicious or vulnerable components.",
    "medium", "low", "medium", ["ci-cd"],
    ["Generate SBOMs in a trusted, automated pipeline step", "Sign SBOM artifacts", "Cross-verify SBOM against actual build inputs"]),
  T("T", "Configuration File Tampering at Runtime",
    "Attacker with host access modifies application configuration files to alter behavior.",
    "high", "medium", "high", ["vm", "container"],
    ["Apply file integrity monitoring", "Use read-only file systems for config in containers", "Load critical config from a signed source"]),
  T("T", "HTML/DOM Tampering via Browser Extension",
    "A malicious or compromised browser extension modifies page content or intercepts form submissions.",
    "medium", "medium", "medium", ["web-app"],
    ["Use Subresource Integrity (SRI) for scripts", "Implement strict CSP", "Warn users about risky extension permissions"]),
  T("T", "Database Direct Access Bypassing Application Logic",
    "Attacker or over-privileged user modifies data directly in the database, bypassing application-layer validation.",
    "high", "medium", "high", ["database"],
    ["Restrict direct database access to break-glass scenarios only", "Enforce constraints and triggers at the database layer", "Audit direct query access"]),
  T("T", "API Response Tampering via Compromised CDN Node",
    "A compromised CDN edge node serves modified API responses to clients.",
    "high", "low", "high", ["cdn"],
    ["Sign API responses where feasible", "Use TLS termination close to origin for sensitive data", "Monitor CDN configuration changes"]),

  // ---- Repudiation (R) ----
  T("R", "Missing Audit Trail for Destructive Actions",
    "Users can delete or modify critical resources without any record of who performed the action.",
    "high", "high", "medium", ["api", "admin-console"],
    ["Log all destructive actions with actor identity and timestamp", "Require confirmation and reason capture for deletions", "Retain logs per policy"]),
  T("R", "Shared Service Account Prevents Attribution",
    "Multiple individuals use a shared credential, making it impossible to attribute specific actions to a person.",
    "medium", "high", "medium", ["admin-console", "database"],
    ["Eliminate shared accounts in favor of individual identities", "Use short-lived, per-user credentials", "Require justification logging for shared/break-glass use"]),
  T("R", "Logging Disabled Before Unauthorized Change",
    "An attacker or insider disables logging temporarily to perform an unauthorized action undetected.",
    "high", "medium", "high", ["logging"],
    ["Alert on logging configuration changes", "Forward logs externally in real time so local disabling has limited effect", "Restrict permission to modify logging config"]),
  T("R", "Unsynchronized Clocks Undermine Log Correlation",
    "Systems with drifting clocks make it difficult to correlate events across services during investigation.",
    "medium", "medium", "medium", ["logging", "vm"],
    ["Use authenticated NTP across all systems", "Alert on clock drift beyond threshold", "Use monotonic/logical clocks for ordering where possible"]),
  T("R", "Transactions Lack Non-Repudiation Evidence",
    "Financial or critical transactions are not cryptographically signed, enabling later disputes.",
    "high", "medium", "high", ["api", "database"],
    ["Digitally sign critical transactions", "Provide cryptographic receipts to counterparties", "Retain signed evidence per regulatory retention rules"]),
  T("R", "API Calls Without Caller Identity Logging",
    "Internal or external API calls are processed without recording which identity/service made the call.",
    "medium", "high", "medium", ["api"],
    ["Require authenticated identity for all API calls", "Log caller identity alongside source IP", "Reject unauthenticated calls to sensitive endpoints"]),
  T("R", "Mutable Log Storage Allows Retroactive Edits",
    "Logs are stored in a mutable location, allowing an attacker with access to alter historical records.",
    "high", "low", "high", ["logging"],
    ["Use write-once/object-lock storage for logs", "Hash-chain log entries for tamper evidence", "Restrict write/delete permissions on log storage"]),
  T("R", "Break-Glass Account Usage Without Attribution",
    "Emergency/break-glass accounts are used without recording which individual invoked them.",
    "medium", "medium", "medium", ["admin-console"],
    ["Require individual checkout/approval for break-glass credentials", "Log the requester identity and justification", "Auto-rotate break-glass credentials after each use"]),
  T("R", "Insufficient Log Retention for Forensics",
    "Logs are purged too quickly to support incident investigation after a delayed detection.",
    "medium", "medium", "medium", ["logging"],
    ["Define retention periods aligned to detection latency and compliance", "Archive logs to cold storage instead of deleting", "Test log retrieval as part of IR drills"]),

  // ---- Information Disclosure (I) ----
  T("I", "Verbose Error Messages Leak Internals",
    "Stack traces or internal paths are returned to clients on error, revealing implementation details.",
    "medium", "high", "medium", ["web-app", "api"],
    ["Return generic error messages to clients", "Log detailed errors server-side only", "Disable debug mode in production"]),
  T("I", "Publicly Exposed Cloud Storage Bucket",
    "A storage bucket is misconfigured with public read/write access, exposing sensitive data.",
    "critical", "high", "critical", ["file-storage"],
    ["Default to private bucket ACLs", "Use automated scanning for public bucket misconfigurations", "Apply bucket policies denying public access by default"]),
  T("I", "Plaintext Secrets in Logs",
    "Passwords, tokens, or PII are inadvertently logged in plaintext.",
    "high", "high", "high", ["logging", "api"],
    ["Redact sensitive fields before logging", "Use structured logging with field-level redaction rules", "Scan logs for accidental secret exposure"]),
  T("I", "Username Enumeration via Timing/Response Differences",
    "Login or password-reset endpoints reveal whether a username exists via response timing or messages.",
    "low", "high", "low", ["auth-service", "api"],
    ["Return uniform responses regardless of account existence", "Use constant-time comparisons", "Rate limit enumeration attempts"]),
  T("I", "Over-Broad API Responses Leak Internal Fields",
    "An API returns more data fields than the client needs, exposing internal or sensitive attributes.",
    "medium", "high", "medium", ["api"],
    ["Apply response schemas / DTOs limiting exposed fields", "Review API responses for over-exposure during code review", "Use field-level authorization"]),
  T("I", "Unencrypted Backups in Shared Storage",
    "Backups containing sensitive data are stored without encryption in a shared or semi-public location.",
    "high", "medium", "high", ["backup"],
    ["Encrypt backups at rest", "Restrict backup storage access to authorized roles", "Audit backup storage locations regularly"]),
  T("I", "Directory Listing Enabled on Web Server",
    "A misconfigured web server exposes directory listings, revealing source files or sensitive assets.",
    "medium", "medium", "medium", ["web-app"],
    ["Disable directory listing at the web server level", "Remove unused files from web roots", "Apply automated configuration scanning"]),
  T("I", "Debug Endpoints Left Enabled in Production",
    "Debug or diagnostic endpoints (e.g. /debug, /actuator) remain accessible in production, leaking internals.",
    "high", "medium", "high", ["api", "web-app"],
    ["Disable debug endpoints in production builds", "Gate diagnostic endpoints behind internal-only network access", "Include debug endpoint checks in release gating"]),
  T("I", "CDN Caches and Serves Sensitive Data to Wrong Users",
    "Sensitive, user-specific responses are cached by a CDN and served to a different user.",
    "high", "medium", "high", ["cdn"],
    ["Set Cache-Control: private/no-store on sensitive responses", "Vary cache keys by authenticated identity where needed", "Audit CDN caching rules for sensitive routes"]),
  T("I", "Insecure Direct Object Reference (IDOR)",
    "An API exposes internal object identifiers without verifying the requester is authorized to access them.",
    "high", "high", "high", ["api"],
    ["Enforce object-level authorization on every request", "Use indirect/opaque identifiers", "Add automated IDOR test coverage"]),
  T("I", "Source Maps Deployed to Production",
    "JavaScript source maps are deployed publicly, revealing original source code and internal logic.",
    "medium", "medium", "medium", ["web-app"],
    ["Exclude source maps from production deployments", "Restrict source map access to internal debugging tools", "Automate build checks for accidental inclusion"]),
  T("I", "Secrets Committed to Public Git Repository",
    "API keys, credentials, or certificates are committed to a repository that is or becomes public.",
    "critical", "high", "critical", ["ci-cd"],
    ["Run pre-commit and CI secret scanning", "Rotate any credential immediately upon exposure", "Use a secrets manager instead of embedding secrets in code"]),
  T("I", "Cross-Tenant Data Leakage in Multi-Tenant SaaS",
    "Insufficient tenant isolation allows one customer to access another customer's data.",
    "critical", "medium", "critical", ["database", "api"],
    ["Enforce tenant ID checks on every query", "Use row-level security or per-tenant schemas", "Add automated cross-tenant isolation tests"]),
  T("I", "Core Dumps Containing Sensitive Data",
    "Application crash dumps written to disk contain sensitive in-memory data such as keys or credentials.",
    "medium", "low", "high", ["vm", "container"],
    ["Disable core dumps in production or restrict access tightly", "Scrub sensitive data from memory after use", "Encrypt any crash dump storage"]),
  T("I", "SSRF Exposing Cloud Metadata Service",
    "Server-side request forgery is used to reach the cloud instance metadata endpoint and steal credentials.",
    "critical", "medium", "critical", ["api", "vm"],
    ["Enforce IMDSv2 with hop-limit protections", "Validate and restrict outbound URLs from server-side fetchers", "Apply network policies blocking metadata IP from app containers"]),
  T("I", "Sensitive Data Exposed via GraphQL Introspection",
    "GraphQL introspection is left enabled in production, revealing the full schema including sensitive fields/mutations.",
    "medium", "medium", "medium", ["api"],
    ["Disable introspection in production", "Apply field-level access control", "Rate limit and monitor introspection queries"]),
  T("I", "Third-Party Analytics Script Exfiltrating Data",
    "A third-party JavaScript library unintentionally or maliciously exfiltrates user data or form input.",
    "medium", "medium", "medium", ["web-app", "third-party-service"],
    ["Audit third-party scripts and their data access", "Use Subresource Integrity and CSP to restrict script behavior", "Minimize third-party script usage on sensitive pages"]),

  // ---- Denial of Service (D) ----
  T("D", "Volumetric DDoS Flood",
    "Attacker floods network bandwidth with high-volume traffic to exhaust capacity.",
    "high", "medium", "high", ["network", "load-balancer"],
    ["Deploy DDoS scrubbing / cloud-based protection", "Use anycast routing to distribute load", "Establish upstream ISP mitigation agreements"]),
  T("D", "Application-Layer HTTP Flood",
    "Attacker sends high volumes of seemingly legitimate HTTP requests to exhaust application resources.",
    "high", "medium", "high", ["web-app", "api"],
    ["Rate limit per client/IP/API key", "Use a web application firewall with bot detection", "Cache expensive responses"]),
  T("D", "Regular Expression Denial of Service (ReDoS)",
    "A crafted input triggers catastrophic backtracking in a vulnerable regular expression, exhausting CPU.",
    "high", "medium", "high", ["api", "web-app"],
    ["Audit regexes for backtracking risk", "Use regex engines/timeouts that bound execution time", "Validate input length before regex evaluation"]),
  T("D", "Unbounded Memory Allocation from User Input",
    "User-controlled input size directly drives memory allocation, allowing an attacker to exhaust memory.",
    "high", "medium", "high", ["api"],
    ["Enforce maximum request/payload size limits", "Stream large payloads instead of buffering fully in memory", "Apply per-request memory quotas"]),
  T("D", "DNS/NTP Amplification Attack",
    "Attacker abuses open resolvers to amplify traffic directed at a victim.",
    "high", "low", "high", ["dns", "network"],
    ["Disable open recursive resolution to the internet", "Apply response rate limiting", "Follow BCP38 ingress filtering"]),
  T("D", "Account Lockout Abuse",
    "Attacker deliberately triggers account lockout policies to deny access to legitimate users.",
    "medium", "medium", "medium", ["auth-service"],
    ["Use progressive delays instead of hard lockouts where feasible", "Notify and allow secondary recovery channels", "Monitor for lockout-triggering patterns"]),
  T("D", "Slowloris Connection Exhaustion",
    "Attacker holds many connections open with slow/partial requests to exhaust the connection pool.",
    "medium", "medium", "medium", ["web-app", "reverse-proxy"],
    ["Set aggressive idle and header timeouts", "Use a reverse proxy designed to mitigate slow attacks", "Limit concurrent connections per client"]),
  T("D", "Message Queue Flooding Causes Worker Starvation",
    "Attacker or buggy client floods a queue with messages, starving legitimate job processing.",
    "medium", "medium", "medium", ["message-queue", "queue-worker"],
    ["Apply per-producer quotas on queue submission", "Use priority queues for critical workloads", "Auto-scale workers with backpressure limits"]),
  T("D", "Third-Party API Quota Exhaustion",
    "Attacker triggers excessive calls to a shared third-party API, exhausting the application's quota.",
    "medium", "medium", "medium", ["third-party-service", "api"],
    ["Cache third-party responses where possible", "Apply per-user quotas before calling third-party APIs", "Monitor quota consumption with alerting"]),
  T("D", "Log Flooding Exhausts Disk Space",
    "Excessive log generation (accidental or malicious) fills disk space, crashing the logging pipeline or host.",
    "medium", "medium", "medium", ["logging", "vm"],
    ["Apply log rotation and retention limits", "Rate limit repetitive log entries", "Alert on disk usage thresholds"]),
  T("D", "Deeply Nested Payload Exhausts Parser",
    "A deeply nested JSON/XML payload exhausts stack or heap resources during parsing.",
    "medium", "medium", "medium", ["api"],
    ["Enforce maximum nesting depth in parsers", "Use streaming parsers with bounded resource usage", "Reject malformed or excessively large payloads early"]),
  T("D", "Decompression Bomb on File Upload",
    "A small compressed file expands to an enormous size upon decompression, exhausting disk or memory.",
    "high", "low", "high", ["file-storage", "api"],
    ["Limit decompression ratio and total output size", "Scan and validate archive contents before full extraction", "Process uploads in isolated, resource-limited sandboxes"]),
  T("D", "Noisy Neighbor Resource Exhaustion in Shared Infrastructure",
    "A tenant consumes disproportionate shared resources, degrading service for other tenants.",
    "medium", "medium", "medium", ["container", "vm"],
    ["Apply per-tenant resource quotas and cgroup limits", "Use dedicated node pools for high-priority tenants", "Monitor per-tenant resource consumption"]),

  // ---- Elevation of Privilege (E) ----
  T("E", "Vertical Privilege Escalation via Missing Authorization Check",
    "A regular user accesses admin-only functionality because the server fails to check role on a request.",
    "critical", "medium", "critical", ["api", "admin-console"],
    ["Enforce server-side authorization checks on every endpoint", "Use centralized authorization middleware", "Add automated tests for privilege boundaries"]),
  T("E", "Horizontal Privilege Escalation Accessing Other Users' Data",
    "A user manipulates identifiers to access another user's resources at the same privilege level.",
    "high", "high", "high", ["api"],
    ["Verify resource ownership on every request", "Use unguessable, unique resource identifiers", "Add automated authorization test coverage"]),
  T("E", "Container Escape to Host",
    "A vulnerability or misconfiguration allows a process inside a container to gain access to the host system.",
    "critical", "low", "critical", ["container"],
    ["Run containers as non-root with minimal capabilities", "Apply seccomp/AppArmor/SELinux profiles", "Keep container runtimes patched"]),
  T("E", "Setuid Binary Exploitation",
    "A vulnerability in a setuid root binary is exploited to gain elevated local privileges.",
    "high", "low", "critical", ["vm"],
    ["Minimize use of setuid binaries", "Patch and audit setuid binaries regularly", "Use capabilities instead of full setuid root where possible"]),
  T("E", "Insecure Deserialization Leading to RCE",
    "Untrusted data is deserialized without validation, allowing arbitrary code execution.",
    "critical", "medium", "critical", ["api", "web-app"],
    ["Avoid deserializing untrusted data with unsafe formats", "Use schema-validated, safe serialization formats (JSON with strict schemas)", "Apply sandboxing around deserialization logic"]),
  T("E", "Missing Authorization on Internal Admin API",
    "An internal admin API is reachable without proper authorization because it was assumed to be network-isolated only.",
    "critical", "medium", "critical", ["admin-console", "api"],
    ["Apply authentication and authorization even on 'internal-only' APIs", "Use network segmentation as defense-in-depth, not the sole control", "Audit internal API exposure regularly"]),
  T("E", "Path Traversal Overwriting Privileged Config",
    "Attacker uses path traversal sequences to write or overwrite files outside the intended directory.",
    "high", "medium", "high", ["api", "file-storage"],
    ["Canonicalize and validate all file paths", "Use allow-lists for permitted file operations", "Run file-writing processes with least-privilege file system access"]),
  T("E", "Kernel Vulnerability Local Privilege Escalation",
    "A local kernel vulnerability is exploited to escalate from an unprivileged process to root.",
    "critical", "low", "critical", ["vm", "container"],
    ["Apply kernel security patches promptly", "Use grsecurity/hardened kernels where appropriate", "Minimize attack surface with reduced kernel modules"]),
  T("E", "Misconfigured IAM Role Allows Privilege Chaining",
    "An IAM policy allows an entity to assume or modify a role with greater privileges than intended.",
    "critical", "medium", "critical", ["identity-provider"],
    ["Run automated IAM privilege escalation path analysis", "Apply least-privilege IAM policies", "Require approval for role/policy changes"]),
  T("E", "SQL Injection Granting Elevated Database Privileges",
    "SQL injection is used to run administrative statements that grant the attacker elevated database permissions.",
    "critical", "medium", "critical", ["database"],
    ["Use parameterized queries", "Apply least-privilege database accounts for application use", "Disable dangerous administrative functions for app accounts"]),
  T("E", "CI/CD Pipeline Exploited for Production Credential Access",
    "An attacker exploits a CI/CD pipeline vulnerability to exfiltrate production deployment credentials.",
    "critical", "medium", "critical", ["ci-cd"],
    ["Scope pipeline credentials narrowly and rotate frequently", "Isolate build and deploy stages with distinct credentials", "Audit third-party CI/CD plugins/actions for supply-chain risk"]),
  T("E", "JWT Algorithm Confusion Bypass",
    "An attacker exploits improper JWT library configuration (e.g. accepting 'alg: none') to forge valid-looking tokens.",
    "critical", "low", "critical", ["auth-service", "api"],
    ["Explicitly allow-list accepted signing algorithms", "Reject unsigned or 'none' algorithm tokens", "Use vetted, up-to-date JWT libraries"]),
  T("E", "GraphQL Admin Mutation Exposed via Introspection",
    "Introspection reveals administrative mutations that lack proper authorization enforcement.",
    "high", "medium", "high", ["api"],
    ["Disable introspection in production", "Apply per-field/mutation authorization checks", "Restrict admin operations to a separate, protected API surface"]),
  T("E", "Sudo Misconfiguration Enables Arbitrary Command Execution",
    "Overly permissive sudoers entries (e.g. NOPASSWD on broad commands) allow privilege escalation.",
    "high", "medium", "high", ["vm"],
    ["Restrict sudoers entries to specific, minimal commands", "Audit sudoers configuration regularly", "Avoid NOPASSWD except where strictly necessary"]),

  // ---- Additional cross-cutting threats to exceed 100 entries ----
  T("S", "Voice Phishing (Vishing) Impersonating IT Support",
    "Attacker calls an employee impersonating IT support to extract credentials or MFA codes.",
    "medium", "medium", "medium", ["auth-service"],
    ["Train employees to verify support requests through a secondary channel", "Never request full credentials or OTP codes via phone", "Use phishing-resistant MFA that cannot be relayed verbally"]),
  T("T", "Man-in-the-Browser Malware Modifying Transactions",
    "Malware on the client modifies transaction details after user confirmation but before submission.",
    "high", "low", "high", ["web-app", "mobile-client"],
    ["Use out-of-band transaction confirmation", "Display transaction summary at the point of final signing", "Detect anomalous client-side script injection"]),
  T("R", "Anonymous Feedback/Support Channel Abuse",
    "An anonymous support or feedback channel is abused to submit false claims with no accountability.",
    "low", "medium", "low", ["web-app"],
    ["Require lightweight identity verification for sensitive submissions", "Rate limit anonymous submissions", "Log submission metadata for abuse investigation"]),
  T("I", "Search Index Leaking Restricted Documents",
    "A search index includes documents the searching user is not authorized to view.",
    "high", "medium", "high", ["search-index"],
    ["Apply document-level access control filtering at query time", "Re-index with authorization metadata", "Audit search results for cross-permission leakage"]),
  T("D", "Search Query Complexity Exhaustion",
    "Complex or wildcard-heavy search queries consume excessive resources on the search index.",
    "medium", "medium", "medium", ["search-index"],
    ["Limit query complexity and wildcard usage", "Apply per-user query rate limits", "Set query timeout thresholds"]),
  T("E", "Default Credentials Left on IoT Device",
    "IoT devices are shipped or deployed with default admin credentials that are never changed.",
    "high", "high", "high", ["iot-device"],
    ["Force credential change on first boot", "Disable default accounts where possible", "Scan deployed fleets for default credential usage"]),
  T("S", "Bluetooth Impersonation Attack on IoT Device",
    "Attacker impersonates a paired device over Bluetooth to gain control of an IoT device.",
    "medium", "low", "medium", ["iot-device"],
    ["Use Bluetooth LE Secure Connections with authenticated pairing", "Disable legacy/insecure pairing modes", "Bind device pairing to physical proximity confirmation"]),
  T("T", "Firmware Downgrade Attack",
    "Attacker forces a device to install an older, vulnerable firmware version to reintroduce a patched flaw.",
    "high", "low", "high", ["iot-device"],
    ["Enforce anti-rollback version checks", "Sign firmware with monotonic version counters", "Reject downgrade requests without explicit authorization"]),
  T("I", "Telemetry Data Leaking User Location",
    "Device or application telemetry inadvertently includes precise location data sent to third parties.",
    "medium", "medium", "medium", ["iot-device", "mobile-client"],
    ["Minimize and anonymize telemetry data collected", "Obtain explicit consent for location data sharing", "Audit third-party SDKs for excessive data collection"]),
  T("D", "Battery/Resource Drain Attack on IoT Device",
    "Attacker sends repeated wake or processing requests to drain a battery-powered device's resources.",
    "low", "low", "medium", ["iot-device"],
    ["Rate limit wake-triggering requests", "Authenticate requests before triggering expensive processing", "Implement power-aware request throttling"]),
  T("E", "Admin Console Exposed to Public Internet",
    "An administrative console intended for internal use only is reachable from the public internet.",
    "critical", "medium", "critical", ["admin-console"],
    ["Restrict admin console access to VPN/private network", "Require MFA and IP allow-listing for admin access", "Continuously scan for accidental public exposure"]),
  T("I", "Reverse Proxy Header Injection Leaking Internal Hostnames",
    "Misconfigured reverse proxy forwards or reflects internal headers/hostnames to external clients.",
    "low", "medium", "low", ["reverse-proxy"],
    ["Strip internal headers before forwarding responses externally", "Use generic server banners", "Review proxy configuration for information leakage"]),
  T("T", "Load Balancer Health Check Spoofing",
    "Attacker manipulates health check responses to manipulate traffic routing decisions.",
    "medium", "low", "medium", ["load-balancer"],
    ["Authenticate health check endpoints", "Restrict health check access to the load balancer's network", "Monitor for anomalous routing behavior"]),
  T("S", "Secrets Manager Access Token Theft",
    "A leaked access token for the secrets manager allows an attacker to retrieve all stored secrets.",
    "critical", "low", "critical", ["secrets-manager"],
    ["Scope secrets manager tokens to specific paths/secrets", "Use short-lived, auto-rotated access tokens", "Audit and alert on secrets access patterns"]),
  T("E", "Queue Worker Executes Untrusted Job Payloads",
    "A queue worker deserializes and executes job payloads without validating their origin or contents.",
    "high", "medium", "high", ["queue-worker"],
    ["Validate and schema-check job payloads before processing", "Sign job payloads from trusted producers", "Run workers with least-privilege execution context"]),
  T("D", "Email Service Abused for Outbound Spam Flood",
    "Attacker abuses a compromised account or open relay to send high volumes of outbound email, risking blocklisting.",
    "medium", "medium", "medium", ["email-service"],
    ["Rate limit outbound email per account", "Monitor sending reputation and bounce rates", "Require authentication for all outbound relay use"]),
  T("I", "Third-Party Service Data Retention Beyond Agreement",
    "A third-party processor retains customer data longer than contractually agreed, increasing breach exposure.",
    "medium", "low", "medium", ["third-party-service"],
    ["Include data retention and deletion clauses in vendor contracts", "Periodically audit third-party data handling practices", "Minimize data shared with third parties"]),
  T("R", "Webhook Delivery Lacks Delivery Proof",
    "Recipient of a webhook can deny receiving it because there is no signed delivery receipt or retry log.",
    "low", "medium", "low", ["webhook"],
    ["Log webhook delivery attempts and responses", "Provide signed delivery receipts", "Implement retry with exponential backoff and delivery status tracking"]),
];

const THREAT_LIBRARY = (function buildLibrary() {
  const counters = { S: 0, T: 0, R: 0, I: 0, D: 0, E: 0 };
  return RAW_THREATS.map((t) => {
    counters[t.category] += 1;
    const id = makeThreatId(t.category, counters[t.category]);
    return Object.assign({ id, fingerprint: hashId(id + t.name) }, t);
  });
})();

// ---------------------------------------------------------------------------
// Scoring weights and lookup tables
// ---------------------------------------------------------------------------

const SEVERITY_WEIGHT = { critical: 40, high: 30, medium: 18, low: 8 };
const LIKELIHOOD_WEIGHT = { high: 35, medium: 20, low: 8 };
const IMPACT_WEIGHT = { high: 25, medium: 14, low: 6 };

const SEVERITY_ORDER = ["low", "medium", "high", "critical"];
const LEVEL_ORDER = ["low", "medium", "high"];

function normalizeLevel(value, table) {
  const v = String(value || "").toLowerCase();
  return Object.prototype.hasOwnProperty.call(table, v) ? v : "medium";
}

// ---------------------------------------------------------------------------
// calculateRisk(threat) -> 0-100 numeric risk score
// ---------------------------------------------------------------------------
// Weighted scoring: severity carries the most weight (business consequence
// classification), likelihood next (how plausible the threat is given the
// architecture), and impact last (blast radius if realized). The three
// weight pools sum to 100 so a maximum-severity/likelihood/impact threat
// scores 100.

function calculateRisk(threat) {
  if (!threat || typeof threat !== "object") return 0;

  const severity = normalizeLevel(threat.severity, SEVERITY_WEIGHT);
  const likelihood = normalizeLevel(threat.likelihood, LIKELIHOOD_WEIGHT);
  const impact = normalizeLevel(threat.impact, IMPACT_WEIGHT);

  const score =
    SEVERITY_WEIGHT[severity] +
    LIKELIHOOD_WEIGHT[likelihood] +
    IMPACT_WEIGHT[impact];

  return Math.max(0, Math.min(100, Math.round(score)));
}

function riskLevelFromScore(score) {
  if (score >= 75) return "critical";
  if (score >= 55) return "high";
  if (score >= 30) return "medium";
  return "low";
}

// ---------------------------------------------------------------------------
// analyzeThreat(component, dataFlow) -> matched threats with relevance
// ---------------------------------------------------------------------------
// component: { type, name, trustLevel, exposedToInternet, storesData, ... }
// dataFlow: { source, destination, protocol, encrypted, authenticated,
//             crossesTrustBoundary, dataClassification, ... }
//
// Returns an array of { threat, relevanceScore, reasons } sorted by
// relevanceScore descending. relevanceScore blends the threat's intrinsic
// risk with contextual signals from the component/data flow.

function analyzeThreat(component, dataFlow) {
  const comp = component || {};
  const flow = dataFlow || {};

  const componentType = String(comp.type || "").toLowerCase();
  const results = [];

  for (const threat of THREAT_LIBRARY) {
    let matches = false;
    const reasons = [];

    // Direct component-type match against the threat's affected components.
    if (componentType && threat.affectedComponents.includes(componentType)) {
      matches = true;
      reasons.push("Component type '" + componentType + "' is a known target for this threat");
    }

    // Contextual signals that raise or create relevance even without a
    // direct type match (e.g. any internet-exposed component is relevant
    // to Spoofing/DoS threats).
    if (comp.exposedToInternet && (threat.category === "S" || threat.category === "D")) {
      matches = true;
      reasons.push("Component is exposed to the internet");
    }

    if (comp.storesData && threat.category === "I") {
      matches = true;
      reasons.push("Component stores data relevant to information disclosure");
    }

    if (comp.privileged && threat.category === "E") {
      matches = true;
      reasons.push("Component runs with elevated privileges");
    }

    if (flow.crossesTrustBoundary && (threat.category === "S" || threat.category === "T")) {
      matches = true;
      reasons.push("Data flow crosses a trust boundary");
    }

    if (flow.encrypted === false && threat.category === "T") {
      matches = true;
      reasons.push("Data flow is unencrypted, increasing tampering risk");
    }

    if (flow.encrypted === false && threat.category === "I") {
      matches = true;
      reasons.push("Data flow is unencrypted, increasing disclosure risk");
    }

    if (flow.authenticated === false && threat.category === "S") {
      matches = true;
      reasons.push("Data flow lacks authentication");
    }

    if (flow.authenticated === false && threat.category === "E") {
      matches = true;
      reasons.push("Unauthenticated flow may allow privilege escalation");
    }

    if (String(flow.dataClassification || "").toLowerCase() === "sensitive" && threat.category === "I") {
      matches = true;
      reasons.push("Data flow carries classified/sensitive data");
    }

    if (!matches) continue;

    const baseRisk = calculateRisk(threat);
    let contextBoost = 0;
    if (comp.exposedToInternet) contextBoost += 8;
    if (flow.crossesTrustBoundary) contextBoost += 6;
    if (flow.encrypted === false) contextBoost += 6;
    if (flow.authenticated === false) contextBoost += 6;
    if (comp.privileged) contextBoost += 5;

    const relevanceScore = Math.max(0, Math.min(100, Math.round(baseRisk * 0.7 + contextBoost)));

    results.push({
      threat,
      relevanceScore,
      reasons,
    });
  }

  results.sort((a, b) => b.relevanceScore - a.relevanceScore);
  return results;
}

// ---------------------------------------------------------------------------
// generateThreatModel(architecture) -> full STRIDE analysis
// ---------------------------------------------------------------------------
// architecture: {
//   name, components: [{type, name, trustLevel, exposedToInternet,
//     storesData, privileged, ...}],
//   dataFlows: [{source, destination, protocol, encrypted, authenticated,
//     crossesTrustBoundary, dataClassification, ...}],
//   trustBoundaries: [{name, description}]
// }

function generateThreatModel(architecture) {
  const arch = architecture || {};
  const components = Array.isArray(arch.components) ? arch.components : [];
  const dataFlows = Array.isArray(arch.dataFlows) ? arch.dataFlows : [];
  const trustBoundaries = Array.isArray(arch.trustBoundaries) ? arch.trustBoundaries : [];

  const threatsByCategory = { S: [], T: [], R: [], I: [], D: [], E: [] };
  const seen = new Map(); // threatId -> merged finding

  function record(component, flow, matched) {
    for (const m of matched) {
      const key = m.threat.id + "::" + (component ? component.name || component.type : "*") + "::" + (flow ? (flow.source || "") + "->" + (flow.destination || "") : "*");
      if (seen.has(key)) continue;
      seen.set(key, true);

      const finding = {
        id: m.threat.id,
        category: m.threat.category,
        categoryName: STRIDE_CATEGORIES[m.threat.category].name,
        name: m.threat.name,
        description: m.threat.description,
        severity: m.threat.severity,
        likelihood: m.threat.likelihood,
        impact: m.threat.impact,
        riskScore: calculateRisk(m.threat),
        relevanceScore: m.relevanceScore,
        reasons: m.reasons,
        mitigations: m.threat.mitigations,
        affectedComponent: component ? (component.name || component.type) : null,
        dataFlow: flow ? { source: flow.source, destination: flow.destination } : null,
      };

      threatsByCategory[m.threat.category].push(finding);
    }
  }

  if (components.length === 0 && dataFlows.length === 0) {
    // No architecture detail provided — fall back to reporting the entire
    // library as generically applicable, at base risk, so callers still
    // get a usable model.
    for (const threat of THREAT_LIBRARY) {
      threatsByCategory[threat.category].push({
        id: threat.id,
        category: threat.category,
        categoryName: STRIDE_CATEGORIES[threat.category].name,
        name: threat.name,
        description: threat.description,
        severity: threat.severity,
        likelihood: threat.likelihood,
        impact: threat.impact,
        riskScore: calculateRisk(threat),
        relevanceScore: calculateRisk(threat),
        reasons: ["No architecture detail supplied; showing generic library entry"],
        mitigations: threat.mitigations,
        affectedComponent: null,
        dataFlow: null,
      });
    }
  } else {
    for (const component of components) {
      const matched = analyzeThreat(component, {});
      record(component, null, matched);
    }

    for (const flow of dataFlows) {
      const sourceComponent = components.find((c) => c.name === flow.source) || { type: flow.sourceType };
      const destComponent = components.find((c) => c.name === flow.destination) || { type: flow.destinationType };

      record(sourceComponent, flow, analyzeThreat(sourceComponent, flow));
      record(destComponent, flow, analyzeThreat(destComponent, flow));
    }
  }

  // Sort each category's findings by risk score descending.
  for (const cat of Object.keys(threatsByCategory)) {
    threatsByCategory[cat].sort((a, b) => b.riskScore - a.riskScore || b.relevanceScore - a.relevanceScore);
  }

  const allFindings = Object.keys(threatsByCategory).reduce(
    (acc, cat) => acc.concat(threatsByCategory[cat]),
    []
  );

  // Risk matrix: likelihood (rows) x impact (columns) -> count of findings.
  const riskMatrix = {};
  for (const l of LEVEL_ORDER) {
    riskMatrix[l] = {};
    for (const i of LEVEL_ORDER) riskMatrix[l][i] = 0;
  }
  for (const f of allFindings) {
    const l = normalizeLevel(f.likelihood, LIKELIHOOD_WEIGHT);
    const i = normalizeLevel(f.impact, IMPACT_WEIGHT);
    riskMatrix[l][i] += 1;
  }

  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of allFindings) bySeverity[normalizeLevel(f.severity, SEVERITY_WEIGHT)] += 1;

  const byCategoryCount = {};
  for (const cat of Object.keys(threatsByCategory)) {
    byCategoryCount[STRIDE_CATEGORIES[cat].name] = threatsByCategory[cat].length;
  }

  const totalRisk = allFindings.reduce((sum, f) => sum + f.riskScore, 0);
  const averageRisk = allFindings.length ? Math.round(totalRisk / allFindings.length) : 0;

  const topRisks = allFindings
    .slice()
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 10);

  const summary = {
    architectureName: arch.name || "Unnamed Architecture",
    componentCount: components.length,
    dataFlowCount: dataFlows.length,
    trustBoundaryCount: trustBoundaries.length,
    totalThreats: allFindings.length,
    bySeverity,
    byCategory: byCategoryCount,
    averageRiskScore: averageRisk,
    highestRiskScore: allFindings.length ? topRisks[0].riskScore : 0,
    generatedAt: new Date().toISOString(),
    modelId: hashId((arch.name || "model") + JSON.stringify(components.map((c) => c.name)) + Date.now()),
  };

  return {
    architecture: {
      name: arch.name || "Unnamed Architecture",
      components,
      dataFlows,
      trustBoundaries,
    },
    threatsByCategory,
    allFindings,
    riskMatrix,
    topRisks,
    summary,
  };
}

// ---------------------------------------------------------------------------
// formatThreatReport(model) -> Markdown string
// ---------------------------------------------------------------------------

function pad(str, len) {
  str = String(str);
  return str.length >= len ? str.slice(0, len) : str + " ".repeat(len - str.length);
}

function riskBar(score) {
  const filled = Math.round((score / 100) * 20);
  return "#".repeat(filled) + "-".repeat(20 - filled);
}

function buildHeatMap(riskMatrix) {
  const cols = LEVEL_ORDER; // impact columns
  const rows = LEVEL_ORDER.slice().reverse(); // likelihood rows, high first

  let out = "";
  out += "```\n";
  out += "Likelihood \\ Impact   " + cols.map((c) => pad(c.toUpperCase(), 10)).join("") + "\n";
  out += "-".repeat(22 + cols.length * 10) + "\n";
  for (const l of rows) {
    out += pad(l.toUpperCase(), 22);
    for (const i of cols) {
      const count = riskMatrix[l] ? riskMatrix[l][i] || 0 : 0;
      const marker = count === 0 ? "." : String(count);
      out += pad(marker, 10);
    }
    out += "\n";
  }
  out += "```\n";
  return out;
}

function formatThreatReport(model) {
  if (!model || typeof model !== "object") {
    return "# STRIDE Threat Model Report\n\nNo model data provided.\n";
  }

  const summary = model.summary || {};
  const lines = [];

  lines.push("# STRIDE Threat Model Report");
  lines.push("");
  lines.push("Architecture: **" + (summary.architectureName || "Unnamed Architecture") + "**");
  lines.push("Model ID: `" + (summary.modelId || "n/a") + "`");
  lines.push("Generated: " + (summary.generatedAt || new Date().toISOString()));
  lines.push("");

  // Executive summary
  lines.push("## Executive Summary");
  lines.push("");
  lines.push("- Components analyzed: " + (summary.componentCount || 0));
  lines.push("- Data flows analyzed: " + (summary.dataFlowCount || 0));
  lines.push("- Trust boundaries: " + (summary.trustBoundaryCount || 0));
  lines.push("- Total threats identified: " + (summary.totalThreats || 0));
  lines.push("- Average risk score: " + (summary.averageRiskScore || 0) + " / 100");
  lines.push("- Highest risk score: " + (summary.highestRiskScore || 0) + " / 100");
  lines.push("");
  lines.push("Severity breakdown:");
  const sev = summary.bySeverity || {};
  lines.push("");
  lines.push("| Severity | Count |");
  lines.push("| --- | --- |");
  lines.push("| Critical | " + (sev.critical || 0) + " |");
  lines.push("| High | " + (sev.high || 0) + " |");
  lines.push("| Medium | " + (sev.medium || 0) + " |");
  lines.push("| Low | " + (sev.low || 0) + " |");
  lines.push("");

  // Threat matrix (top risks)
  lines.push("## Threat Matrix (Top Risks)");
  lines.push("");
  lines.push("| ID | Category | Threat | Severity | Likelihood | Impact | Risk Score |");
  lines.push("| --- | --- | --- | --- | --- | --- | --- |");
  const topRisks = Array.isArray(model.topRisks) ? model.topRisks : [];
  for (const f of topRisks) {
    lines.push(
      "| " + f.id + " | " + f.categoryName + " | " + f.name + " | " +
      f.severity + " | " + f.likelihood + " | " + f.impact + " | " + f.riskScore + " |"
    );
  }
  if (topRisks.length === 0) lines.push("| - | - | No threats identified | - | - | - | - |");
  lines.push("");

  // Per-category findings
  lines.push("## Findings by STRIDE Category");
  lines.push("");
  const threatsByCategory = model.threatsByCategory || {};
  for (const key of Object.keys(STRIDE_CATEGORIES)) {
    const cat = STRIDE_CATEGORIES[key];
    const findings = threatsByCategory[key] || [];
    lines.push("### " + cat.name + " (" + findings.length + " finding" + (findings.length === 1 ? "" : "s") + ")");
    lines.push("");
    lines.push(cat.description);
    lines.push("");
    if (findings.length === 0) {
      lines.push("No findings identified for this category.");
      lines.push("");
      continue;
    }
    for (const f of findings) {
      lines.push("- **" + f.name + "** (`" + f.id + "`, risk " + f.riskScore + "/100" +
        (f.affectedComponent ? ", component: " + f.affectedComponent : "") + ")");
      lines.push("  " + f.description);
      if (f.mitigations && f.mitigations.length) {
        lines.push("  Mitigations: " + f.mitigations.join("; "));
      }
    }
    lines.push("");
  }

  // Risk heat map
  lines.push("## Risk Heat Map");
  lines.push("");
  lines.push("Count of findings by likelihood x impact:");
  lines.push("");
  lines.push(buildHeatMap(model.riskMatrix || {}));

  lines.push("Risk score bars for top findings:");
  lines.push("");
  lines.push("```");
  for (const f of topRisks) {
    lines.push(pad(f.id, 14) + " [" + riskBar(f.riskScore) + "] " + f.riskScore + "/100");
  }
  lines.push("```");
  lines.push("");

  // Recommended mitigations, prioritized by risk
  lines.push("## Recommended Mitigations (Prioritized by Risk)");
  lines.push("");
  const allFindings = Array.isArray(model.allFindings) ? model.allFindings.slice() : [];
  allFindings.sort((a, b) => b.riskScore - a.riskScore);

  const mitigationRank = new Map();
  for (const f of allFindings) {
    for (const mit of f.mitigations || []) {
      const existing = mitigationRank.get(mit);
      if (!existing || f.riskScore > existing.riskScore) {
        mitigationRank.set(mit, { riskScore: f.riskScore, threatId: f.id, threatName: f.name });
      }
    }
  }

  const rankedMitigations = Array.from(mitigationRank.entries())
    .map(([mitigation, info]) => ({ mitigation, ...info }))
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 30);

  let priority = 1;
  for (const m of rankedMitigations) {
    lines.push(
      priority + ". " + m.mitigation + " (addresses `" + m.threatId + "` - " + m.threatName +
      ", risk " + m.riskScore + "/100)"
    );
    priority++;
  }
  if (rankedMitigations.length === 0) {
    lines.push("No mitigations to recommend; no threats identified.");
  }
  lines.push("");

  lines.push("---");
  lines.push("");
  lines.push("_Report generated by Darknode Nexus STRIDE threat modeling module._");
  lines.push("");

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Additional utility exports
// ---------------------------------------------------------------------------

function getThreatById(id) {
  return THREAT_LIBRARY.find((t) => t.id === id) || null;
}

function getThreatsByCategory(category) {
  const key = String(category || "").toUpperCase().slice(0, 1);
  return THREAT_LIBRARY.filter((t) => t.category === key);
}

function listComponentTypes() {
  const types = new Set();
  for (const t of THREAT_LIBRARY) {
    for (const c of t.affectedComponents) types.add(c);
  }
  return Array.from(types).sort();
}

module.exports = {
  STRIDE_CATEGORIES,
  THREAT_LIBRARY,
  analyzeThreat,
  generateThreatModel,
  calculateRisk,
  formatThreatReport,
  getThreatById,
  getThreatsByCategory,
  listComponentTypes,
  riskLevelFromScore,
};
