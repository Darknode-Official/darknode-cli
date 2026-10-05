# NX-005 — Security Capability Inventory (for approval)

> Status: **awaiting owner approval before any new-capability implementation**
> (per NX-005: "Submit the inventory for approval before implementation").
> Date: 2026-10-04. Measured against branch `feat/nexus-coding-agent`.

Each row: **source** (where the capability comes from), **capability**, **why it
belongs in an agentic runtime** (vs. a one-shot tool invocation), and the
**measurement** that would show it working. Per NX-005, no capability ships
without a measured **false-positive rate** on a ground-truth corpus — that corpus
is the NX-008 harness, which does not yet have a baseline. So every "measurement"
below is a target the harness must produce, not a number we already have.

Legend: **[E]** exists in the tree today · **[P]** partial · **[G]** gap to build.

---

## A. Code & dependency analysis

| # | Source | Capability | Why agentic | Measurement |
|---|--------|-----------|-------------|-------------|
| A1 [E] | `lib/governance/security.js scanSecrets`, `lib/nexus/git-security.js` | Secret detection in code + git history | The agent reads a repo as part of a task; detection must gate what enters prompts/writes, not be a separate run | TP/FP on a corpus of planted + decoy secrets; target FP < 5% |
| A2 [E] | `lib/nexus/deps.js` | Dependency hygiene: unused + undeclared imports vs package.json | Feeds the agent's plan (what it may import) mid-task | Precision/recall on repos with known unused/undeclared deps |
| A3 [P] | `lib/nexus/code-radar.js`, `capindex.js` | Static findings / dead-code / tech-debt + a capability index | Lets the agent reason about blast radius before editing | Agreement vs. a labelled findings set; FP rate |
| A4 [G] | *new* | **Software composition analysis**: resolve the dependency tree to versions and map to known CVEs | A one-shot scanner restates CVEs; the agent must reason **reachability** (is the vulnerable symbol actually called?) and **exploitability** (is the path reachable with attacker-controlled input?) before it proposes a fix | TP/FP vs. a corpus with known-reachable and known-unreachable CVEs; report reachability accuracy separately |
| A5 [G] | *new* | **Vulnerability-to-fix**: propose the remediation as a reviewable diff, then run the project's tests | The value is the verified fix, not the finding — exactly the agent loop (NX-004) | % of proposed fixes that build + pass existing tests; regression rate |

## B. Configuration review

| # | Source | Capability | Why agentic | Measurement |
|---|--------|-----------|-------------|-------------|
| B1 [G] | *new* | **IAM / access-policy review** (cloud IAM, RBAC docs, k8s RBAC) | The agent correlates a policy with how the repo *uses* it (over-grant vs. actual need) — impossible from the policy file alone | TP/FP on a corpus of over-permissive vs. least-privilege policies |
| B2 [G] | *new* | **Container & orchestration settings** (Dockerfile, compose, k8s manifests): root user, caps, host mounts, `:latest`, missing limits | Found while the agent reads the repo; findings feed a remediation diff | TP/FP vs. labelled manifests (e.g. KICS/Checkov ground truth) |
| B3 [G] | *new* | **CI/CD pipeline permissions** (GH Actions `permissions:`, untrusted `pull_request_target`, unpinned actions, secret exposure in logs) | The agent already edits CI (`project-bootstrap.js`); it should review what it writes | TP/FP on a corpus of known-vulnerable workflow files |
| B4 [P] | `lib/nexus/vuln-scanner.js` | **Network policy / exposure**: security headers, TLS, DNS config (live) | Real network observation drives the next recon step | TP/FP vs. sites with known header/TLS posture |

## C. Authorized testing workflow (strictly under NX-002)

| # | Source | Capability | Why agentic | Measurement |
|---|--------|-----------|-------------|-------------|
| C1 [E] | `lib/governance/authorization.js`, `engagement-gate.js` | Scoped target definition + signed authorization + fail-closed gate | Every active step is checked at execution against the signed scope | Red-team escape rate (NX-002 suite) — target 0 |
| C2 [E/P] | `scan`,`dns`,`subs`,`fuzz`,`nmap`,`nuclei` + `pentest-engine.js` | Collection + finding generation | The agent sequences collection→validation, observing real output | Coverage vs. a target with known exposed services |
| C3 [G] | *new* | **Finding validation + reproduction**: re-test each finding, attach reproduction steps, drop non-reproducing ones | Unvalidated findings are the category's #1 failure mode (NX-005); only an agent that re-observes can validate | **FP rate after validation** on a corpus with ground truth — the gate for shipping |
| C4 [P] | `report-generator.js`, `lib/governance/compliance.js` | Remediation proposed as a reviewable diff | Closes the loop: the deliverable is a verified change | % remediations that apply + pass tests |

## D. Reporting

| # | Source | Capability | Why agentic | Measurement |
|---|--------|-----------|-------------|-------------|
| D1 [E/P] | `report-generator.js`, `reporting.js`, `compliance.js` | Severity, impact, evidence, reproduction, remediation; hash/HMAC-signed bundle | The agent assembles evidence it actually observed, separating verified from inferred (NX-009) | Rubric score by 2 raters on a sample; inter-rater agreement; % claims with attached evidence |

---

## Proposed build order (smallest verifiable increments)
1. **C3 finding-validation** — highest leverage; it is the FP-rate gate the whole
   category lives or dies on. Build first, measured on NX-008.
2. **A4/A5 SCA + reachability + verified fix** — the clearest "agent, not scanner"
   differentiator; measured reachability accuracy + fix pass-rate.
3. **B2/B3 container & CI/CD config review** — high-signal, deterministic ground
   truth available (Checkov/KICS corpora), so FP rates are cheap to measure.
4. **B1 IAM review** — hardest ground truth; last.

## What is explicitly NOT proposed
- No absorbing the feature list of every security product (NX-005 method
  constraint). Each item above earns its place by the agent-loop rationale.
- No offensive capability beyond what the signed-authorization gate already
  guards; no exploitation/malware/evasion.

## Blocking dependency
Every measurement here requires the **NX-008 harness + a ground-truth corpus**.
Until that baseline exists, these capabilities cannot be *shipped* (a capability
without a measured FP rate is not shipped, per NX-005) — only built against the
harness. Approve this inventory (or amend it) and confirm the build order before
implementation begins.
