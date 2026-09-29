# Authorization & scope gate

Under concierge delivery Darknode operates the tooling itself, so nothing may run
against an environment without a **signed, in-scope, in-window written authorization**.
Unauthorized access is a criminal matter (CFAA / Computer Misuse Act), not a policy
preference. This gate is the enforcement point and the evidence trail.

## What is enforced

`DARKNODE_ENGAGEMENT=<id>` puts `darknode` in **engagement mode**. In that mode:

- Only tools in the gated registry run (`engagement-gate.js` `TOOLS`): `scan headers cert dns whois ipinfo subs subrecon fuzz nmap nuclei`.
  Everything else that touches the network or spawns things (`nexus`, `api`, `serve`, `listen`, `git`, `setup`, the interactive menu, `sentinel.js`) is refused. Offline helpers (hash, encode, cheat sheets…) still work. It is an allow-list.
- Before each run the gate checks, and **denies on any failure**:
  1. a signed authorization exists for the engagement, signed by a key in `authorizers.json`
  2. the record is valid (client signatory, agreement ref + sha256 of the signed PDF, asset-ownership attestation, window, emergency contact, ≥1 scope entry, permitted action classes)
  3. not revoked; `now` inside `[notBefore, notAfter)`; agreement `signedAt` not in the future
  4. the tool's action class (`recon < scan < vuln-scan < exploit`) is permitted by the record
  5. **every** target is covered by an in-scope entry and touches no out-of-scope entry
  6. the audit entry was written (no audit → no run)
- Tool arguments are parsed against a per-tool **flag allow-list**; unknown flags are denied (this blocks `-iL hosts.txt`, `--script`, `--resolve`, `-l list`, `-H Host:` and similar target smuggling). All targets in argv are checked, not just the first.
- `nmap` / `nuclei` are spawned by the gate (no shell). A watchdog re-evaluates every 2 s and kills the tool on revocation or window close.
- `headers` never follows redirects in engagement mode; `subrecon` drops discovered subdomains that are out of scope before probing them.

## Scope record

Entries: `203.0.113.5`, `203.0.113.0/28` (broader than /16 refused), `app.example.com` (exact host),
`*.example.com` (subdomains only — **not** the apex), `https://api.example.com/v1` (host + path prefix).
`outOfScope` always wins and matches on *overlap* (a /24 target containing an excluded IP is denied; excluding a host excludes its subdomains).
A domain entry does not authorize its IPs and vice versa. Decimal/hex/octal IP obfuscation is normalised before matching. IPv6 is refused in v1. Ports are not part of scope in v1.

## Operator flow

```
darknode authz keygen auth-1                       # authorizer, once; private key stays offline
darknode authz trust auth-1 auth-1.public.pem      # on each engagement host / image
darknode authz template <engagement-id> > rec.json # fill from the signed partner agreement
darknode authz sign rec.json --key auth-1.private.pem --key-id auth-1
darknode authz install rec.signed.json
darknode authz status <engagement-id>
DARKNODE_ENGAGEMENT=<id> darknode scan app.example.com 1-1024
darknode authz run <id> -- nmap -sT -T4 app.example.com
darknode authz check <id> nmap -sT app.example.com # dry-run, audited
darknode authz revoke <id> --reason "client asked us to stop"
darknode authz log <id> --verify
```

The signer is the person who has verified the countersigned agreement; **the gate only verifies, it never signs**, and engineers do not hold the authorizer key.

## Audit trail

`~/.darknode/engagements/<id>/audit.jsonl` — sha256 hash chain (same format as `.nexus/audit.jsonl`), written under a file lock. Records installs, every allow **and deny** (operator, host, tool, argv, class, targets, matched scope entry, record digest), exec end, watchdog kills, revocations, discovered-host filtering. Verify with `authz log <id> --verify`. Record the chain head in the engagement ticket at start/end — a chain proves internal consistency, not that the whole file wasn't rewritten.

## Limits (be honest about them)

- The process gate is a **guardrail and evidence layer, not a security boundary against a malicious operator**: `DARKNODE_ENGAGEMENT` can be unset, and someone with write access to `~/.darknode` can add their own trusted key. The boundary must be the per-engagement VM (T3): bake `DARKNODE_ENGAGEMENT`, a read-only `authorizers.json`, and an egress allow-list generated from the same scope record; no other tooling on the image.
- Tools that follow redirects or resolve names themselves (nuclei templates, nmap NSE — not enabled) can reach hosts the gate did not see. Egress filtering is the backstop.
- A hostname in scope may resolve to third-party infrastructure (CDN, cloud). The record's `assetOwnership.thirdPartyConsents` is where that consent must be captured; the gate does not verify it.
- Standalone (non-engagement) use of the CLI is unchanged and ungated; the existing responsible-use rule applies.
