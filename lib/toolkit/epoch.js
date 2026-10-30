"use strict";
// Timestamp converter — unix epoch <-> ISO/UTC, both directions, auto-detecting the
// input. Deterministic (UTC, no wall-clock), so it's fully testable.

// Detect the input: all-digits -> epoch (10-digit-ish = seconds, 12+ = milliseconds);
// otherwise parse as a date string. Returns { kind, ms } or null.
function detect(input) {
  const s = String(input || "").trim();
  // Signed and fractional epochs too: "-1" used to fall through to Date.parse, which reads it as
  // a YEAR (2001-01-01 here), not 1969-12-31T23:59:59Z.
  const e = /^-?(\d+)(?:\.\d+)?$/.exec(s);
  if (e) { const n = Number(s); return { kind: "epoch", ms: e[1].length >= 12 ? Math.trunc(n) : Math.round(n * 1000) }; }
  // An ISO date-time with no zone is LOCAL time to Date.parse; read it as UTC as documented.
  const t = Date.parse(/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?$/.test(s) ? s.replace(" ", "T") + "Z" : s);
  if (!Number.isNaN(t)) return { kind: "date", ms: t };
  return null;
}
// Convert any accepted input to a normalized set of representations, or null.
function convert(input) {
  const d = detect(input);
  if (!d) return null;
  const dt = new Date(d.ms);
  if (Number.isNaN(dt.getTime())) return null; // oversized epoch (> ±8.64e15) — out of the JS Date range; honor the "null on bad input" contract instead of throwing on toISOString()
  return { from: d.kind, epochSeconds: Math.floor(d.ms / 1000), epochMs: d.ms, iso: dt.toISOString(), utc: dt.toUTCString() };
}
module.exports = { detect, convert };
