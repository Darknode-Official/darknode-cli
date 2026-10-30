"use strict";
// Durable agent memory (a `remember` capability): merge a fact into NEXUS.md under
// a "## Remembered" section, with dedup so the same fact called twice doesn't stack.
// Pure — takes the current markdown, returns the new markdown + whether it changed.
//
// Dedup is an exact or leading match (case, punctuation and spacing ignored) against the bullets of
// the Remembered section only: substring matching against every bullet in the file
// dropped "run tests" because a convention said "Do not run tests on CI", and a note in
// a non-Latin script normalised to "" - a substring of everything.
function normalize(s) { return String(s || "").normalize("NFKC").toLowerCase().replace(/[^\p{L}\p{N}\s]+/gu, "").replace(/\s+/g, " ").trim(); } // \s, not " ": a tab was deleted, so "run\ttests" became "runtests" and never deduped
function mergeMemory(md, note) {
  const clean = String(note || "").trim().replace(/\s*[\r\n]+\s*/g, " "); // one bullet line: a later line would fall outside it, and a "#" line would end the section
  if (clean.length < 3) return { md, added: false, reason: "too short" };
  const target = normalize(clean) || clean;
  const lines = String(md || "").split("\n");
  const head = lines.findIndex((l) => /^##\s+Remembered\s*$/.test(l));
  if (head >= 0) {
    let end = lines.length; // the section runs to the next heading of level 1-2
    for (let i = head + 1; i < lines.length; i++) if (/^#{1,2}\s/.test(lines[i])) { end = i; break; }
    for (let i = head + 1; i < end; i++) {
      const m = lines[i].match(/^\s*[-*]\s+(.*)/);
      const other = m ? normalize(m[1]) || m[1].trim() : "";
      // same fact, or a shorter start of one already kept ("use the shared Table component" after
      // "... at src/Table.tsx") - never a match in the middle, which can flip the meaning
      if (other && (other === target || other.startsWith(target + " "))) return { md, added: false, reason: "already known" };
    }
    let at = end; while (at > head + 1 && !lines[at - 1].trim()) at--; // after the section's last non-blank line
    lines.splice(at, 0, "- " + clean);
    let out = lines.join("\n"); if (!out.endsWith("\n")) out += "\n";
    return { md: out, added: true };
  }
  let out = String(md || "");
  out += (out && !out.endsWith("\n") ? "\n" : "") + (out ? "\n" : "") + "## Remembered\n- " + clean + "\n";
  return { md: out, added: true };
}
module.exports = { mergeMemory, normalize };
