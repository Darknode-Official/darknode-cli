"use strict";
// The whole conversation as plain text, for /find: what you asked, every answer,
// and each tool call WITH its output (the transcript only previews outputs, and
// /export lists tool names only). Pure: the host passes the transcript blocks
// and its tool-result-to-text function.
//
//   conversationText(transcript, asText) -> string
const { stripAnsi } = require("./tui-format");

function conversationText(transcript, asText) {
  const toText = asText || ((x) => (x == null ? "" : typeof x === "string" ? x : JSON.stringify(x, null, 2)));
  const out = [];
  const indent = (s) => String(s).replace(/\s+$/, "").split("\n").map((l) => "    " + l).join("\n");
  for (const m of transcript || []) {
    if (!m) continue;
    if (m.role === "user") out.push("❯ " + String(m.text || ""), "");
    else if (m.role === "nexus") {
      for (const it of m.items || []) {
        if (it.type === "text" && it.full) out.push(String(it.full).replace(/\s+$/, ""), "");
        else if (it.type === "tool") {
          out.push("● " + stripAnsi(String(it.label || it.name || "tool")) + (it.status === "err" ? "  (error)" : ""));
          const r = it.result !== undefined ? toText(it.result) : "";
          if (r.trim()) out.push(indent(r));
          out.push("");
        }
      }
    } else if (m.role === "system") {
      const t = m.text != null ? String(m.text) : Array.isArray(m.lines) ? m.lines.join("\n") : "";
      if (t.trim()) out.push(stripAnsi(t).replace(/\s+$/, ""), "");
    }
  }
  return out.join("\n").replace(/\n{3,}/g, "\n\n").trimEnd();
}

module.exports = { conversationText };
