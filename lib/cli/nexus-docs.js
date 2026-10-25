"use strict";
// ============================================================================
// nexus-docs — the Nexus reference the AI reads when the user asks about Nexus
// itself ("what does /warm do?", "how do I open an agent?"). Built from the
// SAME data the TUI uses (the slash-command menu, the /help and /keys tables,
// the /docs topics), so it can never drift from the real commands. Pure: the
// host passes the data in; docs/NEXUS-COMMANDS.md is generated from it too
// (scripts/gen-nexus-docs.js).
//
// Token cost: the reference is attached to a turn ONLY when isNexusQuestion()
// says the message is about Nexus — ordinary coding prompts never carry it.
// ============================================================================

// How the interactive parts behave — things a command list can't convey.
const GUIDE = [
  ["What Nexus is", [
    "Nexus is a terminal AI coding agent (the `nexus` / `darknode nexus` command). It drives one of six engines behind one interface: claude (Claude Code), gemini, codex, opencode, aider, or ollama (local, free, offline). Switch with /engine, pick a model with /model.",
    "Every engine gets the same slash commands, cost tracking, checkpoints and safety guard. Project instructions live in .nexus/NEXUS.md and are given to every engine.",
  ]],
  ["Sending, queueing, interrupting", [
    "Enter sends. While a turn is running, Enter QUEUES the prompt (shown as '· queued'); Ctrl+X or Ctrl+S sends it now and interrupts the current turn.",
    "Esc interrupts a running turn. If nothing was produced yet, the prompt is put back in the composer to edit and resend.",
    "Esc Esc (after a turn) rewinds: undoes that turn's file changes and puts the prompt back; /redo re-applies.",
  ]],
  ["Modes (Shift+Tab cycles)", [
    "normal / accept edits — the agent edits files and runs commands, subject to the /guard danger check and your /allow and /deny rules · plan — the prompt asks for a plan only and file/system-changing tools are blocked · bypass — also waives the destructive-command guard (use with care). The mode is remembered between sessions (bypass never is).",
  ]],
  ["Input prefixes", [
    "/command runs a Nexus command (type / to browse; Tab completes) · @path attaches a file or image (Tab completes) · !cmd runs a shell command and gives the output to the AI · #note saves a note to .nexus/NEXUS.md memory.",
    "Pasting an image path or attaching one with @ shows 'attached N image(s)' and sends it to the model (needs a vision-capable model on local engines).",
  ]],
  ["Side panel and /btw (never added to the conversation)", [
    "/btw <question> asks a quick side question answered from the conversation so far. It opens a framed card and is NOT saved to the chat history.",
    "/pager opens the newest tool output in full inside the TUI (the transcript only previews it): j/k or arrows scroll, space/b page, g/G jump to top/end, / searches (smart case), n/N step through matches, q closes. /pager 2 opens the one before; /pager answer pages the last answer. /less is the same command.",
    "In the card: type a follow-up and press Enter to ask it · Enter or Esc on an empty field closes · Esc clears a typed follow-up · Left/Right step through earlier side answers · Up/Down, PgUp/PgDn and the mouse wheel scroll · Ctrl+Y copies the answer · Ctrl+X forgets all side questions. /btw with no question reopens the last one.",
    "Read-only lookups open in the same card instantly, even mid-turn, without touching the chat: SIDE_COMMANDS.",
  ]],
  ["Agents panel and agent conversations", [
    "Sub-agents (Claude Task agents, /agents a ;; b, local spawn_agents) appear in the agents panel under the prompt with status (running/done/failed/stopped) and time. Finished agents stay listed until you clear them.",
    "Press Down on an empty prompt to focus the panel · Up/Down move · Enter, Right or a digit opens that agent · s stops a running agent · x clears finished agents · Esc returns to the prompt.",
    "Opening an agent shows its full conversation like the main chat: its brief, its own messages, thinking and tool calls with results, and a live 'working' line while it runs. Up/Down, PgUp/PgDn, the wheel scroll · Home = its brief, End = latest · Left/Right switch agent · s stops it · Ctrl+Y copies its result · Esc (or Enter/q) goes back to the list with the same agent selected.",
    "A Claude sub-agent's messages appear only in its own view, not in the main reply.",
  ]],
  ["Cost and tokens", [
    "The status bar shows context use and, on the claude engine, the prompt-cache countdown ('cache 4m'). /cost is exact list-price cost, /turns the per-turn ledger, /tokens the breakdown, /warm the cache countdown with warm-vs-cold follow-up cost, /cheaper lossless ways to spend less.",
    "/cheap turns on lossless savings only (no quality loss). Limiting features (budget cap, auto-compact) are OFF by default; toggles you set are remembered in ~/.nexus/settings.json.",
  ]],
  ["Checkpoints and safety", [
    "A git checkpoint is taken before every file-changing turn: /undo, /redo, /rewind N, /checkpoints. Only files Nexus changed are restored.",
    "File tools are confined to the project folder; secrets are blocked from being written; destructive shell commands are checked by /guard; .nexus/permissions.json holds allow/deny rules (/allow, /deny, /perms) and .nexus/policy.json the security policy.",
  ]],
  ["Your own commands", [
    "/alias name = text|/cmd makes a shortcut (saved in ~/.nexus/settings.json) · /feature create <name> <what it does> adds a project command · .nexus/commands/*.md are custom /commands whose body is the prompt ($ARGUMENTS is substituted) · /commands lists them.",
  ]],
];

const clean = (s) => String(s == null ? "" : s).replace(/\x1b\[[0-9;]*m/g, "");

// buildReference({ cmds, help, keys, side, topics, topicOrder, custom, brief }) -> markdown
//   brief  true → the copy sent to the model: skips the /help groups and topic
//          guides (they repeat the command list) to keep the tokens down
//   cmds   [[name, desc]]            the slash-command menu
//   help   [{ title, rows:[[k,v]] }] the /help sections   keys  same shape (/keys)
//   side   [name]                    commands that open in the side panel
//   topics { key: { title, body } }  the /docs topics      custom [[name, desc]]
function buildReference(d) {
  d = d || {};
  const side = (d.side || []).slice().sort();
  const out = ["# Nexus reference", "", "How Nexus works and every command it has. Generated from the live command tables — do not edit by hand.", ""];
  out.push("## How it works", "");
  for (const [title, paras] of GUIDE) {
    out.push("### " + title, "");
    for (const p of paras) out.push(p.replace("SIDE_COMMANDS", side.join(" ")), "");
  }
  out.push("## All commands", "");
  const seen = new Set();
  for (const [n, desc] of (d.cmds || [])) { if (seen.has(n)) continue; seen.add(n); out.push("- `" + n + "` — " + clean(desc) + (side.includes(n) ? " (opens in the side panel)" : "")); }
  out.push("");
  if (d.custom && d.custom.length) { out.push("## This project's custom commands", ""); for (const [n, desc] of d.custom) out.push("- `" + n + "` — " + clean(desc)); out.push(""); }
  for (const [label, secs] of [["Command groups (/help)", d.brief ? null : d.help], ["Keyboard shortcuts (/keys)", d.keys]]) {
    if (!secs || !secs.length) continue;
    out.push("## " + label, "");
    for (const s of secs) { out.push("### " + s.title, ""); for (const [k, v] of s.rows || []) out.push("- `" + k + "` — " + clean(v)); out.push(""); }
  }
  if (d.topics && !d.brief) {
    out.push("## Topic guides (/docs <topic>)", "");
    for (const k of (d.topicOrder || Object.keys(d.topics))) { const t = d.topics[k]; if (!t) continue; out.push("### " + t.title + " (`/docs " + k + "`)", "", "```", clean(t.body), "```", ""); }
  }
  return out.join("\n").replace(/\n{3,}/g, "\n\n").trimEnd() + "\n";
}

// Is this message a question about Nexus itself? Conservative on purpose: the
// reference costs tokens, so ordinary coding prompts must never trigger it.
const ASK_RE = /\?|\b(how|what|which|where|when|why|can i|could i|is there|are there|does|do i|explain|show me|tell me|list|help)\b/i;
const NEXUS_TOPIC_RE = /\b(slash commands?|keyboard shortcuts?|key ?bindings?|hot ?keys?|shortcuts? (in|for) (nexus|here|this))\b/i;
function isNexusQuestion(text, cmdNames) {
  const t = String(text || "");
  if (!t.trim() || t.length > 2000) return false;               // a long prompt is a task, not a question about the tool
  if (/^\s*\//.test(t)) return false;                              // a command itself, not a question
  const asks = ASK_RE.test(t);
  if (!asks) return false;
  if (/\bnexus\b/i.test(t)) return true;
  if (NEXUS_TOPIC_RE.test(t)) return true;
  const names = cmdNames instanceof Set ? cmdNames : new Set(cmdNames || []);
  const m = t.match(/(^|[\s"'`(])\/[a-z][a-z0-9:-]*/gi) || [];
  return m.some((x) => names.has(x.trim().replace(/^["'`(]/, "").toLowerCase()));
}

// The block prepended to the user's message on a Nexus question.
function forPrompt(ref) {
  return "[Nexus reference — the user is asking about Nexus, the terminal app you are running inside. Answer from this reference; do not invent commands or keys that are not listed. Use it only for this question.]\n"
    + ref + "\n[End of Nexus reference. The user's message:]\n";
}

// Search the reference for /docs <query>: lines containing every query word,
// with the heading they sit under. Returns [] when nothing matches.
function search(ref, query) {
  const words = String(query || "").toLowerCase().split(/\s+/).filter(Boolean).map((w) => { const st = w.length > 3 && /y$/.test(w) ? w.slice(0, -1) : w; return new RegExp("\\b" + st.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "(?:s|es|ies|ed|ing)?\\b"); }); // whole words; copy ~ copies, agent ~ agents
  if (!words.length) return [];
  const hits = []; let head = "", lastHead = null, inFence = false;
  for (const ln of String(ref).split("\n")) {
    if (/^```/.test(ln)) { inFence = !inFence; continue; }
    if (!inFence && /^#{1,3} /.test(ln)) { head = ln.replace(/^#+ /, ""); continue; }
    if (!ln.trim()) continue;
    const l = ln.toLowerCase();
    if (words.every((w) => w.test(l))) { if (head !== lastHead) { hits.push("## " + head); lastHead = head; } hits.push(ln); }
  }
  return hits;
}

module.exports = { GUIDE, buildReference, isNexusQuestion, forPrompt, search };
