"use strict";
// ============================================================================
// hub/status — is a background session working, blocked or idle?
//
//   working  the program is producing output (or Nexus says it is mid-turn)
//   blocked  it stopped and is waiting for a person: a permission prompt, a
//            yes/no question, an ask_user popup
//   idle     it is waiting for the next prompt
//   done     the process exited
//
// Nexus reports its own state exactly (hub/report.js), so a fresh report wins.
// Other agents (Claude Code, Codex, OpenCode, Gemini, a shell) are read from the
// screen: recent output means working; otherwise the bottom of the screen is
// checked for a question. Pure: the caller passes the clock and the screen text.
// ============================================================================

const QUIET_MS = 1500;      // no output for this long = the program has stopped
const REPORT_TTL = 15000;   // a Nexus report is trusted this long without a refresh

// Prompts that mean "a person has to answer before I continue". A menu with a highlighted
// first choice (the agent permission dialogs) counts anywhere in the last few lines; a
// one-line question only when it is the last line (where the cursor waits), so a question that was
// already answered and has output under it does not keep the session marked blocked.
const MENU = [
  /^\s*[│|]?\s*[❯>›]\s*1[.)]\s*(yes|allow|approve|proceed|run)/im,
];
const QUESTION = [
  /\bdo you want to (proceed|continue|make this edit|create|run|allow|apply|overwrite)/i,
  /\b(allow|approve|permit|trust)\b[^\n]{0,80}\?/i,
  /\((y\/n)\)|\[(y\/n|y\/N|Y\/n)\]|\(yes\/no\)/,
  /\bpress enter to (continue|confirm)/i,
  /\bwaiting for (your )?(input|approval|confirmation|answer)/i,
];

function asking(screenTail) {
  const lines = String(screenTail || "").split("\n").filter((l) => l.trim());
  const menu = lines.slice(-8).join("\n"), last = lines.slice(-1).join("\n");
  return MENU.some((re) => re.test(menu)) || QUESTION.some((re) => re.test(last));
}

// s: { exited, lastOutputAt, report: { state, at } | null, fgJob, tail }
function classify(s, now) {
  if (!s) return "idle";
  if (s.exited) return "done";
  const r = s.report;
  if (r && (r.state === "working" || r.state === "blocked" || r.state === "idle") && now - r.at < REPORT_TTL) return r.state;
  if (s.fgJob) return "working"; // a shell is running a command in the foreground (quiet or not)
  if (s.lastOutputAt && now - s.lastOutputAt < QUIET_MS) return "working";
  return asking(s.tail) ? "blocked" : "idle";
}

// What `wait --until` accepts. "stopped" = anything but working (the usual thing an
// agent wants: wait until the other one needs me or is finished).
const WAIT_STATES = new Set(["blocked", "idle", "done", "stopped", "working"]);
function reached(state, until) {
  const want = Array.isArray(until) ? until : String(until || "stopped").split(/[,|]/).map((x) => x.trim()).filter(Boolean);
  return want.some((w) => w === state || (w === "stopped" && state !== "working"));
}

module.exports = { classify, asking, reached, WAIT_STATES, QUIET_MS, REPORT_TTL };
