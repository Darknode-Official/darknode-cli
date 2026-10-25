"use strict";
// What to do when a local/API model replies with something that is not the
// {thought, action, tool, args, final} JSON protocol. Show the model what it
// sent and ask once more; if it answers in prose again, that prose IS its
// answer — the caller shows it and stops. (Retrying blindly spun thousands of
// requests a minute with nothing on screen, and threw the answer away.)

const FIX = "That was not the required JSON. Reply with ONE JSON object only: {\"thought\":\"...\",\"action\":\"tool\",\"tool\":\"<name>\",\"args\":{...}} or {\"thought\":\"...\",\"action\":\"final\",\"final\":\"<your answer>\"}";

// st = { bad: 0 } per loop; reset st.bad = 0 after every valid reply.
// Returns { stop: false } (retry; correction already pushed onto messages) or
// { stop: true, answer: string|null } (answer null = nothing usable to show).
function badProtoReply(raw, messages, st) {
  const prose = String(raw == null ? "" : raw).trim();
  if (++st.bad >= 2) return { stop: true, answer: prose && !/^[[{]/.test(prose) ? prose : null };
  if (prose) messages.push({ role: "assistant", content: prose.slice(0, 2000) });
  messages.push({ role: "tool", content: FIX });
  return { stop: false };
}

// Reply was JSON but named no tool (action "tool" without tool, or an unknown action).
function missingTool(o, messages, st) {
  if (++st.bad >= 3) return { stop: true };
  messages.push({ role: "tool", content: o && o.action === "tool" ? "Missing \"tool\": name the tool to call (e.g. read_file, search, run_command) and put its arguments in args." : "action must be \"tool\" (with tool + args) or \"final\" (with final: your answer)." });
  return { stop: false };
}

const GAVE_UP = "(the model kept replying in a format Nexus can't use — try again, or switch model with /model)";

module.exports = { badProtoReply, missingTool, FIX, GAVE_UP };
