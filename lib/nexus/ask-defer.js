"use strict";
// ask-defer — ask_user for external engines without a blocking wait. The model's
// ask_user call returns at once with DEFERRED_NOTE, so the model ends its turn and
// nothing spends tokens or times out while the question waits. The popup stays on
// screen until the user answers (no expiry); the answer is then sent as the user's
// next ordinary message in the same session. Dismissing it sends nothing.

const DEFERRED_NOTE =
  "Your question is now on the user's screen. End your turn now: no more tool calls and no closing text. " +
  "The user's answer will arrive as their next message.";

const QMAX = 300;
// The message sent once the user answers. Short: it is billed as input on the next turn.
function answerPrompt(question, answer) {
  const q = String(question || "").replace(/\s+/g, " ").trim();
  const qq = q.length > QMAX ? q.slice(0, QMAX - 1) + "…" : q;
  return "Answer to your question \"" + qq + "\": " + String(answer);
}

// The answer text from a normalized bridge answer, or null when the user dismissed it.
function answerText(r) {
  if (!r || r.cancelled || r.skipped) return null;
  const a = r.selected != null ? [].concat(r.selected).join(", ") : r.answer;
  return a == null || String(a) === "" ? null : String(a);
}

module.exports = { DEFERRED_NOTE, answerPrompt, answerText };
