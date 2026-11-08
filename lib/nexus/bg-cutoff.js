"use strict";
// bg-cutoff — notices when Claude Code ends a Nexus turn while its background agents are
// still working. Nexus runs the claude engine one message at a time (`claude -p`). After
// Claude's reply ends, that process keeps its background agents running for a while
// (about 10 minutes) and then exits, and the agents stop mid-task. Before this, the turn
// just ended and the agents were shown as done, so it looked like Nexus cut out at random.
//
// The tracker reads the same stream-json events runClaudeStream parses: once a `result`
// arrives (the reply is over), any further event from a sub-agent (parent_tool_use_id set)
// means background work is in flight; a new `result` clears it (Claude picked the work up
// again). If the process then closes, that work was cut off.

const RESUME_LIMIT = 6; // automatic resumes per message the user typed

function createBgTracker() {
  let afterResult = false;
  const live = new Set();
  return {
    event(ev) {
      if (!ev || typeof ev !== "object") return;
      if (ev.type === "result") { afterResult = true; live.clear(); return; }
      if (!afterResult) return;
      const pid = ev.parent_tool_use_id;
      if (pid && (ev.type === "assistant" || ev.type === "user" || ev.type === "stream_event")) live.add(pid);
    },
    // -> number of sub-agents that were still working when the process closed (0 = none)
    cut() { return live.size; },
  };
}

// Told to the model on every claude-engine turn, so long work is not started in a way
// that dies with the process.
const HOST_NOTE = "Host note (Nexus): each message runs as a separate `claude -p` session. " +
  "Background agents and background commands are stopped about 10 minutes after your reply ends, even mid-task. " +
  "For work that takes longer: run the agents in the foreground (run_in_background: false) and stay in the turn until they finish, " +
  "or start them as Nexus background sessions with the mcp__nexus__sessions tool (action=spawn, then wait), which keep running between messages. " +
  "Have long jobs save progress as they go so a stopped job can resume.";

function resumePrompt(n) {
  return "Your " + (n === 1 ? "background agent was" : n + " background agents were") +
    " stopped mid-task because the previous session ended (Claude Code stops background work about 10 minutes after a reply). " +
    "Check what each one finished, then continue the unfinished work. Prefer foreground agents (run_in_background: false) so this session stays open until they are done.";
}

module.exports = { createBgTracker, HOST_NOTE, resumePrompt, RESUME_LIMIT };
