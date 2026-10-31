"use strict";
// One line reader for a piped / redirected stdin.
//
//   makeLineReader(input) -> { next() -> Promise<string | null> }   (null once the input has ended)
//
// A readline interface per question (rl.question, then close) loses input when stdin is a pipe:
// the first interface buffers every line already sent and closing it throws them away, so
// `printf '/help\n/pins\n' | nexus` ran /help and dropped the rest. A single interface queues them.
const readline = require("readline");

function makeLineReader(input) {
  const lines = [], waiters = [];
  let ended = false, r = null;
  const start = () => {
    if (r) return;
    r = readline.createInterface({ input, terminal: false });
    r.on("line", (l) => { const w = waiters.shift(); if (w) w(l); else lines.push(l); });
    r.on("close", () => { ended = true; while (waiters.length) waiters.shift()(null); });
  };
  return {
    next() {
      start();
      if (lines.length) return Promise.resolve(lines.shift());
      if (ended) return Promise.resolve(null);
      return new Promise((res) => waiters.push(res));
    },
  };
}

module.exports = { makeLineReader };
