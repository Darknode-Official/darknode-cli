const assert = require("assert");
const { pLimit } = require("./limit.js");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
(async () => {
  const limit = pLimit(2);
  let active = 0, peak = 0;
  const job = (i) => limit(async () => { active++; peak = Math.max(peak, active); await sleep(20); active--; return i * 2; });
  const out = await Promise.all([1, 2, 3, 4, 5, 6].map(job));
  assert.deepStrictEqual(out, [2, 4, 6, 8, 10, 12]);
  assert.strictEqual(peak, 2, "peak concurrency must equal the limit");
  console.log("OK");
})().catch((e) => { console.error(e); process.exit(1); });
