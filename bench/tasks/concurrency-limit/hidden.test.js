const assert = require("assert");
const { pLimit } = require("./limit.js");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
(async () => {
  const limit = pLimit(1);
  const r = await Promise.allSettled([
    limit(async () => { await sleep(10); throw new Error("boom"); }),
    limit(() => { throw new Error("sync boom"); }),
    limit(async () => "after"),
  ]);
  assert.strictEqual(r[0].status, "rejected");
  assert.strictEqual(r[1].status, "rejected");
  assert.deepStrictEqual(r[2], { status: "fulfilled", value: "after" });
  const l3 = pLimit(3); let active = 0, peak = 0;
  await Promise.all(Array.from({ length: 20 }, (_, i) => l3(async () => { active++; peak = Math.max(peak, active); await sleep(i % 3 * 5); active--; })));
  assert.strictEqual(peak, 3);
  console.log("HIDDEN OK");
})().catch((e) => { console.error(e); process.exit(1); });
