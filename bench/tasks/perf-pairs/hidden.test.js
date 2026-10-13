const assert = require("assert");
const { countPairs } = require("./pairs.js");
assert.strictEqual(countPairs([-1, 1, 0, 0, 2, -2], 0), 3);
assert.strictEqual(countPairs([5], 10), 0);
assert.strictEqual(countPairs([], 0), 0);
assert.strictEqual(countPairs([3, 3, 3, 3], 6), 6);
console.log("HIDDEN OK");
