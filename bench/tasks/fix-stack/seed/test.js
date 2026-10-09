const assert = require("assert");
const { Stack } = require("./stack.js");
const s = new Stack();
s.push(1).push(2).push(3);
assert.strictEqual(s.peek(), 3);
assert.strictEqual(s.size, 3);   // peek must not remove
assert.strictEqual(s.pop(), 3);
assert.strictEqual(s.peek(), 2);
console.log("OK");
