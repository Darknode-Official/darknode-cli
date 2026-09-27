class Stack {
  constructor() { this.items = []; }
  push(x) { this.items.push(x); return this; }
  pop() { if (!this.items.length) throw new Error("empty"); return this.items.pop(); }
  peek() { return this.items[this.items.length]; } // BUG: off-by-one -> undefined
  get size() { return this.items.length; }
}
module.exports = { Stack };
