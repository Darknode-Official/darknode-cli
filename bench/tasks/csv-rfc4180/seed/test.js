const assert = require("assert");
const { parseCSV } = require("./csv.js");
assert.deepStrictEqual(parseCSV("a,b\n1,2\n"), [["a", "b"], ["1", "2"]]);
assert.deepStrictEqual(parseCSV('x,"hello, world"\n'), [["x", "hello, world"]]);
assert.deepStrictEqual(parseCSV('q,"say ""hi"""'), [["q", 'say "hi"']]);
assert.deepStrictEqual(parseCSV("a,b\r\nc,d\r\n"), [["a", "b"], ["c", "d"]]);
console.log("OK");
