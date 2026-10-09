const { add, multiply } = require("./math.js");
function total(nums) { return nums.reduce((a, b) => add(a, b), 0); }
function product(nums) { return nums.reduce((a, b) => multiply(a, b), 1); }
module.exports = { total, product };
