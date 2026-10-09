const { add } = require("./math.js");
function total(nums) { return nums.reduce((a, b) => add(a, b), 0); }
module.exports = { total };
