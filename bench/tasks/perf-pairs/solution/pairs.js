function countPairs(nums, target) {
  const seen = new Map(); let c = 0;
  for (const x of nums) { c += seen.get(target - x) || 0; seen.set(x, (seen.get(x) || 0) + 1); }
  return c;
}
module.exports = { countPairs };
