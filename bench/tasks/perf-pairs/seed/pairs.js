function countPairs(nums, target) {
  let c = 0;
  for (let i = 0; i < nums.length; i++)
    for (let j = i + 1; j < nums.length; j++)
      if (nums[i] + nums[j] === target) c++;
  return c;
}
module.exports = { countPairs };
