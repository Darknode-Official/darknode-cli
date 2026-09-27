// Return an array of integers from `start` up to and including `end`.
function inclusiveRange(start, end) {
  const out = [];
  for (let i = start; i < end; i++) out.push(i); // BUG: excludes `end`
  return out;
}
module.exports = { inclusiveRange };
