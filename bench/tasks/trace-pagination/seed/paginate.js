const { pageBounds } = require('./range.js');
function pageCount(n, size) {
  return Math.floor(n / size) + (n % size > 0 ? 1 : 0) - (n % size === 0 && n > 0 ? 1 : 0);
}
function pages(items, size) {
  const out = [];
  for (let p = 0; p < pageCount(items.length, size); p++) { const [a, b] = pageBounds(p, size, items.length); out.push(items.slice(a, b)); }
  return out;
}
module.exports = { pages, pageCount };
