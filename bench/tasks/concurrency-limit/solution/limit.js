function pLimit(n) {
  let active = 0;
  const queue = [];
  function next() {
    while (active < n && queue.length) {
      const { fn, resolve, reject } = queue.shift();
      active++;
      let p;
      try { p = Promise.resolve(fn()); } catch (e) { p = Promise.reject(e); }
      p.then(resolve, reject).finally(() => { active--; next(); });
    }
  }
  return (fn) => new Promise((resolve, reject) => { queue.push({ fn, resolve, reject }); next(); });
}
module.exports = { pLimit };
