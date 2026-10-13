const { pages, pageCount } = require('./paginate.js');
function report(invoices, size = 3) {
  const ps = pages(invoices, size);
  return { pageCount: pageCount(invoices.length, size), rows: ps.flat() };
}
module.exports = { report };
