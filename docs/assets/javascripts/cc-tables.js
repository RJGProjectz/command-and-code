/**
 * Command & Code — Responsive tables (WP-16)
 * Wide tables (4+ columns: the generated browse tables and similar) become stacked cards
 * below 600 px. This script only labels each cell with its column header (data-label) and
 * marks the table; the layout itself is CSS in cc.css (.cc-stack).
 * Tables inside .cc-coverage stay a grid: their cells are a single check mark.
 */

(function () {
  'use strict';

  var MIN_COLUMNS = 4;

  function prepare(table) {
    if (table.classList.contains('cc-stack') || table.closest('.cc-coverage')) { return; }
    var headers = table.querySelectorAll('thead th');
    if (headers.length < MIN_COLUMNS) { return; }
    var labels = Array.prototype.map.call(headers, function (th) { return th.textContent.trim(); });
    table.querySelectorAll('tbody tr').forEach(function (row) {
      Array.prototype.forEach.call(row.children, function (cell, index) {
        if (labels[index]) { cell.setAttribute('data-label', labels[index]); }
      });
    });
    table.classList.add('cc-stack');
    var wrap = table.closest('.md-typeset__table');
    if (wrap) { wrap.classList.add('cc-stack-wrap'); }
  }

  function onPage() {
    document.querySelectorAll('.md-typeset table').forEach(prepare);
  }

  // Material instant navigation emits on the first load and on every page change.
  if (typeof window.document$ !== 'undefined' && window.document$.subscribe) {
    window.document$.subscribe(onPage);
  } else if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', onPage);
  } else {
    onPage();
  }
})();
