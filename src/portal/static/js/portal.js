/* Portal progressive enhancements (vendored, no CDN).
   Currently: click-to-sort on any data table that has a <thead>.
   Re-runs after HTMX swaps so partial-loaded tables become sortable too. */
(function () {
  "use strict";

  function cellValue(row, idx) {
    var cell = row.children[idx];
    return cell ? (cell.getAttribute("data-sort") || cell.textContent || "").trim() : "";
  }

  function comparer(idx, asc) {
    return function (a, b) {
      var v1 = cellValue(asc ? a : b, idx);
      var v2 = cellValue(asc ? b : a, idx);
      var n1 = parseFloat(v1.replace(/[$,%\s]/g, ""));
      var n2 = parseFloat(v2.replace(/[$,%\s]/g, ""));
      if (!isNaN(n1) && !isNaN(n2)) return n1 - n2;
      return v1.localeCompare(v2, undefined, { numeric: true, sensitivity: "base" });
    };
  }

  function makeSortable(table) {
    if (table.__sortable) return;
    var head = table.tHead;
    var body = table.tBodies[0];
    if (!head || !body) return;
    var headerRow = head.rows[head.rows.length - 1];
    if (!headerRow) return;
    Array.prototype.forEach.call(headerRow.cells, function (th, idx) {
      if (!th.textContent.trim()) return; // skip action/blank columns
      th.style.cursor = "pointer";
      th.setAttribute("role", "button");
      th.title = "Sort by " + th.textContent.trim();
      th.addEventListener("click", function () {
        var asc = !(th.__asc);
        th.__asc = asc;
        var rows = Array.prototype.slice.call(body.rows);
        rows.sort(comparer(idx, asc));
        rows.forEach(function (r) { body.appendChild(r); });
        Array.prototype.forEach.call(headerRow.cells, function (c) {
          c.textContent = c.textContent.replace(/[▲▼]\s*$/, "").trim();
        });
        th.textContent = th.textContent.trim() + " " + (asc ? "▲" : "▼");
      });
    });
    table.__sortable = true;
  }

  function addFilter(table) {
    if (table.__filtered) return;
    var body = table.tBodies[0];
    if (!table.tHead || !body || body.rows.length < 3) return; // skip tiny tables
    var box = document.createElement("input");
    box.type = "search";
    box.placeholder = "Filter rows…";
    box.className = "table-filter";
    box.setAttribute("aria-label", "Filter table rows");
    box.addEventListener("input", function () {
      var needle = box.value.trim().toLowerCase();
      Array.prototype.forEach.call(body.rows, function (row) {
        row.style.display = (!needle || row.textContent.toLowerCase().indexOf(needle) !== -1) ? "" : "none";
      });
    });
    table.parentNode.insertBefore(box, table);
    table.__filtered = true;
  }

  function enhance(root) {
    (root || document).querySelectorAll("table").forEach(function (t) {
      makeSortable(t);
      addFilter(t);
    });
  }

  document.addEventListener("DOMContentLoaded", function () { enhance(document); });
  // HTMX-swapped content (e.g. audit results, dsr queue) gets enhanced too.
  document.body.addEventListener("htmx:afterSwap", function (e) { enhance(e.target); });
})();
