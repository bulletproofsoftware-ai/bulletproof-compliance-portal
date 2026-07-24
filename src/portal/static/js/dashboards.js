/* WI-13 — Compliance Dashboards.
 *
 * Self-contained ES2020 module. Renders:
 *   * Inline SVG sparklines for 90-day score trends (no external deps).
 *   * Bar chart for per-domain scores (Chart.js if present; degrades to
 *     <table> if Chart.js absent).
 *
 * NO external dependencies are required at runtime. Pages that need
 * Chart.js include a vendored copy via base.html or a per-page script tag.
 *
 * Public entry points:
 *   ComplianceDashboards.renderSparkline(svgEl, points)
 *   ComplianceDashboards.renderScoreBars(canvasEl, labels, values)
 *   ComplianceDashboards.renderRadar(canvasEl, labels, values)
 *
 * Each `renderX` is idempotent: calling twice clears + redraws.
 */

(function (window, document) {
  "use strict";

  function clearSvg(svg) {
    while (svg.firstChild) svg.removeChild(svg.firstChild);
  }

  function renderSparkline(svg, points) {
    if (!svg) return;
    clearSvg(svg);
    const w = svg.viewBox && svg.viewBox.baseVal && svg.viewBox.baseVal.width
      ? svg.viewBox.baseVal.width
      : 60;
    const h = svg.viewBox && svg.viewBox.baseVal && svg.viewBox.baseVal.height
      ? svg.viewBox.baseVal.height
      : 20;
    if (!points || points.length === 0) {
      const txt = document.createElementNS("http://www.w3.org/2000/svg", "text");
      txt.setAttribute("x", String(w / 2));
      txt.setAttribute("y", String(h / 2));
      txt.setAttribute("text-anchor", "middle");
      txt.setAttribute("font-size", "10");
      txt.setAttribute("fill", "#9ca3af");
      txt.textContent = "no data";
      svg.appendChild(txt);
      return;
    }
    const min = Math.min.apply(null, points);
    const max = Math.max.apply(null, points);
    const range = max - min || 1;
    const dx = w / Math.max(points.length - 1, 1);
    let d = "";
    for (let i = 0; i < points.length; i++) {
      const x = i * dx;
      const y = h - ((points[i] - min) / range) * (h - 2) - 1;
      d += (i === 0 ? "M" : "L") + x.toFixed(2) + "," + y.toFixed(2);
    }
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", d);
    path.setAttribute("fill", "none");
    path.setAttribute("stroke", "#1d4ed8");
    path.setAttribute("stroke-width", "1.5");
    svg.appendChild(path);
  }

  function renderScoreBars(canvas, labels, values) {
    if (!canvas) return;
    if (typeof window.Chart === "undefined") {
      // Graceful degradation: replace canvas with a table.
      const tbl = document.createElement("table");
      tbl.className = "score-fallback";
      const thead = tbl.appendChild(document.createElement("thead"));
      const trh = thead.appendChild(document.createElement("tr"));
      labels.forEach(function (l) {
        const th = document.createElement("th");
        th.textContent = l;
        trh.appendChild(th);
      });
      const tbody = tbl.appendChild(document.createElement("tbody"));
      const trv = tbody.appendChild(document.createElement("tr"));
      values.forEach(function (v) {
        const td = document.createElement("td");
        td.textContent = String(Math.round(v));
        trv.appendChild(td);
      });
      canvas.parentNode.replaceChild(tbl, canvas);
      return;
    }
    new window.Chart(canvas.getContext("2d"), {
      type: "bar",
      data: {
        labels: labels,
        datasets: [
          {
            label: "Score",
            data: values,
            backgroundColor: "#1d4ed8",
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: { y: { beginAtZero: true, max: 100 } },
      },
    });
  }

  function renderRadar(canvas, labels, values) {
    if (!canvas || typeof window.Chart === "undefined") {
      // Skip radar in degraded mode — bars cover the same data.
      return;
    }
    new window.Chart(canvas.getContext("2d"), {
      type: "radar",
      data: {
        labels: labels,
        datasets: [
          {
            label: "Score",
            data: values,
            backgroundColor: "rgba(29,78,216,0.15)",
            borderColor: "#1d4ed8",
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: { r: { suggestedMin: 0, suggestedMax: 100 } },
      },
    });
  }

  window.ComplianceDashboards = {
    renderSparkline: renderSparkline,
    renderScoreBars: renderScoreBars,
    renderRadar: renderRadar,
  };
})(window, document);
