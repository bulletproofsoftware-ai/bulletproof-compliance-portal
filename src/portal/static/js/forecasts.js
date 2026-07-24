/* WI-15 — Forecast confidence-interval band visualization.
 *
 * Renders a D3-free inline-SVG line + shaded p10–p90 envelope. Self-contained
 * so we don't have to vendor D3 just for one chart. Inputs:
 *
 *   svgEl          — <svg viewBox="0 0 W H"> placeholder
 *   labels         — array of x-axis labels (display-only)
 *   mean / p10 / p90 — arrays of equal length; values clamp to [0..max]
 *   options        — { color, axisColor, max }
 *
 * Public entry points:
 *   ForecastChart.render(svg, { labels, mean, p10, p90, max })
 */

(function (window, document) {
  "use strict";

  const NS = "http://www.w3.org/2000/svg";

  function clear(svg) {
    while (svg.firstChild) svg.removeChild(svg.firstChild);
  }

  function pathFromPoints(points, h, max, w) {
    const dx = w / Math.max(points.length - 1, 1);
    let d = "";
    for (let i = 0; i < points.length; i++) {
      const x = i * dx;
      const y = h - (points[i] / max) * (h - 8) - 4;
      d += (i === 0 ? "M" : "L") + x.toFixed(2) + "," + y.toFixed(2);
    }
    return d;
  }

  function bandPathFromPoints(p10, p90, h, max, w) {
    const dx = w / Math.max(p10.length - 1, 1);
    let dUp = "";
    let dDown = "";
    for (let i = 0; i < p90.length; i++) {
      const x = i * dx;
      const yUp = h - (p90[i] / max) * (h - 8) - 4;
      dUp += (i === 0 ? "M" : "L") + x.toFixed(2) + "," + yUp.toFixed(2);
    }
    for (let i = p10.length - 1; i >= 0; i--) {
      const x = i * dx;
      const yDown = h - (p10[i] / max) * (h - 8) - 4;
      dDown += "L" + x.toFixed(2) + "," + yDown.toFixed(2);
    }
    return dUp + dDown + "Z";
  }

  function render(svg, opts) {
    if (!svg) return;
    opts = opts || {};
    const labels = opts.labels || [];
    const mean = opts.mean || [];
    const p10 = opts.p10 || [];
    const p90 = opts.p90 || [];
    const max = opts.max || Math.max.apply(null, p90.concat([1])) || 1;
    const color = opts.color || "#1d4ed8";
    const bandFill = opts.bandFill || "rgba(29,78,216,0.15)";

    const vb = svg.viewBox && svg.viewBox.baseVal;
    const w = vb && vb.width ? vb.width : 600;
    const h = vb && vb.height ? vb.height : 200;

    clear(svg);

    // Confidence band p10..p90
    if (p10.length === p90.length && p10.length > 0) {
      const bandEl = document.createElementNS(NS, "path");
      bandEl.setAttribute("d", bandPathFromPoints(p10, p90, h, max, w));
      bandEl.setAttribute("fill", bandFill);
      bandEl.setAttribute("stroke", "none");
      svg.appendChild(bandEl);
    }

    // Mean line
    if (mean.length > 0) {
      const meanEl = document.createElementNS(NS, "path");
      meanEl.setAttribute("d", pathFromPoints(mean, h, max, w));
      meanEl.setAttribute("fill", "none");
      meanEl.setAttribute("stroke", color);
      meanEl.setAttribute("stroke-width", "2");
      svg.appendChild(meanEl);
    }

    // Axis baseline
    const axis = document.createElementNS(NS, "line");
    axis.setAttribute("x1", "0");
    axis.setAttribute("y1", String(h - 4));
    axis.setAttribute("x2", String(w));
    axis.setAttribute("y2", String(h - 4));
    axis.setAttribute("stroke", "#9ca3af");
    axis.setAttribute("stroke-width", "0.5");
    svg.appendChild(axis);

    // First & last labels
    if (labels.length > 0) {
      const t0 = document.createElementNS(NS, "text");
      t0.setAttribute("x", "0");
      t0.setAttribute("y", String(h));
      t0.setAttribute("font-size", "10");
      t0.setAttribute("fill", "#6b7280");
      t0.textContent = String(labels[0]).slice(0, 10);
      svg.appendChild(t0);

      const tN = document.createElementNS(NS, "text");
      tN.setAttribute("x", String(w - 60));
      tN.setAttribute("y", String(h));
      tN.setAttribute("font-size", "10");
      tN.setAttribute("fill", "#6b7280");
      tN.textContent = String(labels[labels.length - 1]).slice(0, 10);
      svg.appendChild(tN);
    }
  }

  window.ForecastChart = { render: render };

  // ─── Template-facing helpers (used by outcomes/forecast_view.html) ───────
  // The forecast template passes a <div> + the raw chart_data object
  // {horizon_days, generated_at, points: [{asof, cost_mean_usd, cost_p10_usd,
  // cost_p90_usd, quality_mean, quality_p10, quality_p90, confidence}, ...]}.
  // These wrappers build an inline SVG inside the div and delegate to render().

  function _ensureSvg(container, w, h) {
    if (!container) return null;
    while (container.firstChild) container.removeChild(container.firstChild);
    const svg = document.createElementNS(NS, "svg");
    svg.setAttribute("viewBox", "0 0 " + w + " " + h);
    svg.setAttribute("width", "100%");
    svg.setAttribute("height", "100%");
    svg.setAttribute("preserveAspectRatio", "none");
    container.appendChild(svg);
    return svg;
  }

  function _pluck(points, fields) {
    return fields.map(function (field) {
      return points.map(function (p) { return Number(p[field]) || 0; });
    });
  }

  function _emptyMessage(container, msg) {
    if (!container) return;
    while (container.firstChild) container.removeChild(container.firstChild);
    const p = document.createElement("p");
    p.className = "muted";
    p.textContent = msg;
    container.appendChild(p);
  }

  function renderCostBand(container, chartData) {
    const labels = (chartData && chartData.labels) || [];
    const cost = (chartData && chartData.cost) || {};
    const mean = cost.mean || [];
    const p10 = cost.p10 || [];
    const p90 = cost.p90 || [];
    if (!mean.length) return _emptyMessage(container, "No forecast data.");
    const max = Math.max.apply(null, p90.concat([0.0001])) * 1.1;
    const svg = _ensureSvg(container, 600, 200);
    render(svg, { labels: labels, mean: mean, p10: p10, p90: p90, max: max, color: "#1d4ed8" });
  }

  function renderQualityBand(container, chartData) {
    const labels = (chartData && chartData.labels) || [];
    const q = (chartData && chartData.quality) || {};
    const mean = q.mean || [];
    const p10 = q.p10 || [];
    const p90 = q.p90 || [];
    if (!mean.length) return _emptyMessage(container, "No forecast data.");
    const svg = _ensureSvg(container, 600, 200);
    // Quality is 0..1; pad to 1.0 ceiling
    render(svg, { labels: labels, mean: mean, p10: p10, p90: p90, max: 1.0, color: "#047857" });
  }

  window.ComplianceForecasts = {
    renderCostBand: renderCostBand,
    renderQualityBand: renderQualityBand,
  };
})(window, document);
