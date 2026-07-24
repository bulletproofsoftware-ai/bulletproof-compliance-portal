"""WI-15 — Forecast rendering helpers.

Shapes ForecastData into chart-ready arrays for D3/Chart.js confidence band
visualization. No statistical math — this is layout/serialization only. The
service computes mean / p10 / p90 / confidence; the portal just renders.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from shared.api_client import ForecastData


def shape_for_chart(forecast: ForecastData) -> dict[str, Any]:
    """Return Chart.js / D3-friendly nested arrays for cost & quality bands.

    Output schema:
        {
          "labels": [iso8601 strings, …],
          "cost": {
            "mean": [float, …],
            "p10":  [float, …],
            "p90":  [float, …],
          },
          "quality": {
            "mean": [float, …],
            "p10":  [float, …],
            "p90":  [float, …],
          },
          "confidence": [float, …],
          "horizon_days": int,
          "generated_at": iso8601 string,
        }

    Invariants asserted (tests):
      * For any index i: cost.p10[i] <= cost.mean[i] <= cost.p90[i]
      * Same for quality
      * Lengths of all arrays equal len(forecast.points)
    """
    labels: list[str] = []
    cost_mean: list[float] = []
    cost_p10: list[float] = []
    cost_p90: list[float] = []
    quality_mean: list[float] = []
    quality_p10: list[float] = []
    quality_p90: list[float] = []
    confidence: list[float] = []

    for p in forecast.points:
        labels.append(_iso(p.asof))
        cost_mean.append(p.cost_mean_usd)
        cost_p10.append(p.cost_p10_usd)
        cost_p90.append(p.cost_p90_usd)
        quality_mean.append(p.quality_mean)
        quality_p10.append(p.quality_p10)
        quality_p90.append(p.quality_p90)
        confidence.append(p.confidence)

    return {
        "labels": labels,
        "cost": {
            "mean": cost_mean,
            "p10": cost_p10,
            "p90": cost_p90,
        },
        "quality": {
            "mean": quality_mean,
            "p10": quality_p10,
            "p90": quality_p90,
        },
        "confidence": confidence,
        "horizon_days": forecast.horizon_days,
        "generated_at": _iso(forecast.generated_at),
    }


def validate_band_ordering(forecast: ForecastData) -> list[str]:
    """Return a list of human-readable problems where p10 > mean or mean > p90.

    Used as a defensive check in the router — the service should never emit
    inverted bands but if it does, we surface a warning rather than render
    a misleading chart.
    """
    problems: list[str] = []
    for i, p in enumerate(forecast.points):
        if p.cost_p10_usd > p.cost_mean_usd:
            problems.append(f"point[{i}].cost: p10 > mean")
        if p.cost_mean_usd > p.cost_p90_usd:
            problems.append(f"point[{i}].cost: mean > p90")
        if p.quality_p10 > p.quality_mean:
            problems.append(f"point[{i}].quality: p10 > mean")
        if p.quality_mean > p.quality_p90:
            problems.append(f"point[{i}].quality: mean > p90")
    return problems


def _iso(dt: datetime) -> str:
    return dt.isoformat()


__all__ = ["shape_for_chart", "validate_band_ordering"]
