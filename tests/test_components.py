"""Reusable index-pattern macro tests (Plan 2 Task 1)."""

from __future__ import annotations

from portal.templates import get_templates


def _render(src, **ctx):
    return get_templates().env.from_string(src).render(**ctx)


def test_page_header_renders_title_subtitle_req():
    html = _render(
        "{% from '_components.html' import page_header %}"
        "{{ page_header('Gate Decisions', 'Review pending gates.', 'REQ-CPL-009') }}"
    )
    assert "<h1>Gate Decisions</h1>" in html
    assert "Review pending gates." in html
    assert "REQ-CPL-009" in html


def test_kpi_cards_render_values_and_links():
    html = _render(
        "{% from '_components.html' import kpi_cards %}{{ kpi_cards(cards) }}",
        cards=[{"label": "Pending", "value": 3, "href": "/gates"}],
    )
    assert "kpi-grid" in html
    assert "3" in html and "Pending" in html
    assert 'href="/gates"' in html


def test_breadcrumbs_marks_last_as_current():
    html = _render(
        "{% from '_components.html' import breadcrumbs %}{{ breadcrumbs(items) }}",
        items=[{"label": "Gates", "href": "/gates"}, {"label": "g1"}],
    )
    assert 'href="/gates"' in html
    assert "g1" in html
    assert 'aria-current="page"' in html


def test_empty_state_renders_message():
    html = _render(
        "{% from '_components.html' import empty_state %}{{ empty_state('No gates.', 'They will appear here.') }}"
    )
    assert "No gates." in html
    assert "They will appear here." in html
