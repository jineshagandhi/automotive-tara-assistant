"""Reusable UI pieces: risk colours, KPI cards, heatmaps, tables."""

from collections import Counter

import altair as alt
import pandas as pd
import streamlit as st

RISK_COLOURS = {5: "#c1121f", 4: "#e8590c", 3: "#d4a72c", 2: "#6aa56a", 1: "#3f8f5a"}
SEVERITY_COLOURS = {"High": "#c1121f", "Medium": "#e8590c", "Low": "#6aa56a"}
STATUS_COLOURS = {"Addressed": "#3f8f5a", "CSMS process": "#4a7bb7", "Not applicable": "#8a8f98", "Open": "#e8590c"}

CSS = """
<style>
.block-container { padding-top: 1.6rem; padding-bottom: 3rem; max-width: 1400px; }
.kpi { border: 1px solid rgba(128,128,128,0.25); border-radius: 10px; padding: 14px 16px; height: 100%; }
.kpi .label { font-size: 0.78rem; text-transform: uppercase; letter-spacing: .04em; opacity: .7; }
.kpi .value { font-size: 1.9rem; font-weight: 700; line-height: 1.2; }
.kpi .sub { font-size: 0.8rem; opacity: .75; }
.badge { display: inline-block; padding: 1px 8px; border-radius: 999px; color: #fff; font-size: 0.78rem; font-weight: 600; }
.risk { display: inline-block; min-width: 26px; text-align: center; padding: 2px 6px; border-radius: 6px; color: #fff; font-weight: 700; }
.small { font-size: 0.85rem; opacity: .8; }
.cite { font-size: 0.8rem; opacity: .75; }
</style>
"""


def inject_css():
    st.markdown(CSS, unsafe_allow_html=True)


def risk_badge(risk):
    return '<span class="risk" style="background:%s">%d</span>' % (RISK_COLOURS[risk], risk)


def badge(text, colour):
    return '<span class="badge" style="background:%s">%s</span>' % (colour, text)


def kpi(column, label, value, sub=""):
    column.markdown('<div class="kpi"><div class="label">%s</div><div class="value">%s</div>'
                    '<div class="sub">%s</div></div>' % (label, value, sub), unsafe_allow_html=True)


def risk_heatmap(result, method, title=None):
    """Impact x feasibility matrix, coloured by risk value, labelled with scenario counts."""
    counts = Counter((ts.impact, ts.feasibility) for ts in result.threat_scenarios)
    rows = []
    for impact in method.impact_levels:
        for feasibility in method.feasibility_levels:
            risk = method.risk_value(impact, feasibility)
            count = counts.get((impact, feasibility), 0)
            rows.append({"Impact": impact, "Feasibility": feasibility, "Risk": risk,
                         "Scenarios": count, "Label": str(count) if count else ""})
    data = pd.DataFrame(rows)
    scale = alt.Scale(domain=[1, 2, 3, 4, 5], range=[RISK_COLOURS[r] for r in (1, 2, 3, 4, 5)])
    chart = alt.Chart(data, title=title) if title else alt.Chart(data)
    base = chart.encode(
        x=alt.X("Feasibility:N", sort=method.feasibility_levels, title="Attack feasibility",
                axis=alt.Axis(labelAngle=0)),
        y=alt.Y("Impact:N", sort=list(reversed(method.impact_levels)), title="Impact",
                axis=alt.Axis(labelOverlap=False)),
    )
    cells = base.mark_rect(cornerRadius=4, stroke="white", strokeWidth=2).encode(
        color=alt.Color("Risk:O", scale=scale, legend=alt.Legend(title="Risk value", orient="bottom")),
        opacity=alt.condition("datum.Scenarios > 0", alt.value(1), alt.value(0.28)),
        tooltip=["Impact", "Feasibility", "Risk", "Scenarios"],
    )
    text = base.mark_text(fontSize=18, fontWeight="bold", color="white").encode(text="Label:N")
    return (cells + text).properties(height=300)


def risk_distribution(before, after=None):
    """Scenarios per risk value, initial next to residual."""
    rows = []
    for label, result in (("Initial", before), ("Residual", after)):
        if result is None:
            continue
        counts = Counter(ts.risk for ts in result.threat_scenarios)
        for risk in (5, 4, 3, 2, 1):
            rows.append({"Stage": label, "Risk value": str(risk), "Scenarios": counts.get(risk, 0)})
    data = pd.DataFrame(rows)
    return alt.Chart(data).mark_bar(cornerRadiusTopLeft=3, cornerRadiusTopRight=3).encode(
        x=alt.X("Risk value:N", sort=["5", "4", "3", "2", "1"], axis=alt.Axis(labelAngle=0)),
        xOffset=alt.XOffset("Stage:N", sort=["Initial", "Residual"]),
        y=alt.Y("Scenarios:Q", title="Threat scenarios"),
        color=alt.Color("Stage:N", scale=alt.Scale(domain=["Initial", "Residual"], range=["#9aa4b2", "#1f4e8c"]),
                        legend=alt.Legend(title=None, orient="top")),
        tooltip=["Stage", "Risk value", "Scenarios"],
    ).properties(height=230)


def style_risk(df, column="Risk"):
    def colour(value):
        if isinstance(value, (int, float)) and int(value) in RISK_COLOURS:
            return "background-color: %s; color: white; font-weight: 700; text-align: center" % RISK_COLOURS[int(value)]
        return ""
    return df.style.map(colour, subset=[c for c in ([column] if isinstance(column, str) else column) if c in df])


def asset_names(architecture):
    return {a.id: a.name for a in architecture.assets}

