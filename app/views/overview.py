from collections import Counter

import pandas as pd
import streamlit as st

from app import components as ui
from app import state


def render():
    arch = state.architecture()
    result = state.result()
    residual = state.residual_result()
    method = state.method()
    reviews = state.reviews()

    st.title(arch.name)
    st.caption("%s · version %s · %d components · %d interfaces · %d assets" % (
        arch.description.strip().split(".")[0] if arch.description else "Item under analysis",
        arch.version, len(arch.components), len(arch.interfaces), len(arch.assets)))

    risks = Counter(ts.risk for ts in result.threat_scenarios)
    residual_risks = Counter(ts.risk for ts in residual.threat_scenarios)
    coverage = Counter(c.status for c in result.coverage)
    covered = coverage.get("Addressed", 0) + coverage.get("CSMS process", 0) + coverage.get("Not applicable", 0)
    reviewed = sum(1 for ts in result.threat_scenarios if reviews.get(ts.key, {}).get("status", "Proposed") != "Proposed")

    cols = st.columns(6)
    ui.kpi(cols[0], "Threat scenarios", len(result.threat_scenarios), "%d damage scenarios" % len(result.damage_scenarios))
    ui.kpi(cols[1], "Initial risk 4-5", risks.get(5, 0) + risks.get(4, 0), "with existing controls")
    ui.kpi(cols[2], "Residual risk 4-5", residual_risks.get(5, 0) + residual_risks.get(4, 0),
           "%d proposed controls" % len(st.session_state.proposed))
    ui.kpi(cols[3], "Cybersecurity goals", len(result.goals), "for risks to reduce")
    ui.kpi(cols[4], "R155 Annex 5", "%d%%" % round(100 * covered / len(result.coverage)),
           "%d of %d threats dispositioned" % (covered, len(result.coverage)))
    ui.kpi(cols[5], "Reviewed", "%d / %d" % (reviewed, len(result.threat_scenarios)), "human decisions recorded")

    st.write("")
    left, right = st.columns([1.1, 1])
    with left:
        with st.container(border=True):
            st.markdown("**Risk matrix: initial risk**")
            st.altair_chart(ui.risk_heatmap(result, method), width="stretch")
    with right:
        with st.container(border=True):
            st.markdown("**Risk profile: initial vs residual**")
            st.altair_chart(ui.risk_distribution(result, residual), width="stretch")
            if not st.session_state.proposed:
                st.info("No controls proposed yet. Use **Risk and treatment > Treatment planner** or the "
                        "**Control simulator** to see the residual risk.", icon=":material/lightbulb:")
            else:
                st.caption("Residual risk includes %d proposed controls from the treatment plan or simulator."
                           % len(st.session_state.proposed))

        with st.container(border=True):
            st.markdown("**Architecture findings**")
            if not result.findings:
                st.success("No architecture level findings.")
            for finding in result.findings:
                st.markdown("%s **%s**  \n<span class='small'>%s · R155 %s</span>" % (
                    ui.badge(finding.severity, ui.SEVERITY_COLOURS[finding.severity]), finding.title,
                    finding.detail, ", ".join(finding.r155)), unsafe_allow_html=True)

    st.subheader("Highest risks")
    names = ui.asset_names(arch)
    top = sorted(result.threat_scenarios, key=lambda t: (-t.risk, t.id))[:8]
    residual_by_id = {t.id: t.risk for t in residual.threat_scenarios}
    df = pd.DataFrame([{
        "ID": ts.id, "Asset": names[ts.asset_id], "Threat": ts.stride, "Impact": ts.impact,
        "Feasibility": ts.feasibility, "Risk": ts.risk, "Residual": residual_by_id.get(ts.id, ts.risk),
        "Most feasible path": " > ".join(s.label for s in ts.paths[0].steps),
        "Review": reviews.get(ts.key, {}).get("status", "Proposed"),
    } for ts in top])
    st.dataframe(ui.style_risk(df, ["Risk", "Residual"]), hide_index=True, width="stretch")

    with st.expander("How this TARA is built", icon=":material/info:"):
        st.markdown("""
The workflow follows **ISO/SAE 21434 clause 15** and the pages in the sidebar:

1. **Architecture**: components, networks, external interfaces and assets, imported from YAML or drafted from a design document.
2. **Damage scenarios**: Safety, Financial, Operational and Privacy impact, proposed by transparent rules and editable by the analyst.
3. **Threats and attack paths**: STRIDE threat per asset property, matched to **UN R155 Annex 5** with retrieval and cited; every path from every external interface is found by graph search and rated with the attack potential method.
4. **Risk and treatment**: risk matrix, treatment decision, cybersecurity goals with CAL, and an automatic treatment planner.
5. **Control simulator**: what-if analysis of residual risk.

All ratings are proposals. The analyst reviews them, and every decision is logged.
""")


render()
