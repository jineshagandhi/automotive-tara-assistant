import pandas as pd
import streamlit as st

from app import components as ui
from app import state
from tara import knowledge
from tara.diagram import to_dot
from tara.explain import explain_threat
from tara.store import REVIEW_STATES

CONFIDENCE_COLOURS = {"High": "#3f8f5a", "Medium": "#d4a72c", "Low": "#8a8f98"}


def render():
    st.title("Threat scenarios and attack paths")
    st.caption("ISO/SAE 21434 clauses 15.4, 15.6 and 15.7. Threats are matched to UN R155 Annex 5 by hybrid "
               "retrieval, attack paths come from a graph search over the architecture, and feasibility uses "
               "the attack potential method.")

    arch = state.architecture()
    result = state.result()
    method = state.method()
    reviews = state.reviews()
    names = ui.asset_names(arch)

    order = st.segmented_control("Sort", ["Highest risk", "ID"], default="Highest risk")
    scenarios = sorted(result.threat_scenarios, key=(lambda t: (-t.risk, t.id)) if order != "ID" else (lambda t: t.id))
    labels = {ts.id: "%s · risk %d · %s" % (ts.id, ts.risk, ts.description) for ts in scenarios}
    if st.session_state.get("selected_ts") not in labels:
        st.session_state.selected_ts = scenarios[0].id
    ts_id = st.selectbox("Threat scenario", list(labels), format_func=labels.get, key="selected_ts")
    ts = next(t for t in result.threat_scenarios if t.id == ts_id)

    cols = st.columns(6)
    ui.kpi(cols[0], "Risk value", ui.risk_badge(ts.risk), ts.treatment)
    ui.kpi(cols[1], "Impact", ts.impact, names[ts.asset_id])
    ui.kpi(cols[2], "Feasibility", ts.feasibility, "attack potential %d" % ts.paths[0].attack_potential)
    ui.kpi(cols[3], "Attack vector", ts.attack_vector, ts.paths[0].steps[0].label)
    ui.kpi(cols[4], "CAL", ts.cal or "-", "assurance level")
    ui.kpi(cols[5], "Review", reviews.get(ts.key, {}).get("status", "Proposed"),
           reviews.get(ts.key, {}).get("reviewer", ""))
    st.write("")

    left, right = st.columns([1, 1.25])
    with left:
        with st.container(border=True):
            st.markdown(explain_threat(ts, result, arch, method))
        r155_panel(ts)
    with right:
        paths_panel(ts, arch, method)

    review_panel(ts, reviews)


def r155_panel(ts):
    st.markdown("#### UN R155 Annex 5 references")
    if not ts.r155:
        st.info("No Annex 5 threat matched with sufficient confidence. Link one on the R155 coverage page.")
    mitigations = knowledge.r155_mitigations()
    for match in ts.r155:
        with st.container(border=True):
            st.markdown("%s **Threat %s**: %s" % (
                ui.badge("%s confidence" % match.confidence, CONFIDENCE_COLOURS[match.confidence]),
                match.threat_id, match.text), unsafe_allow_html=True)
            st.markdown("<span class='cite'>%s · high level: %s · score %.2f (%s)</span>" % (
                knowledge.r155_citation(match.threat_id), match.high_level, match.score, "; ".join(match.reasons)),
                unsafe_allow_html=True)
            for ref in match.mitigations:
                st.markdown("- **%s**: %s <span class='cite'>(%s)</span>" % (
                    ref, mitigations[ref]["text"], knowledge.mitigation_citation(ref)), unsafe_allow_html=True)


def paths_panel(ts, arch, method):
    st.markdown("#### Attack paths")
    rows = [{"Path": p.id, "Route": " > ".join(s.label for s in p.steps), "Vector": p.attack_vector,
             "Potential": p.attack_potential, "Feasibility": p.feasibility,
             "Controls on path": ", ".join(c.split("@")[0] for c in p.controls_on_path)} for p in ts.paths]
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")

    path_id = st.selectbox("Show path", [p.id for p in ts.paths],
                           format_func=lambda i: "%s: %s" % (i, " > ".join(
                               s.label for s in next(p for p in ts.paths if p.id == i).steps)))
    path = next(p for p in ts.paths if p.id == path_id)
    st.graphviz_chart(to_dot(arch, highlight_path=[s.node for s in path.steps if s.node != "direct"],
                             extra_controls=[]), width="stretch")

    if path.entry_interface == "direct":
        return
    with st.expander("Attack potential rating for this entry point", icon=":material/calculate:"):
        key = "%s/%s" % (ts.key, path.entry_interface)
        overridden = key in st.session_state.overrides.factors
        st.caption("Computed from the interface catalogue, the number of ECUs on the path and the controls on "
                   "the path. An analyst rating replaces the computed rating for this entry point."
                   + (" **Analyst rating active.**" if overridden else ""))
        factors = {}
        cols = st.columns(5)
        for col, (factor, level) in zip(cols, path.factors.items()):
            options = method.factor_levels(factor)
            factors[factor] = col.selectbox(method.factors[factor]["label"], options, index=options.index(level),
                                            key="f_%s_%s" % (key, factor))
        total, rating = method.attack_potential(factors)
        st.markdown("Attack potential **%d**, feasibility **%s**" % (total, rating))
        c1, c2 = st.columns(2)
        if c1.button("Save analyst rating", disabled=factors == path.factors):
            st.session_state.overrides.factors[key] = factors
            state.save()
            state.log("override feasibility", key, ", ".join("%s=%s" % kv for kv in factors.items()))
            st.rerun()
        if c2.button("Clear analyst rating", disabled=not overridden):
            del st.session_state.overrides.factors[key]
            state.save()
            state.log("clear feasibility override", key)
            st.rerun()


def review_panel(ts, reviews):
    st.markdown("#### Review decision")
    current = reviews.get(ts.key, {})
    with st.form("review_%s" % ts.id, border=True):
        c1, c2 = st.columns([1, 3])
        status = c1.selectbox("Status", REVIEW_STATES, index=REVIEW_STATES.index(current.get("status", "Proposed")))
        comment = c2.text_input("Comment or rationale", current.get("comment", ""))
        if st.form_submit_button("Record decision", type="primary"):
            state.store().set_review(st.session_state.project_id, ts.key, status,
                                     st.session_state.get("reviewer", "analyst"), comment)
            st.toast("Decision recorded for %s" % ts.id, icon=":material/fact_check:")
            st.rerun()
    if current:
        st.caption("Last decision: %s by %s at %s" % (current["status"], current["reviewer"], current["updated_at"]))


render()
