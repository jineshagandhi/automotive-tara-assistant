from collections import Counter

import pandas as pd
import streamlit as st

from app import components as ui
from app import state
from tara import knowledge
from tara.diagram import to_dot
from tara.graph import ArchitectureGraph
from tara.models import AppliedControl


def placements(arch):
    """Every control placement allowed by the catalogue for this architecture."""
    graph = ArchitectureGraph(arch)
    catalogue = knowledge.controls()
    nodes = [c.id for c in arch.components] + [b.id for b in arch.buses] + [i.id for i in arch.interfaces]
    existing = {(c.control, c.target) for c in arch.controls}
    options = []
    for key, spec in catalogue.items():
        for node in nodes:
            if graph.node_type(node) not in spec["placement"] or (key, node) in existing:
                continue
            if "bus_types" in spec and node in graph.buses and graph.buses[node].type not in spec["bus_types"]:
                continue
            if "entries" in spec and node in graph.interfaces and graph.interfaces[node].type not in spec["entries"]:
                continue
            options.append((key, node, "%s  on  %s" % (spec["name"], graph.label(node))))
    return options


def render():
    st.title("Control simulator")
    st.caption("What-if analysis: propose controls and see the residual risk of every threat scenario. "
               "Proposed controls are shown with * in the diagrams and exported as the treatment plan.")

    arch = state.architecture()
    method = state.method()
    options = placements(arch)
    labels = {(k, n): label for k, n, label in options}
    current = [(c.control, c.target) for c in st.session_state.proposed if (c.control, c.target) in labels]

    chosen = st.multiselect("Proposed controls", list(labels), default=current, format_func=labels.get,
                            placeholder="Choose controls to deploy")
    if set(chosen) != set(current):
        st.session_state.proposed = [AppliedControl(control=k, target=n, status="proposed") for k, n in chosen]
        state.save()
        state.log("simulate controls", "", "; ".join(labels[c] for c in chosen) or "none")
        st.rerun()

    c1, c2 = st.columns([1, 5])
    if c1.button("Clear all", disabled=not chosen):
        st.session_state.proposed = []
        state.save()
        st.rerun()
    if st.session_state.get("plan") and c2.button("Load the treatment plan"):
        st.session_state.proposed = [AppliedControl(control=s["control"], target=s["target"], status="proposed")
                                     for s in st.session_state.plan]
        state.save()
        st.rerun()

    initial = state.result()
    residual = state.residual_result()
    before = Counter(t.risk for t in initial.threat_scenarios)
    after = Counter(t.risk for t in residual.threat_scenarios)

    cols = st.columns(4)
    ui.kpi(cols[0], "Risk 5", "%d → %d" % (before.get(5, 0), after.get(5, 0)))
    ui.kpi(cols[1], "Risk 4", "%d → %d" % (before.get(4, 0), after.get(4, 0)))
    ui.kpi(cols[2], "Average risk", "%.1f → %.1f" % (
        sum(t.risk for t in initial.threat_scenarios) / len(initial.threat_scenarios),
        sum(t.risk for t in residual.threat_scenarios) / len(residual.threat_scenarios)))
    ui.kpi(cols[3], "Findings", "%d → %d" % (len(initial.findings), len(residual.findings)))
    st.write("")

    left, right = st.columns(2)
    with left:
        st.altair_chart(ui.risk_heatmap(initial, method, "Initial risk"), width="stretch")
    with right:
        st.altair_chart(ui.risk_heatmap(residual, method, "Residual risk"), width="stretch")

    names = ui.asset_names(arch)
    residual_by_id = {t.id: t for t in residual.threat_scenarios}
    rows = []
    for ts in initial.threat_scenarios:
        res = residual_by_id[ts.id]
        rows.append({"ID": ts.id, "Asset": names[ts.asset_id], "Property": ts.property,
                     "Initial": ts.risk, "Residual": res.risk, "Change": res.risk - ts.risk,
                     "Residual feasibility": res.feasibility,
                     "Remaining most feasible path": " > ".join(s.label for s in res.paths[0].steps)})
    df = pd.DataFrame(rows).sort_values(["Residual", "Initial"], ascending=False)
    st.dataframe(ui.style_risk(df, ["Initial", "Residual"]), hide_index=True, width="stretch", height=420)

    with st.expander("Architecture with proposed controls", icon=":material/account_tree:"):
        st.graphviz_chart(to_dot(arch, extra_controls=st.session_state.proposed), width="stretch")


render()
