from collections import Counter

import pandas as pd
import streamlit as st

from app import components as ui
from app import state
from tara.compare import compare
from tara.models import TaraResult
from tara.store import REVIEW_STATES


def render():
    st.title("Review and audit")
    st.caption("Human approval of every AI proposal, a complete audit trail, and change impact analysis "
               "against saved baselines.")

    arch = state.architecture()
    result = state.result()
    reviews = state.reviews()
    names = ui.asset_names(arch)

    counts = Counter(reviews.get(ts.key, {}).get("status", "Proposed") for ts in result.threat_scenarios)
    cols = st.columns(4)
    for col, status in zip(cols, REVIEW_STATES):
        ui.kpi(col, status, counts.get(status, 0), "threat scenarios")
    st.write("")

    tab_reviews, tab_audit, tab_baselines = st.tabs(
        [":material/fact_check: Review status", ":material/history: Audit log", ":material/compare: Baselines and change impact"])

    with tab_reviews:
        st.caption("Record decisions on the Threats page, or in bulk here.")
        rows = [{"ID": ts.id, "Asset": names[ts.asset_id], "Risk": ts.risk, "Treatment": ts.treatment,
                 "Status": reviews.get(ts.key, {}).get("status", "Proposed"),
                 "Reviewer": reviews.get(ts.key, {}).get("reviewer", ""),
                 "Comment": reviews.get(ts.key, {}).get("comment", "")} for ts in result.threat_scenarios]
        st.dataframe(ui.style_risk(pd.DataFrame(rows)), hide_index=True, width="stretch", height=380)

        with st.form("bulk_review"):
            c1, c2, c3 = st.columns([2, 1, 2])
            keys = {ts.id: ts.key for ts in result.threat_scenarios}
            selected = c1.multiselect("Threat scenarios", list(keys))
            status = c2.selectbox("Status", REVIEW_STATES[1:])
            comment = c3.text_input("Comment")
            if st.form_submit_button("Record for selected", type="primary") and selected:
                for ts_id in selected:
                    state.store().set_review(st.session_state.project_id, keys[ts_id], status,
                                             st.session_state.get("reviewer", "analyst"), comment)
                st.rerun()

    with tab_audit:
        audit = state.store().audit(st.session_state.project_id)
        if audit:
            st.dataframe(pd.DataFrame(audit), hide_index=True, width="stretch", height=480)
        else:
            st.info("No actions recorded yet.")

    with tab_baselines:
        with st.form("baseline"):
            name = st.text_input("Baseline name", "Concept phase v%s" % arch.version)
            if st.form_submit_button("Save current TARA as baseline"):
                state.store().save_baseline(st.session_state.project_id, name, result.model_dump_json(),
                                            st.session_state.get("reviewer", "analyst"))
                st.rerun()

        baselines = state.store().baselines(st.session_state.project_id)
        if not baselines:
            st.info("Save a baseline, change the architecture, and compare to see the change impact.")
            return
        chosen = st.selectbox("Compare current TARA with", [b["id"] for b in baselines],
                              format_func=lambda i: next("%s (%s)" % (b["name"], b["created_at"])
                                                         for b in baselines if b["id"] == i))
        old = TaraResult.model_validate_json(state.store().load_baseline(chosen))
        diff = compare(old, result)
        if not diff["scenarios"] and not diff["new_findings"] and not diff["resolved_findings"]:
            st.success("No change against this baseline.")
        if diff["scenarios"]:
            st.dataframe(pd.DataFrame(diff["scenarios"]), hide_index=True, width="stretch")
        for title in diff["new_findings"]:
            st.error("New finding: %s" % title)
        for title in diff["resolved_findings"]:
            st.success("Resolved finding: %s" % title)


render()
