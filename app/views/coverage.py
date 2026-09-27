from collections import Counter

import altair as alt
import pandas as pd
import streamlit as st

from app import components as ui
from app import state
from tara import knowledge


def render():
    st.title("UN R155 Annex 5 coverage")
    st.caption("UN R155 paragraph 7.3.3 requires the risk assessment to consider all threats in Annex 5, Part A. "
               "Each threat is addressed by a threat scenario, handled by a CSMS process, not applicable with a "
               "rationale, or still open.")

    result = state.result()
    overrides = st.session_state.overrides
    counts = Counter(c.status for c in result.coverage)
    total = len(result.coverage)

    cols = st.columns(4)
    for col, status in zip(cols, ["Addressed", "CSMS process", "Not applicable", "Open"]):
        ui.kpi(col, status, counts.get(status, 0), "%d%% of %d threats" % (round(100 * counts.get(status, 0) / total), total))
    st.write("")

    short = {"4.3.1": "4.3.1 Back-end servers", "4.3.2": "4.3.2 Communication channels",
             "4.3.3": "4.3.3 Update procedures", "4.3.4": "4.3.4 Unintended human actions",
             "4.3.5": "4.3.5 External connectivity", "4.3.6": "4.3.6 Vehicle data and code",
             "4.3.7": "4.3.7 Potential vulnerabilities"}
    category_ids = {t["id"]: t["category_id"] for t in knowledge.r155()["threats"]}
    data = pd.DataFrame([{"Category": short.get(category_ids.get(c.threat_id), "Table C3: physical loss of data"),
                          "Status": c.status} for c in result.coverage])
    chart = alt.Chart(data).mark_bar().encode(
        y=alt.Y("Category:N", title=None, sort="ascending", axis=alt.Axis(labelLimit=260)),
        x=alt.X("count():Q", title="Annex 5 threats"),
        color=alt.Color("Status:N", scale=alt.Scale(domain=list(ui.STATUS_COLOURS),
                                                     range=list(ui.STATUS_COLOURS.values()))),
        tooltip=["Category", "Status", "count()"],
    ).properties(height=260)
    st.altair_chart(chart, width="stretch")

    status_filter = st.multiselect("Status", list(ui.STATUS_COLOURS), default=list(ui.STATUS_COLOURS))
    rows = [{"Threat": c.threat_id, "Status": c.status, "Text": c.text,
             "Threat scenarios": ", ".join(c.scenarios), "Note": c.note,
             "Suggested scenario": c.suggested or ""} for c in result.coverage if c.status in status_filter]
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", height=420)

    open_items = [c for c in result.coverage if c.status == "Open"]
    st.subheader("Disposition open threats")
    if not open_items:
        st.success("Every Annex 5 threat is dispositioned.")
        return

    ts_ids = [t.id for t in result.threat_scenarios]
    descriptions = {t.id: t.description for t in result.threat_scenarios}
    item_id = st.selectbox("Open threat", [c.threat_id for c in open_items],
                           format_func=lambda i: "%s: %s" % (i, next(c.text for c in open_items if c.threat_id == i)))
    item = next(c for c in open_items if c.threat_id == item_id)
    st.markdown("<span class='cite'>%s · %s</span>" % (knowledge.r155_citation(item.threat_id), item.category),
                unsafe_allow_html=True)

    with st.form("disposition"):
        action = st.radio("Decision", ["Link to a threat scenario", "Not applicable"], horizontal=True)
        default = ts_ids.index(item.suggested) if item.suggested in ts_ids else 0
        ts_id = st.selectbox("Threat scenario (suggested by retrieval)", ts_ids, index=default,
                             format_func=lambda i: "%s: %s" % (i, descriptions[i]))
        rationale = st.text_input("Rationale", placeholder="Required for 'Not applicable'")
        if st.form_submit_button("Record", type="primary"):
            if action == "Not applicable":
                if not rationale.strip():
                    st.error("A rationale is required.")
                    st.stop()
                overrides.not_applicable[item.threat_id] = rationale.strip()
                state.log("R155 not applicable", item.threat_id, rationale.strip())
            else:
                key = next(t.key for t in result.threat_scenarios if t.id == ts_id)
                overrides.links.setdefault(item.threat_id, []).append(key)
                state.log("R155 link", item.threat_id, "linked to %s. %s" % (ts_id, rationale))
            state.save()
            st.rerun()

    if overrides.links or overrides.not_applicable:
        with st.expander("Analyst dispositions"):
            for tid, ids in overrides.links.items():
                st.markdown("- %s linked to %s" % (tid, ", ".join(ids)))
            for tid, why in overrides.not_applicable.items():
                st.markdown("- %s not applicable: %s" % (tid, why))
            if st.button("Clear all dispositions"):
                overrides.links, overrides.not_applicable = {}, {}
                state.save()
                state.log("clear R155 dispositions")
                st.rerun()


render()
