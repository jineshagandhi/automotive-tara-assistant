import altair as alt
import pandas as pd
import streamlit as st

from app import components as ui
from app import state
from tara.export import rows_risk_register
from tara.models import AppliedControl


def render():
    st.title("Risk determination and treatment")
    st.caption("ISO/SAE 21434 clauses 15.8 and 15.9: risk value from the risk matrix, treatment decision, "
               "cybersecurity goals with CAL, and controls ranked by risk reduction.")

    arch = state.architecture()
    result = state.result()
    method = state.method()

    tab_register, tab_goals, tab_recs, tab_plan = st.tabs([
        ":material/table: Risk register", ":material/flag: Cybersecurity goals",
        ":material/recommend: Control recommendations", ":material/auto_awesome: Treatment planner"])

    with tab_register:
        c1, c2 = st.columns([1, 1.4])
        with c1:
            st.altair_chart(ui.risk_heatmap(result, method), width="stretch")
        with c2:
            with st.container(border=True):
                st.markdown("**Risk matrix and treatment rules** (%s)" % method.name)
                matrix = pd.DataFrame(method.profile["risk_matrix"]).T[method.feasibility_levels]
                st.dataframe(ui.style_risk(matrix, method.feasibility_levels), width="stretch")
                st.caption(" · ".join("%s: %s" % (risk, rule["decision"])
                                      for risk, rule in sorted(method.profile["treatment"].items(), reverse=True)))
        df = pd.DataFrame(rows_risk_register(result, arch, state.reviews()))
        risk_filter = st.multiselect("Risk values", [5, 4, 3, 2, 1], default=[5, 4, 3, 2, 1])
        df = df[df["Risk"].isin(risk_filter)]
        st.dataframe(ui.style_risk(df), hide_index=True, width="stretch", height=520)

    with tab_goals:
        st.caption("A cybersecurity goal is proposed for every threat scenario with the decision 'Reduce'. "
                   "The CAL follows from impact and attack vector.")
        st.dataframe(pd.DataFrame([{"Goal": g.id, "Threat scenario": g.threat_scenario_id, "CAL": g.cal or "-",
                                    "Cybersecurity goal": g.text} for g in result.goals]),
                     hide_index=True, width="stretch", height=560)

    with tab_recs:
        names = ui.asset_names(arch)
        rows = []
        for ts in result.threat_scenarios:
            for rank, rec in enumerate(ts.recommendations, 1):
                rows.append({"Threat scenario": ts.id, "Asset": names[ts.asset_id], "Risk": ts.risk,
                             "Rank": rank, "Control": rec.name, "Deploy on": rec.target_label,
                             "R155": ", ".join(rec.r155), "Residual risk": rec.residual_risk,
                             "Reduction": rec.risk_reduction})
        st.caption("For each scenario, every applicable control placement on the most feasible path is tried "
                   "and ranked by the risk it removes on its own.")
        st.dataframe(ui.style_risk(pd.DataFrame(rows), ["Risk", "Residual risk"]), hide_index=True,
                     width="stretch", height=560)

    with tab_plan:
        planner(arch, method)


def planner(arch, method):
    st.markdown("The planner searches for a **small set of control placements** that brings every attack path "
                "to the target risk or below. At each step it adds the placement that removes the most risk "
                "above the target, counted over all paths, so controls that close alternative paths are found too.")
    c1, c2, c3 = st.columns([1, 1, 2])
    target = c1.select_slider("Target risk value", [2, 3, 4], value=st.session_state.get("plan_target", 3))
    max_steps = c2.number_input("Maximum controls", 3, 25, 15)
    if c3.button("Run treatment planner", type="primary", icon=":material/auto_awesome:"):
        with st.spinner("Evaluating control placements..."):
            steps, _ = state.engine().plan_treatment(arch, target_risk=target, max_steps=int(max_steps),
                                                     overrides=st.session_state.overrides)
        st.session_state.plan = steps
        st.session_state.plan_target = target
        state.save()
        state.log("run treatment planner", "", "target %d, %d controls" % (target, len(steps)))

    steps = st.session_state.get("plan", [])
    if not steps:
        st.info("Run the planner to get a proposed treatment plan.")
        return

    result = state.result()
    start = sum(1 for ts in result.threat_scenarios if ts.risk > st.session_state.plan_target)
    chart = pd.DataFrame([{"Step": 0, "Scenarios above target": start}] +
                         [{"Step": s["step"], "Scenarios above target": s["above_target"]} for s in steps])
    left, right = st.columns([1.3, 1])
    with left:
        st.dataframe(pd.DataFrame([{"Step": s["step"], "Control": s["name"], "Deploy on": s["target_label"],
                                    "R155": ", ".join(s["r155"]), "Above target": s["above_target"],
                                    "Highest risk": s["max_risk"]} for s in steps]),
                     hide_index=True, width="stretch")
    with right:
        st.altair_chart(alt.Chart(chart).mark_line(point=True).encode(
            x=alt.X("Step:O", axis=alt.Axis(labelAngle=0)), y=alt.Y("Scenarios above target:Q")).properties(height=260),
            width="stretch")

    remaining = steps[-1]["above_target"]
    if remaining:
        st.warning("%d %s above risk %d. %s a control outside the catalogue, a design change, or a "
                   "documented risk acceptance." % (
                       remaining, "scenario stays" if remaining == 1 else "scenarios stay",
                       st.session_state.plan_target, "It needs" if remaining == 1 else "They need"))
    else:
        st.success("All threat scenarios reach risk %d or lower with %d controls." % (
            st.session_state.plan_target, len(steps)))

    if st.button("Apply plan as proposed controls", icon=":material/playlist_add_check:"):
        st.session_state.proposed = [AppliedControl(control=s["control"], target=s["target"], status="proposed")
                                     for s in steps]
        state.save()
        state.log("apply treatment plan", "", "%d proposed controls" % len(steps))
        st.toast("Plan applied. Open the Control simulator to review the residual risk.", icon=":material/check:")


render()
