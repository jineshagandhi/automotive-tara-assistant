import pandas as pd
import streamlit as st

from app import components as ui
from app import state


def render():
    st.title("Damage scenarios and impact rating")
    st.caption("ISO/SAE 21434 clause 15.3 and 15.5. The engine proposes Safety, Financial, Operational and "
               "Privacy impact from the rules in knowledge/impact_rules.yaml. Change any rating in the table; "
               "the change is recorded as an analyst override.")

    arch = state.architecture()
    result = state.result()
    method = state.method()
    names = ui.asset_names(arch)
    categories = method.impact_categories

    rows = []
    for ds in result.damage_scenarios:
        row = {"ID": ds.id, "Asset": names[ds.asset_id], "Property": ds.property}
        for impact in ds.impacts:
            row[impact.category] = impact.level
        row["Overall"] = ds.impact
        row["Analyst"] = any(i.overridden for i in ds.impacts)
        rows.append(row)
    original = pd.DataFrame(rows)

    edited = st.data_editor(
        original, hide_index=True, width="stretch", key="impact_editor_" + state.fingerprint(),
        disabled=["ID", "Asset", "Property", "Overall", "Analyst"],
        column_config={c: st.column_config.SelectboxColumn(options=method.impact_levels, required=True)
                       for c in categories} | {"Analyst": st.column_config.CheckboxColumn(help="Overridden by an analyst")},
    )

    keys = {ds.id: ds.key for ds in result.damage_scenarios}
    changes = []
    for (_, before), (_, after) in zip(original.iterrows(), edited.iterrows()):
        for category in categories:
            if before[category] != after[category]:
                changes.append((after["ID"], category, before[category], after[category]))
    if changes:
        overrides = st.session_state.overrides
        for ds_id, category, old, new in changes:
            overrides.impacts.setdefault(keys[ds_id], {})[category] = new
            state.log("override impact", ds_id, "%s: %s -> %s" % (category, old, new))
        state.save()
        st.rerun()

    c1, c2 = st.columns([1, 3])
    if c1.button("Reset all impact overrides", disabled=not st.session_state.overrides.impacts):
        st.session_state.overrides.impacts = {}
        state.save()
        state.log("reset impact overrides")
        st.rerun()

    st.subheader("Rationale")
    ds_id = st.selectbox("Damage scenario", [d.id for d in result.damage_scenarios],
                         format_func=lambda i: "%s: %s" % (i, next(d.description for d in result.damage_scenarios if d.id == i)))
    ds = next(d for d in result.damage_scenarios if d.id == ds_id)
    st.markdown("**%s**" % ds.description)
    st.dataframe(pd.DataFrame([{"Category": i.category, "Level": i.level, "Rationale": i.rationale,
                                "Source": "Analyst" if i.overridden else "Rule"} for i in ds.impacts]),
                 hide_index=True, width="stretch")


render()
