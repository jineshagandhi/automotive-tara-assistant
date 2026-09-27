import re

import streamlit as st

from app import state
from tara.export import to_excel, to_html, to_json
from tara.io import dump_architecture


def render():
    st.title("Reports")
    st.caption("Export the TARA for review meetings, type approval evidence or downstream tools.")

    arch = state.architecture()
    result = state.result()
    reviews = state.reviews()
    audit = state.store().audit(st.session_state.project_id)
    plan = st.session_state.get("plan", [])
    slug = re.sub(r"[^a-z0-9]+", "-", arch.name.lower()).strip("-")

    c1, c2, c3, c4 = st.columns(4)
    c1.download_button("Excel workbook", to_excel(result, arch, reviews, audit, plan), file_name="%s-tara.xlsx" % slug,
                       mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                       icon=":material/table_view:", width="stretch", type="primary")
    report = to_html(result, arch, reviews, plan)
    c2.download_button("HTML report", report, file_name="%s-tara.html" % slug, mime="text/html",
                       icon=":material/description:", width="stretch")
    c3.download_button("JSON (full result)", to_json(result), file_name="%s-tara.json" % slug,
                       mime="application/json", icon=":material/data_object:", width="stretch")
    c4.download_button("Architecture YAML", dump_architecture(arch), file_name="%s.yaml" % slug,
                       mime="text/yaml", icon=":material/code:", width="stretch")

    st.caption("The Excel workbook has sheets for the summary, assets, damage scenarios, risk register, attack "
               "paths, cybersecurity goals, treatment plan, R155 coverage, findings and the audit log. "
               "The HTML report prints to PDF from the browser.")
    st.subheader("Report preview")
    # All user supplied text in the report is escaped in tara.export.to_html
    st.iframe(report, height=900)


render()
