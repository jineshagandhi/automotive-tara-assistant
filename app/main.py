"""Automotive TARA Assistant, Streamlit entry point.

Run with:  streamlit run app/main.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import streamlit as st  # noqa: E402

st.set_page_config(page_title="Automotive TARA Assistant", page_icon=":material/shield_lock:", layout="wide")

from app import components, state  # noqa: E402
from tara import __version__  # noqa: E402

ASSETS = Path(__file__).parent / "assets"
st.logo(str(ASSETS / "logo.svg"), size="large", icon_image=str(ASSETS / "icon.svg"))
components.inject_css()
state.init()


def sidebar():
    with st.sidebar:
        st.caption("Version %s" % __version__)
        projects = state.store().list_projects()
        ids = [p["id"] for p in projects]
        names = {p["id"]: p["name"] for p in projects}
        current = st.session_state.project_id
        if current not in ids:
            ids.insert(0, current)
            names[current] = state.architecture().name
        choice = st.selectbox("Project", ids, index=ids.index(current), format_func=lambda i: names[i])
        if choice != current:
            state.open_project(choice)
            st.rerun()

        with st.popover("Project actions", width="stretch"):
            if st.button("Reload sample project", width="stretch"):
                state.reset_sample()
                st.rerun()
            if current != state.SAMPLE_ID and st.button("Delete this project", width="stretch"):
                state.store().delete_project(current)
                del st.session_state["project_id"]
                st.rerun()

        st.session_state.reviewer = st.text_input(
            "Reviewer", st.session_state.get("reviewer", "analyst"),
            help="Recorded in the audit log for every decision")

        st.divider()
        llm = state.llm()
        kb = state.knowledge_base()
        if llm.available:
            st.markdown(":green[:material/smart_toy:] LLM: **%s** (%s)" % (llm.model, llm.name))
        else:
            st.markdown(":orange[:material/smart_toy:] LLM: not connected, "
                        "running in retrieval mode")
        st.markdown(":material/manage_search: Retrieval: %s" % kb.mode)
        st.markdown(":material/rule: %s" % state.method().name)


sidebar()

pages = {
    "TARA workflow": [
        st.Page("views/overview.py", title="Overview", icon=":material/dashboard:", default=True),
        st.Page("views/architecture.py", title="1 · Architecture", icon=":material/account_tree:", url_path="architecture"),
        st.Page("views/damage.py", title="2 · Damage scenarios", icon=":material/warning:", url_path="damage"),
        st.Page("views/threats.py", title="3 · Threats and attack paths", icon=":material/route:", url_path="threats"),
        st.Page("views/treatment.py", title="4 · Risk and treatment", icon=":material/health_and_safety:", url_path="treatment"),
        st.Page("views/simulator.py", title="5 · Control simulator", icon=":material/tune:", url_path="simulator"),
    ],
    "Assurance": [
        st.Page("views/coverage.py", title="UN R155 coverage", icon=":material/verified:", url_path="r155"),
        st.Page("views/review.py", title="Review and audit", icon=":material/fact_check:", url_path="review"),
        st.Page("views/reports.py", title="Reports", icon=":material/description:", url_path="reports"),
    ],
    "Assistant": [
        st.Page("views/copilot.py", title="TARA copilot", icon=":material/forum:", url_path="copilot"),
        st.Page("views/knowledge_page.py", title="Methodology and knowledge", icon=":material/menu_book:", url_path="knowledge"),
    ],
}

st.navigation(pages).run()
