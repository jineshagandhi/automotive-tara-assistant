import pandas as pd
import streamlit as st

from app import state
from tara import knowledge
from tara.diagram import VECTOR_COLOURS, to_dot
from tara.extraction import extract, read_document
from tara.io import dump_architecture, example_path, load_architecture
from tara.retrieval import chunk_text

COMPONENT_TYPES = ["telematics", "infotainment", "gateway", "ecu", "sensor", "backend"]
BUS_TYPES = ["CAN", "CAN-FD", "LIN", "FlexRay", "Ethernet", "Cellular", "Internal"]
ASSET_TYPES = ["message", "function", "firmware", "key", "personal_data", "configuration", "diagnostic", "log", "service"]
ASIL = ["QM", "A", "B", "C", "D"]


def _split(value):
    return [v.strip() for v in str(value or "").split(",") if v.strip()]


def render():
    st.title("Architecture")
    st.caption("The item under analysis: components, networks, external interfaces, assets and existing controls.")
    arch = state.architecture()

    tab_diagram, tab_edit, tab_yaml, tab_import = st.tabs(
        [":material/account_tree: Diagram", ":material/edit: Edit model", ":material/code: YAML",
         ":material/upload_file: Import from document"])

    with tab_diagram:
        diagram(arch)
    with tab_edit:
        editor(arch)
    with tab_yaml:
        yaml_editor(arch)
    with tab_import:
        importer()


def diagram(arch):
    result = state.result()
    options = ["None"] + ["Finding: %s" % f.title for f in result.findings] + \
        ["%s: %s" % (ts.id, ts.description) for ts in sorted(result.threat_scenarios, key=lambda t: -t.risk)]
    choice = st.selectbox("Highlight", options, help="Show an architecture finding or the most feasible "
                                                     "attack path of a threat scenario")
    path, nodes = None, None
    if choice.startswith("Finding: "):
        finding = next(f for f in result.findings if f.title == choice[len("Finding: "):])
        nodes = finding.nodes
        st.warning("**%s.** %s" % (finding.title, finding.detail), icon=":material/report:")
    elif choice != "None":
        ts = next(t for t in result.threat_scenarios if choice.startswith(t.id + ":"))
        best = ts.paths[0]
        path = [s.node for s in best.steps if s.node != "direct"]
        st.info("Most feasible path, attack potential %d (%s feasibility): %s" % (
            best.attack_potential, best.feasibility, " > ".join(s.label for s in best.steps)),
            icon=":material/route:")

    st.graphviz_chart(to_dot(arch, highlight_path=path, highlight_nodes=nodes,
                             extra_controls=st.session_state.proposed), width="stretch")
    legend = " ".join(
        '<span class="badge" style="background:%s">%s</span>' % (colour, vector)
        for vector, colour in VECTOR_COLOURS.items())
    st.markdown("Interface attack vector: %s &nbsp; `+` existing control &nbsp; `*` proposed control" % legend,
                unsafe_allow_html=True)


def editor(arch):
    st.caption("Edit the tables, then apply. Lists (bus members, asset properties, tags) are comma separated.")
    interface_types = list(knowledge.interfaces())
    control_keys = list(knowledge.controls())
    version = state.fingerprint()

    components = st.data_editor(pd.DataFrame([c.model_dump() for c in arch.components]), num_rows="dynamic",
                                width="stretch", key="ed_components_" + version, column_config={
        "type": st.column_config.SelectboxColumn(options=COMPONENT_TYPES, required=True),
        "asil": st.column_config.SelectboxColumn(options=ASIL, required=True),
    })
    st.markdown("**Networks**")
    buses = st.data_editor(pd.DataFrame([{**b.model_dump(), "members": ", ".join(b.members)} for b in arch.buses]),
                           num_rows="dynamic", width="stretch", key="ed_buses_" + version, column_config={
        "type": st.column_config.SelectboxColumn(options=BUS_TYPES, required=True),
    })
    st.markdown("**External interfaces**")
    interfaces = st.data_editor(pd.DataFrame([{**i.model_dump(), "targets": ", ".join(i.targets)}
                                              for i in arch.interfaces]),
                                num_rows="dynamic", width="stretch", key="ed_interfaces_" + version, column_config={
        "type": st.column_config.SelectboxColumn(options=interface_types, required=True),
        "targets": st.column_config.TextColumn(help="Receive-only links: asset ids fed by the link"),
    })
    st.markdown("**Assets**")
    assets = st.data_editor(pd.DataFrame([{**a.model_dump(), "properties": ", ".join(a.properties),
                                           "tags": ", ".join(a.tags)} for a in arch.assets]),
                            num_rows="dynamic", width="stretch", key="ed_assets_" + version, column_config={
        "type": st.column_config.SelectboxColumn(options=ASSET_TYPES, required=True),
        "asil": st.column_config.SelectboxColumn(options=ASIL, required=True),
        "personal_data": st.column_config.SelectboxColumn(options=["none", "personal", "sensitive"], required=True),
        "properties": st.column_config.TextColumn(help="Confidentiality, Integrity, Availability, Authenticity"),
    })
    st.markdown("**Existing controls**")
    controls = st.data_editor(pd.DataFrame([c.model_dump() for c in arch.controls] or
                                           [{"control": None, "target": None, "status": "existing"}]).dropna(how="all"),
                              num_rows="dynamic", width="stretch", key="ed_controls_" + version, column_config={
        "control": st.column_config.SelectboxColumn(options=control_keys, required=True),
        "status": st.column_config.SelectboxColumn(options=["existing"], default="existing"),
    })

    if st.button("Apply changes", type="primary", icon=":material/check:"):
        data = {
            "name": arch.name, "description": arch.description, "version": arch.version,
            "components": components.fillna("").to_dict("records"),
            "buses": [{**r, "members": _split(r["members"])} for r in buses.fillna("").to_dict("records")],
            "interfaces": [{**r, "targets": _split(r.get("targets"))} for r in interfaces.fillna("").to_dict("records")],
            "assets": [{**r, "properties": _split(r["properties"]), "tags": _split(r["tags"])}
                       for r in assets.fillna("").to_dict("records")],
            "controls": [r for r in controls.fillna("").to_dict("records") if r.get("control")],
        }
        try:
            updated = load_architecture(data)
        except Exception as error:
            st.error(str(error))
            return
        state.set_architecture(updated, "edit architecture", "table editor")
        st.toast("Architecture updated, TARA recalculated", icon=":material/check:")
        st.rerun()


def yaml_editor(arch):
    text = st.text_area("Architecture as YAML", dump_architecture(arch), height=480,
                        key="yaml_text_" + state.fingerprint())
    c1, c2 = st.columns([1, 4])
    if c1.button("Apply YAML", type="primary"):
        try:
            updated = load_architecture(text)
        except Exception as error:
            st.error(str(error))
        else:
            state.set_architecture(updated, "edit architecture", "YAML editor")
            st.rerun()
    c2.download_button("Download YAML", dump_architecture(arch), file_name="architecture.yaml", mime="text/yaml")


def importer():
    st.markdown("Start a new project from an architecture file, or let the assistant draft the model from a "
                "design document (HLD, system description). The draft is always reviewed before use.")
    upload = st.file_uploader("Architecture YAML/JSON or design document (PDF, Markdown, text)",
                              type=["yaml", "yml", "json", "pdf", "md", "txt"])
    use_sample = st.button("Try with the sample HLD document", icon=":material/science:")

    if use_sample:
        path = example_path("sample_hld.md")
        st.session_state.import_doc = (path.name, path.read_bytes())
    elif upload is not None:
        st.session_state.import_doc = (upload.name, upload.getvalue())

    if "import_doc" not in st.session_state:
        return
    name, data = st.session_state.import_doc

    if name.lower().endswith((".yaml", ".yml", ".json")):
        try:
            draft, errors, how = load_architecture(data.decode("utf-8")), [], "file"
        except Exception as error:
            st.error(str(error))
            return
        pages = []
    else:
        pages = read_document(name, data)
        text = "\n\n".join(t for _, t in pages)
        with st.spinner("Extracting architecture..."):
            draft, errors, how = extract(text, state.llm(), name=name.rsplit(".", 1)[0])

    st.success("Draft from **%s** using the %s: %d components, %d networks, %d interfaces, %d assets." % (
        name, how, len(draft.components), len(draft.buses), len(draft.interfaces), len(draft.assets)),
        icon=":material/auto_awesome:")
    for error in errors:
        st.warning(error)
    st.graphviz_chart(to_dot(draft), width="stretch")

    c1, c2 = st.columns(2)
    if c1.button("Create a new project from this draft", type="primary", disabled=bool(errors)):
        state.new_project(draft)
        if pages:
            chunks = [c for page, text in pages for c in chunk_text(text, name, page=page)]
            st.session_state.project_docs = chunks
        del st.session_state["import_doc"]
        st.rerun()
    if pages and c2.button("Only add the document to the copilot knowledge base"):
        chunks = [c for page, text in pages for c in chunk_text(text, name, page=page)]
        st.session_state.project_docs = st.session_state.get("project_docs", []) + chunks
        state.log("add document", name, "%d chunks" % len(chunks))
        st.toast("%d chunks from %s added to the copilot" % (len(chunks), name))


render()
