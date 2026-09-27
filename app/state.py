"""Session state, caching and persistence shared by all pages."""

import json
import uuid
from dataclasses import asdict

import streamlit as st

from tara.engine import Overrides, TaraEngine
from tara.io import dump_architecture, example_path, load_architecture
from tara.llm import get_llm
from tara.methodology import load_methodology
from tara.models import AppliedControl, Architecture
from tara.retrieval import KnowledgeBase, knowledge_documents, load_embedder
from tara.store import Store

SAMPLE_ID = "sample-connected-ev"


# ------------------------------------------------------------------ resources

@st.cache_resource(show_spinner="Loading embedding model...")
def embedder():
    return load_embedder()


@st.cache_resource
def store():
    return Store()


@st.cache_resource(show_spinner="Building knowledge base...")
def base_knowledge_base():
    return KnowledgeBase(knowledge_documents(), embedder=embedder())


def knowledge_base():
    """The shared base, or a session copy that also holds uploaded documents."""
    docs = st.session_state.get("project_docs", [])
    if not docs:
        return base_knowledge_base()
    key = tuple(d.id for d in docs)
    if st.session_state.get("_kb_key") != key:
        st.session_state._kb = KnowledgeBase(knowledge_documents() + list(docs), embedder=embedder())
        st.session_state._kb_key = key
    return st.session_state._kb


def engine():
    return TaraEngine(knowledge_base(), load_methodology())


def method():
    return load_methodology()


@st.cache_resource(ttl=30)
def llm():
    return get_llm()


# ------------------------------------------------------------------ project state

def _state_dict():
    return {
        "overrides": asdict(st.session_state.overrides),
        "proposed": [c.model_dump() for c in st.session_state.proposed],
        "plan": st.session_state.get("plan", []),
        "plan_target": st.session_state.get("plan_target", 3),
    }


def save():
    arch = st.session_state.architecture
    store().save_project(st.session_state.project_id, arch.name, dump_architecture(arch), _state_dict())


def open_project(project_id):
    project = store().load_project(project_id)
    if project is None:
        return False
    state = project["state"]
    st.session_state.project_id = project_id
    st.session_state.architecture = load_architecture(project["architecture"])
    st.session_state.overrides = Overrides(**state.get("overrides", {}))
    st.session_state.proposed = [AppliedControl(**c) for c in state.get("proposed", [])]
    st.session_state.plan = state.get("plan", [])
    st.session_state.plan_target = state.get("plan_target", 3)
    st.session_state.project_docs = []
    st.session_state.chat = []
    return True


def new_project(architecture, project_id=None):
    st.session_state.project_id = project_id or "prj-" + uuid.uuid4().hex[:8]
    st.session_state.architecture = architecture
    st.session_state.overrides = Overrides()
    st.session_state.proposed = []
    st.session_state.plan = []
    st.session_state.plan_target = 3
    st.session_state.project_docs = []
    st.session_state.chat = []
    save()
    log("create project", architecture.name)


def init():
    if "project_id" in st.session_state:
        return
    st.session_state.reviewer = st.session_state.get("reviewer", "analyst")
    projects = store().list_projects()
    if projects and open_project(projects[0]["id"]):
        return
    new_project(load_architecture(example_path()), SAMPLE_ID)


def reset_sample():
    store().delete_project(SAMPLE_ID)
    new_project(load_architecture(example_path()), SAMPLE_ID)


def log(action, item_id="", detail=""):
    store().log(st.session_state.project_id, st.session_state.get("reviewer", "analyst"), action, item_id, detail)


def set_architecture(architecture, action="edit architecture", detail=""):
    st.session_state.architecture = architecture
    # Analyst decisions are keyed by asset and property, so they survive the edit.
    # The treatment plan is recomputed, and proposed controls on removed nodes are dropped.
    nodes = {c.id for c in architecture.components} | {b.id for b in architecture.buses} | \
        {i.id for i in architecture.interfaces}
    st.session_state.proposed = [c for c in st.session_state.proposed if c.target in nodes]
    st.session_state.plan = []
    save()
    log(action, architecture.name, detail)


# ------------------------------------------------------------------ analysis

@st.cache_data(show_spinner="Running TARA...", max_entries=32)
def _run(architecture_yaml, overrides_json, proposed_json, kb_mode, _engine):
    architecture = load_architecture(architecture_yaml)
    overrides = Overrides(**json.loads(overrides_json))
    proposed = [AppliedControl(**c) for c in json.loads(proposed_json)]
    return _engine.run(architecture, extra_controls=proposed, overrides=overrides)


def _key():
    return (dump_architecture(st.session_state.architecture),
            json.dumps(asdict(st.session_state.overrides), sort_keys=True))


def result():
    """TARA with the existing controls: the initial risk."""
    arch_yaml, overrides = _key()
    kb = knowledge_base()
    return _run(arch_yaml, overrides, "[]", kb.mode + str(len(kb.documents)), engine())


def residual_result():
    """TARA with existing and proposed controls: the residual risk."""
    arch_yaml, overrides = _key()
    proposed = json.dumps([c.model_dump() for c in st.session_state.proposed], sort_keys=True)
    kb = knowledge_base()
    return _run(arch_yaml, overrides, proposed, kb.mode + str(len(kb.documents)), engine())


def architecture() -> Architecture:
    return st.session_state.architecture


def fingerprint():
    """Changes whenever the architecture or overrides change. Used in widget keys
    so editable tables start fresh instead of re-applying stale edits."""
    import hashlib
    arch_yaml, overrides = _key()
    return hashlib.md5((arch_yaml + overrides + st.session_state.project_id).encode("utf-8")).hexdigest()[:10]


def reviews():
    return store().reviews(st.session_state.project_id)
