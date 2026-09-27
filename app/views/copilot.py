import streamlit as st

from app import state
from tara.copilot import ask

EXAMPLES = [
    "Why is TS-001 rated risk 4 and what reduces it?",
    "Which R155 mitigations apply to OTA update packages?",
    "How can an attacker reach the brake control unit?",
    "What does UN R155 say about diagnostic access through the OBD port?",
]


def render():
    st.title("TARA copilot")
    llm = state.llm()
    kb = state.knowledge_base()
    if llm.available:
        st.caption("Answers from **%s** grounded in UN R155 Annex 5, the control catalogue, uploaded documents "
                   "and the current TARA. Every statement cites its source." % llm.model)
    else:
        st.caption("No language model connected: answers are built from retrieval and the TARA rules. "
                   "Start Ollama (`ollama pull qwen2.5:7b`) for generated answers.")
    docs = st.session_state.get("project_docs", [])
    if docs:
        st.caption("Project documents in the knowledge base: %s" % ", ".join(sorted({d.meta["source"] for d in docs})))

    history = st.session_state.setdefault("chat", [])
    cols = st.columns(len(EXAMPLES))
    clicked = None
    for col, example in zip(cols, EXAMPLES):
        if col.button(example, width="stretch"):
            clicked = example

    for message in history:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
            if message.get("sources"):
                with st.expander("Sources"):
                    for tag, citation, snippet in message["sources"]:
                        st.markdown("**[%s]** %s  \n<span class='cite'>%s</span>" % (tag, citation, snippet),
                                    unsafe_allow_html=True)

    question = st.chat_input("Ask about the TARA, a threat, a control or UN R155") or clicked
    if not question:
        return

    history.append({"role": "user", "content": question})
    with st.chat_message("user"):
        st.markdown(question)
    with st.chat_message("assistant"):
        with st.spinner("Retrieving evidence..."):
            answer = ask(question, state.result(), state.architecture(), kb, llm, state.method())
        st.markdown(answer.text)
        st.caption("Mode: %s" % answer.mode)
    history.append({"role": "assistant", "content": answer.text + "\n\n_Mode: %s_" % answer.mode,
                    "sources": answer.sources})
    state.log("copilot question", "", question[:200])
    st.rerun()


render()
