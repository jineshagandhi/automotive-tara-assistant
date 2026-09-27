import pandas as pd
import streamlit as st

from app import components as ui
from app import state
from tara import knowledge


def render():
    st.title("Methodology and knowledge base")
    method = state.method()

    tab_method, tab_r155, tab_search, tab_interfaces, tab_controls, tab_llm = st.tabs([
        "Methodology profile", "UN R155 Annex 5", "Knowledge search", "Interface catalogue",
        "Control catalogue", "LLM setup"])

    with tab_method:
        st.markdown("Profile **%s** (version %s). All rating tables below come from this YAML file and can be "
                    "replaced with an organisation's approved rules via `TARA_PROFILE`." % (
                        method.name, method.profile["version"]))
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Attack potential factors**")
            rows = []
            for factor, spec in method.factors.items():
                for level in spec["levels"]:
                    rows.append({"Factor": spec["label"], "Level": level["name"], "Value": level["value"]})
            st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", height=420)
        with c2:
            st.markdown("**Attack potential to feasibility**")
            bands, low = [], 0
            for band in method.profile["attack_potential"]["rating"]:
                bands.append({"Attack potential": "%d-%s" % (low, band["max"] if band["max"] < 999 else "+"),
                              "Feasibility": band["rating"]})
                low = band["max"] + 1
            st.dataframe(pd.DataFrame(bands), hide_index=True, width="stretch")
            st.markdown("**Risk matrix**")
            matrix = pd.DataFrame(method.profile["risk_matrix"]).T[method.feasibility_levels]
            st.dataframe(ui.style_risk(matrix, method.feasibility_levels), width="stretch")
            st.markdown("**CAL determination**")
            st.dataframe(pd.DataFrame(method.profile["cal_matrix"]).T.fillna("-"), width="stretch")

    with tab_r155:
        source = knowledge.r155()["source"]
        st.markdown("Parsed from **%s**, %s ([EUR-Lex](%s)) by `scripts/build_r155_library.py`." % (
            source["title"], source["publication"], source["url"]))
        threats = pd.DataFrame([{"ID": t["id"], "Category": t["category"], "High-level threat": t["high_level"],
                                 "Example of vulnerability or attack method": t["text"],
                                 "Mitigations": ", ".join(t["mitigations"])} for t in knowledge.r155()["threats"]])
        st.dataframe(threats, hide_index=True, width="stretch", height=380)
        st.dataframe(pd.DataFrame([{"ID": m["id"], "Mitigation": m["text"], "Tables": ", ".join(m["tables"])}
                                   for m in knowledge.r155()["mitigations"]]), hide_index=True, width="stretch")

    with tab_search:
        kb = state.knowledge_base()
        st.caption("Retrieval mode: %s over %d documents. Reciprocal rank fusion of lexical and dense rankings." % (
            kb.mode, len(kb.documents)))
        query = st.text_input("Search", "attacker replays diagnostic messages to reprogram an ECU")
        if query:
            hits = kb.search(query, k=8)
            st.dataframe(pd.DataFrame([{"Source": h.document.citation, "Text": h.document.text[:180],
                                        "Fused score": h.score, "BM25 (norm.)": h.lexical,
                                        "Cosine": h.dense} for h in hits]), hide_index=True, width="stretch")

    with tab_interfaces:
        st.dataframe(pd.DataFrame([{"Type": k, "Interface": v["label"], "Attack vector": v["attack_vector"],
                                    **{f.replace("_", " ").capitalize(): l for f, l in v["factors"].items()},
                                    "Can pivot": v.get("pivot", True), "Typical R155 threats": ", ".join(v["r155"])}
                                   for k, v in knowledge.interfaces().items()]), hide_index=True, width="stretch")

    with tab_controls:
        st.dataframe(pd.DataFrame([{"Key": k, "Control": v["name"], "R155": ", ".join(v["r155"]),
                                    "Placement": ", ".join(v["placement"]), "Protects": ", ".join(v["protects"]),
                                    "Effect": ", ".join("%s +%d" % e for e in v["effect"].items()),
                                    "Reference": v["reference"]} for k, v in knowledge.controls().items()]),
                     hide_index=True, width="stretch", height=520)

    with tab_llm:
        llm = state.llm()
        st.markdown("Current provider: **%s**, model **%s**, available: **%s**" % (llm.name, llm.model, llm.available))
        st.markdown("""
The assistant keeps engineering data inside the organisation: the default is a **local model through Ollama**.

```
# Install Ollama from https://ollama.com, then once:
ollama pull qwen2.5:7b
# Restart the app: the model is detected automatically
```

Without a model every feature still works. The copilot answers from retrieval and the TARA rules, and
architecture import uses the keyword extractor.
""")


render()
