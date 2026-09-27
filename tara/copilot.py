"""TARA copilot: grounded question answering over the analysis and the knowledge base.

The answer is built only from retrieved sources (UN R155 Annex 5, the control
catalogue, uploaded project documents) and rows of the current TARA. Every
source gets a tag such as [S1] or [TS-004] that the answer must cite. Without
an LLM the copilot answers from the same sources with templates.
"""

import re
from dataclasses import dataclass, field

from tara.explain import explain_threat
from tara.llm import LLMUnavailable

SYSTEM_PROMPT = """You are a cybersecurity engineer assisting with an automotive
Threat Analysis and Risk Assessment (TARA) under ISO/SAE 21434 and UN R155.

Rules:
- Answer only from the CONTEXT. If the context does not contain the answer, say so.
- Cite every statement with the tags from the context, for example [S2] or [TS-004].
- Never invent threat ids, mitigation ids, risk values or standards clauses.
- Be concise and use engineering language. Use short bullet points where helpful.
- The analyst makes the final decision; phrase recommendations as proposals."""


@dataclass
class Answer:
    text: str
    sources: list = field(default_factory=list)   # (tag, citation, snippet)
    mode: str = "retrieval"


GENERIC_WORDS = {"control", "function", "messages", "message", "module", "system", "unit", "data",
                 "vehicle", "parameters", "value", "values", "requests", "service", "services",
                 "and", "the", "for", "with", "from", "what", "how", "why", "does", "can", "are",
                 "which", "this", "that", "about", "into", "under", "require", "attacker"}


def _words(text):
    return {w for w in re.findall(r"[a-z0-9]+", re.sub(r"\(.*?\)", " ", text.lower()))
            if len(w) > 2 and w not in GENERIC_WORDS}


def _mentioned_scenarios(question, result, architecture):
    """Threat scenarios the question is about, best match first.

    Explicit ids (TS-004) win. Otherwise assets and components are scored by
    the distinctive words of their name that appear in the question, ignoring
    generic words such as 'control' or 'unit'.
    """
    q = question.lower()
    ids = set(re.findall(r"ts-\d{3}", q))
    if ids:
        return [ts for ts in result.threat_scenarios if ts.id.lower() in ids]

    q_words = _words(question)
    scores = {}
    for asset in architecture.assets:
        overlap = len(_words(asset.name) & q_words)
        if overlap:
            scores[asset.id] = overlap
    for component in architecture.components:
        words = _words(component.name) | {component.id.lower()}
        overlap = len(words & (q_words | set(re.findall(r"[a-z0-9]+", q))))
        if overlap:
            for asset in architecture.assets:
                if asset.component == component.id:
                    scores[asset.id] = max(scores.get(asset.id, 0), overlap)
    if not scores:
        return []
    best = max(scores.values())
    chosen = {a for a, score in scores.items() if score == best}
    return sorted((ts for ts in result.threat_scenarios if ts.asset_id in chosen), key=lambda t: (-t.risk, t.id))


def build_context(question, result, architecture, kb, k=6):
    hits = kb.search(question, k=k)
    sources = []
    blocks = []
    for n, hit in enumerate(hits, 1):
        tag = "S%d" % n
        sources.append((tag, hit.document.citation, hit.document.text[:300]))
        blocks.append("[%s] %s\n%s" % (tag, hit.document.citation, hit.document.content))

    scenarios = _mentioned_scenarios(question, result, architecture)
    if not scenarios:
        scenarios = sorted(result.threat_scenarios, key=lambda t: -t.risk)[:6]
    for ts in scenarios[:8]:
        best = ts.paths[0]
        rows = "risk %d (%s impact, %s feasibility), treatment %s, path %s, R155 %s, top control %s" % (
            ts.risk, ts.impact, ts.feasibility, ts.treatment,
            " > ".join(s.label for s in best.steps),
            ", ".join(m.threat_id for m in ts.r155) or "none",
            ts.recommendations[0].name if ts.recommendations else "none")
        blocks.append("[%s] %s: %s" % (ts.id, ts.description, rows))
        sources.append((ts.id, "Current TARA, %s" % ts.id, ts.description))

    return "\n\n".join(blocks), sources, scenarios


def ask(question, result, architecture, kb, llm, method):
    context, sources, scenarios = build_context(question, result, architecture, kb)

    if llm.available:
        prompt = "CONTEXT\n%s\n\nQUESTION\n%s" % (context, question)
        try:
            text = llm.chat(SYSTEM_PROMPT, prompt)
            return Answer(text=text, sources=sources, mode="llm (%s %s)" % (llm.name, llm.model))
        except LLMUnavailable:
            pass

    # Retrieval-only answer: explain the matching scenario and list the evidence
    parts = []
    if scenarios and _mentioned_scenarios(question, result, architecture):
        parts.append(explain_threat(scenarios[0], result, architecture, method))
        if len(scenarios) > 1:
            parts.append("\nOther related scenarios: " + ", ".join(
                "%s (risk %d)" % (ts.id, ts.risk) for ts in scenarios[1:6]))
    else:
        parts.append("Most relevant sources for your question:")
    parts.append("")
    for tag, citation, snippet in sources:
        if tag.startswith("S"):
            parts.append("- **[%s] %s**: %s" % (tag, citation, snippet))
    parts.append("\n_No language model is connected, so this answer is built from retrieval "
                 "and the TARA rules. Start Ollama for generated answers._")
    return Answer(text="\n".join(parts), sources=sources, mode="retrieval")
