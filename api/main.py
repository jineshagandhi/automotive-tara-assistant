"""REST service layer for the TARA engine.

Run with:  uvicorn api.main:app --reload
Docs:      http://127.0.0.1:8000/docs

The same engine powers the Streamlit UI. The API lets other tools (ALM,
requirements management, CI pipelines) run a TARA on an architecture model
and fetch the risk register, treatment plan or reports.
"""

from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field

from tara import __version__, knowledge
from tara.copilot import ask
from tara.engine import Overrides, TaraEngine
from tara.export import to_excel, to_html
from tara.io import example_path, load_architecture, validate
from tara.llm import get_llm
from tara.methodology import load_methodology
from tara.models import AppliedControl, Architecture, TaraResult
from tara.retrieval import KnowledgeBase

app = FastAPI(
    title="Automotive TARA Assistant API",
    description="ISO/SAE 21434 threat analysis and risk assessment with UN R155 Annex 5 grounding.",
    version=__version__,
)

_kb = None


def kb():
    global _kb
    if _kb is None:
        _kb = KnowledgeBase()
    return _kb


def engine():
    return TaraEngine(kb(), load_methodology())


class AnalyzeRequest(BaseModel):
    architecture: Architecture
    proposed_controls: list[AppliedControl] = Field(default_factory=list)
    impact_overrides: dict[str, dict[str, str]] = Field(default_factory=dict)


class PlanRequest(BaseModel):
    architecture: Architecture
    target_risk: int = Field(3, ge=1, le=5)
    max_steps: int = Field(15, ge=1, le=50)


class SearchRequest(BaseModel):
    query: str
    k: int = Field(5, ge=1, le=20)


class AskRequest(BaseModel):
    question: str
    architecture: Optional[Architecture] = None


def _checked(architecture):
    errors = validate(architecture)
    if errors:
        raise HTTPException(status_code=422, detail=errors)
    return architecture


@app.get("/health")
def health():
    llm = get_llm()
    return {"status": "ok", "version": __version__, "retrieval": kb().mode,
            "llm": {"provider": llm.name, "model": llm.model, "available": llm.available}}


@app.get("/example/architecture", response_model=Architecture)
def example_architecture():
    return load_architecture(example_path())


@app.post("/tara/analyze", response_model=TaraResult)
def analyze(request: AnalyzeRequest):
    architecture = _checked(request.architecture)
    return engine().run(architecture, extra_controls=request.proposed_controls,
                        overrides=Overrides(impacts=request.impact_overrides))


@app.post("/tara/plan")
def plan(request: PlanRequest):
    architecture = _checked(request.architecture)
    steps, risks = engine().plan_treatment(architecture, target_risk=request.target_risk,
                                           max_steps=request.max_steps)
    return {"steps": steps, "final_risk": risks}


@app.post("/tara/report.html", response_class=HTMLResponse)
def report_html(request: AnalyzeRequest):
    architecture = _checked(request.architecture)
    result = engine().run(architecture, extra_controls=request.proposed_controls)
    return to_html(result, architecture)


@app.post("/tara/report.xlsx")
def report_excel(request: AnalyzeRequest):
    architecture = _checked(request.architecture)
    result = engine().run(architecture, extra_controls=request.proposed_controls)
    return Response(to_excel(result, architecture),
                    media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": 'attachment; filename="tara.xlsx"'})


@app.get("/r155/threats")
def r155_threats():
    return knowledge.r155()["threats"]


@app.get("/r155/mitigations")
def r155_mitigations():
    return knowledge.r155()["mitigations"]


@app.get("/controls")
def controls():
    return knowledge.controls()


@app.get("/methodology")
def methodology():
    return load_methodology().profile


@app.post("/search")
def search(request: SearchRequest):
    return [{"id": h.document.id, "citation": h.document.citation, "text": h.document.text,
             "score": h.score, "lexical": h.lexical, "dense": h.dense}
            for h in kb().search(request.query, k=request.k)]


@app.post("/copilot/ask")
def copilot(request: AskRequest):
    architecture = _checked(request.architecture) if request.architecture else load_architecture(example_path())
    result = engine().run(architecture)
    answer = ask(request.question, result, architecture, kb(), get_llm(), load_methodology())
    return {"answer": answer.text, "mode": answer.mode,
            "sources": [{"tag": t, "citation": c, "snippet": s} for t, c, s in answer.sources]}
