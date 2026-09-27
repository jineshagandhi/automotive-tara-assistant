"""Exports, persistence, change impact and the diagram."""

import io

from openpyxl import load_workbook

from tara.compare import compare
from tara.diagram import to_dot
from tara.export import to_excel, to_html, to_json
from tara.io import dump_architecture, load_architecture
from tara.models import AppliedControl, TaraResult
from tara.store import Store


def test_excel_workbook(result, architecture):
    workbook = load_workbook(io.BytesIO(to_excel(result, architecture)))
    assert workbook.sheetnames == ["Summary", "Assets", "Damage scenarios", "Risk register", "Attack paths",
                                   "Cybersecurity goals", "Treatment plan", "R155 coverage", "Findings", "Audit log"]
    register = workbook["Risk register"]
    assert register.max_row == len(result.threat_scenarios) + 1


def test_html_report_escapes_input(result, architecture):
    architecture = architecture.model_copy(update={"name": "<script>alert(1)</script>"})
    html = to_html(result, architecture)
    assert "<script>alert(1)</script>" not in html
    assert "Risk register" in html and "UN R155 Annex 5 coverage" in html


def test_json_round_trip(result):
    assert TaraResult.model_validate_json(to_json(result)) == result


def test_yaml_round_trip(architecture):
    assert load_architecture(dump_architecture(architecture)) == architecture


def test_store(tmp_path):
    store = Store(tmp_path / "tara.db")
    store.save_project("p1", "Demo", "name: x", {"proposed": []})
    assert store.load_project("p1")["name"] == "Demo"
    store.set_review("p1", "TS-001", "Accepted", "alice", "checked")
    assert store.reviews("p1")["TS-001"]["reviewer"] == "alice"
    assert store.audit("p1")[0]["action"] == "review"
    store.save_baseline("p1", "v1", "{}", "alice")
    assert store.baselines("p1")[0]["name"] == "v1"
    store.delete_project("p1")
    assert store.load_project("p1") is None and store.audit("p1") == []


def test_compare_detects_reduced_risk(engine, architecture, result):
    after = engine.run(architecture, extra_controls=[AppliedControl(control="SECOC", target="CAN_CH")])
    diff = compare(result, after)
    reduced = [c for c in diff["scenarios"] if c["change"] == "Reduced"]
    assert any(c["asset"] == "A_BRAKE" for c in reduced)
    assert "No message authentication on Chassis CAN-FD" in diff["resolved_findings"]


def test_diagram_highlights_path(architecture):
    dot = to_dot(architecture, highlight_path=["IF_OBD", "CGW", "CAN_CH", "ESC"])
    assert dot.startswith("graph architecture {") and dot.rstrip().endswith("}")
    assert '"IF_OBD" -- "CGW" [style=solid' in dot
    assert "#c1121f" in dot
