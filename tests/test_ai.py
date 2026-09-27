"""Architecture extraction and copilot, with and without a language model."""

import json

from tara.copilot import ask
from tara.extraction import extract, extract_with_keywords, read_document
from tara.io import example_path
from tara.llm import BaseLLM, NoLLM


class FakeLLM(BaseLLM):
    name = "fake"
    model = "fake-model"

    def __init__(self, reply):
        self.reply = reply
        self.prompts = []

    @property
    def available(self):
        return True

    def chat(self, system, user, json_mode=False, temperature=0.1):
        self.prompts.append((system, user))
        return self.reply


def test_keyword_extraction_of_sample_hld():
    text = example_path("sample_hld.md").read_text(encoding="utf-8")
    architecture, errors, how = extract_with_keywords(text)
    assert errors == [] and how == "keyword extractor"
    buses = {b.name: set(b.members) for b in architecture.buses}
    assert buses["Chassis CAN-FD"] == {"ADAS", "CGW", "EPS", "ESC"}
    assert buses["Powertrain CAN-FD"] == {"BMS", "CGW", "OBC", "VCU"}
    types = {i.type for i in architecture.interfaces}
    assert {"cellular", "ota", "wifi", "bluetooth", "usb", "obd", "ev_charging", "ble_key"} <= types


def test_read_markdown_document():
    pages = read_document("hld.md", "# Title\nThe TCU uses LTE.".encode("utf-8"))
    assert pages == [(None, "# Title\nThe TCU uses LTE.")]


def test_llm_extraction_is_validated():
    reply = json.dumps({
        "name": "Mini", "description": "",
        "components": [{"id": "TCU", "name": "Telematics", "type": "telematics", "zone": "connectivity"},
                       {"id": "ESC", "name": "Brakes", "type": "ecu", "zone": "chassis", "asil": "D"}],
        "buses": [{"id": "CAN1", "name": "Chassis CAN", "type": "CAN", "members": ["TCU", "ESC"]}],
        "interfaces": [{"id": "IF_CELL", "type": "cellular", "component": "TCU"}],
        "assets": [{"id": "A1", "name": "brake requests", "type": "message", "component": "ESC",
                    "properties": ["Integrity"], "asil": "D"}],
    })
    llm = FakeLLM("Here is the model:\n" + reply)
    architecture, errors, how = extract("any document", llm)
    assert errors == [] and how.startswith("llm")
    assert [c.id for c in architecture.components] == ["TCU", "ESC"]


def test_llm_extraction_falls_back_on_bad_json():
    text = example_path("sample_hld.md").read_text(encoding="utf-8")
    architecture, errors, how = extract(text, FakeLLM("not json at all"))
    assert how == "keyword extractor" and architecture.components


def test_copilot_retrieval_mode_explains_scenario(result, architecture, kb, method):
    answer = ask("Why is TS-001 rated like this?", result, architecture, kb, NoLLM(), method)
    assert answer.mode == "retrieval"
    assert "TS-001" in answer.text and "Risk value" in answer.text
    assert any(tag.startswith("S") for tag, _, _ in answer.sources)


def test_copilot_grounds_the_llm(result, architecture, kb, method):
    llm = FakeLLM("Use SecOC on the chassis CAN [S1] [TS-001].")
    answer = ask("How do I protect the brake request messages?", result, architecture, kb, llm, method)
    system, prompt = llm.prompts[0]
    assert "Answer only from the CONTEXT" in system
    assert "[S1]" in prompt and "brake request messages" in prompt
    assert answer.mode.startswith("llm") and answer.text.startswith("Use SecOC")


def test_copilot_finds_the_asset_the_question_is_about(result, architecture):
    from tara.copilot import _mentioned_scenarios
    found = _mentioned_scenarios("How can an attacker reach the brake control unit, and what does UN R155 require?",
                                 result, architecture)
    assert found and {t.asset_id for t in found} <= {"A_BRAKE", "A_ESC_FW"}
    assert _mentioned_scenarios("What does UN R155 say in general?", result, architecture) == []
