"""Smoke test: every page of the Streamlit app renders without an exception."""

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

APP = str(Path(__file__).resolve().parents[1] / "app" / "main.py")
PAGES = ["architecture", "damage", "threats", "treatment", "simulator", "coverage", "review",
         "reports", "copilot", "knowledge_page"]


@pytest.fixture(scope="module")
def app():
    at = AppTest.from_file(APP, default_timeout=120)
    at.run()
    return at


def test_overview(app):
    assert not app.exception
    assert app.title[0].value == "Connected EV - concept phase"


@pytest.mark.parametrize("page", PAGES)
def test_page_renders(app, page):
    app.switch_page("views/%s.py" % page)
    app.run()
    assert not app.exception, [e.value for e in app.exception]
    assert app.title


def test_planner_and_simulator(app):
    app.switch_page("views/treatment.py")
    app.run()
    next(b for b in app.button if b.label == "Run treatment planner").click().run()
    assert app.session_state.plan
    next(b for b in app.button if b.label == "Apply plan as proposed controls").click().run()
    assert len(app.session_state.proposed) == len(app.session_state.plan)
    app.switch_page("views/simulator.py")
    app.run()
    assert not app.exception


def test_review_survives_architecture_edit(app):
    import yaml

    from tara.store import Store

    project = app.session_state.project_id
    Store().set_review(project, "A_BRAKE/Integrity", "Accepted", "tester", "ok")

    app.switch_page("views/architecture.py")
    app.run()
    area = next(t for t in app.text_area if t.label == "Architecture as YAML")
    data = yaml.safe_load(area.value)
    data["assets"].insert(0, {"id": "A_NEW", "name": "new sensor data", "type": "message",
                              "component": "BCM", "properties": ["Integrity"]})
    area.set_value(yaml.safe_dump(data, sort_keys=False))
    next(b for b in app.button if b.label == "Apply YAML").click().run()
    assert not app.exception

    arch = app.session_state.architecture
    assert arch.assets[0].id == "A_NEW"
    assert Store().reviews(project)["A_BRAKE/Integrity"]["status"] == "Accepted"
    app.switch_page("views/review.py")
    app.run()
    assert not app.exception
