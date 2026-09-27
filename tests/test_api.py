from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


def example():
    return client.get("/example/architecture").json()


def test_health():
    body = client.get("/health").json()
    assert body["status"] == "ok" and body["retrieval"] == "BM25"


def test_analyze_example():
    response = client.post("/tara/analyze", json={"architecture": example()})
    assert response.status_code == 200
    body = response.json()
    assert len(body["threat_scenarios"]) == 30 and body["goals"]


def test_invalid_architecture_is_rejected():
    architecture = example()
    architecture["interfaces"][0]["component"] = "NOPE"
    response = client.post("/tara/analyze", json={"architecture": architecture})
    assert response.status_code == 422
    assert "unknown component NOPE" in str(response.json()["detail"])


def test_plan():
    body = client.post("/tara/plan", json={"architecture": example(), "target_risk": 3, "max_steps": 5}).json()
    assert len(body["steps"]) == 5 and "TS-001" in body["final_risk"]


def test_reports_and_search():
    assert client.post("/tara/report.html", json={"architecture": example()}).text.startswith("<!doctype html>")
    excel = client.post("/tara/report.xlsx", json={"architecture": example()})
    assert excel.headers["content-type"].startswith("application/vnd.openxmlformats")
    hits = client.post("/search", json={"query": "OTA update compromise", "k": 3}).json()
    assert hits[0]["id"].startswith(("R155-12", "CTRL-SIGNED_OTA"))


def test_copilot_endpoint():
    body = client.post("/copilot/ask", json={"question": "Which controls reduce TS-001?"}).json()
    assert body["mode"] == "retrieval" and body["sources"]
