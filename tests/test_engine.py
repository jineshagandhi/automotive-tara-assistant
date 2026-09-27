from collections import Counter

from conftest import scenario

from tara.engine import Overrides
from tara.io import load_architecture
from tara.models import AppliedControl


def test_one_scenario_per_asset_property(result, architecture):
    expected = sum(len(a.properties) for a in architecture.assets)
    assert len(result.damage_scenarios) == len(result.threat_scenarios) == expected


def test_brake_manipulation_is_severe_safety_impact(result):
    ds = next(d for d in result.damage_scenarios if d.asset_id == "A_BRAKE" and d.property == "Integrity")
    safety = next(i for i in ds.impacts if i.category == "Safety")
    assert safety.level == "Severe" and ds.impact == "Severe"


def test_privacy_impact_for_location_history(result):
    ds = next(d for d in result.damage_scenarios if d.asset_id == "A_LOC")
    assert next(i for i in ds.impacts if i.category == "Privacy").level == "Severe"


def test_risk_follows_matrix(result, method):
    for ts in result.threat_scenarios:
        assert ts.risk == method.risk_value(ts.impact, ts.feasibility)
        assert ts.feasibility == ts.paths[0].feasibility
        assert ts.paths[0].attack_potential == min(p.attack_potential for p in ts.paths)


def test_goals_for_every_reduce_decision(result):
    reduce = {t.id for t in result.threat_scenarios if t.treatment == "Reduce"}
    assert {g.threat_scenario_id for g in result.goals} == reduce


def test_secoc_reduces_brake_risk(engine, architecture, result):
    before = scenario(result, "A_BRAKE", "Integrity").risk
    after = engine.run(architecture, extra_controls=[AppliedControl(control="SECOC", target="CAN_CH")])
    assert scenario(after, "A_BRAKE", "Integrity").risk < before


def test_control_only_applies_to_protected_properties(engine, architecture, result):
    # SecOC protects integrity and authenticity, not availability
    after = engine.run(architecture, extra_controls=[AppliedControl(control="SECOC", target="CAN_CH")])
    assert scenario(after, "A_BRAKE", "Availability").risk == scenario(result, "A_BRAKE", "Availability").risk


def test_findings_detect_gateway_bypass(result):
    titles = [f.title for f in result.findings]
    assert "Gateway bypass through ADAS domain controller" in titles
    assert "No message authentication on Chassis CAN-FD" in titles


def test_ota_tampering_is_matched_to_update_threats(result):
    ts = scenario(result, "A_OTA", "Integrity")
    assert any(m.threat_id.startswith("12.") for m in ts.r155)


def test_r155_matches_are_diverse(result):
    for ts in result.threat_scenarios:
        groups = [m.threat_id.split(".")[0] for m in ts.r155]
        assert len(groups) == len(set(groups))


def test_backend_threats_need_a_backend(engine, architecture):
    data = architecture.model_dump()
    data["components"] = [c for c in data["components"] if c["id"] != "BACKEND"]
    data["buses"] = [b for b in data["buses"] if b["id"] != "LTE"]
    data["interfaces"] = [i for i in data["interfaces"] if i["component"] != "BACKEND"]
    data["assets"] = [a for a in data["assets"] if a["component"] != "BACKEND"]
    result = engine.run(load_architecture(data))
    status = {c.threat_id: c.status for c in result.coverage}
    assert status["1.1"] == "Not applicable"
    assert not any(m.threat_id == "1.1" for t in result.threat_scenarios for m in t.r155)


def test_impact_override_changes_risk(engine, architecture, result):
    ts = scenario(result, "A_ODO", "Integrity")
    overrides = Overrides(impacts={ts.key: {"Financial": "Negligible", "Operational": "Negligible"}})
    after = engine.run(architecture, overrides=overrides)
    changed = scenario(after, "A_ODO", "Integrity")
    assert changed.impact == "Negligible" and changed.risk == 1
    assert any(i.overridden for d in after.damage_scenarios if d.id == ts.damage_scenario_id for i in d.impacts)


def test_feasibility_override(engine, architecture, result):
    ts = scenario(result, "A_BRAKE", "Integrity")
    hard = {"elapsed_time": "> 6 months", "expertise": "Multiple experts", "knowledge": "Strictly confidential",
            "window": "Difficult", "equipment": "Multiple bespoke"}
    overrides = Overrides(factors={"%s/%s" % (ts.key, i.id): hard for i in architecture.interfaces})
    after = scenario(engine.run(architecture, overrides=overrides), "A_BRAKE", "Integrity")
    assert after.feasibility == "Very low"
    assert after.risk == 2  # Severe impact x Very low feasibility


def test_coverage_statuses(result):
    counts = Counter(c.status for c in result.coverage)
    assert sum(counts.values()) == 70
    assert counts["Addressed"] >= 20
    assert counts["CSMS process"] == 5


def test_coverage_links_and_not_applicable(engine, architecture):
    overrides = Overrides(links={"26.1": ["A_BRAKE/Integrity"]}, not_applicable={"4.2": "No V2X in scope"})
    status = {c.threat_id: c for c in engine.run(architecture, overrides=overrides).coverage}
    assert status["26.1"].status == "Addressed" and "TS-001" in status["26.1"].scenarios
    assert status["4.2"].status == "Not applicable"


def test_recommendations_reduce_risk(result):
    for ts in result.threat_scenarios:
        if ts.treatment != "Reduce":
            assert not ts.recommendations
        for rec in ts.recommendations:
            assert rec.residual_risk <= ts.risk


def test_treatment_planner(engine, architecture, result):
    steps, risks = engine.plan_treatment(architecture, target_risk=3, max_steps=15)
    before = sum(1 for t in result.threat_scenarios if t.risk > 3)
    assert steps and steps[-1]["above_target"] < before
    assert all(a["remaining_excess"] >= b["remaining_excess"] for a, b in zip(steps, steps[1:]))
    placed = {(s["control"], s["target"]) for s in steps}
    residual = engine.run(architecture, extra_controls=[AppliedControl(control=c, target=t) for c, t in placed])
    assert {t.id: t.risk for t in residual.threat_scenarios} == risks


def test_decisions_stay_attached_when_assets_change(engine, architecture):
    """Adding an asset renumbers the scenarios, analyst decisions must follow the asset."""
    overrides = Overrides(impacts={"A_ODO/Integrity": {"Financial": "Negligible", "Operational": "Negligible"}},
                          links={"26.1": ["A_ODO/Integrity"]})
    data = architecture.model_dump()
    data["assets"].insert(0, {"id": "A_NEW", "name": "new sensor data", "type": "message",
                              "component": "BCM", "properties": ["Integrity", "Availability"]})
    result = engine.run(load_architecture(data), overrides=overrides)
    odo = scenario(result, "A_ODO", "Integrity")
    assert odo.impact == "Negligible"
    assert next(c for c in result.coverage if c.threat_id == "26.1").scenarios == [odo.id]
    assert scenario(result, "A_BRAKE", "Integrity").impact == "Severe"


def test_expert_review_fixes(result):
    # OBD access from inside the car is a Local attack vector in ISO/SAE 21434
    assert scenario(result, "A_BRAKE", "Integrity").attack_vector == "Local"
    # Internal CAN spoofing is not the external V2X/GNSS spoofing threat 4.1
    assert "4.1" not in [m.threat_id for m in scenario(result, "A_BRAKE", "Authenticity").r155]
    # A key store is only protected by an HSM in the ECU that holds the keys
    for rec in scenario(result, "A_DKEY", "Confidentiality").recommendations:
        assert rec.control != "HSM_KEYS" or rec.target == "DKM"
    # Secure boot does not stop fake TPMS radio data
    assert "SECURE_BOOT" not in [r.control for r in scenario(result, "A_TPMS", "Integrity").recommendations]
