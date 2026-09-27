"""The Annex 5 library must match the official text exactly."""

from tara import knowledge


def test_counts():
    library = knowledge.r155()
    assert len(library["categories"]) == 7
    assert len(library["threats"]) == 70
    assert len(library["mitigations"]) == 23


def test_ids_are_unique_and_every_threat_has_a_mitigation():
    threats = knowledge.r155()["threats"]
    ids = [t["id"] for t in threats]
    assert len(ids) == len(set(ids))
    assert all(t["mitigations"] for t in threats)


def test_numbering_follows_the_regulation():
    threats = knowledge.r155_threats()
    # The regulation has no item 14 and no example 22.1
    assert not any(tid.startswith("14.") for tid in threats)
    assert "22.1" not in threats and "22.2" in threats
    # 30.x is only listed in Table C3
    assert threats["30.1"]["category"] == "Listed in Table C3 only"
    # M17 does not exist in UN R155
    assert "M17" not in knowledge.r155_mitigations()


def test_known_mappings():
    threats = knowledge.r155_threats()
    assert threats["5.1"]["mitigations"] == ["M6", "M10"]
    assert threats["12.1"]["mitigations"] == ["M16"]
    assert threats["24.1"]["mitigations"] == ["M13"]
    assert threats["18.3"]["mitigations"] == ["M22"]
    assert threats["30.1"]["mitigations"] == ["M24"]


def test_mitigation_text_and_tables():
    mitigations = knowledge.r155_mitigations()
    assert mitigations["M10"]["text"] == "The vehicle shall verify the authenticity and integrity of messages it receives"
    assert mitigations["M3"]["parts"] == ["B", "C"]


def test_catalogues_reference_real_mitigations():
    known = set(knowledge.r155_mitigations())
    for key, control in knowledge.controls().items():
        assert set(control["r155"]) <= known, key
    threats = set(knowledge.r155_threats())
    for key, interface in knowledge.interfaces().items():
        assert set(interface["r155"]) <= threats, key
    priors = knowledge.r155_priors()
    for group in list(priors["by_property"].values()) + list(priors["by_asset_type"].values()):
        assert set(group) <= threats
