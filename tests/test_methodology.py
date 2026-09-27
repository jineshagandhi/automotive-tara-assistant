import pytest


@pytest.mark.parametrize("total, rating", [
    (0, "High"), (13, "High"), (14, "Medium"), (19, "Medium"),
    (20, "Low"), (24, "Low"), (25, "Very low"), (60, "Very low"),
])
def test_attack_potential_bands(method, total, rating):
    assert method.feasibility_from_potential(total) == rating


def test_attack_potential_sum(method):
    factors = {"elapsed_time": "<= 1 month", "expertise": "Expert", "knowledge": "Restricted",
               "window": "Moderate", "equipment": "Specialized"}
    assert method.attack_potential(factors) == (4 + 6 + 3 + 4 + 4, "Low")


def test_raise_level_is_capped(method):
    assert method.raise_level("expertise", "Proficient", 1) == "Expert"
    assert method.raise_level("expertise", "Expert", 5) == "Multiple experts"


@pytest.mark.parametrize("impact, feasibility, risk", [
    ("Severe", "High", 5), ("Severe", "Very low", 2), ("Major", "Medium", 3),
    ("Moderate", "High", 3), ("Negligible", "High", 1),
])
def test_risk_matrix(method, impact, feasibility, risk):
    assert method.risk_value(impact, feasibility) == risk


def test_cal_and_treatment(method):
    assert method.cal("Severe", "Network") == "CAL4"
    assert method.cal("Moderate", "Physical") == "CAL1"
    assert method.cal("Negligible", "Network") is None
    assert method.treatment(4)[0] == "Reduce"
    assert method.treatment(2)[0] == "Retain"


def test_max_impact(method):
    assert method.max_impact(["Moderate", "Severe", "Negligible"]) == "Severe"
    assert method.max_impact([]) == "Negligible"
