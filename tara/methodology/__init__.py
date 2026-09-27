"""Rating rules from a methodology profile (ISO/SAE 21434 clause 15)."""

import os
from functools import lru_cache
from pathlib import Path

import yaml

DEFAULT_PROFILE = Path(__file__).with_name("iso21434_default.yaml")


class Methodology:
    def __init__(self, profile):
        self.profile = profile
        self.name = profile["name"]
        self.impact_levels = profile["impact"]["levels"]
        self.impact_categories = profile["impact"]["categories"]
        self.feasibility_levels = profile["feasibility_levels"]
        self.factors = profile["attack_potential"]["factors"]
        self.pivot_steps = profile.get("pivot_elapsed_time_steps", 1)

    # ------------------------------------------------------------ impact

    def max_impact(self, levels):
        if not levels:
            return self.impact_levels[0]
        return max(levels, key=self.impact_levels.index)

    # ------------------------------------------------------------ feasibility

    def factor_levels(self, factor):
        return [level["name"] for level in self.factors[factor]["levels"]]

    def factor_value(self, factor, level_name):
        for level in self.factors[factor]["levels"]:
            if level["name"] == level_name:
                return level["value"]
        raise ValueError("Unknown level %r for factor %r" % (level_name, factor))

    def raise_level(self, factor, level_name, steps):
        """Move a factor up by a number of levels, capped at the hardest level."""
        names = self.factor_levels(factor)
        index = min(names.index(level_name) + steps, len(names) - 1)
        return names[index]

    def attack_potential(self, factors):
        total = sum(self.factor_value(f, level) for f, level in factors.items())
        return total, self.feasibility_from_potential(total)

    def feasibility_from_potential(self, total):
        for band in self.profile["attack_potential"]["rating"]:
            if total <= band["max"]:
                return band["rating"]
        return self.feasibility_levels[0]

    # ------------------------------------------------------------ risk

    def risk_value(self, impact, feasibility):
        return int(self.profile["risk_matrix"][impact][feasibility])

    def cal(self, impact, attack_vector):
        return self.profile["cal_matrix"][impact][attack_vector]

    def treatment(self, risk):
        rule = self.profile["treatment"][risk]
        return rule["decision"], rule["note"]


@lru_cache(maxsize=4)
def load_methodology(path=None):
    path = path or os.environ.get("TARA_PROFILE") or DEFAULT_PROFILE
    with open(path, encoding="utf-8") as f:
        return Methodology(yaml.safe_load(f))
