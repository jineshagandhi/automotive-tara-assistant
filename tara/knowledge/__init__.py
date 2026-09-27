"""Loads the knowledge base files shipped with the package."""

import json
from functools import lru_cache
from pathlib import Path

import yaml

KNOWLEDGE_DIR = Path(__file__).parent


def _yaml(name):
    with open(KNOWLEDGE_DIR / name, encoding="utf-8") as f:
        return yaml.safe_load(f)


@lru_cache(maxsize=1)
def r155():
    with open(KNOWLEDGE_DIR / "r155_annex5.json", encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def r155_threats():
    return {threat["id"]: threat for threat in r155()["threats"]}


@lru_cache(maxsize=1)
def r155_mitigations():
    return {mitigation["id"]: mitigation for mitigation in r155()["mitigations"]}


@lru_cache(maxsize=1)
def interfaces():
    return _yaml("interfaces.yaml")


@lru_cache(maxsize=1)
def controls():
    return _yaml("controls.yaml")


@lru_cache(maxsize=1)
def impact_rules():
    return _yaml("impact_rules.yaml")


@lru_cache(maxsize=1)
def r155_priors():
    return _yaml("r155_priors.yaml")


def r155_citation(threat_id):
    return "UN R155 Annex 5, Part A, threat %s" % threat_id


def mitigation_citation(mitigation_id):
    tables = r155_mitigations()[mitigation_id]["tables"]
    return "UN R155 Annex 5, %s (Table %s)" % (mitigation_id, ", ".join(tables))
