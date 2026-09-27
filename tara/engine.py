"""TARA engine following ISO/SAE 21434 clause 15.

 1. Asset identification           (input: architecture assets and properties)
 2. Damage scenarios and impacts   rule based SFOP impact rating
 3. Threat scenarios               STRIDE per property, matched to UN R155 Annex 5
 4. Attack path analysis           graph search from every external interface
 5. Attack feasibility             attack potential per path, controls on the path
 6. Risk value                     risk matrix of impact and feasibility
 7. Risk treatment                 decision, cybersecurity goal, CAL, controls

Every number the engine produces can be traced to a rule in the methodology
profile or a knowledge base entry, and every rating can be overridden.
"""

from dataclasses import dataclass, field

from rank_bm25 import BM25Okapi

from tara import knowledge
from tara.graph import ArchitectureGraph
from tara.methodology import load_methodology
from tara.models import (
    AppliedControl, AttackPath, AttackStep, ControlRecommendation, CoverageItem,
    CybersecurityGoal, DamageScenario, Finding, ImpactRating, R155Match,
    TaraResult, ThreatScenario,
)
from tara.retrieval import tokenize

# Used when no external interface reaches the component holding the asset:
# the attacker needs physical access to the ECU itself
DIRECT_ACCESS_FACTORS = {
    "elapsed_time": "<= 1 month",
    "expertise": "Expert",
    "knowledge": "Confidential",
    "window": "Difficult",
    "equipment": "Specialized",
}

MAX_R155_MATCHES = 3
MIN_R155_SCORE = 0.30
PATHS_FOR_MATCHING = 3
PATHS_KEPT = 6


@dataclass
class Overrides:
    """Analyst decisions that replace engine suggestions.

    Decisions are stored against the scenario key "asset id/property" (for
    example "A_BRAKE/Integrity"), not the running number TS-001, so they stay
    attached to the right scenario when assets are added or removed.
    """
    impacts: dict = field(default_factory=dict)         # "A_BRAKE/Integrity" -> {category: level}
    factors: dict = field(default_factory=dict)         # "A_BRAKE/Integrity/IF_OBD" -> {factor: level}
    not_applicable: dict = field(default_factory=dict)  # R155 threat id -> rationale
    links: dict = field(default_factory=dict)           # R155 threat id -> [scenario keys]


def scenario_key(asset_id, prop):
    return "%s/%s" % (asset_id, prop)


class TaraEngine:
    def __init__(self, knowledge_base, methodology=None):
        self.kb = knowledge_base
        self.method = methodology or load_methodology()
        self.interfaces = knowledge.interfaces()
        self.controls = knowledge.controls()
        self.rules = knowledge.impact_rules()
        self.priors = knowledge.r155_priors()
        self.r155 = knowledge.r155_threats()

    # ================================================================ public

    def run(self, architecture, extra_controls=None, overrides=None):
        overrides = overrides or Overrides()
        controls = list(architecture.controls) + list(extra_controls or [])
        graph = ArchitectureGraph(architecture)
        has_backend = any(c.type == "backend" for c in architecture.components)

        damage_scenarios, threat_scenarios, goals = [], [], []

        for asset in architecture.assets:
            for prop in asset.properties:
                n = len(damage_scenarios) + 1
                ds = self._damage_scenario("DS-%03d" % n, asset, prop, overrides)
                ts = self._threat_scenario("TS-%03d" % n, ds, asset, graph, controls,
                                           overrides, has_backend)
                damage_scenarios.append(ds)
                threat_scenarios.append(ts)

                if ts.treatment == "Reduce":
                    goals.append(CybersecurityGoal(
                        id="CSG-%03d" % (len(goals) + 1),
                        threat_scenario_id=ts.id,
                        text="Protect the %s of the %s against %s, to prevent: %s." % (
                            prop.lower(), asset.name, ts.stride.lower(), self._consequence(ds)),
                        cal=ts.cal,
                    ))

        return TaraResult(
            architecture=architecture.name,
            profile=self.method.name,
            damage_scenarios=damage_scenarios,
            threat_scenarios=threat_scenarios,
            goals=goals,
            findings=self._findings(architecture, graph, controls),
            coverage=self._coverage(threat_scenarios, overrides, has_backend),
        )

    # ================================================================ step 2

    def _damage_scenario(self, ds_id, asset, prop, overrides):
        levels = self.method.impact_levels
        proposals = {}
        for rule in self.rules["rules"]:
            if prop not in rule["properties"]:
                continue
            if "asil" in rule and asset.asil not in rule["asil"]:
                continue
            if "types" in rule and asset.type not in rule["types"]:
                continue
            if "tags" in rule and not set(rule["tags"]) & set(asset.tags):
                continue
            if "personal_data" in rule and asset.personal_data not in rule["personal_data"]:
                continue

            category, level = rule["category"], rule["level"]
            current = proposals.get(category)
            if current is None or levels.index(level) > levels.index(current[0]):
                proposals[category] = (level, rule["rationale"].format(asset=asset.name, asil=asset.asil))

        impacts = []
        manual = overrides.impacts.get(scenario_key(asset.id, prop), {})
        for category in self.method.impact_categories:
            level, rationale = proposals.get(
                category, ("Negligible", "No rule indicates a %s impact" % category.lower()))
            if category in manual:
                level, rationale = manual[category], "Set by analyst (engine proposed %s)" % level
            impacts.append(ImpactRating(category=category, level=level, rationale=rationale,
                                        overridden=category in manual))

        verb = self.rules["verbs"][prop]
        worst = max(impacts, key=lambda i: levels.index(i.level))
        consequence = worst.rationale if worst.level != "Negligible" else "no significant consequence expected"

        return DamageScenario(
            id=ds_id,
            key=scenario_key(asset.id, prop),
            asset_id=asset.id,
            property=prop,
            description="%s%s %s: %s" % (verb[0].upper(), verb[1:], asset.name, consequence),
            impacts=impacts,
            impact=self.method.max_impact([i.level for i in impacts]),
        )

    @staticmethod
    def _consequence(ds):
        text = ds.description.split(": ", 1)[-1]
        return text[0].lower() + text[1:]

    # ================================================================ steps 3-7

    def _threat_scenario(self, ts_id, ds, asset, graph, controls, overrides, has_backend):
        stride = self.rules["stride"][ds.property]
        paths = sorted(self._attack_paths(ts_id, asset, ds.property, graph, controls, overrides),
                       key=lambda p: (p.attack_potential, len(p.steps)))
        best = paths[0]

        risk = self.method.risk_value(ds.impact, best.feasibility)
        treatment, note = self.method.treatment(risk)

        recommendations = []
        if treatment == "Reduce":
            recommendations = self._recommend(ts_id, asset, ds, graph, controls, overrides, best)

        return ThreatScenario(
            id=ts_id,
            key=ds.key,
            damage_scenario_id=ds.id,
            asset_id=asset.id,
            property=ds.property,
            stride=stride,
            description="%s of %s via %s" % (stride, asset.name, self._via(paths, graph)),
            r155=self._match_r155(asset, ds.property, stride, paths, graph, has_backend),
            paths=paths[:PATHS_KEPT],
            feasibility=best.feasibility,
            attack_vector=best.attack_vector,
            impact=ds.impact,
            risk=risk,
            treatment=treatment,
            treatment_note=note,
            cal=self.method.cal(ds.impact, best.attack_vector),
            recommendations=recommendations,
        )

    @staticmethod
    def _via(paths, graph):
        if paths[0].entry_type == "direct":
            return "direct physical access to %s" % graph.label(paths[0].steps[0].node)
        entries = list(dict.fromkeys(p.entry_interface for p in paths))
        names = [graph.label(e) for e in entries[:2]]
        if len(entries) > 2:
            return "%s and %d other entry points" % (", ".join(names), len(entries) - 2)
        return " or ".join(names)

    def _score_path(self, ts_id, nodes, asset, prop, graph, controls, overrides):
        """Attack potential factors of one path, after hops, controls and overrides."""
        entry = graph.interfaces[nodes[0]]
        factors = dict(self.interfaces[entry.type]["factors"])

        # Each ECU the attack has to move through costs the attacker time
        hops = graph.hops(nodes)
        if hops:
            factors["elapsed_time"] = self.method.raise_level(
                "elapsed_time", factors["elapsed_time"], self.method.pivot_steps * len(hops))

        applied = self._controls_on_path(nodes, entry.type, asset, prop, graph, controls)
        factors = self._apply_controls(factors, applied)

        manual = overrides.factors.get("%s/%s" % (scenario_key(asset.id, prop), entry.id))
        if manual:
            factors.update(manual)

        potential, feasibility = self.method.attack_potential(factors)
        return factors, applied, potential, feasibility

    def _attack_paths(self, ts_id, asset, prop, graph, controls, overrides):
        paths = []
        for n, nodes in enumerate(graph.paths_to(asset.component, asset.id), 1):
            entry = graph.interfaces[nodes[0]]
            spec = self.interfaces[entry.type]
            factors, applied, potential, feasibility = self._score_path(
                ts_id, nodes, asset, prop, graph, controls, overrides)
            paths.append(AttackPath(
                id="%s-P%d" % (ts_id, n),
                entry_interface=entry.id,
                entry_type=entry.type,
                attack_vector=spec["attack_vector"],
                steps=[AttackStep(node=node, kind=graph.kind(node), label=graph.label(node)) for node in nodes],
                factors=factors,
                controls_on_path=["%s@%s" % (c.control, c.target) for c in applied],
                attack_potential=potential,
                feasibility=feasibility,
            ))

        if not paths:
            factors = dict(DIRECT_ACCESS_FACTORS)
            applied = self._controls_on_path([asset.component], "direct", asset, prop, graph, controls)
            factors = self._apply_controls(factors, applied)
            potential, feasibility = self.method.attack_potential(factors)
            paths.append(AttackPath(
                id="%s-P0" % ts_id,
                entry_interface="direct",
                entry_type="direct",
                attack_vector="Physical",
                steps=[AttackStep(node=asset.component, kind="component", label=graph.label(asset.component))],
                factors=factors,
                controls_on_path=["%s@%s" % (c.control, c.target) for c in applied],
                attack_potential=potential,
                feasibility=feasibility,
            ))
        return paths

    def control_fits(self, key, node, entry_type, asset, prop, graph):
        """Whether a control placed on a node protects this asset on this path."""
        spec = self.controls[key]
        if prop not in spec["protects"]:
            return False
        if graph.node_type(node) not in spec["placement"]:
            return False
        if "entries" in spec and entry_type not in spec["entries"]:
            return False
        if entry_type in spec.get("exclude_entries", []):
            return False
        if spec.get("scope") == "asset" and node != asset.component:
            return False
        if "asset_types" in spec and asset.type not in spec["asset_types"]:
            return False
        if "bus_types" in spec and node in graph.buses and graph.buses[node].type not in spec["bus_types"]:
            return False
        return True

    def _controls_on_path(self, nodes, entry_type, asset, prop, graph, controls):
        on_path = set(nodes) | {asset.component}
        applied, seen = [], set()
        for control in controls:
            if control.control not in self.controls or control.target not in on_path:
                continue
            if control.control in seen:
                continue
            if not self.control_fits(control.control, control.target, entry_type, asset, prop, graph):
                continue
            seen.add(control.control)
            applied.append(control)
        return applied

    def _apply_controls(self, factors, applied):
        factors = dict(factors)
        for control in applied:
            for factor, steps in self.controls[control.control]["effect"].items():
                factors[factor] = self.method.raise_level(factor, factors[factor], steps)
        return factors

    # ---------------------------------------------------------------- R155

    def _match_r155(self, asset, prop, stride, paths, graph, has_backend):
        top_paths = paths[:PATHS_FOR_MATCHING]
        entry_types = list(dict.fromkeys(p.entry_type for p in top_paths if p.entry_type != "direct"))

        query = "%s %s %s (%s). %s. %s. Entry: %s" % (
            stride, self.rules["verbs"][prop], asset.name, asset.type.replace("_", " "),
            asset.description, self.priors["property_terms"][prop],
            ", ".join(self.interfaces[e]["label"] for e in entry_types) or "physical access")

        backend_only = set(self.priors["backend_only"])
        backend_in_play = graph.components[asset.component].type == "backend" or any(
            graph.components[s.node].type == "backend" for p in top_paths for s in p.steps
            if s.node in graph.components)
        entry_specific = self.priors["entry_specific"]
        candidates = [
            tid for tid in self.r155
            if tid not in self.priors["csms_process"]
            and (tid not in backend_only or (has_backend and backend_in_play))
            and (tid not in entry_specific or set(entry_specific[tid]) & set(entry_types))
        ]

        similarity = self.kb.similarity(query, ["R155-" + tid for tid in candidates])
        interface_prior = {tid for e in entry_types for tid in self.interfaces[e]["r155"]}
        property_prior = set(self.priors["by_property"].get(prop, []))
        type_prior = set(self.priors["by_asset_type"].get(asset.type, []))

        scored = []
        for tid in candidates:
            text_score = similarity["R155-" + tid]
            reasons = ["text similarity %.2f" % text_score]
            score = 0.55 * text_score
            if tid in property_prior:
                score += 0.15
                reasons.append("fits the compromised property (%s)" % prop.lower())
            if tid in type_prior:
                score += 0.15
                reasons.append("fits the asset type (%s)" % asset.type.replace("_", " "))
            if tid in interface_prior:
                score += 0.15
                reasons.append("typical for %s" % ", ".join(
                    self.interfaces[e]["label"] for e in entry_types if tid in self.interfaces[e]["r155"]))
            scored.append((score, tid, reasons))

        # Best match per high-level threat, so the matches cover different threats
        scored.sort(key=lambda item: -item[0])
        matches, groups = [], set()
        for score, tid, reasons in scored:
            if len(matches) == MAX_R155_MATCHES or score < MIN_R155_SCORE:
                break
            group = self.r155[tid]["high_level_id"]
            if group in groups:
                continue
            groups.add(group)
            threat = self.r155[tid]
            matches.append(R155Match(
                threat_id=tid,
                text=threat["text"],
                high_level=threat["high_level"],
                category=threat["category"],
                mitigations=threat["mitigations"],
                score=round(score, 3),
                confidence="High" if score >= 0.6 else "Medium" if score >= 0.45 else "Low",
                reasons=reasons,
            ))
        return matches

    # ---------------------------------------------------------------- treatment

    def _recommend(self, ts_id, asset, ds, graph, controls, overrides, best):
        """Rank controls by how much they reduce the risk of this threat scenario."""
        existing = {(c.control, c.target) for c in controls}
        nodes = list(dict.fromkeys([s.node for s in best.steps] + [asset.component]))

        candidates = []
        for key in self.controls:
            for node in nodes:
                if (key, node) in existing:
                    continue
                if self.control_fits(key, node, best.entry_type, asset, ds.property, graph):
                    candidates.append((key, node))

        current_risk = self.method.risk_value(ds.impact, best.feasibility)
        results = []
        for key, node in candidates:
            extra = AppliedControl(control=key, target=node, status="proposed")
            paths = self._attack_paths(ts_id, asset, ds.property, graph, controls + [extra], overrides)
            feasibility = min(paths, key=lambda p: p.attack_potential).feasibility
            risk = self.method.risk_value(ds.impact, feasibility)
            results.append(ControlRecommendation(
                control=key,
                name=self.controls[key]["name"],
                target=node,
                target_label=graph.label(node),
                r155=self.controls[key]["r155"],
                residual_feasibility=feasibility,
                residual_risk=risk,
                risk_reduction=current_risk - risk,
            ))

        # Largest reduction first, one placement per control
        results.sort(key=lambda r: (-r.risk_reduction, r.residual_risk, r.control))
        unique, seen = [], set()
        for result in results:
            if result.control not in seen:
                seen.add(result.control)
                unique.append(result)
        return unique[:4]

    # ---------------------------------------------------------------- findings

    def _findings(self, architecture, graph, controls):
        findings = []
        placed = {(c.control, c.target) for c in controls}
        remote = {"Network", "Adjacent"}

        def add(severity, title, detail, r155, nodes):
            findings.append(Finding(id="F-%02d" % (len(findings) + 1), severity=severity,
                                    title=title, detail=detail, r155=r155, nodes=nodes))

        # Safety critical ECUs reachable from remote interfaces without a gateway
        exposed, bridges = {}, {}
        critical = [c for c in architecture.components if c.asil in ("C", "D")]
        for component in critical:
            for nodes in graph.paths_to(component.id):
                entry = graph.interfaces[nodes[0]]
                if self.interfaces[entry.type]["attack_vector"] not in remote:
                    continue
                # Back-end paths continue through the TCU, which its own interfaces already cover
                if graph.components[nodes[1]].type == "backend":
                    continue
                pivots = graph.pivots(nodes)
                if any(graph.is_gateway(n) for n in [nodes[1]] + pivots):
                    continue
                if nodes[1] == component.id:
                    continue
                if not pivots:
                    exposed.setdefault(component.id, set()).add(entry.id)
                else:
                    # The last component before the target joins the untrusted side to it
                    bridge = pivots[-1]
                    bridges.setdefault(bridge, {"targets": set(), "entries": set()})
                    bridges[bridge]["targets"].add(component.id)
                    bridges[bridge]["entries"].add(entry.id)

        for component_id, entries in exposed.items():
            component = graph.components[component_id]
            add("High", "%s shares a network with an external-facing ECU" % component.name,
                "The ASIL %s %s is reachable from %s without passing a gateway." % (
                    component.asil, component.name, ", ".join(sorted(graph.label(e) for e in entries))),
                ["29.2"], [component_id] + sorted(entries))

        for bridge, info in bridges.items():
            targets = sorted(info["targets"])
            add("High", "Gateway bypass through %s" % graph.label(bridge),
                "%s connects the external-facing network to %s, so %s can reach safety critical ECUs "
                "without gateway filtering." % (
                    graph.label(bridge), ", ".join(graph.label(t) for t in targets),
                    ", ".join(sorted(graph.label(e) for e in info["entries"]))),
                ["29.2"], [bridge] + targets)

        # Buses that carry safety critical messages without message authentication
        for bus in architecture.buses:
            if bus.type in ("Cellular", "Internal"):
                continue
            carried = [a for a in architecture.assets
                       if a.type == "message" and a.asil in ("C", "D") and a.component in bus.members]
            if carried and ("SECOC", bus.id) not in placed:
                add("High", "No message authentication on %s" % bus.name,
                    "%s carries %s without SecOC or an equivalent message authentication code." % (
                        bus.name, " and ".join(a.name for a in carried)),
                    ["11.1", "6.3"], [bus.id])

        # Components with remote interfaces and no recorded control
        remote_by_component = {}
        for interface in architecture.interfaces:
            if self.interfaces[interface.type]["attack_vector"] == "Network":
                remote_by_component.setdefault(interface.component, []).append(interface)
        for component_id, items in remote_by_component.items():
            ids = {component_id} | {i.id for i in items}
            if not any(target in ids for _, target in placed):
                add("Medium", "No controls on %s" % graph.label(component_id),
                    "%s exposes %s to the internet, but no security control is recorded." % (
                        graph.label(component_id), ", ".join(graph.label(i.id) for i in items)),
                    sorted({t for i in items for t in self.interfaces[i.type]["r155"][:2]}),
                    sorted(ids))

        # Diagnostic ports should terminate at a gateway
        for interface in architecture.interfaces:
            if interface.type == "obd" and not graph.is_gateway(interface.component):
                add("Medium", "OBD port not behind a gateway",
                    "The OBD port is attached to %s instead of a gateway." % graph.label(interface.component),
                    ["18.3"], [interface.id, interface.component])

        return findings

    # ---------------------------------------------------------------- coverage

    def _coverage(self, threat_scenarios, overrides, has_backend):
        by_threat = {}
        for ts in threat_scenarios:
            for match in ts.r155:
                by_threat.setdefault(match.threat_id, []).append(ts.id)
        id_by_key = {ts.key: ts.id for ts in threat_scenarios}
        for tid, keys in overrides.links.items():
            for key in keys:
                ts_id = id_by_key.get(key)
                if ts_id and ts_id not in by_threat.setdefault(tid, []):
                    by_threat[tid].append(ts_id)

        # For open threats, suggest the closest existing threat scenario
        ts_index = BM25Okapi([tokenize(ts.description + " " + ts.stride, expand=True)
                              for ts in threat_scenarios]) if threat_scenarios else None

        items = []
        for tid, threat in self.r155.items():
            scenarios = by_threat.get(tid, [])
            note = ""
            if tid in overrides.not_applicable:
                status, note = "Not applicable", overrides.not_applicable[tid]
            elif scenarios:
                status = "Addressed"
            elif tid in self.priors["csms_process"]:
                status, note = "CSMS process", self.priors["csms_process"][tid]
            elif not has_backend and tid in self.priors["backend_only"]:
                status, note = "Not applicable", "No back-end in the scope of the item"
            else:
                status = "Open"

            suggested = None
            if status == "Open" and ts_index is not None:
                scores = ts_index.get_scores(tokenize(threat["text"] + " " + threat["high_level"], expand=True))
                best = int(scores.argmax())
                if scores[best] > 0:
                    suggested = threat_scenarios[best].id

            items.append(CoverageItem(threat_id=tid, text=threat["text"], category=threat["category"],
                                      status=status, scenarios=scenarios, note=note, suggested=suggested))
        return items

    # ================================================================ treatment plan

    def plan_treatment(self, architecture, target_risk=3, max_steps=12, overrides=None):
        """Greedy search for a small set of controls that brings every attack
        path to a risk value at or below the target.

        The objective is the sum over all attack paths of the risk above the
        target, so a control that closes one of several paths still counts.
        Returns the chosen placements in order and the final risk per scenario.
        """
        overrides = overrides or Overrides()
        graph = ArchitectureGraph(architecture)
        controls = list(architecture.controls)

        scenarios = []  # (ts_id, asset, prop, impact, [path nodes])
        n = 0
        for asset in architecture.assets:
            for prop in asset.properties:
                n += 1
                ds = self._damage_scenario("DS-%03d" % n, asset, prop, overrides)
                scenarios.append(("TS-%03d" % n, asset, prop, ds.impact,
                                  graph.paths_to(asset.component, asset.id)))

        def evaluate(active, subset):
            excess, risks = 0, {}
            for ts_id, asset, prop, impact, paths in subset:
                worst = 1
                if not paths:
                    _, feasibility = self.method.attack_potential(DIRECT_ACCESS_FACTORS)
                    worst = self.method.risk_value(impact, feasibility)
                    excess += max(0, worst - target_risk)
                for nodes in paths:
                    feasibility = self._score_path(ts_id, nodes, asset, prop, graph, active, overrides)[3]
                    risk = self.method.risk_value(impact, feasibility)
                    excess += max(0, risk - target_risk)
                    worst = max(worst, risk)
                risks[ts_id] = worst
            return excess, risks

        # Every placement that could protect at least one path
        placements = {}
        for ts_id, asset, prop, impact, paths in scenarios:
            for nodes in paths:
                entry_type = graph.interfaces[nodes[0]].type
                for node in dict.fromkeys(list(nodes) + [asset.component]):
                    for key in self.controls:
                        if self.control_fits(key, node, entry_type, asset, prop, graph):
                            placements.setdefault((key, node), set()).add(ts_id)

        existing = {(c.control, c.target) for c in controls}
        by_id = {item[0]: item for item in scenarios}
        excess, risks = evaluate(controls, scenarios)
        steps = []

        while excess > 0 and len(steps) < max_steps:
            best = None
            for (key, node), affected in sorted(placements.items()):
                if (key, node) in existing:
                    continue
                subset = [by_id[t] for t in sorted(affected)]
                before, _ = evaluate(controls, subset)
                trial = controls + [AppliedControl(control=key, target=node, status="proposed")]
                after, _ = evaluate(trial, subset)
                gain = before - after
                if gain > 0 and (best is None or gain > best[0]):
                    best = (gain, key, node)
            if best is None:
                break

            gain, key, node = best
            controls.append(AppliedControl(control=key, target=node, status="proposed"))
            existing.add((key, node))
            excess, risks = evaluate(controls, scenarios)
            steps.append({
                "step": len(steps) + 1,
                "control": key,
                "name": self.controls[key]["name"],
                "target": node,
                "target_label": graph.label(node),
                "r155": self.controls[key]["r155"],
                "remaining_excess": excess,
                "above_target": sum(1 for r in risks.values() if r > target_risk),
                "max_risk": max(risks.values()),
            })

        return steps, risks
