"""Plain language explanation of how a risk value was derived."""

from tara import knowledge


def factor_breakdown(path, method):
    parts = []
    for factor, level in path.factors.items():
        label = method.factors[factor]["label"]
        parts.append("%s %s (%d)" % (label.lower(), level, method.factor_value(factor, level)))
    return ", ".join(parts)


def explain_threat(ts, result, architecture, method):
    ds = next(d for d in result.damage_scenarios if d.id == ts.damage_scenario_id)
    asset = next(a for a in architecture.assets if a.id == ts.asset_id)
    best = ts.paths[0]
    worst_impacts = [i for i in ds.impacts if i.level == ds.impact]

    lines = [
        "**%s: %s**" % (ts.id, ts.description),
        "",
        "1. **Asset and property.** The %s of the %s (%s) is at stake." % (
            ts.property.lower(), asset.name, asset.description or asset.type),
        "2. **Impact: %s.** %s" % (ds.impact, " ".join(
            "%s: %s." % (i.category, i.rationale) for i in worst_impacts)),
        "3. **Most feasible attack path.** %s (%s attack vector)." % (
            " > ".join(step.label for step in best.steps), best.attack_vector),
        "4. **Attack potential %d, so feasibility is %s.** %s." % (
            best.attack_potential, best.feasibility, factor_breakdown(best, method).capitalize()),
    ]
    if best.controls_on_path:
        lines.append("   Controls already on this path: %s." % ", ".join(
            knowledge.controls()[c.split("@")[0]]["name"] for c in best.controls_on_path))
    lines.append("5. **Risk value %d.** The risk matrix gives %s impact x %s feasibility = %d, "
                 "so the treatment decision is **%s** (%s)." % (
                     ts.risk, ds.impact, ts.feasibility, ts.risk, ts.treatment, ts.treatment_note.lower()))
    if ts.cal:
        lines.append("6. **%s** follows from %s impact and the %s attack vector." % (
            ts.cal, ds.impact, ts.attack_vector.lower()))
    if ts.r155:
        lines.append("")
        lines.append("Related UN R155 Annex 5 threats: %s." % "; ".join(
            "%s %s" % (m.threat_id, m.text) for m in ts.r155))
    if ts.recommendations:
        rec = ts.recommendations[0]
        lines.append("")
        lines.append("Most effective single control: **%s** on %s, residual risk %d (%s)." % (
            rec.name, rec.target_label, rec.residual_risk, ", ".join(rec.r155)))
    return "\n".join(lines)
