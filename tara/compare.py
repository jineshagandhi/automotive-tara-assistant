"""Change impact analysis between two TARA results (e.g. baseline and current)."""

from tara.models import TaraResult


def _key(ts, result):
    """Threat scenarios are matched by asset and property, not by their running id."""
    return ts.asset_id, ts.property


def compare(old: TaraResult, new: TaraResult):
    old_ts = {_key(t, old): t for t in old.threat_scenarios}
    new_ts = {_key(t, new): t for t in new.threat_scenarios}

    changes = []
    for key, ts in new_ts.items():
        before = old_ts.get(key)
        if before is None:
            changes.append({"change": "New", "asset": ts.asset_id, "property": ts.property,
                            "id": ts.id, "risk_before": None, "risk_after": ts.risk,
                            "detail": ts.description})
        elif before.risk != ts.risk or before.feasibility != ts.feasibility or before.impact != ts.impact:
            detail = []
            if before.impact != ts.impact:
                detail.append("impact %s -> %s" % (before.impact, ts.impact))
            if before.feasibility != ts.feasibility:
                detail.append("feasibility %s -> %s" % (before.feasibility, ts.feasibility))
            changes.append({"change": "Increased" if ts.risk > before.risk else
                            "Reduced" if ts.risk < before.risk else "Changed",
                            "asset": ts.asset_id, "property": ts.property, "id": ts.id,
                            "risk_before": before.risk, "risk_after": ts.risk,
                            "detail": ", ".join(detail)})
    for key, ts in old_ts.items():
        if key not in new_ts:
            changes.append({"change": "Removed", "asset": ts.asset_id, "property": ts.property,
                            "id": ts.id, "risk_before": ts.risk, "risk_after": None,
                            "detail": ts.description})

    old_findings = {f.title for f in old.findings}
    new_findings = {f.title for f in new.findings}
    return {
        "scenarios": changes,
        "new_findings": sorted(new_findings - old_findings),
        "resolved_findings": sorted(old_findings - new_findings),
    }
