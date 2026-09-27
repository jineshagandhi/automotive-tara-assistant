"""Export a TARA as an Excel workbook, a standalone HTML report or JSON."""

import html
import io
from collections import Counter
from datetime import date

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from tara import __version__, knowledge

RISK_FILL = {5: "C1121F", 4: "E8590C", 3: "F2C14E", 2: "8CC084", 1: "5DA271"}
HEADER_FILL = "1F2A44"


def _asset_names(architecture):
    return {a.id: a.name for a in architecture.assets}


def rows_risk_register(result, architecture, reviews=None):
    names = _asset_names(architecture)
    reviews = reviews or {}
    rows = []
    for ts in result.threat_scenarios:
        best = ts.paths[0]
        rows.append({
            "ID": ts.id,
            "Asset": names[ts.asset_id],
            "Property": ts.property,
            "STRIDE": ts.stride,
            "Threat scenario": ts.description,
            "Impact": ts.impact,
            "Attack path": " > ".join(s.label for s in best.steps),
            "Attack vector": ts.attack_vector,
            "Attack potential": best.attack_potential,
            "Feasibility": ts.feasibility,
            "Risk": ts.risk,
            "Treatment": ts.treatment,
            "CAL": ts.cal or "",
            "R155 threats": ", ".join(m.threat_id for m in ts.r155),
            "Top control": ts.recommendations[0].name if ts.recommendations else "",
            "Review": reviews.get(ts.key, {}).get("status", "Proposed"),
        })
    return rows


def rows_damage(result, architecture):
    names = _asset_names(architecture)
    rows = []
    for ds in result.damage_scenarios:
        row = {"ID": ds.id, "Asset": names[ds.asset_id], "Property": ds.property,
               "Damage scenario": ds.description}
        for impact in ds.impacts:
            row[impact.category] = impact.level + (" (analyst)" if impact.overridden else "")
        row["Overall impact"] = ds.impact
        rows.append(row)
    return rows


def rows_paths(result):
    rows = []
    for ts in result.threat_scenarios:
        for path in ts.paths:
            row = {"Threat scenario": ts.id, "Path": path.id,
                   "Steps": " > ".join(s.label for s in path.steps),
                   "Vector": path.attack_vector}
            row.update({k.replace("_", " ").capitalize(): v for k, v in path.factors.items()})
            row.update({"Attack potential": path.attack_potential, "Feasibility": path.feasibility,
                        "Controls on path": ", ".join(path.controls_on_path)})
            rows.append(row)
    return rows


def rows_goals(result):
    return [{"ID": g.id, "Threat scenario": g.threat_scenario_id, "Cybersecurity goal": g.text, "CAL": g.cal or ""}
            for g in result.goals]


def rows_coverage(result):
    return [{"R155 threat": c.threat_id, "Category": c.category or "", "Threat": c.text,
             "Status": c.status, "Threat scenarios": ", ".join(c.scenarios), "Note": c.note}
            for c in result.coverage]


def rows_findings(result):
    return [{"ID": f.id, "Severity": f.severity, "Finding": f.title, "Detail": f.detail,
             "R155": ", ".join(f.r155)} for f in result.findings]


def rows_plan(plan_steps):
    return [{"Step": s["step"], "Control": s["name"], "Deploy on": s["target_label"],
             "R155 mitigations": ", ".join(s["r155"]), "Scenarios above target": s["above_target"],
             "Highest risk": s["max_risk"]} for s in plan_steps or []]


def _sheet(workbook, title, rows, widths=None, risk_column=None):
    sheet = workbook.create_sheet(title)
    if not rows:
        sheet.append(["No entries"])
        return sheet
    headers = list(rows[0].keys())
    sheet.append(headers)
    for row in rows:
        sheet.append([row.get(h, "") for h in headers])

    for cell in sheet[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor=HEADER_FILL)
        cell.alignment = Alignment(vertical="center", wrap_text=True)
    for col, header in enumerate(headers, 1):
        longest = max(len(str(r.get(header, ""))) for r in rows)
        width = (widths or {}).get(header, min(max(len(header), longest) + 2, 60))
        sheet.column_dimensions[get_column_letter(col)].width = width
    for row in sheet.iter_rows(min_row=2):
        for cell in row:
            cell.alignment = Alignment(vertical="top", wrap_text=True)
    if risk_column and risk_column in headers:
        index = headers.index(risk_column)
        for row in sheet.iter_rows(min_row=2):
            cell = row[index]
            if isinstance(cell.value, int) and cell.value in RISK_FILL:
                cell.fill = PatternFill("solid", fgColor=RISK_FILL[cell.value])
                cell.font = Font(bold=True, color="FFFFFF")
                cell.alignment = Alignment(horizontal="center", vertical="top")
    sheet.freeze_panes = "B2"
    sheet.auto_filter.ref = sheet.dimensions
    return sheet


def to_excel(result, architecture, reviews=None, audit=None, plan_steps=None):
    workbook = Workbook()
    summary = workbook.active
    summary.title = "Summary"
    risks = Counter(ts.risk for ts in result.threat_scenarios)
    coverage = Counter(c.status for c in result.coverage)
    lines = [
        ("TARA report", architecture.name),
        ("Architecture version", architecture.version),
        ("Methodology", result.profile),
        ("Date", date.today().isoformat()),
        ("Tool", "Automotive TARA Assistant %s" % __version__),
        ("", ""),
        ("Assets", len(architecture.assets)),
        ("Threat scenarios", len(result.threat_scenarios)),
        ("Risk 5 / 4 / 3 / 2 / 1", " / ".join(str(risks.get(r, 0)) for r in (5, 4, 3, 2, 1))),
        ("Cybersecurity goals", len(result.goals)),
        ("Architecture findings", len(result.findings)),
        ("R155 Annex 5 threats addressed", "%d of %d" % (coverage.get("Addressed", 0), len(result.coverage))),
        ("", ""),
        ("Note", "AI-assisted draft. All ratings require review and approval by a qualified cybersecurity engineer."),
    ]
    for key, value in lines:
        summary.append([key, value])
    summary.column_dimensions["A"].width = 32
    summary.column_dimensions["B"].width = 90
    summary["A1"].font = Font(bold=True, size=14)
    summary["B1"].font = Font(bold=True, size=14)

    _sheet(workbook, "Assets", [
        {"ID": a.id, "Asset": a.name, "Type": a.type, "Component": a.component,
         "Properties": ", ".join(a.properties), "ASIL": a.asil, "Personal data": a.personal_data,
         "Description": a.description} for a in architecture.assets])
    _sheet(workbook, "Damage scenarios", rows_damage(result, architecture))
    _sheet(workbook, "Risk register", rows_risk_register(result, architecture, reviews), risk_column="Risk")
    _sheet(workbook, "Attack paths", rows_paths(result))
    _sheet(workbook, "Cybersecurity goals", rows_goals(result))
    _sheet(workbook, "Treatment plan", rows_plan(plan_steps))
    _sheet(workbook, "R155 coverage", rows_coverage(result))
    _sheet(workbook, "Findings", rows_findings(result))
    _sheet(workbook, "Audit log", audit or [])

    buffer = io.BytesIO()
    workbook.save(buffer)
    return buffer.getvalue()


def _table(rows, risk_column=None):
    if not rows:
        return "<p class='muted'>No entries.</p>"
    headers = list(rows[0].keys())
    out = ["<table><thead><tr>%s</tr></thead><tbody>" % "".join("<th>%s</th>" % html.escape(h) for h in headers)]
    for row in rows:
        cells = []
        for h in headers:
            value = row.get(h, "")
            if h == risk_column and isinstance(value, int):
                cells.append("<td><span class='risk r%d'>%d</span></td>" % (value, value))
            else:
                cells.append("<td>%s</td>" % html.escape(str(value)))
        out.append("<tr>%s</tr>" % "".join(cells))
    out.append("</tbody></table>")
    return "".join(out)


def to_html(result, architecture, reviews=None, plan_steps=None):
    risks = Counter(ts.risk for ts in result.threat_scenarios)
    coverage = Counter(c.status for c in result.coverage)
    source = knowledge.r155()["source"]
    register = rows_risk_register(result, architecture, reviews)
    for row in register:
        for key in ("Attack path", "Top control", "STRIDE"):
            row.pop(key, None)

    matrix_rows = []
    method_levels = ["Severe", "Major", "Moderate", "Negligible"]
    feasibility = ["Very low", "Low", "Medium", "High"]
    counts = Counter((ts.impact, ts.feasibility) for ts in result.threat_scenarios)
    for impact in method_levels:
        cells = "".join("<td class='cell'>%s</td>" % (counts.get((impact, f)) or "") for f in feasibility)
        matrix_rows.append("<tr><th>%s</th>%s</tr>" % (impact, cells))

    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>TARA report</title>
<style>
:root {{ --ink:#1f2a44; --muted:#5c6370; --line:#d9dde3; --bg:#ffffff; }}
body {{ font-family: -apple-system, Segoe UI, Helvetica, Arial, sans-serif; color: var(--ink); background: var(--bg);
       margin: 0 auto; max-width: 1180px; padding: 32px 16px; font-size: 14px; line-height: 1.45; }}
h1 {{ font-size: 26px; margin: 0 0 4px; }} h2 {{ font-size: 18px; margin: 32px 0 8px; border-bottom: 2px solid var(--ink); padding-bottom: 4px; }}
.muted {{ color: var(--muted); }} .kpis {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 20px 0; }}
.kpi {{ border: 1px solid var(--line); border-radius: 8px; padding: 12px; }} .kpi b {{ display: block; font-size: 24px; }}
table {{ border-collapse: collapse; width: 100%; font-size: 12.5px; }} th, td {{ border: 1px solid var(--line); padding: 6px 8px; text-align: left; vertical-align: top; }}
thead th {{ background: var(--ink); color: #fff; }} .risk {{ display: inline-block; min-width: 22px; text-align: center; border-radius: 4px; color: #fff; font-weight: 700; }}
.r5 {{ background:#c1121f; }} .r4 {{ background:#e8590c; }} .r3 {{ background:#d4a72c; }} .r2 {{ background:#6aa56a; }} .r1 {{ background:#3f8f5a; }}
.matrix td.cell {{ text-align: center; font-weight: 700; width: 18%; }} .note {{ border-left: 4px solid #e8590c; padding: 8px 12px; background: #fff6ef; }}
.scroll {{ overflow-x: auto; }} @media print {{ body {{ padding: 0; }} h2 {{ page-break-after: avoid; }} }}
</style></head><body>
<h1>Threat Analysis and Risk Assessment</h1>
<div class="muted">{name} &middot; version {version} &middot; {profile} &middot; {today}</div>
<div class="kpis">
  <div class="kpi"><b>{n_assets}</b>assets</div>
  <div class="kpi"><b>{n_ts}</b>threat scenarios</div>
  <div class="kpi"><b>{n_high}</b>risks rated 4 or 5</div>
  <div class="kpi"><b>{n_goals}</b>cybersecurity goals</div>
  <div class="kpi"><b>{covered} / {n_r155}</b>R155 threats addressed</div>
</div>
<p class="note">AI-assisted draft generated by Automotive TARA Assistant {tool_version}. Ratings follow the methodology profile
"{profile}" and must be reviewed and approved by a qualified cybersecurity engineer before use for type approval.</p>

<h2>Risk matrix (impact x attack feasibility)</h2>
<div class="scroll"><table class="matrix"><thead><tr><th>Impact</th>{feas_headers}</tr></thead><tbody>{matrix}</tbody></table></div>

<h2>Architecture findings</h2><div class="scroll">{findings}</div>
<h2>Risk register</h2><div class="scroll">{register}</div>
<h2>Cybersecurity goals</h2><div class="scroll">{goals}</div>
<h2>Treatment plan</h2><div class="scroll">{plan}</div>
<h2>Damage scenarios</h2><div class="scroll">{damage}</div>
<h2>UN R155 Annex 5 coverage</h2><div class="scroll">{coverage}</div>
<p class="muted">Threat and mitigation texts: {source_title}, {source_pub}.</p>
</body></html>""".format(
        name=html.escape(architecture.name), version=html.escape(architecture.version),
        profile=html.escape(result.profile), today=date.today().isoformat(), tool_version=__version__,
        n_assets=len(architecture.assets), n_ts=len(result.threat_scenarios),
        n_high=risks.get(5, 0) + risks.get(4, 0), n_goals=len(result.goals),
        covered=coverage.get("Addressed", 0), n_r155=len(result.coverage),
        feas_headers="".join("<th>%s</th>" % f for f in feasibility), matrix="".join(matrix_rows),
        findings=_table(rows_findings(result)), register=_table(register, risk_column="Risk"),
        goals=_table(rows_goals(result)), plan=_table(rows_plan(plan_steps)),
        damage=_table(rows_damage(result, architecture)), coverage=_table(rows_coverage(result)),
        source_title=html.escape(source["title"]), source_pub=html.escape(source["publication"]),
    )


def to_json(result):
    return result.model_dump_json(indent=2)
