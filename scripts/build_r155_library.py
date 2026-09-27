"""Build the UN R155 Annex 5 knowledge base from the official EUR-Lex text.

Source: UN Regulation No 155, Official Journal of the European Union,
L 82, 9.3.2021, p. 30 (CELEX 42021X0387).

Usage:
    python scripts/build_r155_library.py path/to/r155.html

Download the HTML version in a browser from:
    https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:42021X0387

The output, tara/knowledge/r155_annex5.json, is committed to the repository,
so this script only needs to run when the source text changes.
"""

import json
import re
import sys
from pathlib import Path

from lxml import html

OUTPUT = Path(__file__).resolve().parents[1] / "tara" / "knowledge" / "r155_annex5.json"

SOURCE = {
    "title": "UN Regulation No 155 - Cybersecurity and cybersecurity management system",
    "publication": "Official Journal of the European Union, L 82, 9.3.2021",
    "celex": "42021X0387",
    "url": "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:42021X0387",
}


def clean(text):
    text = " ".join(text.split())
    return text.replace("‘", "'").replace("’", "'")


def expand_table(table):
    """Return the table as a grid with rowspan and colspan cells repeated."""
    grid = {}
    rows = table.xpath("./tr|./tbody/tr|./thead/tr")

    for r, row in enumerate(rows):
        c = 0
        for cell in row.xpath("./td|./th"):
            while (r, c) in grid:
                c += 1
            rowspan = int(cell.get("rowspan", 1))
            colspan = int(cell.get("colspan", 1))
            # Keep line breaks between paragraphs, some cells hold several refs
            parts = [clean(p.text_content()) for p in cell.xpath(".//p")] or [clean(cell.text_content())]
            value = [p for p in parts if p]
            for dr in range(rowspan):
                for dc in range(colspan):
                    grid[(r + dr, c + dc)] = value
            c += colspan

    height = max((key[0] for key in grid), default=-1) + 1
    width = max((key[1] for key in grid), default=-1) + 1
    return [[grid.get((r, c), []) for c in range(width)] for r in range(height)]


def parse_part_a(table):
    """Table A1: categories (4.3.x), high-level threats (N) and examples (N.M)."""
    categories, threats = {}, []
    category_id = category_title = None
    high_level = {}

    for row in expand_table(table)[1:]:
        cells = [" ".join(cell) for cell in row]
        joined = " | ".join(cells)

        match = re.match(r"(4\.3\.\d)\.\s*(.+)", cells[0])
        if match:
            category_id, category_title = match.group(1), match.group(2)
            categories[category_id] = category_title

        # Rows look like: [category, N, high level text, N.M, example text]
        tokens = [t for t in cells if t]
        for i, token in enumerate(tokens[:-1]):
            if re.fullmatch(r"\d{1,2}", token):
                high_level[token] = tokens[i + 1]
            elif re.fullmatch(r"\d{1,2}\.\d{1,2}", token):
                parent = token.split(".")[0]
                threats.append({
                    "id": token,
                    "high_level_id": parent,
                    "high_level": high_level.get(parent, ""),
                    "category_id": category_id,
                    "category": category_title,
                    "text": tokens[i + 1],
                })
        if not tokens:
            raise ValueError("Unexpected empty row: %s" % joined)

    # A threat example can appear twice when the table repeats a merged row
    unique = {}
    for threat in threats:
        unique.setdefault(threat["id"], threat)

    return categories, sorted(unique.values(), key=lambda t: [int(x) for x in t["id"].split(".")])


def parse_mitigation_table(table, table_name, table_title):
    """Tables B1-B8 and C1-C3: threat refs -> mitigation refs and text."""
    mitigations, links = {}, []

    for row in expand_table(table)[1:]:
        if len(row) < 4:
            continue
        threat_refs = re.findall(r"\d{1,2}\.\d{1,2}", " ".join(row[0]))
        mitigation_refs = [ref for ref in row[2] if re.fullmatch(r"M\d{1,2}", ref)]
        mitigation_texts = row[3]

        for ref, text in zip(mitigation_refs, mitigation_texts):
            mitigations.setdefault(ref, {"id": ref, "text": text, "tables": []})
            if table_name not in mitigations[ref]["tables"]:
                mitigations[ref]["tables"].append(table_name)

        for threat_ref in threat_refs:
            for ref in mitigation_refs:
                links.append({"threat_id": threat_ref, "mitigation_id": ref, "table": table_name,
                              "table_title": table_title, "threat_text": " ".join(row[1])})

    return mitigations, links


def main(path):
    doc = html.parse(path).getroot()
    tables = doc.xpath("//table")

    part_a = None
    mitigation_tables = []

    for table in tables:
        first_row = table.xpath("./tr|./tbody/tr|./thead/tr")[0]
        header = clean(first_row.text_content())
        if header.startswith("High-level and sub-level descriptions"):
            part_a = table
        elif header.startswith("Table A1 reference"):
            mitigation_tables.append(table)

    if part_a is None or len(mitigation_tables) != 11:
        raise SystemExit("Annex 5 tables not found (found %d mitigation tables)" % len(mitigation_tables))

    categories, threats = parse_part_a(part_a)

    # The table names and titles are in the paragraph just before each table
    text = clean(doc.text_content())
    names = re.findall(r"Table ([BC]\d) (Mitigations? to the threats (?:which are )?related to '[^']+')", text)
    titles = {}
    for name, title in names:
        titles.setdefault(name, title)
    order = ["B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8", "C1", "C2", "C3"]

    mitigations, links = {}, []
    for name, table in zip(order, mitigation_tables):
        found, found_links = parse_mitigation_table(table, name, titles.get(name, ""))
        for ref, mitigation in found.items():
            if ref in mitigations:
                for t in mitigation["tables"]:
                    if t not in mitigations[ref]["tables"]:
                        mitigations[ref]["tables"].append(t)
            else:
                mitigations[ref] = mitigation
        links.extend(found_links)

    # Threat 30.1 ('Physical loss of data') is only listed in Table C3, not in Table A1
    known = {t["id"] for t in threats}
    for link in links:
        if link["threat_id"] not in known:
            known.add(link["threat_id"])
            threats.append({
                "id": link["threat_id"],
                "high_level_id": link["threat_id"].split(".")[0],
                "high_level": link["table_title"].split("'")[1],
                "category_id": None,
                "category": "Listed in Table %s only" % link["table"],
                "text": link["threat_text"],
            })
    threats.sort(key=lambda t: [int(x) for x in t["id"].split(".")])

    # Attach mitigation refs to each threat
    by_threat = {}
    for link in links:
        by_threat.setdefault(link["threat_id"], [])
        if link["mitigation_id"] not in by_threat[link["threat_id"]]:
            by_threat[link["threat_id"]].append(link["mitigation_id"])
    for threat in threats:
        threat["mitigations"] = sorted(by_threat.get(threat["id"], []), key=lambda m: int(m[1:]))

    # Some mitigations appear in both Part B (vehicle) and Part C (back-end)
    for mitigation in mitigations.values():
        mitigation["parts"] = sorted({table[0] for table in mitigation["tables"]})

    library = {
        "source": SOURCE,
        "categories": [{"id": k, "title": v} for k, v in categories.items()],
        "threats": threats,
        "mitigations": sorted(mitigations.values(), key=lambda m: int(m["id"][1:])),
        "mitigation_tables": {name: titles.get(name, "") for name in order},
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(library, indent=2, ensure_ascii=False), encoding="utf-8")

    unmapped = [t["id"] for t in threats if not t["mitigations"]]
    print("Categories :", len(categories))
    print("Threats    :", len(threats))
    print("Mitigations:", len(mitigations))
    print("Threats without a mitigation reference:", unmapped)
    print("Written to", OUTPUT)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    main(sys.argv[1])
