"""Draft an architecture model from a design document (HLD, system description).

With an LLM the document is turned into the architecture schema directly.
Without one, a keyword based extractor recognises common ECUs, buses and
external interfaces. Either way the result is a draft for the analyst to
review in the Architecture editor, never a final model.
"""

import io
import re

from tara import knowledge
from tara.io import validate
from tara.models import Architecture

# name pattern -> (id, display name, type, zone, asil)
COMPONENT_PATTERNS = [
    (r"\b(back-?end|cloud platform|oem server)", ("BACKEND", "OEM back-end", "backend", "external", "QM")),
    (r"\b(telematics|tcu)\b", ("TCU", "Telematics control unit", "telematics", "connectivity", "QM")),
    (r"\b(infotainment|head unit|ivi)\b", ("IVI", "Infotainment head unit", "infotainment", "infotainment", "QM")),
    (r"\b(central gateway|gateway|cgw)\b", ("CGW", "Central gateway", "gateway", "backbone", "QM")),
    (r"\b(adas|driver assistance)\b", ("ADAS", "ADAS controller", "ecu", "chassis", "D")),
    (r"\b(esc|brake control|brake ecu|abs)\b", ("ESC", "Brake control unit", "ecu", "chassis", "D")),
    (r"\b(eps|power steering|steering ecu)\b", ("EPS", "Electric power steering", "ecu", "chassis", "D")),
    (r"\b(vcu|vehicle control unit|powertrain controller)\b", ("VCU", "Vehicle control unit", "ecu", "powertrain", "C")),
    (r"\b(bms|battery management)\b", ("BMS", "Battery management system", "ecu", "powertrain", "C")),
    (r"\b(obc|on-board charger|charge controller)\b", ("OBC", "On-board charger", "ecu", "powertrain", "B")),
    (r"\b(bcm|body control)\b", ("BCM", "Body control module", "ecu", "body", "B")),
    (r"\b(digital key|keyless|peps)\b", ("DKM", "Digital key module", "ecu", "body", "QM")),
]

# interface type -> component id it is usually attached to
INTERFACE_HOME = {
    "cellular": "TCU", "ota": "TCU", "gnss": "TCU", "v2x": "TCU",
    "backend_api": "BACKEND", "mobile_app": "BACKEND",
    "wifi": "IVI", "bluetooth": "IVI", "usb": "IVI",
    "obd": "CGW", "ev_charging": "OBC",
    "ble_key": "DKM", "key_fob_rf": "DKM", "tpms_rf": "BCM",
}

# Optional domain word, bus technology, optional 'backbone'
BUS_PATTERN = re.compile(
    r"\b(?:(chassis|powertrain|body|diagnostic|infotainment|comfort)\s+)?"
    r"(can[- ]?fd|can|automotive ethernet|ethernet|flexray|lin)\b(\s+backbone)?")
BUS_TYPES = {"can-fd": "CAN-FD", "can fd": "CAN-FD", "canfd": "CAN-FD", "can": "CAN",
             "automotive ethernet": "Ethernet", "ethernet": "Ethernet", "flexray": "FlexRay", "lin": "LIN"}

# Typical assets per component, used to seed the draft
ASSET_TEMPLATES = {
    "ESC": [("brake request messages", "message", ["Integrity", "Authenticity", "Availability"], "D", "none", [])],
    "EPS": [("steering torque requests", "message", ["Integrity", "Authenticity"], "D", "none", [])],
    "ADAS": [("driver assistance function", "function", ["Integrity", "Availability"], "C", "none", [])],
    "BMS": [("battery charge and thermal limits", "configuration", ["Integrity"], "C", "none", ["fire"])],
    "OBC": [("charging session parameters", "message", ["Integrity", "Availability"], "B", "none", [])],
    "VCU": [("odometer value", "configuration", ["Integrity"], "QM", "none", ["fraud"])],
    "BCM": [("door lock and immobilizer function", "function", ["Integrity", "Authenticity"], "QM", "none", ["theft"])],
    "DKM": [("digital key credentials", "key", ["Confidentiality", "Integrity"], "QM", "none", ["theft"])],
    "TCU": [("remote vehicle commands", "function", ["Integrity", "Authenticity"], "QM", "none", ["theft"]),
            ("vehicle location history", "personal_data", ["Confidentiality"], "QM", "sensitive", [])],
    "IVI": [("user profile and contacts", "personal_data", ["Confidentiality"], "QM", "personal", [])],
    "BACKEND": [("fleet customer database", "personal_data", ["Confidentiality"], "QM", "sensitive", [])],
    "CGW": [("diagnostic trouble codes and event logs", "diagnostic", ["Integrity"], "QM", "none", [])],
}

EXTRACTION_PROMPT = """Extract the E/E architecture of the vehicle system described in the document
as JSON with exactly these keys: name, description, components, buses, interfaces, assets.

components: [{id, name, type, zone, asil, description}]
  type is one of: telematics, infotainment, gateway, ecu, sensor, backend
  asil is one of: QM, A, B, C, D (use the document, otherwise your best engineering estimate)
buses: [{id, name, type, members}]  type is one of: CAN, CAN-FD, LIN, FlexRay, Ethernet, Cellular
  members lists component ids. Model the vehicle to back-end link as a Cellular bus.
interfaces: [{id, type, component, name}]  external interfaces only, type is one of: %s
assets: [{id, name, type, component, properties, asil, personal_data, tags, description}]
  type is one of: message, function, firmware, key, personal_data, configuration, diagnostic, log, service
  properties: subset of Confidentiality, Integrity, Availability, Authenticity
  personal_data: none, personal or sensitive; tags: any of theft, fraud, fleet, fire

Use short upper case ids such as TCU, CAN_CH, IF_OBD, A_BRAKE. Only include what the document supports."""


def read_document(name, data):
    """Return a list of (page or None, text) for PDF, Markdown or text uploads."""
    if name.lower().endswith(".pdf"):
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(data))
        return [(n, page.extract_text() or "") for n, page in enumerate(reader.pages, 1)]
    return [(None, data.decode("utf-8", errors="replace"))]


def extract_with_llm(text, llm):
    types = ", ".join(knowledge.interfaces())
    data = llm.chat_json(EXTRACTION_PROMPT % types, text[:24000])
    data.setdefault("controls", [])
    return _finalise(data, "llm (%s)" % llm.model)


def extract_with_keywords(text, name="Extracted architecture"):
    lower = text.lower()
    # Join wrapped lines inside a paragraph before splitting into sentences
    paragraphs = [" ".join(p.split()) for p in re.split(r"\n\s*\n", lower)]
    sentences = [s for p in paragraphs for s in re.split(r"(?<=[.;])\s+", p)]

    components = {}
    for pattern, (cid, cname, ctype, zone, asil) in COMPONENT_PATTERNS:
        if re.search(pattern, lower):
            components[cid] = {"id": cid, "name": cname, "type": ctype, "zone": zone, "asil": asil,
                               "description": "Detected from the document"}

    def mentioned(sentence):
        return [cid for pattern, (cid, *_rest) in COMPONENT_PATTERNS
                if cid in components and re.search(pattern, sentence)]

    # A bus is identified by its domain and technology, e.g. 'chassis CAN-FD'
    found = {}
    for sentence in sentences:
        for match in BUS_PATTERN.finditer(sentence):
            domain = match.group(1) or ("backbone" if match.group(3) else "vehicle")
            bus_type = BUS_TYPES[match.group(2)]
            found.setdefault((domain, bus_type), set()).update(mentioned(sentence))

    buses = []
    for (domain, bus_type), members in found.items():
        if len(members) >= 2:
            buses.append({"id": "%s_%s" % (domain.upper(), bus_type.replace("-", "").upper()),
                          "name": "%s %s" % (domain.capitalize(), bus_type),
                          "type": bus_type, "members": sorted(members)})
    if "BACKEND" in components and "TCU" in components:
        buses.append({"id": "LTE", "name": "Cellular link", "type": "Cellular", "members": ["BACKEND", "TCU"]})

    interfaces = []
    for itype, spec in knowledge.interfaces().items():
        home = INTERFACE_HOME.get(itype)
        if home not in components:
            continue
        if any(re.search(r"\b%s\b" % re.escape(k), lower) for k in spec["keywords"]):
            interfaces.append({"id": "IF_" + itype.upper(), "type": itype, "component": home,
                               "name": spec["label"]})

    assets = []
    for cid in components:
        for aname, atype, props, asil, personal, tags in ASSET_TEMPLATES.get(cid, []):
            assets.append({"id": "A_%s_%d" % (cid, len(assets) + 1), "name": aname, "type": atype,
                           "component": cid, "properties": props, "asil": asil,
                           "personal_data": personal, "tags": tags,
                           "description": "Proposed from the component type"})

    data = {"name": name, "description": "Draft extracted from a design document",
            "components": list(components.values()), "buses": buses,
            "interfaces": interfaces, "assets": assets, "controls": []}
    return _finalise(data, "keyword extractor")


def _finalise(data, method):
    architecture = Architecture.model_validate(data)
    return architecture, validate(architecture), method


def extract(text, llm, name="Extracted architecture"):
    if llm.available:
        try:
            return extract_with_llm(text, llm)
        except Exception:  # fall back to keywords on any model or schema problem
            pass
    return extract_with_keywords(text, name)
