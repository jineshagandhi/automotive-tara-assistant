"""Load, validate and save architectures."""

from pathlib import Path

import yaml

from tara import knowledge
from tara.models import Architecture

EXAMPLES_DIR = Path(__file__).resolve().parents[1] / "examples"


def load_architecture(source):
    """Load from a path, a YAML/JSON string or a dict."""
    if isinstance(source, dict):
        data = source
    elif isinstance(source, Path) or (isinstance(source, str) and "\n" not in source and Path(source).exists()):
        data = yaml.safe_load(Path(source).read_text(encoding="utf-8"))
    else:
        data = yaml.safe_load(source)
    architecture = Architecture.model_validate(data)
    errors = validate(architecture)
    if errors:
        raise ValueError("Invalid architecture:\n- " + "\n- ".join(errors))
    return architecture


def validate(architecture):
    errors = []
    components = {c.id for c in architecture.components}
    buses = {b.id for b in architecture.buses}
    interfaces = {i.id for i in architecture.interfaces}
    catalogue = knowledge.interfaces()
    controls = knowledge.controls()

    all_ids = [c.id for c in architecture.components] + [b.id for b in architecture.buses] + \
        [i.id for i in architecture.interfaces] + [a.id for a in architecture.assets]
    duplicates = sorted({x for x in all_ids if all_ids.count(x) > 1})
    if duplicates:
        errors.append("Duplicate ids: %s" % ", ".join(duplicates))

    for bus in architecture.buses:
        for member in bus.members:
            if member not in components:
                errors.append("Bus %s: unknown component %s" % (bus.id, member))
    for interface in architecture.interfaces:
        if interface.component not in components:
            errors.append("Interface %s: unknown component %s" % (interface.id, interface.component))
        if interface.type not in catalogue:
            errors.append("Interface %s: unknown type %s (known: %s)" % (
                interface.id, interface.type, ", ".join(catalogue)))
    for asset in architecture.assets:
        if asset.component not in components:
            errors.append("Asset %s: unknown component %s" % (asset.id, asset.component))
    for control in architecture.controls:
        if control.control not in controls:
            errors.append("Control %s: not in the control catalogue" % control.control)
        if control.target not in components | buses | interfaces:
            errors.append("Control %s: unknown placement %s" % (control.control, control.target))
    return errors


def dump_architecture(architecture):
    return yaml.safe_dump(architecture.model_dump(mode="json"), sort_keys=False, allow_unicode=True)


def example_path(name="connected_ev.yaml"):
    return EXAMPLES_DIR / name
