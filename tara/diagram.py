"""Graphviz DOT rendering of the architecture, with attack path highlighting."""

from tara import knowledge

VECTOR_COLOURS = {
    "Network": "#d1495b",
    "Adjacent": "#e8871e",
    "Local": "#d4a72c",
    "Physical": "#6c757d",
}

TYPE_COLOURS = {
    "backend": "#dbe7f5",
    "telematics": "#e3ecfa",
    "infotainment": "#e3ecfa",
    "gateway": "#e6f2e6",
    "ecu": "#f4f4f4",
    "sensor": "#f4f4f4",
}

ZONE_TITLES = {
    "external": "External / cloud",
    "connectivity": "Connectivity",
    "infotainment": "Infotainment",
    "backbone": "Backbone",
    "chassis": "Chassis (safety critical)",
    "powertrain": "Powertrain",
    "body": "Body and comfort",
}

HIGHLIGHT = "#c1121f"


def _quote(text):
    return '"%s"' % str(text).replace('"', "'")


def _depths(architecture):
    """Distance of every component and bus from the outside world.

    The diagram is layered like an E/E drawing: cloud and connectivity at the
    top, domain ECUs at the bottom. Edges are written from the lower to the
    higher layer so Graphviz ranks them that way.
    """
    import networkx as nx

    graph = nx.Graph()
    graph.add_nodes_from(c.id for c in architecture.components)
    for bus in architecture.buses:
        for member in bus.members:
            graph.add_edge(bus.id, member)

    roots = [c.id for c in architecture.components if c.type == "backend"] or \
        [c.id for c in architecture.components if c.type in ("telematics", "infotainment")] or \
        [c.id for c in architecture.components[:1]]
    depth = {}
    for root in roots:
        for node, distance in nx.single_source_shortest_path_length(graph, root).items():
            depth[node] = min(distance, depth.get(node, distance))
    return depth


def to_dot(architecture, highlight_path=None, highlight_nodes=None, extra_controls=None):
    """Return DOT source. highlight_path is a list of node ids along an attack path."""
    depth = _depths(architecture)
    catalogue = knowledge.interfaces()
    control_names = knowledge.controls()
    highlight_nodes = set(highlight_nodes or [])
    path = list(highlight_path or [])
    path_nodes = set(path)
    path_edges = {frozenset(pair) for pair in zip(path, path[1:])}

    controls_by_node = {}
    for control in list(architecture.controls) + list(extra_controls or []):
        name = control_names.get(control.control, {}).get("name", control.control)
        short = name.split(" (")[0]
        mark = "+" if control.status == "existing" else "*"
        controls_by_node.setdefault(control.target, []).append("%s %s" % (mark, short))

    lines = [
        "graph architecture {",
        '  graph [rankdir=TB, bgcolor="transparent", fontname="Helvetica", fontsize=12, '
        'nodesep=0.25, ranksep=0.45, pad=0.2, newrank=true];',
        '  node [fontname="Helvetica", fontsize=10, penwidth=1.2];',
        '  edge [color="#8a8f98", penwidth=1.1];',
    ]

    zones = {}
    for component in architecture.components:
        zones.setdefault(component.zone, []).append(component)

    for n, (zone, components) in enumerate(zones.items()):
        lines.append("  subgraph cluster_%d {" % n)
        lines.append('    label=%s; style="rounded,dashed"; color="#b8bec7"; fontcolor="#5c6370";'
                     % _quote(ZONE_TITLES.get(zone, zone.capitalize())))
        for component in components:
            label = "%s\\n%s" % (component.id, component.name)
            if component.asil != "QM":
                label += "\\nASIL %s" % component.asil
            for text in controls_by_node.get(component.id, []):
                label += "\\n%s" % text
            hot = component.id in path_nodes or component.id in highlight_nodes
            lines.append('    %s [shape=box, style="rounded,filled", fillcolor=%s, color=%s, penwidth=%s, label=%s];' % (
                _quote(component.id), _quote("#fde2e4" if hot else TYPE_COLOURS.get(component.type, "#f4f4f4")),
                _quote(HIGHLIGHT if hot else "#6b7280"), "2.4" if hot else "1.2", _quote(label)))
        lines.append("  }")

    for bus in architecture.buses:
        label = "%s\\n%s" % (bus.name, bus.type)
        for text in controls_by_node.get(bus.id, []):
            label += "\\n%s" % text
        hot = bus.id in path_nodes or bus.id in highlight_nodes
        lines.append('  %s [shape=box, style="filled", fillcolor=%s, fontcolor="white", color=%s, penwidth=%s, label=%s];' % (
            _quote(bus.id), _quote(HIGHLIGHT if hot else "#3d4451"), _quote(HIGHLIGHT if hot else "#3d4451"),
            "2.4" if hot else "1", _quote(label)))
        for member in bus.members:
            on_path = frozenset((bus.id, member)) in path_edges
            a, b = bus.id, member
            if depth.get(member, 99) < depth.get(bus.id, 99):
                a, b = member, bus.id
            lines.append("  %s -- %s [color=%s, penwidth=%s];" % (
                _quote(a), _quote(b), _quote(HIGHLIGHT if on_path else "#8a8f98"),
                "3" if on_path else "1.1"))

    for interface in architecture.interfaces:
        spec = catalogue[interface.type]
        colour = VECTOR_COLOURS[spec["attack_vector"]]
        label = "%s\\n(%s)" % (interface.name or spec["label"], spec["attack_vector"])
        for text in controls_by_node.get(interface.id, []):
            label += "\\n%s" % text
        hot = interface.id in path_nodes or interface.id in highlight_nodes
        lines.append('  %s [shape=cds, style="filled", fillcolor=%s, fontcolor="white", color=%s, penwidth=%s, label=%s];' % (
            _quote(interface.id), _quote(colour), _quote(HIGHLIGHT if hot else colour),
            "3" if hot else "1", _quote(label)))
        on_path = frozenset((interface.id, interface.component)) in path_edges
        lines.append("  %s -- %s [style=%s, color=%s, penwidth=%s];" % (
            _quote(interface.id), _quote(interface.component), "solid" if on_path else "dashed",
            _quote(HIGHLIGHT if on_path else colour), "3" if on_path else "1.1"))

    lines.append("}")
    return "\n".join(lines)
