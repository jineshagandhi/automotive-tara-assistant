"""Architecture graph and attack path search.

Nodes are interfaces, components and buses. An attack path starts at an
external interface, enters the component that exposes it, and moves over
buses and components to the component that holds the target asset.
"""

import networkx as nx

from tara import knowledge

MAX_PATHS_PER_ENTRY = 3
PATH_CUTOFF = 9


class ArchitectureGraph:
    def __init__(self, architecture):
        self.architecture = architecture
        self.components = {c.id: c for c in architecture.components}
        self.buses = {b.id: b for b in architecture.buses}
        self.interfaces = {i.id: i for i in architecture.interfaces}
        self.catalogue = knowledge.interfaces()

        graph = nx.Graph()
        for component in architecture.components:
            graph.add_node(component.id, kind="component", label=component.name)
        for bus in architecture.buses:
            graph.add_node(bus.id, kind="bus", label=bus.name)
            for member in bus.members:
                graph.add_edge(bus.id, member)
        for interface in architecture.interfaces:
            label = interface.name or self.catalogue[interface.type]["label"]
            graph.add_node(interface.id, kind="interface", label=label)
            graph.add_edge(interface.id, interface.component)
        self.graph = graph
        self._paths = {}

    def kind(self, node):
        return self.graph.nodes[node]["kind"]

    def label(self, node):
        return self.graph.nodes[node]["label"]

    def node_type(self, node):
        """Type used to match control placement: component type, 'bus' or interface type."""
        if node in self.components:
            return self.components[node].type
        if node in self.buses:
            return "bus"
        return self.interfaces[node].type

    def is_gateway(self, node):
        return node in self.components and self.components[node].type == "gateway"

    def paths_to(self, target, asset_id=None):
        """All attack paths from every interface to the target component.

        Paths never run through a second interface. Receive-only radio links
        (GNSS, TPMS, key fob) only reach the assets they feed, listed in the
        interface's targets.
        """
        key = (target, asset_id)
        if key not in self._paths:
            self._paths[key] = self._search(target, asset_id)
        return self._paths[key]

    def _search(self, target, asset_id):
        found = []
        other_interfaces = set(self.interfaces)

        for interface in self.architecture.interfaces:
            spec = self.catalogue[interface.type]
            if not spec.get("pivot", True):
                if interface.component == target and asset_id in interface.targets:
                    found.append([interface.id, target])
                continue
            if interface.component == target:
                found.append([interface.id, target])
                continue

            blocked = other_interfaces - {interface.id}
            view = nx.restricted_view(self.graph, blocked, [])
            try:
                paths = nx.shortest_simple_paths(view, interface.id, target)
                for n, path in enumerate(paths):
                    if n >= MAX_PATHS_PER_ENTRY or len(path) > PATH_CUTOFF:
                        break
                    found.append(path)
            except nx.NetworkXNoPath:
                continue

        return found

    def pivots(self, path):
        """Components the attacker must compromise between entry and target."""
        return [node for node in path[2:-1] if node in self.components]

    def hops(self, path):
        """Components the attack must move through after the entry component,
        including the target. An asset on the entry component needs no hop."""
        return [node for node in path[2:] if node in self.components]
