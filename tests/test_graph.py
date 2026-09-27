from tara.graph import ArchitectureGraph


def test_obd_reaches_brake_through_gateway(architecture):
    graph = ArchitectureGraph(architecture)
    paths = [p for p in graph.paths_to("ESC") if p[0] == "IF_OBD"]
    assert paths[0] == ["IF_OBD", "CGW", "CAN_CH", "ESC"]
    assert graph.hops(paths[0]) == ["ESC"]


def test_paths_never_pass_through_another_interface(architecture):
    graph = ArchitectureGraph(architecture)
    interfaces = set(graph.interfaces)
    for component in graph.components:
        for path in graph.paths_to(component):
            assert not set(path[1:]) & interfaces


def test_receive_only_links_do_not_pivot(architecture):
    graph = ArchitectureGraph(architecture)
    # GNSS feeds the position asset on the TCU but cannot be used to reach the brakes
    assert not any(p[0] == "IF_GNSS" for p in graph.paths_to("ESC"))
    assert ["IF_GNSS", "TCU"] in graph.paths_to("TCU", "A_POS")
    assert ["IF_GNSS", "TCU"] not in graph.paths_to("TCU", "A_REMOTE")


def test_node_types(architecture):
    graph = ArchitectureGraph(architecture)
    assert graph.node_type("CGW") == "gateway"
    assert graph.node_type("CAN_CH") == "bus"
    assert graph.node_type("IF_OBD") == "obd"
