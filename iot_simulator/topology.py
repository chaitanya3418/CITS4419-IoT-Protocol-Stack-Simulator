"""Static network topology required by CITS4419 Project Parts A and B."""

from .network import Network
from .node import Node
from .rpl import RPL_INFINITY, RPL_ROOT_RANK


NODE_CONFIG = {
    "A": {
        "mac_address": "00:00:00:01",
        "ipv6_address": "fd00::1",
        "neighbors": ["B", "C"],
    },
    "B": {
        "mac_address": "00:00:00:02",
        "ipv6_address": "fd00::2",
        "neighbors": ["A", "D"],
    },
    "C": {
        "mac_address": "00:00:00:03",
        "ipv6_address": "fd00::3",
        "neighbors": ["A", "E"],
    },
    "D": {
        "mac_address": "00:00:00:04",
        "ipv6_address": "fd00::4",
        "neighbors": ["B"],
    },
    "E": {
        "mac_address": "00:00:00:05",
        "ipv6_address": "fd00::5",
        "neighbors": ["C"],
    },
}


def build_iot_network() -> dict[str, Node]:
    """Create nodes A-E with their initial MAC and RPL state."""
    # Node A starts as the RPL root; every other node begins with an
    # infinite rank and no preferred parent.
    nodes = {
        name: Node(
            name=name,
            mac_address=config["mac_address"],
            ipv6_address=config["ipv6_address"],
            neighbors=list(config["neighbors"]),
            rank=RPL_ROOT_RANK if name == "A" else RPL_INFINITY,
            parent=None,
        )
        for name, config in NODE_CONFIG.items()
    }

    network = Network(nodes)

    for node in nodes.values():
        node.network = network

    return nodes


def setup_network(nodes: dict[str, Node]) -> None:
    """Call setup() for every IoT node at simulator startup."""
    for node in nodes.values():
        node.setup()


def converge_rpl(nodes: dict[str, Node]) -> None:
    """Start automatic RPL formation from root Node A.

    The root advertises Rank 0. Each node that accepts a better route updates
    its rank/parent and immediately rebroadcasts its own DIO, allowing the
    fixed five-node topology to converge automatically.
    """
    # Start topology formation by broadcasting the root's Rank-0 DIO.
    root = nodes["A"]

    if root.rank != RPL_ROOT_RANK:
        raise ValueError("Node A must have RPL Rank 0 before convergence")

    print("[RPL] Starting automatic topology formation from root Node A")
    root.send_rpl_dio()

    print("[RPL] Topology formation complete")
