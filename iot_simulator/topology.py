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
