"""Node model used by the IoT protocol stack simulator.

Part A1 establishes the node properties required by the assignment.
Later parts extend this same class with MAC, IPv6, RPL, UDP, CoAP,
IPsec ESP and DTLS send/receive behaviour.
"""

from dataclasses import dataclass, field


@dataclass
class Node:
    """Represent one IoT node in the five-node wireless network."""

    name: str
    mac_address: str
    ipv6_address: str
    neighbors: list[str] = field(default_factory=list)
    mac_sequence_number: int = 0

    def setup(self) -> None:
        """Initialize the node and print its required identification details."""
        print(
            f"[Node {self.name}][SETUP] Initialized: "
            f"MAC={self.mac_address}, IPv6={self.ipv6_address}"
        )
