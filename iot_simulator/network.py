"""One-hop wireless delivery model for Part A3.

The project specification says to ignore collisions, interference, channel
contention and CSMA/CA. Therefore a transmitted unicast MAC frame is delivered
directly to the addressed one-hop neighbor.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .mac import BROADCAST_MAC, MACFrame

if TYPE_CHECKING:
    from .node import Node


class Network:
    """Deliver unicast MAC frames between one-hop neighbors."""

    def __init__(self, nodes: dict[str, Node]) -> None:
        self.nodes = nodes
        self.nodes_by_mac = {
            node.mac_address: node for node in nodes.values()
        }

    def transmit(self, sender: Node, frame_bytes: bytes) -> None:
        """Deliver one serialized unicast MAC frame."""
        frame = MACFrame.from_bytes(frame_bytes)

        if frame.source_mac != sender.mac_address:
            raise ValueError(
                "Frame source MAC does not match the transmitting node"
            )

        if frame.destination_mac == BROADCAST_MAC:
            raise NotImplementedError(
                "Broadcast delivery is implemented in Part A4"
            )

        receiver = self.nodes_by_mac.get(frame.destination_mac)

        if receiver is None:
            raise ValueError(
                f"Unknown destination MAC: {frame.destination_mac}"
            )

        if receiver.name not in sender.neighbors:
            raise ValueError(
                f"Node {receiver.name} is not a one-hop neighbor "
                f"of Node {sender.name}"
            )

        print(
            f"[Network][MAC] One-hop delivery: "
            f"Node {sender.name} -> Node {receiver.name}"
        )

        receiver.receive_mac(frame_bytes)
