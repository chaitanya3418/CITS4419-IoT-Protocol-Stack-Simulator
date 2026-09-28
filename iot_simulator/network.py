"""One-hop wireless delivery model for the IoT simulator.

The project specification says to ignore collisions, interference, channel
contention and CSMA/CA. A transmitted frame is therefore delivered directly
to the appropriate one-hop neighbor or neighbors.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .mac import BROADCAST_MAC, MACFrame

if TYPE_CHECKING:
    from .node import Node


class Network:
    """Deliver MAC frames between one-hop neighbors."""

    def __init__(self, nodes: dict[str, Node]) -> None:
        self.nodes = nodes
        self.nodes_by_mac = {
            node.mac_address: node for node in nodes.values()
        }

    def transmit(self, sender: Node, frame_bytes: bytes) -> None:
        """Deliver one serialized MAC frame."""
        frame = MACFrame.from_bytes(frame_bytes)

        if frame.source_mac != sender.mac_address:
            raise ValueError(
                "Frame source MAC does not match the transmitting node"
            )

        if frame.destination_mac == BROADCAST_MAC:
            self._broadcast(sender, frame_bytes)
            return

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

    def _broadcast(
        self,
        sender: Node,
        frame_bytes: bytes,
    ) -> None:
        """Deliver a broadcast frame to all one-hop neighbors."""
        print(
            f"[Network][MAC] Broadcast from Node {sender.name} "
            f"to one-hop neighbors={sender.neighbors}"
        )

        for neighbor_name in sender.neighbors:
            receiver = self.nodes[neighbor_name]

            print(
                f"[Network][MAC] Broadcast delivery: "
                f"Node {sender.name} -> Node {receiver.name}"
            )

            receiver.receive_mac(frame_bytes)
