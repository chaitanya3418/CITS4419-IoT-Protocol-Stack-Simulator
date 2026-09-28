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
        self.nodes_by_ipv6 = {
            node.ipv6_address: node for node in nodes.values()
        }
        self.server = None

    def attach_server(self, server) -> None:
        """Attach the wired CoAP server to gateway Node A."""

        self.server = server
        server.network = self

    def transmit_to_server(self, packet_bytes: bytes):
        """Deliver an IPv6 packet from gateway Node A to the wired server."""

        if self.server is None:
            raise RuntimeError(
                "CoAP server is not attached to the network"
            )

        print(
            "[Network][Wired] Delivering IPv6 packet: "
            "Node A -> CoAP Server"
        )

        return self.server.receive_ipv6(packet_bytes)

    def transmit_from_server(self, packet_bytes: bytes) -> None:
        """Deliver a server IPv6 packet to gateway Node A."""

        print(
            "[Network][Wired] Delivering IPv6 packet: "
            "CoAP Server -> Node A"
        )

        self.nodes["A"].receive_ipv6(packet_bytes)

    def node_name_for_ipv6(self, ipv6_address: str) -> str:
        """Resolve an IoT node name from its configured IPv6 address."""
        node = self.nodes_by_ipv6.get(ipv6_address)

        if node is None:
            raise ValueError(
                f"Unknown IoT source IPv6 address: {ipv6_address}"
            )

        return node.name

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

    def next_hop_for_ipv6(
        self,
        sender: Node,
        destination_ipv6: str,
    ) -> Node | None:
        """Return the next IoT node along the converged RPL tree."""

        # The CoAP server is connected directly to root Node A.
        if destination_ipv6 == "2001:db8::1":
            if sender.name == "A":
                # A has reached the wired gateway side.
                return None

            if sender.parent is None:
                raise RuntimeError(
                    f"Node {sender.name} has no RPL parent"
                )

            return self.nodes[sender.parent]

        destination = self.nodes_by_ipv6.get(destination_ipv6)

        if destination is None:
            raise ValueError(
                f"Unknown IPv6 destination: {destination_ipv6}"
            )

        if destination.name == sender.name:
            return None

        # Build destination -> ... -> root path.
        path_to_root = [destination]
        current = destination

        while current.parent is not None:
            current = self.nodes[current.parent]
            path_to_root.append(current)

        path_names = [node.name for node in path_to_root]

        # sender is an ancestor of destination:
        # move downward to the child leading toward destination.
        if sender.name in path_names:
            sender_index = path_names.index(sender.name)
            return path_to_root[sender_index - 1]

        # Otherwise move upward toward sender's preferred parent.
        if sender.parent is None:
            raise RuntimeError(
                f"No route from Node {sender.name} "
                f"to {destination_ipv6}"
            )

        return self.nodes[sender.parent]