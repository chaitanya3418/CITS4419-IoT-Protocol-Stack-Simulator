"""Node model used by the IoT protocol stack simulator.

The Node class is extended progressively across Parts A-D so that each
protocol-layer operation remains easy to follow during the demonstration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .mac import BROADCAST_MAC, FrameType, MACFrame

if TYPE_CHECKING:
    from .network import Network


@dataclass
class Node:
    """Represent one IoT node in the five-node wireless network."""

    name: str
    mac_address: str
    ipv6_address: str
    neighbors: list[str] = field(default_factory=list)
    mac_sequence_number: int = 0
    network: Network | None = field(default=None, repr=False, compare=False)

    # Observable MAC state used by later tests and protocol layers.
    last_ack_sequence: int | None = field(default=None, init=False)
    received_mac_payloads: list[bytes] = field(default_factory=list, init=False)

    def setup(self) -> None:
        """Initialize the node and print its required identification details."""
        print(
            f"[Node {self.name}][SETUP] Initialized: "
            f"MAC={self.mac_address}, IPv6={self.ipv6_address}"
        )

    def _require_network(self) -> Network:
        """Return the attached network or fail if the node is not connected."""
        if self.network is None:
            raise RuntimeError(f"Node {self.name} is not attached to a network")
        return self.network

    def _next_mac_sequence(self) -> int:
        """Return the current sequence number and advance the 8-bit counter."""
        sequence = self.mac_sequence_number
        self.mac_sequence_number = (self.mac_sequence_number + 1) % 256
        return sequence

    def send_mac(
        self,
        payload: bytes,
        destination_mac: str,
        frame_type: FrameType = FrameType.DATA,
    ) -> int:
        """Create and transmit a unicast DATA frame.

        Part A3 intentionally implements only unicast DATA/ACK behaviour.
        Broadcast CONTROL transmission is added separately in Part A4.
        """
        if frame_type != FrameType.DATA:
            raise NotImplementedError(
                "Part A3 send_mac() currently supports DATA frames only"
            )

        if destination_mac == BROADCAST_MAC:
            raise NotImplementedError(
                "Broadcast MAC transmission is implemented in Part A4"
            )

        sequence = self._next_mac_sequence()

        frame = MACFrame(
            source_mac=self.mac_address,
            destination_mac=destination_mac,
            sequence_number=sequence,
            frame_type=FrameType.DATA,
            payload=payload,
        )

        print(
            f"[Node {self.name}][MAC] Creating DATA frame: "
            f"Seq={sequence}, Payload Length={len(payload)}"
        )
        print(
            f"[Node {self.name}][MAC] Transmitting DATA frame: "
            f"Source MAC={self.mac_address}, "
            f"Destination MAC={destination_mac}"
        )

        self._require_network().transmit(self, frame.to_bytes())
        return sequence

    def send_mac_ack(
        self,
        destination_mac: str,
        acknowledged_sequence: int,
    ) -> None:
        """Transmit an ACK containing the received DATA sequence number."""
        frame = MACFrame(
            source_mac=self.mac_address,
            destination_mac=destination_mac,
            sequence_number=acknowledged_sequence,
            frame_type=FrameType.ACK,
            payload=b"",
        )

        print(
            f"[Node {self.name}][MAC] Creating ACK frame: "
            f"Seq={acknowledged_sequence}"
        )
        print(
            f"[Node {self.name}][MAC] Transmitting ACK frame: "
            f"Source MAC={self.mac_address}, "
            f"Destination MAC={destination_mac}"
        )

        self._require_network().transmit(self, frame.to_bytes())

    def receive_mac(self, frame_bytes: bytes) -> None:
        """Parse and process a unicast DATA or ACK frame."""
        frame = MACFrame.from_bytes(frame_bytes)

        if frame.destination_mac != self.mac_address:
            raise ValueError(
                f"Node {self.name} received a frame addressed to "
                f"{frame.destination_mac}"
            )

        print(
            f"[Node {self.name}][MAC] Received {frame.frame_type.name} frame "
            f"from MAC={frame.source_mac}, Seq={frame.sequence_number}"
        )
        print(
            f"[Node {self.name}][MAC] Parsed MAC header: "
            f"Destination MAC={frame.destination_mac}, "
            f"Payload Length={len(frame.payload)}"
        )

        if frame.frame_type == FrameType.ACK:
            self.last_ack_sequence = frame.sequence_number
            print(
                f"[Node {self.name}][MAC] ACK accepted for "
                f"Seq={frame.sequence_number}"
            )
            return

        if frame.frame_type == FrameType.DATA:
            self.received_mac_payloads.append(frame.payload)
            print(
                f"[Node {self.name}][MAC] Extracted DATA payload "
                f"({len(frame.payload)} bytes)"
            )

            # The assignment requires the ACK to contain the same sequence
            # number as the DATA frame being acknowledged.
            self.send_mac_ack(
                destination_mac=frame.source_mac,
                acknowledged_sequence=frame.sequence_number,
            )
            return

        raise NotImplementedError(
            "CONTROL frame processing is implemented in Part A4"
        )
