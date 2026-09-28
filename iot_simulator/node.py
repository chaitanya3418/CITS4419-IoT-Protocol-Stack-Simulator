"""Node model used by the IoT protocol stack simulator.

The Node class is extended progressively across Parts A-D so that each
protocol-layer operation remains easy to follow during the demonstration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .ipv6 import IPV6_HEADER_LENGTH, NEXT_HEADER_ICMPV6, IPv6Packet
from .mac import BROADCAST_MAC, FrameType, MACFrame
from .rpl import RPL_INFINITY, RPL_MULTICAST_IPV6, RPLDIO

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

    # Part B RPL state.
    rank: int = RPL_INFINITY
    parent: str | None = None

    network: Network | None = field(default=None, repr=False, compare=False)

    # Observable MAC state used by tests and later protocol layers.
    last_ack_sequence: int | None = field(default=None, init=False)
    received_mac_payloads: list[bytes] = field(default_factory=list, init=False)
    received_control_payloads: list[bytes] = field(
        default_factory=list,
        init=False,
    )

    def setup(self) -> None:
        """Initialize the node and print its required identification details."""
        rank_text = "infinity" if self.rank == RPL_INFINITY else str(self.rank)
        parent_text = self.parent if self.parent is not None else "None"

        print(
            f"[Node {self.name}][SETUP] Initialized: "
            f"MAC={self.mac_address}, IPv6={self.ipv6_address}, "
            f"RPL Rank={rank_text}, Parent={parent_text}"
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
        """Create and transmit a DATA or broadcast CONTROL MAC frame."""
        if frame_type == FrameType.ACK:
            raise ValueError(
                "ACK frames must be created with send_mac_ack()"
            )

        if frame_type == FrameType.DATA and destination_mac == BROADCAST_MAC:
            raise ValueError(
                "Part A uses broadcast transmission for CONTROL frames only"
            )

        if frame_type == FrameType.CONTROL and destination_mac != BROADCAST_MAC:
            raise ValueError(
                "CONTROL frames in Part A4 must use the broadcast MAC address"
            )

        sequence = self._next_mac_sequence()

        frame = MACFrame(
            source_mac=self.mac_address,
            destination_mac=destination_mac,
            sequence_number=sequence,
            frame_type=frame_type,
            payload=payload,
        )

        action = (
            "Broadcasting"
            if destination_mac == BROADCAST_MAC
            else "Transmitting"
        )

        print(
            f"[Node {self.name}][MAC] Creating {frame_type.name} frame: "
            f"Seq={sequence}, Payload Length={len(payload)}"
        )
        print(
            f"[Node {self.name}][MAC] {action} {frame_type.name} frame: "
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

    def send_rpl_dio(self) -> int:
        """Broadcast this node's current RPL rank using IPv6 and MAC."""
        if self.rank == RPL_INFINITY:
            raise ValueError(
                f"Node {self.name} cannot advertise an infinite RPL rank"
            )

        dio = RPLDIO(rank=self.rank)

        print(
            f"[Node {self.name}][RPL] Creating DIO: "
            f"Type={dio.type}, Code={dio.code}, Rank={dio.rank}"
        )

        ipv6_packet = IPv6Packet(
            source_ipv6=self.ipv6_address,
            destination_ipv6=RPL_MULTICAST_IPV6,
            next_header=NEXT_HEADER_ICMPV6,
            payload=dio.to_bytes(),
        )

        print(
            f"[Node {self.name}][IPv6] Encapsulating RPL DIO: "
            f"Source={ipv6_packet.source_ipv6}, "
            f"Destination={ipv6_packet.destination_ipv6}, "
            f"Next Header={ipv6_packet.next_header}, "
            f"Payload Length={len(ipv6_packet.payload)}"
        )

        return self.send_mac(
            payload=ipv6_packet.to_bytes(),
            destination_mac=BROADCAST_MAC,
            frame_type=FrameType.CONTROL,
        )

    def receive_mac(self, frame_bytes: bytes) -> None:
        """Parse and process a DATA, ACK, or broadcast CONTROL frame."""
        frame = MACFrame.from_bytes(frame_bytes)

        if frame.destination_mac not in (
            self.mac_address,
            BROADCAST_MAC,
        ):
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

            self.send_mac_ack(
                destination_mac=frame.source_mac,
                acknowledged_sequence=frame.sequence_number,
            )
            return

        if frame.frame_type == FrameType.CONTROL:
            self.received_control_payloads.append(frame.payload)
            print(
                f"[Node {self.name}][MAC] Extracted CONTROL payload "
                f"({len(frame.payload)} bytes)"
            )

            if frame.destination_mac == BROADCAST_MAC:
                print(
                    f"[Node {self.name}][MAC] Broadcast CONTROL frame: "
                    "no MAC ACK required"
                )

            # Part A allowed generic CONTROL payloads. From Part B onward,
            # CONTROL payloads that contain a full IPv6 header are passed up.
            if len(frame.payload) >= IPV6_HEADER_LENGTH:
                self.receive_ipv6(frame.payload)

            return

        raise ValueError(
            f"Unsupported MAC frame type: {frame.frame_type}"
        )

    def receive_ipv6(self, packet_bytes: bytes) -> None:
        """Parse an IPv6 packet and dispatch an ICMPv6/RPL payload."""
        packet = IPv6Packet.from_bytes(packet_bytes)

        print(
            f"[Node {self.name}][IPv6] Received packet: "
            f"Source={packet.source_ipv6}, "
            f"Destination={packet.destination_ipv6}, "
            f"Next Header={packet.next_header}, "
            f"Payload Length={len(packet.payload)}"
        )

        if packet.next_header != NEXT_HEADER_ICMPV6:
            print(
                f"[Node {self.name}][IPv6] Next Header "
                f"{packet.next_header} is not RPL/ICMPv6"
            )
            return

        self.receive_rpl_dio(
            dio_bytes=packet.payload,
            source_ipv6=packet.source_ipv6,
        )

    def receive_rpl_dio(
        self,
        dio_bytes: bytes,
        source_ipv6: str,
    ) -> bool:
        """Apply a better RPL route advertised by a one-hop neighbor."""
        dio = RPLDIO.from_bytes(dio_bytes)

        print(
            f"[Node {self.name}][RPL] Received DIO: "
            f"Source={source_ipv6}, Advertised Rank={dio.rank}"
        )

        if dio.rank == RPL_INFINITY:
            print(
                f"[Node {self.name}][RPL] Ignoring infinite advertised rank"
            )
            return False

        candidate_rank = dio.rank + 1

        if candidate_rank >= RPL_INFINITY:
            candidate_rank = RPL_INFINITY

        if candidate_rank >= self.rank:
            current_rank = (
                "infinity"
                if self.rank == RPL_INFINITY
                else str(self.rank)
            )
            print(
                f"[Node {self.name}][RPL] Route not better: "
                f"Candidate Rank={candidate_rank}, "
                f"Current Rank={current_rank}"
            )
            return False

        parent_name = self._require_network().node_name_for_ipv6(source_ipv6)

        old_rank = (
            "infinity"
            if self.rank == RPL_INFINITY
            else str(self.rank)
        )

        self.rank = candidate_rank
        self.parent = parent_name

        print(
            f"[Node {self.name}][RPL] Better route accepted: "
            f"Rank {old_rank} -> {self.rank}, "
            f"Parent={self.parent}"
        )

        # B4 deliberately stops here. B5 will rebroadcast an updated DIO
        # automatically so the complete RPL tree can converge.
        return True
