"""Node model used by the IoT protocol stack simulator.

The Node class is extended progressively across Parts A-D so that each
protocol-layer operation remains easy to follow during the demonstration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .ipv6 import IPV6_HEADER_LENGTH, NEXT_HEADER_ICMPV6, IPv6Packet, NEXT_HEADER_UDP
from .mac import BROADCAST_MAC, FrameType, MACFrame
from .rpl import RPL_INFINITY, RPL_MULTICAST_IPV6, RPLDIO

from .udp import serialize_udp, deserialize_udp, serialize_udp_payload
from .coap import serialize_coap, deserialize_coap

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

    def send_udp(
        self,
        payload,
        src_port=50000,
        dst_port=5683,
    ):
        """Create a UDP datagram carrying an upper-layer payload."""

        # Temporary integration bridge.
        # The serializers will be moved into the shared package later.

        payload_bytes = serialize_udp_payload(payload)

        udp_datagram = {
            "source_port": src_port,
            "destination_port": dst_port,
            "length": 8 + len(payload_bytes),
            "checksum": 0,
            "payload": payload,
        }


        print(
            f"[Node {self.name}][UDP] "
            "Encapsulating upper-layer payload"
        )
        print(
            f"[Node {self.name}][UDP] Source Port={src_port}"
        )
        print(
            f"[Node {self.name}][UDP] Destination Port={dst_port}"
        )
        print(
            f"[Node {self.name}][UDP] "
            f"Length={udp_datagram['length']} bytes"
        )

        return udp_datagram

    def send_coap(self, temperature):
        """Create the Part C CoAP CON POST request."""

        token = b"\x01\x02"

        coap_message = {
            "version": 1,
            "type": "CON",
            "token_length": len(token),
            "code": "POST",
            "message_id": 1001,
            "token": token,
            "options": {
                "Uri-Path": "temperature"
            },
            "payload": f"Temperature={temperature}°C"
        }

        print(f"[Node {self.name}][CoAP] Creating CON POST request")
        print(f"[Node {self.name}][CoAP] Uri-Path=/temperature")
        print(
            f"[Node {self.name}][CoAP] "
            f"Message ID={coap_message['message_id']}"
        )
        print(f"[Node {self.name}][CoAP] Token={token.hex()}")
        print(
            f"[Node {self.name}][CoAP] "
            f"Payload={coap_message['payload']}"
        )

        return coap_message

    def send_ipv6(
        self,
        payload: bytes,
        destination_ipv6: str,
        next_header: int,
    ) -> int | None:
        """Create an IPv6 packet and send it toward its next RPL hop."""

        ipv6_packet = IPv6Packet(
            source_ipv6=self.ipv6_address,
            destination_ipv6=destination_ipv6,
            next_header=next_header,
            payload=payload,
        )

        print(
            f"[Node {self.name}][IPv6] Creating packet: "
            f"Source={ipv6_packet.source_ipv6}, "
            f"Destination={ipv6_packet.destination_ipv6}, "
            f"Next Header={ipv6_packet.next_header}, "
            f"Payload Length={len(ipv6_packet.payload)}"
        )

        network = self._require_network()
        next_hop = network.next_hop_for_ipv6(
            self,
            destination_ipv6,
        )

        if next_hop is None:
            print(
                f"[Node {self.name}][IPv6] Destination reached "
                f"or ready for gateway delivery"
            )
            return None

        print(
            f"[Node {self.name}][IPv6] Next RPL hop="
            f"Node {next_hop.name}"
        )

        return self.send_mac(
            payload=ipv6_packet.to_bytes(),
            destination_mac=next_hop.mac_address,
            frame_type=FrameType.DATA,
        )

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

            # Part C/D DATA frames carry IPv6 packets.
            if len(frame.payload) >= IPV6_HEADER_LENGTH:
                print(
                    f"[Node {self.name}][MAC] Passing DATA payload to IPv6"
                )
                self.receive_ipv6(frame.payload)

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
        """Parse, forward, or deliver an IPv6 packet."""

        packet = IPv6Packet.from_bytes(packet_bytes)

        print(
            f"[Node {self.name}][IPv6] Received packet: "
            f"Source={packet.source_ipv6}, "
            f"Destination={packet.destination_ipv6}, "
            f"Next Header={packet.next_header}, "
            f"Payload Length={len(packet.payload)}"
        )

        # RPL CONTROL traffic is processed locally.
        if packet.next_header == NEXT_HEADER_ICMPV6:
            self.receive_rpl_dio(
                dio_bytes=packet.payload,
                source_ipv6=packet.source_ipv6,
            )
            return

        # This node is only an intermediate router.
        if packet.destination_ipv6 != self.ipv6_address:
            network = self._require_network()

            next_hop = network.next_hop_for_ipv6(
                self,
                packet.destination_ipv6,
            )

            if next_hop is None:
                print(
                    f"[Node {self.name}][IPv6] Packet reached "
                    f"gateway for destination="
                    f"{packet.destination_ipv6}"
                )

                if self.name == "A":
                    print(
                        f"[Node A][IPv6] Forwarding packet "
                        f"through wired interface to server"
                    )

                    network.transmit_to_server(packet_bytes)

                return

            print(
                f"[Node {self.name}][IPv6] Forwarding packet "
                f"toward Node {next_hop.name}"
            )

            # IMPORTANT:
            # Forward the original IPv6 packet unchanged.
            # Only the MAC addresses change at each hop.
            self.send_mac(
                payload=packet_bytes,
                destination_mac=next_hop.mac_address,
                frame_type=FrameType.DATA,
            )
            return

        if packet.next_header == NEXT_HEADER_UDP:

            print(
                f"[Node {self.name}][IPv6] Passing payload to UDP"
            )

            udp_datagram = deserialize_udp(
                packet.payload,
                secure=False,
            )

            self.receive_udp(udp_datagram)
            return

        print(
            f"[Node {self.name}][IPv6] Upper-layer protocol "
            f"Next Header={packet.next_header} is not integrated yet"
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

        print(
            f"[Node {self.name}][RPL] Rank changed; "
            "rebroadcasting updated DIO"
        )

        # A node that accepts a better route immediately advertises its new
        # rank. Better-route-only updates prevent endless rebroadcast loops.
        self.send_rpl_dio()
        return True

    def receive_udp(self, udp_datagram):
        """Process a UDP datagram delivered to this IoT node."""

        print()
        print(f"[Node {self.name}][UDP] Received UDP datagram")
        print(
            f"[Node {self.name}][UDP] "
            f"Source Port={udp_datagram['source_port']}"
        )
        print(
            f"[Node {self.name}][UDP] "
            f"Destination Port={udp_datagram['destination_port']}"
        )
        print(
            f"[Node {self.name}][UDP] "
            f"Length={udp_datagram['length']} bytes"
        )

        if udp_datagram["destination_port"] != 50000:
            print(
                f"[Node {self.name}][UDP] Datagram is not for this client"
            )
            return

        print(
            f"[Node {self.name}][UDP] Passing payload to CoAP"
        )

        self.receive_coap(udp_datagram["payload"])


    def receive_coap(self, coap_message):
        """Process the CoAP response returned by the server."""

        print(f"[Node {self.name}][CoAP] Received CoAP response")
        print(f"[Node {self.name}][CoAP] Type={coap_message['type']}")
        print(f"[Node {self.name}][CoAP] Code={coap_message['code']}")
        print(
            f"[Node {self.name}][CoAP] "
            f"Message ID={coap_message['message_id']}"
        )
        print(
            f"[Node {self.name}][CoAP] "
            f"Token={coap_message['token'].hex()}"
        )
        print(
            f"[Node {self.name}][CoAP] "
            f"Payload={coap_message['payload']}"
        )
