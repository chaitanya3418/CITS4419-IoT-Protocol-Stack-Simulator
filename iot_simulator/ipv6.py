"""Simplified IPv6 packet format required by CITS4419 Part B.

The assignment uses a teaching-oriented IPv6 header containing:
    Source IPv6 Address      16 bytes
    Destination IPv6 Address 16 bytes
    Next Header               1 byte
    Payload Length            2 bytes
followed by the variable-length payload.
"""

from dataclasses import dataclass
from ipaddress import IPv6Address
import struct


IPV6_HEADER_LENGTH = 35

# Next Header values required later by the project.
NEXT_HEADER_UDP = 17
NEXT_HEADER_ESP = 50
NEXT_HEADER_ICMPV6 = 58
NEXT_HEADER_NONE = 59

_IPV6_HEADER = struct.Struct("!16s16sBH")


@dataclass(frozen=True)
class IPv6Packet:
    """Represent the simplified IPv6 packet used by the simulator."""

    source_ipv6: str
    destination_ipv6: str
    next_header: int
    payload: bytes = b""

    def to_bytes(self) -> bytes:
        """Serialize the simplified IPv6 header and payload."""
        if not 0 <= self.next_header <= 0xFF:
            raise ValueError("IPv6 Next Header must fit in one byte")

        if len(self.payload) > 0xFFFF:
            raise ValueError(
                "IPv6 payload is too large for the 2-byte length field"
            )

        source = IPv6Address(self.source_ipv6).packed
        destination = IPv6Address(self.destination_ipv6).packed

        header = _IPV6_HEADER.pack(
            source,
            destination,
            self.next_header,
            len(self.payload),
        )

        return header + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> "IPv6Packet":
        """Parse raw bytes into the simulator's simplified IPv6 packet."""
        if len(data) < IPV6_HEADER_LENGTH:
            raise ValueError(
                "IPv6 packet is shorter than the required 35-byte header"
            )

        source, destination, next_header, payload_length = (
            _IPV6_HEADER.unpack(data[:IPV6_HEADER_LENGTH])
        )

        payload = data[IPV6_HEADER_LENGTH:]

        if len(payload) != payload_length:
            raise ValueError(
                "IPv6 payload length mismatch: "
                f"header={payload_length}, actual={len(payload)}"
            )

        return cls(
            source_ipv6=str(IPv6Address(source)),
            destination_ipv6=str(IPv6Address(destination)),
            next_header=next_header,
            payload=payload,
        )
