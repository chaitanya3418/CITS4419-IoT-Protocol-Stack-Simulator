"""Simplified IEEE 802.15.4 MAC frame used by the project.

The assignment defines a teaching-oriented 12-byte fixed header:
    Source MAC        4 bytes
    Destination MAC   4 bytes
    Sequence Number   1 byte
    Frame Type        1 byte
    Payload Length    2 bytes
followed by the variable-length payload.
"""

from dataclasses import dataclass
from enum import IntEnum
import struct


BROADCAST_MAC = "FF:FF:FF:FF"

# Network byte order (big-endian):
# 4s = source MAC, 4s = destination MAC,
# B = sequence number, B = frame type, H = payload length.
_MAC_HEADER = struct.Struct("!4s4sBBH")
MAC_HEADER_LENGTH = _MAC_HEADER.size


class FrameType(IntEnum):
    """Frame-type values required by the project specification."""

    DATA = 1
    ACK = 2
    CONTROL = 3


def mac_to_bytes(address: str) -> bytes:
    """Convert a four-byte colon-separated MAC address to raw bytes."""
    parts = address.split(":")
    if len(parts) != 4:
        raise ValueError(f"MAC address must contain exactly 4 bytes: {address}")

    if any(len(part) != 2 for part in parts):
        raise ValueError(
            f"Each MAC byte must use two hexadecimal digits: {address}"
        )

    try:
        return bytes(int(part, 16) for part in parts)
    except ValueError as exc:
        raise ValueError(f"Invalid hexadecimal MAC address: {address}") from exc


def bytes_to_mac(raw: bytes) -> str:
    """Convert four raw MAC-address bytes to the simulator display format."""
    if len(raw) != 4:
        raise ValueError("A simulator MAC address must be exactly 4 bytes")
    return ":".join(f"{byte:02X}" for byte in raw)


@dataclass(frozen=True)
class MACFrame:
    """Represent one simplified IEEE 802.15.4 MAC frame."""

    source_mac: str
    destination_mac: str
    sequence_number: int
    frame_type: FrameType
    payload: bytes = b""

    def to_bytes(self) -> bytes:
        """Serialize the MAC header and payload into the required layout."""
        if not 0 <= self.sequence_number <= 0xFF:
            raise ValueError("MAC sequence number must fit in one byte")

        if len(self.payload) > 0xFFFF:
            raise ValueError(
                "MAC payload is too large for the 2-byte length field"
            )

        header = _MAC_HEADER.pack(
            mac_to_bytes(self.source_mac),
            mac_to_bytes(self.destination_mac),
            self.sequence_number,
            int(self.frame_type),
            len(self.payload),
        )

        return header + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> "MACFrame":
        """Parse raw bytes into a MACFrame and validate payload length."""
        if len(data) < MAC_HEADER_LENGTH:
            raise ValueError(
                "MAC frame is shorter than the required 12-byte header"
            )

        source, destination, sequence, frame_type, payload_length = (
            _MAC_HEADER.unpack(data[:MAC_HEADER_LENGTH])
        )

        payload = data[MAC_HEADER_LENGTH:]

        if len(payload) != payload_length:
            raise ValueError(
                "MAC payload length mismatch: "
                f"header={payload_length}, actual={len(payload)}"
            )

        return cls(
            source_mac=bytes_to_mac(source),
            destination_mac=bytes_to_mac(destination),
            sequence_number=sequence,
            frame_type=FrameType(frame_type),
            payload=payload,
        )
