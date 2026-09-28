"""Simplified ICMPv6 RPL structures and state for CITS4419 Part B.

The assignment defines a teaching-oriented RPL DIO structure containing:
    Type   1 byte  (155)
    Code   1 byte  (1 for DIO)
    Rank   2 bytes
"""

from dataclasses import dataclass
import struct


ICMPV6_RPL_TYPE = 155
RPL_CODE_DIO = 1
RPL_DIO_LENGTH = 4

RPL_ROOT_RANK = 0

# The project states that non-root nodes begin at "infinity".
# Because the transmitted Rank field is two bytes, 0xFFFF is used as the
# simulator's explicit two-byte sentinel for an unknown/infinite rank.
RPL_INFINITY = 0xFFFF

_RPL_DIO = struct.Struct("!BBH")


@dataclass(frozen=True)
class RPLDIO:
    """Represent the simplified ICMPv6 RPL DIO message."""

    rank: int
    type: int = ICMPV6_RPL_TYPE
    code: int = RPL_CODE_DIO

    def to_bytes(self) -> bytes:
        """Serialize Type, Code and Rank into the required 4-byte layout."""
        if self.type != ICMPV6_RPL_TYPE:
            raise ValueError(
                f"RPL DIO Type must be {ICMPV6_RPL_TYPE}"
            )

        if self.code != RPL_CODE_DIO:
            raise ValueError(
                f"RPL DIO Code must be {RPL_CODE_DIO}"
            )

        if not 0 <= self.rank <= 0xFFFF:
            raise ValueError("RPL Rank must fit in two bytes")

        return _RPL_DIO.pack(
            self.type,
            self.code,
            self.rank,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "RPLDIO":
        """Parse the simplified ICMPv6 RPL DIO message."""
        if len(data) != RPL_DIO_LENGTH:
            raise ValueError(
                "RPL DIO must be exactly 4 bytes "
                "(Type=1, Code=1, Rank=2)"
            )

        message_type, code, rank = _RPL_DIO.unpack(data)

        if message_type != ICMPV6_RPL_TYPE:
            raise ValueError(
                f"Unexpected ICMPv6 RPL Type: {message_type}"
            )

        if code != RPL_CODE_DIO:
            raise ValueError(
                f"Unexpected RPL Code: {code}"
            )

        return cls(
            rank=rank,
            type=message_type,
            code=code,
        )
