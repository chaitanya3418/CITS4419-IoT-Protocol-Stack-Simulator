"""Automated checks for CITS4419 Project Part B."""

import unittest

from iot_simulator import (
    IPV6_HEADER_LENGTH,
    NEXT_HEADER_ICMPV6,
    RPL_DIO_LENGTH,
    RPL_INFINITY,
    RPL_ROOT_RANK,
    IPv6Packet,
    RPLDIO,
    build_iot_network,
    converge_rpl,
)
from iot_simulator.rpl import RPL_MULTICAST_IPV6


class TestIPv6Packet(unittest.TestCase):
    """Check the simplified 35-byte IPv6 header."""

    def test_ipv6_header_is_35_bytes(self) -> None:
        self.assertEqual(IPV6_HEADER_LENGTH, 35)

    def test_ipv6_binary_round_trip(self) -> None:
        dio = RPLDIO(rank=0)

        packet = IPv6Packet(
            source_ipv6="fd00::1",
            destination_ipv6=RPL_MULTICAST_IPV6,
            next_header=NEXT_HEADER_ICMPV6,
            payload=dio.to_bytes(),
        )

        encoded = packet.to_bytes()
        decoded = IPv6Packet.from_bytes(encoded)

        self.assertEqual(
            len(encoded),
            IPV6_HEADER_LENGTH + RPL_DIO_LENGTH,
        )
        self.assertEqual(decoded, packet)

    def test_ipv6_payload_length_mismatch_is_rejected(self) -> None:
        packet = IPv6Packet(
            source_ipv6="fd00::1",
            destination_ipv6="fd00::2",
            next_header=NEXT_HEADER_ICMPV6,
            payload=b"abcd",
        )

        encoded = packet.to_bytes()

        with self.assertRaises(ValueError):
            IPv6Packet.from_bytes(encoded[:-1])


class TestRPLDIO(unittest.TestCase):
    """Check the simplified 4-byte ICMPv6 RPL DIO."""

    def test_rpl_dio_is_4_bytes(self) -> None:
        encoded = RPLDIO(rank=2).to_bytes()

        self.assertEqual(len(encoded), RPL_DIO_LENGTH)
        self.assertEqual(RPL_DIO_LENGTH, 4)

    def test_rpl_dio_round_trip(self) -> None:
        dio = RPLDIO(rank=2)

        self.assertEqual(RPLDIO.from_bytes(dio.to_bytes()), dio)

    def test_invalid_rpl_type_is_rejected(self) -> None:
        invalid = bytes([154, 1, 0, 0])

        with self.assertRaises(ValueError):
            RPLDIO.from_bytes(invalid)

    def test_invalid_rpl_code_is_rejected(self) -> None:
        invalid = bytes([155, 2, 0, 0])

        with self.assertRaises(ValueError):
            RPLDIO.from_bytes(invalid)


class TestRPLStateAndConvergence(unittest.TestCase):
    """Check initial RPL state, DIO encapsulation and final tree."""

    def setUp(self) -> None:
        self.nodes = build_iot_network()

    def test_initial_rpl_state(self) -> None:
        self.assertEqual(self.nodes["A"].rank, RPL_ROOT_RANK)
        self.assertIsNone(self.nodes["A"].parent)

        for name in ("B", "C", "D", "E"):
            self.assertEqual(self.nodes[name].rank, RPL_INFINITY)
            self.assertIsNone(self.nodes[name].parent)

    def test_root_dio_is_ipv6_inside_mac_control(self) -> None:
        converge_rpl(self.nodes)

        first_control_at_b = self.nodes["B"].received_control_payloads[0]
        ipv6_packet = IPv6Packet.from_bytes(first_control_at_b)
        dio = RPLDIO.from_bytes(ipv6_packet.payload)

        self.assertEqual(ipv6_packet.source_ipv6, "fd00::1")
        self.assertEqual(
            ipv6_packet.destination_ipv6,
            RPL_MULTICAST_IPV6,
        )
        self.assertEqual(
            ipv6_packet.next_header,
            NEXT_HEADER_ICMPV6,
        )
        self.assertEqual(dio.rank, 0)

    def test_automatic_rpl_convergence_matches_required_tree(self) -> None:
        converge_rpl(self.nodes)

        expected = {
            "A": (0, None),
            "B": (1, "A"),
            "C": (1, "A"),
            "D": (2, "B"),
            "E": (2, "C"),
        }

        actual = {
            name: (node.rank, node.parent)
            for name, node in self.nodes.items()
        }

        self.assertEqual(actual, expected)

    def test_equal_or_worse_route_is_ignored(self) -> None:
        converge_rpl(self.nodes)

        node_b = self.nodes["B"]
        original_state = (node_b.rank, node_b.parent)

        changed = node_b.receive_rpl_dio(
            dio_bytes=RPLDIO(rank=1).to_bytes(),
            source_ipv6=self.nodes["C"].ipv6_address,
        )

        self.assertFalse(changed)
        self.assertEqual((node_b.rank, node_b.parent), original_state)

    def test_rpl_broadcasts_do_not_generate_mac_acks(self) -> None:
        converge_rpl(self.nodes)

        for node in self.nodes.values():
            self.assertIsNone(node.last_ack_sequence)


if __name__ == "__main__":
    unittest.main()
