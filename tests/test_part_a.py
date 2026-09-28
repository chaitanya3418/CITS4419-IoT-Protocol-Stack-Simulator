"""Automated checks for CITS4419 Project Part A."""

import unittest

from iot_simulator import (
    BROADCAST_MAC,
    MAC_HEADER_LENGTH,
    FrameType,
    MACFrame,
    build_iot_network,
)


class TestPartATopology(unittest.TestCase):
    """Check the exact five-node topology and configured addresses."""

    def setUp(self) -> None:
        self.nodes = build_iot_network()

    def test_exact_node_addresses_and_neighbors(self) -> None:
        expected = {
            "A": ("00:00:00:01", "fd00::1", ["B", "C"]),
            "B": ("00:00:00:02", "fd00::2", ["A", "D"]),
            "C": ("00:00:00:03", "fd00::3", ["A", "E"]),
            "D": ("00:00:00:04", "fd00::4", ["B"]),
            "E": ("00:00:00:05", "fd00::5", ["C"]),
        }

        self.assertEqual(set(self.nodes), set(expected))

        for name, (mac, ipv6, neighbors) in expected.items():
            node = self.nodes[name]
            self.assertEqual(node.mac_address, mac)
            self.assertEqual(node.ipv6_address, ipv6)
            self.assertEqual(node.neighbors, neighbors)
            self.assertEqual(node.mac_sequence_number, 0)


class TestMACFrame(unittest.TestCase):
    """Check the simplified 12-byte MAC header and parser."""

    def test_mac_header_is_12_bytes(self) -> None:
        self.assertEqual(MAC_HEADER_LENGTH, 12)

    def test_binary_round_trip(self) -> None:
        frame = MACFrame(
            source_mac="00:00:00:01",
            destination_mac="00:00:00:02",
            sequence_number=7,
            frame_type=FrameType.DATA,
            payload=b"sensor-data",
        )

        encoded = frame.to_bytes()

        self.assertEqual(
            len(encoded),
            MAC_HEADER_LENGTH + len(b"sensor-data"),
        )
        self.assertEqual(MACFrame.from_bytes(encoded), frame)

    def test_invalid_payload_length_is_rejected(self) -> None:
        encoded = MACFrame(
            source_mac="00:00:00:01",
            destination_mac="00:00:00:02",
            sequence_number=0,
            frame_type=FrameType.DATA,
            payload=b"abc",
        ).to_bytes()

        with self.assertRaises(ValueError):
            MACFrame.from_bytes(encoded[:-1])


class TestMACBehaviour(unittest.TestCase):
    """Check unicast DATA/ACK and broadcast CONTROL behaviour."""

    def setUp(self) -> None:
        self.nodes = build_iot_network()

    def test_unicast_data_generates_matching_ack(self) -> None:
        node_a = self.nodes["A"]
        node_b = self.nodes["B"]

        sequence = node_a.send_mac(
            payload=b"hello",
            destination_mac=node_b.mac_address,
            frame_type=FrameType.DATA,
        )

        self.assertEqual(sequence, 0)
        self.assertEqual(node_a.mac_sequence_number, 1)
        self.assertEqual(node_b.received_mac_payloads, [b"hello"])
        self.assertEqual(node_a.last_ack_sequence, 0)

    def test_sequence_number_advances_for_new_frames(self) -> None:
        node_a = self.nodes["A"]
        node_b = self.nodes["B"]

        first = node_a.send_mac(
            b"one",
            node_b.mac_address,
            FrameType.DATA,
        )
        second = node_a.send_mac(
            b"two",
            node_b.mac_address,
            FrameType.DATA,
        )

        self.assertEqual((first, second), (0, 1))
        self.assertEqual(node_a.mac_sequence_number, 2)
        self.assertEqual(node_a.last_ack_sequence, 1)

    def test_non_neighbor_unicast_is_rejected(self) -> None:
        node_a = self.nodes["A"]
        node_d = self.nodes["D"]

        with self.assertRaises(ValueError):
            node_a.send_mac(
                b"not-one-hop",
                node_d.mac_address,
                FrameType.DATA,
            )

    def test_broadcast_control_reaches_only_one_hop_neighbors(self) -> None:
        node_a = self.nodes["A"]
        payload = b"RPL-DIO-placeholder"

        sequence = node_a.send_mac(
            payload=payload,
            destination_mac=BROADCAST_MAC,
            frame_type=FrameType.CONTROL,
        )

        self.assertEqual(sequence, 0)
        self.assertEqual(self.nodes["B"].received_control_payloads, [payload])
        self.assertEqual(self.nodes["C"].received_control_payloads, [payload])
        self.assertEqual(self.nodes["D"].received_control_payloads, [])
        self.assertEqual(self.nodes["E"].received_control_payloads, [])

    def test_broadcast_control_generates_no_ack(self) -> None:
        node_a = self.nodes["A"]

        node_a.send_mac(
            payload=b"control",
            destination_mac=BROADCAST_MAC,
            frame_type=FrameType.CONTROL,
        )

        self.assertIsNone(node_a.last_ack_sequence)
        self.assertIsNone(self.nodes["B"].last_ack_sequence)
        self.assertIsNone(self.nodes["C"].last_ack_sequence)


if __name__ == "__main__":
    unittest.main()
