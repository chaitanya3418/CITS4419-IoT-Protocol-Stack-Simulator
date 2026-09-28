"""Integration tests for CITS4419 Project Part C."""

import io
import unittest

from contextlib import redirect_stdout
from unittest.mock import patch
from iot_simulator.coap import (
    serialize_coap,
    deserialize_coap,
)

from iot_simulator import (
    NEXT_HEADER_UDP,
    build_iot_network,
    converge_rpl,
)

from iot_simulator.server import CoAPServer
from iot_simulator.udp import serialize_udp

class TestCoAPSerialization(unittest.TestCase):
    """Check the Part C binary CoAP representation."""

    def test_coap_request_binary_round_trip(self) -> None:
        message = {
            "version": 1,
            "type": "CON",
            "token_length": 2,
            "code": "POST",
            "message_id": 1001,
            "token": b"\x01\x02",
            "options": {
                "Uri-Path": "temperature"
            },
            "payload": "Temperature=24°C",
        }

        encoded = serialize_coap(message)
        decoded = deserialize_coap(encoded)

        self.assertEqual(decoded, message)

        # Version=1, CON=0, TKL=2.
        self.assertEqual(encoded[0], 0x42)

        # POST = 0.02.
        self.assertEqual(encoded[1], 0x02)

        # Message ID = 1001 = 0x03E9.
        self.assertEqual(encoded[2:4], b"\x03\xe9")

        # Token immediately follows the fixed header.
        self.assertEqual(encoded[4:6], b"\x01\x02")

    def test_coap_ack_binary_round_trip(self) -> None:
        message = {
            "version": 1,
            "type": "ACK",
            "token_length": 2,
            "code": "2.04 Changed",
            "message_id": 1001,
            "token": b"\x01\x02",
            "options": {},
            "payload": "Temperature updated",
        }

        encoded = serialize_coap(message)
        decoded = deserialize_coap(encoded)

        self.assertEqual(decoded, message)

        # Version=1, ACK=2, TKL=2.
        self.assertEqual(encoded[0], 0x62)

        # 2.04 Changed.
        self.assertEqual(encoded[1], 0x44)

class TestPartCIntegration(unittest.TestCase):
    """Check the Part C CoAP/UDP/IPv6/RPL/MAC integration."""

    def setUp(self) -> None:
        self.nodes = build_iot_network()

        # Suppress the long RPL convergence log during automated tests.
        with redirect_stdout(io.StringIO()):
            converge_rpl(self.nodes)

        self.server = CoAPServer()
        self.nodes["A"].network.attach_server(self.server)

    def test_coap_request_reaches_server(self) -> None:
        """Node D should deliver a CoAP POST to the fixed server."""

        source = self.nodes["D"]

        with patch.object(
            self.server,
            "receive_coap",
            wraps=self.server.receive_coap,
        ) as receive_coap_mock:

            with redirect_stdout(io.StringIO()):
                coap_request = source.send_coap(24)
                udp_request = source.send_udp(coap_request)
                udp_bytes = serialize_udp(udp_request)

                source.send_ipv6(
                    payload=udp_bytes,
                    destination_ipv6=self.server.ipv6_address,
                    next_header=NEXT_HEADER_UDP,
                )

        receive_coap_mock.assert_called_once()

        received_request = receive_coap_mock.call_args.args[0]

        self.assertEqual(received_request["type"], "CON")
        self.assertEqual(received_request["code"], "POST")
        self.assertEqual(
            received_request["options"]["Uri-Path"],
            "temperature",
        )
        self.assertEqual(
            received_request["payload"],
            "Temperature=24°C",
        )
        self.assertEqual(received_request["message_id"], 1001)
        self.assertEqual(received_request["token"], b"\x01\x02")

    def test_coap_response_returns_to_source(self) -> None:
        """Server ACK should return through A and B to Node D."""

        source = self.nodes["D"]

        with patch.object(
            source,
            "receive_coap",
            wraps=source.receive_coap,
        ) as receive_coap_mock:

            with redirect_stdout(io.StringIO()):
                coap_request = source.send_coap(24)
                udp_request = source.send_udp(coap_request)
                udp_bytes = serialize_udp(udp_request)

                source.send_ipv6(
                    payload=udp_bytes,
                    destination_ipv6=self.server.ipv6_address,
                    next_header=NEXT_HEADER_UDP,
                )

        receive_coap_mock.assert_called_once()

        response = receive_coap_mock.call_args.args[0]

        self.assertEqual(response["type"], "ACK")
        self.assertEqual(response["code"], "2.04 Changed")
        self.assertEqual(response["message_id"], 1001)
        self.assertEqual(response["token"], b"\x01\x02")
        self.assertEqual(
            response["payload"],
            "Temperature updated",
        )

    def test_node_a_can_send_part_c_to_server(self):
        source = self.nodes["A"]

        with patch.object(
            self.server,
            "receive_coap",
            wraps=self.server.receive_coap,
        ) as receive_coap_mock:

            coap_request = source.send_coap(24)
            udp_request = source.send_udp(coap_request)
            udp_bytes = serialize_udp(udp_request)

            source.send_ipv6(
                payload=udp_bytes,
                destination_ipv6=self.server.ipv6_address,
                next_header=NEXT_HEADER_UDP,
            )

        receive_coap_mock.assert_called_once()
    


if __name__ == "__main__":
    unittest.main()