import io
import unittest

from contextlib import redirect_stdout
from unittest.mock import patch

from iot_simulator import (
    NEXT_HEADER_ESP,
    build_iot_network,
    converge_rpl,
)

from iot_simulator.esp import (
    deserialize_esp,
    serialize_esp,
)

from iot_simulator.udp import (
    deserialize_udp,
    serialize_udp,
)

from iot_simulator.server import CoAPServer


class TestDTLS(unittest.TestCase):
    """Unit tests for DTLS, UDP, and ESP processing."""

    def setUp(self):
        self.nodes = build_iot_network()
        self.node = self.nodes["D"]

    def test_dtls_round_trip(self):
        coap_message = self.node.send_coap(24)

        dtls_record = self.node.send_dtls(
            coap_message
        )

        recovered = self.node.receive_dtls(
            dtls_record
        )

        self.assertEqual(
            recovered,
            coap_message,
        )

    def test_dtls_sequence_number_advances(self):
        coap_message = self.node.send_coap(24)

        first = self.node.send_dtls(
            coap_message
        )

        second = self.node.send_dtls(
            coap_message
        )

        self.assertEqual(
            first["sequence_number"],
            0,
        )

        self.assertEqual(
            second["sequence_number"],
            1,
        )

    def test_dtls_inside_udp_round_trip(self):
        coap_message = self.node.send_coap(24)

        dtls_record = self.node.send_dtls(
            coap_message
        )

        udp_datagram = self.node.send_udp(
            dtls_record
        )

        udp_bytes = serialize_udp(
            udp_datagram
        )

        recovered_udp = deserialize_udp(
            udp_bytes,
            secure=True,
        )

        recovered_coap = self.node.receive_dtls(
            recovered_udp["payload"]
        )

        self.assertEqual(
            recovered_coap,
            coap_message,
        )

    def test_esp_round_trip(self):
        coap_message = self.node.send_coap(24)

        dtls_record = self.node.send_dtls(
            coap_message
        )

        udp_datagram = self.node.send_udp(
            dtls_record
        )

        esp_packet = self.node.send_ipsec(
            udp_datagram
        )

        recovered_udp = self.node.receive_ipsec(
            esp_packet
        )

        self.assertIsNotNone(
            recovered_udp
        )

        self.assertEqual(
            recovered_udp["source_port"],
            50000,
        )

        self.assertEqual(
            recovered_udp["destination_port"],
            5683,
        )

        recovered_coap = self.node.receive_dtls(
            recovered_udp["payload"]
        )

        self.assertEqual(
            recovered_coap,
            coap_message,
        )

    def test_esp_sequence_number_advances(self):
        coap_message = self.node.send_coap(24)

        dtls_record = self.node.send_dtls(
            coap_message
        )

        udp_datagram = self.node.send_udp(
            dtls_record
        )

        first = self.node.send_ipsec(
            udp_datagram
        )

        second = self.node.send_ipsec(
            udp_datagram
        )

        self.assertEqual(
            first["sequence_number"],
            1,
        )

        self.assertEqual(
            second["sequence_number"],
            2,
        )

    def test_esp_replay_is_rejected(self):
        coap_message = self.node.send_coap(24)

        dtls_record = self.node.send_dtls(
            coap_message
        )

        udp_datagram = self.node.send_udp(
            dtls_record
        )

        esp_packet = self.node.send_ipsec(
            udp_datagram
        )

        first_result = self.node.receive_ipsec(
            esp_packet
        )

        second_result = self.node.receive_ipsec(
            esp_packet
        )

        self.assertIsNotNone(
            first_result
        )

        self.assertIsNone(
            second_result
        )

    def test_esp_binary_round_trip(self):
        coap_message = self.node.send_coap(24)

        dtls_record = self.node.send_dtls(
            coap_message
        )

        udp_datagram = self.node.send_udp(
            dtls_record
        )

        esp_packet = self.node.send_ipsec(
            udp_datagram
        )

        esp_bytes = serialize_esp(
            esp_packet
        )

        recovered = deserialize_esp(
            esp_bytes
        )

        self.assertEqual(
            recovered,
            esp_packet,
        )

        self.assertEqual(
            len(recovered["iv"]),
            16,
        )

        self.assertEqual(
            len(
                recovered[
                    "authentication_data"
                ]
            ),
            32,
        )

        self.assertEqual(
            recovered["next_header"],
            17,
        )


class TestPartDNetworkIntegration(unittest.TestCase):
    """Integration tests for secure Part D communication."""

    def setUp(self):
        self.nodes = build_iot_network()

        # RPL convergence produces a lot of log output.
        with redirect_stdout(io.StringIO()):
            converge_rpl(
                self.nodes
            )

        self.server = CoAPServer()

        self.nodes["A"].network.attach_server(
            self.server
        )

    def test_secure_request_reaches_server(self):
        source = self.nodes["D"]

        with patch.object(
            self.server,
            "receive_coap",
            wraps=self.server.receive_coap,
        ) as receive_coap_mock:

            with redirect_stdout(
                io.StringIO()
            ):
                coap_request = source.send_coap(
                    24
                )

                dtls_request = source.send_dtls(
                    coap_request
                )

                udp_request = source.send_udp(
                    dtls_request
                )

                esp_request = source.send_ipsec(
                    udp_request
                )

                esp_bytes = serialize_esp(
                    esp_request
                )

                source.send_ipv6(
                    payload=esp_bytes,
                    destination_ipv6=(
                        self.server.ipv6_address
                    ),
                    next_header=NEXT_HEADER_ESP,
                )

        receive_coap_mock.assert_called_once()

        received = (
            receive_coap_mock
            .call_args
            .args[0]
        )

        self.assertEqual(
            received["type"],
            "CON",
        )

        self.assertEqual(
            received["code"],
            "POST",
        )

        self.assertEqual(
            received["options"]["Uri-Path"],
            "temperature",
        )

        self.assertEqual(
            received["payload"],
            "Temperature=24°C",
        )

    def test_secure_response_returns_to_source(self):
        source = self.nodes["D"]

        with patch.object(
            source,
            "receive_coap",
            wraps=source.receive_coap,
        ) as receive_coap_mock:

            with redirect_stdout(
                io.StringIO()
            ):
                coap_request = source.send_coap(
                    24
                )

                dtls_request = source.send_dtls(
                    coap_request
                )

                udp_request = source.send_udp(
                    dtls_request
                )

                esp_request = source.send_ipsec(
                    udp_request
                )

                esp_bytes = serialize_esp(
                    esp_request
                )

                source.send_ipv6(
                    payload=esp_bytes,
                    destination_ipv6=(
                        self.server.ipv6_address
                    ),
                    next_header=NEXT_HEADER_ESP,
                )

        receive_coap_mock.assert_called_once()

        response = (
            receive_coap_mock
            .call_args
            .args[0]
        )

        self.assertEqual(
            response["type"],
            "ACK",
        )

        self.assertEqual(
            response["code"],
            "2.04 Changed",
        )

        self.assertEqual(
            response["message_id"],
            1001,
        )

        self.assertEqual(
            response["token"],
            b"\x01\x02",
        )

        self.assertEqual(
            response["payload"],
            "Temperature updated",
        )
    def test_all_source_nodes_can_complete_secure_round_trip(self):
        """Every selectable source A-E should complete a secure Part D exchange."""

        for source_name in ("A", "B", "C", "D", "E"):
            with self.subTest(source=source_name):
                # A fresh server is important here because ESP sequence numbers
                # start at 1 for each node and the server performs replay checks.
                nodes = build_iot_network()
                with redirect_stdout(io.StringIO()):
                    converge_rpl(nodes)

                server = CoAPServer()
                nodes["A"].network.attach_server(server)
                source = nodes[source_name]

                # Monitor both endpoints to verify that the secure request
                # and ACK complete the round trip.
                with patch.object(
                    server,
                    "receive_coap",
                    wraps=server.receive_coap,
                ) as server_receive_mock, patch.object(
                    source,
                    "receive_coap",
                    wraps=source.receive_coap,
                ) as source_receive_mock:

                    with redirect_stdout(io.StringIO()):
                        coap_request = source.send_coap(24)
                        dtls_request = source.send_dtls(coap_request)
                        udp_request = source.send_udp(dtls_request)
                        esp_request = source.send_ipsec(udp_request)
                        esp_bytes = serialize_esp(esp_request)

                        source.send_ipv6(
                            payload=esp_bytes,
                            destination_ipv6=server.ipv6_address,
                            next_header=NEXT_HEADER_ESP,
                        )

                server_receive_mock.assert_called_once()
                source_receive_mock.assert_called_once()

                request = server_receive_mock.call_args.args[0]
                response = source_receive_mock.call_args.args[0]

                self.assertEqual(request["type"], "CON")
                self.assertEqual(request["code"], "POST")
                self.assertEqual(request["options"]["Uri-Path"], "temperature")
                self.assertEqual(request["payload"], "Temperature=24°C")

                self.assertEqual(response["type"], "ACK")
                self.assertEqual(response["code"], "2.04 Changed")
                self.assertEqual(response["message_id"], 1001)
                self.assertEqual(response["token"], b"\x01\x02")
                self.assertEqual(response["payload"], "Temperature updated")



if __name__ == "__main__":
    unittest.main()