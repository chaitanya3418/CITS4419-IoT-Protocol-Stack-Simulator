"""Entry point for the CITS4419 IoT Protocol Stack Simulator."""

from iot_simulator import (
    NEXT_HEADER_ESP,
    NEXT_HEADER_UDP,
    build_iot_network,
    converge_rpl,
    setup_network,
)

from iot_simulator.esp import serialize_esp
from iot_simulator.udp import serialize_udp

from iot_simulator.server import CoAPServer


def select_part() -> str:
    """Ask the user which project part to demonstrate."""

    while True:
        choice = input(
            "Select part to run (C/D): "
        ).strip().upper()

        if choice in ("C", "D"):
            return choice

        print("Please enter C or D.")


def select_source(nodes):
    """Ask the user to select source IoT node A-E."""

    while True:
        choice = input(
            "Select source node (A/B/C/D/E): "
        ).strip().upper()

        if choice in nodes:
            return nodes[choice]

        print("Please enter A, B, C, D, or E.")


def run_part_c(source, server) -> None:
    """Run plaintext CoAP over UDP."""

    print()
    print("=" * 72)
    print("PART C: UDP + CoAP SENSOR COMMUNICATION")
    print("=" * 72)

    coap_request = source.send_coap(24)

    udp_request = source.send_udp(
        coap_request
    )

    udp_bytes = serialize_udp(
        udp_request
    )

    source.send_ipv6(
        payload=udp_bytes,
        destination_ipv6=server.ipv6_address,
        next_header=NEXT_HEADER_UDP,
    )


def run_part_d(source, server) -> None:
    """Run CoAP protected by DTLS and IPsec ESP."""

    print()
    print("=" * 72)
    print("PART D: DTLS + IPsec ESP")
    print("=" * 72)

    # Protect the CoAP message with DTLS.
    coap_request = source.send_coap(24)

    dtls_request = source.send_dtls(
        coap_request
    )

    # Encapsulate the DTLS record in UDP.
    udp_request = source.send_udp(
        dtls_request
    )

    # Protect the complete UDP datagram with ESP.
    esp_request = source.send_ipsec(
        udp_request
    )

    # Serialize the ESP packet before placing it in IPv6.
    esp_bytes = serialize_esp(
        esp_request
    )

    # Next Header 50 tells IPv6 that its payload is ESP.
    source.send_ipv6(
        payload=esp_bytes,
        destination_ipv6=server.ipv6_address,
        next_header=NEXT_HEADER_ESP,
    )


def main() -> None:
    """Initialize the network and run the selected demonstration."""

    # Create the five IoT nodes and their fixed neighbour relationships.
    nodes = build_iot_network()

    # Display the configured addresses and initial routing state.
    setup_network(nodes)

    print()
    print("=" * 72)
    print("AUTOMATIC RPL TOPOLOGY FORMATION")
    print("=" * 72)

    # Form the RPL routing tree before application traffic begins.
    converge_rpl(nodes)

    # Attach the CoAP server to Node A's wired side.
    server = CoAPServer()

    nodes["A"].network.attach_server(
        server
    )

    print()
    print("=" * 72)
    print("APPLICATION TRAFFIC")
    print("=" * 72)

    part = select_part()
    source = select_source(nodes)

    print()
    print(
        f"Selected source: Node {source.name} "
        f"({source.ipv6_address})"
    )

    if part == "C":
        run_part_c(
            source,
            server,
        )
    else:
        run_part_d(
            source,
            server,
        )


if __name__ == "__main__":
    main()