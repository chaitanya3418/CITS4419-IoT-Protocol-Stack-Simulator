"""Entry point for the CITS4419 IoT Protocol Stack Simulator."""

from iot_simulator import build_iot_network, setup_network
from iot_simulator.part_cd import Node as CDNode, CoAPServer


def select_part() -> str:
    """
    Ask the user whether to run Part C or Part D.
    Part C processes CoAP over UDP.
    Part D processes secure CoAP using DTLS and IPsec ESP.
    """
    while True:
        part = input("Select part to run (C/D): ").strip().upper()

        if part in {"C", "D"}:
            return part

        print("Invalid selection. Please enter C or D.")


def select_source(nodes):
    """Ask the user to select the source IoT node."""
    while True:
        source_name = input(
            "Select source node (A/B/C/D/E): "
        ).strip().upper()

        if source_name in nodes:
            return nodes[source_name]

        print("Invalid selection. Please enter A, B, C, D, or E.")


def run_part_c(source: CDNode, server: CoAPServer) -> None:
    """Run plaintext CoAP over UDP."""
    print()
    print("========== PART C: UDP + CoAP ==========")

    # Source: CoAP -> UDP
    coap_request = source.send_coap(24)
    udp_request = source.send_udp(coap_request)

    # Temporary direct handoff to the server.
    # IPv6/RPL/MAC will be inserted here after Parts A/B are available.
    coap_response = server.receive_udp(
        udp_request,
        secure=False
    )

    # Server: CoAP ACK -> UDP
    udp_response = server.send_udp(coap_response)

    # Temporary direct handoff back to the selected source node.
    source.receive_udp(udp_response)


def run_part_d(source: CDNode, server: CoAPServer) -> None:
    """Run secure CoAP using DTLS and IPsec ESP."""
    print()
    print("========== PART D: DTLS + IPsec ESP ==========")

    # Source: CoAP -> DTLS -> UDP -> ESP
    coap_request = source.send_coap(24)
    dtls_request = source.send_dtls(coap_request)
    udp_request = source.send_udp(dtls_request)
    esp_request = source.send_ipsec(udp_request)

    # Temporary direct handoff to the server.
    # IPv6/RPL/MAC will later carry the ESP packet.
    coap_response = server.receive_ipsec(esp_request)

    # Server: CoAP ACK -> DTLS -> UDP -> ESP
    dtls_response = server.send_dtls(coap_response)
    udp_response = server.send_udp(dtls_response)
    esp_response = server.send_ipsec(udp_response)

    # Temporary source-side decapsulation.
    recovered_udp = source.receive_ipsec(esp_response)
    recovered_dtls = recovered_udp["payload"]
    recovered_coap = source.receive_dtls(recovered_dtls)
    source.receive_coap(recovered_coap)


def main() -> None:
    """Initialize the network and execute the selected simulation part."""

    # Part A node/topology setup.
    nodes = build_iot_network()
    setup_network(nodes)

    part = select_part()
    selected_node = select_source(nodes)

    print()
    print(
        f"Selected source: Node {selected_node.name} "
        f"({selected_node.ipv6_address})"
    )

    # Temporary C/D protocol node.
    # The selected node's name and IPv6 address are reused from the Part A topology.
    # MAC/IPv6/RPL forwarding will be integrated once the lower-layer implementation is available.
    source = CDNode(
        selected_node.name,
        selected_node.ipv6_address
    )

    server = CoAPServer()

    if part == "C":
        run_part_c(source, server)
    else:
        run_part_d(source, server)


if __name__ == "__main__":
    main()