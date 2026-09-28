"""Entry point for the CITS4419 IoT Protocol Stack Simulator."""

from iot_simulator import build_iot_network, converge_rpl, setup_network


def main() -> None:
    """Create the IoT network, initialize nodes, and form the RPL tree."""
    nodes = build_iot_network()
    setup_network(nodes)

    print()
    print("=" * 72)
    print("AUTOMATIC RPL TOPOLOGY FORMATION")
    print("=" * 72)

    converge_rpl(nodes)


if __name__ == "__main__":
    main()
