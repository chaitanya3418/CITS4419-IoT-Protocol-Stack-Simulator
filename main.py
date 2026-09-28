"""Entry point for the CITS4419 IoT Protocol Stack Simulator."""

from iot_simulator import build_iot_network, setup_network


def main() -> None:
    """Create and initialize the five-node IoT network."""
    nodes = build_iot_network()
    setup_network(nodes)


if __name__ == "__main__":
    main()
