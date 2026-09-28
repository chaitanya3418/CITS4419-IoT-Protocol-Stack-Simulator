"""Repeatable demonstration of CITS4419 Project Part B."""

from iot_simulator import (
    IPV6_HEADER_LENGTH,
    NEXT_HEADER_ICMPV6,
    RPL_DIO_LENGTH,
    RPL_INFINITY,
    RPLDIO,
    IPv6Packet,
    build_iot_network,
    converge_rpl,
    setup_network,
)
from iot_simulator.rpl import RPL_MULTICAST_IPV6


def divider(title: str) -> None:
    """Print a clear section heading for the Week 12 demonstration."""
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def rank_text(rank: int) -> str:
    """Return a readable form of the simulator's RPL rank."""
    return "infinity" if rank == RPL_INFINITY else str(rank)


def print_rpl_state(nodes) -> None:
    """Print rank and parent state for every IoT node."""
    for name in ("A", "B", "C", "D", "E"):
        node = nodes[name]
        parent = node.parent if node.parent is not None else "None"
        print(
            f"Node {name}: Rank={rank_text(node.rank)}, "
            f"Parent={parent}"
        )


def run_demo() -> None:
    """Demonstrate IPv6, RPL DIO encoding, and automatic convergence."""
    nodes = build_iot_network()

    divider("PART B - INITIAL NODE STATE")
    setup_network(nodes)

    divider("PART B - SIMPLIFIED IPV6 AND RPL DIO FORMATS")
    root_dio = RPLDIO(rank=nodes["A"].rank)

    root_ipv6 = IPv6Packet(
        source_ipv6=nodes["A"].ipv6_address,
        destination_ipv6=RPL_MULTICAST_IPV6,
        next_header=NEXT_HEADER_ICMPV6,
        payload=root_dio.to_bytes(),
    )

    print(
        f"[Demo] RPL DIO size={RPL_DIO_LENGTH} bytes, "
        f"Type={root_dio.type}, Code={root_dio.code}, "
        f"Rank={root_dio.rank}"
    )
    print(
        f"[Demo] IPv6 fixed header={IPV6_HEADER_LENGTH} bytes, "
        f"Next Header={root_ipv6.next_header}, "
        f"Destination={root_ipv6.destination_ipv6}"
    )

    divider("PART B - RPL STATE BEFORE CONVERGENCE")
    print_rpl_state(nodes)

    divider("PART B - AUTOMATIC RPL TOPOLOGY FORMATION")
    converge_rpl(nodes)

    divider("PART B - FINAL RPL STATE")
    print_rpl_state(nodes)

    divider("PART B - FINAL RPL TREE")
    print("        A (Rank 0)")
    print("       /          \\")
    print(" B (Rank 1)    C (Rank 1)")
    print("    |              |")
    print(" D (Rank 2)    E (Rank 2)")

    expected = {
        "A": (0, None),
        "B": (1, "A"),
        "C": (1, "A"),
        "D": (2, "B"),
        "E": (2, "C"),
    }

    actual = {
        name: (node.rank, node.parent)
        for name, node in nodes.items()
    }

    divider("PART B - DEMONSTRATION COMPLETE")
    print(f"[Demo] Required RPL tree reached: {actual == expected}")


if __name__ == "__main__":
    run_demo()
