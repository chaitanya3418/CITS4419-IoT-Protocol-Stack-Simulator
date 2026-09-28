"""Repeatable demonstration of CITS4419 Project Part A."""

from iot_simulator import (
    BROADCAST_MAC,
    FrameType,
    build_iot_network,
    setup_network,
)


def divider(title: str) -> None:
    """Print a clear section heading for the Week 12 demonstration."""
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def run_demo() -> None:
    """Demonstrate initialization, unicast DATA/ACK, and broadcast CONTROL."""
    nodes = build_iot_network()

    divider("PART A - NETWORK INITIALIZATION")
    setup_network(nodes)

    divider("PART A - UNICAST DATA: NODE A -> NODE B")
    data_sequence = nodes["A"].send_mac(
        payload=b"Part A unicast payload",
        destination_mac=nodes["B"].mac_address,
        frame_type=FrameType.DATA,
    )

    print(
        f"[Demo] DATA sequence={data_sequence}; "
        f"ACK received by A={nodes['A'].last_ack_sequence}"
    )

    divider("PART A - BROADCAST CONTROL: NODE A -> {B, C}")
    control_sequence = nodes["A"].send_mac(
        payload=b"RPL-DIO placeholder for Part B",
        destination_mac=BROADCAST_MAC,
        frame_type=FrameType.CONTROL,
    )

    print(f"[Demo] CONTROL sequence={control_sequence}")
    print(
        "[Demo] CONTROL deliveries: "
        f"B={len(nodes['B'].received_control_payloads)}, "
        f"C={len(nodes['C'].received_control_payloads)}, "
        f"D={len(nodes['D'].received_control_payloads)}, "
        f"E={len(nodes['E'].received_control_payloads)}"
    )
    print(
        "[Demo] Broadcast ACK check: "
        f"A last ACK remains {nodes['A'].last_ack_sequence}"
    )

    divider("PART A - DEMONSTRATION COMPLETE")
    print(
        "[Demo] Part A shows node setup, the simplified MAC frame, "
        "one-hop unicast DATA/ACK, and one-hop CONTROL broadcast."
    )


if __name__ == "__main__":
    run_demo()
