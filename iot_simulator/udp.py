

import struct
from .coap import  deserialize_coap, serialize_coap
from .dtls import deserialize_dtls, serialize_dtls


def serialize_udp(udp_datagram):
    payload = udp_datagram["payload"]

    # Part C: plaintext CoAP
    # Part D: DTLS record
    payload_bytes = serialize_udp_payload(payload)

    udp_length = 8 + len(payload_bytes)

    header = struct.pack(
        "!HHHH",
        udp_datagram["source_port"],
        udp_datagram["destination_port"],
        udp_length,
        udp_datagram["checksum"]
    )

    return header + payload_bytes

def deserialize_udp(data, secure=False):
    if len(data) < 8:
        raise ValueError("UDP datagram is too short")

    source_port, destination_port, length, checksum = struct.unpack(
        "!HHHH",
        data[:8]
    )

    if length < 8 or length > len(data):
        raise ValueError("Invalid UDP length")

    payload_bytes = data[8:length]

    if secure:
        # Part D: UDP payload contains a DTLS record
        payload = deserialize_dtls(payload_bytes)
    else:
        # Part C: UDP payload contains plaintext CoAP
        payload = deserialize_coap(payload_bytes)

    return {
        "source_port": source_port,
        "destination_port": destination_port,
        "length": length,
        "checksum": checksum,
        "payload": payload
    }


def serialize_udp_payload(payload):
            # DTLS record
            if (
                isinstance(payload, dict)
                and "protected_data" in payload
                and "epoch" in payload
                and "sequence_number" in payload
            ):
                return serialize_dtls(payload)

            # Plain CoAP message used in Part C
            return serialize_coap(payload)
