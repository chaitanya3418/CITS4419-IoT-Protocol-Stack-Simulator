"""Simplified IPsec ESP serialization helpers."""

ESP_FIXED_PREFIX_LENGTH = 4 + 4 + 16
ESP_FIXED_SUFFIX_LENGTH = 1 + 32
ESP_MIN_LENGTH = (
    ESP_FIXED_PREFIX_LENGTH
    + ESP_FIXED_SUFFIX_LENGTH
)


def serialize_esp(esp_packet):
    """Serialize a simplified ESP packet to bytes."""

    spi = esp_packet["spi"]
    sequence_number = esp_packet["sequence_number"]
    iv = esp_packet["iv"]
    encrypted_payload = esp_packet["encrypted_payload"]
    next_header = esp_packet["next_header"]
    authentication_data = esp_packet["authentication_data"]

    if len(iv) != 16:
        raise ValueError("ESP IV must be 16 bytes")

    if len(authentication_data) != 32:
        raise ValueError(
            "ESP HMAC-SHA256 must be 32 bytes"
        )

    return (
        spi.to_bytes(4, "big")
        + sequence_number.to_bytes(4, "big")
        + iv
        + encrypted_payload
        + next_header.to_bytes(1, "big")
        + authentication_data
    )


def deserialize_esp(data):
    """Parse bytes into a simplified ESP packet."""

    if len(data) < ESP_MIN_LENGTH:
        raise ValueError("ESP packet is too short")

    spi = int.from_bytes(
        data[0:4],
        "big",
    )

    sequence_number = int.from_bytes(
        data[4:8],
        "big",
    )

    iv = data[8:24]

    # Last 33 bytes:
    # 1-byte ESP Next Header + 32-byte HMAC.
    encrypted_payload = data[24:-33]

    next_header = data[-33]

    authentication_data = data[-32:]

    if len(encrypted_payload) == 0:
        raise ValueError(
            "ESP encrypted payload is empty"
        )

    return {
        "spi": spi,
        "sequence_number": sequence_number,
        "iv": iv,
        "encrypted_payload": encrypted_payload,
        "next_header": next_header,
        "authentication_data": authentication_data,
    }