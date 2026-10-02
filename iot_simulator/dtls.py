"""Serialize and parse the simplified DTLS record format."""

DTLS_HEADER_LENGTH = 13


def deserialize_dtls(data):
    # The fixed header contains Type, Version, Epoch, Sequence Number and Length.
    if len(data) < DTLS_HEADER_LENGTH:
        raise ValueError("DTLS record is too short")

    record_type = data[0]
    version = int.from_bytes(data[1:3], "big")
    epoch = int.from_bytes(data[3:5], "big")
    sequence_number = int.from_bytes(data[5:11], "big")
    length = int.from_bytes(data[11:13], "big")

    # Protected Data begins immediately after the fixed DTLS header.
    protected_data = data[DTLS_HEADER_LENGTH:DTLS_HEADER_LENGTH + length]

    if len(protected_data) != length:
        raise ValueError("Invalid DTLS protected-data length")

    return {
        "type": record_type,
        "version": version,
        "epoch": epoch,
        "sequence_number": sequence_number,
        "length": length,
        "protected_data": protected_data
    }

def serialize_dtls(dtls_record):
    return (
        dtls_record["type"].to_bytes(1, "big")
        + dtls_record["version"].to_bytes(2, "big")
        + dtls_record["epoch"].to_bytes(2, "big")
        + dtls_record["sequence_number"].to_bytes(6, "big")
        + dtls_record["length"].to_bytes(2, "big")
        + dtls_record["protected_data"]
    )
