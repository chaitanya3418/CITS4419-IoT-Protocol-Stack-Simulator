"""CoAP message serialization for the CITS4419 simulator."""

# CoAP message types.
TYPE_TO_VALUE = {
    "CON": 0,
    "NON": 1,
    "ACK": 2,
    "RST": 3,
}

VALUE_TO_TYPE = {
    value: name
    for name, value in TYPE_TO_VALUE.items()
}

# CoAP codes used by this project.
#
# POST = 0.02
# 2.04 Changed = class 2, detail 04
CODE_TO_VALUE = {
    "POST": 0x02,
    "2.04 Changed": 0x44,
}

VALUE_TO_CODE = {
    value: name
    for name, value in CODE_TO_VALUE.items()
}

# Standard CoAP option number for Uri-Path.
URI_PATH_OPTION = 11

# Standard CoAP payload marker.
PAYLOAD_MARKER = 0xFF


def serialize_coap(coap_message):
    """Serialize the simplified project CoAP message to binary."""

    version = coap_message["version"]
    message_type = TYPE_TO_VALUE[coap_message["type"]]
    token = coap_message["token"]
    token_length = len(token)
    code = CODE_TO_VALUE[coap_message["code"]]
    message_id = coap_message["message_id"]

    if version != 1:
        raise ValueError("CoAP Version must be 1")

    if not 0 <= token_length <= 8:
        raise ValueError("CoAP Token Length must be between 0 and 8")

    if not 0 <= message_id <= 0xFFFF:
        raise ValueError("CoAP Message ID must fit in 16 bits")

    # Byte 0:
    # Version (2 bits) | Type (2 bits) | Token Length (4 bits)
    first_byte = (
        (version << 6)
        | (message_type << 4)
        | token_length
    )

    header = bytes([
        first_byte,
        code,
    ]) + message_id.to_bytes(2, "big")

    encoded = header + token

    # This project only requires Uri-Path=/temperature.
    uri_path = coap_message.get(
        "options",
        {},
    ).get("Uri-Path")

    if uri_path:
        option_value = uri_path.encode("utf-8")

        option_delta = URI_PATH_OPTION
        option_length = len(option_value)

        # The project only needs one short Uri-Path option, so the
        # simple 4-bit delta/length representation is sufficient.
        if option_delta >= 13 or option_length >= 13:
            raise ValueError(
                "Extended CoAP option encoding is not implemented"
            )

        option_header = bytes([
            (option_delta << 4) | option_length
        ])

        encoded += option_header + option_value

    payload = coap_message.get("payload", "")

    if payload:
        payload_bytes = payload.encode("utf-8")
        encoded += bytes([PAYLOAD_MARKER]) + payload_bytes

    return encoded


def deserialize_coap(data):
    """Parse binary CoAP bytes into the project's dictionary format."""

    if len(data) < 4:
        raise ValueError(
            "CoAP message is shorter than the 4-byte fixed header"
        )

    first_byte = data[0]

    version = (first_byte >> 6) & 0x03
    message_type_value = (first_byte >> 4) & 0x03
    token_length = first_byte & 0x0F

    if version != 1:
        raise ValueError("Unsupported CoAP Version")

    if token_length > 8:
        raise ValueError("Invalid CoAP Token Length")

    code_value = data[1]
    message_id = int.from_bytes(data[2:4], "big")

    if message_type_value not in VALUE_TO_TYPE:
        raise ValueError("Unknown CoAP message type")

    if code_value not in VALUE_TO_CODE:
        raise ValueError(
            f"Unsupported CoAP Code: 0x{code_value:02X}"
        )

    index = 4

    if len(data) < index + token_length:
        raise ValueError("CoAP token is truncated")

    token = data[index:index + token_length]
    index += token_length

    options = {}

    # Parse the one Uri-Path option required by the project.
    if (
        index < len(data)
        and data[index] != PAYLOAD_MARKER
    ):
        option_header = data[index]
        index += 1

        option_delta = (option_header >> 4) & 0x0F
        option_length = option_header & 0x0F

        if option_delta >= 13 or option_length >= 13:
            raise ValueError(
                "Extended CoAP option encoding is not implemented"
            )

        if len(data) < index + option_length:
            raise ValueError("CoAP option value is truncated")

        option_value = data[
            index:index + option_length
        ]
        index += option_length

        if option_delta == URI_PATH_OPTION:
            options["Uri-Path"] = option_value.decode("utf-8")
        else:
            raise ValueError(
                f"Unsupported CoAP option number: {option_delta}"
            )

    payload = ""

    if index < len(data):
        if data[index] != PAYLOAD_MARKER:
            raise ValueError(
                "Expected CoAP payload marker"
            )

        index += 1
        payload = data[index:].decode("utf-8")

    return {
        "version": version,
        "type": VALUE_TO_TYPE[message_type_value],
        "token_length": token_length,
        "code": VALUE_TO_CODE[code_value],
        "message_id": message_id,
        "token": token,
        "options": options,
        "payload": payload,
    }