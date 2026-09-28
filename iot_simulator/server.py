import hashlib
import hmac
import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)

from iot_simulator import (
    IPv6Packet,
    NEXT_HEADER_ESP,
    NEXT_HEADER_UDP,
)

from iot_simulator.coap import (
    deserialize_coap,
    serialize_coap,
)

from iot_simulator.esp import (
    deserialize_esp,
    serialize_esp,
)

from iot_simulator.udp import (
    deserialize_udp,
    serialize_udp,
    serialize_udp_payload,
)

class CoAPServer:
    def __init__(self):
        self.name = "Server"
        self.ipv6_address = "2001:db8::1"
        self.mac_address = "00:00:01:02"
        self.udp_port = 5683

        # Part D - DTLS security context.
        # The project assumes the DTLS handshake has already completed
        # and both endpoints already share these keys.
        self.dtls_encryption_key = b"0123456789ABCDEF"
        self.dtls_hmac_key = b"ABCDEF0123456789"
        self.dtls_epoch = 1
        self.dtls_sequence_number = 0

        # Part D - IPsec ESP security context.
        # The Security Association is assumed to already be established.
        self.ipsec_encryption_key = b"IPSEC-ENC-KEY-01"
        self.ipsec_hmac_key = b"IPSEC-HMAC-KEY1"
        self.ipsec_spi = 0x00000001
        self.esp_sequence_number = 1

        # Track accepted inbound ESP sequence numbers for replay protection.
        self.received_esp_sequence_numbers = set()

    def receive_ipv6(self, packet_bytes):
        """Receive an IPv6 packet delivered by gateway Node A."""

        packet = IPv6Packet.from_bytes(packet_bytes)

        print()
        print(
            f"[{self.name}][IPv6] Received packet: "
            f"Source={packet.source_ipv6}, "
            f"Destination={packet.destination_ipv6}, "
            f"Next Header={packet.next_header}, "
            f"Payload Length={len(packet.payload)}"
        )

        if packet.destination_ipv6 != self.ipv6_address:
            print(
                f"[{self.name}][IPv6] Packet is not for this server"
            )
            return None

        # Part C: plaintext UDP -> CoAP
        if packet.next_header == NEXT_HEADER_UDP:
            print(
                f"[{self.name}][IPv6] Passing payload to UDP"
            )

            udp_datagram = deserialize_udp(
                packet.payload,
                secure=False,
            )

            coap_response = self.receive_udp(
                udp_datagram,
                secure=False,
            )

            if coap_response is None:
                return None

            udp_response = self.send_udp(
                coap_response,
                dst_port=50000,
            )

            udp_bytes = serialize_udp(
                udp_response
            )

            self.send_ipv6(
                payload=udp_bytes,
                destination_ipv6=packet.source_ipv6,
                next_header=NEXT_HEADER_UDP,
            )

            return coap_response

        # Part D: ESP -> UDP -> DTLS -> CoAP
        if packet.next_header == NEXT_HEADER_ESP:
            print(
                f"[{self.name}][IPv6] "
                "Passing payload to IPsec ESP"
            )

            esp_packet = deserialize_esp(
                packet.payload
            )

            coap_response = self.receive_ipsec(
                esp_packet
            )

            if coap_response is None:
                return None

            # Secure response:
            # CoAP -> DTLS -> UDP -> ESP -> IPv6
            dtls_response = self.send_dtls(
                coap_response
            )

            udp_response = self.send_udp(
                dtls_response,
                dst_port=50000,
            )

            esp_response = self.send_ipsec(
                udp_response
            )

            esp_bytes = serialize_esp(
                esp_response
            )

            self.send_ipv6(
                payload=esp_bytes,
                destination_ipv6=packet.source_ipv6,
                next_header=NEXT_HEADER_ESP,
            )

            return coap_response

    def send_ipv6(
        self,
        payload,
        destination_ipv6,
        next_header,
    ):
        """Send an IPv6 packet from the server through gateway Node A."""

        if self.network is None:
            raise RuntimeError(
                "CoAP server is not attached to a network"
            )

        packet = IPv6Packet(
            source_ipv6=self.ipv6_address,
            destination_ipv6=destination_ipv6,
            next_header=next_header,
            payload=payload,
        )

        print()
        print(
            f"[{self.name}][IPv6] Creating packet: "
            f"Source={packet.source_ipv6}, "
            f"Destination={packet.destination_ipv6}, "
            f"Next Header={packet.next_header}, "
            f"Payload Length={len(packet.payload)}"
        )

        self.network.transmit_from_server(
            packet.to_bytes()
        )

    def receive_udp(self, udp_datagram, secure=False):
        print(f"[{self.name}][UDP] Received UDP datagram")
        print(
            f"[{self.name}][UDP] Source Port="
            f"{udp_datagram['source_port']}"
        )
        print(
            f"[{self.name}][UDP] Destination Port="
            f"{udp_datagram['destination_port']}"
        )
        print(
            f"[{self.name}][UDP] Length="
            f"{udp_datagram['length']} bytes"
        )

        if udp_datagram["destination_port"] != self.udp_port:
            print(f"[{self.name}][UDP] Destination port is not CoAP")
            return None

        if secure:
            print(f"[{self.name}][UDP] Passing payload to DTLS")
            # In Part D, the UDP payload is a DTLS record rather than plaintext CoAP.
            coap_message = self.receive_dtls(
                udp_datagram["payload"]
            )

            if coap_message is None:
                return None

        else:
            print(f"[{self.name}][UDP] Passing payload to CoAP")
            coap_message = udp_datagram["payload"]

        return self.receive_coap(coap_message)

    def receive_coap(self, coap_message):
        print(f"[{self.name}][CoAP] Received CoAP message")
        print(f"[{self.name}][CoAP] Type={coap_message['type']}")
        print(f"[{self.name}][CoAP] Code={coap_message['code']}")
        print(
            f"[{self.name}][CoAP] Message ID="
            f"{coap_message['message_id']}"
        )
        print(
            f"[{self.name}][CoAP] Token="
            f"{coap_message['token'].hex()}"
        )

        uri = coap_message["options"]["Uri-Path"]
        print(f"[{self.name}][CoAP] Uri-Path=/{uri}")
        print(
            f"[{self.name}][CoAP] Payload="
            f"{coap_message['payload']}"
        )

        response = self.send_coap(coap_message)
        return response

    def send_coap(self, request):
        # Create a simplified successful piggybacked response to the POST request.
        # The ACK reuses the request Message ID and Token.
        # TODO(COAP): Confirm the selected response code and payload against Lecture 6.
        response = {
            "version": 1,
            "type": "ACK",
            "token_length": request["token_length"],
            "code": "2.04 Changed",
            "message_id": request["message_id"],
            "token": request["token"],
            "options": {},
            "payload": "Temperature updated"
        }

        print()
        print(f"[{self.name}][CoAP] Creating piggybacked ACK response")
        print(f"[{self.name}][CoAP] Type={response['type']}")
        print(f"[{self.name}][CoAP] Code={response['code']}")
        print(
            f"[{self.name}][CoAP] Message ID="
            f"{response['message_id']}"
        )
        print(
            f"[{self.name}][CoAP] Token="
            f"{response['token'].hex()}"
        )
        print(
            f"[{self.name}][CoAP] Payload="
            f"{response['payload']}"
        )

        return response

    def send_udp(self, payload, dst_port=50000):
        # Serialize the upper-layer payload to calculate the UDP datagram length.
        payload_bytes = serialize_udp_payload(payload)

        udp_datagram = {
            "source_port": self.udp_port,
            "destination_port": dst_port,
            "length": 8 + len(payload_bytes),
            "checksum": 0,  # TODO(UDP): Temporary checksum placeholder
            "payload": payload
        }

        print()
        print(f"[{self.name}][UDP] Encapsulating upper-layer payload")
        print(f"[{self.name}][UDP] Source Port={self.udp_port}")
        print(f"[{self.name}][UDP] Destination Port={dst_port}")
        print(f"[{self.name}][UDP] Length={udp_datagram['length']} bytes")

        return udp_datagram

    def send_dtls(self, coap_message):
        # Protect the CoAP message using the simplified DTLS model required
        # by Part D. The handshake is assumed to have already completed.
        plaintext = serialize_coap(coap_message)

        # Week 8: the explicit 48-bit DTLS sequence number is included
        # in the HMAC calculation.
        sequence_bytes = self.dtls_sequence_number.to_bytes(6, "big")
        hmac_value = hmac.new(
            self.dtls_hmac_key,
            sequence_bytes + plaintext,
            hashlib.sha256
        ).digest()

        # Week 8 record model encrypts Data + HMAC together.
        data_with_hmac = plaintext + hmac_value

        # AES-CBC requires a new 16-byte IV and block-aligned input.
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data_with_hmac) + padder.finalize()

        cipher = Cipher(
            algorithms.AES(self.dtls_encryption_key),
            modes.CBC(iv)
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # The project exposes one Protected Data field, so the IV is kept
        # alongside the ciphertext that contains encrypted CoAP data + HMAC.
        protected_data = iv + ciphertext

        dtls_record = {
            "type": 23,
            "version": 0xFEFD,
            "epoch": self.dtls_epoch,
            "sequence_number": self.dtls_sequence_number,
            "length": len(protected_data),
            "protected_data": protected_data
        }

        print()
        print(f"[{self.name}][DTLS] Creating DTLS record")
        print(
            f"[{self.name}][DTLS] Sequence Number="
            f"{self.dtls_sequence_number}"
        )
        print(f"[{self.name}][DTLS] Plaintext={plaintext.hex()}")
        print(f"[{self.name}][DTLS] IV={iv.hex()}")
        print(f"[{self.name}][DTLS] Ciphertext={ciphertext.hex()}")
        print(f"[{self.name}][DTLS] HMAC={hmac_value.hex()}")
        print(f"[{self.name}][DTLS] Protected Data Length={len(protected_data)} bytes")

        self.dtls_sequence_number += 1
        return dtls_record

    def receive_dtls(self, dtls_record):
        print()
        print(f"[{self.name}][DTLS] Received DTLS record")
        print(
            f"[{self.name}][DTLS] Sequence Number="
            f"{dtls_record['sequence_number']}"
        )

        protected_data = dtls_record["protected_data"]

        # Protected Data = IV || Encrypt(CoAP data || HMAC).
        iv = protected_data[:16]
        ciphertext = protected_data[16:]

        print(
            f"[{self.name}][DTLS] Received Ciphertext="
            f"{ciphertext.hex()}"
        )

        cipher = Cipher(
            algorithms.AES(self.dtls_encryption_key),
            modes.CBC(iv)
        )
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        data_with_hmac = unpadder.update(padded_data) + unpadder.finalize()

        if len(data_with_hmac) < 32:
            print(f"[{self.name}][DTLS] Invalid protected data")
            return None

        plaintext = data_with_hmac[:-32]
        received_hmac = data_with_hmac[-32:]

        print(
            f"[{self.name}][DTLS] Decrypted Plaintext="
            f"{plaintext.hex()}"
        )

        sequence_bytes = dtls_record["sequence_number"].to_bytes(6, "big")
        expected_hmac = hmac.new(
            self.dtls_hmac_key,
            sequence_bytes + plaintext,
            hashlib.sha256
        ).digest()

        if not hmac.compare_digest(received_hmac, expected_hmac):
            print(f"[{self.name}][DTLS] HMAC Verification=FAILED")
            return None

        print(f"[{self.name}][DTLS] HMAC Verification=SUCCESS")

        coap_message = deserialize_coap(plaintext)
        print(f"[{self.name}][DTLS] Passing plaintext to CoAP")
        return coap_message
    

    def send_ipsec(self, udp_datagram):
        plaintext = serialize_udp(udp_datagram)

        iv = os.urandom(16)

        padder = padding.PKCS7(128).padder()
        padded_plaintext = (
            padder.update(plaintext)
            + padder.finalize()
        )

        cipher = Cipher(
            algorithms.AES(self.ipsec_encryption_key),
            modes.CBC(iv)
        )

        encryptor = cipher.encryptor()

        ciphertext = (
            encryptor.update(padded_plaintext)
            + encryptor.finalize()
        )

        next_header = 17

        authenticated_data = (
            self.ipsec_spi.to_bytes(4, "big")
            + self.esp_sequence_number.to_bytes(4, "big")
            + iv
            + ciphertext
            + next_header.to_bytes(1, "big")
        )

        # Simulator design choice:
        # authenticate all simplified ESP fields except Authentication Data itself.
        hmac_value = hmac.new(
            self.ipsec_hmac_key,
            authenticated_data,
            hashlib.sha256
        ).digest()

        esp_packet = {
            "spi": self.ipsec_spi,
            "sequence_number": self.esp_sequence_number,
            "iv": iv,
            "encrypted_payload": ciphertext,
            "next_header": next_header,
            "authentication_data": hmac_value
        }

        print()
        print(f"[{self.name}][IPsec ESP] Creating ESP packet")
        print(f"[{self.name}][IPsec ESP] SPI=0x{self.ipsec_spi:08X}")
        print(
            f"[{self.name}][IPsec ESP] Sequence Number="
            f"{self.esp_sequence_number}"
        )
        print(f"[{self.name}][IPsec ESP] Plaintext={plaintext.hex()}")
        print(f"[{self.name}][IPsec ESP] IV={iv.hex()}")
        print(f"[{self.name}][IPsec ESP] Ciphertext={ciphertext.hex()}")
        print(f"[{self.name}][IPsec ESP] Next Header={next_header}")
        print(f"[{self.name}][IPsec ESP] HMAC={hmac_value.hex()}")

        self.esp_sequence_number += 1

        return esp_packet

    def receive_ipsec(self, esp_packet):
        print()
        print(f"[{self.name}][IPsec ESP] Received ESP packet")
        print(
            f"[{self.name}][IPsec ESP] SPI="
            f"0x{esp_packet['spi']:08X}"
        )
        print(
            f"[{self.name}][IPsec ESP] Sequence Number="
            f"{esp_packet['sequence_number']}"
        )

        # Check that the packet belongs to the expected Security Association
        if esp_packet["spi"] != self.ipsec_spi:
            print(f"[{self.name}][IPsec ESP] Invalid SPI - packet rejected")
            return None

        sequence_number = esp_packet["sequence_number"]
        iv = esp_packet["iv"]
        ciphertext = esp_packet["encrypted_payload"]
        next_header = esp_packet["next_header"]
        received_hmac = esp_packet["authentication_data"]

        print(
            f"[{self.name}][IPsec ESP] Received Ciphertext="
            f"{ciphertext.hex()}"
        )

        # Reconstruct the same data authenticated by the sender
        authenticated_data = (
            esp_packet["spi"].to_bytes(4, "big")
            + sequence_number.to_bytes(4, "big")
            + iv
            + ciphertext
            + next_header.to_bytes(1, "big")
        )

        expected_hmac = hmac.new(
            self.ipsec_hmac_key,
            authenticated_data,
            hashlib.sha256
        ).digest()

        if not hmac.compare_digest(received_hmac, expected_hmac):
            print(f"[{self.name}][IPsec ESP] HMAC Verification=FAILED")
            return None

        print(f"[{self.name}][IPsec ESP] HMAC Verification=SUCCESS")

        # Replay protection
        if sequence_number in self.received_esp_sequence_numbers:
            print(
                f"[{self.name}][IPsec ESP] Replay Check=FAILED "
                f"(Sequence Number {sequence_number} already received)"
            )
            return None

        print(f"[{self.name}][IPsec ESP] Replay Check=SUCCESS")

        if next_header != 17:
            print(
                f"[{self.name}][IPsec ESP] Unexpected Next Header="
                f"{next_header}"
            )
            return None

        cipher = Cipher(
            algorithms.AES(self.ipsec_encryption_key),
            modes.CBC(iv)
        )

        decryptor = cipher.decryptor()

        padded_plaintext = (
            decryptor.update(ciphertext)
            + decryptor.finalize()
        )

        unpadder = padding.PKCS7(128).unpadder()

        plaintext = (
            unpadder.update(padded_plaintext)
            + unpadder.finalize()
        )

        print(
            f"[{self.name}][IPsec ESP] Decrypted Plaintext="
            f"{plaintext.hex()}"
        )

        # Only mark it as accepted after all checks/decryption succeed
        self.received_esp_sequence_numbers.add(sequence_number)

        udp_datagram = deserialize_udp(
            plaintext,
            secure=True,
        )

        print(
            f"[{self.name}][IPsec ESP] ESP Next Header={next_header} "
            f"(UDP)"
        )
        print(f"[{self.name}][IPsec ESP] Passing decrypted payload to UDP")

        # after ESP checking over, we can pass the payload to UDP layer, 
        # and we need to set secure=True to indicate that the payload is secure
        return self.receive_udp(
            udp_datagram,
            secure=True
        )

    