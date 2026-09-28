# CITS4419 IoT Protocol Stack Simulator

Python-based simulator for the CITS4419 project, demonstrating a simplified IoT protocol stack across IEEE 802.15.4 MAC, IPv6, RPL, UDP, CoAP, DTLS, and IPsec ESP.

## Features

The simulator implements the four project parts in one integrated architecture:

- **Part A — IEEE 802.15.4 MAC**
  - Fixed five-node topology
  - Simplified 12-byte MAC header
  - DATA, ACK, and CONTROL frames
  - One-hop unicast delivery
  - MAC acknowledgements
  - Broadcast CONTROL frames

- **Part B — IPv6 and RPL**
  - Simplified IPv6 packet format
  - ICMPv6 RPL DIO messages
  - Automatic rank and preferred-parent selection
  - Automatic RPL topology convergence
  - Multi-hop forwarding through the converged RPL tree

- **Part C — UDP and CoAP**
  - CoAP Confirmable POST request
  - Resource: `/temperature`
  - UDP transport
  - End-to-end IPv6 communication
  - Piggybacked CoAP ACK response from the server

- **Part D — DTLS and IPsec ESP**
  - DTLS protection of the CoAP message
  - AES-128-CBC encryption
  - HMAC-SHA-256 integrity checking
  - IPsec ESP protection of the complete UDP datagram
  - ESP sequence numbers and simplified replay protection
  - Secure request and response processing

## Topology

The simulator uses the following fixed IoT topology:

```text
        A (Rank 0)
       /          \
 B (Rank 1)    C (Rank 1)
    |              |
 D (Rank 2)    E (Rank 2)
```

After RPL convergence:

```text
A: Rank 0, Parent None
B: Rank 1, Parent A
C: Rank 1, Parent A
D: Rank 2, Parent B
E: Rank 2, Parent C
```

Node A acts as the RPL root and gateway. The CoAP server is connected to Node A through a simulated wired interface.

## Protocol Stack

### Part C

Sender-side encapsulation:

```text
CoAP
  ↓
UDP
  ↓
IPv6
  ↓
IEEE 802.15.4 MAC
```

The IPv6 packet is forwarded through the RPL topology while the MAC source and destination addresses change at each wireless hop.

### Part D

Sender-side encapsulation:

```text
CoAP
  ↓
DTLS
  ↓
UDP
  ↓
IPsec ESP
  ↓
IPv6
  ↓
IEEE 802.15.4 MAC
```

DTLS protects the CoAP message. IPsec ESP protects the complete UDP datagram containing the DTLS record.

## Requirements

- Python 3.10 or later
- `cryptography`

Install the required dependency with:

```bash
python -m pip install -r requirements.txt
```

## Running the Simulator

Run:

```bash
python main.py
```

The simulator will:

1. Create and initialize Nodes A-E.
2. Automatically form the RPL topology.
3. Attach the CoAP server to gateway Node A.
4. Ask whether to run Part C or Part D.
5. Ask for a source node from A-E.
6. Run the complete request and response through the simulated protocol stack.

Example selection:

```text
Select part to run (C/D): D
Select source node (A/B/C/D/E): D
```

## Server

The CoAP server uses:

```text
IPv6 address: 2001:db8::1
MAC address:  00:00:01:02
UDP port:     5683
```

For the client nodes, UDP source port `50000` is used for application traffic.

## Security Configuration

The project assumes that the DTLS handshake and IPsec Security Association have already been established.

### DTLS

```text
Encryption key: 0123456789ABCDEF
HMAC key:       ABCDEF0123456789
```

DTLS uses:

- AES-128-CBC
- HMAC-SHA-256
- Epoch and 48-bit sequence number
- A 16-byte IV

### IPsec ESP

```text
SPI:            0x00000001
Encryption key: IPSEC-ENC-KEY-01
HMAC key:       IPSEC-HMAC-KEY1
```

ESP uses:

- AES-128-CBC
- HMAC-SHA-256
- 32-bit sequence numbers
- A 16-byte IV
- Simplified replay protection

## Tests

Run all automated tests with:

```bash
python -m unittest discover -s tests -v
```

The test suite covers the protocol layers and the integrated Part C and Part D request/response flows.

## Continuous Integration

GitHub Actions is configured to run automatically on pushes and pull requests.

The CI workflow:

- checks out the repository,
- installs Python and project dependencies,
- checks Python syntax,
- runs the complete `unittest` test suite.

The workflow file is located at:

```text
.github/workflows/ci.yml
```

## Project Structure

```text
.
├── .github/
│   └── workflows/
│       └── ci.yml
├── iot_simulator/
│   ├── __init__.py
│   ├── coap.py
│   ├── dtls.py
│   ├── esp.py
│   ├── ipv6.py
│   ├── mac.py
│   ├── network.py
│   ├── node.py
│   ├── rpl.py
│   ├── server.py
│   ├── topology.py
│   └── udp.py
├── tests/
│   ├── test_part_a.py
│   ├── test_part_b.py
│   ├── test_part_c.py
│   └── test_part_d.py
├── main.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Notes

This simulator is intentionally simplified for the CITS4419 project. It demonstrates the required protocol structures, encapsulation order, forwarding behavior, security processing, logging, and replay checking rather than implementing complete production versions of IEEE 802.15.4, IPv6, RPL, CoAP, DTLS, or IPsec.
