# CITS4419 IoT Protocol Stack Simulator

Python-based IoT protocol stack simulator for CITS4419, demonstrating IEEE 802.15.4 MAC, IPv6, RPL, UDP, CoAP, IPsec ESP and DTLS.

## Development approach

The project is being implemented incrementally so every protocol operation can be tested and explained during the Week 12 demonstration.

### Part A — IEEE 802.15.4 MAC

- [x] **A1 — Node model and fixed five-node topology**
- [x] **A2 — Simplified MAC frame format and serialization**
- [x] **A3 — Unicast DATA frames and MAC ACKs**
- [x] **A4 — Broadcast CONTROL frames**
- [x] **A5 — Part A tests and demonstration**

### Part B — IPv6 and RPL

- [x] **B1 — Simplified IPv6 packet/header**
  - 16-byte source IPv6 address
  - 16-byte destination IPv6 address
  - 1-byte Next Header field
  - 2-byte Payload Length field
  - Variable-length payload
  - Binary serialization and parsing
  - Next Header constants for UDP (17), ESP (50), ICMPv6/RPL (58), and No Next Header (59)
- [ ] **B2 — ICMPv6 RPL DIO message format**
- [ ] **B3 — RPL rank and preferred-parent state**
- [ ] **B4 — DIO broadcast and rank updates**
- [ ] **B5 — Full RPL topology convergence**
- [ ] **B6 — Part B tests and demonstration**

## Run the current simulator

Initialize the five IoT nodes:

```bash
python main.py
```

Run the complete Part A demonstration:

```bash
python demo_part_a.py
```

Run the Part A automated tests:

```bash
python -m unittest discover -s tests -v
```

## Current status

Part A is complete.

Part B1 now provides the simplified IPv6 packet structure required for later RPL, UDP, and ESP encapsulation. RPL DIO processing is intentionally deferred to B2 and later sub-parts.
