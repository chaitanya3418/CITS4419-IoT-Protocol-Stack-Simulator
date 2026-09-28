# CITS4419 IoT Protocol Stack Simulator

Python-based IoT protocol stack simulator for CITS4419, demonstrating IEEE 802.15.4 MAC, IPv6, RPL, UDP, CoAP, IPsec ESP and DTLS.

## Development approach

The project is being implemented incrementally so every protocol operation can be tested and explained during the Week 12 demonstration.

### Part A — IEEE 802.15.4 MAC

- [x] **A1 — Node model and fixed five-node topology**
  - Node class
  - MAC and IPv6 addresses from the project brief
  - One-hop neighbor lists
  - Per-node MAC sequence number initialized to 0
  - `setup()` initialization logging
- [x] **A2 — Simplified MAC frame format and serialization**
  - Exact 12-byte fixed header
  - DATA=1, ACK=2, CONTROL=3
  - Binary serialization and parsing
- [x] **A3 — Unicast DATA frames and MAC ACKs**
  - Direct one-hop unicast delivery
  - Per-node DATA sequence-number progression
  - DATA frame parsing and payload extraction
  - Receiver automatically returns a MAC ACK
  - ACK carries the same sequence number as the DATA frame
  - Sender parses and records the returned ACK
- [ ] **A4 — Broadcast CONTROL frames**
- [ ] **A5 — Part A tests and demonstration**

## Current run

```bash
python main.py
```

At the end of Part A3, the MAC layer can deliver a unicast DATA frame between directly connected neighbors and automatically return the required MAC ACK.

Broadcast CONTROL delivery is intentionally left for Part A4 so each protocol feature remains in a separate pull request.
