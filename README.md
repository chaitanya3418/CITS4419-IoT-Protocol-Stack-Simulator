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
  - Per-node sequence-number progression
  - Receiver automatically returns the required ACK
  - ACK carries the same sequence number as the DATA frame
- [x] **A4 — Broadcast CONTROL frames**
  - Broadcast address `FF:FF:FF:FF`
  - Delivery to all one-hop neighbors
  - No MAC acknowledgements for broadcasts
  - CONTROL payload handling ready for RPL DIOs
- [x] **A5 — Part A tests and demonstration**
  - Exact topology/address checks
  - MAC 12-byte header and serialization checks
  - Payload-length validation
  - Unicast DATA/ACK tests
  - Sequence-number progression tests
  - Non-neighbor delivery rejection
  - Broadcast CONTROL/no-ACK tests
  - Repeatable Part A demonstration script

## Run the current simulator

Initialize the five IoT nodes:

```bash
python main.py
```

Run the complete Part A demonstration:

```bash
python demo_part_a.py
```

Run the automated Part A tests:

```bash
python -m unittest discover -s tests -v
```

## Part A status

Part A is now complete. The MAC layer demonstrates the simplified IEEE 802.15.4 behavior required by the assignment: node addressing, per-node sequence numbers, frame construction/parsing, one-hop unicast DATA with ACKs, and one-hop broadcast CONTROL without ACKs.

The next development stage is Part B: simplified IPv6 and RPL topology construction.
