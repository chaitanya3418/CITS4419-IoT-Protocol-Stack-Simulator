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
- [ ] **A2 — Simplified MAC frame format and serialization**
- [ ] **A3 — Unicast DATA frames and MAC ACKs**
- [ ] **A4 — Broadcast CONTROL frames**
- [ ] **A5 — Part A tests and demonstration**

## Current run

```bash
python main.py
```

Expected initialization output begins with:

```text
[Node A][SETUP] Initialized: MAC=00:00:00:01, IPv6=fd00::1
[Node B][SETUP] Initialized: MAC=00:00:00:02, IPv6=fd00::2
```

Protocol functionality is intentionally added one sub-part at a time.
