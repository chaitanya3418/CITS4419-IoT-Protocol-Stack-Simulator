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
- [x] **B2 — ICMPv6 RPL DIO message format**
- [x] **B3 — RPL rank and preferred-parent state**
  - Node A starts as the RPL root with Rank 0
  - Nodes B, C, D and E start with infinite/unknown Rank
  - Every node has a parent field initialized to `None`
  - `0xFFFF` is used internally as the two-byte infinity sentinel
  - RPL state is displayed during node setup
- [ ] **B4 — DIO broadcast and rank updates**
- [ ] **B5 — Full RPL topology convergence**
- [ ] **B6 — Part B tests and demonstration**

## Initial RPL State

Before any DIO messages are exchanged:

```text
Node A: Rank=0,        Parent=None
Node B: Rank=infinity, Parent=None
Node C: Rank=infinity, Parent=None
Node D: Rank=infinity, Parent=None
Node E: Rank=infinity, Parent=None
```

B4 will add DIO processing so a node can update its rank and preferred parent when it receives a better route.

## Run the current simulator

```bash
python main.py
```

Run the existing Part A automated tests:

```bash
python -m unittest discover -s tests -v
```
