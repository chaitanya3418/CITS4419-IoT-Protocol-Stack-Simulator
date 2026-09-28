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
- [x] **B4 — DIO broadcast and rank updates**
  - DIO encapsulation: RPL → IPv6 → MAC CONTROL
  - IPv6 Next Header = 58 for ICMPv6/RPL
  - MAC destination = `FF:FF:FF:FF`
  - One-hop neighbors parse the IPv6 packet and DIO
  - Candidate rank = advertised rank + 1
  - Rank/parent change only when the candidate route is better
  - No automatic DIO rebroadcast yet
- [ ] **B5 — Full RPL topology convergence**
- [ ] **B6 — Part B tests and demonstration**

## B4 DIO Flow

A node with a finite rank can call `send_rpl_dio()`.

For example, Node A begins at Rank 0 and broadcasts:

```text
RPL DIO (Rank 0)
        ↓
IPv6 (Next Header 58)
        ↓
MAC CONTROL (FF:FF:FF:FF)
        ↓
     B and C
```

Nodes B and C calculate:

```text
Candidate Rank = advertised Rank + 1
               = 0 + 1
               = 1
```

Because Rank 1 is better than their initial infinite rank, they update to:

```text
B: Rank=1, Parent=A
C: Rank=1, Parent=A
```

Nodes D and E remain at infinity in B4 because B and C do not automatically rebroadcast their updated DIOs yet. That automatic propagation is intentionally reserved for B5.

## IPv6 multicast design choice

The assignment specifies MAC broadcast for RPL DIOs but does not specify the simplified IPv6 destination address. This simulator uses `ff02::1a` as the RPL multicast destination, while the MAC destination remains the assignment-required `FF:FF:FF:FF`.

## Run the current simulator

```bash
python main.py
```

Run the existing tests:

```bash
python -m unittest discover -s tests -v
```
