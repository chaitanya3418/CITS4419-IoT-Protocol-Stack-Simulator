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
- [x] **B5 — Full automatic RPL topology convergence**
- [x] **B6 — Part B tests and demonstration**
  - IPv6 35-byte header checks
  - IPv6 serialization/parsing and payload-length validation
  - RPL DIO 4-byte format checks
  - RPL Type/Code validation
  - Initial RPL state checks
  - RPL-over-IPv6 encapsulation verification
  - Required final tree verification
  - Equal/worse-route rejection
  - Confirmation that DIO broadcasts generate no MAC ACK
  - Repeatable Part B demonstration script

## Required RPL tree

After automatic convergence:

```text
        A (Rank 0)
       /          \
 B (Rank 1)    C (Rank 1)
    |              |
 D (Rank 2)    E (Rank 2)
```

Final state:

```text
A: Rank 0, Parent None
B: Rank 1, Parent A
C: Rank 1, Parent A
D: Rank 2, Parent B
E: Rank 2, Parent C
```

## Run the simulator

Initialize the nodes and automatically form the RPL tree:

```bash
python main.py
```

Run the Part A demonstration:

```bash
python demo_part_a.py
```

Run the Part B demonstration:

```bash
python demo_part_b.py
```

Run all automated tests:

```bash
python -m unittest discover -s tests -v
```

## Current status

Parts A and B are now implemented in the main simulator architecture.

The repository also contains the teammate-contributed standalone Part C/D implementation in `part_cd.py`. The next integration stage can connect UDP/CoAP and the security layers to the Part A/B node, IPv6, MAC and RPL routing architecture.
