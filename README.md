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
  - Node A starts topology formation by broadcasting Rank 0
  - A node accepts only a strictly better candidate rank
  - After a successful update, that node automatically rebroadcasts its DIO
  - Better-route-only updates prevent endless DIO rebroadcast loops
  - `main.py` now starts RPL formation automatically after setup
- [ ] **B6 — Part B tests and demonstration**

## Automatic RPL convergence

The initial state is:

```text
A: Rank 0,        Parent None
B: Rank infinity, Parent None
C: Rank infinity, Parent None
D: Rank infinity, Parent None
E: Rank infinity, Parent None
```

Node A begins by broadcasting a DIO with Rank 0.

B and C accept Rank 1 and rebroadcast their updated DIOs. D receives B's Rank 1 DIO and adopts Rank 2 with B as parent. E receives C's Rank 1 DIO and adopts Rank 2 with C as parent.

The resulting RPL tree is:

```text
        A (Rank 0)
       /          \
 B (Rank 1)    C (Rank 1)
    |              |
 D (Rank 2)    E (Rank 2)
```

Final preferred-parent state:

```text
A: Rank 0, Parent None
B: Rank 1, Parent A
C: Rank 1, Parent A
D: Rank 2, Parent B
E: Rank 2, Parent C
```

## Run the simulator

```bash
python main.py
```

The program initializes all five nodes and then starts RPL topology formation automatically.

Run the existing automated tests:

```bash
python -m unittest discover -s tests -v
```

B6 will add dedicated IPv6/RPL tests and a repeatable Part B demonstration.
