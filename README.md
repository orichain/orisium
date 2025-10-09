-----

# Orisium

Orisium is a **high-performance, resilient Peer-to-Peer (P2P) transport protocol** engineered for **geometric scalability** and $\mathbf{robust}$ $\mathbf{cryptographic}$ $\mathbf{resilience}$ in decentralized environments.

-----

## 🔒 Secure & Hyper-Efficient P2P Transport Layer

Orisium is a **custom, ultra-low-latency P2P transport protocol** built on top of $\text{UDP}$ and implemented in **pure C**. The protocol strategically combines **Post-Quantum Cryptography (PQC)**, an **Adaptive Dual-State Architecture**, and $\mathbf{Intelligent}$ $\mathbf{Kalman-Filtered}$ $\mathbf{Flow}$ $\mathbf{Control}$ to meet the demanding requirements of real-time, decentralized networking.

-----

## 🚀 Key Architectural Innovations

### 1\. Post-Quantum Cryptography (PQC) Foundation

Orisium ensures long-term security against future quantum computing threats by building on $\text{NIST}$-standardized $\text{PQC}$ primitives:

  * **PQC Key Encapsulation (KEM):** Uses **ML-KEM 1024** ($\text{NIST}$ standard) for secure key exchange, providing an $\text{AES-256}$ equivalent security level.
  * **PQC Digital Signatures:** Uses **Falcon-512** ($\text{NIST}$ standard) to verify message authenticity, guaranteeing strong, $\mathbf{non-repudiable}$ authentication.
  * **Strict Serial Handshake:** A rigid $\mathbf{state}$ $\mathbf{machine}$ (`HELLO` to `FINISH`) ensures every $\text{PQC}$ key exchange step is verified and authenticated.
  * **Absolute Anti-Replay:** The protocol strictly rejects re-received packets (including retries of old handshake packets) to maintain $\mathbf{state}$ $\mathbf{integrity}$ and prevent replay attacks.

-----

### 2\. Adaptive Dual-Stream Architecture

Orisium separates traffic into two functionally distinct streams to simultaneously optimize reliability and speed, $\mathbf{eliminating}$ $\mathbf{the}$ $\mathbf{classic}$ $\mathbf{Speed}$ $\mathbf{vs.}$ $\mathbf{Reliability}$ $\mathbf{trade-off}$.

| Stream | Flow Nature | Purpose & Key Innovation |
| :--- | :--- | :--- |
| **Control Stream** | **Serial & Reliable** (Requires ACK) | Establishes the $\text{PQC}$ $\text{session}$, performs $\mathbf{Network}$ $\mathbf{Orchestration}$, and manages $\mathbf{Node}$ $\mathbf{Hierarchy}$. Failure here triggers a $\mathbf{controlled}$ $\mathbf{session}$ $\mathbf{disconnect}$. |
| **Data Stream** | **Parallel & Reliable** (Selective Repeat/Per-Packet Timer) | High-speed *payload* transmission. **Eliminates Head-of-Line Blocking (HOLB)**, ensuring minimal $\mathbf{worst-case}$ $\mathbf{latency}$ for data. Failure only triggers packet retransmission. |

-----

### 3\. Core Security & Resilience (The Adaptive Heartbeat)

Orisium is engineered to **survive and maintain cryptographic integrity** in highly lossy, unstable, or actively censored network environments.

#### a. Heartbeat & Adaptive Retry Protocol (The Core Innovation)

Session security is maintained through a strict, $\mathbf{intelligent}$ $\mathbf{and}$ $\mathbf{adaptive}$ Heartbeat mechanism:

  * **Adaptive Heartbeat (The Kalman Rocket):** Employs a **Kalman Filter** to dynamically predict $\text{Round}$ $\text{Trip}$ $\text{Time}$ ($\text{RTT}$) and the $\mathbf{Retry}$ $\mathbf{Prediction}$ $\mathbf{Value}$ ($\text{V.P.}$), which represents $\mathbf{network}$ $\mathbf{reliability}$.
  * **Dynamic Exponential Backoff:** The heartbeat interval is dynamically adjusted: $\text{Interval} = \text{Base} \times 2^{\text{V.P.}}$. This mechanism ensures $\mathbf{controlled}$ $\mathbf{backoff}$ and $\mathbf{fast}$ $\mathbf{convergence}$ $\mathbf{to}$ $\mathbf{the}$ $\mathbf{base}$ $\mathbf{interval}$ when the network is stable ($\text{V.P.} \to 0$).
  * **Integrity-First Timer Logic:** The $\mathbf{retry}$ $\mathbf{timer}$ $\mathbf{is}$ $\mathbf{only}$ $\mathbf{created}$ $\mathbf{after}$ the $\text{UDP}$ packet has been $\mathbf{fully}$ $\mathbf{sent}$ (past $\text{serialization}$ and $\text{encryption}$), eliminating the risk of false $\mathbf{timeouts}$ and $\mathbf{state}$ $\mathbf{corruption}$.

#### b. Cryptographic Synchronization (The Safety Net)

The protocol includes a secure recovery mechanism from extreme state drift:

  * **Cryptographic Anchor State:** The protocol maintains an $\mathbf{Anchor}$ $\mathbf{State}$ (`packet_anchor`) holding the $\text{CTR}$ and $\text{Nonce}$ of the $\mathbf{last}$ $\mathbf{successfully}$ $\mathbf{validated}$ $\mathbf{Heartbeat}$ $\mathbf{packet}$.
  * **State-Aware Retry Logic:** When the Heartbeat timer expires, retry is initiated using the $\text{CTR}$ from the $\text{Anchor}$ $\text{State}$. The $\mathbf{live}$ $\mathbf{session}$ $\mathbf{Counter}$ ($\text{CTR}$) $\mathbf{is}$ $\mathbf{only}$ $\mathbf{advanced}$ $\mathbf{upon}$ $\mathbf{successful}$ $\mathbf{Heartbeat}$ $\mathbf{protocol}$ $\mathbf{completion}$.
  * **Guaranteed Session Persistence:** The $\text{Retry}$ mechanism serves as the $\mathbf{core}$ $\mathbf{self-healing}$ $\mathbf{mechanism}$ to quickly resynchronize the $\text{Heartbeat}$ $\text{CTR}$ and $\mathbf{avoid}$ $\mathbf{the}$ $\mathbf{high-latency}$ $\mathbf{full}$ $\mathbf{PQC}$ $\mathbf{rehandshake}$.

-----

### 4\. High-Throughput Data Optimization

  * **Selective Repeat (SR):** Each data packet operates with its own timer and is retransmitted independently, guaranteeing **maximum throughput** by ensuring only lost packets are resent.
  * **Responsible Flow Control:** Transmission is governed by the **Receive Window Buffer** (set at **256 packets** or $\approx 300$ KB), preventing receiver overload.
  * **Safe Fragmentation:** Data is segmented into $\approx 1200$ $\text{byte}$ fragments, $\mathbf{mitigating}$ $\mathbf{the}$ $\mathbf{risks}$ $\mathbf{of}$ $\text{IP}$ $\mathbf{fragmentation}$ and optimizing $\text{UDP}$ payload size.

-----

### 5\. Dynamic Hierarchical Network Architecture

Orisium adopts a layered network structure for $\mathbf{extreme}$ $\mathbf{scalability}$ and $\mathbf{self-healing}$ $\mathbf{resilience}$. There is no fixed root—$\mathbf{a}$ $\mathbf{root}$ $\mathbf{can}$ $\mathbf{be}$ $\mathbf{automatically}$ $\mathbf{replaced}$.

### Structure & Self-Healing

The network is structured around **313 Root Nodes** with $\mathbf{deterministic}$ $\mathbf{recovery}$ $\mathbf{logic}$:

| Level | Role and Recovery Mechanism | Connectivity |
| :--- | :--- | :--- |
| **Root Nodes (313)** | The network core. When a $\text{Root}$ fails, its $\text{Level-1}$ $\text{nodes}$ coordinate to promote a $\mathbf{replacement}$ $\mathbf{via}$ $\mathbf{consensus}$ internal to the group. | **25** *downstreams* ($\text{Level-1}$) and **312** horizontal connections (*partial mesh*). |
| **Level-1 Nodes** | Connects to **1** *upstream* $\text{Root}$ and **24** horizontal connections within the same *group*. | Maximum **25** *downstreams* ($\text{Level-2}$). |
| **Hierarchical Layers (L2 to L4)** | The structure continues with each node maintaining **1** *upstream*, **24** *horizontal*, and a maximum of **25** *downstreams*. | Ensures **geometric scalability** and $\mathbf{short}$ $\mathbf{multihop}$ $\mathbf{paths}$. |

-----

### 🛠️ Modular Multi-Process Architecture

Internal communication (`master` $\leftrightarrow$ `logic` $\leftrightarrow$ `cow`) is handled by **Unix Domain Sockets (UDS)** for maximum $\text{IPC}$ speed and security, **avoiding shared memory to eliminate $\mathbf{race}$ $\mathbf{conditions}$**. This multi-process design ensures that $\mathbf{protocol-level}$ $\mathbf{stateful}$ $\mathbf{operations}$ (like *retry* $\mathbf{logic}$ and *holepunching*) $\mathbf{do}$ $\mathbf{not}$ $\mathbf{introduce}$ $\mathbf{system-wide}$ $\mathbf{bottlenecks}$.

| Component | Count | Primary Task |
| :--- | :--- | :--- |
| **`logic`** | **4** | **System-level decision engine.** Manages the dynamic **Hierarchical Network Architecture**, handles $\text{PQC}$ key lifecycle, $\text{session}$ control, and enforces the $\mathbf{Adaptive}$ $\mathbf{Heartbeat}$ $\mathbf{policy}$. |
| `master` | 1 | Main $\text{UDP}$ listener, header disassembly, and forwarding to worker $\text{sio}$. |
| `sio` | 2 | Initial parsing, *checksum* verification, and internal packet routing. |
| **`cow`** | **5** | $\mathbf{Outbound}$ $\mathbf{client}$ for horizontal and *upstream* connections (multiplexes $\sim 65$ $\text{sessions}$ per process), handling **low-level transport, reliability functions, and $\text{I/O}$ multiplexing.** |
| `r-lmdb` | 5 | Local $\text{database}$ $\text{reader}$ (*read-only*). |
| `w-lmdb` | 1 | Local $\text{database}$ $\text{writer}$ (*write-heavy*). |

-----

## Installation

The main development and testing environment currently uses **Rocky Linux 10** and **CentOS Stream 9**.

```bash
git clone https://github.com/orichain/orisium.git
cd orisium
git submodule update --init --recursive
gmake clean debug
```

-----

## License This project is licensed under the **GNU Affero General Public License (AGPLv3)**. See the [LICENSE](https://github.com/orichain/orisium/blob/main/LICENSE) file for details.
