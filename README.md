-----

# Orisium

Orisium is a **high-performance, resilient Peer-to-Peer (P2P) network** designed for global scalability, attack resilience, and robust decentralization. Utilizing a dynamic hierarchical architecture and a specialized custom $\text{UDP}$-based protocol, Orisium provides a superior, secure foundation for next-generation decentralized applications.

-----

## 🔒 Secure & Hyper-Efficient P2P Transport Layer

Orisium is a **custom, ultra-low-latency P2P transport protocol** built on top of UDP and implemented in $\text{C}$. The protocol strategically combines **Post-Quantum Cryptography (PQC)** with an **Adaptive Dual-State Architecture** and intelligent flow control to meet the demanding requirements of real-time, decentralized networking.

-----

## 🚀 Key Architectural Innovations

### 1\. Post-Quantum Cryptography (PQC) Foundation

Orisium ensures long-term security against future quantum computing threats by building on $\text{NIST}$-standardized $\text{PQC}$ primitives:

  * **PQC Key Encapsulation (KEM):** Uses **ML-KEM 1024** ($\text{NIST}$ standard) for secure key exchange, providing an $\text{AES-256}$ equivalent security level.
  * **PQC Digital Signatures:** Uses **Falcon-512** ($\text{NIST}$ standard) to verify message authenticity, guaranteeing strong, non-repudiable authentication.
  * **Strict Serial Handshake:** A rigid state machine (`HELLO` to `FINISH`) ensures every $\text{PQC}$ key exchange step is verified and authenticated.
  * **Absolute Anti-Replay:** The protocol strictly rejects re-received packets (including retries of old handshake packets) to maintain state integrity and prevent replay attacks.

-----

### 2\. Adaptive Dual-Stream Architecture

Orisium separates traffic into two functionally distinct streams to simultaneously optimize reliability and speed, eliminating the classic Speed vs. Reliability trade-off.

| Stream | Flow Nature | Purpose & Key Innovation |
| :--- | :--- | :--- |
| **Control Stream** | **Serial & Reliable** (Requires ACK) | Establishes the $\text{PQC}$ session, performs **Network Orchestration**, and manages **Node Hierarchy**. Failure here triggers a controlled session disconnect. |
| **Data Stream** | **Parallel & Reliable** (Selective Repeat/Per-Packet Timer) | High-speed *payload* transmission. **Eliminates Head-of-Line Blocking (HOLB)**, ensuring minimal *worst-case latency* for data. Failure only triggers packet retransmission. |

-----

### 3\. Core Security & Resilience

Orisium is engineered to **survive and maintain cryptographic integrity** in highly lossy, unstable, or actively censored network environments.

#### a. Hierarchical Counter Management

Security is maintained through a strict two-tiered cryptographic state:

  * **Heartbeat Counter (Global State):** Serves as the **master clock** and custodian of the session's current cryptographic state. Its primary function is to lock the session's security state, making it highly **resilient against general replay attacks**.
  * **Prepared/Re Counter (Data Stream State):** Used for securing each individual data stream packet. The integrity of these counters is **tethered** to the validity of the global $\text{Heartbeat}$ state.
  * **Stream State Synchronization (SYN\_DATA):** This frame communicates the **last verified $\text{Heartbeat}$ base counter** to the receiving endpoint, ensuring **every new data stream begins with a cryptographically unique state** (preventing $\text{Nonce}$ reuse).

#### b. Strategic State Synchronization (The Safety Net)

The protocol includes a highly-secure mechanism to recover from extreme state drift:

  * **Temporary Rollback Check:** If a packet arrives with a non-matching counter, the protocol performs a temporary, non-destructive check. It copies the current counter (tmp\_ctr), decrements it, and **tests** if the packet validates against the previous state.
  * **Secure Implementation:** The actual live session counter is **never modified** unless this check is passed. This design means the mechanism functions as a **cryptographic safety net** for critical failure scenarios, rather than a routine recovery tool.

-----

### 4\. Intelligent Network Control

The protocol achieves superior resilience and efficiency through advanced adaptive logic:

  * **Adaptive Heartbeat (The Kalman Rocket):** Employs a **Kalman Filter** to predict network conditions based on accumulated **Retry Count** (reliability) and RTT (performance). The heartbeat interval is dynamically adjusted: Interval = Base $\times$ $2^{\text{retry.prediction}}$.
      * This intelligent **Exponential Backoff** ensures $\text{Orisium}$ avoids detection by network filters and prevents network congestion (*congestion avoidance*).
  * **Two-Way State Synchronization:** The **Ping-Pong Heartbeat cycle** forces both SIO and COW endpoints into a mutual agreement on session timing and state. This eliminates *timer drift* and the need for frequent, costly rollback attempts.
  * **Mobile Efficiency:** The heartbeat interval is deliberately extended for mobile clients (e.g., 20-30 seconds) to prevent **cellular radio wake-up** and subsequent **battery drain**.

-----

### 5\. High-Throughput Data Optimization

  * **Selective Repeat (SR):** Each data packet operates with its own timer and is retransmitted independently, guaranteeing **maximum throughput** by ensuring only lost packets are resent.
  * **Responsible Flow Control:** Transmission is governed by the **Receive Window Buffer** (set at **256 packets** or $\approx 300$ KB), preventing receiver overload.
  * **Safe Fragmentation:** Data is segmented into $\approx 1200$ byte fragments, mitigating the risks of $\text{IP}$ fragmentation and optimizing $\text{UDP}$ payload size.

-----

## 🌐 Dynamic Hierarchical Network Architecture

Orisium adopts a layered network structure for extreme scalability and self-healing resilience. There is no fixed root—a root can be automatically replaced.

### Structure & Self-Healing

The network is structured around **313** **Root Nodes** with deterministic recovery logic:

| Level | Role and Recovery Mechanism | Connectivity |
| :--- | :--- | :--- |
| **Root Nodes (313)** | The network core. When a Root fails, its Level-1 nodes coordinate to promote a replacement via consensus. | **25** *downstreams* (Level-1) and **312** horizontal connections (partial mesh). |
| **Level-1 Nodes** | Connects to **1** *upstream Root* and **24** horizontal connections within the same *group*. | Maximum **25** *downstreams* (Level-2). |
| **Hierarchical Layers (L2 to L4)** | The structure continues with each node maintaining **1** *upstream*, **24** *horizontal*, and a maximum of **25** *downstreams*. | Ensures **geometric scalability** and short *multihop* paths. |

### Deterministic Routing & Reconnect

The system guarantees reliable connectivity through a deterministic routing and connection recovery process:

1.  **Entry:** New clients connect to a pre-defined **Bootstrap IP**, then are routed to an optimized **Root Node**.
2.  **Optimized Path:** The Root assigns the client to the most suitable upstream (e.g., a Level-1 Node).
3.  **Persistence:** Nodes store the last verified upstream information locally to ensure **session persistence**.
4.  **Automatic Fallback:** Upon failure, the node first attempts to reconnect to the last upstream; if this fails, it automatically **falls back to a Root Node** for a new route assignment.

-----

## 🌟 Potential Applications (Decentralized Systems)

Orisium is a foundational layer designed to solve critical scalability challenges in decentralized systems, particularly for blockchains and consensus mechanisms.

  * **Delegated Consensus Framework:** By providing an efficient hierarchical structure and robust recovery, $\text{Orisium}$ effectively solves **three-quarters of the consensus problem** at the communication and node delegation level. This frees the overlying consensus protocol to focus purely on transaction validation.
  * **Blockchain Performance:** $\text{Orisium}$ can be implemented to strengthen existing blockchain networks by:
      * **Boosting Block Propagation Speed:** The hierarchical structure allows new blocks to spread rapidly from *root nodes*.
      * **Enhancing Network Resilience:** Self-healing mechanisms improve resistance to DoS attacks and partitioning.

-----

## 🛠️ Modular Architecture

Internal communication (`master` $\leftrightarrow$ `logic` $\leftrightarrow$ `cow`) is handled by **Unix Domain Sockets (UDS)** for maximum $\text{IPC}$ speed and security, avoiding shared memory to eliminate *race conditions*.

| Component | Count | Primary Task |
| :--- | :--- | :--- |
| `logic` | 4 | Protocol state machine, connection control, *handshake*, and reliability functions. |
| `master` | 1 | Main $\text{UDP}$ listener, header disassembly, and forwarding to worker $\text{sio}$. |
| `sio` | 2 | Initial parsing, *checksum* verification, and internal packet routing. |
| `cow` | 5 | *Outbound client* for horizontal and *upstream* connections (multiplexes $\sim 65$ sessions per process). |
| `r-lmdb` | 5 | Local database reader (*read-only*). |
| `w-lmdb` | 1 | Local database writer (*write-heavy*). |

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

## License

This project is licensed under [Your License Name] - see the [LICENSE.md] file for details.
