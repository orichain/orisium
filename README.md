-----

# Orisium

Orisium is a high-performance peer-to-peer (P2P) network designed for global scalability, attack resilience, and robust decentralization. With a dynamic hierarchical architecture and a specialized UDP-based protocol, Orisium creates a strong foundation for future decentralized applications.

-----

## Core Architectural Principles

Orisium's unique design sets it apart by embedding intelligence and resilience directly into the protocol's core.

* **Hierarchical Transport Layer:** Unlike traditional protocols that build hierarchy at the application layer, Orisium's decentralized hierarchy is formed directly at the **transport layer**. This ensures a more efficient, inherently censorship-resistant network where nodes can dynamically route data around compromised or blocked connections.
* **Intelligent Node Scoring:** The protocol uses a smart, **weighted metrics system** to evaluate the quality of a connection. It automatically measures and rates nodes based on factors like latency (RTT), reliability (retry count), and overall health. For blockchain applications, a success rate for writing blocks is given the highest weight, ensuring the network always prefers the most capable and trustworthy nodes.

## Key Features

### Dynamic Hierarchical Network Architecture with 313 Root Nodes

Orisium adopts a layered network structure for extreme scalability and resilience. There is no fixed root — a root can be automatically replaced. When a root node fails, one of its Level-1 nodes is promoted to take its place. This promotion is decided by a consensus among all the other Level-1 nodes from the old root's group, and then validated by all other root nodes, ensuring both speed and decentralization.

  - **313 Root Nodes**

      - Each root has:
          - **25 downstreams** (Level-1)
          - **312 horizontal connections** to other roots (partial mesh)

  - **Level-1 Nodes:**

      - Connects to **1 upstream Root**
      - Has **24 horizontal connections** to other Level-1 nodes within the same **group**
      - Can have up to **25 downstreams** (Level-2)

  - **Level-2 to Level-4 Nodes:**

      - The hierarchical structure continues with the same pattern.
      - Each node has:
          - **1 upstream**, **24 horizontal**, and a maximum of **25 downstreams**

*Note: The numbers and details mentioned above are a representation of the initial design. These figures may change as development progresses and based on the results of rigorous performance testing, to ensure the network operates at an optimal level.*

-----

### Deterministic Routing & Reconnect

This protocol guarantees reliable connectivity through a **deterministic** routing and connection recovery system. This approach ensures each node can efficiently find its path within the network and can automatically recover its connection if a failure occurs.

  - Each new client node initiates its first connection by pinging a **bootstrap IP** from a pre-defined list. These bootstrap IPs serve as stable entry points and are not necessarily Root Nodes themselves.
  - Once connected to a bootstrap IP, the new node will be routed to a suitable **Root Node**. The Root will then evaluate the network topology and route the node to the most suitable **upstream** (e.g., a Level-1 Node) to optimize its path.
  - Once connected, the node stores its latest upstream information in a local file or DB. This process ensures **session persistence** even after a restart or crash.
  - When a node fails or disconnects, it will first attempt to reconnect to the same upstream. If this attempt fails, the node will automatically **fall back to a Root Node** to get a new route assignment.

-----

### Automatic Recovery from Node Failure

Orisium implements a highly efficient and self-healing mechanism to handle node failures.

  - **Fast Peer-to-Peer Recovery**: When a node fails, its horizontal peers (nodes at the same hierarchical level) will coordinate to quickly promote a replacement from the failed node's downstreams. This is done deterministically based on pre-defined criteria.
  - **Proactive Redundancy**: The network will not only recover at the downstream level but will also **replace the lost node**. One of the downstreams of the failed node will be promoted and take over the upstream role for the other downstreams.
  - **Decentralized Decision-Making**: This mechanism reduces the burden on the root node and ensures that every network segment always has an active upstream, preventing the creation of isolated sub-trees.

This approach creates a truly resilient and decentralized network, where every node has a clear strategy to ensure uninterrupted connectivity.

-----

### Custom Protocol with Post-Quantum Cryptography

Orisium strategically avoids TCP for inter-node connections, opting for a custom-built, lightweight protocol over UDP. This approach provides **full control** over the data transmission process, resulting in **ultra-low latency** and high performance. Additionally, we integrate advanced, standardized post-quantum cryptography (PQC) to secure every inter-process communication (IPC) interaction. Communication between the **master** and **worker** nodes is fully encrypted, guaranteeing data confidentiality and integrity.

  - **Post-Quantum Encryption**: We use **ML-KEM 1024** for the key encapsulation mechanism (KEM). ML-KEM 1024 was selected by NIST as an official standard, providing an equivalent security level to **AES-256**, which ensures communication remains secure even against attacks from future quantum computers.
  - **Post-Quantum Digital Signatures**: Message authenticity is verified using **Falcon-512**, an efficient digital signature algorithm also standardized by NIST. This provides strong, non-repudiable authentication.

This protocol manually implements key functions like session management, window control, message ordering, and selective retransmission, ensuring reliability without the unnecessary overhead of a standard protocol.

-----

### Advanced Connection Strategy

To ensure efficient direct connections between nodes, Orisium does not rely on relay servers that can burden bandwidth. Instead, we use a layered strategy, with **UDP-based NAT hole punching** as its main mechanism. This technique allows two nodes behind a firewall or NAT to efficiently create a direct communication path, fundamentally increasing decentralization and resilience by reducing reliance on central servers.

-----

### Potential Applications & Use Cases

Orisium functions not just as a general P2P network, but as a foundation for building the next generation of decentralized applications. Its network architecture directly addresses the most critical scalability challenges, particularly for blockchains and consensus systems.

By providing an efficient hierarchical structure and a robust recovery mechanism, Orisium effectively solves **three-quarters of the consensus problem** at the communication and node delegation level. This allows the consensus protocol built on top to focus on transaction validation and ordering, without having to worry about slow or non-decentralized peer-to-peer communication.

As such, Orisium serves as a **delegated consensus framework**, paving the way for significantly faster and more efficient blockchains.

-----

### Relevance to Blockchain and Decentralized Finance (DeFi)

Orisium is designed as a foundational layer that can enhance the performance and scalability of blockchain networks. While many blockchains have a robust P2P architecture, they often use a slower TCP protocol and a flat mesh architecture that can lead to bottlenecks in block propagation.

By integrating Orisium, blockchain networks can:

  - **Boost Block Propagation Speed**: The hierarchical architecture allows new blocks to spread rapidly from root nodes throughout the network, reducing latency and ensuring all full nodes receive blocks almost instantly.
  - **Enhance Network Resilience**: Orisium's self-healing mechanisms and deterministic connections can make blockchain networks far more resistant to DoS attacks and other disruptions, ensuring maximum uptime.
  - **Reduce Network Load**: The custom UDP protocol reduces overhead on each data packet, allowing for more efficient dissemination of information and lowering the bandwidth burden on each node, which is crucial for nodes with limited resources.

Orisium is the next-generation P2P layer that can be implemented to strengthen existing blockchain networks.

-----

### Modular Architecture

```
          w-lmdb[1]        r-lmdb[5]
             ▲                ▲
             │                │
             ▼                ▼ 
sio[2] <───>   master[1]      <───> cow[5]
                   ▲
                   │
                   ▼
                 logic[4]
```

#### Components

| Component | Count | Primary Task |
| :--- | :--- | :--- |
| `logic` | 4 | Protocol state machine, connection control, handshake, upstream/downstream, reliability |
| `master` | 1 | Main UDP listener, disassembles header, and forwards to `sio` |
| `sio` | 2 | Initial parsing, checksum verification, internal packet routing |
| `cow` | 5 | Outbound client for horizontal and upstream connections. The Root requires up to 317 active sessions, and one `cow` process can handle up to 65 sessions through `connection_id` multiplexing. |
| `r-lmdb` | 5 | Local database reader (read-only) |
| `w-lmdb` | 1 | Local database writer (write-heavy) |

*Note: The counts and functions of the components listed above are a representation of the initial design. These details may change as development progresses and based on the results of rigorous performance testing.*

#### Internal Communication

  - **Unix Domain Socket (UDS)**: Used for inter-process communication (IPC), faster and more secure than local TCP/UDP.
  - This design avoids shared memory, reducing the potential for race conditions and making it easier to debug each module independently.
  
### Proof of Concept: Automatic Recovery from Worker Failure

This is the most powerful evidence of Orisium's resilience: a test where all workers were manually terminated (kill pids). The logs below demonstrate how the system automatically detects the failure and brings all workers back online in seconds, ensuring seamless operation.

```

./orisium
[Orisium]: ==========================================================
[Orisium]: Orisium dijalankan.
[Orisium]: ==========================================================
[2025-09-19 02:45:05] [INFO] (src/orisium.c:main:40)
[Orisium]: SIGINT handler installed.
[Master]: --- Node Configuration ---
[Master]: Listen Port: 40000
[Master]: Bootstrap Nodes (5):
[Master]:   - Node 1: IP ::ffff:127.0.0.1, Port 40000
[Master]:   - Node 2: IP ::ffff:127.0.0.1, Port 40001
[Master]:   - Node 3: IP ::ffff:127.0.0.1, Port 40002
[Master]:   - Node 4: IP ::ffff:127.0.0.1, Port 40003
[Master]:   - Node 5: IP ::ffff:127.0.0.1, Port 40004
[Master]: -------------------------
[2025-09-19 02:45:05] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[2025-09-19 02:45:05] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[SIO 0]: Master Ready ...
[SIO 1]: Master Ready ...
[2025-09-19 02:45:05] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[Logic 0]: Master Ready ...
[2025-09-19 02:45:05] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[Logic 1]: Master Ready ...
[2025-09-19 02:45:05] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[Logic 2]: Master Ready ...
[2025-09-19 02:45:05] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[COW 1]: Master Ready ...
[2025-09-19 02:45:05] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[Logic 3]: Master Ready ...
[2025-09-19 02:45:05] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[2025-09-19 02:45:05] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[2025-09-19 02:45:05] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[2025-09-19 02:45:05] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[2025-09-19 02:45:05] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[2025-09-19 02:45:05] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[2025-09-19 02:45:05] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[COW 0]: Master Ready ...
[Logic 4]: Master Ready ...
[COW 5]: Master Ready ...
[2025-09-19 02:45:05] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[COW 4]: Master Ready ...
[2025-09-19 02:45:05] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[DBR 5]: Master Ready ...
[2025-09-19 02:45:05] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[DBW 0]: Master Ready ...
[2025-09-19 02:45:05] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[DBR 4]: Master Ready ...
[2025-09-19 02:45:05] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[2025-09-19 02:45:05] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[COW 3]: Master Ready ...
[DBR 0]: Master Ready ...
[DBR 1]: Master Ready ...
[DBR 2]: Master Ready ...
[COW 2]: Master Ready ...
[Logic 5]: Master Ready ...
[2025-09-19 02:45:05] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[DBR 3]: Master Ready ...
[2025-09-19 02:45:05] [INFO] (src/master/ipc.c:handle_master_ipc_event:360)
[Master]: ====================================================
[2025-09-19 02:45:05] [INFO] (src/master/ipc.c:handle_master_ipc_event:361)
[Master]: SEMUA WORKER SUDAH READY
[2025-09-19 02:45:05] [INFO] (src/master/ipc.c:handle_master_ipc_event:362)
[Master]: ====================================================
Perintah Connect Ke: ::ffff:127.0.0.1:40000
[2025-09-19 02:45:05] [INFO] (src/master/master.c:run_master:379)
[Master]: PID 1010588 UDP Server listening on port 40000.
Perintah Connect Ke: ::ffff:127.0.0.1:40001
Perintah Connect Ke: ::ffff:127.0.0.1:40003
Perintah Connect Ke: ::ffff:127.0.0.1:40004
Perintah Connect Ke: ::ffff:127.0.0.1:40002
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY SIO-0]First-time setup.
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY SIO-0]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY SIO-0]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY SIO-1]First-time setup.
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY SIO-1]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY SIO-1]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY Logic-0]First-time setup.
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY Logic-0]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY Logic-0]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY Logic-1]First-time setup.
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY Logic-1]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY Logic-1]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY Logic-2]First-time setup.
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY Logic-2]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY Logic-2]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY Logic-3]First-time setup.
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY Logic-3]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY Logic-3]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY Logic-4]First-time setup.
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY Logic-4]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY Logic-4]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY Logic-5]First-time setup.
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY Logic-5]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY Logic-5]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY COW-0]First-time setup.
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY COW-0]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY COW-0]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY COW-1]First-time setup.
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY COW-1]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY COW-1]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY COW-2]First-time setup.
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY COW-2]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY COW-2]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY COW-3]First-time setup.
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY COW-3]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY COW-3]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY COW-4]First-time setup.
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY COW-4]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY COW-4]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY COW-5]First-time setup.
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY COW-5]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY COW-5]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY DBR-0]First-time setup.
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY DBR-0]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY DBR-0]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY DBR-1]First-time setup.
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY DBR-1]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY DBR-1]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY DBR-2]First-time setup.
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY DBR-2]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY DBR-2]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY DBR-3]First-time setup.
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY DBR-3]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY DBR-3]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY DBR-4]First-time setup.
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY DBR-4]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY DBR-4]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY DBR-5]First-time setup.
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY DBR-5]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY DBR-5]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY DBW-0]First-time setup.
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY DBW-0]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:14] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY DBW-0]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY SIO-0]Calibrating... (2/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY SIO-0]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY SIO-1]Calibrating... (2/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY SIO-1]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY Logic-0]Calibrating... (2/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY Logic-0]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY Logic-1]Calibrating... (2/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY Logic-1]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY Logic-2]Calibrating... (2/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY Logic-2]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY Logic-3]Calibrating... (2/20) -> Meas: 133.34 -> EWMA: 106.67
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY Logic-3]Meas: 133.34 -> Est: 106.67
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY Logic-4]Calibrating... (2/20) -> Meas: 66.67 -> EWMA: 93.33
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY Logic-4]Meas: 66.67 -> Est: 93.33
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY Logic-5]Calibrating... (2/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY Logic-5]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY COW-0]Calibrating... (2/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY COW-0]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY COW-1]Calibrating... (2/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY COW-1]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY COW-2]Calibrating... (2/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY COW-2]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY COW-3]Calibrating... (2/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY COW-3]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY COW-4]Calibrating... (2/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY COW-4]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY COW-5]Calibrating... (2/20) -> Meas: 133.34 -> EWMA: 106.67
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY COW-5]Meas: 133.34 -> Est: 106.67
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY DBR-0]Calibrating... (2/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY DBR-0]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY DBR-1]Calibrating... (2/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY DBR-1]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY DBR-2]Calibrating... (2/20) -> Meas: 100.01 -> EWMA: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY DBR-2]Meas: 100.01 -> Est: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY DBR-3]Calibrating... (2/20) -> Meas: 66.67 -> EWMA: 93.33
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY DBR-3]Meas: 66.67 -> Est: 93.33
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY DBR-4]Calibrating... (2/20) -> Meas: 100.01 -> EWMA: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY DBR-4]Meas: 100.01 -> Est: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY DBR-5]Calibrating... (2/20) -> Meas: 100.01 -> EWMA: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY DBR-5]Meas: 100.01 -> Est: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY DBW-0]Calibrating... (2/20) -> Meas: 100.01 -> EWMA: 100.00
[2025-09-19 02:45:23] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY DBW-0]Meas: 100.01 -> Est: 100.00
[2025-09-19 02:45:31] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[DBW 0]: Master Ready ...
[2025-09-19 02:45:31] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[DBR 2]: Master Ready ...
[2025-09-19 02:45:31] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[DBR 3]: Master Ready ...
[2025-09-19 02:45:31] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[DBR 4]: Master Ready ...
[2025-09-19 02:45:31] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[DBR 5]: Master Ready ...
[2025-09-19 02:45:31] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[DBR 1]: Master Ready ...
[2025-09-19 02:45:31] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[DBR 0]: Master Ready ...
[2025-09-19 02:45:31] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[COW 2]: Master Ready ...
[2025-09-19 02:45:31] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[COW 1]: Master Ready ...
[2025-09-19 02:45:31] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[Logic 4]: Master Ready ...
[2025-09-19 02:45:31] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[Logic 3]: Master Ready ...
[2025-09-19 02:45:31] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[COW 0]: Master Ready ...
[2025-09-19 02:45:31] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[Logic 1]: Master Ready ...
[2025-09-19 02:45:31] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[Logic 2]: Master Ready ...
[2025-09-19 02:45:31] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[Logic 0]: Master Ready ...
[2025-09-19 02:45:31] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[SIO 0]: Master Ready ...
[2025-09-19 02:45:31] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[SIO 1]: Master Ready ...
[2025-09-19 02:45:31] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[Logic 5]: Master Ready ...
[2025-09-19 02:45:31] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[COW 3]: Master Ready ...
[2025-09-19 02:45:31] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[COW 4]: Master Ready ...
[2025-09-19 02:45:31] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:70)
[COW 5]: Master Ready ...
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY SIO-0]First-time setup.
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY SIO-0]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY SIO-0]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY SIO-1]First-time setup.
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY SIO-1]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY SIO-1]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY Logic-0]First-time setup.
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY Logic-0]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY Logic-0]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY Logic-1]First-time setup.
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY Logic-1]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY Logic-1]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY Logic-2]First-time setup.
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY Logic-2]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY Logic-2]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY Logic-3]First-time setup.
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY Logic-3]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY Logic-3]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY Logic-4]First-time setup.
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY Logic-4]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY Logic-4]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY Logic-5]First-time setup.
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY Logic-5]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY Logic-5]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY COW-0]First-time setup.
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY COW-0]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY COW-0]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY COW-1]First-time setup.
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY COW-1]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY COW-1]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY COW-2]First-time setup.
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY COW-2]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY COW-2]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY COW-3]First-time setup.
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY COW-3]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY COW-3]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY COW-4]First-time setup.
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY COW-4]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY COW-4]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY COW-5]First-time setup.
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY COW-5]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY COW-5]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY DBR-0]First-time setup.
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY DBR-0]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY DBR-0]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY DBR-1]First-time setup.
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY DBR-1]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY DBR-1]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY DBR-2]First-time setup.
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY DBR-2]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY DBR-2]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY DBR-3]First-time setup.
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY DBR-3]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY DBR-3]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY DBR-4]First-time setup.
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY DBR-4]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY DBR-4]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY DBR-5]First-time setup.
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY DBR-5]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY DBR-5]Meas: 100.00 -> Est: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:46)
[Master]: [ORICLE => HEALTHY DBW-0]First-time setup.
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:79)
[Master]: [ORICLE => HEALTHY DBW-0]Calibrating... (1/20) -> Meas: 100.00 -> EWMA: 100.00
[2025-09-19 02:45:32] [DEVEL-DEBUG] (src/kalman.c:calculate_oricle_double:82)
[Master]: [ORICLE => HEALTHY DBW-0]Meas: 100.00 -> Est: 100.00
^C[2025-09-19 02:45:38] [INFO] (src/master/master.c:run_master:190)
[Master]: SIGINT received. Initiating graceful shutdown...
[2025-09-19 02:45:38] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:64)
[SIO 0]: SIGINT received. Initiating graceful shutdown...
[2025-09-19 02:45:38] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:64)
[SIO 1]: SIGINT received. Initiating graceful shutdown...
[2025-09-19 02:45:38] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:64)
[Logic 0]: SIGINT received. Initiating graceful shutdown...
[2025-09-19 02:45:38] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:64)
[2025-09-19 02:45:38] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:64)
[Logic 3]: SIGINT received. Initiating graceful shutdown...
[Logic 2]: SIGINT received. Initiating graceful shutdown...
[2025-09-19 02:45:38] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:64)
[Logic 1]: SIGINT received. Initiating graceful shutdown...
[2025-09-19 02:45:38] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:64)
[Logic 4]: SIGINT received. Initiating graceful shutdown...
[2025-09-19 02:45:38] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:64)
[COW 0]: SIGINT received. Initiating graceful shutdown...
[2025-09-19 02:45:38] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:64)
[COW 1]: SIGINT received. Initiating graceful shutdown...
[2025-09-19 02:45:38] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:64)
[COW 2]: SIGINT received. Initiating graceful shutdown...
[2025-09-19 02:45:38] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:64)
[Logic 5]: SIGINT received. Initiating graceful shutdown...
[2025-09-19 02:45:38] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:64)
[COW 5]: SIGINT received. Initiating graceful shutdown...
[2025-09-19 02:45:38] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:64)
[COW 3]: SIGINT received. Initiating graceful shutdown...
[2025-09-19 02:45:38] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:64)
[COW 4]: SIGINT received. Initiating graceful shutdown...
[2025-09-19 02:45:38] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:64)
[DBR 0]: SIGINT received. Initiating graceful shutdown...
[2025-09-19 02:45:38] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:64)
[2025-09-19 02:45:38] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:64)
[2025-09-19 02:45:38] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:64)
[2025-09-19 02:45:38] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:64)
[DBR 3]: SIGINT received. Initiating graceful shutdown...
[2025-09-19 02:45:38] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:64)
[DBR 5]: SIGINT received. Initiating graceful shutdown...
[DBR 1]: SIGINT received. Initiating graceful shutdown...
[DBR 2]: SIGINT received. Initiating graceful shutdown...
[DBR 4]: SIGINT received. Initiating graceful shutdown...
[2025-09-19 02:45:38] [INFO] (src/workers/ipc.c:handle_workers_ipc_event:64)
[DBW 0]: SIGINT received. Initiating graceful shutdown...
[2025-09-19 02:45:38] [INFO] (src/master/workers.c:cleanup_workers:626)
[Master]: Performing cleanup...
[2025-09-19 02:45:38] [INFO] (src/master/workers.c:cleanup_workers:642)
[Master]: Cleanup complete.
[Orisium]: ==========================================================
[Orisium]: Orisium selesai dijalankan.
[Orisium]: ==========================================================
[cirill@cirill orisium]$

```

This demonstrates the effectiveness of the **`Master`'s** self-healing capabilities, ensuring continuous network operation by automatically restoring all worker connections.

-----

## Installation

The main development and testing environment currently uses **Rocky Linux 10** and **CentOS Stream 9**. We highly recommend using one of these operating systems for the best results.

```bash
git clone https://github.com/orichain/orisium.git
cd orisium
git submodule update --init --recursive
gmake clean debug
```

-----

## License

This project is licensed under [Your License Name] - see the [LICENSE.md] file for details.
