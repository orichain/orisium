# Orisium

Orisium is a high-performance peer-to-peer (P2P) network designed for global scalability, attack resilience, and robust decentralization. With a dynamic hierarchical architecture and a specialized UDP-based protocol, Orisium creates a strong foundation for future decentralized applications.

-----

## Key Features

### **Dynamic Hierarchical Network Architecture with 313 Root Nodes**

Orisium adopts a layered network structure for extreme scalability and resilience. There is no fixed root — a root can be automatically replaced. When a root node fails, one of its Level-1 nodes is promoted to take its place. This promotion is decided by a consensus among all the other Level-1 nodes from the old root's group, and then validated by all other root nodes, ensuring both speed and decentralization.

  * **313 Root Nodes**

      * Each root has:
          - **25 downstreams** (Level-1)
          - **312 horizontal connections** to other roots (partial mesh)

  * **Level-1 Nodes:**

      - Connects to **1 upstream Root**
      - Has **24 horizontal connections** to other Level-1 nodes within the same **group**
      - Can have up to **25 downstreams** (Level-2)

  * **Level-2 to Level-4 Nodes:**

      - The hierarchical structure continues with the same pattern
      - Each node has:
          - **1 upstream**, **24 horizontal**, and a maximum of **25 downstreams**

*Note: The numbers and details mentioned above are a representation of the initial design. These figures may change as development progresses and based on the results of rigorous performance testing, to ensure the network operates at an optimal level.*

### **Deterministic Routing & Reconnect**

This protocol guarantees reliable connectivity through a **deterministic** routing and connection recovery system. This approach ensures each node can efficiently find its path within the network and can automatically recover its connection if a failure occurs.

  * Each new client node initiates its first connection by pinging a **bootstrap IP** from a pre-defined list. These bootstrap IPs serve as stable entry points and are not necessarily Root Nodes themselves.
  * Once connected to a bootstrap IP, the new node will be routed to a suitable **Root Node**. The Root will then evaluate the network topology and route the node to the most suitable **upstream** (e.g., a Level-1 Node) to optimize its path.
  * Once connected, the node stores its latest upstream information in a local file or DB. This process ensures **session persistence** even after a restart or crash.
  * When a node fails or disconnects, it will first attempt to reconnect to the same upstream. If this attempt fails, the node will automatically **fall back to a Root Node** to get a new route assignment.

### **Automatic Recovery from Node Failure**

Orisium implements a highly efficient and self-healing mechanism to handle node failures.

  * **Fast Peer-to-Peer Recovery**: When a node fails, its horizontal peers (nodes at the same hierarchical level) will coordinate to quickly promote a replacement from the failed node's downstreams. This is done deterministically based on pre-defined criteria.
  * **Proactive Redundancy**: The network will not only recover at the downstream level but will also **replace the lost node**. One of the downstreams of the failed node will be promoted and take over the upstream role for the other downstreams.
  * **Decentralized Decision-Making**: This mechanism reduces the burden on the root node and ensures that every network segment always has an active upstream, preventing the creation of isolated sub-trees.

This approach creates a truly resilient and decentralized network, where every node has a clear strategy to ensure uninterrupted connectivity.

### **Custom Protocol over UDP**

Orisium strategically avoids TCP for inter-node connections, opting for a custom-built, lightweight protocol over UDP. This approach provides **full control** over the data transmission process, resulting in **ultra-low latency** and high performance.

This protocol manually implements key functions like session management, window control, message ordering, and selective retransmission, ensuring reliability without the unnecessary overhead of a standard protocol.

### **Advanced Connection Strategy**

To ensure efficient direct connections between nodes, Orisium does not rely on relay servers that can burden bandwidth. Instead, we use a layered strategy, with **UDP-based NAT hole punching** as its main mechanism.

This technique allows two nodes behind a firewall or NAT to efficiently create a direct communication path, fundamentally increasing decentralization and resilience by reducing reliance on central servers.

-----

### **Potential Applications & Use Cases**

Orisium functions not just as a general P2P network, but as a foundation for building the next generation of decentralized applications. Its network architecture directly addresses the most critical scalability challenges, particularly for blockchains and consensus systems.

By providing an efficient hierarchical structure and a robust recovery mechanism, Orisium effectively solves **three-quarters of the consensus problem** at the communication and node delegation level. This allows the consensus protocol built on top to focus on transaction validation and ordering, without having to worry about slow or non-decentralized peer-to-peer communication.

As such, Orisium serves as a **delegated consensus framework**, paving the way for significantly faster and more efficient blockchains.

-----

### **Relevance to Blockchain and Decentralized Finance (DeFi)**

Orisium is designed as a foundational layer that can enhance the performance and scalability of blockchain networks. While many blockchains have a robust P2P architecture, they often use a slower TCP protocol and a flat mesh architecture that can lead to bottlenecks in block propagation.

By integrating Orisium, blockchain networks can:

  * **Boost Block Propagation Speed**: The hierarchical architecture allows new blocks to spread rapidly from root nodes throughout the network, reducing latency and ensuring all full nodes receive blocks almost instantly.
  * **Enhance Network Resilience**: Orisium's self-healing mechanisms and deterministic connections can make blockchain networks far more resistant to DoS attacks and other disruptions, ensuring maximum uptime.
  * **Reduce Network Load**: The custom UDP protocol reduces overhead on each data packet, allowing for more efficient dissemination of information and lowering the bandwidth burden on each node, which is crucial for nodes with limited resources.

Orisium is the next-generation P2P layer that can be implemented to strengthen existing blockchain networks.

-----

### **Modular Architecture**

```
            w-lmdb[1]     r-lmdb[5]
                ▲             ▲
                │             │
                ▼             ▼ 
sio[2] <─────>     master[1]      <─────> cow[5]
                      ▲
                      │
                      ▼
                   Logic[4]

Internal Communication / IPC:
IPC Protocol via Unix Domain Socket
```

#### 📦 Components

| Component | Count | Primary Task |
| :--- | :--- | :--- |
| `logic` | 4 | Protocol state machine, connection control, handshake, upstream/downstream, reliability |
| `master` | 1 | Main UDP listener, disassembles header, and forwards to `sio` |
| `sio` | 2 | Initial parsing, checksum verification, internal packet routing |
| `cow` | 5 | Outbound client for horizontal and upstream connections. The Root requires up to 317 active sessions, and one `cow` process can handle up to 65 sessions through `connection_id` multiplexing. |
| `r-lmdb` | 5 | Local database reader (read-only) |
| `w-lmdb` | 1 | Local database writer (write-heavy) |

*Note: The counts and functions of the components listed above are a representation of the initial design. These details may change as development progresses and based on the results of rigorous performance testing.*

#### 🔌 Internal Communication

  - **Unix Domain Socket (UDS)**: Used for inter-process communication (IPC), faster and more secure than local TCP/UDP.
  - This design avoids shared memory, reducing the potential for race conditions and making it easier to debug each module independently.

-----

## Installation

```bash
git clone https://github.com/orichain/orisium.git
cd orisium
git submodule update --init --recursive
gmake clean debug
```

-----

## License

This project is licensed under [Your License Name] - see the [LICENSE.md] file for details.
