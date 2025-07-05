<p align="center">
<img src="assets/images/orisium.png" alt="Orisium Logo" width="200">
</p>

# Orisium Network: Arsitektur Jaringan Terdesentralisasi

## ✨ Pendahuluan

**Orisium** adalah jaringan **terdesentralisasi** yang dirancang untuk operasi **multiproses** yang aman, efektif, dan cepat. Arsitekturnya mengadopsi model **hierarkis** dengan tingkatan node yang memiliki peran dan tanggung jawab spesifik.

Tujuan utama Orisium adalah membangun **ekosistem yang skalabel, tahan manipulasi, dan berbasis kriptografi pasca-kuantum (PQC)**, lengkap dengan **mekanisme konsensus cerdas**.

---

## 🔺 Struktur Jaringan Hierarkis

Orisium menggunakan struktur **berlapis (layered)** untuk memudahkan distribusi beban dan skalabilitas:

- **Node Root Bootstrap**: Titik masuk jaringan.
- **Node Root**: Penjaga integritas database global.
- **Node Level-1 hingga Level-7**: Perantara dan pemroses transaksi.

### Batas Maksimal Node per Level

| Level           | Maksimal Node     |
|-----------------|-------------------|
| Root Bootstrap  | 3                 |
| Root            | 313               |
| Level-1         | 3.130             |
| Level-2         | 31.300            |
| Level-3         | 313.000           |
| Level-4         | 3.130.000         |
| Level-5         | 31.300.000        |
| Level-6         | 313.000.000       |
| Level-7         | 3.130.000.000     |

### Jenis Koneksi Node

- **Downstream**: Node di level bawah.
- **Horizontalstream**: Node di level sama.
- **Upstream**: Node di level atas.

---

## 📄 Jenis Node & Tanggung Jawab

### 1. Node Root Bootstrap

**Definisi**:
- Minimal Downstream: 0
- Maksimal Downstream: 10
- Minimal Horizontalstream: 2
- Maksimal Horizontalstream: 312

**Kewajiban & Hak**:
- Nama domain tidak berubah (immutability, DNSSEC, PQC)
- Menyimpan **Global Database** sharded + verifikasi Merkle Tree
- Database Memori untuk node downstream (IP, performa)
- **Jawaban Rolling** menggunakan VRF/hash dengan nonce
- **Voting VRF** untuk pemilihan validator

### 2. Node Root (Non-Bootstrap)

- Hampir sama dengan Root Bootstrap
- Wajib memberi pengumuman penurunan level ke Downstream Horizontalstream

### 3. Node Level-1

**Definisi**:
- Fixed Horizontalstream: 9
- Pertanyaan Jumlah Horizontalstream: 2
- Fixed Upstream: 1

**Tugas**:
- Evaluasi dan pindah Upstream jika perlu
- Umumkan kehilangan Upstream
- Dapat **naik level** jika memenuhi syarat dan sinkronisasi database shard

### 4. Node Level-2 hingga Level-7

- Sama seperti Node Level-1
- Menyederhanakan implementasi dan pemeliharaan

---

## 📊 Manajemen Data

### Global Database File Transaksi (Sharded)

- Sharding berdasarkan address/hash
- Merkle Root per shard → digabung menjadi **Global State Root**
- Digunakan untuk verifikasi dan finalisasi transaksi lintas node

### Database Memori Node Downstream

- Menyimpan IP, level, jumlah downstream, performa secara real-time
- Hanya untuk Node Root & Level-1 ke atas

---

## 🧠 Komunikasi Antar Proses (IPC)

### Arsitektur Multiproses (menggunakan `fork()` di C)

- **Master Process**: Menginisialisasi dan memantau
- **SIO (Socket I/O)**: I/O non-blokir (epoll/kqueue)
- **Logic**: Verifikasi, routing, decision making
- **COW (Database)**: Akses baca/tulis terpisah

**IPC yang digunakan**:
- Message Queues
- Shared Memory (plus semaphore/mutex)
- Pipes

---

## 🔐 Mekanisme Keamanan

- Tanda tangan & autentikasi berbasis **kriptografi PQC**
- Enkripsi TLS untuk komunikasi antar node
- Nonce & timestamp untuk mencegah replay attack
- **Rolling Answer** dengan VRF untuk mencegah kartel
- Handshake kriptografis untuk verifikasi node baru
- Sistem reputasi dan voting untuk kontrol level

---

## ⏱ Efisiensi & Kecepatan

- **Non-blocking I/O** dengan epoll/kqueue
- Struktur data optimal: Hash table, balanced tree
- Caching agresif
- Load balancing berdasarkan performa
- Optimasi kode C dan profiling

---

## ⚡ Ketahanan & Toleransi Kesalahan

- Redundansi pada Node Root Bootstrap
- Penemuan otomatis Upstream jika gagal
- Pemantauan proses anak oleh Master
- Logging dan debugging komprehensif

---

## ⚖️ Strategi Menghindari Bottleneck

### A. Optimalisasi Database

- Sharding global database
- Query lintas shard
- Batch processing
- Indeks tepat & pustaka database efisien (RocksDB, LevelDB)

### B. Optimalisasi SIO

- I/O Multiplexing (epoll/kqueue)
- Pool buffer jaringan
- Rate limiting + deteksi anomali

### C. Optimalisasi Logic

- Message Queue async
- Parallelisasi tugas berat (VRF, hashing, PQC)
- Shared memory untuk data yang sering diakses

### D. Optimalisasi COW

- Antrean request
- Batch write
- Indeks + snapshot

### E. Sinkronisasi Promosi Node

- Pre-synchronization untuk kandidat Node Root
- Verifikasi shard melalui Merkle Proof
- Challenge-response
- Konsensus voting untuk promosi

---

## 🌐 Validasi Kepemilikan Shard & Global State

- Merkle Proof: Verifikasi shard
- Global State Root: Verifikasi seluruh jaringan
- Konsensus promosi Node Level-1 ke Root

---

## ✅ Kesimpulan

Orisium Network dirancang untuk menjadi:

- **Desentralisasi yang kuat**
- **Skalabilitas besar** (hingga miliaran node)
- **Tangguh terhadap manipulasi dan kartel**
- **Efisien secara IPC dan multiproses**
- **Aman untuk masa depan** dengan PQC

Dengan pendekatan **sharding, rolling-answer, dan validasi promosi node**, Orisium siap menjadi fondasi untuk ekosistem blockchain masa depan yang adil dan skalabel.

---

> 🔧 Untuk pertanyaan teknis dan kontribusi, buka [Issues](https://github.com/your-repo/issues) atau kirim PR.
