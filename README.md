<p align="center">
<img src="assets/images/orisium.png" alt="Orisium Logo" width="200">
</p>

-----

# Orisium

Orisium adalah jaringan *peer-to-peer* (P2P) berperforma tinggi yang dirancang untuk skalabilitas global, ketahanan terhadap serangan, dan desentralisasi yang kuat. Dengan arsitektur hierarkis dinamis dan protokol khusus berbasis UDP, Orisium menciptakan fondasi tangguh untuk aplikasi terdesentralisasi masa depan.

-----

## Fitur Utama

### **1. Arsitektur Jaringan Hierarkis Dinamis**

Orisium mengadopsi struktur jaringan berlapis untuk skalabilitas dan ketahanan ekstrem. Tidak ada root tetap — root dapat digantikan secara otomatis berdasarkan evaluasi horizontal oleh root lain.

* **Root Node (Maks. 40 Node)**: Titik pusat dalam jaringan untuk masing-masing *shard*. Dapat dijatuhkan oleh sesama root. Bertanggung jawab untuk manajemen upstream-downstream dan sinkronisasi global.
* **Node Level-1 (Maks. 400 Node)**: Terhubung ke **1 upstream Root** dan memiliki **39 koneksi horizontal** ke sesama Level-1 dalam root yang sama. Dapat dijatuhkan oleh Level-1 lain melalui pernyataan resmi, bukan *gossip*.
* **Node Level-2 hingga Level-4**: Meneruskan hierarki dengan pola yang sama. Setiap node memiliki **1 upstream**, **39 horizontal**, dan **hingga 10 downstream**.

### **2. Routing & Reconnect Deterministik**

Setiap node klien:

1. Pertama kali terkoneksi ke Root.
2. Root mengarahkan ke upstream yang sesuai (misalnya Level-1).
3. Node menyimpan info upstream ke file/DB lokal.
4. Saat restart atau kegagalan, node mencoba reconnect ke upstream lama, dan fallback ke Root jika gagal.
5. Upstream dapat mengarahkan node untuk mengganti upstream.

### **3. Custom Protocol di atas UDP**

Orisium tidak menggunakan TCP untuk koneksi antar-node. Seluruh komunikasi antar-node dijalankan dengan protokol ringan custom-built di atas UDP, memungkinkan:

* Latensi sangat rendah
* Tidak tergantung handshake TCP
* Implementasi kontrol jendela (*window control*), urutan pesan, dan retransmisi secara manual.

Fungsi `find_or_create_session()` menyimpan info sesi termasuk `connection_id`, `addr`, dan status handshaking, dengan window awal default misalnya 150000 byte.

### **4. Sharding Berdasarkan Public Key (Hashing)**

Pembagian *shard* tidak lagi berdasarkan zona waktu, melainkan menggunakan **hash dari public key/address**. Ini memberikan:

* Sebaran merata
* Kemampuan distribusi tanpa bergantung pada lokasi geografis
* Direktori seperti:

```bash
db/hash-prefix/ab/cd/<rest-of-pubkey>/...
```

Struktur address:

```
address = prefix || pubkey || checksum
```

-----

### **5. Arsitektur Proses & Komunikasi Internal**

Orisium menggunakan pemisahan proses berbasis modul dengan skema IPC efisien melalui Unix Domain Socket. Setiap proses bertanggung jawab atas satu tugas spesifik, mempermudah debugging dan penskalaan.

```
            w-lmdb[1]     r-lmdb[5]
                ▲             ▲
                │             │
                ▼             ▼ 
sio[2] <─────>     master[1]      <─────> cow[45]
                      ▲
                      │
                      ▼
                   Logic[4]
```

#### 📦 Komponen

| Komponen    | Jumlah | Tugas Utama |
|-------------|--------|-------------|
| `logic`     | 4      | State machine protokol, kontrol koneksi, handshake, upstream/downstream, reliability |
| `master`    | 1      | Listener UDP utama, membongkar header dan meneruskan ke `sio` |
| `sio`       | 2      | Parsing awal, verifikasi checksum, routing internal paket |
| `cow`       | 45     | Client outbound untuk koneksi horizontal dan upstream |
| `r-lmdb`    | 5      | Pembaca database lokal (read-only) |
| `w-lmdb`    | 1      | Penulis database lokal (write-heavy) |

#### 🔌 Komunikasi Internal

- **Unix Domain Socket (UDS)**: Digunakan untuk komunikasi antar proses (IPC), lebih cepat dan aman dibanding TCP/UDP lokal.
- Desain ini menghindari shared memory, mengurangi potensi race condition dan mempermudah debugging tiap modul secara independen.

-----

## Instalasi

```bash
git clone https://github.com/yourusername/orisium.git
cd orisium
make
./orisium_master
```

-----

## Penggunaan

```bash
./orisium_master --config master.json
./orisium_node --config node1.json
```

-----

## Lisensi

Proyek ini dilisensikan di bawah [Nama Lisensi Anda] - lihat file [LICENSE.md] untuk detailnya.
