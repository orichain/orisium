<p align="center">
<img src="assets/images/orisium.png" alt="Orisium Logo" width="200">
</p>

-----

# Orisium

Orisium adalah jaringan *peer-to-peer* (P2P) berperforma tinggi yang dirancang untuk skalabilitas global, ketahanan terhadap serangan, dan desentralisasi yang kuat. Dengan arsitektur hierarkis dinamis dan protokol khusus berbasis UDP, Orisium menciptakan fondasi tangguh untuk aplikasi terdesentralisasi masa depan.

-----

## Fitur Utama

### **1. Arsitektur Jaringan Hierarkis Dinamis dengan 313 Shard**

Orisium mengadopsi struktur jaringan berlapis untuk skalabilitas dan ketahanan ekstrem. Tidak ada root tetap — root dapat digantikan secara otomatis berdasarkan evaluasi horizontal oleh root lain.

* **313 Shard = 313 Root Node**
  * Setiap root memiliki:
    - **25 downstream** (Level-1)
    - **312 koneksi horizontal** ke root lain (mesh parsial)

* **Node Level-1:**
  - Terhubung ke **1 upstream Root**
  - Memiliki **24 koneksi horizontal** ke Level-1 lain di dalam shard yang sama
  - Dapat memiliki hingga **25 downstream** (Level-2)

* **Node Level-2 hingga Level-4:**
  - Struktur hierarki terus berlanjut dengan pola yang sama
  - Setiap node:
    - **1 upstream**, **24 horizontal**, dan **25 downstream** maksimum

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

Pembagian *shard* dilakukan dengan **hash dari public key/address**. Ini memberikan:

* Sebaran merata
* Kemampuan distribusi tanpa bergantung pada lokasi geografis

Struktur direktori:

```bash
db/hash-prefix/ab/cd/<rest-of-pubkey>/...
```

Struktur address:

```
address = prefix || pubkey || checksum
```

-----

## Arsitektur Modular

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

Komunikasi internal / IPC:
Protocol IPC lewat Unix Domain Socket
```

* **master** menerima koneksi UDP dan mem-forward ke SIO
* **sio** menangani parsing awal dan validasi message
* **logic** menjalankan protokol inti dan semua state machine
* **cow** adalah outbound client untuk horizontal dan upstream

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
