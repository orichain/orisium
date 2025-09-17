-----

# Orisium

Orisium adalah jaringan *peer-to-peer* (P2P) berperforma tinggi yang dirancang untuk skalabilitas global, ketahanan terhadap serangan, dan desentralisasi yang kuat. Dengan arsitektur hierarkis dinamis dan protokol khusus berbasis UDP, Orisium menciptakan fondasi tangguh untuk aplikasi terdesentralisasi masa depan.

-----

## Fitur Utama

### **Arsitektur Jaringan Hierarkis Dinamis dengan 313 Shard**

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

### **Routing & Reconnect Deterministik**
Protokol ini menjamin konektivitas yang andal melalui sistem *routing* dan pemulihan koneksi yang **deterministik**. Pendekatan ini memastikan setiap *node* dapat menemukan jalurnya di dalam jaringan secara efisien dan dapat memulihkan koneksi secara otomatis jika terjadi kegagalan.

* Setiap *node* klien yang baru akan memulai koneksi pertamanya ke salah satu *Root Node*.
* *Root* akan mengevaluasi topologi jaringan dan mengarahkan *node* tersebut ke *upstream* yang paling sesuai (misalnya, *Node Level-1*) untuk mengoptimalkan rute.
* Setelah terhubung, *node* akan menyimpan informasi *upstream* terbarunya ke basis data lokal. Proses ini memastikan **persistensi sesi** bahkan setelah *restart* atau *crash*.
* Saat *node* mengalami kegagalan atau terputus, ia akan terlebih dahulu mencoba terhubung kembali ke *upstream* yang sama. Jika upaya ini gagal, *node* akan secara otomatis **jatuh kembali (*fallback*) ke *Root Node*** untuk mendapatkan penugasan rute baru.

### **Pemulihan Otomatis dari Kegagalan Node**
Jika sebuah *node* tiba-tiba *down* atau tumbang, jaringan tidak hanya akan memulihkan dirinya di level *downstream* saja, tetapi juga akan **mengganti *node* yang hilang**. Salah satu *downstream* dari *node* yang tumbang akan dipromosikan dan mengambil alih peran *upstream* untuk *downstream* lainnya. Mekanisme ini memastikan bahwa setiap segmen jaringan selalu memiliki *upstream* yang aktif dan mencegah terjadinya `sub-tree` yang terisolasi.

Mekanisme ini menciptakan jaringan yang sangat tangguh, di mana setiap *node* memiliki strategi yang jelas untuk memastikan konektivitas tanpa henti.

### **Custom Protocol di atas UDP**
Untuk memastikan koneksi langsung yang efisien antar-node, Orisium tidak bergantung pada *server* relai yang dapat membebani *bandwidth*. Sebaliknya, kami menggunakan strategi berlapis, dengan **NAT *hole punching* berbasis UDP** sebagai mekanisme utamanya.

*Hole punching* dimungkinkan karena **protokol UDP** yang tidak memiliki koneksi. Teknik ini memungkinkan dua *node* di belakang *firewall* atau NAT untuk secara efisien membuat jalur komunikasi langsung.

Ini sangat penting karena dua alasan:

1.  **Mengurangi Latensi & Menghemat Bandwidth**: Komunikasi langsung jauh lebih cepat daripada menggunakan *server* perantara. Ini juga menghemat sumber daya *server* pusat (seperti *root node* Anda) yang tidak perlu lagi bertindak sebagai relai untuk semua data.
2.  **Meningkatkan Desentralisasi**: Dengan mengurangi ketergantungan pada *server* pusat, kami secara fundamental meningkatkan desentralisasi dan ketahanan jaringan.

Strategi kami adalah mencoba koneksi langsung terlebih dahulu, dan beralih ke *hole punching* jika diperlukan, menjadikannya solusi konektivitas yang kuat, efisien, dan sepenuhnya terdesentralisasi.

## Arsitektur Modular

```
            w-lmdb[1]     r-lmdb[5]
                ▲             ▲
                │             │
                ▼             ▼ 
sio[2] <─────>     master[1]      <─────> cow[5]
                      ▲
                      │
                      ▼
                   Logic[4]

Komunikasi internal / IPC:
Protocol IPC lewat Unix Domain Socket
```

#### 📦 Komponen

| Komponen    | Jumlah  | Tugas Utama |
|-------------|---------|-------------|
| `logic`     | 4       | State machine protokol, kontrol koneksi, handshake, upstream/downstream, reliability |
| `master`    | 1       | Listener UDP utama, membongkar header dan meneruskan ke `sio` |
| `sio`       | 2       | Parsing awal, verifikasi checksum, routing internal paket |
| `cow`       | 5       | Outbound client untuk koneksi horizontal dan upstream. Root membutuhkan hingga 317 sesi aktif, dan satu proses `cow` dapat menangani hingga 65 sesi melalui multiplexing `connection_id`. |
| `r-lmdb`    | 5       | Pembaca database lokal (read-only) |
| `w-lmdb`    | 1       | Penulis database lokal (write-heavy) |

#### 🔌 Komunikasi Internal

- **Unix Domain Socket (UDS)**: Digunakan untuk komunikasi antar proses (IPC), lebih cepat dan aman dibanding TCP/UDP lokal.
- Desain ini menghindari shared memory, mengurangi potensi race condition dan mempermudah debugging tiap modul secara independen.

-----

## Instalasi

```bash
git clone https://github.com/orichain/orisium.git
cd orisium
git submodule update --init --recursive
gmake clean debug
```

-----

## Lisensi

Proyek ini dilisensikan di bawah [Nama Lisensi Anda] - lihat file [LICENSE.md] untuk detailnya.
