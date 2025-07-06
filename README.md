<p align="center">
<img src="assets/images/orisium.png" alt="Orisium Logo" width="200">
</p>

-----

# Orisium

Orisium adalah jaringan *peer-to-peer* (P2P) berkinerja tinggi yang dirancang untuk skalabilitas global, ketahanan terhadap serangan, dan desentralisasi yang kuat. Menggabungkan arsitektur hierarkis yang dinamis dengan mekanisme keamanan berlapis, Orisium menciptakan fondasi yang tangguh untuk aplikasi terdesentralisasi masa depan.

-----

## Fitur Utama

### **1. Arsitektur Jaringan Hierarkis Dinamis**

Orisium mengadopsi struktur jaringan berlapis yang unik untuk skalabilitas dan ketahanan. Jaringan Root didasarkan pada sekitar **40 *timezone* unik** di seluruh dunia, yang secara langsung memetakan ke *shard* data.

  * **Node Root Bootstrap (3 Node)**: Ini adalah **fondasi awal jaringan** yang stabil, yang di-*hardcode* untuk mewakili 3 *timezone* spesifik yang berdekatan. Mereka adalah bagian dari total 40 Node Root, memiliki konektivitas horizontal terluas (terhubung ke semua 39 Node Root lainnya), dan **harus menyimpan database lengkap setiap *shard* *timezone***. Meskipun krusial di awal, node Bootstrap ini **dapat turun level** jika tidak mampu, namun akan tetap **menyediakan daftar IP** untuk membantu node baru menemukan jaringan.
  * **Node Root (Maks. 40 Node)**: Ini adalah **tulang punggung utama sharding *timezone***. Setiap Node Root secara eksklusif **mewakili satu dari sekitar 40 *timezone* unik** dan **harus menyimpan database lengkap** untuk *shard* tersebut. Setiap Node Root **terhubung ke semua 39 Node Root lainnya** untuk konsensus yang cepat dan penyebaran informasi global. Root node mengelola sub-jaringan di bawahnya dan dapat menjatuhkan level *Horizontalstream* yang melanggar syarat.
  * **Node Level-1 (Maks. 400 Node)**: Berperan sebagai perantara penting di dalam *shard timezone* mereka. Node Level-1 memiliki **satu koneksi Upstream ke sebuah Node Root** dan **39 koneksi Horizontalstream ke Node Level-1 lainnya yang memiliki Root Upstream yang sama**. Node Level-1 sangat vital karena mereka dapat **berpindah Upstream Root** jika tidak memenuhi syarat, dan bahkan **mempromosikan diri menjadi Root baru** untuk mengisi slot kosong atau menggantikan Root yang bermasalah.
  * **Node Level-2 (Maks. 4000 Node)**: Terhubung ke **satu Upstream Node Level-1** dan memiliki **39 koneksi Horizontalstream ke Node Level-2 lainnya yang memiliki Root Upstream yang sama**. Node ini berfungsi memperluas jangkauan jaringan.
  * **Node Level-3 (Maks. 40000 Node)**: Terhubung ke **satu Upstream Node Level-2** dan memiliki **39 koneksi Horizontalstream ke Node Level-3 lainnya yang memiliki Root Upstream yang sama**. Node ini lebih lanjut memperluas jangkauan jaringan.
  * **Node Level-4 (Maks. 400000 Node)**: Lapisan terluar jaringan, terhubung ke **satu Upstream Node Level-3** dan memiliki **39 koneksi Horizontalstream ke Node Level-4 lainnya yang memiliki Root Upstream yang sama**. Node Level-4 bertanggung jawab untuk jangkauan massal ke pengguna akhir.

-----

### **2. Sharding Berbasis Timezone pada Public Key**

Orisium memanfaatkan konsep *sharding* inovatif untuk distribusi data dan optimasi kinerja global:

  * **Identitas Tersemat Timezone**: Setiap Alamat/Public Key pengirim transaksi secara eksplisit **menyematkan kode *timezone*** saat dibuat. Kode ini berfungsi sebagai **shard key** yang deterministik, memastikan alamat tersebut terkait dengan *shard timezone* tertentu.
  * **Optimalisasi Latensi Regional**: Transaksi dan data yang terkait dengan alamat dari *timezone* tertentu secara otomatis diarahkan ke *shard* yang relevan (dikelola oleh Node Root dalam *timezone* tersebut), secara signifikan mengurangi latensi bagi pengguna di wilayah yang sama.
  * **Penanganan Perubahan Timezone**: Jika pengguna bertransaksi dari *timezone* yang berbeda dari *timezone* yang disematkan pada alamat mereka, sistem akan mendeteksi dan memberi **peringatan, merekomendasikan pembuatan alamat baru** untuk kinerja optimal. Transaksi tetap dapat diproses menggunakan alamat lama, namun dengan potensi latensi yang lebih tinggi karena memerlukan komunikasi antar-shard yang melibatkan Node Root.

-----

### **3. Mekanisme Keamanan dan Ketahanan Canggih**

Orisium mengimplementasikan pertahanan berlapis terhadap serangan dan beban berlebih:

  * **Manajemen Koneksi Efisien (epoll)**: Menggunakan `epoll` untuk I/O *non-blocking* yang efisien, memungkinkan penanganan ribuan koneksi secara bersamaan dengan *overhead* minimal.
  * ***Rate Limiting* Agresif (5 Detik)**: Mencegah klien membanjiri server dengan permintaan koneksi berulang. Klien yang melanggar akan dikenai penalti perpanjangan waktu, membuat penyerang atau *bot* sederhana sulit untuk terhubung. Klien P2P yang terprogram dengan baik mengimplementasikan strategi *backoff* yang selaras dengan waktu *rate limit* ini untuk pengalaman yang mulus.
  * ***Inactivity Timeout***: Secara proaktif membersihkan koneksi yang tidak aktif atau mati, mencegah *resource exhaustion* dan serangan *slowloris*.
  * **Pencegahan Koneksi Ganda**: Menolak koneksi dari IP yang sudah memiliki sesi aktif, membatasi *resource* yang dapat dihabiskan oleh satu sumber.
  * **Batas Sesi Global**: Menjaga jumlah sesi aktif maksimum untuk melindungi stabilitas server.

-----

### **4. Distribusi Beban Cerdas**

Orisium memastikan alokasi beban kerja yang efisien untuk kinerja optimal:

  * ***Load Balancing* Adaptif**: Pemilihan *worker* IO untuk koneksi baru tidak hanya berdasarkan *Round-Robin*, tetapi memprioritaskan *worker* yang **terakhir kali menyelesaikan tugas terlama**. Ini memastikan distribusi beban yang lebih adaptif dan efisien.

-----

## Arsitektur

Arsitektur Orisium mengintegrasikan berbagai komponen dan level node untuk menciptakan jaringan yang kuat:

  * **Master Node**: Bertanggung jawab untuk menerima koneksi baru, menerapkan *rate limiting*, menentukan *shard* berdasarkan *timezone* dari alamat, memilih *worker* yang tepat, dan meneruskan *file descriptor* klien ke *worker* yang dipilih melalui Unix Domain Sockets (UDS). Juga mengelola daftar `closed_correlation_id_t` untuk *rate limiting* dan `sio_worker_stats` untuk *load balancing* *worker*.
  * **Server IO Workers**: Menerima *file descriptor* klien dari *master* melalui UDS dan bertanggung jawab untuk menangani komunikasi P2P yang sebenarnya dengan klien/peer. Setelah menyelesaikan tugas, mereka melaporkan status kembali ke *master* untuk pembaruan *load balancing*.
  * **Shard Databases (di Node Root)**: Setiap Node Root menyimpan database lengkap untuk *shard* *timezone* yang diwakilinya, termasuk informasi alamat, saldo, tanda tangan transaksi, dan badan transaksi. Node-node ini adalah sumber otoritatif untuk *shard* mereka.
  * **Node Downstream (Level-1, Level-2, Level-3, Level-4)**: Bertindak sebagai perpanjangan tangan dari jaringan *Root*, memperluas jangkauan dan mendistribusikan beban. Mereka memelihara koneksi `Upstream` dan `Horizontalstream` yang ketat sesuai definisi levelnya, memastikan komunikasi yang efisien dalam *shard* mereka sendiri. Mereka juga memiliki hak untuk berpindah `Upstream` atau bahkan naik level menjadi `Root` jika memenuhi syarat.

-----

## Instalasi

(Bagian ini akan berisi petunjuk instalasi proyek Anda. Contoh: mengkompilasi dari sumber, dependensi.)

```bash
# Contoh langkah-langkah instalasi
git clone https://github.com/yourusername/orisium.git
cd orisium
make
./orisium_server
```

-----

## Penggunaan

(Bagian ini akan berisi contoh cara menjalankan dan berinteraksi dengan proyek Anda, baik sebagai *master*, *worker*, atau *node* P2P lainnya.)

```bash
# Contoh perintah penggunaan
./orisium_server --role master --config master_config.json
./orisium_worker --id 1 --config worker_config.json
./orisium_p2p_client --address <your_public_key> --connect <root_ip>
```

-----

## Kontribusi

Kami menyambut kontribusi\! Silakan baca panduan kontribusi kami dan ajukan *pull request*.

-----

## Lisensi

Proyek ini dilisensikan di bawah [Nama Lisensi Anda] - lihat file [LICENSE.md] untuk detailnya.
