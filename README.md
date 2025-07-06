<p align="center">
<img src="assets/images/orisium.png" alt="Orisium Logo" width="200">
</p>

-----

# Orisium

Orisium adalah jaringan *peer-to-peer* (P2P) berperforma tinggi yang dirancang untuk skalabilitas global, ketahanan terhadap serangan, dan desentralisasi yang kuat. Dengan arsitektur hierarkis yang dinamis dan mekanisme keamanan berlapis, Orisium menciptakan fondasi tangguh untuk aplikasi terdesentralisasi masa depan.

-----

## Fitur Utama

### **1. Arsitektur Jaringan Hierarkis Dinamis**

Orisium mengadopsi struktur jaringan berlapis yang unik untuk skalabilitas dan ketahanan. Jaringan Root didasarkan pada sekitar **40 *zona waktu* unik** di seluruh dunia, yang secara langsung memetakan ke *shard* data.

  * **Node Root Bootstrap (3 Node)**: Ini adalah **fondasi awal jaringan** yang stabil, di-*hardcode* untuk mewakili 3 *zona waktu* spesifik yang berdekatan. Mereka adalah bagian dari total 40 Node Root, memiliki konektivitas horizontal terluas (terhubung ke semua 39 Node Root lainnya), dan **harus menyimpan basis data lengkap setiap *shard* *zona waktu***. Meskipun krusial di awal, node Bootstrap ini **dapat turun level** jika tidak mampu, namun akan tetap **menyediakan daftar IP** untuk membantu node baru menemukan jaringan.
  * **Node Root (Maks. 40 Node)**: Ini adalah **tulang punggung utama *sharding* *zona waktu***. Setiap Node Root secara eksklusif **mewakili satu dari sekitar 40 *zona waktu* unik** dan **harus menyimpan basis data lengkap** untuk *shard* tersebut. Setiap Node Root **terhubung ke semua 39 Node Root lainnya** untuk konsensus yang cepat dan penyebaran informasi global. Setiap Node Root dapat mengelola hingga **10 koneksi *Downstream* ke Node Level-1**. Node Root mengelola sub-jaringan di bawahnya dan dapat menjatuhkan level *horizontalstream* yang melanggar syarat.
  * **Node Level-1 (Maks. 400 Node)**: Berperan sebagai perantara penting di dalam *shard* *zona waktu* mereka. Node Level-1 memiliki **satu koneksi *Upstream* ke sebuah Node Root** dan **39 koneksi *Horizontalstream* ke Node Level-1 lainnya yang memiliki Root *Upstream* yang sama**. Node Level-1 dapat mengelola hingga **10 koneksi *Downstream* ke Node Level-2**. Node Level-1 sangat vital karena mereka dapat **berpindah *Upstream* Root** jika tidak memenuhi syarat, dan bahkan **mempromosikan diri menjadi Root baru** untuk mengisi slot kosong atau menggantikan Root yang bermasalah.
  * **Node Level-2 (Maks. 4000 Node)**: Terhubung ke **satu *Upstream* Node Level-1** dan memiliki **39 koneksi *Horizontalstream* ke Node Level-2 lainnya yang memiliki Root *Upstream* yang sama**. Setiap Node Level-2 dapat mengelola hingga **10 koneksi *Downstream* ke Node Level-3**. Node ini berfungsi memperluas jangkauan jaringan.
  * **Node Level-3 (Maks. 40000 Node)**: Terhubung ke **satu *Upstream* Node Level-2** dan memiliki **39 koneksi *Horizontalstream* ke Node Level-3 lainnya yang memiliki Root *Upstream* yang sama**. Setiap Node Level-3 dapat mengelola hingga **10 koneksi *Downstream* ke Node Level-4**. Node ini lebih lanjut memperluas jangkauan jaringan.
  * **Node Level-4 (Maks. 400000 Node)**: Lapisan terluar jaringan, terhubung ke **satu *Upstream* Node Level-3** dan memiliki **39 koneksi *Horizontalstream* ke Node Level-4 lainnya yang memiliki Root *Upstream* yang sama**. Node Level-4 bertanggung jawab untuk jangkauan massal ke pengguna akhir dan **tidak memiliki koneksi *Downstream***.

### **2. *Sharding* Berbasis *Zona Waktu* pada *Public Key***

Orisium memanfaatkan konsep *sharding* inovatif untuk distribusi data dan optimasi kinerja global:

  * **Identitas Tersemat *Zona Waktu***: Setiap Alamat/*Public Key* pengirim transaksi secara eksplisit **menyematkan kode *zona waktu*** saat dibuat. Kode ini berfungsi sebagai ***shard key*** yang deterministik, memastikan alamat tersebut terkait dengan *shard* *zona waktu* tertentu.
  * **Optimalisasi Latensi Regional**: Transaksi dan data yang terkait dengan alamat dari *zona waktu* tertentu secara otomatis diarahkan ke *shard* yang relevan (dikelola oleh Node Root dalam *zona waktu* tersebut), secara signifikan mengurangi latensi bagi pengguna di wilayah yang sama.
  * **Penanganan Perubahan *Zona Waktu***: Jika pengguna bertransaksi dari *zona waktu* yang berbeda dari *zona waktu* yang disematkan pada alamat mereka, sistem akan mendeteksi dan memberi **peringatan, merekomendasikan pembuatan alamat baru** untuk kinerja optimal. Transaksi tetap dapat diproses menggunakan alamat lama, namun dengan potensi latensi yang lebih tinggi karena memerlukan komunikasi antar-*shard* yang melibatkan Node Root.

### **3. Mekanisme Keamanan dan Ketahanan Canggih**

Orisium mengimplementasikan pertahanan berlapis terhadap serangan dan beban berlebih:

  * **Manajemen Koneksi Efisien (`epoll`/`kqueue`)**: Menggunakan `epoll`\`kqueue` untuk I/O *non-blocking* yang efisien, memungkinkan penanganan ribuan koneksi secara bersamaan dengan *overhead* minimal.
  * ***Rate Limiting* Agresif (5 Detik)**: Mencegah klien membanjiri server dengan permintaan koneksi berulang. Klien yang melanggar akan dikenai penalti perpanjangan waktu, membuat penyerang atau *bot* sederhana sulit untuk terhubung. Klien P2P yang terprogram dengan baik mengimplementasikan strategi *backoff* yang selaras dengan waktu *rate limit* ini untuk pengalaman yang mulus.
  * ***Inactivity Timeout***: Secara proaktif membersihkan koneksi yang tidak aktif atau mati, mencegah *resource exhaustion* dan serangan *slowloris*.
  * **Pencegahan Koneksi Ganda**: Menolak koneksi dari IP yang sudah memiliki sesi aktif, membatasi *resource* yang dapat dihabiskan oleh satu sumber.
  * **Batas Sesi Global**: Menjaga jumlah sesi aktif maksimum untuk melindungi stabilitas server.

### **4. Distribusi Beban Cerdas**

Orisium memastikan alokasi beban kerja yang efisien untuk kinerja optimal:

  * ***Load Balancing* Adaptif**: Pemilihan *worker* IO untuk koneksi baru tidak hanya berdasarkan *Round-Robin*, tetapi memprioritaskan *worker* yang **terakhir kali menyelesaikan tugas terlama**. Ini memastikan distribusi beban yang lebih adaptif dan efisien.

-----

## Arsitektur

Arsitektur Orisium mengintegrasikan berbagai komponen dan level node untuk menciptakan jaringan yang kuat, dengan detail alur internal sebagai berikut:

```
master --> sio (server IO) <--> logic <--> cow (client outbound)
  ^                               ^
  |                               |
  v                               v 
  ---------------------------------  (Laporan/Status ke Master)
Komunikasi internal / IPC:
Protocol IPC lewat Unix Domain Socket
```

### **1. Master**

**Master** adalah orkestrator utama dan titik masuk node. Perannya adalah mengelola koneksi masuk dan memantau kesehatan node secara keseluruhan.

  * **Menerima Koneksi Masuk**: Master menerima koneksi jaringan baru dari *peer* atau klien.
  * **Mengarahkan ke Sio**: Master secara langsung meneruskan koneksi yang baru diterima (biasanya sebagai *file descriptor*) ke **Sio** *worker* yang sesuai untuk penanganan I/O.
  * **Menerima Laporan Konsolidasi**: Master menerima metrik kinerja, *event* penting, dan laporan status dari **Logic**, bukan dari Sio atau Cow secara langsung. Ini membantu Master mempertahankan pandangan tingkat tinggi untuk *load balancing* dan manajemen node.

### **2. Sio (Server I/O Workers)**

**Sio** *worker* adalah penangan jaringan **masuk** khusus node. Mereka bertanggung jawab atas semua data yang mengalir *ke dalam* node dari koneksi yang diterima oleh Master.

  * **Menangani Data Masuk**: Sio *worker* melakukan operasi baca/tulis *non-blocking* pada koneksi yang mereka kelola. Mereka bertanggung jawab untuk penerimaan data mentah dan *parsing* awal pesan masuk.
  * **Memberi Umpan ke Logic**: Setiap pesan atau data yang di-*parse* yang memerlukan pemahaman tingkat aplikasi, validasi, atau respons **harus** diteruskan ke **Logic**. Sio tidak memulai respons atau koneksi eksternal sendiri; ia bertindak sebagai jembatan ke Logic.
  * **Melapor via Logic**: Semua pembaruan status, kesalahan, atau metrik operasional dari Sio harus terlebih dahulu melalui **Logic** sebelum berpotensi diteruskan ke Master.

### **3. Logic**

**Logic** adalah unit pemrosesan sentral node. Ini adalah satu-satunya komponen yang memiliki pemahaman komprehensif tentang protokol jaringan, status node, dan bagaimana node berinteraksi. Logic bertindak sebagai **perantara tunggal** untuk semua aliran data penting.

  * **Eksekusi Protokol Inti**: Logic menerima pesan yang di-*parse* dari Sio, memvalidasinya terhadap aturan Orisium, memproses transaksi, mengkueri basis data node, dan berpartisipasi dalam mekanisme konsensus (khususnya untuk Node Root).
  * **Mengarahkan Aliran Keluar**: Berdasarkan pemrosesannya, Logic mengorkestrasi semua komunikasi keluar:
      * **Respons via Sio**: Jika sebuah respons perlu dikirim kembali melalui koneksi masuk awal, Logic mengirimkan data yang telah diproses kembali ke Sio *worker* yang relevan.
      * **Koneksi Eksternal via Cow**: Jika node perlu memulai koneksi baru ke *peer* lain (misalnya, membuat koneksi horizontal) atau mengirim data melalui koneksi keluar yang sudah ada, Logic mengeluarkan perintah dan data ke **Cow**.
  * **Mengkonsolidasikan Laporan untuk Master**: Logic mengumpulkan dan memproses berbagai laporan (dari Sio, Cow, dan status internalnya sendiri) dan kemudian **mengirimkan laporan yang terkonsolidasi ini ke Master**. Ini memastikan Master menerima informasi yang disaring dan relevan untuk tugas manajemen tingkat tingginya.

### **4. Cow (Client Outbound Writer)**

**Cow** didedikasikan khusus untuk mengelola dan mengeksekusi semua **koneksi jaringan keluar** serta transmisi data dari node Orisium ke *peer* lain dalam jaringan.

  * **Mengelola Koneksi Keluar**: Cow membangun dan memelihara semua koneksi keluar yang diperlukan, seperti 39 koneksi horizontal ke Node Root lainnya, atau koneksi ke node *Upstream*.
  * **Mengirim Data Keluar**: Cow menerima data dan perintah dari **Logic** dan secara efisien mengirimkannya melalui koneksi keluar yang relevan.
  * **Melapor via Logic**: Mirip dengan Sio, setiap pembaruan status, kesalahan, atau pemutusan koneksi yang terkait dengan koneksi keluar dilaporkan dari Cow ke **Logic**. Cow tidak berkomunikasi langsung dengan Master.

### **5. Mekanisme Penyimpanan Data Otomatis & Validasi Shard (Semua Level)**

Setiap node Orisium (kecuali mungkin Level-4 yang bisa hanya menjadi klien murni) dirancang untuk secara cerdas mengelola penyimpanan data *shard* berdasarkan kapasitas sumber daya yang tersedia, serta memvalidasi dan melaporkan integritas data tersebut. Fitur ini sangat penting untuk efisiensi, keandalan, dan desentralisasi jaringan, terutama bagi node yang bercita-cita untuk promosi:

  * **Pendeteksian Ruang Disk**: Node akan secara otomatis **mendeteksi ketersediaan ruang hard disk** saat beroperasi atau memulai ulang.
  * **Penyimpanan Kondisional**:
      * Jika node mendeteksi ada **ruang hard disk yang mencukupi** (sesuai ambang batas yang ditentukan sistem), node tersebut akan **mulai atau melanjutkan proses penyimpanan data *shard*** yang relevan dengan *zona waktu*-nya.
      * Namun, jika ruang hard disk **tidak memenuhi syarat** atau mencapai batas minimum, node akan **menghentikan proses penyimpanan data *shard***. Ini mencegah *resource exhaustion* dan memastikan node tetap stabil untuk tugas-tugas vital lainnya.
  * **Validasi Data Shard Lokal**: Saat node level bawah berhasil menyimpan atau memperbarui data *shard* secara lokal (misalnya, setelah menerima blok baru atau *snapshot* dari *Upstream* mereka), mereka akan melakukan **validasi internal** terhadap data tersebut. Ini mengurangi kebutuhan untuk selalu bertanya ke Root untuk data yang sudah dimiliki.
  * **Pelaporan dan *Signature* Root**: Setelah validasi lokal sukses, node level bawah akan **memberi laporan ke Root *Upstream*** mereka. Root node, setelah memverifikasi keabsahan laporan tersebut, akan memberikan **tanda tangan digital (*signature*)** yang berfungsi sebagai "sertifikat kelengkapan data". *Signature* ini mengonfirmasi bahwa node level bawah memiliki salinan data *shard* yang otentik dan terkini dari Root.
  * **Prasyarat Promosi**: Kemampuan untuk menyimpan data *shard* yang valid dan memiliki *signature* dari Root adalah **syarat penting** bagi node di Level-1, Level-2, Level-3, dan Level-4 yang ingin memenuhi syarat untuk dipromosikan ke level yang lebih tinggi. Ini memastikan node yang naik level sudah memiliki data yang diperlukan dan terverifikasi.

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
./orisium_p2p_client --address <public_key_anda> --connect <ip_root>
```

-----

## Kontribusi

Kami menyambut kontribusi\! Silakan baca panduan kontribusi kami dan ajukan *pull request*.

-----

## Lisensi

Proyek ini dilisensikan di bawah [Nama Lisensi Anda] - lihat file [LICENSE.md] untuk detailnya.
