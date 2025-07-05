\<p align=\"center\"\> \<img src=\"assets/images/orisium.png\"
alt=\"Orisium Logo\" width=\"200\"\> \</p\>

Orisium Network: Arsitektur Jaringan Terdesentralisasi Pendahuluan
Orisium adalah sebuah jaringan terdesentralisasi yang dirancang untuk
operasi multiproses yang aman, efektif, dan cepat. Arsitektur ini
mengadopsi model hierarkis dengan berbagai tingkatan node, masing-masing
memiliki definisi, kewajiban, dan hak yang spesifik. Tujuan utama
Orisium adalah menciptakan ekosistem yang tangguh, terukur, dan tahan
terhadap manipulasi, didukung oleh kriptografi pasca-kuantum (PQC) dan
mekanisme konsensus yang cerdas.

Struktur Jaringan Hierarkis Jaringan Orisium dibangun di atas struktur
berlapis yang memungkinkan skalabilitas besar dan distribusi tanggung
jawab. Lapisan-lapisan ini didefinisikan sebagai berikut:

Node Root Bootstrap: Node awal yang menjadi titik masuk dan jangkar
stabilitas jaringan.

Node Root: Node inti yang bertanggung jawab untuk menjaga integritas
database global dan mengelola lapisan di bawahnya.

Node Level-1 hingga Level-7: Node-node di lapisan bawah yang berfungsi
sebagai perantara, memproses transaksi, dan memperluas jangkauan
jaringan.

Batas Maksimal Node per Level:

Node Root Bootstrap: Maksimal 3 node (awalnya 3 node bootstrap).

Node Root: Maksimal 313 node.

Node Level-1: Maksimal 3.130 node.

Node Level-2: Maksimal 31.300 node.

Node Level-3: Maksimal 313.000 node.

Node Level-4: Maksimal 3.130.000 node.

Node Level-5: Maksimal 31.300.000 node.

Node Level-6: Maksimal 313.000.000 node.

Node Level-7: Maksimal 3.130.000.000 node.

Setiap node dalam jaringan mempertahankan koneksi dengan:

Downstream: Node di level yang lebih rendah yang terhubung langsung
dengannya.

Horizontalstream: Node di level yang sama yang terhubung langsung
dengannya.

Upstream: Node di level yang lebih tinggi yang terhubung langsung
dengannya (hanya untuk Level-1 ke bawah).

Jenis Node dan Tanggung Jawab 3.1. Node Root Bootstrap Definisi:

Minimal Downstream: 0

Maksimal Downstream: 10

Minimal Horizontalstream: 2

Maksimal Horizontalstream: 312

Kewajiban dan Hak:

Imutabilitas Nama Domain: Nama domain tidak boleh berubah sejak pertama
kali muncul. Ini diverifikasi melalui sertifikat yang terikat dengan
Public Key node dan mekanisme DNSSEC.

Penyimpanan Database Lengkap (dalam Konteks Sharding):

Global Database File Transaksi: Menyimpan seluruh riwayat transaksi
jaringan. Dalam arsitektur sharded, \"database lengkap\" untuk Node Root
berarti:

Memiliki data lengkap dan tersinkronisasi untuk semua shard yang menjadi
tanggung jawabnya.

Mampu memverifikasi integritas seluruh Global State jaringan, meskipun
tidak menyimpan semua data dari shard lain. Ini dilakukan melalui
mekanisme Global State Root (lihat Bagian 4.1).

Address -\> Publickey (PQC): Pemetaan alamat ke kunci publik PQC.

Address -\> Saldo: Status saldo untuk setiap alamat.

Sig-Hash -\> Signature (PQC): Hash dari tanda tangan untuk verifikasi.

Trx-Hash -\> Trx Body: Isi lengkap transaksi.

Mekanisme Konsensus: Untuk menjaga konsistensi dan integritas database
ini, node root bootstrap dan node root lainnya akan berpartisipasi dalam
mekanisme konsensus terdistribusi (misalnya, modifikasi Paxos atau Raft)
untuk mencapai kesepakatan pada setiap pembaruan state global.
Penggunaan Merkle Tree akan memverifikasi integritas data secara
efisien.

Database Memori Node Downstream: Cache data penting tentang node
Downstream yang terhubung.

Address -\> IP

Address -\> Level

Address -\> Downstream (jumlah)

Address -\> Performa (Jaringan, Jumlah Downstream): Metrik performa yang
spesifik (latency, bandwidth, uptime, responsivitas).

Konektivitas Minimum: Wajib memiliki \"Minimal Downstream\" dan
\"Minimal Horizontalstream\".

Menjawab Pertanyaan Horizontalstream:

Pertanyaan tentang syarat 1-3 (definisi node, konektivitas).

Pertanyaan tentang syarat 4 (performa, jumlah Downstream): Jawaban harus
\"rolling\" atau berubah-ubah untuk menghindari kartel. Ini
diimplementasikan dengan teknik kriptografi seperti turunan hash dengan
nonce acak atau VRF, yang membuat jawaban tidak dapat diprediksi namun
dapat diverifikasi.

Membuat Laporan Horizontalstream: Laporan pertanyaan tentang syarat 1-4.

Hak Menjatuhkan Level Horizontalstream: Hanya Node Root yang bisa
menjatuhkan level Node Root Horizontalstream-nya. Mekanisme ini
memerlukan konsensus dari mayoritas Node Root lainnya untuk mencegah
penyalahgunaan, didasarkan pada sistem reputasi atau poin penalti yang
lebih toleran terhadap kegagalan sementara.

Hak Naik Level Kembali: 5 menit setelah turun level.

Menjawab Pertanyaan Downstream:

Pertanyaan tentang syarat 1-3.

Jawaban harus \"rolling\" atau berubah-ubah untuk menghindari kartel.

Membuat Laporan Downstream: Address -\> Performa, dan laporan pertanyaan
tentang syarat menjadi root.

Memverifikasi Koneksi Root Baru: Proses handshake kriptografis yang
kuat, di mana node root baru harus membuktikan kepemilikannya atas
Public Key yang terdaftar dengan menandatangani tantangan.

Hak Voting VRF: Berpartisipasi dalam voting Variable Random Function
(VRF), yang dapat digunakan untuk pemilihan validator, penambang, atau
penentuan hak istimewa lainnya dalam jaringan.

Penurunan Level: Hanya bisa dijatuhkan levelnya oleh
Horizontalstream-nya (dengan konsensus Root).

3.2. Node Root (Non-Bootstrap) Definisi:

Minimal Downstream: 5

Maksimal Downstream: 10

Minimal Horizontalstream: 5

Maksimal Horizontalstream: 312

Kewajiban dan Hak:

Hampir sama dengan Node Root Bootstrap, dengan perbedaan pada minimal
Downstream dan Horizontalstream.

Perbedaan Utama: Memberikan pengumuman resmi kepada Downstream milik
Horizontalstream yang dijatuhkan levelnya. Ini adalah fungsi penting
untuk menjaga konsistensi dan memungkinkan node Downstream untuk mencari
Upstream baru.

3.3. Node Level-1 Definisi:

Minimal Downstream: 0

Maksimal Downstream: 10

Fixed Horizontalstream: 9

Fixed Pertanyaan Jumlah Horizontalstream: 2 (node ini akan bertanya ke 2
Horizontalstream tentang jumlah Horizontalstream mereka)

Fixed Upstream: 1

Kewajiban dan Hak:

Konektivitas Minimum: Wajib memiliki \"Minimal Downstream\", \"Fixed
Upstream\", dan \"Fixed Horizontalstream\".

Manajemen Upstream: Meninggalkan Upstream-nya/berpindah Upstream/mencari
Upstream lain jika Upstream-nya saat ini tidak memenuhi syarat
(misalnya, latency tinggi, tidak merespons, memberikan informasi salah).
Mekanisme penemuan Upstream baru melibatkan querying Horizontalstream
atau node root yang diketahui.

Menjawab Pertanyaan Downstream:

Pertanyaan tentang syarat 1-2.

Pertanyaan tentang syarat 3 (\"Fixed Pertanyaan Jumlah
Horizontalstream\"): Jawaban harus \"rolling\" untuk menghindari kartel.

Pemberitahuan Kehilangan Upstream: Memberikan pengumuman kepada
Downstream-nya jika kehilangan Upstream.

Hak Naik Level: Berhak naik level jika ada slot kosong dan merasa
memenuhi syarat. Syarat \"mampu\" berarti node tersebut telah memilih
satu atau beberapa shard yang ingin dikelolanya sebagai Node Root, dan
telah memiliki salinan database lengkap untuk shard(s) tersebut serta
tersinkronisasi penuh dengan Global State Root jaringan. Membutuhkan
verifikasi performa dan konsistensi data oleh Upstream potensial.

3.4. Node Level-2 hingga Level-7 Definisi:

Minimal Downstream: 0

Maksimal Downstream: 10

Fixed Horizontalstream: 9

Fixed Pertanyaan Jumlah Horizontalstream: 2

Fixed Upstream: 1

Kewajiban dan Hak:

Sama dengan Node Level-1. Struktur dan tanggung jawabnya konsisten di
seluruh lapisan bawah untuk menyederhanakan implementasi dan
pemeliharaan.

4\. Manajemen Data 4.1. Global Database File Transaksi Disimpan secara
terdistribusi di semua Node Root Bootstrap dan Node Root melalui
mekanisme sharding.

Sharding (Partisi Database Global): Database dibagi menjadi
bagian-bagian yang lebih kecil (shard) berdasarkan kunci sharding
(misalnya, rentang Address atau hash dari Address). Setiap Node Root
bertanggung jawab atas satu atau beberapa shard.

Manfaat: Mengurangi beban penyimpanan dan I/O pada satu node,
memungkinkan pemrosesan paralel di beberapa node, dan meningkatkan
skalabilitas.

Mekanisme Query Lintas Shard: Node Root akan memiliki tabel routing
shard atau mekanisme discovery untuk menemukan Node Root mana yang
menyimpan data yang diminta jika data tersebut berada di shard lain.

Konsistensi Data dan Global State Root:

Untuk menjaga konsistensi dan integritas database di seluruh shard,
jaringan akan mengadopsi konsep Global State Root.

Setiap shard akan memiliki Merkle Root-nya sendiri, yang secara
kriptografis merangkum semua data dan transaksi dalam shard tersebut.

Global State Root adalah Merkle Root yang dihasilkan dari semua Merkle
Root shard individu. Ini adalah representasi kriptografis dari seluruh
keadaan jaringan pada waktu tertentu.

Setiap kali blok baru difinalisasi (melalui konsensus VRF), Global State
Root diperbarui dan disepakati oleh semua Node Root.

Verifikasi Integritas: Node Root (dan node lain yang relevan) dapat
memverifikasi integritas seluruh Global Database dengan memverifikasi
Merkle Root shard mereka sendiri dan kemudian memverifikasi bahwa Merkle
Root shard tersebut (bersama dengan Merkle Root dari shard lain yang
diterima dari Node Root lain) berkontribusi dengan benar pada Global
State Root yang disepakati.

Integritas Data: Penggunaan Merkle Tree untuk setiap blok transaksi atau
snapshot database memungkinkan verifikasi integritas data yang efisien
di seluruh jaringan.

4.2. Database Memori Node Downstream Disimpan di memori setiap node root
dan node level-1 ke atas.

Berisi informasi real-time tentang Downstream yang terhubung (IP, level,
jumlah Downstream, performa).

Diperbarui secara dinamis berdasarkan laporan dari Downstream dan
pemantauan langsung.

5\. Komunikasi Antar Proses (IPC) dan Jaringan Arsitektur ini
mengandalkan model multiproses menggunakan fork() di C, dengan pembagian
tanggung jawab yang jelas untuk keamanan, efektivitas, dan kecepatan:

Master Process: Proses orkestrator yang menginisialisasi sumber daya IPC
(shared memory, message queues, semaphores), melakukan fork() untuk
meluncurkan proses SIO, Logic, dan COW, serta memantau kesehatan mereka.

SIO (Socket I/O) Process: Bertanggung jawab penuh atas semua komunikasi
jaringan. Menggunakan I/O non-blokir (misalnya epoll di Linux atau
kqueue di BSD/macOS) untuk menangani ribuan koneksi secara efisien.
Berkomunikasi dengan Logic melalui Message Queues.

Logic Process: Jantung logika bisnis node. Menerima pesan dari SIO,
memproses logika jaringan (verifikasi, routing, manajemen koneksi,
pertanyaan), berinteraksi dengan COW untuk data database, dan mengirim
respons kembali ke SIO. Menggunakan Shared Memory untuk data yang sering
diakses (misalnya, tabel routing node, status koneksi).

COW (Copy-On-Write / Database Management) Process: Mengelola akses ke
Global Database File Transaksi. Menerima permintaan dari Logic melalui
Message Queues dan melakukan operasi baca/tulis database. Penting untuk
memastikan operasi database ini thread-safe dan efisien.

Mekanisme IPC:

Message Queues: Digunakan untuk komunikasi asinkron antar proses (SIO
\<-\> Logic, Logic \<-\> COW). Ini mengurangi ketergantungan langsung
dan memungkinkan proses untuk beroperasi secara independen.

Shared Memory: Digunakan untuk data yang sering diakses dan dibagikan
oleh beberapa proses (terutama SIO dan Logic), seperti status koneksi
aktif atau tabel routing node global. Akses ke shared memory dilindungi
oleh mutexes atau semaphores untuk mencegah race conditions.

Pipes: Dapat digunakan untuk komunikasi satu arah yang sederhana,
misalnya Master mengirim perintah ke proses anak.

6\. Mekanisme Keamanan Kriptografi Pasca-Kuantum (PQC): Semua otentikasi
dan tanda tangan digital menggunakan algoritma PQC untuk memastikan
keamanan jangka panjang terhadap ancaman komputasi kuantum.

Enkripsi Komunikasi: Semua komunikasi antar node dienkripsi menggunakan
TLS/SSL untuk mencegah eavesdropping dan serangan man-in-the-middle.

Otentikasi Kuat: Setiap pesan penting antar node ditandatangani secara
digital oleh pengirim menggunakan PQC untuk memastikan integritas pesan
dan otentisitas pengirim.

Proteksi Replay Attack: Nonce atau timestamp ditambahkan ke setiap
pesan, dan pesan memiliki masa berlaku terbatas untuk mencegah serangan
replay.

\"Jawaban Rolling\" Anti-Kartel: Untuk pertanyaan sensitif (misalnya,
performa atau jumlah Horizontalstream), jawaban yang diberikan bersifat
acak namun dapat diverifikasi secara kriptografis (misalnya, menggunakan
VRF atau turunan hash dengan nonce), mencegah node berkolusi atau
memprediksi jawaban.

Verifikasi Node Baru: Proses handshake kriptografis yang ketat untuk
node baru yang ingin bergabung, terutama untuk node root, memastikan
mereka memiliki Public Key yang sah dan terdaftar.

Sistem Reputasi/Voting: Untuk mekanisme penurunan level, sistem reputasi
atau voting di antara Horizontalstream dapat diterapkan untuk mencegah
serangan jahat dan memastikan keadilan.

Pemantauan dan Audit: Logging ekstensif untuk aktivitas jaringan dan
deteksi anomali. Sistem audit dapat memverifikasi integritas log.

Rate Limiting: Menerapkan batas laju permintaan untuk setiap jenis
interaksi untuk mencegah serangan DDoS/DoS.

7\. Efisiensi dan Kecepatan I/O Non-Blokir: Penggunaan epoll/kqueue di
proses SIO memastikan penanganan koneksi jaringan yang sangat efisien
dan tidak memblokir.

Struktur Data Optimal: Penggunaan hash tables, balanced trees, dan
caching agresif di memori untuk database Downstream dan data yang sering
diakses.

Database Terdistribusi: Implementasi sharding dan partisi untuk Global
Database File Transaksi di antara node root untuk skalabilitas dan
performa.

Komunikasi Asinkron: Message Queues memungkinkan proses untuk bekerja
secara asinkron, mengurangi latensi dan meningkatkan throughput.

Load Balancing: Node Downstream mempertimbangkan beban node Upstream
atau Horizontalstream potensial saat mencari koneksi baru untuk
distribusi yang merata.

Pemeliharaan Koneksi: Pesan keep-alive secara teratur memastikan koneksi
tetap hidup dan mendeteksi pemutusan dengan cepat.

Optimasi Kode C: Fokus pada algoritma yang efisien, manajemen memori
yang cermat, dan penggunaan profiling untuk mengidentifikasi dan
menghilangkan bottleneck.

8\. Ketahanan dan Toleransi Kesalahan Redundansi Node Root Bootstrap:
Dengan 3 node bootstrap, jaringan memiliki titik awal yang redundan.

Mekanisme Penemuan Upstream/Horizontalstream Alternatif: Jika koneksi
Upstream atau Horizontalstream terputus, node secara otomatis mencari
koneksi alternatif yang memenuhi syarat untuk menjaga konektivitas
jaringan.

Pemberitahuan Penurunan Level/Kehilangan Upstream: Mekanisme pengumuman
yang jelas memastikan node Downstream diberitahu tentang perubahan
status Upstream mereka, memungkinkan mereka untuk beradaptasi dengan
cepat.

Pemantauan Proses oleh Master: Proses Master secara aktif memantau
kesehatan proses anak (SIO, Logic, COW) dan dapat meluncurkan ulang atau
mengambil tindakan korektif jika ada yang mati.

Logging dan Debugging: Sistem logging yang komprehensif membantu dalam
mendiagnosis masalah dan memulihkan dari kegagalan.

9\. Strategi Menghindari Bottleneck Untuk memastikan jaringan Orisium
dapat beroperasi secara efektif pada skala yang sangat besar dan
menghindari hambatan kinerja (bottleneck), beberapa strategi kunci akan
diimplementasikan:

9.1. Optimalisasi Database dan Penyimpanan Data Sharding/Partisi
Database Global: Dengan potensi jutaan hingga miliaran transaksi,
menyimpan seluruh Global Database File Transaksi secara lengkap di
setiap Node Root akan menjadi bottleneck penyimpanan dan I/O.

Implementasi: Database akan di-sharding (dipisah-pisah) berdasarkan
kriteria tertentu, misalnya rentang Address atau hash dari Trx-Hash.
Setiap Node Root akan bertanggung jawab atas satu atau beberapa shard.

Manfaat: Mengurangi beban penyimpanan dan I/O pada satu node,
memungkinkan pemrosesan paralel di beberapa node, dan meningkatkan
skalabilitas.

Mekanisme Query Lintas Shard: Node Root akan memiliki tabel routing
shard atau mekanisme discovery untuk menemukan Node Root mana yang
menyimpan data yang diminta jika data tersebut berada di shard lain.

Database Terdistribusi untuk Konsensus Root: Mekanisme konsensus
(misalnya, modifikasi Paxos atau Raft) di antara Node Root tidak hanya
menjamin konsistensi tetapi juga mendistribusikan beban pembaruan
database.

Implementasi: Pembaruan state global (transaksi baru, perubahan saldo)
akan melalui proses voting dan replikasi terdistribusi di antara Node
Root yang berpartisipasi dalam konsensus.

Manfaat: Menghindari satu titik kegagalan dan mendistribusikan beban
komputasi untuk pembaruan database.

Caching Agresif: Data yang sering diakses dari Global Database File
Transaksi atau Database Memori Node Downstream akan di-cache secara
agresif di memori.

Implementasi: Proses Logic dan SIO dapat menyimpan cache lokal dari data
yang relevan (misalnya, informasi node Downstream yang sering di-query,
saldo akun yang aktif).

Manfaat: Mengurangi latensi dengan menghindari akses disk atau IPC yang
berulang.

Struktur Data Efisien: Penggunaan struktur data yang dioptimalkan untuk
performa (misalnya, hash tables untuk pencarian cepat berdasarkan
Address atau Trx-Hash, balanced trees untuk data terurut) di memori.

9.2. Optimalisasi Komunikasi Jaringan (SIO Process) I/O Multiplexing
(Epoll/Kqueue): Proses SIO dirancang untuk menggunakan epoll (Linux)
atau kqueue (BSD/macOS) untuk menangani ribuan hingga jutaan koneksi
secara efisien.

Implementasi: SIO akan beroperasi dalam mode non-blokir, memungkinkan
satu thread atau proses untuk mengelola banyak socket secara bersamaan
tanpa menunggu operasi I/O selesai.

Manfaat: Meminimalkan penggunaan sumber daya CPU dan memori per koneksi,
memungkinkan skalabilitas vertikal yang tinggi.

Buffer Jaringan yang Efisien: Penggunaan buffer yang dialokasikan secara
dinamis atau pool buffer untuk menerima dan mengirim data jaringan,
mengurangi overhead alokasi/dealokasi memori.

Rate Limiting dan Deteksi Anomali: Menerapkan batas laju pada jenis
permintaan tertentu (misalnya, jumlah koneksi baru per detik, jumlah
query per menit dari satu IP) untuk mencegah serangan DoS/DDoS yang
dapat membanjiri SIO.

9.3. Optimalisasi Pemrosesan Logika (Logic Process) Pemrosesan Asinkron:
Logic Process akan memproses permintaan dari SIO secara asinkron melalui
Message Queues. Ini memungkinkan SIO untuk terus menerima data jaringan
tanpa terblokir oleh pemrosesan logika yang kompleks.

Paralelisasi Tugas: Untuk tugas-tugas komputasi intensif (misalnya,
verifikasi tanda tangan PQC, hashing, komputasi VRF), Logic Process
dapat mendelegasikan tugas ke thread worker atau proses anak tambahan
jika diperlukan, atau menggunakan pustaka yang dioptimalkan untuk
paralelisme.

Algoritma Efisien: Penggunaan algoritma yang dioptimalkan untuk
pencarian, routing, dan manajemen data dalam memori untuk mengurangi
waktu pemrosesan.

Shared Memory untuk Data Kritis: Data yang sering diakses dan
dimodifikasi oleh SIO dan Logic (misalnya, tabel routing node, status
koneksi aktif) akan disimpan di Shared Memory, meminimalkan latensi IPC
dibandingkan Message Queues untuk akses berulang. Akses ke Shared Memory
akan dilindungi dengan mutex/semaphore.

9.4. Optimalisasi Akses Database (COW Process) Antrean Permintaan
(Message Queue): COW Process menerima permintaan database dari Logic
melalui Message Queue, memungkinkannya memproses permintaan secara
berurutan atau menggunakan pool thread internal untuk menangani beberapa
permintaan secara paralel jika database mendukungnya.

Batch Processing: Untuk operasi tulis ke database, COW dapat
mengumpulkan beberapa permintaan kecil dan memprosesnya dalam batch,
mengurangi overhead I/O disk.

Indeks Database yang Tepat: Memastikan indeks yang tepat dibuat pada
kolom-kolom yang sering di-query (misalnya, Address, Trx-Hash) untuk
mempercepat operasi baca.

Pustaka Database yang Efisien: Memilih pustaka database (misalnya,
SQLite, RocksDB, LevelDB) yang dioptimalkan untuk performa I/O tinggi
dan konkurensi, sesuai dengan kebutuhan Global Database File Transaksi.

9.5. Manajemen Sumber Daya Sistem Pemantauan Sumber Daya: Proses Master
atau modul terpisah akan memantau penggunaan CPU, memori, disk I/O, dan
bandwidth jaringan secara real-time.

Skalabilitas Horizontal: Desain hierarkis memungkinkan penambahan node
di berbagai level untuk mendistribusikan beban. Jika satu Node Root
kewalahan, node Downstream dapat mencari Upstream alternatif.

Graceful Degradation: Jaringan akan dirancang untuk dapat beroperasi
bahkan jika beberapa node mengalami masalah kinerja, dengan mekanisme
penemuan dan re-routing otomatis.

9.6. Promosi Node dan Sinkronisasi Database Pre-sinkronisasi Database:
Untuk memastikan node yang \"mampu\" dapat naik level dengan cepat, Node
Level-1 (dan Level-2) yang berpotensi menjadi Node Root akan secara
proaktif memilih satu atau beberapa shard yang ingin mereka kelola dan
melakukan pre-sinkronisasi database untuk shard(s) tersebut.

Implementasi: Node Level-1/2 akan secara aktif berlangganan pembaruan
dan data historis dari Node Root yang saat ini mengelola shard target,
secara bertahap membangun dan menjaga salinan database shard tersebut
agar selalu tersinkronisasi. Ini memastikan bahwa saat promosi atau
perpindahan tanggung jawab shard, node sudah siap dengan data yang
relevan.

Snapshot dan Sinkronisasi Incremental: Node Root dapat secara berkala
membuat snapshot database shard mereka. Node yang baru dipromosikan
dapat mengunduh snapshot terbaru dan hanya menyinkronkan perubahan
(incremental updates) sejak snapshot tersebut.

Prioritas Sinkronisasi: Ketika node baru dipromosikan, jaringan dapat
memberikan prioritas tinggi pada lalu lintas sinkronisasi database untuk
memastikan node baru dapat berfungsi penuh secepat mungkin.

9.7. Validasi Kepemilikan Database dalam Lingkungan Sharded Dalam
konteks sharding, \"memiliki database lengkap\" atau \"mampu\" berarti
node tersebut telah memenuhi dua kriteria utama:

Kepemilikan dan Sinkronisasi Shard yang Ditugaskan:

Node Root (atau kandidat promosi) harus memiliki seluruh data yang benar
dan tersinkronisasi untuk satu atau beberapa shard yang secara logis
ditugaskan kepadanya.

Validasi: Ini dapat diverifikasi dengan:

Merkle Root Shard: Setiap shard secara independen mempertahankan Merkle
Tree dari semua data (transaksi, akun) di dalamnya. Node Root harus
mampu menghasilkan dan menyajikan Merkle Root yang benar dan terkini
untuk shard-nya.

Verifikasi Acak (Challenge-Response): Node Root lain (terutama
Horizontalstream atau Node Root Bootstrap) dapat secara acak meminta
data spesifik dari shard yang diklaim oleh node tersebut. Node yang
divalidasi harus dapat menyajikan data tersebut beserta Merkle Proof
yang membuktikan bahwa data tersebut termasuk dalam Merkle Root shard
yang diklaim.

Verifikasi Integritas Global State:

Meskipun Node Root hanya menyimpan sebagian data (shard-nya), ia harus
mampu memverifikasi integritas seluruh Global State jaringan.

Validasi: Ini dilakukan melalui Global State Root, yang merupakan Merkle
Root dari semua Merkle Root shard individu.

Setiap kali blok baru difinalisasi, Global State Root diperbarui dan
disepakati oleh konsensus VRF di antara semua Node Root.

Node Root (atau kandidat) harus dapat memverifikasi bahwa Merkle Root
shard-nya sendiri secara kriptografis berkontribusi dengan benar pada
Global State Root yang disepakati secara global. Ini melibatkan
penerimaan dan verifikasi Merkle Proof dari Node Root lain untuk shard
yang tidak dipegangnya.

Dengan demikian, setiap Node Root secara kriptografis \"mempercayai\"
komitmen (Merkle Root) dari Node Root lain untuk shard yang tidak mereka
simpan, dan memverifikasi bahwa semua komitmen ini secara kolektif
membentuk Global State Root yang sah.

Proses Validasi untuk Promosi Node Level-1 ke Root:

Ketika node Level-1 ingin dipromosikan menjadi Node Root, proses
validasi \"kemampuan\" akan melibatkan langkah-langkah berikut:

Deklarasi Kemampuan & Pemilihan Shard Target: Node Level-1
mendeklarasikan niatnya untuk menjadi Node Root. Pada tahap ini, ia juga
memilih shard mana yang ingin dikelolanya jika dipromosikan. Pemilihan
ini bisa berdasarkan ketersediaan slot kosong untuk shard tertentu,
kedekatan geografis, atau kriteria beban.

Pre-sinkronisasi & Bukti: Node Level-1 harus telah menyelesaikan
pre-sinkronisasi data untuk shard yang dipilih tersebut dan menghasilkan
Merkle Root dari shard tersebut. Node Level-1 akan secara aktif meminta
data historis dan pembaruan terkini untuk shard target dari Node Root
yang saat ini mengelola shard tersebut.

Pengajuan Merkle Root Shard: Node Level-1 mengajukan Merkle Root
shard-nya ke Node Root Bootstrap atau Node Root Horizontalstream yang
relevan.

Verifikasi Peer: Node Root yang ada akan melakukan verifikasi:

Verifikasi Merkle Root Shard: Memastikan Merkle Root yang diajukan valid
dan sesuai dengan Global State Root saat ini.

Challenge Acak: Node Root yang memverifikasi dapat mengirimkan
permintaan challenge acak untuk data tertentu dalam shard yang diklaim.
Node Level-1 harus dapat merespons dengan data yang benar dan Merkle
Proof yang valid.

Verifikasi Performa: Selain data, performa jaringan dan komputasi node
Level-1 juga akan diverifikasi untuk memastikan ia dapat menangani beban
Node Root.

Konsensus Promosi: Jika verifikasi berhasil, Node Root yang ada akan
mencapai konsensus (misalnya, melalui voting) untuk mempromosikan node
Level-1 tersebut ke status Root dan menugaskan shard yang relevan
kepadanya.

Dengan demikian, \"memiliki database lengkap\" dalam konteks sharding
berarti memiliki data yang lengkap dan terverifikasi untuk shard yang
ditugaskan, serta kemampuan untuk memverifikasi integritas seluruh
Global State jaringan secara kriptografis.

10\. Kesimpulan Arsitektur jaringan Orisium yang diusulkan ini dirancang
untuk menjadi fondasi yang kuat, aman, dan efisien untuk ekosistem
terdesentralisasi yang sangat skalabel. Dengan pembagian tanggung jawab
yang jelas antar proses, penggunaan IPC yang tepat, penerapan
kriptografi pasca-kuantum, dan mekanisme konsensus yang cerdas, Orisium
bertujuan untuk mengatasi tantangan skalabilitas, keamanan, dan
konsistensi dalam lingkungan jaringan yang kompleks. Fokus pada
\"jawaban rolling\" dan mekanisme anti-kartel lebih lanjut memperkuat
desentralisasi dan ketahanan jaringan terhadap manipulasi. Strategi
menghindari bottleneck yang komprehensif, termasuk sharding database,
optimalisasi I/O, pemrosesan asinkron, dan mekanisme promosi yang
efisien dengan pre-sinkronisasi database, akan memastikan kinerja
optimal bahkan pada skala yang sangat besar.
