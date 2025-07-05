<p align="center">
  <img src="assets/images/orisium.png" alt="Orisium Logo" width="200">
</p>

# Orisium

### Powered by the **Orichain** & **Orivotura Consensus Protocol**

*Secure. Lightweight. Post-Quantum Ready.*

---

## Ringkasan

**Orichain** adalah jaringan blockchain ringan dan tahan terhadap serangan kuantum, dengan fokus pada efisiensi penyimpanan, bandwidth, dan latensi. Sistem ini mengandalkan mekanisme konsensus inovatif bernama **Orivotura**, yang memanfaatkan **VRF paralel** dan penyusunan urutan voting secara deterministik melalui proses tiga langkah.

Coin resmi jaringan ini adalah **Orisium (OSM)** — mata uang digital asli dari Orichain, dirancang untuk disimpan, ditransaksikan, dan dihargai sebagai penyimpan nilai dalam ekosistem blockchain-nya sendiri.

---

## Fitur Utama

* **Post-Quantum Cryptography**: Dukungan untuk algoritma Falcon, ML-KEM, ML-DSA.
* **Lightweight FinalBlock**: Blok final hanya menyimpan referensi ke PreBlock.
* **PreBlock-on-Demand**: PreBlock disimpan atau direkonstruksi hanya jika dibutuhkan.
* **Orivotura (VRF-Based Consensus)**: Protokol konsensus deterministik berdasarkan skor VRF.
* **Modular dan Efisien**: Dirancang dalam bahasa C modular dan hemat sumber daya.

---

## Orivotura: Konsensus dalam Tiga Langkah

### 1. `VRF_Announce`

Node menghitung skor VRF dari `alpha = seed || slot_number`. Jika `beta < threshold`, node layak menjadi proposer.

Payload:

* `public_key`
* `vrf_proof`
* `vrf_beta`
* `local_timestamp`
* `storage_proof` (opsional)

Node menyimpan semua entri valid di antrean lokal.

---

### 2. `VRF_Queue`

Setelah waktu tertentu (misal 3 menit), node menyusun antrean dari `VRF_Announce` valid, diurutkan dari `beta` terkecil. Ini adalah urutan penulisan blok untuk beberapa slot ke depan, lalu disiarkan sebagai `VRF_Queue`.

---

### 3. `VRF_Queue_Commit` / `VRF_Queue_Reveal`

Untuk menjamin kejujuran:

1. Commit: Hash dari `VRF_Queue`
2. Reveal: Isi lengkap setelah waktu tertentu

Mayoritas node menyepakati queue sebagai urutan final voting. Jika proposer utama gagal, posisi berikutnya mengambil alih.

---

## Eksekusi Blok: Paralel dan Terkontrol

* **Interval blok**: 3 menit
* **Penjadwalan VRF Queue**: 1 menit
* **Proposer paralel**: Semua node dalam queue menyusun proposal PreBlock.
* **Finalisasi**: Proposal urutan teratas dipilih saat slot tiba.

Node lain hanya memverifikasi dan menyimpan `FinalBlock`.

---

## Threshold Dinamis

```c
uint64_t calculate_threshold(uint32_t num_nodes) {
    if (num_nodes == 0) return 0;
    return ((uint64_t)(~0ULL) / num_nodes);
}
```

Dapat dikalikan konstanta (mis. 1.2) untuk mengatur rata-rata kandidat per slot.

---

## Coin Resmi: Orisium (OSM)

**Orisium** adalah unit nilai resmi dan coin asli dari jaringan Orichain. Terinspirasi dari nama unsur logam, Orisium dirancang sebagai aset digital bernilai tinggi yang layak disimpan, digunakan, dan dihargai dalam setiap interaksi blockchain.

Tidak seperti token yang bergantung pada blockchain pihak ketiga, **Orisium adalah native coin** yang langsung dihasilkan dari protokol konsensus **Orivotura**.

* **Ticker**: `OSM`
* **Decimals**: 8
* **Fungsi**:

  * Transaksi antar akun
  * Hadiah untuk node proposer
  * Biaya jaringan
  * Coin simpanan/staking

Contoh penggunaan:

* "Transfer 25 Orisium ke alamat wallet."
* "Reward blok ini adalah 12.5 Orisium."

---

## Peer Database dan Strategi Reconnect

Orichain menggunakan **database peer lokal** yang dinamis dan persisten untuk membangun peta jaringan antar node.

### 📡 Peer DB Lokal

Setiap node menyimpan **daftar peer yang diketahui**, mencatat:

* `peer_client_ip` dan `peer_server_ip` sebagai key unik per koneksi,
* Port dan public key,
* Waktu terakhir terlihat (`last_seen_ns`),
* Arah koneksi (direction hint),
* Skor bandwidth (estimasi jalur optimal).

### ♻️ Strategi Reconnect & Merge

Saat node **terputus dan terhubung kembali**, ia tidak menghapus seluruh peer DB, melainkan:

1. **Mencoba reconnect** ke peer server terakhir yang tersimpan.
2. Jika berhasil, node akan **melanjutkan dari kondisi terakhir** menggunakan **log peer DB** lokal.
3. Jika gagal, node akan **fallback** ke bootstrap peer dan membangun ulang DB secara bertahap.

### 📜 Peer Change Log

Setiap perubahan pada peer DB (penambahan atau penghapusan peer) dicatat dalam log:

* Tersimpan dalam file (mis. `peers.log`)
* Disimpan hingga 7 hari
* Dapat dipangkas otomatis untuk efisiensi

Contoh entri log:

```
[+][2025-06-23T12:00:00Z] Peer added: client=2001:db8::10 → server=2001:db8::1
[-][2025-06-23T13:10:00Z] Peer removed: client=2001:db8::20 → server=2001:db8::1
```

### 📤 PEER\_ANNOUNCE

Setiap node yang berhasil konek akan mengirimkan daftar peer yang aktif darinya ke peer server melalui `PEER_ANNOUNCE`. Hal ini memungkinkan:

* Pemetaan topologi dua arah,
* Optimalisasi routing broadcast,
* Penurunan beban jaringan.

---

## Broadcast Terarah

Orichain mendukung **broadcast terarah** berdasarkan arah dan tujuan koneksi peer:

* Setiap pesan broadcast dikirim dengan menyertakan `ip_asal` (pengirim) dan `ip_tujuan` (target),
* Node menentukan **next-hop** terbaik menuju `ip_tujuan` dari PeerDB lokal,
* Broadcast hanya dilakukan ke tetangga yang relevan, bukan semua koneksi,
* Mendukung *multi-hop routing* dengan TTL atau hops\_remaining,
* Menghindari flood dan mempercepat penyampaian pesan.

Desain ini memungkinkan:

* ✅ Efisiensi bandwidth
* ✅ Routing broadcast berbasis topologi
* ✅ Pengiriman pesan lebih privat dan terarah
* ✅ Cocok untuk sistem P2P skala besar atau konsensus relay-aware

---

## Peer Redirection dan Load Balancing

Untuk menghindari penumpukan koneksi pada satu node, Orichain mendukung mekanisme **Peer Redirection**:

* Jika sebuah peer server menerima terlalu banyak koneksi, ia dapat mengirimkan pesan `PEER_REDIRECT`,
* Pesan ini menyarankan IP dan port baru yang dapat dikoneksikan oleh client,
* Client akan menutup koneksi awal dan berpindah ke alamat baru,
* Hal ini membantu distribusi beban dan mendorong konektivitas yang seimbang di seluruh jaringan.

Payload `PEER_REDIRECT` dapat berisi:

* IP dan port tujuan baru,
* Alasan redirect (mis. overload, pemeliharaan, rotasi koneksi),
* Optional: public key target untuk trust routing.

---

## Keunggulan Orivotura & Orisium

* ✅ Post-Quantum Ready
* ✅ Efisien dan Ringan
* ✅ Proses VRF paralel dan terjadwal
* ✅ Mendukung fallback otomatis
* ✅ Tidak mudah dimanipulasi
* ✅ Coin utama: **Orisium** — untuk transaksi dan penyimpanan nilai

---

## Lisensi

* **Kode sumber**: [MIT License](LICENSE)
* **Logo, desain, dan branding**: [CC BY-NC 4.0 License](https://creativecommons.org/licenses/by-nc/4.0/)

> Orisium dan Orichain adalah merek dalam pengembangan dan tidak boleh digunakan secara komersial tanpa izin eksplisit.

---

## Penutup

**Orivotura** memungkinkan konsensus yang ringan, dapat diprediksi, namun tetap aman untuk masa depan post-quantum. **Orichain** dan coinnya, **Orisium**, menawarkan desain modular yang siap dikembangkan lebih lanjut dengan fitur seperti Merkle Tree, DHT, dan model akun sederhana.

---

© 2025 Orichain — Orisium Coin (OSM).
Website: *\[opsional]*
Dokumentasi: *\[opsional]*
