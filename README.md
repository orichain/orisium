<!DOCTYPE html>
<html lang="id" class="scroll-smooth">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Orisium Network - Dasbor Arsitektur</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <!-- Chosen Palette: Warm Neutral (Stone, Slate, Muted Teal) -->
    <!-- Application Structure Plan: A multi-section, single-page application with a sticky navigation bar. The structure is thematic (Architecture, Node Roles, Data Management, IPC) rather than linear, to allow users to jump to concepts of interest. Interactive elements like tabs for node roles and diagrams for sharding/IPC are used to simplify complex information and improve user engagement. This structure is chosen to make a dense technical document more digestible and explorable for developers and architects. -->
    <!-- Visualization & Content Choices: 1. Network Hierarchy -> Goal: Compare -> Bar Chart (Chart.js) to show exponential node capacity per level. Interaction: Hover tooltips. Justification: A visual comparison is more impactful than a list of numbers. 2. Node Roles -> Goal: Organize/Inform -> Interactive Tabs (HTML/CSS/JS) to display details for each node type. Interaction: Click to switch content. Justification: Prevents information overload by showing one node type at a time. 3. Sharding -> Goal: Organize/Explain -> Diagram (HTML/CSS) to visualize the split from Global DB to Shards and roll-up to Global State Root. Interaction: Subtle scroll-based animations. Justification: Makes an abstract database concept concrete. 4. IPC Model -> Goal: Organize/Explain -> Flowchart (HTML/CSS) to show process communication. Interaction: Hover effects. Justification: Clearly illustrates the relationship and data flow between processes. CONFIRMATION: NO SVG graphics used. NO Mermaid JS used. -->
    <!-- CONFIRMATION: NO SVG graphics used. NO Mermaid JS used. -->
    <style>
        body {
            font-family: 'Inter', sans-serif;
            background-color: #f8fafc; /* slate-50 */
        }
        .section-title {
            color: #1e293b; /* slate-800 */
        }
        .section-subtitle {
            color: #475569; /* slate-600 */
        }
        .card {
            background-color: white;
            border-radius: 0.75rem;
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
        }
        .tab-btn {
            transition: all 0.3s ease;
            border-bottom: 2px solid transparent;
        }
        .tab-btn.active {
            color: #0d9488; /* teal-600 */
            border-bottom-color: #0d9488; /* teal-600 */
        }
        .nav-link {
            transition: color 0.3s ease;
        }
        .nav-link:hover {
            color: #0d9488; /* teal-600 */
        }
        .chart-container {
            position: relative;
            width: 100%;
            max-width: 800px;
            margin-left: auto;
            margin-right: auto;
            height: 400px;
            max-height: 50vh;
        }
        .diagram-arrow {
            position: relative;
        }
        .diagram-arrow::after {
            content: '→';
            position: absolute;
            right: -2rem;
            top: 50%;
            transform: translateY(-50%);
            font-size: 2rem;
            color: #94a3b8; /* slate-400 */
        }
    </style>
</head>
<body class="text-slate-700">

    <header class="bg-white/80 backdrop-blur-lg sticky top-0 z-50 shadow-sm">
        <nav class="container mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex items-center justify-between h-16">
                <div class="flex items-center">
                    <span class="text-2xl font-bold text-slate-800">Orisium</span>
                </div>
                <div class="hidden md:block">
                    <div class="ml-10 flex items-baseline space-x-4">
                        <a href="#arsitektur" class="nav-link px-3 py-2 rounded-md text-sm font-medium">Arsitektur</a>
                        <a href="#peran-node" class="nav-link px-3 py-2 rounded-md text-sm font-medium">Peran Node</a>
                        <a href="#data" class="nav-link px-3 py-2 rounded-md text-sm font-medium">Manajemen Data</a>
                        <a href="#ipc" class="nav-link px-3 py-2 rounded-md text-sm font-medium">Arsitektur Proses</a>
                    </div>
                </div>
            </div>
        </nav>
    </header>

    <main class="container mx-auto px-4 sm:px-6 lg:px-8 py-8 md:py-12">
        
        <section id="hero" class="text-center py-12 md:py-20">
            <h1 class="text-4xl md:text-6xl font-extrabold tracking-tight text-slate-900">Arsitektur Jaringan Orisium</h1>
            <p class="mt-4 max-w-2xl mx-auto text-lg text-slate-600">Sebuah eksplorasi interaktif dari jaringan terdesentralisasi yang tangguh, terukur, dan aman.</p>
        </section>

        <section id="arsitektur" class="py-12 md:py-20">
            <div class="text-center mb-12">
                <h2 class="text-3xl font-bold tracking-tight section-title">Struktur Jaringan Hierarkis</h2>
                <p class="mt-2 max-w-xl mx-auto text-lg section-subtitle">Orisium dirancang dengan struktur berlapis untuk skalabilitas eksponensial. Visualisasi di bawah ini menunjukkan kapasitas node maksimal di setiap level.</p>
            </div>
            <div class="card p-4 sm:p-6">
                <div class="chart-container">
                    <canvas id="nodeCapacityChart"></canvas>
                </div>
            </div>
        </section>

        <section id="peran-node" class="py-12 md:py-20">
            <div class="text-center mb-12">
                <h2 class="text-3xl font-bold tracking-tight section-title">Peran dan Tanggung Jawab Node</h2>
                <p class="mt-2 max-w-xl mx-auto text-lg section-subtitle">Setiap node memiliki peran unik. Klik tab di bawah untuk menjelajahi definisi, kewajiban, dan hak dari setiap jenis node.</p>
            </div>
            <div class="card">
                <div class="border-b border-slate-200">
                    <nav class="-mb-px flex space-x-4 sm:space-x-8 px-4 sm:px-6" aria-label="Tabs">
                        <button class="tab-btn active whitespace-nowrap py-4 px-1 text-sm font-medium" data-tab="root-bootstrap">Root Bootstrap</button>
                        <button class="tab-btn whitespace-nowrap py-4 px-1 text-sm font-medium" data-tab="root">Root</button>
                        <button class="tab-btn whitespace-nowrap py-4 px-1 text-sm font-medium" data-tab="level-1">Level 1</button>
                        <button class="tab-btn whitespace-nowrap py-4 px-1 text-sm font-medium" data-tab="level-2-7">Level 2-7</button>
                    </nav>
                </div>
                <div class="p-6 md:p-8">
                    <div class="tab-content" id="content-root-bootstrap">
                        <div class="grid md:grid-cols-2 gap-8">
                            <div>
                                <h3 class="text-xl font-semibold text-slate-800 mb-3">Definisi</h3>
                                <ul class="space-y-2 list-disc list-inside text-slate-600">
                                    <li>Min Downstream: 0</li>
                                    <li>Maks Downstream: 10</li>
                                    <li>Min Horizontalstream: 2</li>
                                    <li>Maks Horizontalstream: 312</li>
                                </ul>
                            </div>
                            <div>
                                <h3 class="text-xl font-semibold text-slate-800 mb-3">Kewajiban & Hak Utama</h3>
                                <ul class="space-y-2 list-disc list-inside text-slate-600">
                                    <li>Menjaga imutabilitas nama domain.</li>
                                    <li>Menyimpan dan memverifikasi shard database yang menjadi tanggung jawabnya.</li>
                                    <li>Menjawab pertanyaan dari Horizontalstream & Downstream dengan "jawaban rolling".</li>
                                    <li>Berpartisipasi dalam konsensus untuk menjatuhkan level Root lain.</li>
                                    <li>Memverifikasi koneksi Root baru dan berhak voting VRF.</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                    <div class="tab-content hidden" id="content-root">
                        <div class="grid md:grid-cols-2 gap-8">
                            <div>
                                <h3 class="text-xl font-semibold text-slate-800 mb-3">Definisi</h3>
                                <ul class="space-y-2 list-disc list-inside text-slate-600">
                                    <li>Min Downstream: 5</li>
                                    <li>Maks Downstream: 10</li>
                                    <li>Min Horizontalstream: 5</li>
                                    <li>Maks Horizontalstream: 312</li>
                                </ul>
                            </div>
                            <div>
                                <h3 class="text-xl font-semibold text-slate-800 mb-3">Kewajiban & Hak Utama</h3>
                                <ul class="space-y-2 list-disc list-inside text-slate-600">
                                    <li>Kewajiban serupa dengan Root Bootstrap.</li>
                                    <li>**Perbedaan Utama:** Memberi pengumuman resmi ke Downstream jika Horizontalstream-nya dijatuhkan levelnya.</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                    <div class="tab-content hidden" id="content-level-1">
                        <div class="grid md:grid-cols-2 gap-8">
                             <div>
                                <h3 class="text-xl font-semibold text-slate-800 mb-3">Definisi</h3>
                                <ul class="space-y-2 list-disc list-inside text-slate-600">
                                    <li>Min/Maks Downstream: 0/10</li>
                                    <li>Fixed Horizontalstream: 9</li>
                                    <li>Fixed Upstream: 1</li>
                                </ul>
                            </div>
                            <div>
                                <h3 class="text-xl font-semibold text-slate-800 mb-3">Kewajiban & Hak Utama</h3>
                                <ul class="space-y-2 list-disc list-inside text-slate-600">
                                    <li>Aktif mengelola koneksi Upstream.</li>
                                    <li>Memberi pengumuman ke Downstream jika kehilangan Upstream.</li>
                                    <li>**Hak Naik Level:** Dapat menjadi Root jika "mampu", yaitu telah memilih dan melakukan pre-sinkronisasi database untuk shard yang dituju.</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                    <div class="tab-content hidden" id="content-level-2-7">
                        <div class="grid md:grid-cols-2 gap-8">
                             <div>
                                <h3 class="text-xl font-semibold text-slate-800 mb-3">Definisi</h3>
                                <ul class="space-y-2 list-disc list-inside text-slate-600">
                                     <li>Min/Maks Downstream: 0/10</li>
                                     <li>Fixed Horizontalstream: 9</li>
                                     <li>Fixed Upstream: 1</li>
                                </ul>
                            </div>
                            <div>
                               <h3 class="text-xl font-semibold text-slate-800 mb-3">Kewajiban & Hak Utama</h3>
                                <ul class="space-y-2 list-disc list-inside text-slate-600">
                                    <li>Kewajiban dan hak sama dengan Node Level-1.</li>
                                    <li>Menjamin konsistensi dan efisiensi di lapisan bawah jaringan.</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <section id="data" class="py-12 md:py-20">
            <div class="text-center mb-12">
                <h2 class="text-3xl font-bold tracking-tight section-title">Manajemen Data & Sharding</h2>
                <p class="mt-2 max-w-xl mx-auto text-lg section-subtitle">Orisium menggunakan sharding untuk skalabilitas. Diagram ini mengilustrasikan bagaimana integritas data dijaga di seluruh jaringan terdistribusi.</p>
            </div>
            <div class="card p-6 md:p-8">
                <div class="flex flex-col items-center space-y-8">
                    <div class="text-center p-4 border-2 border-slate-700 rounded-lg w-full md:w-1/2">
                        <h4 class="font-bold text-lg text-slate-800">Global State Root</h4>
                        <p class="text-sm text-slate-500">Hash tunggal yang merepresentasikan seluruh keadaan jaringan. Disepakati oleh semua Node Root.</p>
                    </div>
                    <div class="text-2xl text-slate-400">↑</div>
                    <p class="text-center text-slate-600 -my-4">Agregasi dari semua Merkle Root Shard</p>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6 w-full pt-4">
                        <div class="text-center p-3 border border-dashed border-teal-500 rounded-lg bg-teal-50">
                            <h5 class="font-semibold text-teal-800">Merkle Root Shard 1</h5>
                            <p class="text-xs text-teal-600">Hash dari semua data di Shard 1</p>
                        </div>
                        <div class="text-center p-3 border border-dashed border-teal-500 rounded-lg bg-teal-50">
                            <h5 class="font-semibold text-teal-800">Merkle Root Shard 2</h5>
                            <p class="text-xs text-teal-600">Hash dari semua data di Shard 2</p>
                        </div>
                         <div class="text-center p-3 border border-dashed border-teal-500 rounded-lg bg-teal-50">
                            <h5 class="font-semibold text-teal-800">Merkle Root Shard N</h5>
                            <p class="text-xs text-teal-600">...</p>
                        </div>
                    </div>
                    <div class="text-2xl text-slate-400">↑</div>
                     <p class="text-center text-slate-600 -my-4">Data lengkap disimpan & di-hash di sini</p>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6 w-full pt-4">
                        <div class="text-center p-4 border border-slate-300 rounded-lg bg-slate-100">
                            <h5 class="font-semibold text-slate-700">Database Shard 1</h5>
                            <p class="text-xs text-slate-500">Disimpan oleh Root A</p>
                        </div>
                        <div class="text-center p-4 border border-slate-300 rounded-lg bg-slate-100">
                             <h5 class="font-semibold text-slate-700">Database Shard 2</h5>
                            <p class="text-xs text-slate-500">Disimpan oleh Root B</p>
                        </div>
                         <div class="text-center p-4 border border-slate-300 rounded-lg bg-slate-100">
                            <h5 class="font-semibold text-slate-700">Database Shard N</h5>
                            <p class="text-xs text-slate-500">Disimpan oleh Root X</p>
                        </div>
                    </div>
                </div>
            </div>
        </section>

         <section id="ipc" class="py-12 md:py-20">
            <div class="text-center mb-12">
                <h2 class="text-3xl font-bold tracking-tight section-title">Arsitektur Proses Internal (IPC)</h2>
                <p class="mt-2 max-w-xl mx-auto text-lg section-subtitle">Setiap node Orisium berjalan dengan model multiproses untuk efisiensi dan keamanan. Diagram ini menunjukkan bagaimana proses-proses tersebut berkomunikasi.</p>
            </div>
             <div class="card p-6 md:p-8">
                <div class="relative grid grid-cols-1 lg:grid-cols-2 gap-8 items-center">
                    <div class="space-y-6">
                        <div class="border p-4 rounded-lg text-center bg-rose-50 border-rose-200">
                            <h4 class="font-bold text-rose-800">Master Process</h4>
                            <p class="text-sm text-rose-600">Menginisialisasi, mem-fork, dan memantau semua proses anak.</p>
                        </div>
                         <div class="grid grid-cols-3 gap-4 text-center text-2xl text-slate-400">
                            <span>↓</span>
                            <span>↓</span>
                            <span>↓</span>
                        </div>
                        <div class="grid grid-cols-3 gap-4">
                            <div class="border p-3 rounded-lg text-center bg-sky-50 border-sky-200">
                                <h5 class="font-semibold text-sky-800">SIO</h5>
                                <p class="text-xs text-sky-600">Socket I/O</p>
                            </div>
                            <div class="border p-3 rounded-lg text-center bg-indigo-50 border-indigo-200">
                                <h5 class="font-semibold text-indigo-800">Logic</h5>
                                <p class="text-xs text-indigo-600">Logika Bisnis</p>
                            </div>
                            <div class="border p-3 rounded-lg text-center bg-amber-50 border-amber-200">
                                <h5 class="font-semibold text-amber-800">COW</h5>
                                <p class="text-xs text-amber-600">Akses DB</p>
                            </div>
                        </div>
                    </div>
                    <div class="relative lg:pl-10">
                        <div class="absolute left-0 top-0 bottom-0 w-0.5 bg-slate-200 hidden lg:block"></div>
                        <div class="space-y-4">
                            <div class="relative pl-6">
                               <h4 class="font-semibold text-slate-800">SIO ↔ Logic</h4>
                               <p class="text-sm text-slate-600">SIO menangani I/O jaringan. Data mentah dikirim ke Logic melalui **Message Queue** untuk pemrosesan asinkron. Logic mengirim kembali data yang akan dikirim melalui antrean lain.</p>
                            </div>
                             <div class="relative pl-6">
                               <h4 class="font-semibold text-slate-800">Logic ↔ COW</h4>
                               <p class="text-sm text-slate-600">Logic meminta data dari COW (Database) melalui **Message Queue**. COW memproses permintaan dan mengembalikan hasilnya, mencegah Logic terblokir oleh operasi disk.</p>
                            </div>
                             <div class="relative pl-6">
                               <h4 class="font-semibold text-slate-800">Logic & SIO ↔ Shared Memory</h4>
                               <p class="text-sm text-slate-600">Data kritis yang membutuhkan akses latensi sangat rendah (seperti tabel routing aktif) disimpan di **Shared Memory**, yang dapat diakses langsung oleh Logic dan SIO dengan perlindungan mutex.</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

    </main>
    
    <footer class="bg-slate-800 text-slate-400">
        <div class="container mx-auto px-4 sm:px-6 lg:px-8 py-4 text-center text-sm">
            <p>&copy; 2025 Orisium Network. Dibuat untuk visualisasi arsitektur.</p>
        </div>
    </footer>


    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const chartCtx = document.getElementById('nodeCapacityChart').getContext('2d');
            const nodeCapacityChart = new Chart(chartCtx, {
                type: 'bar',
                data: {
                    labels: ['Root', 'Level 1', 'Level 2', 'Level 3', 'Level 4', 'Level 5', 'Level 6', 'Level 7'],
                    datasets: [{
                        label: 'Kapasitas Node Maksimal',
                        data: [313, 3130, 31300, 313000, 3130000, 31300000, 313000000, 3130000000],
                        backgroundColor: '#0f766e', // teal-700
                        borderColor: '#0d9488', // teal-600
                        borderWidth: 1,
                        hoverBackgroundColor: '#14b8a6', // teal-500
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            type: 'logarithmic',
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Jumlah Node (Skala Logaritmik)'
                            },
                            ticks: {
                                callback: function(value, index, values) {
                                    if (value === 1000000000) return '3.1 Miliar';
                                    if (value === 100000000) return '313 Juta';
                                    if (value === 10000000) return '31.3 Juta';
                                    if (value === 1000000) return '3.1 Juta';
                                    if (value === 100000) return '313 Ribu';
                                    if (value === 10000) return '31.3 Ribu';
                                    if (value === 1000) return '3.1 Ribu';
                                    if (value === 100) return '313';
                                    return null;
                                }
                            }
                        },
                        x: {
                           grid: {
                                display: false
                           }
                        }
                    },
                    plugins: {
                        legend: {
                            display: false
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    let label = context.dataset.label || '';
                                    if (label) {
                                        label += ': ';
                                    }
                                    if (context.parsed.y !== null) {
                                        label += new Intl.NumberFormat('id-ID').format(context.parsed.y);
                                    }
                                    return label;
                                }
                            }
                        }
                    }
                }
            });

            const tabs = document.querySelectorAll('.tab-btn');
            const contents = document.querySelectorAll('.tab-content');

            tabs.forEach(tab => {
                tab.addEventListener('click', () => {
                    const target = tab.getAttribute('data-tab');
                    
                    tabs.forEach(t => t.classList.remove('active'));
                    tab.classList.add('active');
                    
                    contents.forEach(content => {
                        if (content.id === `content-${target}`) {
                            content.classList.remove('hidden');
                        } else {
                            content.classList.add('hidden');
                        }
                    });
                });
            });
        });
    </script>

</body>
</html>
