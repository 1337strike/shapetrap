# shapetrap

Tool untuk paper *The Shape Trap in the Wild: Auditing Lightweight Injection Detectors from Curated Payload Lists to Honeypot-Observed Attacks*.

Isinya audit lintas-dataset untuk detector injection yang ringan (TF-IDF dengan enam learner: LR, MNB, linear SVM, random forest, LightGBM, MLP), dibandingkan dengan signature lokal dan OWASP CRS asli, lalu uji detector yang sama pada data honeypot publik. Pertanyaan yang dijawab: **detector ini belajar serangannya, atau belajar bentuk input-nya?**

"Bentuk" (shape) di sini adalah wadah tempat sebuah input datang, terlepas dari isinya: `q=laptop` (kv), `laptop` (bare), `{"q": "laptop"}` (json), `/a/b` (path), atau kosong.

Ini kelanjutan paper *Evaluating Input Canonicalization for SQLi and XSS Detection Using Lightweight Machine Learning*. Temuan Table VI di paper itu (0% false positive di CSIC, tapi ~97% di HttpParamsDataset) jadi titik berangkatnya.

Semua jalan di CPU. Tidak ada GPU, tidak ada container. Semua data berasal dari sumber publik; tidak ada data buatan dan tidak ada data workshop.

## Pasang dan jalanin

Butuh Python 3.11+ dan git. Untuk CRS asli (opsional) butuh `gcc` dan `libmodsecurity`.

```bash
sudo pacman -S --needed python git gcc libmodsecurity   # dua terakhir hanya untuk CRS asli
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

shapetrap fetch      # unduh 14 repo sumber data ke data/raw (sekitar 950 MB)
shapetrap anchor     # cek: angka Table VI paper pertama harus keluar persis
shapetrap all        # build -> audit -> crs -> run -> probe -> explain -> report
pytest               # 48 test
```

Kalau `gcc` atau `libmodsecurity` tidak ada, langkah `crs` dilewati dengan pesan, dan sisanya tetap jalan dengan signature lokal sebagai referensi. CRS asli sudah dijalankan dengan libmodsecurity 3.0.12 (mesin uji) dan dengan paket `libmodsecurity` Arch (ThinkPad X1 Carbon Gen 8). Versi library sedikit menggeser hasilnya: dari 272.242 string, level 1 memblok 105.129 di mesin uji dan 105.062 di Arch; level 2 memblok 131.437 dan 131.433. Tulis versi libmodsecurity dan CRS yang dipakai di paper.

Hasil akhirnya ada di `out/REPORT.md`, dengan semua angka mentahnya di CSV di folder yang sama.

`shapetrap fetch` mengambil tiap repo pada commit yang sudah diuji, dan untuk repo besar hanya folder yang dipakai. Repo `1337strike/sqlixss-detector` ikut di-clone; kalau mau pakai clone lokal lu sendiri, ganti `path` di `[datasets.paper1x]` pada `shapetrap.toml`.

## Perintah

| Perintah | Yang dikerjakan | Output utama |
|---|---|---|
| `fetch` | Unduh tiap sumber pada commit yang sudah diuji | `data/raw/` |
| `anchor` | Hitung ulang angka HttpParamsDataset dari paper pertama, dengan pengaturan paper dan dengan LR yang konvergen penuh | layar |
| `build` | Bersihkan, de-duplikasi, buang konflik label, batasi per kelas | `out/corpus/` |
| `audit` | Overlap antar sumber di level string, string ternormalisasi, dan value | `audit_overlap.csv` |
| `run` | Transfer matrix, intervensi bentuk, dan uji pada sumber held-out | `transfer_cells.csv`, `transfer_summary.csv`, `interventions.csv` |
| `crs` | Nilai tiap string korpus dengan OWASP CRS asli lewat libmodsecurity, paranoia level 1 dan 2 | `out/crs/` |
| `render` | Susun ulang bagian 3, 4, 6, 7 laporan dari CSV hasil `run` terakhir, tanpa melatih ulang | `section_*.md` |
| `probe` | Indikator tanpa model: komposisi bentuk per kelas, akurasi dari bentuk saja, separability | `probe.csv` |
| `explain` | Bobot koefisien LR: cue terkuat, token wadah, fitur yang tandanya terbalik | `explain_*.csv` |
| `report` | Gabung semua bagian jadi satu laporan | `REPORT.md` |
| `all` | Semua langkah di atas kecuali `fetch` dan `anchor` | |

Semua pengaturan ada di `shapetrap.toml`: seed, batas sampel per kelas, tokenizer, daftar detector, dan daftar sumber.

## Cara kerjanya

1. **Dua jenis sumber.** Sumber *benchmark* punya kelas benign dan serangan, jadi dipakai untuk melatih dan menguji. Sumber *held-out* (`role = "test"`) tidak pernah dipakai melatih: daftar payload dan data honeypot.
2. **Split.** Tiap sumber benchmark dibagi 75/25 per *family* payload (aturan family sama dengan paper pertama), terstratifikasi per kelas, satu split per seed.
3. **Transfer.** Satu model dilatih di train split sumber A, lalu dites di test split semua sumber. Sebelum sel A→B dihitung, string tes yang kunci ternormalisasinya ada di train A dibuang.
4. **Metrik.** Sebuah input dihitung *flagged* kalau prediksinya bukan `benign`, apa pun label serangannya. Jadi sumber yang serangannya tidak bertipe tetap bisa dibandingkan.
5. **Intervensi bentuk.** Test set yang sama dites lagi dengan wadah diganti saja: `bare` (key dibuang), `kv` (dibungkus `key=value`), `json`. Isinya identik, jadi prediksi yang berubah pasti karena bentuk. Diuji dengan McNemar eksak + Holm.
6. **Abstain.** Dicatat juga hasilnya kalau input yang tidak punya satu pun fitur di vocabulary diloloskan saja, bukan diputuskan dari intercept.
7. **Shape augmentation.** Tiap detector ML juga dilatih versi `+aug`: tiap string train dilihat juga dalam wadah lain dengan label yang sama.
8. **Container canonicalization.** Perluasan canonicalization dari paper pertama: selain isi di-decode, wadahnya juga dibuang sebelum klasifikasi. Ada dua varian:
   - `cstrip`: key, pemisah, dan struktur JSON dibuang; tiap value di-canonicalize lalu digabung dengan satu spasi. `id=5&q=x`, `{"id":"5","q":"x"}`, dan `5 x` jadi teks yang sama.
   - `vmil`: tiap value diputuskan sendiri-sendiri, dan input ter-flag kalau ada satu value yang ter-flag. Karena pada request serangan yang punya banyak value tidak diketahui value mana yang jahat, pelatihannya multiple-instance: mulai dengan menganggap semua value-nya serangan, latih, simpan hanya value dengan skor tertinggi per request, lalu latih ulang (dua putaran).

   Key hanya dibuang kalau berupa identifier polos. Apa pun yang lain di posisi key (percent-encoding, tanda baca) tetap dipakai sebagai value, supaya payload tidak bisa disembunyikan di nama parameter.

9. **Enam learner.** Selain LR, MNB, dan linear SVM dari paper pertama, ada random forest, LightGBM, dan MLP satu hidden layer di atas fitur yang sama, untuk memastikan efeknya bukan sifat model linear. Tiga learner tambahan ini dijalankan pada `raw`, `canon`, dan `cstrip`.
10. **CRS asli.** Tiap string ditaruh di request HTTP sesuai wadahnya (key=value jadi query string, path jadi request target, JSON jadi body, sisanya jadi value satu parameter), lalu dinilai libmodsecurity dengan rule CRS pada paranoia level 1 dan 2. Tidak ada yang dikirim ke jaringan; request-nya hanya jadi argumen ke library. Hasilnya dipakai sebagai detector pembanding (`crs-pl1`, `crs-pl2`) dan sebagai referensi sintaks injection untuk data honeypot.
11. **Ketidakpastian.** Interval Wilson untuk tiap sel, bootstrap 10.000 kali atas sumber latihan untuk rata-rata lintas dataset, dan Wilcoxon signed-rank eksak untuk perbandingan perbaikan.

### Cara membaca data honeypot

- **Kelas serangan** pada sumber honeypot berarti *input yang diterima dari dunia nyata*: perintah shell yang diketik setelah login, atau parameter request ke server yang terekspos. Itu trafik bermusuhan, tapi tidak semuanya terkonfirmasi sebagai injection. Jadi angkanya adalah "berapa persen yang ter-flag", bukan recall.
- **Kelas kontrol** adalah username dan password yang dicoba. Itu input dari pihak yang bermusuhan, tapi bukan payload injection, jadi detector injection tidak punya alasan mem-flag-nya.
- **Distinct dan events.** Satu record bukan satu serangan. Tiap string unik membawa bobot berupa jumlah kejadiannya, dan laporan menampilkan dua angka: per string unik (*distinct*) dan berbobot kejadian (*events*).
- **Referensi sintaks.** Karena tidak ada ground truth, laporan memisahkan string yang diblok CRS asli (sintaks injection eksplisit) dari yang tidak, lalu melihat berapa yang ter-flag model di tiap kelompok. Kalau CRS tidak terpasang, yang dipakai signature lokal.

Isi log hanya dibaca sebagai teks. Tool ini tidak pernah menjalankannya.

## Sumber data

Total 16 sumber: 8 benchmark (191.020 string dipakai, dari 2,1 juta string mentah) dan 8 held-out (90.843 string dipakai). Batas per kelas per sumber 20.000 setelah de-duplikasi.

### Benchmark (dilatih dan diuji)

| Nama | Asal | Tahun (rilis atau commit terakhir) | Bentuk dominan | Lisensi di repo |
|---|---|---|---|---|
| `paper1x` | Korpus paper pertama + daftar cmdi dan traversal dari InfoSecWarrior/Offensive-Payloads | 2026 | benign kv, serangan bare | tidak ada file lisensi di Offensive-Payloads |
| `hpd` | Morzeux/HttpParamsDataset | 2020 | bare | MIT |
| `csic` | CSIC 2010 (mirror msudol), query string atau body | 2010 | kv | mirror GPL-3.0; cek syarat dataset aslinya |
| `ecml` | ECML/PKDD 2007 learning set (mirror msudol) | 2007 | kv | sama seperti di atas |
| `gran` | grananqvist/Machine-Learning-Web-Application-Firewall-and-Dataset | 2018 | bare | MIT |
| `fwaf` | faizann24/Fwaf-Machine-Learning-driven-Web-Application-Firewall | 2017 | path | tidak ada file lisensi |
| `modsec` | pralab/modsec-learn-dataset: query sah dari trafik nyata (open-appsec) + SQLi | 2024 | kv | tidak ada file lisensi; minta disitasi |
| `crs` | Regression test OWASP Core Rule Set: serangan per keluarga rule + *hard negative* buatan penulis rule | 2026 | kv | Apache-2.0 |

### Held-out (hanya diuji)

| Nama | Asal | Periode | Isi | Lisensi |
|---|---|---|---|---|
| `patt` | swisskyrepo/PayloadsAllTheThings (daftar Intruder) | daftar per Okt 2026 | 24.312 payload | MIT |
| `shell21` | zyw-286/shell-attack-evolution-dataset (IEEE SRDS 2025), Cowrie | 2021–2022 | 12.923 perintah unik, 65.317 kejadian | data CC BY 4.0 |
| `shell24` | sama | 2024 | 4.236 perintah unik, 33.259 kejadian | data CC BY 4.0 |
| `copot_ssh` | ymlwww/Conpot2025 (Copot-2025, ICC Workshops 2026), Cowrie di AWS | Apr–Jul 2025 | 439.980 sesi; 190 rangkaian perintah unik; kredensial sebagai kontrol | tidak ada lisensi eksplisit; minta disitasi |
| `tpot25` | samdavi/SSH-Honeypot-Dataset, T-Pot | Nov 2025 | 1.835 perintah unik; username sebagai kontrol | tidak ada file lisensi |
| `copot_web` | Copot-2025, honeypot web Tanner dan h0neytr4p | 2025 | 102.747 request, 11.538 berparameter | sama seperti `copot_ssh` |
| `finch` | 0x4D31/honeypot-data, reverse proxy Finch | Jul–Nov 2025 | 21.816 request, 273 query/body unik | CC BY 4.0 |
| `vps` | masafykun/vps-attack-dataset, VPS produksi | Jun–Okt 2026 | 370.248 request, 13.180 berparameter; username SSH sebagai kontrol | CC BY 4.0 |

Dataset tidak ikut di dalam zip ini. Cek lisensi masing-masing sebelum mendistribusikan ulang, dan sitasi tiap sumber di paper.

### Yang sengaja tidak dipakai

- **Log workshop.** Tidak dipakai dan tidak dimodifikasi. Data hasil pengamatan orang lain tidak boleh diubah lalu disajikan sebagai milik sendiri. Loader `cowrie` tetap ada kalau nanti lu punya log sendiri (contoh di bagian bawah `shapetrap.toml`).
- **Dataset yang berisi data sintetis atau buatan LLM** (misalnya mayarkh210/SQLi_XSS_dataset): bukan data pengamatan.
- **WAF-A-MoLE dataset:** isinya query SQL utuh, bukan input HTTP.
- **CyberLab honeynet (Zenodo, 2019–2020, CC BY 4.0), COW160x4 (2026), SR-BH 2020 (Harvard Dataverse):** layak ditambah, tapi tidak bisa diunduh dari lingkungan tempat tool ini diuji, jadi loader-nya belum ditulis.

## Hasil

Dari run versi 0.5.1 pada 11 November 2026: 3 seed (42, 43, 44), tokenizer `web`, batas 20.000 per kelas, 31 konfigurasi detector. Laporan lengkapnya di `out/REPORT.md`. Di mesin uji (2 core), langkah `crs` makan sekitar 5 menit dan `run` sekitar 48 menit. Di ThinkPad X1 Carbon Gen 8, `run` versi 0.5.0 makan 76 menit; versi 0.5.1 belum diukur di sana dan akan sedikit lebih lama karena LR dijalankan sampai konvergen.

**Angka di bawah ini dari mesin uji.** Untuk paper, pakai angka dari run lu sendiri dan tulis versi library-nya. Model linear (LR, MNB, SVM), signature, dan audit seharusnya keluar sama; random forest, LightGBM, dan MLP bisa bergeser sampai sekitar 2 poin pada rata-rata antar mesin (lihat Batasan).

**1. Pipeline-nya cocok dengan paper pertama.** `shapetrap anchor` mengeluarkan angka Table VI persis: LR raw 97,03% benign ter-flag, 99,68% SQLi, 99,62% XSS; LR canon 97,53% / 99,68% / 99,43%, dengan n yang sama (19.304 / 10.849 / 529). Dengan LR yang dijalankan sampai konvergen penuh angkanya 97,14% dan 97,68% benign ter-flag, jadi temuan paper pertama tidak bergantung pada toleransi optimizer.

**2. Tiga benchmark ternyata satu sumber benign.** 90,5% value benign `hpd` ada di parameter CSIC 2010, padahal overlap di level string 0,0%. Hal yang sama antara `csic` dan `gran` (99,5%, 29.548 value). Jadi di paper pertama, 0% false positive di CSIC dan ~97% di HttpParamsDataset itu terjadi pada data dari aplikasi yang sama, hanya wadahnya beda. Dari 8 benchmark, provenance yang independen ada enam: {`csic`, `hpd`, `gran`}, `paper1x`, `ecml`, `fwaf`, `modsec`, `crs`. Selain itu `paper1x` dan `patt` berbagi 51,1% string karena memakai daftar payload publik yang sama; string yang bocor dibuang per sel.

**3. Di korpus paper pertama, bentuk saja sudah memisahkan kelas.** Aturan satu bit "input ini key=value atau bukan" mencapai akurasi 99,9% di `paper1x` (majority rate 64,4%), tanpa melihat isi sama sekali.

**4. Performa runtuh lintas dataset.** Untuk `lr-raw`, rata-rata in-distribution ke rata-rata lintas dataset (8 sumber):

| Metrik | In-distribution | Lintas dataset |
|---|---|---|
| Benign ter-flag (FPR) | 8,6% | 47,2% |
| Serangan ter-flag | 97,2% | 67,0% |
| Balanced accuracy | 94,3% | 59,9% |

Ini terjadi di keenam learner, bukan hanya model linear:

| Learner (input raw) | FPR in-distribution | FPR lintas dataset | Selisih [95% bootstrap] |
|---|---|---|---|
| Logistic regression | 8,6% | 47,2% | 38,6 [19,2; 57,5] |
| Naive Bayes | 13,6% | 42,4% | 28,8 [15,1; 45,3] |
| Linear SVM | 8,8% | 50,1% | 41,3 [20,5; 59,5] |
| Random forest | 10,3% | 54,4% | 44,1 [21,8; 66,5] |
| LightGBM | 8,5% | 54,4% | 45,9 [22,2; 69,0] |
| MLP | 10,5% | 44,6% | 34,1 [14,5; 54,0] |

Semua interval jauh dari nol. Intervalnya lebar karena unitnya hanya delapan sumber latihan.

Per tipe serangan, deteksi turun dari 98,1% ke 75,9% (SQLi), 96,4% ke 68,2% (XSS), 94,1% ke 60,1% (command injection), dan 93,6% ke 58,7% (traversal). Model yang dilatih di `paper1x` mem-flag 99,7% benign `hpd`, tapi 0,0% benign `csic` sambil cuma menangkap 2,3% serangan `csic`.

**5. Mengganti wadah saja sudah membalik keputusan.** Pada test split sumbernya sendiri (seed pertama): benign `paper1x` ter-flag 0,0% apa adanya, 33,6% kalau key-nya dibuang, 100% kalau jadi JSON. Benign `hpd`: 0,0% → 42,5% (dibungkus kv) → 81,2% (JSON). Benign `gran`: 0,3% → 64,2% (kv). Benign `fwaf`: 0,5% → 87,6% (kv). Dari 264 sel benign, 134 berubah signifikan setelah Holm.

**6. Token `=` tandanya terbalik antar sumber.** Benign margin-nya positif di lima sumber yang benign-nya key=value (+13,0 `paper1x`, +19,7 `ecml`, +6,5 `modsec`, +1,9 `csic`, +1,7 `crs`) dan negatif di tiga sumber lain (−14,5 `hpd`, −16,6 `gran`, −11,6 `fwaf`). Total ada 170 fitur yang tandanya terbalik.

**7. Container canonicalization memotong false positive lintas dataset sekitar 21 poin.** LR, rata-rata lintas dataset:

| Perlakuan | FPR | Serangan ter-flag | Balanced accuracy |
|---|---|---|---|
| `lr-raw` | 47,2% | 67,0% | 59,9% |
| Canonicalization (`lr-canon`) | 49,7% | 79,2% | 64,7% |
| + shape augmentation (`lr-canon+aug`) | 39,2% | 78,5% | 69,6% |
| + wadah dibuang (`lr-cstrip`) | 28,9% | 76,5% | 73,8% |
| + keputusan per value (`lr-vmil`) | 24,6% | 72,2% | 73,8% |
| Signature lokal (`sig-canon`) | 1,9% | 46,8% | 72,5% |

Dibanding `lr-canon`, dengan sumber latihan sebagai unit (n = 8, Wilcoxon signed-rank eksak, Holm untuk tiga perbandingan LR):

- `lr-cstrip`: FPR turun 20,8 poin, membaik di 7 dari 8 sumber, p = 0,016 (Holm 0,031). Deteksi serangan turun 2,6 poin (p = 0,64). FPR in-distribution naik 0,7 poin (p = 0,81).
- `lr-vmil`: FPR turun 25,1 poin, membaik di 8 dari 8 sumber, p = 0,008 (Holm 0,023). Deteksi serangan turun 7,0 poin (p = 0,25).
- Balanced accuracy lintas dataset naik 9,1 poin (`lr-cstrip`), 9,0 poin (`lr-vmil`), dan 4,9 poin (shape augmentation); ketiganya signifikan setelah Holm (p = 0,047).
- Learner lain: SVM −21,8 poin (p = 0,016) dan MLP −15,3 poin (p = 0,016) dengan `cstrip`. Di Naive Bayes (−4,5), random forest (−9,7), dan LightGBM (−7,2) arahnya sama tapi tidak signifikan.
- `cstrip` juga membuat keputusan hampir kebal bentuk di empat learner yang diuji intervensinya (LR, random forest, LightGBM, MLP): benign yang keputusannya berubah saat dibungkus JSON turun dari 14.915–20.066 string ke 14–65 string.

Prediksi juga jadi hampir kebal terhadap bentuk: dari 27.763 string benign di test split sendiri, yang keputusannya berubah saat dibungkus JSON turun dari 20.066 (`lr-canon`) ke 53 (`lr-cstrip`).

Ini perbaikan, bukan penyelesaian: FPR lintas dataset masih 25–29%, jauh di atas in-distribution (sekitar 10%). Sisanya adalah pergeseran isi, bukan bentuk.

**8. Yang tidak terbukti.** Tidak ada hubungan peringkat antara separability sebuah sumber dan performa transfernya (Spearman ρ = −0,12, p = 0,79 terhadap balanced accuracy; n = 8). Jadi jangan klaim pola "makin gampang di-fit, makin jelek transfernya".

**9. Di data honeypot, hasilnya ditentukan oleh sumber latihannya, bukan oleh isi input.** Persentase input yang ter-flag oleh `lr-raw` (per string unik):

| Dilatih di | `shell21` | `shell24` | `copot_ssh` | `tpot25` | `copot_web` | `finch` | `vps` | Kontrol (tiga sumber) |
|---|---|---|---|---|---|---|---|---|
| `paper1x` | 100 | 99,9 | 100 | 100 | 55,8 | 35,4 | 4,9 | 99,7–99,9 |
| `csic` | 100 | 99,8 | 99,3 | 100 | 99,9 | 100 | 100 | 100 |
| `crs` | 98,4 | 99,0 | 90,5 | 99,3 | 73,5 | 64,7 | 12,8 | 98,2–99,5 |
| `fwaf` | 95,0 | 87,1 | 61,2 | 98,7 | 92,4 | 68,4 | 92,4 | 0,2–0,9 |
| `gran` | 87,4 | 75,8 | 48,1 | 93,1 | 89,3 | 59,3 | 90,6 | 0,0–0,1 |
| `hpd` | 37,0 | 92,0 | 39,3 | 27,4 | 77,7 | 55,2 | 67,0 | 0,0–0,2 |
| `ecml` | 5,4 | 10,6 | 37,4 | 8,4 | 19,1 | 2,9 | 3,0 | 0,2–0,5 |
| `modsec` | 0,0 | 0,0 | 0,0 | 0,0 | 1,2 | 0,2 | 0,1 | 0,0 |

Satu arsitektur yang sama memberi hasil dari 0% sampai 100% pada input yang sama, tergantung data latihnya. Tiga sumber mem-flag hampir semua username dan password. Signature lokal mem-flag 17,7% perintah SSH, 17,2% parameter web, dan 0,0% kontrol.

Dengan container canonicalization, username dan password berhenti ter-flag: rata-rata kontrol yang ter-flag turun dari 37,5% (`lr-canon`) ke 12,9% (`lr-cstrip`) dan 0,4% (`lr-vmil`, membaik di 8 dari 8 sumber, Holm p = 0,023). Untuk model `paper1x` angkanya turun dari 99,8% ke 0,6%.

Isi input hanya sedikit berpengaruh pada `lr-raw`. Dengan CRS asli sebagai referensi: pada `vps`, model mem-flag 65,3% string yang diblok CRS dan 45,5% string yang tidak; pada `finch` malah terbalik (36,8% lawan 57,0%). Bentuk tetap berpengaruh: rata-rata kontrol yang ter-flag naik dari 37,5% ke sekitar 48% kalau dibungkus `key=value`, dan ke sekitar 73% kalau jadi JSON (signifikan di 5–6 dari 8 sumber latihan).

**10. CRS asli mengalahkan semua detector ML di bawah protokol lintas dataset.** Rata-rata atas delapan benchmark:

| Detector | FPR | Serangan ter-flag | Balanced accuracy |
|---|---|---|---|
| CRS asli, paranoia level 1 | 6,0% | 75,4% | 84,7% |
| CRS asli, paranoia level 2 | 19,8% | 87,0% | 83,6% |
| ML terbaik lintas dataset (`svm-vmil`) | 25,6% | 73,4% | 73,9% |
| `lr-raw` lintas dataset | 47,2% | 67,0% | 59,9% |
| `lr-raw` in-distribution | 8,6% | 97,2% | 94,3% |
| Signature lokal (`sig-canon`) | 1,9% | 46,8% | 72,5% |

Di data sendiri, ML tampak jauh di atas CRS. Begitu diuji di sumber lain, urutannya terbalik. CRS juga tidak sempurna: FPR-nya 17,9% di benign `csic` dan 14,0% di *hard negative* CRS sendiri, dan di level 1 ia hanya menangkap 47,6% SQLi dari korpus paper pertama. Di honeypot, CRS level 1 mem-flag 94,4% perintah SSH dan 0,1% kontrol.

**11. Mengganti wadah juga jalan sebagai evasion.** Payload tidak diubah sama sekali, hanya dipindah ke dalam `key=value` atau JSON (seed pertama):

- `lr-raw` lintas dataset: deteksi turun signifikan di 15 dari 56 sel saat dibungkus `key=value` (paling besar −22,6 poin) dan di 8 sel saat jadi JSON (paling besar −49,4 poin).
- Kasus terburuk: `gbm-raw` yang dilatih di `modsec` kehilangan seluruh deteksinya di data sendiri saat payload dibungkus JSON (5.029 dari 5.030 serangan lolos).
- Shape augmentation tidak aman: `lr-raw+aug` turun signifikan di 28 dari 56 sel saat jadi JSON (paling besar −66,0 poin).
- Dengan `cstrip`, tidak ada satu sel pun yang turun signifikan pada LR dan LightGBM; pada random forest dan MLP tersisa 1–2 sel dari 56, dengan penurunan di bawah 2 poin.

Rata-rata penurunannya kecil (di data sendiri, `lr-raw` dari 97,0% ke 95,9%); masalahnya ada di kasus-kasus tertentu yang runtuh total.

## Batasan yang harus ditulis di paper

- CRS asli dijalankan di luar server web: tiap string ditaruh di request buatan dengan header minimal. Itu mendekati, bukan menyamai, CRS di deployment nyata.
- Keenam learner memakai fitur TF-IDF token yang sama. Model level karakter atau transformer belum diuji.
- Tiga learner tambahan tidak dijalankan dengan `vmil` atau shape augmentation.
- Section evasion hanya menguji pemindahan wadah pada seed pertama, tanpa mutasi payload.
- Container canonicalization tidak membantu merata. Per sel, FPR turun di 35–36 dari 56 sel dan naik di 16–17 sel, tergantung seed. Dua sumber latihan nyaris tidak tertolong oleh `cstrip`: `paper1x` (53,5% → 48,5%) dan `csic` (100,0% → 94,7%). Pada `modsec` FPR malah naik (2,0% → 4,0%).
- Uji signifikansi perbaikan memakai n = 8 sumber latihan, jadi p terkecil yang mungkin hanya 0,008, dan p Holm 0,031–0,047 tidak jauh dari ambang 0,05. Laporkan bersama interval bootstrap-nya.
- `vmil` menurunkan deteksi serangan 7,0 poin. Pelatihan multiple-instance juga bisa salah pilih kalau value yang tampak benign di request serangan tidak pernah muncul di request benign.
- Sebagian "deteksi" yang hilang sebelumnya bukan deteksi sungguhan. Contoh: model `fwaf` di `csic` turun dari 97,9% ke 33,0% serangan ter-flag begitu wadah dibuang, karena sebelumnya ia mem-flag 98,0% benign juga.
- Pemecahan wadah hanya mengenal key=value, JSON, dan path dengan query string. Multipart, XML, dan wadah bersarang belum ditangani.
- Kelas serangan pada sumber honeypot web bukan injection yang terkonfirmasi. Yang bisa diklaim hanya persentase yang ter-flag dan perbedaannya antar sumber latihan.
- Kredensial sebagai kontrol non-injection adalah pilihan desain. Bisa dimatikan per sumber di config.
- Honeypot SSH merekam perintah shell setelah login, bukan payload command injection di parameter web.
- `hpd`, `csic`, dan `gran` bukan koleksi independen. Sel di antara mereka adalah eksperimen alami soal bentuk, bukan replikasi independen.
- `csic` dan `crs` sumber yang lemah untuk dilatih: FPR in-distribution-nya sendiri 27,8% dan 39,7%. Serangan `csic` tidak bertipe; kelas benign `crs` hanya 490 *hard negative*.
- Semua SQLi di `modsec` dikirim sebagai `p=<payload>`, jadi model yang dilatih di sana hampir tidak mem-flag apa pun di sumber lain.
- Standar deviasi antar seed: median 1,2 poin, tapi 4 dari 64 sel di atas 10 poin dan satu sel mencapai 24,3 poin (`hpd` → `csic`). Intervensi bentuk baru dijalankan di seed pertama.
- **Sel lintas dataset rapuh secara numerik.** Sampai versi 0.5.0, LR memakai toleransi default scikit-learn, sehingga L-BFGS berhenti setelah beberapa puluh iterasi. Skor in-distribution tidak terpengaruh, tapi sel lintas dataset yang titik ujinya menumpuk di batas keputusan bisa bergeser puluhan poin antar mesin: `gran` → `fwaf` (FPR, seed 42) keluar 82,8% dengan toleransi default dan 0,9% setelah konvergen. Sejak 0.5.1, LR dan SVM dijalankan sampai konvergen (`tol=1e-8`); ke-64 sel seed 42 keluar identik dengan dua optimizer berbeda (L-BFGS dan Newton-CG untuk LR, dua seed untuk SVM). Rata-rata hampir tidak berubah (FPR lintas dataset `lr-raw` 47,7% → 47,2%) dan semua kesimpulan tetap. Ini layak ditulis sebagai temuan metodologis: angka per sel lintas dataset jangan dilaporkan dari model yang belum konvergen.
- Random forest, LightGBM, dan MLP tidak bisa dibuat identik antar mesin walau seed-nya sama (seri pada pemilihan split dan urutan operasi floating point). Antara mesin uji dan ThinkPad, rata-rata FPR lintas dataset mereka berbeda sampai 1,8 poin. Kesimpulan utama sebaiknya bertumpu pada model linear, dengan tiga learner ini sebagai uji ketahanan.
- Lima sumber benchmark berasal dari 2020 atau sebelumnya (`csic`, `ecml`, `fwaf`, `gran`, `hpd`). Data terbaru ada di `crs`, `patt`, `vps` (2026), `copot`, `finch`, `tpot25` (2025), `modsec`, `shell24` (2024).
- `copot`, `tpot25`, `modsec`, `fwaf`, dan Offensive-Payloads tidak punya lisensi eksplisit. Pakai dengan sitasi, dan jangan disebarkan ulang.
- Varian JSON menambah token kutip dan kurung kurawal, yang juga dipakai payload serangan.
- Rule signature lokal untuk cmdi dan traversal baru dan kecil. Pembanding yang serius adalah `crs-pl1` dan `crs-pl2`.
- Tokenizer `web` beda dari paper pertama (ditambah `|`, `&`, `../`, dan lain-lain), dan canonicalization di sini punya fallback Latin-1.
- `fetch` mengunci `sqlixss-detector` di commit `0dbdc7a` (HEAD saat diuji), bukan `969efcd` yang disitasi paper.
- Kebaruan baru dicek lewat sembilan pencarian web, bukan tinjauan sistematis. Lihat `RELATED_WORK.md`.

## Dari output ke bagian paper

| Bagian paper | Sumber angkanya |
|---|---|
| Benchmark dan audit integritas | `REPORT.md` bagian 0 dan 1, `audit_overlap.csv` |
| Indikator tanpa model | bagian 2, `probe.csv` |
| Transfer matrix | bagian 3, `transfer_summary.csv` |
| Uji kausal (intervensi bentuk) | bagian 4, `interventions.csv` |
| Mekanisme (koefisien) | bagian 5, `explain_sign_flips_raw.csv` |
| Perbaikan (canon, augmentation, container canonicalization) | bagian 7, tabel per konfigurasi di bagian 3 |
| Konsistensi antar learner dan interval bootstrap | bagian 3 |
| CRS asli sebagai pembanding | baris `crs-pl1` dan `crs-pl2` di bagian 3 dan 6 |
| Evasion lewat wadah | bagian 8, `interventions.csv` |
| Related work dan rumusan klaim | `RELATED_WORK.md` |
| Bukti dari honeypot dan daftar payload | bagian 6, baris sumber held-out di `transfer_summary.csv` dan `interventions.csv` |

## Kenapa Python, bukan Rust

- Angka paper pertama dihitung dengan scikit-learn. `shapetrap anchor` bisa mengeluarkan angka Table VI persis karena memakai library yang sama. Implementasi di Rust memakai kode optimisasi yang berbeda, jadi angkanya bisa bergeser dan kesinambungan dengan paper pertama tidak lagi bisa dicek persis.
- Reviewer bisa mereproduksi hasil scikit-learn tanpa memasang toolchain baru.
- Waktu jalan bukan masalah: satu run penuh selesai dalam satu sampai dua jam di CPU laptop, sekali jalan.

Rust baru masuk akal di bagian yang latency-nya penting, yaitu jalur inferensi di proxy WAF.

## Yang belum dikerjakan

- Pencarian literatur yang sistematis di IEEE Xplore, Scopus, dan Google Scholar (kata kuncinya ada di `RELATED_WORK.md`).
- Model level karakter atau transformer kecil, supaya klaimnya tidak terbatas pada fitur TF-IDF token.
- Intervensi dan evasion di ketiga seed, bukan hanya seed pertama.
- Tambah CyberLab, COW160x4, dan SR-BH 2020 (unduh manual, lalu tulis loader-nya).
- Uji di WAF nyata: pasang `cstrip` ke `sqlixss-detector` dan ulang uji lab VM paper pertama.
- Wadah lain: multipart, XML, dan wadah bersarang.
- Honeypot web sendiri kalau mau data yang sepenuhnya milik lu.
