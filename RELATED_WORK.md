# Cek kebaruan dan related work

Dicek 11 November 2026 lewat sembilan pencarian web dan pembacaan tiga paper. Ini bukan tinjauan sistematis. Sebelum submit, ulangi pencariannya di IEEE Xplore, Scopus, dan Google Scholar dengan kata kunci di bagian akhir.

## Kesimpulan

Dari pencarian ini tidak ketemu paper yang melakukan hal yang sama: transfer matrix lintas-dataset untuk detector injection level payload, uji kausal yang hanya mengganti wadah input, dan pengujian pada data honeypot. Tapi tiga bagian dari cerita lu **sudah dikenal**, jadi klaimnya harus digeser supaya tidak dibantah reviewer:

1. Runtuhnya performa lintas dataset sudah mapan di deteksi intrusi jaringan. Yang baru adalah membawanya ke deteksi injection web dan menunjukkan mekanismenya.
2. Memproses request per field atau per value bukan ide baru. Jangan klaim "container canonicalization" sebagai teknik baru. Klaim yang aman: detector ML akademik dan dataset-nya melewatkan langkah ini, dan itu terukur akibatnya.
3. Bahwa CSIC dan ECML/PKDD punya shortcut sudah disebut paper lain (WebSpotter). Yang baru adalah mengukurnya, menunjukkan asal-usul bersama tiga benchmark, dan membuktikannya secara kausal.

## Yang paling dekat dan wajib disitasi

**WebSpotter (NDSS 2026).** Li dkk., *Achieving Interpretable DL-based Web Attack Detection through Malicious Payload Localization*. Paper ini memecah request HTTP jadi unit semantik terkecil (segmen path, parameter query, header, field body termasuk JSON yang diratakan) untuk menunjukkan field mana yang jahat. Penulisnya mencatat bahwa CSIC membuat model overfit dan bahwa penggantian field benign dengan string acak di PKDD menciptakan shortcut. Evaluasinya memakai CSIC, PKDD, dataset baru (FPAD) dan versi out-of-distribution-nya, tapi tidak melatih di satu dataset publik lalu menguji di dataset publik lain.

Beda dengan paper lu: WebSpotter soal interpretabilitas dan lokalisasi payload. Paper lu soal generalisasi: transfer matrix, intervensi wadah, dan honeypot. Dua catatan mereka soal CSIC dan PKDD justru mendukung temuan lu, jadi sitasi sebagai bukti independen.

**Kruegel dan Vigna (ACM CCS 2003), *Anomaly Detection of Web-based Attacks*.** Deteksi anomali dengan model terpisah untuk tiap atribut query. Ini dasar historis untuk analisis per parameter, dan alasan kenapa `vmil` dan `cstrip` tidak boleh diklaim sebagai ide baru. ModSecurity dan CRS juga sudah mem-parsing argumen sebelum memeriksa rule.

**ModSec-Learn (arXiv 2406.13547) dan ModSec-AdvLearn (arXiv 2308.04964).** ML di atas rule CRS, dengan trafik sah dari dunia nyata. Dataset ModSec-Learn dipakai sebagai sumber `modsec` di sini. AdvLearn dan WAF-A-MoLE menguji ketahanan terhadap mutasi payload; itu beda dengan section evasion lu, yang tidak mengubah payload sama sekali, hanya wadahnya.

**Arp dkk. (USENIX Security 2022), *Dos and Don'ts of Machine Learning in Computer Security*.** Sudah disitasi di paper pertama. Sampling bias dan spurious correlation yang mereka daftar adalah kerangka untuk temuan lu.

## Analog di domain tetangga

Generalisasi lintas dataset sudah banyak diteliti untuk deteksi intrusi jaringan, dan shortcut learning mulai diteliti di IDS IoT dan klasifikasi trafik terenkripsi. Judul yang muncul di pencarian (isinya belum gua baca, jadi baca dulu sebelum disitasi):

- *On the Cross-Dataset Generalization of Machine Learning for Network Intrusion Detection* (arXiv 2402.10974)
- *On Generalisability of Machine Learning-based Network Intrusion Detection Systems* (arXiv 2205.04112)
- *Assessing Generalisation Capability of Machine Learning Models for Intrusion Detection* (arXiv 2605.04407)
- *Unmasking Shortcut Learning in IoT Intrusion Detection* (arXiv 2609.28725)
- *Bias in the Shadows: Explore Shortcuts in Encrypted Network Traffic Classification* (arXiv 2601.10180)
- *Cross-Domain Generalization Failure in Lightweight Intrusion Detection Models for IIoT Networks* (arXiv 2607.00553)

Paper temen lu soal phishing URL memakai keluarga metode yang sama di domain lain. Kalau sudah terbit, sitasi juga.

## Contoh praktik yang lu kritik

- **WAMM (arXiv 2512.23610).** Membersihkan dan melabel ulang SR-BH 2020, lalu mengevaluasi model pada split dari dataset yang sama. Tidak ada uji lintas dataset dan tidak ada angka false positive tersendiri; penulisnya sendiri menyebut generalisasi ke technology stack lain sebagai pekerjaan lanjutan. Mereka melaporkan modelnya jauh di atas CRS, pada data yang berasal dari proses pembuatan yang sama.
- **Rosca dkk., *Machine Learning Models for SQL Injection Detection* (Electronics 14(17), 2025).** Satu dataset gabungan, 72.304 query jahat dibuat dengan GPT-4o, evaluasi pada split internal.

Dua ini contoh pola umum: akurasi tinggi di split internal, tanpa uji di data dari sumber lain. Hasil lu soal CRS asli (lihat README) relevan di sini: di bawah protokol lintas dataset, CRS asli level 1 punya false positive 6,0% dan balanced accuracy 84,7%, lawan 25,6% dan 73,9% untuk konfigurasi ML terbaik. Itu kebalikan dari klaim yang biasa muncul di evaluasi in-dataset. Catatan: deteksi mentah CRS level 1 (75,4%) masih di bawah beberapa konfigurasi ML (sampai 80,4%), jadi keunggulannya ada di false positive dan balanced accuracy.

## Yang tampaknya belum ada

Berdasarkan pencarian ini saja:

- Transfer matrix lintas dataset untuk detector injection level payload, dengan audit kebocoran.
- Uji kausal yang isinya identik dan hanya wadahnya diganti.
- Bukti bahwa benign HttpParamsDataset dan koleksi Granqvist berasal dari CSIC 2010.
- Pengujian detector hasil latihan benchmark pada data honeypot, dengan kredensial sebagai kontrol non-injection.
- Perbandingan CRS asli dengan detector ML di bawah protokol lintas dataset yang sama.

## Saran rumusan klaim

Aman:
- "To our knowledge, this is the first leakage-audited cross-dataset study of payload-level injection detectors that isolates the input container as a causal factor."
- "Parsing a request into values before classification, which rule-based WAFs have always done and anomaly detectors have done since Kruegel and Vigna, removes most of the container effect."

Jangan dipakai:
- "We propose a novel preprocessing technique." (bukan teknik baru)
- "ML-based detectors do not generalize." (terlalu umum; hasil lu soal delapan sumber dan enam learner berbasis TF-IDF)
- Klaim apa pun soal recall di data honeypot web.

## Kata kunci untuk pencarian ulang

`cross-dataset` + `SQL injection` / `web attack detection`; `shortcut learning` + `WAF` / `HTTP`; `benign traffic` + `false positive` + `web application firewall` + `machine learning`; `distribution shift` + `payload classification`; `CSIC 2010` + `bias` / `limitations`; `HttpParamsDataset`; `honeypot` + `web attack detection` + `evaluation`.

## Sumber

- [WebSpotter, NDSS 2026](https://www.ndss-symposium.org/wp-content/uploads/2026-s1029-paper.pdf)
- [Kruegel dan Vigna, CCS 2003](https://sites.cs.ucsb.edu/~chris//research/doc/ccs03_webanomaly.pdf)
- [ModSec-Learn, arXiv 2406.13547](https://arxiv.org/pdf/2406.13547)
- [ModSec-AdvLearn, arXiv 2308.04964](https://arxiv.org/pdf/2308.04964)
- [Dos and Don'ts of Machine Learning in Computer Security, arXiv 2010.09470](https://arxiv.org/pdf/2010.09470)
- [WAMM, arXiv 2512.23610](https://arxiv.org/pdf/2512.23610)
- [Machine Learning Models for SQL Injection Detection, Electronics 2025](https://www.mdpi.com/2079-9292/14/17/3420)
- [On the Cross-Dataset Generalization of Machine Learning for Network Intrusion Detection, arXiv 2402.10974](https://arxiv.org/html/2402.10974v1)
- [On Generalisability of Machine Learning-based Network Intrusion Detection Systems, arXiv 2205.04112](https://arxiv.org/pdf/2205.04112)
- [Assessing Generalisation Capability of Machine Learning Models for Intrusion Detection, arXiv 2605.04407](https://arxiv.org/pdf/2605.04407)
- [Unmasking Shortcut Learning in IoT Intrusion Detection, arXiv 2609.28725](https://arxiv.org/abs/2609.28725)
- [Bias in the Shadows, arXiv 2601.10180](https://arxiv.org/html/2601.10180)
- [Cross-Domain Generalization Failure in Lightweight Intrusion Detection Models for IIoT Networks, arXiv 2607.00553](https://arxiv.org/pdf/2607.00553)
