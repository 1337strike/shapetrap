# shapetrap audit report

Generated 2026-11-11 15:05 · Python 3.12.10 · scikit-learn 1.9.1 · NumPy 2.5.4 · SciPy 1.18.1

Seeds [42, 43, 44] · test share 0.25 · cap 20000 per class · tokenizer `web` · 4000 features

## 0. Sources after cleaning

| source | raw | unique | used | families | duplicates | label conflicts | classes used |
|---|---|---|---|---|---|---|---|
| paper1x | 1653 | 1599 | 1599 | 1299 | 54 | 0 | benign 570, cmdi 508, sqli 307, traversal 79, xss 135 |
| hpd | 31067 | 31067 | 31067 | 22841 | 0 | 0 | benign 19304, cmdi 89, sqli 10852, traversal 290, xss 532 |
| csic | 51586 | 16545 | 16545 | 11075 | 35004 | 37 | attack 7272, benign 9273 |
| ecml | 38447 | 38447 | 29485 | 29484 | 0 | 0 | benign 20000, cmdi 767, other 4490, sqli 1497, traversal 1318, xss 1413 |
| gran | 110357 | 109570 | 29076 | 23831 | 784 | 3 | benign 20000, shell 319, sqli 1367, xss 7390 |
| fwaf | 1342608 | 1310660 | 40000 | 31349 | 31947 | 1 | attack 20000, benign 20000 |
| modsec | 528611 | 89181 | 40000 | 31523 | 439430 | 0 | benign 20000, sqli 20000 |
| crs | 3864 | 3248 | 3248 | 2663 | 573 | 43 | benign 490, cmdi 575, other 1209, sqli 786, traversal 25, xss 163 |
| patt (test only) | 36087 | 31174 | 24312 | 18987 | 4913 | 0 | cmdi 487, other 289, sqli 1359, traversal 20000, xss 2177 |
| shell21 (test only) | 12923 | 12923 | 12923 | 3419 | 0 | 0 | shell 12923 |
| shell24 (test only) | 4236 | 4236 | 4236 | 2694 | 0 | 0 | shell 4236 |
| copot_ssh (test only) | 28180 | 28176 | 20190 | 12438 | 2 | 2 | benign 20000, shell 190 |
| tpot25 (test only) | 3920 | 3916 | 3916 | 2071 | 2 | 2 | benign 2081, shell 1835 |
| copot_web (test only) | 2232 | 2232 | 2232 | 2178 | 0 | 0 | attack 2232 |
| finch (test only) | 273 | 273 | 273 | 258 | 0 | 0 | attack 273 |
| vps (test only) | 55136 | 55126 | 22761 | 21882 | 5 | 5 | attack 2761, benign 20000 |

## 1. Integrity audit

Share of the smaller set that also appears in the other source (%). Values are compared after removing the container; short and purely numeric values are ignored.

**Normalized string overlap (%)**

| source | paper1x | hpd | csic | ecml | gran | fwaf | modsec | crs | patt | shell21 | shell24 | copot_ssh | tpot25 | copot_web | finch | vps |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| paper1x | - | 3.7 | 0.0 | 0.0 | 11.1 | 16.5 | 0.1 | 0.1 | 51.1 | 0.4 | 0.3 | 0.1 | 0.4 | 0.3 | 0.7 | 0.4 |
| hpd | 3.7 | - | 0.0 | 0.0 | 58.3 | 0.8 | 0.0 | 0.0 | 1.1 | 0.0 | 0.0 | 1.8 | 3.2 | 0.2 | 0.0 | 1.9 |
| csic | 0.0 | 0.0 | - | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| ecml | 0.0 | 0.0 | 0.0 | - | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| gran | 11.1 | 58.3 | 0.0 | 0.0 | - | 3.4 | 0.0 | 0.2 | 7.2 | 0.2 | 0.4 | 19.3 | 23.4 | 0.7 | 0.0 | 10.9 |
| fwaf | 16.5 | 0.8 | 0.0 | 0.0 | 3.4 | - | 0.0 | 0.2 | 9.7 | 0.0 | 0.0 | 0.1 | 0.2 | 0.1 | 0.0 | 0.0 |
| modsec | 0.1 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | - | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.1 | 0.3 | 0.4 | 0.0 |
| crs | 0.1 | 0.0 | 0.0 | 0.0 | 0.2 | 0.2 | 0.0 | - | 0.1 | 0.0 | 0.0 | 0.0 | 0.1 | 0.0 | 0.0 | 0.1 |
| patt | 51.1 | 1.1 | 0.0 | 0.0 | 7.2 | 9.7 | 0.0 | 0.1 | - | 0.1 | 0.2 | 0.0 | 0.3 | 0.1 | 0.4 | 0.1 |
| shell21 | 0.4 | 0.0 | 0.0 | 0.0 | 0.2 | 0.0 | 0.0 | 0.0 | 0.1 | - | 1.3 | 0.1 | 0.8 | 0.0 | 0.0 | 0.2 |
| shell24 | 0.3 | 0.0 | 0.0 | 0.0 | 0.4 | 0.0 | 0.0 | 0.0 | 0.2 | 1.3 | - | 0.4 | 0.9 | 0.0 | 0.0 | 0.5 |
| copot_ssh | 0.1 | 1.8 | 0.0 | 0.0 | 19.3 | 0.1 | 0.0 | 0.0 | 0.0 | 0.1 | 0.4 | - | 12.6 | 0.3 | 0.0 | 10.7 |
| tpot25 | 0.4 | 3.2 | 0.0 | 0.0 | 23.4 | 0.2 | 0.1 | 0.1 | 0.3 | 0.8 | 0.9 | 12.6 | - | 0.1 | 0.0 | 40.3 |
| copot_web | 0.3 | 0.2 | 0.0 | 0.0 | 0.7 | 0.1 | 0.3 | 0.0 | 0.1 | 0.0 | 0.0 | 0.3 | 0.1 | - | 8.9 | 2.3 |
| finch | 0.7 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.4 | 0.0 | 0.4 | 0.0 | 0.0 | 0.0 | 0.0 | 8.9 | - | 3.7 |
| vps | 0.4 | 1.9 | 0.0 | 0.0 | 10.9 | 0.0 | 0.0 | 0.1 | 0.1 | 0.2 | 0.5 | 10.7 | 40.3 | 2.3 | 3.7 | - |

**Benign value-level overlap (%)**

| source | paper1x | hpd | csic | ecml | gran | fwaf | modsec | crs | patt | shell21 | shell24 | copot_ssh | tpot25 | copot_web | finch | vps |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| paper1x | - | 0.0 | 0.9 | 0.0 | 12.1 | 0.0 | 5.2 | 0.9 | - | - | - | 7.8 | 1.7 | - | - | 9.5 |
| hpd | 0.0 | - | 90.5 | 0.0 | 90.0 | 0.0 | 0.0 | 0.0 | - | - | - | 2.1 | 5.6 | - | - | 2.5 |
| csic | 0.9 | 90.5 | - | 0.0 | 99.5 | 0.0 | 0.1 | 0.2 | - | - | - | 3.7 | 10.0 | - | - | 2.4 |
| ecml | 0.0 | 0.0 | 0.0 | - | 0.1 | 0.0 | 0.0 | 0.4 | - | - | - | 0.1 | 0.6 | - | - | 0.1 |
| gran | 12.1 | 90.0 | 99.5 | 0.1 | - | 0.0 | 1.0 | 5.1 | - | - | - | 26.1 | 41.9 | - | - | 10.9 |
| fwaf | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | - | 0.0 | 0.0 | - | - | - | 0.0 | 0.0 | - | - | 0.0 |
| modsec | 5.2 | 0.0 | 0.1 | 0.0 | 1.0 | 0.0 | - | 3.2 | - | - | - | 1.1 | 3.6 | - | - | 0.8 |
| crs | 0.9 | 0.0 | 0.2 | 0.4 | 5.1 | 0.0 | 3.2 | - | - | - | - | 1.7 | 0.8 | - | - | 2.5 |
| patt | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - |
| shell21 | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - |
| shell24 | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - |
| copot_ssh | 7.8 | 2.1 | 3.7 | 0.1 | 26.1 | 0.0 | 1.1 | 1.7 | - | - | - | - | 23.2 | - | - | 12.3 |
| tpot25 | 1.7 | 5.6 | 10.0 | 0.6 | 41.9 | 0.0 | 3.6 | 0.8 | - | - | - | 23.2 | - | - | - | 72.8 |
| copot_web | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - |
| finch | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - |
| vps | 9.5 | 2.5 | 2.4 | 0.1 | 10.9 | 0.0 | 0.8 | 2.5 | - | - | - | 12.3 | 72.8 | - | - | - |

Largest benign value-level overlap: **csic / gran** at 99.5% (29548 shared values), against 0.0% at string level.

Benchmark sources linked at >= 25% on either level (shared provenance, not independent collections): hpd + csic + gran.

Pairs involving a held-out source at >= 25% (shared payload lists or common credential dictionaries): paper1x / patt; gran / copot_ssh; gran / tpot25; tpot25 / vps.

Cross-source label conflicts on normalized strings: 413.

## 2. What each source looks like before any detector is trained

**Container of each class (% of the class)**

| source | class | empty | kv | json | path | bare |
|---|---|---|---|---|---|---|
| paper1x | benign | 0.0 | 100.0 | 0.0 | 0.0 | 0.0 |
| paper1x | attack | 0.0 | 0.1 | 0.0 | 4.4 | 95.5 |
| hpd | benign | 0.0 | 0.0 | 0.0 | 0.0 | 100.0 |
| hpd | attack | 0.0 | 0.1 | 0.0 | 2.3 | 97.7 |
| csic | benign | 0.0 | 100.0 | 0.0 | 0.0 | 0.0 |
| csic | attack | 0.0 | 100.0 | 0.0 | 0.0 | 0.0 |
| ecml | benign | 0.0 | 83.9 | 0.0 | 0.0 | 16.1 |
| ecml | attack | 0.0 | 84.5 | 0.0 | 0.0 | 15.5 |
| gran | benign | 0.0 | 0.0 | 0.0 | 0.1 | 99.9 |
| gran | attack | 0.0 | 1.7 | 0.0 | 1.6 | 96.7 |
| fwaf | benign | 0.0 | 0.0 | 0.0 | 95.5 | 4.5 |
| fwaf | attack | 0.0 | 0.1 | 0.0 | 55.3 | 44.6 |
| modsec | benign | 0.0 | 93.9 | 0.0 | 0.3 | 5.9 |
| modsec | attack | 0.0 | 100.0 | 0.0 | 0.0 | 0.0 |
| crs | benign | 0.0 | 84.7 | 2.0 | 0.2 | 13.1 |
| crs | attack | 0.0 | 62.1 | 8.3 | 0.1 | 29.5 |
| patt | attack | 0.0 | 0.1 | 0.0 | 9.2 | 90.7 |
| shell21 | attack | 0.0 | 0.1 | 0.0 | 0.0 | 99.9 |
| shell24 | attack | 0.0 | 0.0 | 0.0 | 0.0 | 100.0 |
| copot_ssh | control | 0.0 | 0.0 | 0.0 | 0.0 | 100.0 |
| copot_ssh | attack | 0.0 | 0.0 | 0.0 | 0.0 | 100.0 |
| tpot25 | control | 0.0 | 0.0 | 0.0 | 0.0 | 100.0 |
| tpot25 | attack | 0.0 | 0.0 | 0.0 | 0.0 | 100.0 |
| copot_web | attack | 0.0 | 88.6 | 0.0 | 0.3 | 11.1 |
| finch | attack | 0.0 | 55.3 | 2.9 | 0.0 | 41.8 |
| vps | control | 0.0 | 0.0 | 0.0 | 0.0 | 100.0 |
| vps | attack | 0.0 | 98.4 | 0.0 | 0.0 | 1.5 |

**How far the container alone separates the classes (benchmark sources)**

| source | majority rate (%) | one-bit rule (%) | shape-only probe (%) | separability AUC |
|---|---|---|---|---|
| paper1x | 64.4 | 99.9 (is `kv`) | 99.9 | 1.0000 |
| hpd | 62.1 | 63.0 (is `bare`) | 63.1 | 0.9998 |
| csic | 56.0 | 56.1 (is `kv`) | 48.4 | 0.7664 |
| ecml | 67.8 | 61.9 (is `kv`) | 68.0 | 0.9997 |
| gran | 68.8 | 69.8 (is `bare`) | 69.9 | 0.9994 |
| fwaf | 50.0 | 70.1 (is `path`) | 70.0 | 0.9971 |
| modsec | 50.0 | 53.1 (is `kv`) | 94.1 | 1.0000 |
| crs | 84.9 | 55.1 (is `kv`) | 85.1 | 0.8859 |

The one-bit rule predicts benign from a single fact: whether the input has the container most common among that source's benign inputs. The shape-only probe is a logistic model on container features only (grouped 5-fold accuracy).

**Rank association with mean cross-dataset performance**

| probe | transfer metric | Spearman rho | exact p |
|---|---|---|---|
| separability AUC | bal. acc. out | -0.214 | 0.619 |
| separability AUC | FPR out | -0.619 | 0.115 |
| shape-only probe | bal. acc. out | 0.024 | 0.977 |
| shape-only probe | FPR out | -0.286 | 0.501 |
| one-bit rule | bal. acc. out | -0.119 | 0.793 |
| one-bit rule | FPR out | 0.452 | 0.267 |

n = 8 sources. With so few points every p-value is coarse; read the direction, not the significance.

## 3. Cross-dataset transfer

Headline configuration: `lr-raw`. Rows are the training source, columns the test source; the diagonal is in-distribution. Means over seeds.

**Benign inputs flagged (false-positive rate, %)**

| train \ test | paper1x | hpd | csic | ecml | gran | fwaf | modsec | crs |
|---|---|---|---|---|---|---|---|---|
| paper1x | 0.0 | 99.7 | 0.0 | 0.1 | 99.8 | 99.7 | 12.5 | 43.9 |
| hpd | 81.4 | 0.0 | 46.7 | 44.7 | 0.2 | 2.4 | 21.3 | 58.3 |
| csic | 100.0 | 100.0 | 27.7 | 99.9 | 100.0 | 100.0 | 99.6 | 100.0 |
| ecml | 1.2 | 3.7 | 0.0 | 0.1 | 4.2 | 2.8 | 35.7 | 16.5 |
| gran | 93.7 | 0.2 | 100.0 | 98.8 | 0.2 | 1.3 | 92.8 | 68.9 |
| fwaf | 96.1 | 1.6 | 100.0 | 99.8 | 5.9 | 0.7 | 87.8 | 89.0 |
| modsec | 0.0 | 0.0 | 0.0 | 0.1 | 0.7 | 0.0 | 0.0 | 11.1 |
| crs | 16.8 | 92.1 | 0.1 | 10.2 | 92.6 | 98.7 | 10.6 | 40.2 |

**Attack inputs flagged (detection rate, %)**

| train \ test | paper1x | hpd | csic | ecml | gran | fwaf | modsec | crs |
|---|---|---|---|---|---|---|---|---|
| paper1x | 99.9 | 99.2 | 2.3 | 6.3 | 95.4 | 96.6 | 68.8 | 62.1 |
| hpd | 57.1 | 99.8 | 50.2 | 53.7 | 87.9 | 61.8 | 71.7 | 60.0 |
| csic | 100.0 | 100.0 | 89.7 | 100.0 | 99.9 | 100.0 | 100.0 | 100.0 |
| ecml | 22.3 | 65.8 | 16.3 | 98.8 | 20.6 | 24.0 | 95.2 | 24.4 |
| gran | 74.8 | 99.3 | 98.3 | 97.1 | 98.1 | 74.3 | 79.4 | 73.2 |
| fwaf | 85.7 | 99.7 | 99.5 | 99.9 | 99.1 | 97.1 | 99.8 | 97.2 |
| modsec | 8.7 | 20.2 | 4.6 | 20.8 | 4.0 | 10.5 | 99.9 | 20.3 |
| crs | 94.0 | 97.5 | 12.4 | 55.1 | 92.1 | 94.1 | 100.0 | 93.5 |

**Balanced accuracy (%)**

| train \ test | paper1x | hpd | csic | ecml | gran | fwaf | modsec | crs |
|---|---|---|---|---|---|---|---|---|
| paper1x | 99.9 | 49.8 | 51.1 | 53.1 | 47.8 | 48.5 | 78.1 | 59.1 |
| hpd | 37.8 | 99.9 | 51.8 | 54.5 | 93.8 | 79.7 | 75.2 | 50.8 |
| csic | 50.0 | 50.0 | 81.0 | 50.0 | 50.0 | 50.0 | 50.2 | 50.0 |
| ecml | 60.5 | 81.1 | 58.2 | 99.3 | 58.2 | 60.6 | 79.8 | 54.0 |
| gran | 40.5 | 99.6 | 49.2 | 49.1 | 99.0 | 86.5 | 43.3 | 52.2 |
| fwaf | 44.8 | 99.0 | 49.8 | 50.0 | 96.6 | 98.2 | 56.0 | 54.1 |
| modsec | 54.3 | 60.1 | 52.3 | 60.3 | 51.7 | 55.2 | 100.0 | 54.6 |
| crs | 88.6 | 52.7 | 56.1 | 72.5 | 49.7 | 47.7 | 94.7 | 76.7 |

3 seed(s); the largest standard deviation across seeds in the two rate matrices is 25.0 points. Leakage purge: at most 592 test strings removed from a cell (gran -> hpd).

**Per training source (`lr-raw`): in-distribution versus mean of the other sources**

| source | FPR in | FPR out | det in | det out | bal.acc in | bal.acc out |
|---|---|---|---|---|---|---|
| paper1x | 0.0 | 50.8 | 99.9 | 61.5 | 99.9 | 55.4 |
| hpd | 0.0 | 36.4 | 99.8 | 63.2 | 99.9 | 63.4 |
| csic | 27.7 | 99.9 | 89.7 | 100.0 | 81.0 | 50.0 |
| ecml | 0.1 | 9.1 | 98.8 | 38.4 | 99.3 | 64.6 |
| gran | 0.2 | 65.1 | 98.1 | 85.2 | 99.0 | 60.1 |
| fwaf | 0.7 | 68.6 | 97.1 | 97.3 | 98.2 | 64.3 |
| modsec | 0.0 | 1.7 | 99.9 | 12.7 | 100.0 | 55.5 |
| crs | 40.2 | 45.9 | 93.5 | 77.9 | 76.7 | 66.0 |

**Detection by attack type (`lr-raw`, %, mean over cells whose test source labels the type)**

| type | in-distribution | cells | cross-dataset | cells |
|---|---|---|---|---|
| sqli | 98.1 | 6 | 75.9 | 42 |
| xss | 96.4 | 5 | 68.2 | 35 |
| cmdi | 93.9 | 4 | 60.3 | 28 |
| traversal | 91.9 | 4 | 58.7 | 28 |

**In-distribution versus mean cross-dataset, per configuration**

| config | FPR in | FPR out | det in | det out | bal.acc in | bal.acc out | FPR out (abstain) | det out (abstain) |
|---|---|---|---|---|---|---|---|---|
| `lr-raw` | 8.6 | 47.2 | 97.1 | 67.0 | 94.2 | 59.9 | 38.7 | 66.6 |
| `lr-raw+aug` | 10.3 | 40.5 | 96.8 | 66.5 | 93.3 | 63.0 | 37.9 | 66.2 |
| `lr-canon` | 10.3 | 49.7 | 96.6 | 79.2 | 93.1 | 64.8 | 41.2 | 79.0 |
| `lr-canon+aug` | 10.4 | 39.3 | 96.2 | 78.5 | 92.9 | 69.6 | 36.6 | 78.4 |
| `lr-cstrip` | 11.0 | 28.8 | 93.9 | 76.6 | 91.4 | 73.9 | 24.4 | 76.3 |
| `lr-vmil` | 9.9 | 24.4 | 92.8 | 72.1 | 91.5 | 73.8 | 24.4 | 72.1 |
| `mnb-raw` | 13.6 | 42.4 | 93.7 | 67.6 | 90.1 | 62.6 | 37.6 | 67.5 |
| `mnb-raw+aug` | 13.2 | 45.9 | 94.1 | 75.2 | 90.5 | 64.6 | 41.2 | 75.1 |
| `mnb-canon` | 13.9 | 41.9 | 93.8 | 78.6 | 89.9 | 68.3 | 37.2 | 78.5 |
| `mnb-canon+aug` | 13.8 | 47.9 | 94.5 | 84.2 | 90.3 | 68.1 | 43.2 | 84.1 |
| `mnb-cstrip` | 15.5 | 37.5 | 91.2 | 77.9 | 87.8 | 70.2 | 29.9 | 77.5 |
| `mnb-vmil` | 14.4 | 35.4 | 91.2 | 76.4 | 88.4 | 70.5 | 29.4 | 76.0 |
| `svm-raw` | 8.8 | 50.5 | 97.5 | 70.4 | 94.3 | 60.0 | 42.0 | 70.0 |
| `svm-raw+aug` | 10.4 | 44.4 | 97.1 | 70.6 | 93.4 | 63.1 | 41.7 | 70.3 |
| `svm-canon` | 10.2 | 52.1 | 96.9 | 80.5 | 93.4 | 64.2 | 43.6 | 80.3 |
| `svm-canon+aug` | 10.4 | 43.8 | 96.5 | 80.1 | 93.1 | 68.2 | 41.1 | 80.0 |
| `svm-cstrip` | 11.0 | 30.3 | 94.2 | 77.9 | 91.6 | 73.8 | 25.9 | 77.6 |
| `svm-vmil` | 10.0 | 25.7 | 93.3 | 73.4 | 91.7 | 73.9 | 25.7 | 73.4 |
| `sig-raw` | 1.5 | 1.5 | 37.5 | 37.5 | 68.0 | 68.0 | 1.5 | 37.5 |
| `sig-canon` | 1.9 | 1.9 | 46.8 | 46.8 | 72.4 | 72.5 | 1.9 | 46.8 |
| `rf-raw` | 10.5 | 52.8 | 96.5 | 66.6 | 93.0 | 56.9 | 41.5 | 66.1 |
| `rf-canon` | 10.6 | 55.5 | 95.8 | 75.1 | 92.6 | 59.8 | 44.2 | 74.9 |
| `rf-cstrip` | 11.5 | 44.8 | 93.6 | 78.3 | 91.0 | 66.7 | 31.2 | 77.3 |
| `gbm-raw` | 8.3 | 55.4 | 96.5 | 67.3 | 94.1 | 55.9 | 44.1 | 66.8 |
| `gbm-canon` | 10.7 | 53.9 | 95.7 | 71.4 | 92.5 | 58.8 | 42.6 | 71.2 |
| `gbm-cstrip` | 14.2 | 46.8 | 92.6 | 78.5 | 89.2 | 65.8 | 32.9 | 77.6 |
| `mlp-raw` | 10.2 | 42.8 | 96.9 | 68.2 | 93.3 | 62.7 | 35.3 | 67.7 |
| `mlp-canon` | 10.6 | 45.6 | 96.1 | 79.0 | 92.8 | 66.7 | 38.0 | 78.8 |
| `mlp-cstrip` | 10.9 | 29.1 | 93.8 | 76.4 | 91.4 | 73.7 | 23.0 | 76.0 |
| `crs-pl1` | 5.9 | 5.9 | 75.2 | 75.4 | 84.7 | 84.8 | 5.9 | 75.4 |
| `crs-pl2` | 19.8 | 19.8 | 86.9 | 87.0 | 83.6 | 83.6 | 19.8 | 87.0 |

"Abstain" lets an input through when it shares no feature with the model's vocabulary, instead of deciding from the intercept or prior.

**Consistency across learners (raw input)**

| config | learner | FPR in | FPR out | bal.acc in | bal.acc out | sources with higher FPR out than in |
|---|---|---|---|---|---|---|
| `lr-raw` | linear (logistic regression) | 8.6 | 47.2 | 94.2 | 59.9 | 8/8 |
| `mnb-raw` | linear (naive Bayes) | 13.6 | 42.4 | 90.1 | 62.6 | 8/8 |
| `svm-raw` | linear (SVM) | 8.8 | 50.5 | 94.3 | 60.0 | 8/8 |
| `rf-raw` | bagged trees (random forest) | 10.5 | 52.8 | 93.0 | 56.9 | 8/8 |
| `gbm-raw` | boosted trees (LightGBM) | 8.3 | 55.4 | 94.1 | 55.9 | 8/8 |
| `mlp-raw` | neural network (one hidden layer) | 10.2 | 42.8 | 93.3 | 62.7 | 7/8 |

**Source-level bootstrap, 95% interval** (10,000 resamples of the training sources; `gap` is cross-dataset minus in-distribution)

| config | FPR out | FPR gap | bal.acc out | bal.acc gap |
|---|---|---|---|---|
| `lr-raw` | 47.2 [26.4, 67.8] | 38.6 [19.0, 57.5] | 59.9 [56.1, 63.4] | -34.3 [-40.4, -26.6] |
| `lr-canon` | 49.7 [30.9, 68.1] | 39.4 [22.8, 54.2] | 64.8 [60.0, 68.7] | -28.4 [-33.7, -22.0] |
| `lr-cstrip` | 28.8 [12.4, 50.3] | 17.8 [4.9, 31.7] | 73.9 [66.9, 78.9] | -17.6 [-23.9, -9.7] |
| `lr-vmil` | 24.4 [13.2, 35.8] | 14.6 [5.0, 26.4] | 73.8 [71.0, 76.7] | -17.6 [-26.7, -7.3] |
| `mnb-raw` | 42.4 [25.4, 59.8] | 28.8 [15.1, 45.2] | 62.6 [57.9, 67.1] | -27.4 [-37.5, -16.1] |
| `svm-raw` | 50.5 [29.6, 70.1] | 41.7 [20.8, 60.3] | 60.0 [56.2, 63.5] | -34.4 [-40.5, -26.7] |
| `sig-raw` | 1.5 [1.3, 1.6] | - | 68.0 [66.9, 69.2] | - |
| `sig-canon` | 1.9 [1.6, 2.1] | - | 72.5 [71.5, 73.5] | - |
| `rf-raw` | 52.8 [28.2, 76.4] | 42.3 [20.3, 64.6] | 56.9 [53.0, 61.0] | -36.1 [-44.0, -26.7] |
| `gbm-raw` | 55.4 [30.6, 78.6] | 47.1 [22.0, 70.7] | 55.9 [52.6, 59.5] | -38.2 [-45.6, -28.1] |
| `mlp-raw` | 42.8 [20.7, 65.8] | 32.6 [12.2, 53.2] | 62.7 [58.1, 67.2] | -30.6 [-37.5, -21.7] |
| `crs-pl1` | 5.9 [5.2, 6.4] | - | 84.8 [83.6, 86.1] | - |
| `crs-pl2` | 19.8 [17.8, 21.6] | - | 83.6 [82.4, 84.9] | - |

## 4. Shape-only interventions

Configuration `lr-raw`, first seed. Each model is tested on its **own** source's test split, first as collected and then with only the container changed (`bare`: keys removed; `kv`: wrapped as key=value; `json`: flat JSON object). Content is identical, so any change is caused by shape.

| source | class | flagged as collected (%) | as bare (%) | as kv (%) | as json (%) |
|---|---|---|---|---|---|
| paper1x | benign | 0.0 | 33.6* | 0.0 | 100.0* |
| paper1x | attack | 99.6 | 99.6 | 94.0* | 100.0 |
| hpd | benign | 0.0 | 0.0 | 42.4* | 81.4* |
| hpd | attack | 99.8 | 99.8 | 99.8 | 100.0 |
| csic | benign | 39.7 | 99.9* | 39.7 | 90.0* |
| csic | attack | 88.7 | 98.8* | 88.7 | 99.4* |
| ecml | benign | 0.1 | 4.3* | 0.1 | 3.6* |
| ecml | attack | 98.9 | 99.6* | 98.9 | 99.5* |
| gran | benign | 0.3 | 0.3 | 64.2* | 94.5* |
| gran | attack | 98.5 | 98.4 | 99.7* | 100.0* |
| fwaf | benign | 0.5 | 0.5 | 87.5* | 100.0* |
| fwaf | attack | 97.1 | 97.1 | 99.8* | 100.0* |
| modsec | benign | 0.0 | 0.2 | 0.0 | 0.0 |
| modsec | attack | 100.0 | 99.5* | 100.0 | 99.1* |
| crs | benign | 37.2 | 54.5* | 36.4 | 63.6* |
| crs | attack | 92.8 | 92.5 | 86.0* | 95.9 |

`*` Holm-adjusted exact McNemar p < 0.05 within this configuration and class.

**Benign decisions changed by the container alone, per configuration** (own test split, summed over sources)

| config | benign strings | changed as bare | changed as kv | changed as json |
|---|---|---|---|---|
| `gbm-canon` | 27763 | 1686 | 13066 | 16570 |
| `gbm-cstrip` | 27763 | 0 | 21 | 24 |
| `gbm-raw` | 27763 | 1952 | 12560 | 16600 |
| `lr-canon` | 27763 | 1384 | 9909 | 20090 |
| `lr-canon+aug` | 27763 | 148 | 41 | 59 |
| `lr-cstrip` | 27763 | 0 | 48 | 51 |
| `lr-raw` | 27763 | 1736 | 10694 | 15908 |
| `lr-raw+aug` | 27763 | 156 | 40 | 51 |
| `lr-vmil` | 27763 | 128 | 25 | 23 |
| `mlp-canon` | 27763 | 1451 | 9837 | 18132 |
| `mlp-cstrip` | 27763 | 0 | 56 | 61 |
| `mlp-raw` | 27763 | 1479 | 9515 | 14809 |
| `rf-canon` | 27763 | 1633 | 13544 | 16377 |
| `rf-cstrip` | 27763 | 0 | 64 | 64 |
| `rf-raw` | 27763 | 1615 | 14704 | 16430 |

Across all 264 train/test/variant cells for the benign class, 132 change significantly after Holm adjustment; the largest shift is +100.0 points (paper1x -> paper1x, as json).

Across all 384 train/test/variant cells for the attack class, 188 change significantly after Holm adjustment; the largest shift is +97.2 points (paper1x -> csic, as json).

## 5. What the logistic model learned (`lr-raw`)

Benign margin of each feature: positive is evidence for benign, negative for an attack. Read directly from the coefficients.

**Container tokens**

| token | paper1x | hpd | csic | ecml | gran | fwaf | modsec | crs |
|---|---|---|---|---|---|---|---|---|
| `=` | 13.03 | -14.45 | 1.97 | 19.53 | -16.60 | -11.15 | 6.54 | 1.73 |
| `&` | 4.11 | -1.77 | 2.15 | 3.16 | -12.78 | -2.89 | 9.96 | 2.69 |
| `{` | -0.66 | -3.38 | - | - | -4.98 | -4.09 | 0.50 | -0.51 |
| `}` | -0.80 | -3.48 | - | - | -4.71 | -3.06 | 0.50 | -0.84 |
| `:` | -1.13 | -8.50 | - | - | -2.08 | -1.58 | 1.96 | 0.41 |
| `/` | -3.66 | -3.82 | -0.11 | - | -5.27 | 2.78 | 1.01 | -3.27 |
| `.` | -1.46 | 0.32 | -0.10 | -6.01 | -1.34 | 0.98 | 1.79 | -0.13 |

**Strongest benign cues per source**

| source | features (margin) |
|---|---|
| paper1x | `=` (+13.0), `&` (+4.1), `token =` (+2.8), `qty =` (+2.7), `qty` (+2.7), `token` (+2.7) |
| hpd | `c /` (+2.5), `de` (+1.7), `calle` (+1.7), `s` (+1.0), `8` (+0.9), `3` (+0.9) |
| csic | `c %2F` (+7.4), `l %27` (+7.0), `s %2F` (+6.6), `vino rioja` (+4.9), `d %27` (+4.8), `7 %3F` (+4.6) |
| ecml | `=` (+19.5), `&` (+3.2), `or &` (+2.8), `%5C &` (+2.0), `0 %3A` (+1.9), `. =` (+1.8) |
| gran | `%2C` (+3.8), `%20 (` (+2.8), `o` (+2.8), `%40 .` (+2.3), `%26 %3D` (+2.2), `%3A` (+2.2) |
| fwaf | `/ javascript` (+5.9), `javascript /` (+5.2), `= ping` (+4.8), `javascript` (+4.3), `= |` (+4.1), `2 /` (+4.0) |
| modsec | `&` (+10.0), `=` (+6.5), `4` (+3.4), `= 4` (+2.6), `1 &` (+2.5), `v =` (+2.4) |
| crs | `the` (+4.0), `value` (+3.9), `%24 %29` (+3.6), `text =` (+3.5), `hello` (+3.4), `file =` (+3.3) |

**Features whose sign flips between sources** (|margin| >= 1.0 on both sides): 164. Largest spreads:

| feature | benign cue in | attack cue in | spread |
|---|---|---|---|
| `=` | paper1x csic ecml modsec crs | hpd gran fwaf | 36.1 |
| `&` | paper1x csic ecml modsec crs | hpd gran fwaf | 22.7 |
| `)` | modsec crs | paper1x hpd gran fwaf | 14.0 |
| `all` | fwaf | hpd modsec | 13.1 |
| `%3F` | gran crs | csic | 12.7 |
| `select` | crs | hpd ecml gran fwaf modsec | 12.6 |
| `or` | crs | paper1x hpd ecml gran fwaf modsec | 11.5 |
| `= &` | fwaf modsec | csic | 10.5 |
| `:` | modsec | paper1x hpd gran fwaf | 10.5 |
| `from` | crs | hpd csic ecml gran modsec | 9.2 |
| `= '` | crs | fwaf | 8.9 |
| `id` | csic modsec | hpd ecml gran crs | 8.8 |

**Decision on an input with no known feature (empty or out of vocabulary)**

| source | LR | MNB | SVM |
|---|---|---|---|
| paper1x | cmdi | benign | cmdi |
| hpd | benign | benign | benign |
| csic | attack | benign | attack |
| ecml | benign | benign | benign |
| gran | benign | benign | benign |
| fwaf | benign | attack | benign |
| modsec | benign | benign | benign |
| crs | sqli | other | sqli |

## 6. Held-out evidence

These sources are never trained on; every detector fitted on a benchmark source is applied to them unchanged. *Distinct* counts each different string once; *events* weights a string by how often it was observed. For honeypot sources the attack class means *input received from the wild*: it is hostile traffic, not traffic confirmed to be an injection. The control class (tried usernames and passwords) is hostile input that is not an injection payload.

**Held-out sources as used**

| source | group | period | attack-class strings | events | control strings | events |
|---|---|---|---|---|---|---|
| patt | curated | list as of Oct 2026 | 24312 | 24312 | - | - |
| shell21 | wild-ssh | 2021_2022 | 12923 | 65317 | - | - |
| shell24 | wild-ssh | 2024 | 4236 | 33259 | - | - |
| copot_ssh | wild-ssh | Apr-Jul 2025 | 190 | 348226 | 20000 | 600413 |
| tpot25 | wild-ssh | Nov 2025 | 1835 | 21866 | 2081 | 39251 |
| copot_web | wild-web | 2025 | 2232 | 11538 | - | - |
| finch | wild-web | Jul-Nov 2025 | 273 | 1755 | - | - |
| vps | wild-web | Jun-Oct 2026 | 2761 | 13087 | 20000 | 203128 |

**Attack-class strings flagged, distinct (`lr-raw`, %)**

| trained on | patt | shell21 | shell24 | copot_ssh | tpot25 | copot_web | finch | vps |
|---|---|---|---|---|---|---|---|---|
| paper1x | 99.5 | 100.0 | 99.9 | 100.0 | 100.0 | 55.8 | 35.4 | 4.9 |
| hpd | 32.6 | 37.0 | 92.0 | 39.3 | 27.5 | 77.6 | 55.2 | 66.9 |
| csic | 99.9 | 100.0 | 99.9 | 99.3 | 100.0 | 99.9 | 100.0 | 100.0 |
| ecml | 36.0 | 5.4 | 10.6 | 37.5 | 8.4 | 19.1 | 2.9 | 3.0 |
| gran | 46.4 | 87.5 | 76.2 | 48.4 | 92.9 | 89.5 | 59.3 | 90.6 |
| fwaf | 93.5 | 95.0 | 87.2 | 61.2 | 98.7 | 92.0 | 68.3 | 91.7 |
| modsec | 1.7 | 0.0 | 0.0 | 0.0 | 0.0 | 1.2 | 0.2 | 0.1 |
| crs | 92.1 | 98.5 | 99.2 | 89.8 | 99.6 | 73.5 | 64.1 | 12.8 |
| **mean** | 62.7 | 65.4 | 70.6 | 59.5 | 65.9 | 63.6 | 48.2 | 46.3 |

**Attack-class strings flagged, weighted by events (`lr-raw`, %)**

| trained on | patt | shell21 | shell24 | copot_ssh | tpot25 | copot_web | finch | vps |
|---|---|---|---|---|---|---|---|---|
| paper1x | 99.5 | 100.0 | 100.0 | 100.0 | 100.0 | 53.8 | 45.8 | 24.1 |
| hpd | 32.6 | 23.8 | 37.0 | 1.0 | 29.0 | 73.1 | 77.2 | 73.0 |
| csic | 99.9 | 100.0 | 100.0 | 100.0 | 100.0 | 99.9 | 100.0 | 100.0 |
| ecml | 36.0 | 1.4 | 3.8 | 0.4 | 0.8 | 15.6 | 0.6 | 6.0 |
| gran | 46.4 | 36.6 | 41.2 | 1.0 | 34.9 | 85.7 | 84.3 | 50.0 |
| fwaf | 93.5 | 72.0 | 74.4 | 99.7 | 76.3 | 91.3 | 92.9 | 85.7 |
| modsec | 1.7 | 0.0 | 0.0 | 0.0 | 0.0 | 1.7 | 0.0 | 8.8 |
| crs | 92.1 | 81.7 | 90.6 | 99.9 | 84.6 | 70.9 | 64.0 | 72.8 |
| **mean** | 62.7 | 51.9 | 55.9 | 50.2 | 53.2 | 61.5 | 58.1 | 52.6 |

**Control strings flagged, distinct (`lr-raw`, %)**

| trained on | copot_ssh | tpot25 | vps |
|---|---|---|---|
| paper1x | 99.9 | 99.7 | 99.9 |
| hpd | 0.2 | 0.0 | 0.0 |
| csic | 100.0 | 100.0 | 100.0 |
| ecml | 0.2 | 0.2 | 0.5 |
| gran | 0.1 | 0.0 | 0.0 |
| fwaf | 0.6 | 0.9 | 0.2 |
| modsec | 0.0 | 0.0 | 0.0 |
| crs | 99.3 | 98.2 | 99.5 |
| **mean** | 37.5 | 37.4 | 37.5 |

**Explicit injection syntax or not (`lr-raw`, mean over training sources)**

| source | strings where the OWASP CRS (paranoia level 1) blocks (%) | of those, flagged by the model (%) | of the rest, flagged by the model (%) |
|---|---|---|---|
| patt | 85.7 | 63.7 | 56.8 |
| shell21 | 95.2 | 66.0 | 53.4 |
| shell24 | 97.5 | 71.2 | 47.5 |
| copot_ssh | 85.8 | 59.0 | 62.3 |
| tpot25 | 98.9 | 66.1 | 45.5 |
| copot_web | 57.7 | 71.2 | 53.2 |
| finch | 43.2 | 36.6 | 57.0 |
| vps | 4.3 | 65.4 | 45.4 |

The reference is the real OWASP Core Rule Set run through libmodsecurity. It marks explicit injection syntax; it is not ground truth.

**Per configuration: mean over training sources and over the sources of each group (%)**

| config | wild-ssh: attack flagged | wild-ssh: control flagged | wild-web: attack flagged | wild-web: control flagged | curated: attack flagged | curated: control flagged |
|---|---|---|---|---|---|---|
| `lr-raw` | 65.3 | 37.5 | 52.7 | 37.5 | 62.7 | - |
| `lr-raw+aug` | 64.5 | 12.9 | 50.4 | 12.7 | 55.3 | - |
| `lr-canon` | 73.8 | 37.5 | 57.8 | 37.5 | 67.2 | - |
| `lr-canon+aug` | 83.2 | 13.0 | 53.0 | 12.7 | 58.3 | - |
| `lr-cstrip` | 78.3 | 12.9 | 36.4 | 12.7 | 54.6 | - |
| `lr-vmil` | 66.9 | 0.4 | 26.5 | 0.2 | 45.1 | - |
| `mnb-raw` | 53.6 | 21.3 | 54.0 | 21.1 | 51.7 | - |
| `mnb-raw+aug` | 68.0 | 21.7 | 49.8 | 21.2 | 64.6 | - |
| `mnb-canon` | 63.4 | 21.4 | 57.5 | 21.1 | 58.8 | - |
| `mnb-canon+aug` | 81.3 | 21.7 | 58.0 | 21.2 | 69.5 | - |
| `mnb-cstrip` | 62.5 | 21.3 | 45.0 | 21.0 | 55.9 | - |
| `mnb-vmil` | 55.4 | 16.9 | 39.3 | 16.7 | 48.2 | - |
| `svm-raw` | 70.4 | 37.5 | 53.8 | 37.5 | 66.0 | - |
| `svm-raw+aug` | 66.2 | 12.9 | 52.0 | 12.7 | 60.3 | - |
| `svm-canon` | 76.4 | 37.5 | 59.2 | 37.5 | 69.4 | - |
| `svm-canon+aug` | 84.2 | 13.0 | 55.5 | 12.7 | 59.8 | - |
| `svm-cstrip` | 80.9 | 13.0 | 37.2 | 12.7 | 58.0 | - |
| `svm-vmil` | 68.0 | 0.5 | 27.0 | 0.3 | 48.7 | - |
| `sig-raw` | 17.7 | 0.0 | 11.8 | 0.0 | 26.9 | - |
| `sig-canon` | 17.7 | 0.0 | 17.2 | 0.0 | 40.7 | - |
| `rf-raw` | 67.0 | 50.0 | 56.7 | 50.0 | 61.0 | - |
| `rf-canon` | 70.1 | 50.0 | 60.0 | 50.0 | 67.9 | - |
| `rf-cstrip` | 73.2 | 37.6 | 49.0 | 37.6 | 64.6 | - |
| `gbm-raw` | 68.7 | 50.0 | 57.7 | 50.0 | 56.5 | - |
| `gbm-canon` | 76.2 | 50.0 | 59.7 | 50.0 | 63.9 | - |
| `gbm-cstrip` | 75.1 | 37.5 | 50.5 | 37.5 | 61.7 | - |
| `mlp-raw` | 66.7 | 33.4 | 50.0 | 33.4 | 62.3 | - |
| `mlp-canon` | 74.5 | 33.5 | 55.5 | 33.4 | 67.7 | - |
| `mlp-cstrip` | 77.1 | 17.0 | 37.0 | 16.8 | 54.7 | - |
| `crs-pl1` | 94.3 | 0.1 | 35.1 | 0.0 | 85.7 | - |
| `crs-pl2` | 97.2 | 0.3 | 39.3 | 0.1 | 89.8 | - |

`wild-ssh`: SSH/Telnet honeypots (shell commands typed after login): shell21, shell24, copot_ssh, tpot25.
`wild-web`: Web honeypots and exposed servers (request parameters): copot_web, finch, vps.
`curated`: Curated payload lists (attack strings only): patt.

**Same strings, container changed (`lr-raw`, first seed, distinct, %, mean over training sources)**

| source | class | as observed | as bare | as kv | as json |
|---|---|---|---|---|---|
| patt | attack class | 62.4 | 62.4 (1/8) | 59.8 (7/8) | 74.9 (7/8) |
| shell21 | attack class | 66.1 | 66.1 (0/8) | 66.4 (6/8) | 69.4 (4/8) |
| shell24 | attack class | 72.1 | 72.1 (0/8) | 71.9 (5/8) | 77.3 (5/8) |
| copot_ssh | attack class | 62.3 | 62.3 (0/8) | 64.5 (3/8) | 72.8 (2/8) |
| copot_ssh | control | 37.5 | 37.5 (0/8) | 48.2 (6/8) | 73.4 (6/8) |
| tpot25 | attack class | 67.8 | 67.8 (0/8) | 65.9 (6/8) | 69.0 (3/8) |
| tpot25 | control | 37.3 | 37.3 (0/8) | 48.1 (5/8) | 73.6 (5/8) |
| copot_web | attack class | 62.7 | 60.7 (6/8) | 62.7 (5/8) | 76.1 (6/8) |
| finch | attack class | 49.3 | 38.4 (5/8) | 51.7 (4/8) | 70.4 (4/8) |
| vps | attack class | 45.4 | 37.1 (6/8) | 45.4 (3/8) | 72.5 (6/8) |
| vps | control | 37.5 | 37.5 (0/8) | 48.5 (6/8) | 73.5 (6/8) |

In brackets: training sources for which the change is significant (Holm-adjusted exact McNemar p < 0.05).

## 7. Remedies compared with plain canonicalization

Unit of analysis: the training source (n = 8). Each value is that source's mean over the listed test sources and over seeds. `better` counts sources where the remedy moves the metric in the desired direction. p: exact two-sided Wilcoxon signed-rank test; the three LR rows of each block are Holm-adjusted together.

**FPR, other benchmark sources (%)**

| configuration | remedy | canon | remedy | difference, points [95% bootstrap] | better | p | p (Holm, LR) |
|---|---|---|---|---|---|---|---|
| `lr-canon+aug` | shape augmentation | 49.7 | 39.3 | -10.4 [-16.3, -4.8] | 7/8 | 0.016 | 0.031 |
| `lr-cstrip` | container removed | 49.7 | 28.8 | -20.8 [-32.5, -9.4] | 7/8 | 0.016 | 0.031 |
| `lr-vmil` | container removed, one decision per value | 49.7 | 24.4 | -25.2 [-39.7, -11.4] | 8/8 | 0.008 | 0.023 |
| `mnb-canon+aug` | shape augmentation | 41.9 | 47.9 | +6.0 [-0.8, +14.9] | 5/8 | 0.742 |  |
| `mnb-cstrip` | container removed | 41.9 | 37.5 | -4.4 [-13.6, +4.9] | 5/8 | 0.461 |  |
| `mnb-vmil` | container removed, one decision per value | 41.9 | 35.4 | -6.5 [-14.2, +1.8] | 6/8 | 0.250 |  |
| `svm-canon+aug` | shape augmentation | 52.1 | 43.8 | -8.3 [-15.1, -1.5] | 6/8 | 0.055 |  |
| `svm-cstrip` | container removed | 52.1 | 30.3 | -21.8 [-35.7, -8.9] | 7/8 | 0.016 |  |
| `svm-vmil` | container removed, one decision per value | 52.1 | 25.7 | -26.4 [-41.9, -11.2] | 8/8 | 0.008 |  |
| `rf-cstrip` | container removed | 55.5 | 44.8 | -10.6 [-30.0, +8.1] | 6/8 | 0.312 |  |
| `gbm-cstrip` | container removed | 53.9 | 46.8 | -7.2 [-25.9, +10.5] | 4/8 | 0.844 |  |
| `mlp-cstrip` | container removed | 45.6 | 29.1 | -16.6 [-25.6, -8.4] | 7/8 | 0.016 |  |

**attacks flagged, other benchmark sources (%)**

| configuration | remedy | canon | remedy | difference, points [95% bootstrap] | better | p | p (Holm, LR) |
|---|---|---|---|---|---|---|---|
| `lr-canon+aug` | shape augmentation | 79.2 | 78.5 | -0.7 [-7.8, +5.8] | 3/8 | 0.641 | 1.000 |
| `lr-cstrip` | container removed | 79.2 | 76.6 | -2.6 [-11.2, +6.2] | 3/8 | 0.641 | 1.000 |
| `lr-vmil` | container removed, one decision per value | 79.2 | 72.1 | -7.0 [-16.3, +2.4] | 2/8 | 0.250 | 0.750 |
| `mnb-canon+aug` | shape augmentation | 78.6 | 84.2 | +5.6 [-0.5, +13.2] | 3/8 | 0.742 |  |
| `mnb-cstrip` | container removed | 78.6 | 77.9 | -0.6 [-4.1, +2.9] | 3/8 | 0.742 |  |
| `mnb-vmil` | container removed, one decision per value | 78.6 | 76.4 | -2.2 [-8.3, +2.3] | 5/8 | 0.742 |  |
| `svm-canon+aug` | shape augmentation | 80.5 | 80.1 | -0.3 [-7.3, +6.9] | 3/8 | 0.641 |  |
| `svm-cstrip` | container removed | 80.5 | 77.9 | -2.6 [-11.0, +6.3] | 3/8 | 0.641 |  |
| `svm-vmil` | container removed, one decision per value | 80.5 | 73.4 | -7.0 [-15.8, +2.6] | 2/8 | 0.195 |  |
| `rf-cstrip` | container removed | 75.1 | 78.3 | +3.2 [-7.7, +16.0] | 3/8 | 0.945 |  |
| `gbm-cstrip` | container removed | 71.4 | 78.5 | +7.0 [-6.3, +22.7] | 3/8 | 0.742 |  |
| `mlp-cstrip` | container removed | 79.0 | 76.4 | -2.6 [-8.9, +3.9] | 3/8 | 0.461 |  |

**balanced accuracy, other benchmark sources (%)**

| configuration | remedy | canon | remedy | difference, points [95% bootstrap] | better | p | p (Holm, LR) |
|---|---|---|---|---|---|---|---|
| `lr-canon+aug` | shape augmentation | 64.8 | 69.6 | +4.9 [+1.9, +8.0] | 7/8 | 0.023 | 0.047 |
| `lr-cstrip` | container removed | 64.8 | 73.9 | +9.1 [+4.8, +13.0] | 7/8 | 0.016 | 0.047 |
| `lr-vmil` | container removed, one decision per value | 64.8 | 73.8 | +9.1 [+3.2, +14.4] | 6/8 | 0.039 | 0.047 |
| `mnb-canon+aug` | shape augmentation | 68.3 | 68.1 | -0.2 [-1.7, +1.1] | 5/8 | 0.945 |  |
| `mnb-cstrip` | container removed | 68.3 | 70.2 | +1.9 [-1.4, +5.3] | 5/8 | 0.383 |  |
| `mnb-vmil` | container removed, one decision per value | 68.3 | 70.5 | +2.2 [-2.0, +6.1] | 5/8 | 0.312 |  |
| `svm-canon+aug` | shape augmentation | 64.2 | 68.2 | +4.0 [+1.4, +6.9] | 7/8 | 0.023 |  |
| `svm-cstrip` | container removed | 64.2 | 73.8 | +9.6 [+5.1, +13.7] | 7/8 | 0.016 |  |
| `svm-vmil` | container removed, one decision per value | 64.2 | 73.9 | +9.7 [+4.1, +14.7] | 6/8 | 0.039 |  |
| `rf-cstrip` | container removed | 59.8 | 66.7 | +6.9 [-0.1, +13.8] | 6/8 | 0.148 |  |
| `gbm-cstrip` | container removed | 58.8 | 65.8 | +7.1 [-0.4, +14.6] | 6/8 | 0.148 |  |
| `mlp-cstrip` | container removed | 66.7 | 73.7 | +7.0 [+3.3, +10.3] | 7/8 | 0.016 |  |

**FPR, own source (in-distribution) (%)**

| configuration | remedy | canon | remedy | difference, points [95% bootstrap] | better | p | p (Holm, LR) |
|---|---|---|---|---|---|---|---|
| `lr-canon+aug` | shape augmentation | 10.3 | 10.4 | +0.1 [-0.0, +0.3] | 2/8 | 0.375 | 1.000 |
| `lr-cstrip` | container removed | 10.3 | 11.0 | +0.7 [-0.1, +1.7] | 4/8 | 0.938 | 1.000 |
| `lr-vmil` | container removed, one decision per value | 10.3 | 9.9 | -0.4 [-1.6, +0.4] | 4/8 | 0.812 | 1.000 |
| `mnb-canon+aug` | shape augmentation | 13.9 | 13.8 | -0.1 [-2.2, +1.4] | 2/8 | 0.383 |  |
| `mnb-cstrip` | container removed | 13.9 | 15.5 | +1.6 [+0.1, +3.8] | 2/8 | 0.078 |  |
| `mnb-vmil` | container removed, one decision per value | 13.9 | 14.4 | +0.5 [-1.6, +2.9] | 3/8 | 0.641 |  |
| `svm-canon+aug` | shape augmentation | 10.2 | 10.4 | +0.2 [+0.0, +0.3] | 2/8 | 0.156 |  |
| `svm-cstrip` | container removed | 10.2 | 11.0 | +0.8 [+0.1, +1.8] | 2/8 | 0.156 |  |
| `svm-vmil` | container removed, one decision per value | 10.2 | 10.0 | -0.2 [-1.2, +0.5] | 3/8 | 0.578 |  |
| `rf-cstrip` | container removed | 10.6 | 11.5 | +0.9 [-2.2, +4.7] | 3/8 | 0.938 |  |
| `gbm-cstrip` | container removed | 10.7 | 14.2 | +3.4 [+0.2, +7.7] | 2/8 | 0.078 |  |
| `mlp-cstrip` | container removed | 10.6 | 10.9 | +0.3 [-1.1, +1.9] | 3/8 | 0.938 |  |

**control flagged, honeypot sources (%)**

| configuration | remedy | canon | remedy | difference, points [95% bootstrap] | better | p | p (Holm, LR) |
|---|---|---|---|---|---|---|---|
| `lr-canon+aug` | shape augmentation | 37.5 | 12.9 | -24.6 [-60.8, -0.1] | 4/8 | 0.312 | 0.312 |
| `lr-cstrip` | container removed | 37.5 | 12.8 | -24.6 [-61.0, -0.1] | 6/8 | 0.148 | 0.297 |
| `lr-vmil` | container removed, one decision per value | 37.5 | 0.3 | -37.1 [-74.0, -12.2] | 8/8 | 0.008 | 0.023 |
| `mnb-canon+aug` | shape augmentation | 21.3 | 21.6 | +0.3 [-0.1, +0.6] | 2/8 | 0.195 |  |
| `mnb-cstrip` | container removed | 21.3 | 21.2 | -0.1 [-0.1, -0.0] | 7/8 | 0.055 |  |
| `mnb-vmil` | container removed, one decision per value | 21.3 | 16.8 | -4.5 [-12.5, -0.3] | 8/8 | 0.008 |  |
| `svm-canon+aug` | shape augmentation | 37.5 | 12.9 | -24.6 [-60.8, -0.0] | 4/8 | 0.312 |  |
| `svm-cstrip` | container removed | 37.5 | 12.9 | -24.6 [-60.8, -0.1] | 5/8 | 0.250 |  |
| `svm-vmil` | container removed, one decision per value | 37.5 | 0.4 | -37.1 [-73.8, -12.1] | 7/8 | 0.016 |  |
| `rf-cstrip` | container removed | 50.0 | 37.6 | -12.4 [-37.2, +0.0] | 4/8 | 0.375 |  |
| `gbm-cstrip` | container removed | 50.0 | 37.5 | -12.5 [-37.4, +0.0] | 5/8 | 0.383 |  |
| `mlp-cstrip` | container removed | 33.5 | 16.9 | -16.5 [-40.6, -0.2] | 6/8 | 0.039 |  |

**attack class flagged, honeypot sources (%)**

| configuration | remedy | canon | remedy | difference, points [95% bootstrap] | better | p | p (Holm, LR) |
|---|---|---|---|---|---|---|---|
| `lr-canon+aug` | shape augmentation | 66.9 | 70.3 | +3.4 [-3.9, +13.1] | - | 0.742 | 0.742 |
| `lr-cstrip` | container removed | 66.9 | 60.4 | -6.6 [-15.9, +6.1] | - | 0.195 | 0.391 |
| `lr-vmil` | container removed, one decision per value | 66.9 | 49.6 | -17.3 [-24.7, -9.6] | - | 0.008 | 0.023 |
| `mnb-canon+aug` | shape augmentation | 60.9 | 71.3 | +10.5 [-2.0, +27.2] | - | 0.641 |  |
| `mnb-cstrip` | container removed | 60.9 | 55.0 | -5.9 [-10.3, -1.5] | - | 0.078 |  |
| `mnb-vmil` | container removed, one decision per value | 60.9 | 48.5 | -12.4 [-19.5, -6.0] | - | 0.016 |  |
| `svm-canon+aug` | shape augmentation | 69.0 | 71.9 | +2.9 [-4.2, +12.7] | - | 0.844 |  |
| `svm-cstrip` | container removed | 69.0 | 62.2 | -6.8 [-16.9, +6.2] | - | 0.195 |  |
| `svm-vmil` | container removed, one decision per value | 69.0 | 50.4 | -18.6 [-26.7, -10.3] | - | 0.008 |  |
| `rf-cstrip` | container removed | 65.8 | 62.8 | -2.9 [-14.0, +8.3] | - | 0.547 |  |
| `gbm-cstrip` | container removed | 69.1 | 64.6 | -4.5 [-13.9, +4.5] | - | 0.461 |  |
| `mlp-cstrip` | container removed | 66.3 | 59.9 | -6.4 [-11.2, +0.6] | - | 0.195 |  |

**`lr-cstrip` against `lr-canon`: FPR on the other benchmark sources, per seed**

| seed | canon | cstrip | cells with lower FPR | cells with higher FPR |
|---|---|---|---|---|
| 42 | 48.6 | 28.0 | 35/56 | 18/56 |
| 43 | 49.9 | 30.4 | 34/56 | 18/56 |
| 44 | 50.5 | 28.0 | 35/56 | 18/56 |

## 8. Container change as an evasion vector

Attack strings of each test split, re-sent with only the container changed (first seed). `missed` counts attacks that were flagged as collected and are no longer flagged. `significant drops` counts train/test cells where detection falls (Holm-adjusted exact McNemar p < 0.05 within the configuration).

**Own source (in-distribution)**

| config | attack strings | flagged as collected (%) | as kv (%) | missed (kv) | largest drop, points (kv) | as json (%) | missed (json) | largest drop, points (json) | significant drops (kv , json) |
|---|---|---|---|---|---|---|---|---|---|
| `gbm-canon` | 20354 | 94.1 | 89.7 | 129 | -36.1 (paper1x) | 86.4 | 4438 | -84.8 (modsec) | 1/8 , 2/8 |
| `gbm-cstrip` | 20354 | 91.6 | 91.7 | 13 | -0.1 (gran) | 91.7 | 6 | +0.0 (paper1x) | 0/8 , 0/8 |
| `gbm-raw` | 20354 | 95.2 | 90.8 | 130 | -36.8 (paper1x) | 85.1 | 5104 | -100.0 (modsec) | 1/8 , 1/8 |
| `lr-canon` | 20354 | 95.8 | 94.6 | 71 | -6.9 (crs) | 99.2 | 174 | -3.4 (modsec) | 2/8 , 1/8 |
| `lr-canon+aug` | 20354 | 95.3 | 95.5 | 33 | -0.5 (hpd) | 95.9 | 46 | -0.4 (hpd) | 1/8 , 0/8 |
| `lr-cstrip` | 20354 | 93.3 | 93.3 | 13 | -0.3 (gran) | 93.3 | 0 | +0.0 (paper1x) | 0/8 , 0/8 |
| `lr-raw` | 20354 | 96.9 | 95.8 | 70 | -6.8 (crs) | 99.2 | 54 | -0.9 (modsec) | 2/8 , 1/8 |
| `lr-raw+aug` | 20354 | 96.4 | 96.7 | 34 | -0.5 (hpd) | 96.7 | 60 | -0.5 (gran) | 1/8 , 1/8 |
| `lr-vmil` | 20354 | 92.3 | 92.2 | 39 | -0.5 (fwaf) | 92.2 | 33 | -0.5 (fwaf) | 1/8 , 1/8 |
| `mlp-canon` | 20354 | 95.3 | 94.6 | 58 | -5.0 (crs) | 97.9 | 353 | -6.6 (modsec) | 1/8 , 1/8 |
| `mlp-cstrip` | 20354 | 93.6 | 93.5 | 22 | -0.6 (gran) | 93.6 | 12 | +0.0 (paper1x) | 0/8 , 0/8 |
| `mlp-raw` | 20354 | 96.6 | 95.1 | 90 | -8.6 (paper1x) | 97.7 | 114 | -3.5 (crs) | 2/8 , 1/8 |
| `rf-canon` | 20354 | 94.2 | 92.4 | 69 | -15.0 (paper1x) | 96.6 | 429 | -7.5 (modsec) | 2/8 , 2/8 |
| `rf-cstrip` | 20354 | 92.5 | 92.5 | 6 | -0.1 (gran) | 92.5 | 1 | +0.0 (paper1x) | 0/8 , 0/8 |
| `rf-raw` | 20354 | 96.1 | 94.1 | 99 | -13.9 (paper1x) | 98.6 | 100 | -0.8 (modsec) | 2/8 , 1/8 |

**Other benchmark sources**

| config | attack strings | flagged as collected (%) | as kv (%) | missed (kv) | largest drop, points (kv) | as json (%) | missed (json) | largest drop, points (json) | significant drops (kv , json) |
|---|---|---|---|---|---|---|---|---|---|
| `gbm-canon` | 141420 | 71.7 | 72.0 | 3070 | -27.8 (paper1x -> fwaf) | 76.8 | 2372 | -25.3 (hpd -> csic) | 10/56 , 7/56 |
| `gbm-cstrip` | 141420 | 79.0 | 79.5 | 116 | -0.7 (crs -> gran) | 79.2 | 66 | -0.4 (modsec -> fwaf) | 0/56 , 1/56 |
| `gbm-raw` | 141420 | 67.5 | 68.4 | 2933 | -27.2 (paper1x -> fwaf) | 73.6 | 2620 | -25.3 (crs -> csic) | 8/56 , 7/56 |
| `lr-canon` | 141420 | 79.1 | 78.2 | 3961 | -23.4 (paper1x -> fwaf) | 86.5 | 3453 | -40.6 (modsec -> gran) | 19/56 , 9/56 |
| `lr-canon+aug` | 141420 | 77.9 | 77.1 | 1645 | -16.9 (modsec -> paper1x) | 72.7 | 7200 | -50.7 (gran -> csic) | 12/56 , 28/56 |
| `lr-cstrip` | 141420 | 77.4 | 77.8 | 226 | -0.7 (modsec -> crs) | 77.6 | 58 | -0.0 (ecml -> fwaf) | 0/56 , 0/56 |
| `lr-raw` | 141420 | 65.9 | 65.1 | 4108 | -22.6 (paper1x -> fwaf) | 74.7 | 2624 | -49.4 (gran -> csic) | 15/56 , 8/56 |
| `lr-raw+aug` | 141420 | 64.5 | 64.2 | 1498 | -13.7 (ecml -> hpd) | 60.4 | 7072 | -66.3 (gran -> csic) | 15/56 , 28/56 |
| `lr-vmil` | 141420 | 73.1 | 73.7 | 575 | -2.3 (modsec -> fwaf) | 73.3 | 493 | -2.5 (modsec -> fwaf) | 4/56 , 3/56 |
| `mlp-canon` | 141420 | 79.4 | 78.6 | 3276 | -15.7 (paper1x -> fwaf) | 86.0 | 3726 | -42.9 (modsec -> gran) | 17/56 , 12/56 |
| `mlp-cstrip` | 141420 | 77.4 | 77.6 | 314 | -1.5 (crs -> paper1x) | 77.5 | 82 | -0.5 (crs -> fwaf) | 2/56 , 0/56 |
| `mlp-raw` | 141420 | 66.5 | 64.9 | 4568 | -31.1 (paper1x -> fwaf) | 75.5 | 3537 | -30.9 (modsec -> hpd) | 20/56 , 14/56 |
| `rf-canon` | 141420 | 75.0 | 75.5 | 2692 | -33.8 (crs -> paper1x) | 79.2 | 1917 | -8.3 (modsec -> paper1x) | 9/56 , 11/56 |
| `rf-cstrip` | 141420 | 78.8 | 79.5 | 65 | -0.2 (crs -> fwaf) | 79.1 | 31 | -0.4 (crs -> fwaf) | 0/56 , 0/56 |
| `rf-raw` | 141420 | 67.2 | 67.6 | 2571 | -39.5 (crs -> paper1x) | 73.9 | 1866 | -12.4 (hpd -> modsec) | 8/56 , 5/56 |

A drop means the detector can be evaded by repackaging alone. A rise means it was reacting to the container rather than to the payload.

