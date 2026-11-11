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
