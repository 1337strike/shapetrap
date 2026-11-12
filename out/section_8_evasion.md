## 8. Container change as an evasion vector

Attack strings of each test split, re-sent with only the container changed (3 seed(s), rates averaged). `missed` counts attacks that were flagged as collected and are no longer flagged (mean over seeds). `significant drops` counts train/test cells where detection falls in every seed (Holm-adjusted exact McNemar p < 0.05 within each seed and configuration); `per seed` gives the count in each seed. The rewrite keeps the payload's characters; whether the attack would still work against a real application is not tested, so a drop measures how sensitive the prediction is to the representation.

**Own source (in-distribution)**

| config | attack strings | flagged as collected (%) | as kv (%) | missed (kv) | largest drop, points (kv) | as json (%) | missed (json) | largest drop, points (json) | significant drops (kv , json) | per seed (kv , json) |
|---|---|---|---|---|---|---|---|---|---|---|
| `gbm-canon` | 20354 | 95.7 | 90.8 | 144 | -37.0 (paper1x) | 88.8 | 3794 | -72.9 (modsec) | 1/8 , 2/8 | 1 / 2 / 3 , 2 / 2 / 2 |
| `gbm-cstrip` | 20354 | 92.6 | 92.6 | 15 | -0.1 (gran) | 92.6 | 8 | +0.0 (paper1x) | 0/8 , 0/8 | 0 / 0 / 0 , 0 / 0 / 0 |
| `gbm-raw` | 20354 | 96.5 | 91.9 | 125 | -36.8 (paper1x) | 88.5 | 4083 | -81.2 (modsec) | 1/8 , 1/8 | 1 / 2 / 2 , 1 / 1 / 2 |
| `lr-canon` | 20354 | 96.6 | 95.6 | 54 | -6.8 (paper1x) | 99.4 | 167 | -3.3 (modsec) | 2/8 , 1/8 | 2 / 2 / 2 , 1 / 1 / 1 |
| `lr-canon+aug` | 20354 | 96.2 | 96.4 | 23 | -0.3 (hpd) | 96.4 | 50 | -0.3 (hpd) | 0/8 , 0/8 | 1 / 0 / 0 , 0 / 0 / 0 |
| `lr-cstrip` | 20354 | 93.9 | 93.9 | 12 | -0.3 (gran) | 93.9 | 0 | +0.0 (paper1x) | 0/8 , 0/8 | 0 / 0 / 0 , 0 / 0 / 0 |
| `lr-raw` | 20354 | 97.1 | 96.3 | 47 | -6.4 (paper1x) | 99.5 | 49 | -0.8 (modsec) | 2/8 , 1/8 | 2 / 2 / 2 , 1 / 1 / 1 |
| `lr-raw+aug` | 20354 | 96.8 | 97.0 | 21 | -0.3 (hpd) | 96.9 | 46 | -0.3 (hpd) | 0/8 , 0/8 | 1 / 0 / 0 , 1 / 0 / 0 |
| `lr-vmil` | 20354 | 92.8 | 92.8 | 36 | -0.4 (fwaf) | 92.8 | 26 | -0.4 (fwaf) | 0/8 , 0/8 | 1 / 1 / 0 , 1 / 1 / 0 |
| `mlp-canon` | 20354 | 96.1 | 95.7 | 41 | -4.1 (paper1x) | 98.6 | 325 | -6.4 (modsec) | 0/8 , 1/8 | 1 / 2 / 0 , 1 / 1 / 1 |
| `mlp-cstrip` | 20354 | 93.8 | 93.7 | 16 | -0.4 (crs) | 93.8 | 10 | +0.0 (paper1x) | 0/8 , 0/8 | 0 / 0 / 0 , 0 / 0 / 0 |
| `mlp-raw` | 20354 | 96.9 | 96.2 | 49 | -5.3 (paper1x) | 98.7 | 95 | -1.4 (modsec) | 0/8 , 1/8 | 2 / 1 / 0 , 1 / 1 / 1 |
| `rf-canon` | 20354 | 95.8 | 94.3 | 59 | -12.4 (paper1x) | 98.3 | 271 | -4.6 (modsec) | 2/8 , 1/8 | 2 / 2 / 2 , 2 / 1 / 2 |
| `rf-cstrip` | 20354 | 93.6 | 93.5 | 9 | -0.2 (crs) | 93.6 | 2 | +0.0 (paper1x) | 0/8 , 0/8 | 0 / 0 / 0 , 0 / 0 / 0 |
| `rf-raw` | 20354 | 96.5 | 94.9 | 74 | -13.0 (paper1x) | 99.1 | 71 | -0.5 (modsec) | 1/8 , 1/8 | 2 / 2 / 1 , 1 / 1 / 1 |

**Other benchmark sources**

| config | attack strings | flagged as collected (%) | as kv (%) | missed (kv) | largest drop, points (kv) | as json (%) | missed (json) | largest drop, points (json) | significant drops (kv , json) | per seed (kv , json) |
|---|---|---|---|---|---|---|---|---|---|---|
| `gbm-canon` | 141420 | 71.4 | 71.5 | 3326 | -27.6 (paper1x -> fwaf) | 77.7 | 2222 | -4.9 (hpd -> csic) | 7/56 , 4/56 | 10 / 9 / 7 , 7 / 10 / 3 |
| `gbm-cstrip` | 141420 | 78.5 | 78.9 | 188 | -0.6 (crs -> ecml) | 78.6 | 97 | -0.5 (modsec -> fwaf) | 0/56 , 1/56 | 0 / 0 / 1 , 1 / 1 / 1 |
| `gbm-raw` | 141420 | 67.3 | 67.9 | 2904 | -27.2 (paper1x -> fwaf) | 73.5 | 3036 | -26.4 (gran -> csic) | 6/56 , 5/56 | 8 / 9 / 7 , 7 / 6 / 7 |
| `lr-canon` | 141420 | 79.2 | 78.3 | 3863 | -23.8 (paper1x -> fwaf) | 87.8 | 3191 | -40.4 (modsec -> gran) | 17/56 , 8/56 | 19 / 19 / 19 , 9 / 8 / 9 |
| `lr-canon+aug` | 141420 | 78.5 | 77.5 | 1679 | -17.4 (modsec -> paper1x) | 72.5 | 8108 | -57.4 (gran -> csic) | 10/56 , 26/56 | 12 / 14 / 14 , 28 / 28 / 28 |
| `lr-cstrip` | 141420 | 76.6 | 76.9 | 156 | -0.3 (modsec -> crs) | 76.8 | 38 | +0.0 (paper1x -> hpd) | 0/56 , 0/56 | 0 / 0 / 0 , 0 / 0 / 0 |
| `lr-raw` | 141420 | 67.0 | 66.3 | 4116 | -23.3 (paper1x -> fwaf) | 76.9 | 2331 | -43.6 (gran -> csic) | 14/56 , 6/56 | 15 / 16 / 17 , 8 / 7 / 9 |
| `lr-raw+aug` | 141420 | 66.5 | 65.8 | 1594 | -14.4 (modsec -> paper1x) | 61.1 | 8255 | -60.5 (gran -> csic) | 11/56 , 25/56 | 15 / 14 / 13 , 28 / 29 / 29 |
| `lr-vmil` | 141420 | 72.1 | 72.5 | 563 | -2.1 (crs -> fwaf) | 72.2 | 495 | -2.2 (ecml -> fwaf) | 2/56 , 3/56 | 4 / 3 / 3 , 3 / 4 / 4 |
| `mlp-canon` | 141420 | 79.0 | 78.3 | 3267 | -16.0 (paper1x -> fwaf) | 86.8 | 3535 | -46.1 (modsec -> gran) | 13/56 , 8/56 | 17 / 16 / 16 , 12 / 9 / 8 |
| `mlp-cstrip` | 141420 | 76.4 | 76.7 | 212 | -0.6 (crs -> paper1x) | 76.6 | 76 | +0.0 (paper1x -> hpd) | 0/56 , 0/56 | 2 / 0 / 0 , 0 / 0 / 0 |
| `mlp-raw` | 141420 | 68.2 | 66.9 | 4052 | -22.7 (paper1x -> fwaf) | 77.9 | 2930 | -31.7 (modsec -> hpd) | 19/56 , 9/56 | 20 / 19 / 20 , 14 / 9 / 9 |
| `rf-canon` | 141420 | 75.1 | 75.6 | 2531 | -29.7 (crs -> paper1x) | 80.2 | 1739 | -10.3 (modsec -> paper1x) | 8/56 , 4/56 | 9 / 9 / 9 , 11 / 5 / 6 |
| `rf-cstrip` | 141420 | 78.3 | 78.9 | 52 | -0.1 (ecml -> paper1x) | 78.6 | 25 | +0.0 (paper1x -> hpd) | 0/56 , 0/56 | 0 / 0 / 0 , 0 / 0 / 0 |
| `rf-raw` | 141420 | 66.6 | 66.7 | 2899 | -35.3 (crs -> paper1x) | 76.0 | 1070 | -4.0 (ecml -> modsec) | 8/56 , 1/56 | 8 / 10 / 10 , 5 / 1 / 3 |

A drop means the prediction can be changed by repackaging alone. A rise means the detector was reacting to the container as well as to the payload.
