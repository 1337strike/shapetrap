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
