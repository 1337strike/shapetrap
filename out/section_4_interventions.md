## 4. Shape-only interventions

Configuration `lr-raw`, 3 seed(s), rates averaged over seeds. Each model is tested on its **own** source's test split, first as collected and then with only the container changed (`bare`: keys removed; `kv`: wrapped as key=value; `json`: flat JSON object). Content is identical, so any change is caused by shape.

| source | class | flagged as collected (%) | as bare (%) | as kv (%) | as json (%) |
|---|---|---|---|---|---|
| paper1x | benign | 0.0 | 37.0* | 0.0 | 100.0* |
| paper1x | attack | 99.9 | 99.9 | 93.5* | 100.0 |
| hpd | benign | 0.0 | 0.0 | 49.9* | 86.1* |
| hpd | attack | 99.8 | 99.8 | 99.9 | 100.0 |
| csic | benign | 27.7 | 100.0* | 27.7 | 95.1* |
| csic | attack | 89.7 | 99.4* | 89.7 | 99.5* |
| ecml | benign | 0.1 | 4.4* | 0.1 | 3.7* |
| ecml | attack | 98.8 | 99.6* | 98.8 | 99.6* |
| gran | benign | 0.2 | 0.2 | 60.0* | 94.3* |
| gran | attack | 98.1 | 97.9 | 99.7* | 100.0* |
| fwaf | benign | 0.7 | 0.7 | 80.0* | 100.0* |
| fwaf | attack | 97.1 | 97.1 | 99.8* | 100.0* |
| modsec | benign | 0.0 | 0.3 | 0.0 | 0.0 |
| modsec | attack | 99.9 | 99.5* | 99.9 | 99.1* |
| crs | benign | 40.2 | 53.3 | 37.9 | 66.0* |
| crs | attack | 93.5 | 94.9 | 89.3* | 97.8 |

`*` Holm-adjusted exact McNemar p < 0.05 in every seed (Holm within each seed, configuration and class).

**Benign decisions changed by the container alone, per configuration** (own test split, summed over sources)

| config | benign strings | changed as bare | changed as kv | changed as json |
|---|---|---|---|---|
| `gbm-canon` | 27763 | 1685 | 11169 | 16120 |
| `gbm-cstrip` | 27763 | 0 | 26 | 25 |
| `gbm-raw` | 27763 | 2083 | 11721 | 16564 |
| `lr-canon` | 27763 | 1515 | 8995 | 19692 |
| `lr-canon+aug` | 27763 | 152 | 38 | 65 |
| `lr-cstrip` | 27763 | 0 | 36 | 39 |
| `lr-raw` | 27763 | 2059 | 9669 | 15927 |
| `lr-raw+aug` | 27763 | 160 | 36 | 53 |
| `lr-vmil` | 27763 | 118 | 19 | 20 |
| `mlp-canon` | 27763 | 1451 | 8486 | 17150 |
| `mlp-cstrip` | 27763 | 0 | 38 | 39 |
| `mlp-raw` | 27763 | 1495 | 9000 | 14509 |
| `rf-canon` | 27763 | 1626 | 13159 | 15994 |
| `rf-cstrip` | 27763 | 0 | 57 | 55 |
| `rf-raw` | 27763 | 1623 | 13509 | 16245 |

For the benign class there are 264 train/test/variant cells (8 training sources x 11 test sources with benign strings x 3 rewrites). Significant after Holm adjustment, per seed: 132 / 132 / 137 of 264; in every seed: 126. The largest mean shift is +100.0 points (paper1x -> paper1x, as json).

For the attack class there are 384 train/test/variant cells (8 training sources x 16 test sources with attack strings x 3 rewrites). Significant after Holm adjustment, per seed: 188 / 199 / 201 of 384; in every seed: 178. The largest mean shift is +97.7 points (paper1x -> csic, as json).
