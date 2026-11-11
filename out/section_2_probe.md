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
