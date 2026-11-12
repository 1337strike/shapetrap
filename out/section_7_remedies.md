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

**Provenance groups as the unit** (each group's mean difference over its member training sources; groups: paper1x; hpd + csic + gran; ecml; fwaf; modsec; crs)

| metric | configuration | difference vs lr-canon, points [95% bootstrap] | better | p | p (Holm, all rows) |
|---|---|---|---|---|---|
| FPR, other benchmark sources | `lr-canon+aug` | -10.7 [-18.1, -3.9] | 5/6 | 0.062 | 0.500 |
| FPR, other benchmark sources | `lr-cstrip` | -18.5 [-30.5, -7.0] | 5/6 | 0.062 | 0.500 |
| FPR, other benchmark sources | `lr-vmil` | -18.8 [-33.2, -5.1] | 6/6 | 0.031 | 0.281 |
| attacks flagged, other benchmark sources | `lr-canon+aug` | -0.4 [-9.9, +7.8] | 3/6 | 1.000 | 1.000 |
| attacks flagged, other benchmark sources | `lr-cstrip` | -0.7 [-11.3, +9.5] | 3/6 | 1.000 | 1.000 |
| attacks flagged, other benchmark sources | `lr-vmil` | -5.0 [-16.7, +6.8] | 2/6 | 0.562 | 1.000 |
| balanced accuracy, other benchmark sources | `lr-canon+aug` | +5.2 [+1.6, +9.1] | 5/6 | 0.062 | 0.500 |
| balanced accuracy, other benchmark sources | `lr-cstrip` | +8.9 [+4.0, +13.0] | 5/6 | 0.062 | 0.500 |
| balanced accuracy, other benchmark sources | `lr-vmil` | +6.9 [+0.7, +12.7] | 4/6 | 0.156 | 0.625 |

With 6 units the smallest attainable two-sided p is 0.031.

**`lr-cstrip` against `lr-canon`: FPR on the other benchmark sources, per seed**

| seed | canon | cstrip | cells with lower FPR | cells with higher FPR |
|---|---|---|---|---|
| 42 | 48.6 | 28.0 | 35/56 | 18/56 |
| 43 | 49.9 | 30.4 | 34/56 | 18/56 |
| 44 | 50.5 | 28.0 | 35/56 | 18/56 |
