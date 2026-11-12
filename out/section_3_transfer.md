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
| `shape-lr` | 15.5 | 55.2 | 44.6 | 54.5 | 64.6 | 49.7 | 55.2 | 54.5 |

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
| `shape-lr` | 55.2 [32.3, 76.0] | 39.7 [7.1, 69.7] | 49.7 [44.9, 54.6] | -14.9 [-30.7, -0.4] |

**Overlap after the container is removed.** Share of test strings whose container-free, canonicalized form also occurs in the training split: 3.3% on the own source (mean; largest 9.6%), 0.4% on other sources (mean; largest 7.5%, modsec -> paper1x). Without those strings, `lr-raw` flags 47.2% of benign and 67.0% of attack strings on other sources (all strings: 47.2% and 67.0%).

**Robustness: cross-dataset means with dependent or special sources left out** (a source left out is neither trained on nor tested on; for a provenance group the range over the choice of member is shown)

| config | FPR (all benchmark sources, 8 sources) | bal.acc (all benchmark sources) | FPR (one of hpd / csic / gran at a time, 6 sources) | bal.acc (one of hpd / csic / gran at a time) | FPR (without crs, 7 sources) | bal.acc (without crs) |
|---|---|---|---|---|---|---|
| `lr-raw` | 47.2 | 59.9 | 37.9-44.4 | 58.1-62.2 | 46.1 | 60.0 |
| `lr-canon` | 49.7 | 64.8 | 44.5-48.8 | 61.3-67.2 | 48.5 | 65.6 |
| `lr-cstrip` | 28.8 | 73.9 | 26.1-40.1 | 66.4-76.1 | 25.9 | 75.2 |
| `lr-vmil` | 24.4 | 73.8 | 29.1-36.6 | 64.7-72.1 | 20.1 | 75.9 |
| `svm-vmil` | 25.7 | 73.9 | 30.3-37.3 | 64.8-72.3 | 20.8 | 76.0 |
| `crs-pl1` | 5.9 | 84.8 | 4.8-7.8 | 80.6-87.7 | 4.8 | 85.5 |
| `shape-lr` | 55.2 | 49.7 | 39.2-52.0 | 49.8-54.1 | 54.7 | 47.8 |

**Ranking quality and detection at a fixed false-positive rate** (threshold set on each cell's own benign strings so that at most 1% or 5% are flagged; a best-case operating point that puts every detector at the same FPR; mean over cells)

| config | AUC own | AUC other | det @1% FPR own | det @1% FPR other | det @5% FPR own | det @5% FPR other |
|---|---|---|---|---|---|---|
| `lr-raw` | 96.8 | 68.3 | 84.4 | 28.3 | 88.7 | 40.9 |
| `lr-raw+aug` | 96.7 | 69.7 | 85.3 | 29.7 | 88.6 | 42.5 |
| `lr-canon` | 95.6 | 78.4 | 81.3 | 39.3 | 85.7 | 54.5 |
| `lr-canon+aug` | 95.6 | 79.5 | 81.4 | 43.0 | 86.6 | 56.5 |
| `lr-cstrip` | 93.4 | 83.1 | 77.9 | 43.8 | 82.3 | 59.6 |
| `lr-vmil` | 93.4 | 83.2 | 77.1 | 40.6 | 81.5 | 53.6 |
| `mnb-raw` | 93.5 | 71.2 | 77.3 | 32.5 | 79.4 | 44.0 |
| `mnb-raw+aug` | 94.1 | 74.6 | 78.0 | 35.9 | 82.5 | 47.4 |
| `mnb-canon` | 93.4 | 80.5 | 77.4 | 47.7 | 79.6 | 58.2 |
| `mnb-canon+aug` | 93.9 | 83.1 | 77.9 | 52.6 | 81.2 | 63.1 |
| `mnb-cstrip` | 91.8 | 81.6 | 76.0 | 49.5 | 77.6 | 60.8 |
| `mnb-vmil` | 91.6 | 81.9 | 76.5 | 49.8 | 77.8 | 59.6 |
| `svm-raw` | 97.1 | 69.3 | 85.2 | 28.5 | 89.4 | 41.0 |
| `svm-raw+aug` | 96.9 | 69.1 | 85.1 | 28.1 | 88.4 | 41.2 |
| `svm-canon` | 96.0 | 78.8 | 82.3 | 39.6 | 85.9 | 54.4 |
| `svm-canon+aug` | 95.9 | 79.2 | 82.2 | 40.3 | 86.6 | 54.9 |
| `svm-cstrip` | 93.7 | 83.4 | 78.0 | 42.8 | 82.9 | 59.3 |
| `svm-vmil` | 93.9 | 83.1 | 78.7 | 39.5 | 83.0 | 53.6 |
| `rf-raw` | 95.1 | 63.3 | 78.9 | 18.8 | 83.0 | 28.1 |
| `rf-canon` | 93.9 | 71.0 | 75.5 | 29.2 | 79.3 | 41.5 |
| `rf-cstrip` | 92.6 | 74.9 | 68.5 | 33.7 | 73.6 | 44.5 |
| `gbm-raw` | 96.9 | 65.8 | 87.4 | 24.9 | 90.1 | 35.7 |
| `gbm-canon` | 95.7 | 73.9 | 83.6 | 34.1 | 88.3 | 45.7 |
| `gbm-cstrip` | 92.3 | 79.8 | 77.8 | 39.1 | 82.5 | 53.3 |
| `mlp-raw` | 96.1 | 74.3 | 84.9 | 35.0 | 87.5 | 47.8 |
| `mlp-canon` | 95.3 | 82.4 | 82.2 | 49.3 | 86.0 | 61.9 |
| `mlp-cstrip` | 93.7 | 84.3 | 79.9 | 51.1 | 83.8 | 63.5 |
| `shape-lr` | 65.7 | 47.9 | 14.2 | 4.4 | 16.2 | 5.3 |
