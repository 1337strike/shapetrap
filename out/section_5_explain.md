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
