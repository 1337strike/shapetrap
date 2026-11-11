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
