# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.6.x | yes |
| older | no |

## Reporting a vulnerability

Please report security problems privately through GitHub: open the **Security** tab of this repository and click **Report a vulnerability**. Do not open a public issue for them.

Include the shapetrap version, your OS and Python version, the command you ran, and the smallest input that shows the problem. You should get a first reply within a week.

Examples of what to report:

- a crafted dataset file or config that makes shapetrap run code, write outside its output folder, or read files it should not
- a crash or memory error in the CRS harness (`src/shapetrap/crs/harness.c`)
- anything that makes `shapetrap fetch` download from a place other than the pinned sources

## Not a vulnerability

shapetrap works with attack payloads on purpose. SQL injection, XSS, command injection, and path traversal strings in the datasets, in `out/`, or in the report are expected and are not a security issue. shapetrap only classifies these strings and passes them to libmodsecurity in memory; it never sends them over the network.

A detector in shapetrap that misses an attack or flags a benign input is a measurement, not a vulnerability. Open a normal issue if you think a result is wrong.
