# Smart Log Analyzer V2

## Detection layers

**Rule-based detection** finds known attack signatures (brute force, password
spray, SQL injection, XSS, impossible travel, insider-threat heuristics).

**Anomaly detection** (optional Isolation Forest) finds statistically unusual
behavioral aggregates across IPs/users in the analyzed dataset.

Anomaly detection does **not** prove malicious intent. Disable it with
`--no-anomaly` if you only want deterministic detectors.
