# Data

`NSL_KDD_Train.csv` / `NSL_KDD_Test.csv`: the NSL-KDD network intrusion
benchmark (Tavallaee et al., 2009), fetched from a public GitHub mirror.
41 raw features + a per-connection attack-type label.

v2 adds two synthetic IoT telemetry features on top (`requests_per_min`,
`avg_payload_bytes`) — see the "A note on the data" section in the main
README for exactly how and why, and what to swap in if your final results
need a native IoT capture (N-BaIoT / TON_IoT / CICIoT2023).
