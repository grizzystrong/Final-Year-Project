# Data

`NSL_KDD_Train.csv` and `NSL_KDD_Test.csv` are the NSL-KDD network intrusion
benchmark (Tavallaee et al., 2009), fetched from a public GitHub mirror of the
dataset maintained by the original NSL-KDD distribution. 41 features + a raw
attack-type label per connection record; see `src/preprocessing.py` for the
column schema and the attack-category mapping.

See the main README's "A note on the dataset" section for why NSL-KDD (a
general network-intrusion benchmark) was used in place of a native IoT
capture, and for pointers to real IoT datasets (N-BaIoT, TON_IoT, CICIoT2023)
if your final results need to be reported on one of those instead.
