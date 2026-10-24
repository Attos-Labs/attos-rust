# Changelog

## Unreleased (first release with v2 readers; suggested version 1.3.0)

* Fail closed with an explicit error when a file uses a format feature newer than the SDK: `AttosError::UnsupportedFeature` for unknown flag bits, offset widths and fingerprint widths on an intact file; `InvalidVersion` now says to upgrade.
* PTHash v2 format reader with LZ4 blocks and 40-bit offsets (`get_cow`/`get_owned` for compressed files).
* Opt-in lean keys reader.
* Lower serving RSS: random-access advice, pages released after the CRC pass.
* Criterion lookup benchmark.

## 1.2.0

* v1 format reader, sync, telemetry.
