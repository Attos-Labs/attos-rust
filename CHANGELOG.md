# Changelog

## Unreleased

* Signed artifacts (as in the Go SDK): `SyncConfig::signature_keys` (Ed25519 public keys by key id, `parse_public_key` accepts standard/URL-safe base64) enforces `X-Attos-Signature: alg=ed25519; kid=..; sig=..` over `"attos-artifact-v1\0" + datasetID + "\0" + SHA-256(file)`; downloads, rebuilt patches and the cached file (re-verified from `<dataset>.attos.sig`) fail closed, the current map keeps serving, `signature_errors()` counts rejects. New `AttosError::{SignatureMissing, SignatureInvalid}`.
* Jittered polling as in Go: success and 4xx wait `interval + up to 50 %`, a 402/429 pause is stretched by up to 20 %, transient errors keep 1 s·2^k ±20 %; polling off (0) stays 0. `next_delay` is now random; `next_delay_with` takes the draws.

* Overflow block reader (v2 flag bit 2, attos-cloud/docs/OVERFLOW_BLOCK.md): inserts, overwrites and tombstones are checked (open-time reject filter, then binary search over XXH64) before the PTHash lookup; `len()` and `scan()` account for them. 0 allocations on the lookup path.
* Sync advertises `X-Attos-Capabilities: overflow,redirect` and `X-Attos-Accept-Delta: 2`; applies ATDL v1 (copy/add) and v2 (tail) patches into a new file through the usual validate-then-swap path; a failed patch falls back to the full blob.
* Signed redirects: 302 with `X-Attos-Content-Length` is downloaded without credentials, https only, from `storage.googleapis.com`, `*.storage.googleapis.com` or hosts in `SyncConfig::redirect_hosts` / `ATTOS_REDIRECT_HOSTS`; a failed signed download is repeated through the endpoint and switches redirects off for 1 h (`redirect_cooldown`). Ordinary redirects never forward the API key or node ID to another host (the HTTP client no longer follows redirects on its own).
* New: `SyncConfig::{delta, redirect, redirect_hosts, redirect_cooldown}`, `AttosSynchronizer::{delta_stats, redirect_stats}`. Flag bit 2 is no longer an unknown feature.

## 1.3.0 - 2026-10-31

* Fail closed with an explicit error when a file uses a format feature newer than the SDK: `AttosError::UnsupportedFeature` for unknown flag bits, offset widths and fingerprint widths on an intact file; `InvalidVersion` now says to upgrade.
* PTHash v2 format reader with LZ4 blocks and 40-bit offsets (`get_cow`/`get_owned` for compressed files).
* Opt-in lean keys reader.
* Lower serving RSS: random-access advice, pages released after the CRC pass.
* Criterion lookup benchmark.

## 1.2.0

* v1 format reader, sync, telemetry.
