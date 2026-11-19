# Changelog

## Unreleased

* Patch updates simplified: the copy/add patch (ATDL v1) is gone; the overflow tail patch (ATDL v2) is the only patch type, negotiated by `X-Attos-Capabilities: patch` (replacing `overflow` and `X-Attos-Accept-Delta`, no longer sent). It applies to any file that starts with the chain's main blob, so a node several versions behind takes the same one patch as a node one behind. The patch header's base size and CRC are no longer checked; the target SHA-256 proves the rebuild. `SyncConfig::delta` still turns it off.
* The redirect cooldown is fixed at one hour; `SyncConfig::redirect_cooldown` is removed.

## 1.5.1 - 2026-11-19

* `AttosClient::reload` and the synchronizer wait for a free retirement slot before mapping a new file, so live + retired + incoming mappings never exceed 1 + `MAX_RETIRED` even while readers are slow to release old maps (the new file used to be mapped first, which could briefly hold one more).
* Tests: the hot-swap stress test waits for the unmap of a just-retired map before counting mapped regions (it raced with a descheduled thread between the last reference dropping and `munmap`; 0 of 50 failures under CPU load, 4 of 15 before); v1 copy/add ops inside a v2 patch and malformed overflow records are refused (same rules as Go, Java, Node, Python).

## 1.5.0 - 2026-11-16

* Warm-up by default in the synchronizer: `OpenConfig::warm_up` reads every page of a newly mapped file before it is published (`SyncConfig::new` sets it; opt out with `config.open.warm_up = false`). Without it each hot swap maps a cold file and first-touch page faults added about 350 to 600 ns to P99 at 100k reads/s. Cost: resident memory equals the file size; the validation pass's pages are no longer dropped when warm-up is on. A direct `AttosMap::open` stays lazy.

## 1.4.0 - 2026-11-13

* Signed artifacts (as in the Go SDK): `SyncConfig::signature_keys` (Ed25519 public keys by key id, `parse_public_key` accepts standard/URL-safe base64) enforces `X-Attos-Signature: alg=ed25519; kid=..; sig=..` over `"attos-artifact-v1\0" + datasetID + "\0" + SHA-256(file)`; downloads, rebuilt patches and the cached file (re-verified from `<dataset>.attos.sig`) fail closed, the current map keeps serving, `signature_errors()` counts rejects. New `AttosError::{SignatureMissing, SignatureInvalid}`.
* Jittered polling as in Go: success and 4xx wait `interval + up to 50 %`, a 402/429 pause is stretched by up to 20 %, transient errors keep 1 s·2^k ±20 %; polling off (0) stays 0. `next_delay` is now random; `next_delay_with` takes the draws.

* Overflow block reader (v2 flag bit 2): inserts, overwrites and tombstones are checked (open-time reject filter, then binary search over XXH64) before the PTHash lookup; `len()` and `scan()` account for them. 0 allocations on the lookup path.
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
