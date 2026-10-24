# attos-rust

`attos-client` is the Rust client SDK for Attos, a zero-latency state distribution engine. Attos Cloud compiles your dataset into a static `.attos` blob. This SDK downloads it, memory-maps it, and serves lookups in-process, with a lock-free hot-swap when a new version is published.

## 3-minute quickstart

You need a recent stable Rust toolchain and a free Attos Cloud account.

**1. Sign up** at <https://attoscloud.com/auth/signup>. Every signup gets a Free-tier personal project.

**2. Create a dataset.** Save this as `sample.ndjson`:

```json
{"user_id": "user_1", "attos_value": "free"}
{"user_id": "user_2", "attos_value": "pro"}
{"user_id": "user_3", "attos_value": "enterprise"}
```

In the dashboard open **Datasets → Create dataset** and upload the file. When the status is `ready`, copy the dataset ID shown under the dataset name.

**3. Create an API key** under **Settings → API Keys**. Copy it now: it is only shown once.  New keys start with `at_live_`; keys created earlier start with `nh_live_` and still work.

**4. Look up a key.**

```bash
cargo new attos-demo && cd attos-demo
cargo add attos-client --git https://github.com/Attos-Labs/attos-rust
export ATTOS_API_KEY="at_live_..."
export ATTOS_DATASET_ID="<dataset id from step 2>"
```

```rust
// src/main.rs
use attos_client::{AttosSynchronizer, SyncConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = SyncConfig::new(
        "https://api.attoscloud.com",
        std::env::var("ATTOS_API_KEY")?,
        std::env::var("ATTOS_DATASET_ID")?,
    );
    let sync = AttosSynchronizer::start(cfg)?;

    let map = sync.read();
    println!("user_2 = {}", map.get_string("user_2")?);

    sync.shutdown();
    Ok(())
}
```

```bash
cargo run --release
# user_2 = pro
```

`AttosSynchronizer::start` runs its own background thread, so it works from sync and async code alike. It downloads the blob before it returns, so the first lookup already works. The blob is cached in `./.attos/cache`, and the SDK re-checks for a new version every 30 seconds.

If it fails: `401` means the key is wrong, `404` means the dataset ID is wrong, and `409` means the dataset is still compiling, so retry in a few seconds.

## Create datasets via the API

You can also create a dataset without the dashboard. Upload a CSV or NDJSON file with your API key:

```bash
curl -X POST https://api.attoscloud.com/api/v1/datasets/compile \
  -H "X-API-Key: $ATTOS_API_KEY" \
  -F file=@sample.ndjson \
  -F name=my-dataset
```

The input must have an `attos_value` column; every other column is a key dimension. The response is `201` with `id` (use it as `ATTOS_DATASET_ID`), `name`, `row_count`, `blob_size`, `compression`, `compression_note` and `status`. `name` is optional and defaults to the file name without its extension. Instead of a multipart upload you can send the NDJSON as the request body and set the name with an `X-Dataset-Name` header.

Compression is off by default. To turn on LZ4, add `-F compression=lz4` and optionally `-F block_size=<records>` (for a raw body, use the `X-Attos-Compression` and `X-Attos-Block-Size` headers). With LZ4, each lookup decompresses one block, which costs roughly 0.4 µs per record in the block and allocates. There is no setting for the input format or the blob format version. To replace the data of an existing dataset, `PUT /api/v1/datasets/{id}/data` with the same API key; it counts against your plan's monthly update limit.

Listing and deleting datasets and creating API keys need a dashboard login and are not available with an API key.

## Local files

You can also map a `.attos` file directly, with no cloud involved:

```rust
use attos_client::AttosMap;

let map = AttosMap::open("/var/data/rules.attos")?;
let value = map.get_string("user_123")?;
```

## Configuration

`SyncConfig::new(base_url, api_key, dataset_id)` has public fields you can change before calling `start`:

| Field | Default |
| :--- | :--- |
| `poll_interval` | 30s; `Duration::ZERO` disables background polling |
| `cache_dir` | `./.attos/cache` |
| `node_id` | `ATTOS_NODE_ID`, then the hostname. Nodes are counted by distinct ID. |
| `compression` | `true` (gzip transfer copy) |
| `telemetry_interval` | 60s; `Duration::ZERO` disables telemetry |
| `open` | `OpenConfig`: checksum validation and memory pinning |

## Errors

`AttosError::KeyNotFound` means the key is not in the current dataset. Validation failures (bad magic, unsupported version, corrupt or checksum-failing blob) are typed variants of `AttosError`. While a sync fails, the SDK keeps serving the last good blob.

## Format compatibility

This SDK reads `.attos` format versions 1 and 2 (PTHash, LZ4 blocks, 40-bit offsets, lean keys) from the first release that contains them, and fails closed with an error that names the unsupported feature and says to upgrade the SDK when it meets a newer file. The full table of format features against SDK versions is in [docs/FORMAT_COMPATIBILITY.md](https://github.com/Attos-Labs/attos-cloud/blob/main/docs/FORMAT_COMPATIBILITY.md).
