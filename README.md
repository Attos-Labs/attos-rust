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
