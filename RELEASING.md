# Releasing attos-rust (crate attos-client)

Rules: commit as the maintainer (no AI trailers), `git push origin main` fast-forward only (fetch and rebase first, never force), tag only from `main` after the gates pass. Do not release the Go, Rust and Java SDKs out of step with a compiler change: readers first (see FORMAT_COMPATIBILITY.md).

## Where the version lives

| Where | Current value |
|---|---|
| Crate name | `attos-client` (`Cargo.toml`) |
| Version | `1.2.0` in `Cargo.toml` **and** the `VERSION` constant in `src/lib.rs` (also used in User-Agent and telemetry), plus `Cargo.lock` |
| Release tag | `v1.2.0` exists. The v2 readers on `main` are not in any release |

Cargo.toml has no `license` / `license-file`, `repository`, `readme` or `keywords`; crates.io accepts a crate without them but users and tooling expect them. **Decision for Samarth:** choose the license (there is no LICENSE file in any SDK repo) before the first crates.io publish.

## Before tagging: run the gates

```bash
# from a checkout of Attos-Labs/attos-cloud with attos-go, attos-rust and attos-java next to it
scripts/release-gate/run.sh        # every format option combination read back by all three SDKs (must print "release gate PASSED")
```

## SDK test suite

```bash
cd attos-rust
cargo fmt --check && cargo clippy --all-targets -- -D warnings   # optional but recommended
cargo test --release                                          
./run_tests.sh
```

## Release steps

1. Bump the version in `Cargo.toml` and `src/lib.rs` (`VERSION`), run `cargo build` so `Cargo.lock` updates, update `CHANGELOG.md`.
2. Add the missing metadata to `Cargo.toml` (`license = "..."`, `repository = "https://github.com/Attos-Labs/attos-rust"`, `readme = "README.md"`, `keywords`, `categories`).
3. Dry run, and look at what would be uploaded:
   ```bash
   cargo package --list
   cargo publish --dry-run
   ```
4. Commit, `git push origin main`, tag, push the tag:
   ```bash
   git tag -a v1.3.0 -m "attos-client v1.3.0" && git push origin v1.3.0
   ```
5. Publish:
   ```bash
   cargo login            # paste the API token once; stored in ~/.cargo/credentials.toml
   cargo publish
   ```
6. Smoke test in a scratch project: `cargo add attos-client@1.3.0`, build, open a golden file. Then change the README quickstart from `cargo add attos-client --git ...` to `cargo add attos-client`.

**Credentials Samarth must create:** a crates.io account (log in with GitHub at https://crates.io), verify the email, create an API token at https://crates.io/settings/tokens with the `publish-new` and `publish-update` scopes, and confirm that the name `attos-client` is free (`cargo search attos-client`; if taken, rename the package first). A published version can be yanked (`cargo yank --version 1.3.0`) but never deleted.

## After the release

* Update `docs/FORMAT_COMPATIBILITY.md` in `Attos-Labs/attos-cloud` (the row for this SDK).
* Update the version shown in the dashboard docs and the site, if it names one.
* Announce which format features this release adds, so operators know when it is safe to compile with them.
