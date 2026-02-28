# Minimum Supported Rust Version (MSRV)

This crate supports **Rust 1.78**.

## Downstream Consumers

If you depend on `spdk` and target Rust 1.78, you must pin certain transitive dependencies in your `Cargo.lock`:

```bash
cargo update rayon-core --precise 1.12.1
cargo update minreq --precise 2.12.0
cargo update async-compression --precise 0.4.18
```

### Why?

| Crate | Latest | Pin to | Reason |
|-------|--------|--------|--------|
| `rayon-core` | 1.13+ | 1.12.1 | Uses features requiring Rust 1.80 |
| `minreq` | 2.14+ | 2.12.0 | Uses `std::sync::LazyLock` (stabilized in Rust 1.80) |
| `async-compression` | 0.4.37+ | 0.4.18 | Requires Rust 1.83 |

## Verifying MSRV

```bash
cargo +1.78 check
cargo +1.78 test
```
