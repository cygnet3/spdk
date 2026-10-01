# Silent Payments Dev Kit

> [!WARNING]
> SPDK currently relies on cryptography that is not professionally reviewed. Be mindful of this when using SPDK with real funds.

SPDK is a library that can be used to build silent payment-based wallets. It consists of these sub-crates:

- **spdk-core**, an internal library that is used for organizing crates within this workspace.
  - Defines a `ChainBackend` trait, that can be used be consumers (e.g. backend-blindbit-v1) to provide chain data.
  - Defines an `Updater` trait, that can be used by wallets to receive updates while scanning the chain.
- **backend-blindbit-v1**, a chain backend that implements a [bip352 light client](https://github.com/setavenger/BIP0352-light-client-specification).
- **local-scanner**, an implementation of the `Scanner` trait that scans through a `ChainBackend`.
- **silentpayments**, the cryptography library that implements silent-payment related operations. Note: although this library passes the test vectors from the BIP, it is not professionally reviewed for security.
- **psbt**, BIP-375 extensions (`signer`, `extractor`) for the `psbt-v2` crate. `Psbt` and the upstream PSBT roles are in `psbt-v2`.
- **spdk-wallet**, a high-level crate that implements a `Client` and a `Scanner`. These can be used to scan the chain for incoming payments, and creating and signing transactions. It reexports `signer`, `extractor`, and `psbt-v2`.

## How to use

If you want to build a silent payments wallet, add **spdk-wallet** to your Cargo.toml:

```toml
[dependencies]
spdk-wallet = { git = "https://github.com/cygnet3/spdk", branch = "master" }
```

The other crates don't need to be imported directly.
By default, this library will use **backend-blindbit-v1** as a chain backend.

## Examples

SPDK is currently being used by [Dana](https://github.com/cygnet3/danawallet), a flutter-based silent payments wallet.
