# Silent Payments Dev Kit

SPDK is a library that can be used to build silent payment wallets.
It builds on top of [rust-silentpayments](https://github.com/cygnet3/rust-silentpayments).

Whereas rust-silentpayments concerns itself with cryptography (it is essentially a wrapper around secp256k1 for some silent payments logic), SPDK can be used for more high-level operations that are required for wallets, such as scanning for payments from a chain backend, or creating and signing transactions.

SPDK is used as a backend for the silent payment wallet [Dana wallet](https://github.com/cygnet3/danawallet).
