use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    // Client creation
    #[error("failed to generate master key from seed")]
    SeedDerivation,
    #[error("failed to derive {0} key")]
    KeyDerivation(&'static str),
    #[error("secret spend key not available")]
    MissingSecretKey,

    // Validation
    #[error("wrong network for address {0}")]
    WrongNetwork(String),
    #[error("invalid scan range: start ({0}) > end ({1})")]
    InvalidRange(u32, u32),
    #[error("unknown recipient address type")]
    UnknownAddressType,

    // Transaction
    #[error("all outputs must be unspent")]
    UnspentOutputsRequired,
    #[error("missing unsigned transaction")]
    MissingUnsignedTx,
    #[error("prevout for input {0} not in selected utxos")]
    MissingPrevout(usize),
    #[error("input {0} missing witness_utxo in PSBT")]
    MissingWitnessUtxo(usize),
    #[error("unknown silent payment address")]
    UnknownSpAddress,
    #[error("multiple outputs per SP address not supported")]
    MultipleOutputsNotSupported,
    #[error("data output must have an amount of 0")]
    DataOutputNonZero,
    #[error("cannot embed data of length {len}, max is {max}")]
    DataTooLarge { len: usize, max: usize },
    #[error("draining to OP_RETURN not allowed")]
    DrainToOpReturn,
    #[error("no funds available")]
    NoFunds,

    // Wrapped external errors
    #[error(transparent)]
    SilentPayments(#[from] silentpayments::Error),
    #[error(transparent)]
    Secp256k1(#[from] bitcoin::secp256k1::Error),
    #[error(transparent)]
    Bip32(#[from] bitcoin::bip32::Error),
    #[error("sighash: {0}")]
    Sighash(String),
    #[error(transparent)]
    BlockFilter(#[from] bitcoin::bip158::Error),
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    CoinSelection(#[from] bdk_coin_select::InsufficientFunds),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    InvalidHeight(#[from] bitcoin::absolute::ConversionError),
    #[error(transparent)]
    PushBytes(#[from] bitcoin::script::PushBytesError),

    // Address validation (string-wrapped because type differs between bitcoin 0.31/0.32)
    #[error("address: {0}")]
    Address(String),

    // Backend pass-through for downstream crates
    #[error(transparent)]
    Backend(Box<dyn std::error::Error + Send + Sync>),
}

pub type Result<T> = std::result::Result<T, Error>;
