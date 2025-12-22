//! File I/O operations for PSBTs

use super::error::{IoError, Result};
use super::metadata::{PsbtFile, PsbtMetadata};
use crate::psbt::core::SilentPaymentPsbt;
use std::fs;
use std::path::Path;

/// Save a PSBT to a file (binary format)
pub fn save_psbt_binary<P: AsRef<Path>>(psbt: &SilentPaymentPsbt, path: P) -> Result<()> {
    let bytes = psbt.serialize();
    fs::write(path, bytes)?;
    Ok(())
}

/// Load a PSBT from a file (binary format)
pub fn load_psbt_binary<P: AsRef<Path>>(path: P) -> Result<SilentPaymentPsbt> {
    let bytes = fs::read(path)?;
    let psbt = SilentPaymentPsbt::deserialize(&bytes)
        .map_err(|e| IoError::Other(format!("PSBT deserialization error: {:?}", e)))?;
    Ok(psbt)
}

/// Save a PSBT to a JSON file with metadata
pub fn save_psbt_with_metadata<P: AsRef<Path>>(
    psbt: &SilentPaymentPsbt,
    metadata: Option<PsbtMetadata>,
    path: P,
) -> Result<()> {
    // Serialize PSBT to base64
    let psbt_bytes = psbt.serialize();
    let psbt_base64 = base64_encode(&psbt_bytes);

    // Create PSBT file structure
    let psbt_file = if let Some(mut meta) = metadata {
        meta.update_timestamps();
        PsbtFile::with_metadata(psbt_base64, meta)
    } else {
        PsbtFile::new(psbt_base64)
    };

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&psbt_file)?;
    fs::write(path, json)?;

    Ok(())
}

/// Load a PSBT from a JSON file (with or without metadata)
pub fn load_psbt_with_metadata<P: AsRef<Path>>(
    path: P,
) -> Result<(SilentPaymentPsbt, Option<PsbtMetadata>)> {
    let json = fs::read_to_string(path)?;
    let psbt_file: PsbtFile = serde_json::from_str(&json)?;

    // Decode base64 PSBT
    let psbt_bytes = base64_decode(&psbt_file.psbt)?;
    let psbt = SilentPaymentPsbt::deserialize(&psbt_bytes)
        .map_err(|e| IoError::Other(format!("PSBT deserialization error: {:?}", e)))?;

    Ok((psbt, psbt_file.metadata))
}

/// Save a PSBT in the format determined by file extension
///
/// - `.psbt` -> binary format
/// - `.json` -> JSON format with metadata
pub fn save_psbt<P: AsRef<Path>>(
    psbt: &SilentPaymentPsbt,
    metadata: Option<PsbtMetadata>,
    path: P,
) -> Result<()> {
    let path_ref = path.as_ref();

    match path_ref.extension().and_then(|s| s.to_str()) {
        Some("json") => save_psbt_with_metadata(psbt, metadata, path),
        Some("psbt") => save_psbt_binary(psbt, path),
        _ => Err(IoError::InvalidFormat(format!(
            "Unsupported file extension: {}",
            path_ref.display()
        ))),
    }
}

/// Load a PSBT from a file (auto-detect format)
///
/// Tries to parse as JSON first, falls back to binary format.
pub fn load_psbt<P: AsRef<Path>>(path: P) -> Result<(SilentPaymentPsbt, Option<PsbtMetadata>)> {
    let path_ref = path.as_ref();

    // Try JSON first
    if let Ok((psbt, metadata)) = load_psbt_with_metadata(path_ref) {
        return Ok((psbt, metadata));
    }

    // Fall back to binary
    let psbt = load_psbt_binary(path_ref)?;
    Ok((psbt, None))
}

/// Encode bytes to base64
fn base64_encode(data: &[u8]) -> String {
    use std::io::Write;
    let mut buf = Vec::new();
    {
        let mut encoder =
            base64::write::EncoderWriter::new(&mut buf, &base64::engine::general_purpose::STANDARD);
        encoder
            .write_all(data)
            .expect("writing to Vec<u8> should never fail");
    }
    String::from_utf8(buf).expect("base64 encoding always produces valid UTF-8")
}

/// Decode base64 to bytes
fn base64_decode(data: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|e| IoError::InvalidFormat(format!("Base64 decode error: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::psbt::core::Bip375PsbtExt;
    use tempfile::TempDir;

    fn create_test_psbt() -> SilentPaymentPsbt {
        use bitcoin::transaction::Version;
        use psbt_v2::v2::Global;

        SilentPaymentPsbt {
            global: Global {
                version: psbt_v2::V2,
                tx_version: Version(2),
                fallback_lock_time: None,
                input_count: 0,
                output_count: 0,
                tx_modifiable_flags: 0,
                sp_dleq_proofs: std::collections::BTreeMap::new(),
                sp_ecdh_shares: std::collections::BTreeMap::new(),
                unknowns: std::collections::BTreeMap::new(),
                xpubs: std::collections::BTreeMap::new(),
                proprietaries: std::collections::BTreeMap::new(),
            },
            inputs: Vec::new(),
            outputs: Vec::new(),
        }
    }

    #[test]
    fn test_binary_save_load() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("test.psbt");

        let psbt = create_test_psbt();
        save_psbt_binary(&psbt, &path).unwrap();

        let loaded = load_psbt_binary(&path).unwrap();
        assert_eq!(psbt.num_inputs(), loaded.num_inputs());
        assert_eq!(psbt.num_outputs(), loaded.num_outputs());
    }

    #[test]
    fn test_json_save_load() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("test.json");

        let psbt = create_test_psbt();
        let mut metadata = PsbtMetadata::new();
        metadata.set_creator("test").set_stage("created");

        save_psbt_with_metadata(&psbt, Some(metadata.clone()), &path).unwrap();

        let (loaded, loaded_metadata) = load_psbt_with_metadata(&path).unwrap();
        assert_eq!(psbt.num_inputs(), loaded.num_inputs());
        assert!(loaded_metadata.is_some());
        assert_eq!(loaded_metadata.unwrap().creator, metadata.creator);
    }

    #[test]
    fn test_auto_detect_format() {
        let temp_dir = TempDir::new().unwrap();

        // Test JSON format
        let json_path = temp_dir.path().join("test.json");
        let psbt = create_test_psbt();
        save_psbt(&psbt, None, &json_path).unwrap();
        let (loaded, _) = load_psbt(&json_path).unwrap();
        assert_eq!(psbt.num_inputs(), loaded.num_inputs());

        // Test binary format
        let binary_path = temp_dir.path().join("test.psbt");
        save_psbt(&psbt, None, &binary_path).unwrap();
        let (loaded, _) = load_psbt(&binary_path).unwrap();
        assert_eq!(psbt.num_inputs(), loaded.num_inputs());
    }

    #[test]
    fn test_base64_encoding() {
        let data = b"test data";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(data, decoded.as_slice());
    }
}
