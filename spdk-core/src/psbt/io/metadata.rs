//! Metadata structures for PSBT files
//!
//! Provides optional JSON metadata that can be stored alongside PSBTs.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Metadata for a PSBT file
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PsbtMetadata {
    /// Human-readable description of the PSBT
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Creation timestamp (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,

    /// Last modified timestamp (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_at: Option<u64>,

    /// Creator software name and version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creator: Option<String>,

    /// Current role/stage in the workflow
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,

    /// Number of inputs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_inputs: Option<usize>,

    /// Number of outputs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_outputs: Option<usize>,

    /// Number of silent payment outputs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_silent_payment_outputs: Option<usize>,

    /// Whether all inputs have ECDH shares
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecdh_complete: Option<bool>,

    /// Whether all inputs are signed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signatures_complete: Option<bool>,

    /// Whether output scripts have been computed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scripts_computed: Option<bool>,

    /// Custom key-value pairs
    #[serde(flatten)]
    pub custom: HashMap<String, serde_json::Value>,
}

impl PsbtMetadata {
    /// Create new empty metadata
    pub fn new() -> Self {
        Self::default()
    }

    /// Create metadata with a description
    pub fn with_description(description: impl Into<String>) -> Self {
        Self {
            description: Some(description.into()),
            ..Default::default()
        }
    }

    /// Set the creator software
    pub fn set_creator(&mut self, creator: impl Into<String>) -> &mut Self {
        self.creator = Some(creator.into());
        self
    }

    /// Set the current stage
    pub fn set_stage(&mut self, stage: impl Into<String>) -> &mut Self {
        self.stage = Some(stage.into());
        self
    }

    /// Set input/output counts
    pub fn set_counts(&mut self, num_inputs: usize, num_outputs: usize) -> &mut Self {
        self.num_inputs = Some(num_inputs);
        self.num_outputs = Some(num_outputs);
        self
    }

    /// Set silent payment output count
    pub fn set_silent_payment_count(&mut self, count: usize) -> &mut Self {
        self.num_silent_payment_outputs = Some(count);
        self
    }

    /// Set completion status flags
    pub fn set_completion_status(
        &mut self,
        ecdh_complete: bool,
        signatures_complete: bool,
        scripts_computed: bool,
    ) -> &mut Self {
        self.ecdh_complete = Some(ecdh_complete);
        self.signatures_complete = Some(signatures_complete);
        self.scripts_computed = Some(scripts_computed);
        self
    }

    /// Add a custom metadata field
    pub fn add_custom(&mut self, key: impl Into<String>, value: serde_json::Value) -> &mut Self {
        self.custom.insert(key.into(), value);
        self
    }

    /// Update timestamps
    pub fn update_timestamps(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be after Unix epoch (1970-01-01)")
            .as_secs();

        if self.created_at.is_none() {
            self.created_at = Some(now);
        }
        self.modified_at = Some(now);
    }
}

/// PSBT file format with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbtFile {
    /// PSBT data (base64 encoded)
    pub psbt: String,

    /// Optional metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<PsbtMetadata>,
}

impl PsbtFile {
    /// Create a new PSBT file with base64-encoded PSBT
    pub fn new(psbt_base64: String) -> Self {
        Self {
            psbt: psbt_base64,
            metadata: None,
        }
    }

    /// Create a PSBT file with metadata
    pub fn with_metadata(psbt_base64: String, metadata: PsbtMetadata) -> Self {
        Self {
            psbt: psbt_base64,
            metadata: Some(metadata),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_creation() {
        let mut metadata = PsbtMetadata::new();
        metadata
            .set_creator("test-app v1.0")
            .set_stage("signing")
            .set_counts(2, 3);

        assert_eq!(metadata.creator, Some("test-app v1.0".to_string()));
        assert_eq!(metadata.stage, Some("signing".to_string()));
        assert_eq!(metadata.num_inputs, Some(2));
        assert_eq!(metadata.num_outputs, Some(3));
    }

    #[test]
    fn test_metadata_serialization() {
        let mut metadata = PsbtMetadata::with_description("Test PSBT");
        metadata.set_creator("rust-impl");
        metadata.update_timestamps();

        let json = serde_json::to_string_pretty(&metadata).unwrap();
        let deserialized: PsbtMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(metadata.description, deserialized.description);
        assert_eq!(metadata.creator, deserialized.creator);
    }

    #[test]
    fn test_psbt_file() {
        let psbt_base64 = "cHNidP8="; // "psbt" in base64
        let mut metadata = PsbtMetadata::new();
        metadata.set_creator("test");

        let file = PsbtFile::with_metadata(psbt_base64.to_string(), metadata);

        let json = serde_json::to_string(&file).unwrap();
        let deserialized: PsbtFile = serde_json::from_str(&json).unwrap();

        assert_eq!(file.psbt, deserialized.psbt);
    }
}
