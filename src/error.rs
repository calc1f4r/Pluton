// Copyright (c) 2025 @calc1f4r
// SPDX-License-Identifier: MIT

//! # Error handling for the Solana Static Analyzer
//!
//! This module defines the error types used throughout the analyzer.
//! It provides a standard way to handle and propagate errors that may
//! occur during the static analysis process.

use thiserror::Error;

/// Errors that can occur during static analysis of Solana programs
#[derive(Error, Debug)]
pub enum AnalyzerError {
    /// Error that occurs when reading files from the filesystem
    #[error("Failed to read file: {0}")]
    FileReadError(#[from] std::io::Error),

    /// Error that occurs when parsing Rust code fails
    #[error("Failed to parse Rust code: {0}")]
    ParseError(#[from] syn::Error),

    /// Error that occurs when parsing JSON fails
    #[error("Failed to parse JSON: {0}")]
    JsonError(#[from] serde_json::Error),

    /// Error that occurs when the program structure doesn't conform to Anchor's expectations
    #[error("Invalid Anchor program structure: {0}")]
    InvalidAnchorStructure(String),

    /// General analysis error that doesn't fit into other categories
    #[error("Analysis error: {0}")]
    AnalysisError(String),

    /// Other errors that don't fit into the above categories
    #[error("Other error: {0}")]
    Other(String),
}

/// Specialized Result type for the analyzer to simplify error handling
pub type Result<T> = std::result::Result<T, AnalyzerError>;

impl From<anyhow::Error> for AnalyzerError {
    fn from(error: anyhow::Error) -> Self {
        AnalyzerError::Other(error.to_string())
    }
}
