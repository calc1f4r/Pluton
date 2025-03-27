// Copyright (c) 2025 @calc1f4r
// SPDX-License-Identifier: MIT

//! # Pluton
//! 
//! A static analysis tool for Solana and Anchor Rust programs that identifies
//! common security vulnerabilities and best practices.
//!
//! This library provides tools to analyze Solana/Anchor programs for security issues such as:
//! - Missing reinitialization checks in initialization functions
//! - Improper validation of remaining accounts
//! - Potential arithmetic overflow/underflow vulnerabilities
//! - Unchecked associated token account initialization issues


use std::fmt;
use std::fs;
use std::path::Path;
use std::collections::HashMap;
use serde_json::Value;

pub mod error;
pub mod visitor;
pub mod utils;

use visitor::AnchorVisitor;
use error::Result;

// MARK: - Analysis Result Types

/// Represents the result of the static analysis
#[derive(Debug, serde::Serialize)]
pub struct AnalysisResult {
    /// List of serious security vulnerabilities found in the analysis
    pub vulnerabilities: Vec<Vulnerability>,
    
    /// List of less severe warnings that should be addressed
    pub warnings: Vec<Warning>,
    
    /// List of informational items that might be useful to the developer
    pub info: Vec<Info>,
    
    /// Mapping of vulnerability keys to their detailed descriptions
    #[serde(skip)]
    pub vulnerability_descriptions: HashMap<String, Value>,
}

impl Default for AnalysisResult {
    fn default() -> Self {
        Self {
            vulnerabilities: Vec::new(),
            warnings: Vec::new(),
            info: Vec::new(),
            vulnerability_descriptions: HashMap::new(),
        }
    }
}

impl AnalysisResult {
    /// Generate a markdown report from the analysis results
    pub fn to_markdown(&self) -> String {
        let mut report = String::new();
        
        // Summary section
        report.push_str("# Pluton Analysis Report\n\n");
        report.push_str("## Summary\n\n");
        report.push_str(&format!("- **Critical Vulnerabilities**: {}\n", 
            self.vulnerabilities.iter().filter(|v| matches!(v.severity, Severity::Critical)).count()));
        report.push_str(&format!("- **High Severity Vulnerabilities**: {}\n", 
            self.vulnerabilities.iter().filter(|v| matches!(v.severity, Severity::High)).count()));
        report.push_str(&format!("- **Warnings**: {}\n", self.warnings.len()));
        report.push_str(&format!("- **Informational Items**: {}\n\n", self.info.len()));
        
        // Vulnerabilities section
        if !self.vulnerabilities.is_empty() {
            report.push_str("## Vulnerabilities\n\n");
            
            // Critical first, then High
            for severity in [Severity::Critical, Severity::High, Severity::Medium, Severity::Low] {
                let severity_vulns: Vec<&Vulnerability> = self.vulnerabilities.iter()
                    .filter(|v| v.severity == severity)
                    .collect();
                
                if !severity_vulns.is_empty() {
                    report.push_str(&format!("### {} Severity\n\n", severity));
                    
                    for vuln in severity_vulns {
                        report.push_str(&format!("#### {}\n\n", vuln.description));
                        
                        // Try to find a detailed description in our database
                        let key_words: Vec<&str> = vuln.description.split_whitespace()
                            .filter(|w| w.len() > 4)
                            .collect();
                        
                        // Try to find matching vulnerability description
                        for key in key_words.iter() {
                            if let Some(desc) = utils::find_vulnerability_description(key.to_lowercase().as_str(), &self.vulnerability_descriptions) {
                                if let Some(detailed_desc) = desc["description"].as_str() {
                                    report.push_str(&format!("**Detailed Description**:\n{}\n\n", detailed_desc));
                                }
                                
                                if let Some(example) = desc["example_scenario"].as_str() {
                                    report.push_str(&format!("**Example Scenario**:\n{}\n\n", example));
                                }
                                
                                break;
                            }
                        }
                        
                        report.push_str(&format!("**Location**: {}:{}:{}\n\n", vuln.location.file, vuln.location.line, vuln.location.column));
                        report.push_str(&format!("**Suggestion**: {}\n\n", vuln.suggestion));
                        
                        // Add secure code example from vulnerability database if available
                        for key in key_words.iter() {
                            if let Some(desc) = utils::find_vulnerability_description(key.to_lowercase().as_str(), &self.vulnerability_descriptions) {
                                if let Some(secure_example) = desc["secure_example"].as_str() {
                                    report.push_str("**Secure Implementation Example**:\n");
                                    report.push_str("```rust\n");
                                    report.push_str(secure_example);
                                    report.push_str("\n```\n\n");
                                    break;
                                }
                            }
                        }
                        
                        report.push_str("---\n\n");
                    }
                }
            }
        }
        
        // Warnings section
        if !self.warnings.is_empty() {
            report.push_str("## Warnings\n\n");
            
            for warning in &self.warnings {
                report.push_str(&format!("### {}\n\n", warning.description));
                report.push_str(&format!("**Location**: {}:{}:{}\n\n", warning.location.file, warning.location.line, warning.location.column));
                report.push_str(&format!("**Suggestion**: {}\n\n", warning.suggestion));
                report.push_str("---\n\n");
            }
        }
        
        // Informational section
        if !self.info.is_empty() {
            report.push_str("## Informational Items\n\n");
            
            for info in &self.info {
                report.push_str(&format!("- **{}** ({}:{}:{})\n", 
                    info.description, info.location.file, info.location.line, info.location.column));
            }
        }
        
        report
    }
    
    /// Generate a JSON report from the analysis results
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

/// Represents a security vulnerability found in the code
#[derive(Debug, serde::Serialize)]
pub struct Vulnerability {
    /// Severity level of the vulnerability
    pub severity: Severity,
    
    /// Description of the vulnerability
    pub description: String,
    
    /// Location where the vulnerability was found
    pub location: Location,
    
    /// Suggested fix for the vulnerability
    pub suggestion: String,
}

/// Represents a warning about a potential issue
#[derive(Debug, serde::Serialize)]
pub struct Warning {
    /// Description of the warning
    pub description: String,
    
    /// Location where the warning was identified
    pub location: Location,
    
    /// Suggested improvement
    pub suggestion: String,
}

/// Represents an informational item that might be useful to the developer
#[derive(Debug, serde::Serialize)]
pub struct Info {
    /// Description of the informational item
    pub description: String,
    
    /// Location where the information applies
    pub location: Location,
}

/// Severity levels for vulnerabilities
#[derive(Debug, serde::Serialize, PartialEq)]
pub enum Severity {
    /// Critical vulnerabilities that require immediate attention
    Critical,
    
    /// High severity issues that should be addressed promptly
    High,
    
    /// Medium severity issues that should be fixed when possible
    Medium,
    
    /// Low severity issues that are worth considering
    Low,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
        }
    }
}

/// Represents a location in the source code
#[derive(Debug, serde::Serialize)]
pub struct Location {
    /// File path where the issue was found
    pub file: String,
    
    /// Line number in the file
    pub line: usize,
    
    /// Column number in the file
    pub column: usize,
}

// MARK: - Analyzer Implementation

/// Main analyzer struct for analyzing Solana/Anchor programs
pub struct SolanaAnalyzer {
    /// Path to the project to analyze
    project_path: String,
    
    /// Whether overflow checks are enabled in Cargo.toml
    has_overflow_checks: bool,
}

impl SolanaAnalyzer {
    /// Create a new analyzer instance for a Solana/Anchor project
    ///
    /// # Arguments
    ///
    /// * `project_path` - Path to the project to analyze
    ///
    /// # Returns
    ///
    /// A new SolanaAnalyzer instance configured for the specified project
    pub fn new(project_path: String) -> Self {
        let has_overflow_checks = Self::check_for_overflow_checks(&project_path);
        
        Self { 
            project_path,
            has_overflow_checks,
        }
    }

    /// Check if the project has overflow-checks=true in Cargo.toml
    ///
    /// # Arguments
    ///
    /// * `project_path` - Path to the project to check
    ///
    /// # Returns
    ///
    /// Whether overflow checks are enabled in the project's Cargo.toml
    fn check_for_overflow_checks(project_path: &str) -> bool {
        let cargo_toml_path = Path::new(project_path).join("Cargo.toml");
        
        if let Ok(content) = fs::read_to_string(cargo_toml_path) {
            // Look for overflow-checks = true in the file
            return content.contains("overflow-checks = true") || 
                   content.contains("overflow-checks=true");
        }
        
        // Also check parent directory in case we're pointing to a subdirectory
        let parent_cargo_toml = Path::new(project_path)
            .parent()
            .map(|p| p.join("Cargo.toml"));
        
        if let Some(parent_path) = parent_cargo_toml {
            if let Ok(content) = fs::read_to_string(parent_path) {
                return content.contains("overflow-checks = true") || 
                       content.contains("overflow-checks=true");
            }
        }
        
        false
    }

    /// Analyze the entire Solana/Anchor program
    ///
    /// Walks through all Rust files in the project and analyzes them for
    /// security vulnerabilities and best practices.
    ///
    /// # Returns
    ///
    /// Analysis result containing vulnerabilities, warnings, and info items
    pub fn analyze(&self) -> Result<AnalysisResult> {
        let mut result = AnalysisResult::default();

        // Load vulnerability descriptions if available
        result.vulnerability_descriptions = utils::load_vulnerability_descriptions()?;

        // Add info about overflow checks if enabled
        if self.has_overflow_checks {
            result.info.push(Info {
                description: "Project has overflow-checks = true in Cargo.toml, which provides runtime protection against integer overflow/underflow".to_string(),
                location: Location {
                    file: "Cargo.toml".to_string(),
                    line: 0,
                    column: 0,
                },
            });
        }

        // Walk through all Rust files in the project
        for entry in walkdir::WalkDir::new(&self.project_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |ext| ext == "rs"))
        {
            self.analyze_file(entry.path(), &mut result)?;
        }

        Ok(result)
    }

    /// Generate a report from the analysis results and write it to a file
    ///
    /// # Arguments
    ///
    /// * `result` - Analysis result to generate report from
    /// * `format` - Format of the report (markdown or json)
    /// * `output_file` - Path to write the report to
    ///
    /// # Returns
    ///
    /// Result indicating success or failure
    pub fn generate_report(&self, result: &AnalysisResult, format: &str, output_file: &str) -> Result<()> {
        let report = match format.to_lowercase().as_str() {
            "json" => result.to_json()?,
            _ => result.to_markdown(),
        };
        
        fs::write(output_file, report)?;
        
        Ok(())
    }

    /// Analyze a single Rust file for vulnerabilities
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file to analyze
    /// * `result` - Analysis result to update with findings
    ///
    /// # Returns
    ///
    /// Result indicating success or failure
    fn analyze_file(&self, path: &Path, result: &mut AnalysisResult) -> Result<()> {
        let content = std::fs::read_to_string(path)?;
        
        // Try to parse the file, but don't fail if it can't be parsed
        match syn::parse_str::<syn::File>(&content) {
            Ok(ast) => {
                // Create a visitor and analyze the AST
                let mut visitor = AnchorVisitor::new(
                    result, 
                    path.to_string_lossy().to_string(),
                    self.has_overflow_checks,
                );
                syn::visit::visit_file(&mut visitor, &ast);
            },
            Err(err) => {
                // Add a warning about the parse failure
                result.warnings.push(Warning {
                    description: format!("Failed to parse file: {}", err),
                    location: Location {
                        file: path.to_string_lossy().to_string(),
                        line: 0,
                        column: 0,
                    },
                    suggestion: "Check for syntax errors or unsupported Rust syntax".to_string(),
                });
            }
        }
        
        Ok(())
    }
}

// MARK: - Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_analysis() {
        let analyzer = SolanaAnalyzer::new("test-project".to_string());
        let result = analyzer.analyze().unwrap();
        
        // If overflow checks are enabled, we might not find vulnerabilities
        if !analyzer.has_overflow_checks {
            assert!(!result.vulnerabilities.is_empty()); // Should find overflow vulnerabilities
        }
        assert!(!result.warnings.is_empty()); // Should find warnings about large numbers
    }
}
