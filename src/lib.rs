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
        
        // Title and Report Information
        report.push_str("# Solana Smart Contract Security Audit Report\n\n");
        
        // Add date
        let now = chrono::Local::now();
        report.push_str(&format!("**Date**: {}\n\n", now.format("%Y-%m-%d")));
        
        // Add version
        report.push_str("**Version**: 1.0\n\n");

        // Executive Summary
        report.push_str("## Executive Summary\n\n");
        report.push_str("This report presents the findings of a security audit performed on the provided Solana/Anchor smart contract code. ");
        report.push_str("The audit was conducted using automated static analysis tools focusing on common security vulnerabilities and best practices in Solana development.\n\n");
        
        // Risk Classification
        report.push_str("### Risk Classification\n\n");
        report.push_str("| Severity | Description |\n");
        report.push_str("|----------|-------------|\n");
        report.push_str("| **Critical** | Vulnerabilities that can lead to loss of funds, unauthorized access to funds, or complete compromise of the contract or user accounts |\n");
        report.push_str("| **High** | Vulnerabilities that can lead to degraded security or loss of funds under specific circumstances |\n");
        report.push_str("| **Medium** | Vulnerabilities that can impact the contract's intended functionality but do not directly lead to loss of funds |\n");
        report.push_str("| **Low** | Issues that do not pose a significant risk but should be addressed as best practice |\n");
        report.push_str("| **Informational** | Suggestions to improve code quality, gas efficiency, or enhance documentation |\n\n");
        
        // Scope
        report.push_str("### Scope\n\n");
        report.push_str("The audit covers the Rust/Anchor program code in the provided project directories.\n\n");
        
        // Audit Statistics
        report.push_str("### Audit Statistics\n\n");
        
        let critical_count = self.vulnerabilities.iter().filter(|v| matches!(v.severity, Severity::Critical)).count();
        let high_count = self.vulnerabilities.iter().filter(|v| matches!(v.severity, Severity::High)).count();
        let medium_count = self.vulnerabilities.iter().filter(|v| matches!(v.severity, Severity::Medium)).count();
        let low_count = self.vulnerabilities.iter().filter(|v| matches!(v.severity, Severity::Low)).count();
        
        report.push_str("| Risk Level | Count |\n");
        report.push_str("|------------|-------|\n");
        report.push_str(&format!("| Critical | {} |\n", critical_count));
        report.push_str(&format!("| High | {} |\n", high_count));
        report.push_str(&format!("| Medium | {} |\n", medium_count));
        report.push_str(&format!("| Low | {} |\n", low_count));
        report.push_str(&format!("| Warnings | {} |\n", self.warnings.len()));
        report.push_str(&format!("| Informational | {} |\n\n", self.info.len()));
        
        // Table of Contents
        report.push_str("## Table of Contents\n\n");
        
        report.push_str("1. [Executive Summary](#executive-summary)\n");
        report.push_str("2. [Findings Overview](#findings-overview)\n");
        
        if !self.vulnerabilities.is_empty() {
            report.push_str("3. [Detailed Findings](#detailed-findings)\n");
            
            // Create sub-sections in TOC for each severity
            let mut section_index = 1;
            
            if critical_count > 0 {
                report.push_str(&format!("   3.{} [Critical Severity Issues](#critical-severity-issues)\n", section_index));
                section_index += 1;
                
                // List each critical issue in TOC
                let critical_vulns: Vec<&Vulnerability> = self.vulnerabilities.iter()
                    .filter(|v| matches!(v.severity, Severity::Critical))
                    .collect();
                
                for (i, vuln) in critical_vulns.iter().enumerate() {
                    let anchor = vuln.description.to_lowercase().replace(' ', "-").replace(['(', ')', ':', '.', ',', '\'', '"'], "");
                    report.push_str(&format!("      - [{}](#{})\n", vuln.description, anchor));
                }
            }
            
            if high_count > 0 {
                report.push_str(&format!("   3.{} [High Severity Issues](#high-severity-issues)\n", section_index));
                section_index += 1;
                
                // List each high issue in TOC
                let high_vulns: Vec<&Vulnerability> = self.vulnerabilities.iter()
                    .filter(|v| matches!(v.severity, Severity::High))
                    .collect();
                
                for (i, vuln) in high_vulns.iter().enumerate() {
                    let anchor = vuln.description.to_lowercase().replace(' ', "-").replace(['(', ')', ':', '.', ',', '\'', '"'], "");
                    report.push_str(&format!("      - [{}](#{})\n", vuln.description, anchor));
                }
            }
            
            if medium_count > 0 {
                report.push_str(&format!("   3.{} [Medium Severity Issues](#medium-severity-issues)\n", section_index));
                section_index += 1;
                
                // List each medium issue in TOC
                let medium_vulns: Vec<&Vulnerability> = self.vulnerabilities.iter()
                    .filter(|v| matches!(v.severity, Severity::Medium))
                    .collect();
                
                for (i, vuln) in medium_vulns.iter().enumerate() {
                    let anchor = vuln.description.to_lowercase().replace(' ', "-").replace(['(', ')', ':', '.', ',', '\'', '"'], "");
                    report.push_str(&format!("      - [{}](#{})\n", vuln.description, anchor));
                }
            }
            
            if low_count > 0 {
                report.push_str(&format!("   3.{} [Low Severity Issues](#low-severity-issues)\n", section_index));
                section_index += 1;
                
                // List each low issue in TOC
                let low_vulns: Vec<&Vulnerability> = self.vulnerabilities.iter()
                    .filter(|v| matches!(v.severity, Severity::Low))
                    .collect();
                
                for (i, vuln) in low_vulns.iter().enumerate() {
                    let anchor = vuln.description.to_lowercase().replace(' ', "-").replace(['(', ')', ':', '.', ',', '\'', '"'], "");
                    report.push_str(&format!("      - [{}](#{})\n", vuln.description, anchor));
                }
            }
        }
        
        if !self.warnings.is_empty() {
            report.push_str("4. [Warnings](#warnings)\n");
        }
        
        if !self.info.is_empty() {
            report.push_str("5. [Informational Items](#informational-items)\n");
        }
        
        report.push_str("6. [Conclusion](#conclusion)\n\n");
        
        // Findings Overview
        report.push_str("## Findings Overview\n\n");
        report.push_str("The following chart summarizes the issues found during the audit:\n\n");
        
        if !self.vulnerabilities.is_empty() || !self.warnings.is_empty() {
            report.push_str("| ID | Title | Severity | Status |\n");
            report.push_str("|----|--------------------|----------|--------|\n");
            
            let mut index = 1;
            
            // Critical vulnerabilities first
            for vuln in self.vulnerabilities.iter().filter(|v| matches!(v.severity, Severity::Critical)) {
                let issue_id = format!("CRIT-{:03}", index);
                report.push_str(&format!("| {} | {} | Critical | Open |\n", issue_id, vuln.description));
                index += 1;
            }
            
            // Reset index for High
            index = 1;
            
            // High vulnerabilities next
            for vuln in self.vulnerabilities.iter().filter(|v| matches!(v.severity, Severity::High)) {
                let issue_id = format!("HIGH-{:03}", index);
                report.push_str(&format!("| {} | {} | High | Open |\n", issue_id, vuln.description));
                index += 1;
            }
            
            // Reset index for Medium
            index = 1;
            
            // Medium vulnerabilities next
            for vuln in self.vulnerabilities.iter().filter(|v| matches!(v.severity, Severity::Medium)) {
                let issue_id = format!("MED-{:03}", index);
                report.push_str(&format!("| {} | {} | Medium | Open |\n", issue_id, vuln.description));
                index += 1;
            }
            
            // Reset index for Low
            index = 1;
            
            // Low vulnerabilities next
            for vuln in self.vulnerabilities.iter().filter(|v| matches!(v.severity, Severity::Low)) {
                let issue_id = format!("LOW-{:03}", index);
                report.push_str(&format!("| {} | {} | Low | Open |\n", issue_id, vuln.description));
                index += 1;
            }
            
            // Reset index for Warnings
            index = 1;
            
            // Warnings last
            for warning in &self.warnings {
                let issue_id = format!("WARN-{:03}", index);
                report.push_str(&format!("| {} | {} | Warning | Open |\n", issue_id, warning.description));
                index += 1;
            }
        } else {
            report.push_str("No issues were found during the audit.\n\n");
        }
        
        // Detailed Findings
        if !self.vulnerabilities.is_empty() {
            report.push_str("\n## Detailed Findings\n\n");
            
            // Critical first, then High, Medium, Low
            for severity in [Severity::Critical, Severity::High, Severity::Medium, Severity::Low] {
                let severity_vulns: Vec<&Vulnerability> = self.vulnerabilities.iter()
                    .filter(|v| v.severity == severity)
                    .collect();
                
                if !severity_vulns.is_empty() {
                    match severity {
                        Severity::Critical => report.push_str("### Critical Severity Issues\n\n"),
                        Severity::High => report.push_str("### High Severity Issues\n\n"),
                        Severity::Medium => report.push_str("### Medium Severity Issues\n\n"),
                        Severity::Low => report.push_str("### Low Severity Issues\n\n"),
                    }
                    
                    let mut index = 1;
                    
                    for vuln in severity_vulns {
                        // Create issue ID based on severity
                        let issue_id = match severity {
                            Severity::Critical => format!("CRIT-{:03}", index),
                            Severity::High => format!("HIGH-{:03}", index),
                            Severity::Medium => format!("MED-{:03}", index),
                            Severity::Low => format!("LOW-{:03}", index),
                        };
                        
                        // Create anchor ID from description
                        let anchor = vuln.description.to_lowercase().replace(' ', "-").replace(['(', ')', ':', '.', ',', '\'', '"'], "");
                        
                        // Add heading with anchor for linking
                        report.push_str(&format!("#### <a name=\"{}\"></a>{}: {}\n\n", anchor, issue_id, vuln.description));
                        
                        // Try to find a detailed description in our database
                        let key_words: Vec<&str> = vuln.description.split_whitespace()
                            .filter(|w| w.len() > 4)
                            .collect();
                        
                        // Try to find matching vulnerability description
                        let mut found_details = false;
                        for key in key_words.iter() {
                            if let Some(desc) = utils::find_vulnerability_description(key.to_lowercase().as_str(), &self.vulnerability_descriptions) {
                                if let Some(detailed_desc) = desc["description"].as_str() {
                                    report.push_str("**Description**:\n\n");
                                    report.push_str(&format!("{}\n\n", detailed_desc));
                                }
                                
                                if let Some(example) = desc["example_scenario"].as_str() {
                                    report.push_str("**Example Scenario**:\n\n");
                                    report.push_str(&format!("{}\n\n", example));
                                }
                                
                                found_details = true;
                                break;
                            }
                        }
                        
                        // If no detailed description was found, use the basic description
                        if !found_details {
                            report.push_str("**Description**:\n\n");
                            report.push_str(&format!("{}\n\n", vuln.description));
                        }
                        
                        // Add technical details section
                        report.push_str("**Technical Details**:\n\n");
                        report.push_str("**File**: `");
                        report.push_str(&vuln.location.file);
                        report.push_str("`\n\n");
                        report.push_str(&format!("**Line Number**: {}\n\n", vuln.location.line));
                        
                        // Add impact section
                        report.push_str("**Impact**:\n\n");
                        match severity {
                            Severity::Critical => report.push_str("This vulnerability poses an immediate risk of fund loss or complete security compromise.\n\n"),
                            Severity::High => report.push_str("This vulnerability can lead to significant security issues or potential fund loss under certain conditions.\n\n"),
                            Severity::Medium => report.push_str("This vulnerability affects the contract's functionality but doesn't directly lead to fund loss.\n\n"),
                            Severity::Low => report.push_str("This vulnerability represents a minor risk but should be addressed as a best practice.\n\n"),
                        }
                        
                        // Add recommendation section
                        report.push_str("**Recommendation**:\n\n");
                        report.push_str(&format!("{}\n\n", vuln.suggestion));
                        
                        // Add secure code example from vulnerability database if available
                        for key in key_words.iter() {
                            if let Some(desc) = utils::find_vulnerability_description(key.to_lowercase().as_str(), &self.vulnerability_descriptions) {
                                if let Some(secure_example) = desc["secure_example"].as_str() {
                                    report.push_str("**Secure Implementation Example**:\n\n");
                                    report.push_str("```rust\n");
                                    report.push_str(secure_example);
                                    report.push_str("\n```\n\n");
                                    break;
                                }
                            }
                        }
                        
                        report.push_str("---\n\n");
                        index += 1;
                    }
                }
            }
        }
        
        // Warnings section
        if !self.warnings.is_empty() {
            report.push_str("## Warnings\n\n");
            report.push_str("The following warnings represent code quality issues or potential vulnerabilities that might require attention:\n\n");
            
            let mut index = 1;
            
            for warning in &self.warnings {
                let issue_id = format!("WARN-{:03}", index);
                let anchor = warning.description.to_lowercase().replace(' ', "-").replace(['(', ')', ':', '.', ',', '\'', '"'], "");
                
                report.push_str(&format!("### <a name=\"{}\"></a>{}: {}\n\n", anchor, issue_id, warning.description));
                report.push_str("**File**: `");
                report.push_str(&warning.location.file);
                report.push_str("`\n\n");
                report.push_str(&format!("**Line Number**: {}\n\n", warning.location.line));
                report.push_str("**Recommendation**:\n\n");
                report.push_str(&format!("{}\n\n", warning.suggestion));
                report.push_str("---\n\n");
                
                index += 1;
            }
        }
        
        // Informational section
        if !self.info.is_empty() {
            report.push_str("## Informational Items\n\n");
            report.push_str("The following items are informational and do not represent security issues, but may be useful for improving code quality or understanding:\n\n");
            
            for (i, info) in self.info.iter().enumerate() {
                report.push_str(&format!("{}. **{}**  \n", i + 1, info.description));
                report.push_str(&format!("   File: `{}`, Line: {}\n\n", info.location.file, info.location.line));
            }
        }
        
        // Conclusion section
        report.push_str("## Conclusion\n\n");
        
        if !self.vulnerabilities.is_empty() {
            if critical_count > 0 {
                report.push_str("**Critical security issues were found that require immediate attention.**\n\n");
            } else if high_count > 0 {
                report.push_str("**High severity issues were found that should be addressed before deployment.**\n\n");
            } else {
                report.push_str("**Some issues were found that should be addressed to improve the security of the contract.**\n\n");
            }
        } else if !self.warnings.is_empty() {
            report.push_str("**No vulnerabilities were found, but some warnings should be addressed to improve code quality.**\n\n");
        } else {
            report.push_str("**No issues were found. The contract appears to be secure based on this static analysis.**\n\n");
        }
        
        report.push_str("This audit was performed using automated static analysis tools and does not guarantee the absence of all possible vulnerabilities. A comprehensive security audit should also include manual code review and dynamic testing.\n\n");
        
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
