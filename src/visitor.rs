// Copyright (c) 2025 @calc1f4r
// SPDX-License-Identifier: MIT

//! # Anchor Program Visitor Module
//! 
//! This module implements a Rust syntax tree visitor that analyzes Solana/Anchor programs
//! for common security vulnerabilities and best practices.
//! 
//! The `AnchorVisitor` works by walking the program's abstract syntax tree (AST) and
//! identifying patterns that might indicate security vulnerabilities, such as:
//! 
//! - Missing reinitialization checks in initialization functions
//! - Unchecked remaining accounts usage
//! - Potential arithmetic overflow/underflow
//! - Missing account validation
//! - Associated Token Account initialization issues
//! - And more...
//!
//! ## Example Usage
//! 
//! ```rust,ignore
//! let mut result = AnalysisResult::default();
//! let visitor = AnchorVisitor::new(&mut result, file_path, has_overflow_checks);
//! visitor.visit_file(&file_ast);
//! // Process analysis results...
//! ```

use crate::{AnalysisResult, Info, Location, Severity, Vulnerability, Warning};
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::{
    BinOp, Expr, ExprBinary, ExprLit, Field, Item, ItemEnum, ItemFn, ItemStruct, Attribute, FnArg, Pat
};
use syn::visit::Visit;
use std::collections::HashMap;
use serde_json::Value;

/// Represents a location in the source code
#[derive(Default, Clone, Debug)]
struct CodeLocation {
    line: usize,
    column: usize,
    file: String,
}

/// Visitor that traverses a Solana/Anchor program's AST to detect vulnerabilities
///
/// The visitor analyzes different Rust constructs (functions, structs, expressions, etc.)
/// and reports security issues to the provided `AnalysisResult`.
pub struct AnchorVisitor<'ast> {
    /// The analysis result where findings will be stored
    result: &'ast mut AnalysisResult,
    
    /// Path to the current file being analyzed
    current_file: String,
    
    /// Current line position in source code
    current_line: usize,
    
    /// Current column position in source code
    current_column: usize,
    
    /// Whether overflow checks are enabled in the project's Cargo.toml
    has_overflow_checks: bool,
    
    /// Tracks if the current function accesses remaining_accounts
    has_remaining_accounts_access: bool,
    
    /// Tracks if we've seen validation code for remaining_accounts
    has_remaining_accounts_validation: bool,
    
    /// Tracks if we're currently analyzing an initialization function
    current_function_is_init: bool,

    /// Content of the current file being analyzed
    file_content: String,

    /// Track if a CPI was performed in the current function
    cpi_performed: bool,

    /// Track expressions that access account data
    accessed_accounts: Vec<String>,

    // Add new fields to track bump seed usage
    non_canonical_bump_detected: bool,
    current_function_has_bump_param: bool,

    /// Current location in the code being analyzed
    current_location: CodeLocation,
    
    /// List of warnings collected during analysis
    warnings: Vec<Warning>,
    
    /// List of vulnerabilities collected during analysis
    vulnerabilities: Vec<Vulnerability>,
    
    /// List of informational items collected during analysis
    info: Vec<Info>,
    
    /// Flag indicating if initialization check was found in the current function
    has_initialization_check: bool,
    
    /// Descriptions of known vulnerabilities
    vulnerability_descriptions: HashMap<String, Value>,
}

impl<'ast> AnchorVisitor<'ast> {
    /// Creates a new AnchorVisitor
    ///
    /// # Arguments
    ///
    /// * `result` - The analysis result where findings will be stored
    /// * `current_file` - Path to the file being analyzed
    /// * `has_overflow_checks` - Whether overflow checks are enabled in Cargo.toml
    ///
    /// # Returns
    ///
    /// A new AnchorVisitor instance
    pub fn new(
        result: &'ast mut AnalysisResult,
        current_file: String,
        has_overflow_checks: bool,
    ) -> Self {
        // Read the file content
        let file_content = match std::fs::read_to_string(&current_file) {
            Ok(content) => content,
            Err(_) => String::new(),
        };
        
        let desc = super::utils::load_vulnerability_descriptions().unwrap_or_default();
        
        // Create visitor with file content
        Self {
            result,
            current_file,
            current_line: 0,
            current_column: 0,
            has_overflow_checks,
            has_remaining_accounts_access: false,
            has_remaining_accounts_validation: false,
            current_function_is_init: false,
            file_content,
            cpi_performed: false,
            accessed_accounts: Vec::new(),
            non_canonical_bump_detected: false,
            current_function_has_bump_param: false,
            vulnerability_descriptions: desc,
            current_location: CodeLocation::default(),
            warnings: Vec::new(),
            vulnerabilities: Vec::new(),
            info: Vec::new(),
            has_initialization_check: false,
        }
    }

    // MARK: - Result Collection Methods

    /// Adds a vulnerability finding to the analysis result
    ///
    /// # Arguments
    ///
    /// * `severity` - The severity level of the vulnerability
    /// * `description` - Description of the vulnerability
    /// * `suggestion` - Suggested fix for the vulnerability
    fn add_vulnerability(&mut self, severity: Severity, description: String, suggestion: String) {
        self.result.vulnerabilities.push(Vulnerability {
            severity,
            description,
            location: Location {
                file: self.current_file.clone(),
                line: self.current_line,
                column: self.current_column,
            },
            suggestion,
        });
    }

    /// Adds a warning finding to the analysis result
    ///
    /// # Arguments
    ///
    /// * `description` - Description of the warning
    /// * `suggestion` - Suggested improvement
    fn add_warning(&mut self, description: String, suggestion: String) {
        self.result.warnings.push(Warning {
            description,
            location: Location {
                file: self.current_file.clone(),
                line: self.current_line,
                column: self.current_column,
            },
            suggestion,
        });
    }

    /// Adds an informational finding to the analysis result
    ///
    /// # Arguments
    ///
    /// * `description` - Description of the informational item
    fn add_info(&mut self, description: String) {
        self.result.info.push(Info {
            description,
            location: Location {
                file: self.current_file.clone(),
                line: self.current_line,
                column: self.current_column,
            },
        });
    }

    /// Updates the current source location based on a syntax node's span
    ///
    /// # Arguments
    ///
    /// * `span` - The syntax node span from which to extract location information
    fn update_location_from_span(&mut self, span: proc_macro2::Span) {
        // Get the source text from the span
        if let Some(source_text) = span.source_text() {
            // Find all occurrences of this text in the file
            let mut line_number = 1;
            let mut last_pos = 0;
            
            while let Some(pos) = self.file_content[last_pos..].find(&source_text) {
                let actual_pos = last_pos + pos;
                let prefix = &self.file_content[..actual_pos];
                line_number = prefix.chars().filter(|&c| c == '\n').count() + 1;
                last_pos = actual_pos + 1;
            }
            
            // Update line number if we found a match
            if last_pos > 0 {
                self.current_line = line_number;
            }
        }
    }

    // MARK: - Function Analysis Methods

    /// Analyzes a function for potential vulnerabilities
    ///
    /// Checks for:
    /// - Initialization functions without reinitialization checks
    /// - Improper validation in functions with "validate" in the name
    /// - Improper error handling in functions with "error" in the name
    /// - Improper access control in functions with "access" in the name
    /// - Unsafe handling of remaining_accounts
    ///
    /// # Arguments
    ///
    /// * `item_fn` - Function to analyze
    fn check_function(&mut self, item_fn: &'ast ItemFn) {
        // Update location from function span
        self.update_location_from_span(item_fn.span());
        
        // Reset state for this function
        self.has_remaining_accounts_access = false;
        self.has_remaining_accounts_validation = false;
        
        // Get function name for heuristic checks
        let fn_name = item_fn.sig.ident.to_string();
        
        // Check if this is an initialization function based on naming convention
        self.current_function_is_init = fn_name.contains("initialize") 
            || fn_name.contains("init") 
            || fn_name.contains("create");
        
        // Various function name-based heuristic checks
        self.check_function_naming_conventions(&fn_name);

        // Check function parameters for bump arguments
        self.current_function_has_bump_param = false;
        for param in &item_fn.sig.inputs {
            if let FnArg::Typed(pat_type) = param {
                if let Pat::Ident(pat_ident) = &*pat_type.pat {
                    let param_name = pat_ident.ident.to_string();
                    if param_name.contains("bump") {
                        self.current_function_has_bump_param = true;
                        break;
                    }
                }
            }
        }

        // Visit the function body to analyze its contents
        syn::visit::visit_block(self, &item_fn.block);
        
        // After visiting the function, check if we found remaining_accounts access without validation
        if self.has_remaining_accounts_access && !self.has_remaining_accounts_validation {
            self.add_vulnerability(
                Severity::High,
                "Accessing remaining_accounts without proper validation".to_string(),
                "Always validate remaining accounts before using them. Check account ownership, type, and other constraints.".to_string(),
            );
        }
        
        // Check for reinitialization vulnerability in initialization functions
        if self.current_function_is_init {
            self.check_for_init_checks(item_fn);
        }
        
        // Reset current function state
        self.current_function_is_init = false;

        // Reset CPI tracking at the beginning of a function
        self.cpi_performed = false;
        self.accessed_accounts.clear();

        // Check if account data was accessed after CPI without reload
        if self.cpi_performed && !self.accessed_accounts.is_empty() {
            self.add_vulnerability(
                Severity::Critical,
                "Account data accessed after CPI without reload()".to_string(),
                "After performing a CPI, call account.reload() before accessing account data to prevent tampering. Other programs can modify account data during a CPI.".to_string(),
            );
        }
        
        // Reset CPI tracking for the next function
        self.cpi_performed = false;
        self.accessed_accounts.clear();

        // Reset bump detection state at the end of the function
        if self.non_canonical_bump_detected && self.current_function_has_bump_param {
            self.add_vulnerability(
                Severity::Critical,
                "Possible bump seed canonicalization vulnerability detected".to_string(),
                "Always use Pubkey::find_program_address() instead of create_program_address() to ensure canonical bump is used, or validate any user-provided bump against the canonical bump.".to_string(),
            );
        }
        
        self.non_canonical_bump_detected = false;
        self.current_function_has_bump_param = false;
    }
    
    /// Checks for issues based on function naming conventions
    ///
    /// # Arguments
    ///
    /// * `fn_name` - Name of the function to check
    fn check_function_naming_conventions(&mut self, fn_name: &str) {
        // Check for unsafe account validation
        if fn_name.contains("validate") {
            self.add_warning(
                "Function contains 'validate' in name - ensure proper validation".to_string(),
                "Consider using Anchor's built-in validation attributes".to_string(),
            );
        }

        // Check for proper error handling
        if fn_name.contains("error") {
            self.add_warning(
                "Function contains 'error' in name - ensure proper error handling".to_string(),
                "Use Anchor's error handling macros and proper error types".to_string(),
            );
        }

        // Check for proper access control
        if fn_name.contains("access") {
            self.add_warning(
                "Function contains 'access' in name - ensure proper access control".to_string(),
                "Implement proper access control checks using Anchor's constraints".to_string(),
            );
        }
    }
    
    /// Checks if an initialization function has proper reinitialization prevention
    ///
    /// # Arguments
    ///
    /// * `item_fn` - The initialization function to check
    fn check_for_init_checks(&mut self, item_fn: &'ast ItemFn) {
        // Check if there's code that checks for is_initialized or similar
        let fn_body = &item_fn.block.to_token_stream().to_string();
        
        // Look for patterns that suggest reinitialization protection
        let has_init_check = fn_body.contains("is_initialized") 
            && (fn_body.contains("if") || fn_body.contains("assert"));
        
        if !has_init_check {
            self.add_vulnerability(
                Severity::High,
                "Initialization function without reinitialization check".to_string(),
                "Add an is_initialized check to prevent reinitialization attacks. In native Rust, verify an is_initialized flag before setting data. In Anchor, use the init constraint.".to_string(),
            );
        }
    }

    // MARK: - Struct Analysis Methods

    /// Analyzes a struct for potential vulnerabilities
    ///
    /// Checks for:
    /// - Missing is_initialized field in account structs
    /// - Improper field validation in Anchor Accounts structs
    ///
    /// # Arguments
    ///
    /// * `item_struct` - Struct to analyze
    fn check_struct(&mut self, item_struct: &'ast ItemStruct) {
        // Update location from struct span
        self.update_location_from_span(item_struct.span());
        
        // Get struct name for pattern matching
        let struct_name = item_struct.ident.to_string();
        
        // Check if this is an Anchor Accounts struct
        let is_accounts_struct = item_struct.attrs.iter().any(|attr| {
            attr.to_token_stream().to_string().contains("Accounts")
        });
        
        if is_accounts_struct {
            self.add_info(format!("Anchor Accounts struct detected: {}", struct_name));
            
            // Check each field for proper constraints
            for field in &item_struct.fields {
                self.check_account_field(field, &struct_name);
            }
        }
        
        // Check for common Solana account patterns
        if struct_name.contains("Account") {
            self.add_info("Account struct detected - ensure proper validation".to_string());
            
            // Check if the struct has an is_initialized field for reinitialization protection
            self.check_for_is_initialized_field(item_struct, is_accounts_struct, &struct_name);
        }
    }
    
    /// Checks if an account struct has an is_initialized field
    ///
    /// # Arguments
    ///
    /// * `item_struct` - The struct to check
    /// * `is_accounts_struct` - Whether the struct is an Anchor Accounts struct
    /// * `struct_name` - Name of the struct
    fn check_for_is_initialized_field(
        &mut self,
        item_struct: &ItemStruct,
        is_accounts_struct: bool,
        struct_name: &str
    ) {
            let has_is_initialized = item_struct.fields.iter().any(|field| {
                if let Some(ident) = &field.ident {
                    ident.to_string() == "is_initialized"
                } else {
                    false
                }
            });
            
            if !has_is_initialized && !is_accounts_struct {
                self.add_warning(
                    format!("Account struct {} missing is_initialized field", struct_name),
                    "Add an is_initialized: bool field to account structs to prevent reinitialization attacks".to_string(),
                );
        }
    }
    
    /// Analyzes an Anchor account field for potential vulnerabilities
    ///
    /// Checks for:
    /// - Unchecked AccountInfo fields
    /// - Missing owner checks
    /// - Incorrect init constraints
    /// - Associated Token Account initialization issues
    ///
    /// # Arguments
    ///
    /// * `field` - The struct field to analyze
    /// * `struct_name` - Name of the containing struct
    fn check_account_field(&mut self, field: &'ast Field, struct_name: &str) {
        // Update location from field span
        self.update_location_from_span(field.span());
        
        // Get field information
        let field_type = field.ty.to_token_stream().to_string();
        let field_name = field.ident
            .as_ref()
            .map_or("unnamed".to_string(), |id| id.to_string());
        
        // Check for different account types
        self.check_account_info_field(field, &field_type, &field_name, struct_name);
        self.check_account_field_validation(field, &field_type, &field_name, struct_name);
        
        // Check field attributes for ATA initialization issues
        for attr in &field.attrs {
            self.check_for_ata_init_issues(attr, &field_name, &field_type);
        }
    }
    
    /// Checks for proper validation of AccountInfo fields
    ///
    /// # Arguments
    ///
    /// * `field` - The field to check
    /// * `field_type` - Type of the field
    /// * `field_name` - Name of the field
    /// * `struct_name` - Name of the containing struct
    fn check_account_info_field(
        &mut self,
        field: &Field,
        field_type: &str,
        field_name: &str,
        struct_name: &str
    ) {
        if field_type.contains("AccountInfo") {
            // Check if there are constraints on this field
            let has_constraints = field.attrs.iter().any(|attr| {
                let attr_str = attr.to_token_stream().to_string();
                attr_str.contains("account") 
                    || attr_str.contains("signer") 
                    || attr_str.contains("constraint")
                    || attr_str.contains("owner")
            });
            
            // Check if it's likely a program account based on name
            let is_program_account = field_name.contains("program") 
                || field_name.contains("Program") 
                || field_name.ends_with("_program")
                || field_name.ends_with("_Program");
            
            if !has_constraints {
                // If this appears to be a program account, it's a critical arbitrary CPI risk
                if is_program_account {
                    self.add_vulnerability(
                        Severity::Critical,
                        format!("Unchecked program AccountInfo in struct {}: field {} - potential arbitrary CPI vulnerability", struct_name, field_name),
                        "Use Program<'info, T> instead of AccountInfo for program accounts to automatically validate program IDs, or add explicit validation checks.".to_string(),
                    );
                } else {
                    // General unconstrained AccountInfo warning
                    self.add_vulnerability(
                        Severity::High,
                        format!("Unchecked AccountInfo in struct {}: field {}", struct_name, field_name),
                        "Add proper constraints to AccountInfo fields using Anchor attributes (e.g., #[account(...)]).".to_string(),
                    );
                }
            } else if is_program_account {
                // Even with some constraints, program accounts need specific checks
                self.add_warning(
                    format!("Program account {} uses AccountInfo - consider stronger validation", field_name),
                    "Use Program<'info, T> or add explicit program ID verification in your code.".to_string(),
                );
            }
        }
    }
    
    /// Checks for proper validation of Account<T> fields
    ///
    /// # Arguments
    ///
    /// * `field` - The field to check
    /// * `field_type` - Type of the field
    /// * `field_name` - Name of the field
    /// * `struct_name` - Name of the containing struct
    fn check_account_field_validation(
        &mut self,
        field: &Field,
        field_type: &str,
        field_name: &str,
        struct_name: &str
    ) {
        if field_type.contains("Account<") {
            // Check for owner constraint
            self.check_account_owner_constraint(field, field_name, struct_name);
            
            // Check for proper initialization constraints
            self.check_account_init_constraints(field, field_name, struct_name);
        }

        // Check field attributes for PDA derivation issues
        for attr in &field.attrs {
            if attr.path().is_ident("account") {
                self.check_anchor_account_attribute(attr);
            }
        }
    }
    
    /// Checks if an Account<T> field has owner constraint
    ///
    /// # Arguments
    ///
    /// * `field` - The field to check
    /// * `field_name` - Name of the field
    /// * `struct_name` - Name of the containing struct
    fn check_account_owner_constraint(
        &mut self,
        field: &Field,
        field_name: &str,
        struct_name: &str
    ) {
            let has_owner_check = field.attrs.iter().any(|attr| {
                attr.to_token_stream().to_string().contains("owner")
            });
            
            if !has_owner_check {
                self.add_warning(
                    format!("Missing owner check for Account in struct {}: field {}", struct_name, field_name),
                    "Add #[account(owner = <PROGRAM_ID>)] to ensure the account is owned by the expected program.".to_string(),
                );
        }
    }
    
    /// Checks for proper initialization constraints on account fields
    ///
    /// # Arguments
    ///
    /// * `field` - The field to check
    /// * `field_name` - Name of the field
    /// * `struct_name` - Name of the containing struct
    fn check_account_init_constraints(
        &mut self,
        field: &Field,
        field_name: &str,
        struct_name: &str
    ) {
        // Check for space attribute without init
            let has_space = field.attrs.iter().any(|attr| {
                attr.to_token_stream().to_string().contains("space")
            });
            
            let has_init = field.attrs.iter().any(|attr| {
                let attr_str = attr.to_token_stream().to_string();
                attr_str.contains("init") || attr_str.contains("init_if_needed")
            });
            
            if has_space && !has_init {
                self.add_warning(
                    format!("Account space specified without init constraint in struct {}: field {}", struct_name, field_name),
                    "Add the init constraint when specifying space: #[account(init, space = ...)]".to_string(),
                );
            }
            
            // Check for use of init_if_needed which requires careful handling
            let has_init_if_needed = field.attrs.iter().any(|attr| {
                attr.to_token_stream().to_string().contains("init_if_needed")
            });
            
            if has_init_if_needed {
                self.add_warning(
                    format!("Using init_if_needed in struct {}: field {}", struct_name, field_name),
                    "init_if_needed can be risky. Ensure the instruction handler includes checks to prevent resetting the account to its initial state.".to_string(),
                );
            }
        }
        
    // MARK: - Enum Analysis Methods

    /// Analyzes an enum for potential issues
    ///
    /// Currently only checks for error enums and adds an informational note
    ///
    /// # Arguments
    ///
    /// * `item_enum` - The enum to analyze
    fn check_enum(&mut self, item_enum: &'ast ItemEnum) {
        // Update location from enum span
        self.update_location_from_span(item_enum.span());
        
        // Check for proper error enum structure
        let enum_name = item_enum.ident.to_string();
        
        if enum_name.contains("Error") {
            self.add_info("Error enum detected - ensure proper error handling".to_string());
        }
    }
    
    // MARK: - Expression Analysis Methods
    
    /// Checks if an expression is validating remaining accounts
    ///
    /// # Arguments
    ///
    /// * `expr` - The expression to check
    fn check_for_remaining_accounts_validation(&mut self, expr: &'ast Expr) {
        match expr {
            // Check for validation patterns like account.owner == expected_owner
            Expr::Binary(bin_expr) => {
                self.update_location_from_span(bin_expr.span());
                if let BinOp::Eq(_) = bin_expr.op {
                    // This could be an ownership check
                    if let Expr::Field(field_expr) = &*bin_expr.left {
                        self.update_location_from_span(field_expr.span());
                        let member_str = field_expr.member.to_token_stream().to_string();
                        if member_str == "owner" || member_str == "key" {
                            // This is checking an account's owner or key, which is a type of validation
                            self.has_remaining_accounts_validation = true;
                        }
                    }
                }
            }
            
            // Check for method calls that might be validations
            Expr::MethodCall(method_call) => {
                self.update_location_from_span(method_call.span());
                let method_name = method_call.method.to_string();
                
                // Check for common validation method name patterns
                if method_name.contains("check") 
                    || method_name.contains("verify") 
                    || method_name.contains("validate")
                    || method_name.contains("assert") {
                    self.has_remaining_accounts_validation = true;
                }
            }
            
            _ => {}
        }
    }

    /// Checks for Associated Token Account (ATA) initialization issues
    ///
    /// Specifically looks for ATAs using 'init' rather than 'init_if_needed'
    ///
    /// # Arguments
    ///
    /// * `attr` - The attribute to check
    /// * `field_name` - Name of the field
    /// * `field_type` - Type of the field
    fn check_for_ata_init_issues(&mut self, attr: &syn::Attribute, field_name: &str, _field_type: &str) {
        // Check if this is an account attribute
        if !attr.path().is_ident("account") {
            return;
        }
        
        // Get location from attribute span
        self.update_location_from_span(attr.span());
        
        let attr_string = attr.to_token_stream().to_string();
        
        // Identify if this is likely an associated token account
        let is_ata = attr_string.contains("associated_token::") 
            || field_name.contains("ata") 
            || field_name.contains("token_account")
            || field_name.contains("tokenAccount");
                     
        if is_ata {
            // Check if it's using init instead of init_if_needed
            let attr_parts: Vec<&str> = attr_string.split(',').collect();
            
            // Check if any part contains the init word but not init_if_needed
            let has_init = attr_parts.iter().any(|part| {
                part.contains("init") && !part.contains("init_if_needed")
            });
            let has_init_if_needed = attr_string.contains("init_if_needed");
            
            if has_init && !has_init_if_needed {
                self.add_vulnerability(
                    Severity::Critical,
                    format!("Associated Token Account '{}' initialized with 'init' constraint instead of 'init_if_needed'", field_name),
                    "Use 'init_if_needed' for Associated Token Accounts to handle cases where users already have ATAs created. Using 'init' will fail if the account already exists.".to_string(),
                );
            }
        }
    }
    
    /// Checks arithmetic expressions for potential overflow/underflow vulnerabilities
    ///
    /// # Arguments
    ///
    /// * `bin_expr` - The binary expression to check
    /// * `op` - The operation being performed
    fn check_arithmetic_operation(&mut self, _bin_expr: &ExprBinary, op: &BinOp) {
        // Determine which arithmetic operation is being performed
        let op_str = match op {
            BinOp::Add(_) => "addition",
            BinOp::Sub(_) => "subtraction",
            BinOp::Mul(_) => "multiplication",
            _ => return, // Not an arithmetic operation we're interested in
        };
        
        // Only report overflow/underflow issues if overflow checks are not enabled
        if !self.has_overflow_checks {
            self.add_vulnerability(
                Severity::High,
                format!("Potential arithmetic overflow/underflow detected in {} operation", op_str),
                "Use checked arithmetic operations (checked_add, checked_sub, checked_mul) or enable overflow-checks = true in Cargo.toml".to_string(),
            );
        } else {
            // If overflow checks are enabled, add a less severe info notice
            self.add_info(
                format!("Arithmetic operation with runtime overflow protection: {} operation", op_str),
            );
        }
    }
    
    /// Checks for large integer literals that might cause overflow
    ///
    /// # Arguments
    ///
    /// * `lit` - The literal expression to check
    fn check_large_integer_literal(&mut self, lit: &ExprLit) {
        if let syn::Lit::Int(int_lit) = &lit.lit {
            // Try to parse the integer value
            if let Ok(value) = int_lit.base10_parse::<u64>() {
                // Check if it exceeds 32-bit range, which is common in Solana
                if value > u32::MAX as u64 {
                    self.add_warning(
                        format!("Large integer literal detected: {}", value),
                        "Consider using a smaller integer type or implementing proper overflow checks".to_string(),
                    );
                }
            }
        }
    }
    
    /// Checks if an expression contains guards against reinitialization
    ///
    /// # Arguments
    ///
    /// * `expr` - The expression to check
    fn check_for_initialization_guards(&mut self, expr: &'ast Expr) {
            match expr {
                Expr::If(if_expr) => {
                    let condition = if_expr.cond.to_token_stream().to_string();
                    if condition.contains("is_initialized") {
                        // Found an is_initialized check, which is good
                        self.add_info(
                            "Detected is_initialized check to prevent reinitialization".to_string(),
                        );
                    }
                },
                Expr::Call(call_expr) => {
                    // Check for assertion calls like assert!() or require!()
                    let func_str = call_expr.func.to_token_stream().to_string();
                    if func_str.contains("assert") || func_str.contains("require") {
                        let args_str = call_expr.args.to_token_stream().to_string();
                        if args_str.contains("is_initialized") {
                            // Found an is_initialized assertion, which is good
                            self.add_info(
                                "Detected is_initialized assertion to prevent reinitialization".to_string(),
                            );
                        }
                    }
                },
                _ => {}
            }
        }
        
    /// Checks an expression for various security issues
    ///
    /// # Arguments
    ///
    /// * `expr` - The expression to check
    fn check_expr_for_issues(&mut self, expr: &'ast Expr) {
        match expr {
            Expr::Field(field_expr) => {
                self.update_location_from_span(field_expr.span());
                
                // If this accesses account data after a CPI, track it to warn about possible account data tampering
                if self.cpi_performed {
                    let field_str = field_expr.to_token_stream().to_string();
                    
                    // Only track if it's not a reload() call, which would be safe
                    if !field_str.contains("reload") {
                        self.accessed_accounts.push(field_str.clone());
                    }
                }
                
                // Check for remaining_accounts access (existing code)
                if let Expr::Path(_path_expr) = &*field_expr.base {
                    let member_str = field_expr.member.to_token_stream().to_string();
                    if member_str == "remaining_accounts" {
                        // Found direct access to remaining_accounts
                        self.has_remaining_accounts_access = true;
                    }
                }
            }
            Expr::MethodCall(method_call) => {
                self.update_location_from_span(method_call.span());
                let method_name = method_call.method.to_string();
                let receiver_str = method_call.receiver.to_token_stream().to_string();
                
                // If a CPI was performed and this is not a reload() call, track it as potential unsafe access
                if self.cpi_performed && method_name != "reload" {
                    self.accessed_accounts.push(receiver_str.clone());
                }
                
                // Check for remaining_accounts access (existing code)
                if receiver_str.contains("remaining_accounts") {
                    // Found a method call on remaining_accounts
                    self.has_remaining_accounts_access = true;
                }
                
                // Look for create_program_address calls
                if method_name == "create_program_address" {
                    // Check if this is in a function that has a bump parameter
                    if self.current_function_has_bump_param {
                        // This might be a non-canonical bump usage
                        self.non_canonical_bump_detected = true;
                    }
                }
            }
            // Look for cast expressions
            Expr::Cast(cast_expr) => {
                self.update_location_from_span(cast_expr.span());
                let target_type = cast_expr.ty.to_token_stream().to_string();
                if target_type.contains("AccountInfo") {
                    self.add_warning(
                        "Casting to AccountInfo - ensure proper validation".to_string(),
                        "Validate the account before and after casting to AccountInfo".to_string(),
                    );
                }
            }
            // Check for CPI calls to ensure proper account validation
            Expr::Call(call_expr) => {
                self.update_location_from_span(call_expr.span());
                let func_str = call_expr.func.to_token_stream().to_string();
                
                // Mark that a CPI was performed if this is an invoke or CpiContext usage
                if func_str.contains("invoke") || func_str.contains("invoke_signed") || func_str.contains("CpiContext") {
                    self.cpi_performed = true;
                }
                
                // Check for direct invoke or invoke_signed calls which may indicate arbitrary CPI
                if func_str.contains("invoke") || func_str.contains("invoke_signed") {
                    // This is a stronger warning since it's a direct Solana CPI which needs careful handling
                    self.add_vulnerability(
                        Severity::Critical,
                        "Potential arbitrary CPI vulnerability detected".to_string(),
                        "Verify the program ID of the target program before invoking a cross-program call. Use `if target_program.key() != expected_program_id { return Err(...) }` to validate.".to_string(),
                    );
                }
                
                // Check for CPI context creation that might lead to arbitrary CPI
                if func_str.contains("CpiContext") {
                    // This is a general warning as it's a common pattern that needs validation
                    self.add_warning(
                        "Cross-Program Invocation detected - ensure proper program validation".to_string(),
                        "Validate the program ID and all accounts passed to the CPI before invoking. Use Program<'info, T> instead of AccountInfo for program accounts.".to_string(),
                    );
                }
                
                // Look for Pubkey::create_program_address without finding canonical bump first
                if func_str.contains("create_program_address") && !func_str.contains("find_program_address") {
                    // This is a potential bump seed canonicalization issue
                    self.add_warning(
                        "Using create_program_address directly may lead to non-canonical bump usage".to_string(),
                        "Use find_program_address to get the canonical bump first, or validate that you're using the canonical bump.".to_string(),
                    );
                }
            }
            _ => {}
        }
    }

    /// Checks anchor account attribute for bump usage
    fn check_anchor_account_attribute(&mut self, attr: &Attribute) {
        if !attr.path().is_ident("account") {
            return;
        }
        
        let attr_str = attr.to_token_stream().to_string();
        
        // Check for seeds without bump, which could indicate manual bump handling
        if attr_str.contains("seeds") && !attr_str.contains("bump") {
            self.add_warning(
                "PDA seeds constraint without bump constraint".to_string(),
                "When using the seeds constraint, also specify a bump constraint to ensure canonical bump is used.".to_string(),
            );
        }
        
        // Check for explicit bump value that might not be canonical
        if attr_str.contains("bump =") && !attr_str.contains("bump = bump") && !attr_str.contains("bump = data.bump") {
            // This could be a hardcoded non-canonical bump
            if attr_str.contains("bump = 0") || 
               attr_str.contains("bump = 1") || 
               attr_str.contains("bump = 2") {
                self.add_vulnerability(
                    Severity::Critical,
                    "Hardcoded non-canonical bump value detected".to_string(),
                    "Using a hardcoded bump value risks using a non-canonical bump. Use bump without a value to derive canonical bump, or use bump = data.bump to reference stored canonical bump.".to_string(),
                );
            } else {
                self.add_warning(
                    "Custom bump value in anchor constraint".to_string(),
                    "Ensure this bump value is the canonical bump, preferably stored from find_program_address() result.".to_string(),
                );
            }
        }
    }
}

// MARK: - Syn Visitor Implementation

impl<'ast> Visit<'ast> for AnchorVisitor<'ast> {
    /// Entry point for visiting any item in the AST
    ///
    /// # Arguments
    ///
    /// * `item` - The item to visit
    fn visit_item(&mut self, item: &'ast Item) {
        // Update location from item span
        match item {
            Item::Fn(item_fn) => self.update_location_from_span(item_fn.span()),
            Item::Struct(item_struct) => self.update_location_from_span(item_struct.span()),
            Item::Enum(item_enum) => self.update_location_from_span(item_enum.span()),
            Item::Mod(item_mod) => self.update_location_from_span(item_mod.span()),
            _ => self.update_location_from_span(item.span()),
        }
        
        // Dispatch to specific item handlers
        match item {
            Item::Fn(item_fn) => self.check_function(item_fn),
            Item::Struct(item_struct) => self.check_struct(item_struct),
            Item::Enum(item_enum) => self.check_enum(item_enum),
            Item::Mod(item_mod) => syn::visit::visit_item_mod(self, item_mod),
            _ => syn::visit::visit_item(self, item),
        }
    }

    /// Visits an expression in the AST
    ///
    /// # Arguments
    ///
    /// * `expr` - The expression to visit
    fn visit_expr(&mut self, expr: &'ast Expr) {
        // Update location from expression span
        self.update_location_from_span(expr.span());
        
        // Check for is_initialized checks in initialization functions
        if self.current_function_is_init {
            self.check_for_initialization_guards(expr);
        }
        
        // Check for various issues in expressions
        self.check_expr_for_issues(expr);
        
        // Check if this expression could be validating remaining accounts
        self.check_for_remaining_accounts_validation(expr);
        
        // Continue with recursive expression checks
        match expr {
            Expr::Binary(bin_expr) => {
                self.update_location_from_span(bin_expr.span());
                match bin_expr.op {
                    BinOp::Add(_) | BinOp::Sub(_) | BinOp::Mul(_) => {
                        self.check_arithmetic_operation(bin_expr, &bin_expr.op);
                    }
                    _ => {}
                }
                syn::visit::visit_expr(self, &bin_expr.left);
                syn::visit::visit_expr(self, &bin_expr.right);
            }
            Expr::Lit(lit) => {
                self.update_location_from_span(lit.span());
                self.check_large_integer_literal(lit);
            }
            _ => syn::visit::visit_expr(self, expr),
        }
    }

    /// Visits a binary expression in the AST
    ///
    /// # Arguments
    ///
    /// * `bin_expr` - The binary expression to visit
    fn visit_expr_binary(&mut self, bin_expr: &'ast ExprBinary) {
        // Check for potential arithmetic overflow/underflow
        self.check_arithmetic_operation(bin_expr, &bin_expr.op);
        
        // Continue with the default visit implementation
        syn::visit::visit_expr_binary(self, bin_expr);
    }

    /// Visits a literal expression in the AST
    ///
    /// # Arguments
    ///
    /// * `lit` - The literal expression to visit
    fn visit_expr_lit(&mut self, lit: &'ast ExprLit) {
        // Check for large integer literals
        self.check_large_integer_literal(lit);
        
        // Continue with the default visit implementation
        syn::visit::visit_expr_lit(self, lit);
    }
} 