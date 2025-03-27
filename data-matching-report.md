# Pluton Analysis Report

## Summary

- **Critical Vulnerabilities**: 0
- **High Severity Vulnerabilities**: 0
- **Warnings**: 2
- **Informational Items**: 4

## Warnings

### Account struct ConfigAccount missing is_initialized field

**Location**: vulnerability-test/src/data_matching.rs:0:0

**Suggestion**: Add an is_initialized: bool field to account structs to prevent reinitialization attacks

---

### Account struct VaultAccount missing is_initialized field

**Location**: vulnerability-test/src/data_matching.rs:0:0

**Suggestion**: Add an is_initialized: bool field to account structs to prevent reinitialization attacks

---

## Informational Items

- **Anchor Accounts struct detected: UpdateAdminSettings** (vulnerability-test/src/data_matching.rs:0:0)
- **Anchor Accounts struct detected: WithdrawVault** (vulnerability-test/src/data_matching.rs:0:0)
- **Account struct detected - ensure proper validation** (vulnerability-test/src/data_matching.rs:0:0)
- **Account struct detected - ensure proper validation** (vulnerability-test/src/data_matching.rs:0:0)
