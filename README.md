# Solana Static Analyzer

A static analyzer for Solana programs that detects common security vulnerabilities and provides suggestions for fixing them.

## Features

The analyzer detects the following types of vulnerabilities:

### Critical Vulnerabilities
- **Unsafe usage of `init_if_needed` constraint** - Detects when this dangerous constraint is used without proper validation, which can lead to reinitialization attacks
- **Unsafe usage of `ctx.remaining_accounts`** - Finds occurrences where accounts from `remaining_accounts` are used without proper validation
- **Account data accessed after CPI without reload** - Identifies when account data is accessed after a Cross-Program Invocation without calling the `.reload()` method
- **Potential confused deputy vulnerability in CPI** - Detects when a CPI is performed without validating the program ID of the target program

### High Severity Vulnerabilities
- **Initialization function without reinitialization check** - Identifies functions that initialize accounts without checking if they're already initialized
- **Missing signer check for authority fields** - Detects when authority fields are not properly validated as signers
- **Accessing `remaining_accounts` without proper validation** - Finds code that accesses `remaining_accounts` without proper checks
- **Unchecked AccountInfo in structs** - Identifies when an `AccountInfo` field lacks proper constraints

### Medium Severity Vulnerabilities
- **Possible missing account data matching checks** - Suggests adding validation for account data matching
- **Potential duplicate mutable accounts vulnerability** - Warns about possible duplicate mutable accounts in an instruction
- **Associated Token Account initialized with 'init' instead of 'init_if_needed'** - Detects when ATAs are initialized incorrectly, which can cause failures when accounts already exist

### Other Warnings
- **PDA creation without explicit bump seed canonicalization** - Recommends using canonical bumps
- **PDA seeds may not be unique enough** - Warns about potential seed collisions
- **Cross-Program Invocation with insufficient validation** - Suggests validating accounts before CPI
- **Large integer literals** - Warns about possible overflow/underflow issues
- **Account struct missing `is_initialized` field** - Recommends adding initialization checks

## Usage

```
cargo run -- --project-path <path-to-your-solana-project>
```

The analyzer provides colored output in the terminal for better readability:
- Critical vulnerabilities: Red, bold
- High severity vulnerabilities: Bright red
- Medium severity vulnerabilities: Yellow
- Low severity vulnerabilities: Blue
- Warnings: Yellow
- Info messages: Blue
- Suggestions: Green

### Markdown Reports

You can generate a detailed markdown report with line numbers and references to the Helius security guide by specifying an output file:

```
cargo run -- --project-path <path-to-your-solana-project> --output-file report.md
```

The markdown report includes:
- A summary of vulnerability counts by severity
- Detailed descriptions of each vulnerability with line numbers
- References to the relevant sections of the [Helius blog](https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security) for each vulnerability type
- Warnings and informational items with locations

This is especially useful for sharing results with team members or including in documentation.

## Example Output

```
Analysis Results:

Vulnerabilities:
- [CRITICAL] Unsafe usage of init_if_needed constraint at ./test-project/programs/test-project/src/init_if_needed_example.rs
  Suggestion: The init_if_needed constraint is dangerous because it allows accounts to be reinitialized. Ensure your instruction handler includes explicit checks to verify the state of already initialized accounts and implement proper permissions checks to prevent unauthorized modification.
- [HIGH] Initialization function without reinitialization check at ./test-project/programs/test-project/src/reinitialization_example.rs
  Suggestion: Add an is_initialized check to prevent reinitialization attacks. In native Rust, verify an is_initialized flag before setting data. In Anchor, use the init constraint.
...
```

## Security Recommendations

### For `init_if_needed` Constraint
Always implement explicit checks in your instruction handler to verify the state of initialized accounts:

```rust
if account.is_initialized {
    // Verify the account owner/authority matches the signer
    require!(account.authority == ctx.accounts.authority.key(), ErrorCode::Unauthorized);
}
```

### For Account Reloading After CPI
Always reload accounts after a CPI call to ensure fresh data:

```rust
// After CPI
ctx.accounts.mint.reload()?;
// Now use the updated data
let updated_supply = ctx.accounts.mint.supply;
```

### For Remaining Accounts
Always validate remaining accounts before use:

```rust
fn validate_remaining_accounts(remaining_accounts: &[AccountInfo]) -> Result<()> {
    // 1. Check ownership
    require!(remaining_accounts[0].owner == &TOKEN_PROGRAM_ID, ErrorCode::InvalidOwner);
    
    // 2. Check account type (discriminator)
    let data = remaining_accounts[0].try_borrow_data()?;
    let disc = &data[0..8];
    require!(disc == &[/* expected discriminator */], ErrorCode::InvalidAccountType);
    
    // 3. Validate address (if needed)
    require!(remaining_accounts[0].key() == expected_key, ErrorCode::InvalidAddress);
    
    // 4. Check if account is initialized/not empty
    require!(!remaining_accounts[0].data_is_empty(), ErrorCode::UninitializedAccount);
    
    Ok(())
}
```

### For Cross-Program Invocations
Always validate the program ID before invoking:

```rust
if target_program.key() != expected_program_id {
    return Err(ErrorCode::InvalidProgram.into());
}
```

### For Associated Token Accounts
Always use `init_if_needed` instead of `init` when initializing ATAs:

```rust
#[account(
    init_if_needed,
    payer = payer,
    associated_token::mint = mint,
    associated_token::authority = authority
)]
pub token_account: Account<'info, TokenAccount>,
```

This ensures your program handles the case where a user already has the token account created.

## License

MIT 