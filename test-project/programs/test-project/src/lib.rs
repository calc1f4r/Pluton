use anchor_lang::prelude::*;
use anchor_lang::solana_program::system_program;

mod reinitialization_example;
mod init_if_needed_example;
mod zellic_examples;
mod ata_example;

declare_id!("6BB75SiK57bXuemqc8d5CQbNthkrauUDLfSqPTTbYXc8");

#[program]
pub mod test_project {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        msg!("Greetings from: {:?}", ctx.program_id);
        Ok(())
    }

    // Function with potential overflow issues
    pub fn unsafe_math(ctx: Context<UnsafeMath>, a: u64, b: u64) -> Result<()> {
        // Potential overflow in addition
        let sum = a + b;
        
        // Potential overflow in multiplication
        let product = a * b;
        
        // Potential underflow in subtraction
        let difference = a - b;
        
        msg!("Unsafe math results: sum={}, product={}, diff={}", sum, product, difference);
        Ok(())
    }

    // Function with large numbers that might cause overflow
    pub fn large_numbers(ctx: Context<LargeNumbers>) -> Result<()> {
        // Large number that might cause overflow
        let large_value: u64 = 4294967296; // 2^32
        
        // Another large number
        let another_large: u128 = 18446744073709551615; // 2^64 - 1
        
        msg!("Large numbers: {}, {}", large_value, another_large);
        Ok(())
    }
    
    // Function with improper remaining accounts usage - no validation
    pub fn unsafe_remaining_accounts(ctx: Context<UnsafeRemainingAccounts>) -> Result<()> {
        // Accessing remaining accounts without validation
        let remaining = &ctx.remaining_accounts;
        
        // Do something with the remaining accounts without validation
        for account in remaining.iter() {
            msg!("Account: {:?}", account.key);
            // Potentially unsafe operations without validation
        }
        
        Ok(())
    }
    
    // Function with proper remaining accounts validation
    pub fn safe_remaining_accounts(ctx: Context<SafeRemainingAccounts>) -> Result<()> {
        // Getting remaining accounts
        let remaining = &ctx.remaining_accounts;
        
        // Validate the accounts before using them
        for account in remaining.iter() {
            // Check ownership
            if account.owner != &system_program::ID {
                return Err(ErrorCode::InvalidOwner.into());
            }
            
            // Additional validation checks
            if !account.is_writable {
                return Err(ErrorCode::AccountNotWritable.into());
            }
        }
        
        // Now it's safe to use the accounts
        for account in remaining.iter() {
            msg!("Account: {:?}", account.key);
        }
        
        Ok(())
    }
    
    // Function that uses unchecked AccountInfo 
    pub fn unchecked_account_info(ctx: Context<UncheckedAccountInfo>) -> Result<()> {
        // Directly using an AccountInfo without proper validation
        let account = &ctx.accounts.unchecked_account;
        
        // Potentially unsafe operations on this account
        msg!("Unchecked account: {:?}", account.key());
        
        Ok(())
    }
    
    // Function that casts to AccountInfo without validation
    pub fn cast_to_account_info(ctx: Context<CastToAccountInfo>, account_idx: u64) -> Result<()> {
        // Casting to AccountInfo without proper validation
        let accounts = &ctx.remaining_accounts;
        
        if (account_idx as usize) < accounts.len() {
            let account = &accounts[account_idx as usize];
            
            // This is dangerous without validation
            msg!("Account: {:?}", account.key());
        }
        
        Ok(())
    }
    
    // Function with cross-program invocation (CPI)
    pub fn perform_cpi(ctx: Context<PerformCPI>) -> Result<()> {
        // Simulating CPI without validation
        msg!("Would perform CPI without account validation");
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize {}

#[derive(Accounts)]
pub struct UnsafeMath {}

#[derive(Accounts)]
pub struct LargeNumbers {}

#[derive(Accounts)]
pub struct UnsafeRemainingAccounts {}

#[derive(Accounts)]
pub struct SafeRemainingAccounts {}

// Struct with unchecked AccountInfo
#[derive(Accounts)]
pub struct UncheckedAccountInfo<'info> {
    // This AccountInfo has no constraints
    pub unchecked_account: AccountInfo<'info>,
    
    // This account is properly checked
    #[account(mut, signer)]
    pub payer: Signer<'info>,
}

// Struct for casting to AccountInfo example
#[derive(Accounts)]
pub struct CastToAccountInfo<'info> {
    #[account(mut, signer)]
    pub authority: Signer<'info>,
}

// Struct for CPI example
#[derive(Accounts)]
pub struct PerformCPI<'info> {
    // Missing owner check
    pub source_account: Account<'info, TokenAccount>,
    
    // Missing owner check
    pub destination_account: Account<'info, TokenAccount>,
    
    #[account(signer)]
    pub authority: Signer<'info>,
    
    pub token_program: AccountInfo<'info>,
}

// Example account struct
#[account]
pub struct TokenAccount {
    pub owner: Pubkey,
    pub amount: u64,
}

// Example struct with missing init constraint
#[derive(Accounts)]
pub struct MissingInitConstraint<'info> {
    #[account(
        init,
        space = 8 + 32 + 8,
        payer = payer
    )]
    pub data_account: Account<'info, SomeData>,
    
    #[account(mut, signer)]
    pub payer: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[account]
pub struct SomeData {
    pub owner: Pubkey,
    pub value: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Account owner is invalid")]
    InvalidOwner,
    #[msg("Account is not writable")]
    AccountNotWritable,
}
