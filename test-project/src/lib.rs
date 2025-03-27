use anchor_lang::prelude::*;
use anchor_spl::token::{self, TokenAccount, Token};

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

// Include all our vulnerable modules
mod token_program;
mod calculator;
mod large_integers;
mod pda_program;

// Re-export the modules
pub use token_program::*;
pub use calculator::*;
pub use large_integers::*;
pub use pda_program::*;

#[program]
pub mod vulnerability_demo {
    use super::*;

    // Another vulnerability: Missing owner check
    pub fn unsafe_operation(ctx: Context<UnsafeOperation>) -> Result<()> {
        // VULNERABILITY: No owner check on the account being modified
        let account = &mut ctx.accounts.target_account;
        account.data = 100;
        Ok(())
    }

    pub fn initialize_vault(ctx: Context<InitializeVault>, owner: Pubkey) -> Result<()> {
        // VULNERABILITY: No check if the vault is already initialized
        let vault = &mut ctx.accounts.vault;
        vault.owner = owner;
        vault.balance = 0;
        vault.is_initialized = true;
        
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        // VULNERABILITY: Arithmetic operation without overflow check
        let vault = &mut ctx.accounts.vault;
        vault.balance = vault.balance + amount;
        
        // VULNERABILITY: Not checking if account matches stored owner
        // if ctx.accounts.user.key() != vault.owner {
        //     return Err(ProgramError::InvalidAccountData.into());
        // }
        
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        // VULNERABILITY: Missing signer check
        // The authority account is not checked for being a signer
        
        let vault = &mut ctx.accounts.vault;
        
        // VULNERABILITY: No check if authority matches vault owner
        // if ctx.accounts.authority.key() != vault.owner {
        //     return Err(ProgramError::InvalidAccountData.into());
        // }
        
        // VULNERABILITY: Arithmetic operation without underflow check
        vault.balance = vault.balance - amount;
        
        Ok(())
    }

    pub fn process_remaining_accounts(ctx: Context<ProcessAccounts>) -> Result<()> {
        // VULNERABILITY: Accessing remaining_accounts without validation
        let remaining_accounts = ctx.remaining_accounts;
        
        if !remaining_accounts.is_empty() {
            for account in remaining_accounts {
                // No validation of account ownership or type
                let data = account.try_borrow_data()?;
                msg!("Account data length: {}", data.len());
            }
        }
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(mut)]
    pub vault: Account<'info, VaultState>,
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, VaultState>,
    pub user: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, VaultState>,
    // VULNERABILITY: Missing signer constraint
    pub authority: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct ProcessAccounts<'info> {
    pub user: Signer<'info>,
}

#[account]
pub struct VaultState {
    pub owner: Pubkey,
    pub balance: u64,
    pub is_initialized: bool,
}

#[derive(Accounts)]
#[instruction(bump: u8)]
pub struct WithdrawWithBump<'info> {
    // VULNERABILITY: Using attacker-supplied bump instead of canonical bump
    #[account(
        seeds = [b"vault", authority.key().as_ref()],
        bump = bump,
    )]
    pub vault: Account<'info, VaultState>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct UnsafeOperation<'info> {
    pub user: Signer<'info>,
    
    /// CHECK: This is unchecked and vulnerable
    #[account(mut)]
    pub target_account: Account<'info, DataAccount>,
}

#[account]
pub struct DataAccount {
    pub data: u64,
} 