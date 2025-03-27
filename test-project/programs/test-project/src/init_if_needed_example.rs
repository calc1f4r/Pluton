use anchor_lang::prelude::*;

#[account]
pub struct RiskyAccount {
    pub authority: Pubkey,
    pub value: u64,
}

// Potentially unsafe initialization with init_if_needed
pub fn initialize_risky(ctx: Context<InitializeRisky>) -> Result<()> {
    // This function doesn't check if the account is already initialized
    // Since init_if_needed will allow this function to execute even for
    // already initialized accounts, this is risky
    
    let account = &mut ctx.accounts.account;
    account.authority = ctx.accounts.authority.key();
    account.value = 0;
    
    // No checks to see if account.authority was already set to a different value
    // An attacker could call this function on an already initialized account
    // and change the authority
    
    Ok(())
}

// Safe usage of init_if_needed with proper checks
pub fn initialize_safe(ctx: Context<InitializeRisky>) -> Result<()> {
    let account = &mut ctx.accounts.account;
    
    // Check if account is already initialized by looking at authority
    // Only proceed if account.authority is either uninitialized (all zeros)
    // or already matches the signer
    
    let uninitialized = account.authority == Pubkey::default();
    let is_owner = account.authority == ctx.accounts.authority.key();
    
    if !uninitialized && !is_owner {
        return Err(ProgramError::IllegalOwner.into());
    }
    
    // Now it's safe to set or reset values
    account.authority = ctx.accounts.authority.key();
    account.value = 0;
    
    Ok(())
}

#[derive(Accounts)]
pub struct InitializeRisky<'info> {
    #[account(
        init_if_needed,
        payer = authority,
        space = 8 + 32 + 8
    )]
    pub account: Account<'info, RiskyAccount>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitializeSecure<'info> {
    #[account(
        init_if_needed,
        payer = authority,
        space = 8 + 1 + 32 + 8  // Added space for is_initialized flag
    )]
    pub account: Account<'info, SecureAccount>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
} 