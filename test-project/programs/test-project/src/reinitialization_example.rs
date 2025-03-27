use anchor_lang::prelude::*;

#[account]
pub struct InsecureAccount {
    pub authority: Pubkey,
    pub data: u64,
}

#[account]
pub struct SecureAccount {
    pub is_initialized: bool,
    pub authority: Pubkey,
    pub data: u64,
}

// Insecure initialization function - no reinitialization check
pub fn initialize_insecure(ctx: Context<InitializeInsecure>) -> Result<()> {
    // No check for reinitialization
    let account = &mut ctx.accounts.account;
    account.authority = ctx.accounts.authority.key();
    account.data = 0;
    
    Ok(())
}

// Secure initialization function - with reinitialization check
pub fn initialize_secure(ctx: Context<InitializeSecure>) -> Result<()> {
    let account = &mut ctx.accounts.account;
    
    // Check if already initialized
    if account.is_initialized {
        return Err(ProgramError::AccountAlreadyInitialized.into());
    }
    
    // Set initialized flag
    account.is_initialized = true;
    account.authority = ctx.accounts.authority.key();
    account.data = 0;
    
    Ok(())
}

// Anchor-recommended initialization using init constraint
pub fn initialize_with_anchor(ctx: Context<InitializeWithAnchor>) -> Result<()> {
    let account = &mut ctx.accounts.account;
    account.authority = ctx.accounts.authority.key();
    account.data = 0;
    
    Ok(())
}

#[derive(Accounts)]
pub struct InitializeInsecure<'info> {
    #[account(mut)]
    pub account: Account<'info, InsecureAccount>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeSecure<'info> {
    #[account(mut)]
    pub account: Account<'info, SecureAccount>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeWithAnchor<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 8
    )]
    pub account: Account<'info, InsecureAccount>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
} 