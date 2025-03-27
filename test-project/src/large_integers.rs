use anchor_lang::prelude::*;

#[program]
pub mod large_integers {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let account = &mut ctx.accounts.account;
        
        // VULNERABILITY: Using large integer literals without specifying type
        account.large_value = 9999999999;  // Exceeds i32 range
        
        // VULNERABILITY: Using large integer literals in computation
        let result = 1000000000 * 10;  // Could cause overflow
        account.computed_value = result;
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = payer, space = 8 + 16)]
    pub account: Account<'info, LargeIntegerAccount>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct LargeIntegerAccount {
    pub large_value: u64,
    pub computed_value: u64,
} 