use anchor_lang::prelude::*;

#[program]
pub mod pda_test {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, bump: u8) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        
        // VULNERABILITY: Using user-supplied bump instead of the bump found by find_program_address
        vault.bump = bump;
        
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &ctx.accounts.vault;
        
        // VULNERABILITY: Using attacker-controlled bump in the seeds
        let seeds = &[
            b"vault".as_ref(),
            ctx.accounts.authority.key.as_ref(),
            &[vault.bump], // Using potentially manipulated bump
        ];
        
        // Create the signer for the PDA with the stored bump
        let signer = &[&seeds[..]];
        
        // Transfer tokens from the vault
        anchor_lang::solana_program::program::invoke_signed(
            &anchor_lang::solana_program::system_instruction::transfer(
                ctx.accounts.vault_account.key,
                ctx.accounts.receiver.key,
                amount,
            ),
            &[
                ctx.accounts.vault_account.to_account_info(),
                ctx.accounts.receiver.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
            signer,
        )?;
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 1,
        seeds = [b"vault", authority.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
    
    // Account that will hold funds
    /// CHECK: This is a raw account that will be controlled by the PDA
    #[account(
        mut,
        seeds = [b"vault", authority.key().as_ref()],
        bump,
    )]
    pub vault_account: AccountInfo<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub authority: Signer<'info>,
    
    #[account(
        constraint = vault.authority == authority.key(),
    )]
    pub vault: Account<'info, Vault>,
    
    /// CHECK: This is a raw account that's controlled by the PDA
    #[account(
        mut,
        seeds = [b"vault", authority.key().as_ref()],
        bump = vault.bump, // VULNERABILITY: Using stored bump instead of canonical bump
    )]
    pub vault_account: AccountInfo<'info>,
    
    /// CHECK: This is the receiver's account
    #[account(mut)]
    pub receiver: AccountInfo<'info>,
    
    pub system_program: Program<'info, System>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub bump: u8,
} 