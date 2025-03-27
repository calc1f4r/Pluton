use anchor_lang::prelude::*;
use anchor_spl::token::{Token, TokenAccount, Mint};
use anchor_spl::associated_token::AssociatedToken;

#[program]
pub mod ata_example {
    use super::*;
    
    // Insecure: Uses 'init' instead of 'init_if_needed' for ATA
    pub fn initialize_ata_insecure(ctx: Context<InitializeATAInsecure>) -> Result<()> {
        msg!("Initialized a new ATA insecurely");
        Ok(())
    }
    
    // Secure: Uses 'init_if_needed' for ATA
    pub fn initialize_ata_secure(ctx: Context<InitializeATASecure>) -> Result<()> {
        msg!("Initialized a new ATA securely");
        Ok(())
    }
}

// Insecure: Uses 'init' which will fail if the ATA already exists
#[derive(Accounts)]
pub struct InitializeATAInsecure<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    
    pub mint: Account<'info, Mint>,
    
    #[account(
        init,
        payer = payer,
        associated_token::mint = mint,
        associated_token::authority = payer
    )]
    pub token_account: Account<'info, TokenAccount>,
    
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

// Secure: Uses 'init_if_needed' which handles both new and existing ATAs
#[derive(Accounts)]
pub struct InitializeATASecure<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    
    pub mint: Account<'info, Mint>,
    
    #[account(
        init_if_needed,
        payer = payer,
        associated_token::mint = mint,
        associated_token::authority = payer
    )]
    pub token_account: Account<'info, TokenAccount>,
    
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

// Another example with a field name that clearly indicates an ATA
#[derive(Accounts)]
pub struct ExplicitATA<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    
    pub mint: Account<'info, Mint>,
    
    #[account(
        init, // Using init instead of init_if_needed (vulnerable)
        payer = payer,
        associated_token::mint = mint,
        associated_token::authority = payer
    )]
    pub ata: Account<'info, TokenAccount>,
    
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
} 