use anchor_lang::prelude::*;

#[program]
pub mod calculator {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let calculator = &mut ctx.accounts.calculator;
        calculator.result = 0;
        Ok(())
    }

    // VULNERABILITY: No overflow checks in arithmetic operations
    pub fn add(ctx: Context<Calculate>, num: u64) -> Result<()> {
        let calculator = &mut ctx.accounts.calculator;
        calculator.result = calculator.result + num; // Vulnerable to overflow
        Ok(())
    }

    // VULNERABILITY: No overflow checks in arithmetic operations
    pub fn multiply(ctx: Context<Calculate>, num: u64) -> Result<()> {
        let calculator = &mut ctx.accounts.calculator;
        calculator.result = calculator.result * num; // Vulnerable to overflow
        Ok(())
    }

    // VULNERABILITY: No overflow checks in arithmetic operations
    pub fn subtract(ctx: Context<Calculate>, num: u64) -> Result<()> {
        let calculator = &mut ctx.accounts.calculator;
        if num > calculator.result {
            return Err(ProgramError::Custom(1).into());
        }
        calculator.result = calculator.result - num; // Still vulnerable to underflow if check is bypassed
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = user, space = 8 + 8)]
    pub calculator: Account<'info, Calculator>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Calculate<'info> {
    #[account(mut)]
    pub calculator: Account<'info, Calculator>,
    pub user: Signer<'info>,
}

#[account]
pub struct Calculator {
    pub result: u64,
}

#[error_code]
pub enum CalcError {
    #[msg("Subtraction would result in underflow")]
    Underflow,
} 