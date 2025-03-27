#!/bin/bash

# Function to count occurrences of patterns in the codebase
function count_occurrences() {
    local pattern=$1
    local directory=$2
    grep -r "$pattern" "$directory" --include="*.rs" | wc -l
}

# Colors for output
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if a directory was provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <path_to_solana_project>"
    exit 1
fi

PROJECT_DIR=$1
echo -e "${BLUE}Checking for bump seed canonicalization issues in $PROJECT_DIR${NC}"
echo "=============================================================="

# Count potentially risky patterns
CREATE_PROGRAM_ADDRESS_COUNT=$(count_occurrences "create_program_address" "$PROJECT_DIR")
FIND_PROGRAM_ADDRESS_COUNT=$(count_occurrences "find_program_address" "$PROJECT_DIR")
USER_BUMP_PARAMS=$(grep -r "pub fn .*(.*bump: *u8" "$PROJECT_DIR" --include="*.rs" | wc -l)
HARDCODED_BUMPS=$(grep -r "bump *= *[0-9]" "$PROJECT_DIR" --include="*.rs" | wc -l)
SEEDS_WITHOUT_BUMP=$(grep -r "seeds *= *\[" "$PROJECT_DIR" --include="*.rs" | grep -v "bump" | wc -l)
STORED_BUMP_USAGE=$(grep -r "bump = .*.bump" "$PROJECT_DIR" --include="*.rs" | wc -l)

# Function to detect if a user-provided bump is used without validation
function check_unvalidated_bumps() {
    echo "Checking files for unvalidated user-provided bumps..."
    
    # Find functions that take a bump parameter
    grep -r "pub fn .*(.*bump: *u8" "$PROJECT_DIR" --include="*.rs" | while read -r line; do
        file=$(echo "$line" | cut -d':' -f1)
        func_name=$(echo "$line" | grep -oP "pub fn \K[a-zA-Z0-9_]+")
        
        echo "  Checking function $func_name in $file"
        
        # Check if the function uses create_program_address
        if grep -A 30 "pub fn $func_name" "$file" | grep -q "create_program_address"; then
            # Check if it also uses find_program_address for validation
            if ! grep -A 30 "pub fn $func_name" "$file" | grep -q "find_program_address"; then
                echo -e "    ${RED}CRITICAL: Function $func_name uses create_program_address with user-provided bump without validation${NC}"
                echo -e "    ${YELLOW}This could lead to security exploits if multiple PDAs can be derived for the same seeds${NC}"
                
                # Extract the vulnerability context
                echo -e "    ${BLUE}Code context:${NC}"
                grep -A 10 "pub fn $func_name" "$file" | head -15 | sed 's/^/      /'
            else
                # Check if the function actually validates the user bump against canonical bump
                if grep -A 30 "pub fn $func_name" "$file" | grep -q "expected_bump.*==.*bump"; then
                    echo -e "    ${GREEN}✓ Function $func_name properly validates the user-provided bump against canonical bump${NC}"
                else
                    echo -e "    ${YELLOW}WARNING: Function $func_name uses find_program_address but might not validate user bump against canonical bump${NC}"
                fi
            fi
        fi
    done
}

# Function to detect hardcoded bumps
function check_hardcoded_bumps() {
    echo "Checking for hardcoded bump values..."
    
    grep -r "bump *= *[0-9]" "$PROJECT_DIR" --include="*.rs" | while read -r line; do
        file=$(echo "$line" | cut -d':' -f1)
        line_content=$(echo "$line" | cut -d':' -f2-)
        
        # Check if this is in a test file
        if [[ "$file" == *"test"* ]]; then
            echo -e "  ${BLUE}INFO: Hardcoded bump in test file (acceptable): $file${NC}"
            continue
        fi
        
        # Try to extract the function this is in
        func_name=$(grep -B 10 -A 0 "$line_content" "$file" | grep -oP "pub fn \K[a-zA-Z0-9_]+" | tail -1)
        
        if [[ -n "$func_name" ]]; then
            echo -e "  ${RED}CRITICAL: Hardcoded bump value in function $func_name in $file${NC}"
            echo -e "  ${BLUE}Code context:${NC}"
            grep -B 5 -A 5 "$line_content" "$file" | sed 's/^/    /'
        else
            echo -e "  ${RED}CRITICAL: Hardcoded bump value in $file${NC}"
            echo -e "  ${BLUE}Code context:${NC}"
            grep -B 5 -A 5 "$line_content" "$file" | sed 's/^/    /'
        fi
    done
}

# Function to check for proper bump storage
function check_bump_storage() {
    echo "Checking for proper bump storage practices..."
    
    # Check for functions that initialize PDAs
    grep -r "#\[account(.*init.*seeds" "$PROJECT_DIR" --include="*.rs" | while read -r line; do
        file=$(echo "$line" | cut -d':' -f1)
        
        # Check if the struct stores the bump
        struct_name=$(echo "$line" | grep -oP "pub \K[a-zA-Z0-9_]+" | tail -1)
        
        if [[ -n "$struct_name" ]]; then
            # Look for bump field in account struct
            if grep -A 20 "struct $struct_name" "$file" | grep -q "bump: *u8"; then
                echo -e "  ${GREEN}✓ Account struct $struct_name properly stores bump in $file${NC}"
            else
                echo -e "  ${YELLOW}WARNING: Account struct $struct_name may not store bump seed in $file${NC}"
                echo -e "  ${BLUE}Consider adding 'pub bump: u8' field to store canonical bump for future validation${NC}"
            fi
        fi
    done
}

echo -e "${BLUE}Potential Risk Indicators:${NC}"
echo -e "${BLUE}-------------------------${NC}"
echo "create_program_address calls: $CREATE_PROGRAM_ADDRESS_COUNT"
echo "find_program_address calls: $FIND_PROGRAM_ADDRESS_COUNT"
echo "Functions with bump parameters: $USER_BUMP_PARAMS"
echo "Hardcoded bump values: $HARDCODED_BUMPS"
echo "Seeds constraints without bump: $SEEDS_WITHOUT_BUMP"
echo "Stored bump usage: $STORED_BUMP_USAGE"
echo ""

# Check for common vulnerability patterns
echo -e "${BLUE}Detailed Vulnerability Analysis:${NC}"
echo -e "${BLUE}------------------------------${NC}"

# Pattern 1: create_program_address is used without find_program_address validation
if [ "$CREATE_PROGRAM_ADDRESS_COUNT" -gt 0 ] && [ "$FIND_PROGRAM_ADDRESS_COUNT" -eq 0 ]; then
    echo -e "${RED}CRITICAL: create_program_address is used without find_program_address for canonical bump${NC}"
elif [ "$CREATE_PROGRAM_ADDRESS_COUNT" -gt "$FIND_PROGRAM_ADDRESS_COUNT" ]; then
    echo -e "${YELLOW}WARNING: More create_program_address calls than find_program_address calls${NC}"
fi

# Pattern 2: Functions with bump parameters
if [ "$USER_BUMP_PARAMS" -gt 0 ]; then
    echo -e "${YELLOW}WARNING: Functions accepting bump parameters may be vulnerable if not validated${NC}"
    check_unvalidated_bumps
fi

# Pattern 3: Hardcoded bump values
if [ "$HARDCODED_BUMPS" -gt 0 ]; then
    check_hardcoded_bumps
fi

# Pattern 4: Seeds without bump
if [ "$SEEDS_WITHOUT_BUMP" -gt 0 ]; then
    echo -e "${YELLOW}WARNING: Seeds constraints without bump constraints detected${NC}"
fi

# Check for proper bump storage
check_bump_storage

# Provide recommendations
echo ""
echo -e "${GREEN}Recommendations:${NC}"
echo -e "${GREEN}--------------${NC}"
echo "1. Always use find_program_address() to get the canonical bump instead of create_program_address()"
echo "2. Never trust user-provided bump parameters without validation against the canonical bump"
echo "3. Store canonical bumps in account data for future reference"
echo "4. With Anchor, use the 'bump' constraint without a value to get the canonical bump"
echo "5. With Anchor, use 'bump = account.bump' to use a stored canonical bump"

# Final assessment
echo ""
echo -e "${BLUE}Final Assessment:${NC}"
if [ "$CREATE_PROGRAM_ADDRESS_COUNT" -gt 0 ] && [ "$FIND_PROGRAM_ADDRESS_COUNT" -eq 0 ] || [ "$USER_BUMP_PARAMS" -gt 0 ] || [ "$HARDCODED_BUMPS" -gt 0 ]; then
    echo -e "${RED}HIGH RISK: This program likely has bump seed canonicalization vulnerabilities${NC}"
    echo -e "${RED}Please address the identified issues to prevent potential exploits${NC}"
elif [ "$CREATE_PROGRAM_ADDRESS_COUNT" -gt "$FIND_PROGRAM_ADDRESS_COUNT" ] || [ "$SEEDS_WITHOUT_BUMP" -gt 0 ]; then
    echo -e "${YELLOW}MEDIUM RISK: This program has some bump seed canonicalization concerns${NC}"
    echo -e "${YELLOW}Follow the recommendations to improve security${NC}"
else
    echo -e "${GREEN}LOW RISK: No significant bump seed canonicalization issues detected${NC}"
    echo -e "${GREEN}Continue to follow best practices for PDA derivation${NC}" 