---
name: contract-hunting
description: "Hunt EVM contract vulnerabilities for bounties. Use when user mentions bounty, vulnerability, contract audit, or Scout."
---

# Contract Hunting Workflow

## Process: Radar → Surface → Prove → Report

### 1. Radar (find targets)
- Run `/hunt radar immunefi 10` to pull top bounty programs
- Focus on programs with highest payouts and recent activity
- Filter for contracts with accessible source code

### 2. Surface (understand the target)
- Run `/hunt surface <id>` to fetch contract source, ABI, metadata
- Read the contract code carefully
- Identify external calls, state changes, access controls

### 3. Hypothesize
- Form a vulnerability hypothesis based on code review
- Common patterns: reentrancy, access control bypass, oracle manipulation, flash loan attacks
- Use `/hunt prove <id> "hypothesis description"`

### 4. Prove (validate on fork)
- Scout forks the chain locally with Anvil
- Executes the exploit transaction
- Confirms the vulnerability is real and exploitable

### 5. Report
- Run `/hunt report <id>` to generate a professional report
- Include: vulnerability description, impact, proof of concept, remediation
- Submit to the bounty program

## Tips
- Always check if the contract is already audited
- Focus on high-value targets (>$10K bounties)
- Test hypotheses before reporting
- Keep findings private until reported
