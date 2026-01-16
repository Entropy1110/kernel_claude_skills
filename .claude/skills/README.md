# Mali Static AI - Claude Code Skills

This directory contains Claude Code skills for the Mali Static AI vulnerability analysis pipeline.

## Recent Improvements (2026-01-16)

Based on real-world usage issues, the following improvements have been made:

### 1. Pre-Flight Check Script
- **File**: `mali-analyze/pre-flight-check.sh`
- **Purpose**: Validate environment before running analysis
- **Checks**:
  - Existing results (avoid re-running unnecessarily)
  - Virtual environment presence
  - Python dependencies
  - Ollama server availability
  - Repository accessibility

### 2. Enhanced Skill Documentation
- **File**: `mali-analyze/skill.md`
- **Added**:
  - Step-by-step execution guide for Claude Code
  - Expected runtime estimates per phase
  - Troubleshooting for common issues
  - Output buffering warnings
  - Silent phase handling

### 3. Main Documentation Updates
- **File**: `../../CLAUDE_SKILLS.md`
- **Added**:
  - Comprehensive troubleshooting section
  - Best practices for Claude Code agents
  - Common error resolutions
  - Phase transition monitoring

## Problems Solved

### Issue 1: Missing Dependencies
**Before**: Pipeline failed with "ModuleNotFoundError: No module named 'rich'"
**After**: Pre-flight check validates dependencies, skill doc instructs to use `.venv/bin/python`

### Issue 2: Output Buffering
**Before**: Pipeline appeared to hang after indexing, no visible progress
**After**:
- Documentation explains silent phases are normal
- Recommends `-u` flag for unbuffered output
- Provides phase duration estimates
- Suggests monitoring checkpoint database

### Issue 3: Redundant Execution
**Before**: No check for existing results, wasted time re-running analysis
**After**:
- Pre-flight check warns about existing reports
- Skill doc mandates checking `out/` directory first
- Shows timestamps and prompts user to review existing results

### Issue 4: Unclear Expected Behavior
**Before**: Unclear if pipeline was working during silent phases
**After**:
- Expected runtime: 5-45 minutes documented
- Phase-by-phase timing provided
- Process verification commands included
- Background task monitoring guidance

## Usage for Claude Code Agents

When `/mali-analyze` is invoked:

1. **Check existing results**:
   ```bash
   ls -lh out/report*.md out/state.json
   ```
   If recent reports exist, offer to review them instead of re-running.

2. **Run pre-flight checks**:
   ```bash
   bash .claude/skills/mali-analyze/pre-flight-check.sh <args>
   ```
   Exit if checks fail.

3. **Execute with proper flags**:
   ```bash
   .venv/bin/python -u mali_skill_runner.py run-full-pipeline <args>
   ```
   Use `-u` for unbuffered output, run in background.

4. **Monitor progress**:
   - Check output file every 60 seconds
   - Look for phase transitions
   - Wait at least 2-3 minutes during silent phases

5. **Present results**:
   - Summarize findings from `out/report_true_positives.md`
   - Provide file paths to detailed reports
