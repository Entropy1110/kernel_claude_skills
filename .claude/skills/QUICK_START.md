# Mali Static Analysis - Quick Start Guide

## TL;DR

```bash
# 1. Check if analysis already exists
ls -lh out/report*.md

# 2. If not, run analysis
.venv/bin/python -u mali_skill_runner.py run-full-pipeline \
    --repo=~/linux \
    --scope=drivers/gpu/drm/panthor \
    --framework=drm

# 3. View results
cat out/report_true_positives.md
```

## Pre-Flight Checklist

- [ ] Virtual environment exists: `.venv/bin/python`
- [ ] Ollama running: `curl http://localhost:11434/api/tags`
- [ ] No existing recent reports: `ls -lh out/`
- [ ] Repository accessible: `ls ~/linux/drivers/gpu/drm/panthor`

## Expected Timeline

| Phase | Duration | What's Happening |
|-------|----------|------------------|
| Index | 1-2 min | tree-sitter AST parsing |
| Map | 1-3 min | ripgrep searching for entry points |
| Select | 2-3 min | Scoring and ranking candidates |
| Triage | 5-10 min | Local Ollama screening |
| Deep Dive | 5-20 min | Claude/OpenRouter analysis |
| Classify | 2-5 min | TP/FP classification |
| Report | <1 min | Markdown generation |
| **Total** | **15-45 min** | Depends on code size |

## Common Commands

```bash
# Check for existing results
ls -lh out/

# Run pre-flight check
bash .claude/skills/mali-analyze/pre-flight-check.sh --repo=~/linux --scope=drivers/gpu/drm/panthor

# Full pipeline (unbuffered output)
.venv/bin/python -u mali_skill_runner.py run-full-pipeline \
    --repo=~/linux \
    --scope=drivers/gpu/drm/panthor \
    --framework=drm

# Test mode (top 3 candidates only, faster)
.venv/bin/python -u mali_skill_runner.py run-full-pipeline \
    --repo=~/linux \
    --scope=drivers/gpu/drm/panthor \
    --framework=drm \
    --test

# View true positives only
cat out/report_true_positives.md

# View all findings
cat out/report.md

# Check analysis state
jq '.findings | length' out/state.json
```

## Troubleshooting One-Liners

```bash
# "ModuleNotFoundError" → Use venv
.venv/bin/python instead of python3

# "Pipeline hangs" → Check it's running
ps aux | grep mali

# "Ollama connection refused" → Start Ollama
curl http://localhost:11434/api/tags

# "Output buffered" → Use -u flag
.venv/bin/python -u <command>

# "Out of memory" → Use test mode
--test flag analyzes top 3 only
```

## Output Files

```
out/
├── report.md                    # All findings (TPs + FPs)
├── report_true_positives.md     # Filtered: TPs and uncertain only
└── state.json                   # Complete analysis state
```

## Quick Results Interpretation

```bash
# Summary line from report
grep "^- Total findings:" out/report_true_positives.md
grep "^- \*\*Validated True Positives:" out/report_true_positives.md

# Count findings by risk
grep "^- risk: \*\*" out/report_true_positives.md | sort | uniq -c

# List high/critical risk
grep -A 3 "risk: \*\*high\|risk: \*\*critical" out/report_true_positives.md
```
