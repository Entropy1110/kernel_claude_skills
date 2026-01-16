# Mali Static AI - Claude Code Skills

Developer guide for Mali Static AI Claude Code skills.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Claude Code                          │
│  /mali-analyze  /mali-map  /mali-triage  /mali-report   │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│              mali_skill_runner.py                        │
│   SkillRunner  │  StateManager  │  CostTracker          │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│              mali_static_ai.py                           │
│           LangGraph Pipeline (11 nodes)                  │
└─────────────────────────────────────────────────────────┘
```

## Skills

| Skill | Nodes | Description |
|-------|-------|-------------|
| `/mali-analyze` | All | Full pipeline |
| `/mali-map` | build_ts_index, map_surface, select_candidates, enrich_candidates | Surface mapping |
| `/mali-triage` | local_triage | Quick screening |
| `/mali-deep-dive` | deep_dive, self_critique | Deep analysis |
| `/mali-classify` | classify_findings, false_positive_classifier | Classification |
| `/mali-followup` | iterative_followup | Iterative analysis |
| `/mali-report` | write_report | Report generation |

## Modes

Configure in `.claude/config/mali-config.json`:

### `claude_code` (Default)
Claude Code handles all analysis directly. No external API calls.

### `hybrid`
- Triage: Local Ollama
- Deep analysis: OpenRouter/Claude

### `local_only`
All stages use local Ollama.

### `openrouter_only`
All stages use OpenRouter API.

## Adding a New Skill

1. Create `.claude/skills/<skill-name>/skill.md`
2. Add to `SKILL_DEFINITIONS` in `mali_skill_runner.py`
3. Implement nodes in `mali_static_ai.py` if needed

### skill.md Template

```markdown
# Skill Name

Description.

## Usage
/skill-name --param=value

## Parameters
| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|

## Output
What the skill produces.
```

## State Schema

```python
class ScanState(TypedDict):
    repo: str
    scope: str
    framework: str
    candidates: list[dict]
    findings: list[dict]
    tags: list[dict]
    tags_by_file: dict
    # ...
```

## Testing

```bash
# List skills
python mali_skill_runner.py list-skills

# Run skill
python mali_skill_runner.py run-skill map \
    --session-id=test \
    --repo=/path/to/code \
    --scope=src

# Full pipeline
python mali_skill_runner.py run-full-pipeline \
    --repo=/path/to/code \
    --scope=src \
    --framework=drm
```

## Troubleshooting

### Common Issues

**1. "ModuleNotFoundError: No module named 'rich'"**
- **Cause**: Not using virtual environment
- **Fix**: Use `.venv/bin/python` instead of `python3`
  ```bash
  .venv/bin/python mali_skill_runner.py <command>
  ```

**2. Pipeline hangs after "build_ts_index: Extracted X tags"**
- **Cause**: map_surface phase uses ripgrep on large repos, output is buffered
- **Normal behavior**: Wait 2-3 minutes, process is still working
- **Check**: `ps aux | grep mali` to verify process is running
- **Fix**: Use `-u` flag for unbuffered output:
  ```bash
  .venv/bin/python -u mali_static_ai.py <args>
  ```

**3. "Ollama connection refused"**
- **Cause**: Ollama server not running
- **Fix**: Start Ollama or use `--no-iterative` for OpenRouter-only mode
  ```bash
  # Check Ollama
  curl http://localhost:11434/api/tags
  ```

**4. "out/report.md already exists but appears outdated"**
- **Cause**: Previous analysis completed, new run will overwrite
- **Best practice**: Check existing reports first
  ```bash
  ls -lh out/
  # Review reports before re-running
  cat out/report_true_positives.md
  ```

**5. Output buffering hides progress**
- **Cause**: Python buffers stdout when not attached to TTY
- **Fix**: Use `-u` flag or monitor checkpoint database
  ```bash
  # Unbuffered output
  .venv/bin/python -u mali_skill_runner.py run-full-pipeline <args>

  # Monitor database updates
  watch -n 5 'ls -lh checkpoints.sqlite'
  ```

### Best Practices for Claude Code

1. **Always check for existing results first**
   ```bash
   ls -lh out/report*.md
   ```

2. **Run pre-flight checks before analysis**
   ```bash
   bash .claude/skills/mali-analyze/pre-flight-check.sh <args>
   ```

3. **Use background execution for long-running tasks**
   - Set appropriate timeout (1200000ms = 20 minutes)
   - Monitor output file periodically
   - Inform user of expected runtime

4. **Handle silent phases gracefully**
   - map_surface: 1-3 minutes (ripgrep search)
   - local_triage: 5-10 minutes (Ollama inference)
   - deep_dive: 5-20 minutes (OpenRouter API calls)

5. **Report phase transitions to user**
   - Parse output for "build_ts_index:", "map_surface:", etc.
   - Update user when transitioning between major phases
