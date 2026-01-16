# Mali Static Analysis (Full Pipeline)

Run complete vulnerability analysis on Linux kernel or user-space C/C++ code.

## Description

This skill performs comprehensive static vulnerability analysis:
1. **Index**: Build tree-sitter AST index of source files
2. **Map**: Extract framework entrypoints (ioctl, file_ops, etc.)
3. **Select**: Score and rank candidates by vulnerability potential
4. **Triage**: Quick screening to identify high-priority targets
5. **Deep Dive**: In-depth analysis with structured reasoning
6. **Classify**: Explicit TP/FP classification with confidence scores
7. **Report**: Generate markdown reports

## Execution Guide for Claude Code

**IMPORTANT**: When this skill is invoked, follow these steps in order:

### Step 1: Check for Existing Results (ALWAYS DO THIS FIRST)
```bash
ls -lh out/report*.md out/state.json 2>/dev/null
```
- If recent reports exist, show timestamps and ask user if they want to review them instead
- Existing reports may already contain the analysis, saving 5-45 minutes

### Step 2: Ask User for Run Configuration (MANDATORY)

**You MUST ask the user these questions using AskUserQuestion before proceeding:**

#### Question 1: Target Selection (if not provided in command)
Ask: "What target should I analyze?"
Options:
- "Use configured default" - Uses `default_repo` from `.claude/config/mali-config.json` if set
- "Custom target" - User provides custom --repo, --scope, and --framework

**Note:** If user selects "Use configured default", check `.claude/config/mali-config.json` for `default_repo` and `default_scope`. If not set, ask user to provide the paths.

#### Question 2: Model Mode (ALWAYS ASK)
Ask: "Which model mode should I use for analysis?"
Options:
- "Claude Code (Recommended)" - Pipeline finds candidates, then YOU analyze source code and write findings
- "Hybrid" - Ollama triages candidates, OpenRouter does deep analysis, you review results
- "Local only" - Ollama does all analysis locally (no API costs), you review results
- "OpenRouter only" - OpenRouter API does all analysis, you review results

#### Question 3: Framework (if custom target selected)
Ask: "What type of code is this?"
Options:
- "Mali GPU driver (kbase/midgard)" - `--framework=mali`
- "DRM/GPU driver (panthor, etc.)" - `--framework=drm`
- "Generic kernel subsystem" - `--framework=generic`
- "User-space application" - `--framework=application`

**Example AskUserQuestion call:**
```
Use AskUserQuestion with:
- Question: "Which model mode should I use for analysis?"
- Header: "Model Mode"
- Options:
  - Label: "Claude Code (Recommended)", Description: "Claude Code handles all analysis directly"
  - Label: "Hybrid", Description: "Local Ollama for triage + OpenRouter for deep analysis"
  - Label: "Local only", Description: "Ollama only, no external API calls"
  - Label: "OpenRouter only", Description: "OpenRouter API only"
```

### Step 3: Run Pre-Flight Checks
```bash
bash .claude/skills/mali-analyze/pre-flight-check.sh --force --repo=<repo> --scope=<scope>
```
- Use `--force` to skip the existing report check (you already asked the user in Step 1)
- Verifies: virtual environment, dependencies, Ollama server, repository access
- If this fails, DO NOT proceed with analysis

### Step 4: Apply Model Mode Configuration

**Based on user's model mode selection, update the config file:**

Use the Edit tool to modify `.claude/config/mali-config.json`:
- Change `"mode": "..."` to the selected mode value

Mode values:
- "Claude Code" → `"mode": "claude_code"`
- "Hybrid" → `"mode": "hybrid"`
- "Local only" → `"mode": "local_only"`
- "OpenRouter only" → `"mode": "openrouter_only"`

### Step 5: Execute Pipeline

```bash
.venv/bin/python -u mali_skill_runner.py run-full-pipeline --repo=<repo> --scope=<scope> --framework=<framework>
```

- Use `-u` for unbuffered output to see real-time progress
- Run with 600000ms (10 min) timeout
- Inform user: "Pipeline started. Expected runtime: 5-45 minutes depending on code size."

Optional: Add `--test` flag if user requests test mode (top 3 candidates only)

### Step 6: Monitor Progress
- Check output file every 60 seconds for phase updates
- Phases: build_ts_index → map_surface → select_candidates → local_triage → deep_dive → classify_findings → write_report
- If pipeline appears stuck after "build_ts_index", wait at least 2-3 minutes (map_surface can be slow)

### Step 7: Claude Code Mode - Perform Deep Analysis (CRITICAL)

**If "Claude Code" mode was selected, the pipeline only identifies candidates - YOU must perform the actual vulnerability analysis.**

The pipeline outputs `out/state.json` containing:
- `candidates`: List of scored functions with reachability paths and guards
- `findings`: Placeholder entries marked "Requires Claude Code analysis"

**You must now:**

1. **Read the state.json** to get the top candidates:
   ```bash
   .venv/bin/python -c "import json; state=json.load(open('out/state.json')); [print(f'{c[\"name\"]} (score: {c.get(\"score\")})') for c in state['candidates'][:10]]"
   ```

2. **Read the source files** for each top candidate (typically top 5-10 by score)

3. **Analyze each candidate** for vulnerabilities:
   - Integer overflows in size/count calculations
   - Use-after-free / double-free conditions
   - TOCTOU race conditions
   - Missing bounds checks on user input
   - Reference counting errors
   - Lock ordering issues

4. **Classify each finding** as:
   - **True Positive**: Real vulnerability with exploitation path
   - **False Positive**: Safe due to guards, framework guarantees, or infeasible path
   - **Needs Review**: Uncertain, requires manual expert review

5. **Write the final report** to `out/report_true_positives.md` with:
   - Executive summary
   - Each finding with: location, code snippet, analysis, reachability path, confidence score
   - False positive explanations
   - Defensive coding observations

### Step 8: Present Results
Once complete:
```bash
cat out/report_true_positives.md
```
- Summarize: total findings, true positives, false positives, uncertain
- Highlight HIGH/CRITICAL risk items
- Provide paths to all report files

## Usage

```
/mali-analyze --repo=/path/to/repo --scope=drivers/gpu/drm/panthor --framework=drm
```

### Examples

Analyze DRM GPU driver:
```
/mali-analyze --repo=/path/to/linux --scope=drivers/gpu/drm/panthor --framework=drm
```

Analyze user-space application:
```
/mali-analyze --repo=/path/to/app --scope=src --framework=application
```

Test mode (top 3 candidates only):
```
/mali-analyze --repo=/path/to/linux --scope=drivers/gpu/drm/panthor --framework=drm --test
```

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `--repo` | Yes | - | Path to repository |
| `--scope` | Yes | - | Directory to analyze (relative to repo) |
| `--framework` | No | `drm` | Framework: `drm`, `generic`, `application` |
| `--test` | No | false | Test mode: analyze top 3 candidates only |

## Frameworks

- **mali**: Mali GPU drivers (kbase/midgard/bifrost/valhall) - kbase_api handlers, CSF queues, GPU memory regions
- **drm**: DRM/GPU drivers (panthor, etc.) - DRM lifecycle, ioctl handlers, GEM objects
- **generic**: Generic kernel subsystems - ext4, netdev, etc.
- **application**: User-space C/C++ applications - CWE patterns

## Output

Reports generated in `out/`:
- `report.md` - All findings with detailed analysis
- `report_true_positives.md` - Validated true positives only
- `state.json` - Complete analysis state

## Important Notes

### Before Running

1. **Check for existing results first**:
   ```bash
   ls -lh out/
   # If reports exist and are recent, review them instead of re-running
   ```

2. **Ensure virtual environment is activated**:
   ```bash
   source .venv/bin/activate  # or use .venv/bin/python directly
   ```

3. **Verify Ollama is running** (for local triage):
   ```bash
   curl -s http://localhost:11434/api/tags | jq .
   ```

4. **Expected runtime**:
   - Small drivers (< 25 files): 5-15 minutes
   - Medium drivers (25-100 files): 15-45 minutes
   - Large subsystems (> 100 files): 45+ minutes

### During Execution

- **Output buffering**: Progress may not appear in real-time. The pipeline is still working.
- **Phases**: Index (1-2 min) → Map (1-2 min) → Select (2-3 min) → Triage (5-10 min) → Deep Dive (5-20 min) → Classify (2-5 min) → Report (< 1 min)
- **Silent periods**: The map_surface and local_triage phases may appear silent while processing

### Troubleshooting

**Pipeline hangs after indexing:**
- This is normal - map_surface uses ripgrep which may take time on large repos
- Check process is running: `ps aux | grep mali`
- For large repos, consider narrowing the scope

**Missing dependencies:**
- Always use `.venv/bin/python` or activate the virtualenv first
- Install missing deps: `.venv/bin/pip install -r requirements.txt`

**Out of memory:**
- Use `--test` mode to analyze only top 3 candidates
- Narrow the `--scope` to specific subdirectories

## Mode Configuration

Configure mode in `.claude/config/mali-config.json`:

| Mode | Pipeline Does | You (Claude Code) Do |
|------|--------------|---------------------|
| `claude_code` | Index, map entrypoints, score candidates, extract guards/paths | **All vulnerability analysis and report writing** |
| `hybrid` | Index, map, score, **Ollama triage**, **OpenRouter deep dive** | Review and present results |
| `local_only` | Index, map, score, **Ollama triage + deep dive** | Review and present results |
| `openrouter_only` | Index, map, score, **OpenRouter triage + deep dive** | Review and present results |

**Key difference:** In `claude_code` mode, the pipeline is just a candidate discovery tool. You must read the source code and perform the actual security analysis yourself. In other modes, LLMs in the pipeline do the analysis.
