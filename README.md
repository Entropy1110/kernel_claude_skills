# Mali Static AI

Static vulnerability analysis pipeline for Linux kernel drivers and C/C++ applications, designed to work with Claude Code.

## Quick Start

### 1. Clone and Setup

```bash
git clone <repository-url>
cd mali-static-ai
./setup.sh
```

The setup script installs:
- Python virtual environment with dependencies
- Tree-sitter CLI and C grammar
- Directory structure for analysis outputs

### 2. Configure Your Targets

Edit `.claude/config/mali-config.json` to set your analysis targets:

```json
{
  "targets": {
    "default_repo": "/path/to/your/linux/kernel",
    "default_scope": "drivers/gpu/drm/your-driver",
    "default_framework": "drm"
  }
}
```

Or copy from the template:
```bash
cp .claude/config/mali-config.json.template .claude/config/mali-config.json
# Edit the file with your paths
```

### 3. Run Analysis

With Claude Code:
```
/mali-analyze
```

Or specify targets directly:
```
/mali-analyze --repo=/path/to/linux --scope=drivers/gpu/drm/panthor --framework=drm
```

## Analysis Modes

| Mode | Description | Requirements |
|------|-------------|--------------|
| `claude_code` | Claude Code performs all analysis (recommended) | Claude Code only |
| `hybrid` | Ollama triages, OpenRouter does deep analysis | Ollama + OpenRouter API key |
| `local_only` | Ollama handles everything locally | Ollama with qwen2.5-coder:32b |
| `openrouter_only` | OpenRouter API for all stages | OpenRouter API key |

Set mode in `.claude/config/mali-config.json`:
```json
{
  "mode": "claude_code"
}
```

## Framework Options

- **drm**: DRM/GPU drivers (panthor, mali, amdgpu, etc.)
- **generic**: Generic kernel subsystems (ext4, netdev, etc.)
- **application**: User-space C/C++ applications

## Output

Reports are generated in `out/`:
- `report_<timestamp>.md` - Full analysis with all findings
- `report_true_positives_<timestamp>.md` - Validated vulnerabilities only
- `state_<timestamp>.json` - Complete analysis state

Symlinks (`report.md`, `report_true_positives.md`, `state.json`) point to the latest run.

## Project Structure

```
mali-static-ai/
├── mali_static_ai.py       # Main analysis pipeline
├── mali_skill_runner.py    # CLI runner for pipeline
├── setup.sh                # One-time setup script
├── .claude/
│   ├── config/
│   │   └── mali-config.json     # Analysis configuration
│   ├── skills/
│   │   └── mali-analyze/        # Claude Code skill
│   └── state/                   # Checkpoints and logs
└── out/                         # Generated reports
```

## For Teammates

### First-Time Setup

1. Clone the repository
2. Run `./setup.sh`
3. Copy and edit the config template:
   ```bash
   cp .claude/config/mali-config.json.template .claude/config/mali-config.json
   ```
4. Set your kernel/code paths in the config file
5. (Optional) For hybrid/openrouter modes, set `OPENROUTER_API_KEY` in `.env`

### Daily Usage

1. Open Claude Code in this directory
2. Run `/mali-analyze` to start analysis
3. Claude will ask for mode selection and target confirmation
4. Results appear in `out/` directory

### Sharing Analysis Results

Reports are self-contained markdown files. Share `out/report_true_positives_<timestamp>.md` with the team.

## Troubleshooting

**Pipeline appears stuck:**
- Silent phases (map_surface, local_triage) can take 2-5 minutes
- Check process: `ps aux | grep mali`

**Missing dependencies:**
- Always use `.venv/bin/python` or run `source .venv/bin/activate`
- Re-run: `.venv/bin/pip install -r requirements.txt`

**Ollama not responding (hybrid/local modes):**
- Start server: `ollama serve`
- Check model: `ollama list | grep qwen2.5-coder`
- Pull model: `ollama pull qwen2.5-coder:32b`
