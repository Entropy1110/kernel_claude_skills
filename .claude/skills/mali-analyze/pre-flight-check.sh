#!/bin/bash
# Pre-flight check for Mali Static Analysis
# This script should be run by Claude Code before starting analysis

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Parse --force flag
FORCE=false
for arg in "$@"; do
    if [ "$arg" = "--force" ]; then
        FORCE=true
    fi
done

echo "=== Mali Static Analysis Pre-Flight Check ==="
echo ""

# Check 1: Existing results
echo "[1/5] Checking for existing results..."
if [ -f "$PROJECT_ROOT/out/report.md" ]; then
    REPORT_AGE=$(find "$PROJECT_ROOT/out/report.md" -mtime -1 2>/dev/null || echo "old")
    if [ "$REPORT_AGE" != "old" ]; then
        echo "✓ Recent report found (less than 24 hours old)"
        echo "  Location: out/report.md"
        if [ "$FORCE" = true ]; then
            echo "  --force specified, continuing anyway"
        else
            echo "  Use --force to skip this check, or review existing reports in out/"
            exit 0
        fi
    else
        echo "✓ Old report found, will be overwritten"
    fi
else
    echo "✓ No existing report found"
fi
echo ""

# Check 2: Virtual environment
echo "[2/5] Checking virtual environment..."
if [ -f "$PROJECT_ROOT/.venv/bin/python" ]; then
    PYTHON_PATH="$PROJECT_ROOT/.venv/bin/python"
    echo "✓ Virtual environment found"
    echo "  Python: $PYTHON_PATH"
else
    echo "✗ Virtual environment not found at .venv/"
    echo "  Run: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
    exit 1
fi
echo ""

# Check 3: Dependencies
echo "[3/5] Checking Python dependencies..."
if $PYTHON_PATH -c "import rich, langchain_ollama, langchain_anthropic" 2>/dev/null; then
    echo "✓ Core dependencies installed"
else
    echo "✗ Missing dependencies"
    echo "  Run: .venv/bin/pip install -r requirements.txt"
    exit 1
fi
echo ""

# Check 4: Ollama availability
echo "[4/5] Checking Ollama server..."
if curl -s --max-time 2 http://localhost:11434/api/tags >/dev/null 2>&1; then
    MODEL=$(curl -s http://localhost:11434/api/tags | python3 -c "import sys, json; data=json.load(sys.stdin); print(data['models'][0]['name'] if data.get('models') else 'none')" 2>/dev/null || echo "unknown")
    echo "✓ Ollama is running"
    echo "  Model: $MODEL"
else
    echo "⚠ Ollama not responding (http://localhost:11434)"
    echo "  Local triage will fail. Ensure Ollama is running or use OpenRouter-only mode."
fi
echo ""

# Check 5: Repository access
echo "[5/5] Checking repository access..."
REPO_ARG=""
for arg in "$@"; do
    case "$arg" in
        --repo=*)
            REPO_ARG="${arg#--repo=}"
            ;;
    esac
done
if [ -n "$REPO_ARG" ]; then
    REPO_PATH=$(eval echo "$REPO_ARG")  # Expand ~ if present
    if [ -d "$REPO_PATH" ]; then
        echo "✓ Repository accessible: $REPO_PATH"
    else
        echo "✗ Repository not found: $REPO_PATH"
        exit 1
    fi
else
    echo "⚠ No --repo argument provided, skipping check"
fi
echo ""

echo "=== Pre-Flight Check Complete ==="
echo ""
echo "Ready to run: .venv/bin/python mali_skill_runner.py run-full-pipeline $@"
echo ""
