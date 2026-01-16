#!/bin/bash
# Mali Static AI - Setup Script
# Sets up tree-sitter, Python dependencies, and Claude Code skills

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

echo "============================================"
echo "  Mali Static AI - Setup"
echo "============================================"
echo

# Detect OS
OS="$(uname -s)"
ARCH="$(uname -m)"
info "Detected OS: $OS ($ARCH)"

# --------------------------------------------
# 1. Check Python
# --------------------------------------------
info "Checking Python..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)
    if [ "$PYTHON_MAJOR" -ge 3 ] && [ "$PYTHON_MINOR" -ge 10 ]; then
        success "Python $PYTHON_VERSION found"
    else
        error "Python 3.10+ required, found $PYTHON_VERSION"
    fi
else
    error "Python3 not found. Please install Python 3.10+"
fi

# --------------------------------------------
# 2. Install tree-sitter CLI
# --------------------------------------------
info "Checking tree-sitter CLI..."
if command -v tree-sitter &> /dev/null; then
    TS_VERSION=$(tree-sitter --version 2>&1 | head -1)
    success "tree-sitter already installed: $TS_VERSION"
else
    info "tree-sitter CLI not found, installing..."

    # Try cargo first (preferred)
    if command -v cargo &> /dev/null; then
        info "Installing via cargo..."
        cargo install tree-sitter-cli
        success "tree-sitter installed via cargo"
    # Try npm
    elif command -v npm &> /dev/null; then
        info "Installing via npm..."
        npm install -g tree-sitter-cli
        success "tree-sitter installed via npm"
    # Try homebrew on macOS
    elif [ "$OS" = "Darwin" ] && command -v brew &> /dev/null; then
        info "Installing via homebrew..."
        brew install tree-sitter
        success "tree-sitter installed via homebrew"
    else
        error "Cannot install tree-sitter. Please install one of: cargo, npm, or homebrew"
    fi
fi

# Verify tree-sitter is in PATH
if ! command -v tree-sitter &> /dev/null; then
    warn "tree-sitter installed but not in PATH"
    if [ -f "$HOME/.cargo/bin/tree-sitter" ]; then
        info "Found at ~/.cargo/bin/tree-sitter"
        info "Add to your shell profile: export PATH=\"\$HOME/.cargo/bin:\$PATH\""
        export PATH="$HOME/.cargo/bin:$PATH"
    fi
fi

# --------------------------------------------
# 3. Setup tree-sitter C grammar
# --------------------------------------------
info "Setting up tree-sitter C grammar..."
TS_CONFIG_DIR="$HOME/.config/tree-sitter"
TS_PARSERS_DIR="$TS_CONFIG_DIR/parsers"
mkdir -p "$TS_PARSERS_DIR"

# Clone tree-sitter-c if not exists
if [ ! -d "$TS_PARSERS_DIR/tree-sitter-c" ]; then
    info "Cloning tree-sitter-c grammar..."
    git clone --depth 1 https://github.com/tree-sitter/tree-sitter-c.git "$TS_PARSERS_DIR/tree-sitter-c" 2>/dev/null
    success "Cloned tree-sitter-c"
else
    success "tree-sitter-c grammar exists"
fi

# Create tree-sitter config.json
TS_CONFIG_FILE="$TS_CONFIG_DIR/config.json"
if [ ! -f "$TS_CONFIG_FILE" ]; then
    cat > "$TS_CONFIG_FILE" << 'EOF'
{
  "parser-directories": [
    "~/.config/tree-sitter/parsers"
  ]
}
EOF
    success "Created tree-sitter config"
fi

# Build the C parser
if [ -d "$TS_PARSERS_DIR/tree-sitter-c" ]; then
    cd "$TS_PARSERS_DIR/tree-sitter-c"
    tree-sitter generate 2>/dev/null || true
    cd - > /dev/null
    success "tree-sitter C parser ready"
fi

# --------------------------------------------
# 4. Create Python virtual environment
# --------------------------------------------
info "Setting up Python virtual environment..."
if [ -d ".venv" ]; then
    success "Virtual environment already exists"
else
    python3 -m venv .venv
    success "Created virtual environment"
fi

# Activate venv
source .venv/bin/activate

# --------------------------------------------
# 5. Install Python dependencies
# --------------------------------------------
info "Installing Python dependencies..."
pip install --upgrade pip -q

# Core dependencies
pip install -q \
    python-dotenv \
    pydantic \
    pyyaml \
    rich \
    langgraph \
    langgraph-checkpoint-sqlite \
    langchain \
    langchain-core \
    langchain-ollama \
    langchain-anthropic \
    langchain-openai \
    httpx \
    tenacity

success "Python dependencies installed"

# --------------------------------------------
# 6. Setup .env file
# --------------------------------------------
info "Checking environment configuration..."
if [ -f ".env" ]; then
    success ".env file exists"
else
    info "Creating .env template..."
    cat > .env << 'EOF'
# Mali Static AI Configuration
# Mode: claude_code | hybrid | local_only | openrouter_only
MALI_MODE=claude_code

# OpenRouter API (required for hybrid/openrouter_only modes)
# Get your key from: https://openrouter.ai/keys
# OPENROUTER_API_KEY=sk-or-v1-your-key-here

# Ollama (required for hybrid/local_only modes)
# OLLAMA_BASE_URL=http://localhost:11434
# OLLAMA_MODEL=qwen2.5-coder:32b
EOF
    warn "Created .env template - edit if using hybrid/openrouter modes"
fi

# --------------------------------------------
# 7. Create directory structure
# --------------------------------------------
info "Setting up directory structure..."
mkdir -p .claude/state/mali-state
mkdir -p .claude/config
mkdir -p .claude/skills
mkdir -p out

success "Directory structure ready"

# --------------------------------------------
# 7b. Configure analysis targets
# --------------------------------------------
info "Checking analysis target configuration..."
CONFIG_FILE=".claude/config/mali-config.json"
if [ -f "$CONFIG_FILE" ]; then
    # Check if targets are configured
    if grep -q '"default_repo": ""' "$CONFIG_FILE" 2>/dev/null; then
        warn "Analysis targets not configured in $CONFIG_FILE"
        echo
        echo "  To configure your default analysis targets, edit $CONFIG_FILE:"
        echo "  - Set 'default_repo' to your Linux kernel path (e.g., /path/to/linux)"
        echo "  - Set 'default_scope' to the driver directory (e.g., drivers/gpu/drm/panthor)"
        echo "  - Or add presets for commonly analyzed targets"
        echo
    else
        success "Analysis targets configured"
    fi
else
    warn "Config file not found - it will be created on first run"
fi

# --------------------------------------------
# 8. Check Ollama (optional)
# --------------------------------------------
info "Checking Ollama (optional, for hybrid/local modes)..."
if command -v ollama &> /dev/null; then
    success "Ollama found"
    if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        success "Ollama server is running"
        if ollama list 2>/dev/null | grep -q "qwen2.5-coder"; then
            success "qwen2.5-coder model available"
        else
            warn "Recommended model 'qwen2.5-coder:32b' not found"
            info "Install with: ollama pull qwen2.5-coder:32b"
        fi
    else
        warn "Ollama installed but not running"
        info "Start with: ollama serve"
    fi
else
    warn "Ollama not installed (optional - for hybrid/local modes)"
    info "Install from: https://ollama.ai"
fi

# --------------------------------------------
# 9. Verify installation
# --------------------------------------------
echo
info "Verifying installation..."

# Test tree-sitter
if command -v tree-sitter &> /dev/null; then
    success "tree-sitter CLI: $(tree-sitter --version 2>&1 | head -1)"
else
    error "tree-sitter not in PATH"
fi

# Test Python imports
python3 -c "
from langgraph.graph import StateGraph
from langchain_ollama import ChatOllama
from pydantic import BaseModel
from rich import print
print('[green][OK][/green] Python imports working')
" 2>/dev/null || warn "Some Python imports failed"

# --------------------------------------------
# Done
# --------------------------------------------
echo
echo "============================================"
echo -e "${GREEN}  Setup Complete!${NC}"
echo "============================================"
echo
echo "Mode Configuration (.claude/config/mali-config.json):"
echo "  - claude_code : Use Claude Code only (default, no external API)"
echo "  - hybrid      : Local Ollama + OpenRouter Claude"
echo "  - local_only  : Ollama only"
echo "  - openrouter_only : OpenRouter API only"
echo
echo "Usage with Claude Code:"
echo "  /mali-analyze --repo=/path/to/linux --scope=drivers/gpu/drm/panthor"
echo "  /mali-map --repo=/path/to/code --scope=src --session-id=my-session"
echo "  /mali-triage --session-id=my-session"
echo
echo "Usage standalone (for hybrid/local/openrouter modes):"
echo "  source .venv/bin/activate"
echo "  python mali_skill_runner.py run-full-pipeline --repo=/path --scope=src"
echo
