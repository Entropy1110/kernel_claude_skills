"""
Mali Static AI - Improved Version (COMPLETE)
- Includes all original nodes
- Few-shot prompting with kernel knowledge
- Self-critique validation stage
- Rule-based false positive filtering
- Structured multi-step reasoning
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, TypedDict
import json
import os
import re
import sqlite3
import tempfile
import urllib.request
import urllib.error
import subprocess

from dotenv import load_dotenv
from pydantic import BaseModel, Field
from rich import print

from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.sqlite import SqliteSaver
from typing import Literal

from langchain_ollama import ChatOllama
from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI

# Import improved prompts
from prompts import (
    get_structured_analysis_prompt,
    get_local_triage_prompt,
    get_batch_deep_dive_prompt,
    get_framework_aware_local_triage_prompt,  # NEW
    get_framework_aware_structured_analysis_prompt,  # NEW
    get_framework_aware_batch_deep_dive_prompt,  # NEW
    SELF_CRITIQUE_PROMPT,
    apply_false_positive_filter
)

from analysis_utils import (
    SCORE_THRESHOLDS,
    build_call_graph,
    build_evidence_pack,
    build_function_index,
    extract_entrypoints,
    extract_json_blob,
    format_reachability_path,
    normalize_finding_dict,
    run_batched_llm,
    score_and_rank_candidates,
    scan_indicators,
    resolve_symbol_location,
)

from mali_llm_factory import get_factory, LLMFactory


load_dotenv()

# -------------------------
# Config
# -------------------------
LOCAL_MODEL = os.getenv("LOCAL_MODEL", "qwen3-coder:30b")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

# OpenRouter Config
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "anthropic/claude-sonnet-4")
OPENROUTER_HEAVY_MODEL = os.getenv("OPENROUTER_HEAVY_MODEL", "anthropic/claude-sonnet-4")
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

# -------------------------
# Helpers (from original)
# -------------------------
def sh(cmd: list[str], cwd: str | None = None) -> str:
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{r.stderr}")
    return r.stdout

def rg(pattern: str, root: str, globs: list[str] | None = None, max_count: int = 2000) -> list[dict]:
    cmd = ["rg", "--no-heading", "--line-number", "--color", "never", "--max-count", str(max_count), pattern]
    if globs:
        for g in globs:
            cmd += ["-g", g]
    cmd += [root]

    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode == 1:
        return []
    if r.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{r.stderr}")

    out = r.stdout
    hits = []
    for line in out.splitlines():
        m = re.match(r"^(.*?):(\d+):(.*)$", line)
        if not m:
            continue
        hits.append({"file": m.group(1), "line": int(m.group(2)), "text": m.group(3)})
    return hits

def read_snippet(path: str, line: int, radius: int = 40) -> str:
    p = Path(path)
    if not p.exists():
        return ""
    lines = p.read_text(errors="ignore").splitlines()
    lo = max(0, line - radius - 1)
    hi = min(len(lines), line + radius)
    chunk = []
    for i in range(lo, hi):
        chunk.append(f"{i+1:6d}  {lines[i]}")
    return "\n".join(chunk)

def ollama_generate(prompt: str, model: str | None = None) -> str:
    host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
    model = model or os.environ.get("OLLAMA_MODEL", "qwen3-coder:30b")

    def _http_post_json(url: str, payload: dict[str, Any], timeout: float = 300.0) -> dict[str, Any]:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))

    out = _http_post_json(f"{host}/api/generate", {"model": model, "prompt": prompt, "stream": False}, timeout=600.0)
    return out.get("response", "")

def git_ls_files(repo: str, scope: str) -> list[str]:
    """List source files in scope. Uses git if available, falls back to find."""
    repo_p = Path(repo)
    scope_p = repo_p / scope

    # Check if this is a git repository
    git_dir = repo_p / ".git"
    if git_dir.exists():
        cmd = ["git", "-C", repo, "ls-files", scope]
        try:
            r = sh(cmd)
            files = []
            for line in r.splitlines():
                line = line.strip()
                if not line:
                    continue
                if re.search(r"\.(c|h|cc|cpp)$", line):
                    files.append(line)
            return files
        except RuntimeError:
            pass  # Fall through to find-based approach

    # Non-git repository: use find
    print(f"[yellow]git_ls_files:[/yellow] Not a git repo, using find instead")
    if not scope_p.exists():
        print(f"[red]git_ls_files:[/red] Scope directory does not exist: {scope_p}")
        return []

    files = []
    for ext in ["*.c", "*.h", "*.cc", "*.cpp"]:
        for p in scope_p.rglob(ext):
            rel = p.relative_to(repo_p)
            files.append(str(rel))
    return sorted(files)

def extract_function_body(file_path: str, start_line: int, max_lines: int = 400) -> str:
    p = Path(file_path)
    if not p.exists():
        return ""
    lines = p.read_text(errors="ignore").splitlines()
    i = max(0, start_line - 1)
    brace = 0
    started = False
    out = []
    for j in range(i, min(len(lines), i + max_lines)):
        s = lines[j]
        out.append(f"{j+1:6d}  {s}")
        if "{" in s:
            brace += s.count("{")
            started = True
        if "}" in s and started:
            brace -= s.count("}")
            if brace <= 0:
                break
    return "\n".join(out)

def find_enclosing_symbol(tags_in_file: list[dict[str, Any]], hit_line: int) -> dict[str, Any] | None:
    best = None
    for t in tags_in_file:
        if t.get("line") is None:
            continue
        if t["line"] <= hit_line:
            best = t
        else:
            break
    return best


def normalize_file_hint(file_hint: str | None, repo: str) -> str | None:
    if not file_hint:
        return None
    hint = file_hint.strip()
    if not hint:
        return None
    path = Path(hint)
    if not path.is_absolute():
        path = (Path(repo) / hint).resolve()
    else:
        path = path.resolve()
    return str(path)


def build_analysis_key(symbol: str, file_path: str | None) -> str:
    if file_path:
        return f"{file_path}::{symbol}"
    return symbol


def parse_next_question(question: str) -> tuple[str | None, str | None]:
    if not question:
        return None, None
    raw = question.strip().lstrip("-").strip()
    if not raw:
        return None, None
    if raw.startswith("`") and raw.endswith("`"):
        raw = raw[1:-1].strip()

    file_hint = None
    symbol = None

    if ":" in raw:
        left, right = raw.rsplit(":", 1)
        if left and right:
            file_hint = left.strip()
            symbol = right.strip()
        else:
            symbol = raw.strip()
    else:
        symbol = raw.strip()

    if not symbol:
        return None, file_hint

    symbol = re.sub(r"\s*\(.*\)\s*$", "", symbol)
    symbol = symbol.split()[0].strip().rstrip(",.;")
    if not symbol:
        return None, file_hint
    return symbol, file_hint


def is_within_scope(file_path: str, repo: str, scope: str) -> bool:
    base = (Path(repo) / scope).resolve()
    target = Path(file_path)
    if not target.is_absolute():
        target = (Path(repo) / file_path).resolve()
    else:
        target = target.resolve()
    try:
        target.relative_to(base)
        return True
    except ValueError:
        return False


def extract_unique_questions(
    findings: list[dict[str, Any]],
    analyzed_keys: set[str],
    func_index: dict[str, list[dict[str, Any]]],
    repo: str,
    scope: str,
) -> list[dict[str, Any]]:
    questions_to_analyze = []
    seen = set(analyzed_keys)

    for finding_item in findings:
        finding = finding_item.get("finding", {})
        for question in finding.get("next_questions", []):
            symbol, file_hint = parse_next_question(question)
            if not symbol:
                continue

            file_hint_abs = normalize_file_hint(file_hint, repo)
            file_path, line = resolve_symbol_location(symbol, file_hint_abs, func_index)
            if not file_path:
                continue

            if not is_within_scope(file_path, repo, scope):
                continue

            key = build_analysis_key(symbol, file_path)
            if key in seen:
                continue
            seen.add(key)

            questions_to_analyze.append({
                "symbol": symbol,
                "file": file_path,
                "line": line or 1,
                "original_question": question,
                "source_finding": finding_item,
                "analysis_key": key,
            })

    return questions_to_analyze

# -------------------------
# LLM output schema (enhanced)
# -------------------------
class Finding(BaseModel):
    title: str
    risk: Literal["low", "medium", "high", "critical"]
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
    evidence: list[str] = Field(default_factory=list)
    counter_evidence: list[str] = Field(default_factory=list)  # NEW
    next_questions: list[str] = Field(default_factory=list)
    framework_context: str = ""  # NEW
    is_false_positive: bool = False  # NEW
    false_positive_reason: str = ""  # NEW
    exploitability_notes: str = ""  # NEW
    # Explicit classification (Phase 3)
    classification: Literal["true_positive", "false_positive", "uncertain"] = "uncertain"
    classification_rationale: str = ""
    needs_deeper_analysis: bool = False

# -------------------------
# LangGraph State
# -------------------------
class ScanState(TypedDict):
    repo: str
    scope: str
    thread_id: str
    test_mode: bool
    framework: str  # NEW: framework name (e.g., "drm", "generic")
    framework_config: Any  # NEW: FrameworkConfig object
    iterative_mode: bool  # NEW: enable iterative follow-up
    analyzed_symbols: list[str]  # NEW: track analyzed symbols
    iteration_count: int  # NEW: iteration counter
    use_mcp: bool  # NEW: enable MCP integration (IDA Pro, Ghidra, etc.)
    entrypoints: list[dict[str, Any]]
    deep_dive_notes: dict[str, Any]
    surface_hits: list[dict[str, Any]]
    tags: list[dict[str, Any]]
    tags_by_file: dict[str, list[dict[str, Any]]]
    candidates: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    report_md: str

# -------------------------
# Nodes (from original, except deep_dive & new self_critique)
# -------------------------
def map_surface(state: ScanState) -> dict:
    """Collect ioctl/handler/entrypoint hints within the scope.

    Hardened version with:
    - Framework-specific patterns (DRM, Mali/kbase, generic)
    - Configurable hit limits with warnings
    - Better deduplication
    """
    repo = state["repo"]
    scope = str(Path(repo) / state["scope"])
    framework = state.get("framework", "drm")

    # Base patterns for all frameworks
    base_patterns = [
        r"\bfile_operations\b",
        r"\bdebugfs_create\b",
        r"\.unlocked_ioctl\s*=",
        r"\.compat_ioctl\s*=",
        r"\.mmap\s*=",
        r"\.open\s*=",
        r"\.release\s*=",
    ]

    # Framework-specific patterns
    drm_patterns = [
        r"\bDRM_IOCTL\b",
        r"\bDRM_IOCTL_DEF_DRV\b",
        r"\bdrm_ioctl_desc\b",
        r"\bdrm_driver\b",
        r"\bDRM_RENDER_ALLOW\b",
        r"\bdrm_gem_object\b",
    ]

    mali_patterns = [
        # Mali kbase specific
        r"\bKBASE_IOCTL\b",
        r"\bkbase_ioctl\b",
        r"\bkbase_api_\w+\b",
        r"\bkbase_file\b",
        r"\bkbase_context\b",
        r"\bkbase_device\b",
        r"\bkbase_mem_\w+\b",
        r"\bkbase_mmap\b",
        r"\bkbase_open\b",
        r"\bkbase_release\b",
        # Mali GPU memory management
        r"\bkbase_va_region\b",
        r"\bkbase_alloc\b",
        r"\bkbase_free\b",
        r"\bkbase_gpu_\w+\b",
        # Mali CSF (Command Stream Frontend)
        r"\bkbase_csf_\w+\b",
        r"\bkbase_queue\b",
        r"\bkbase_queue_group\b",
        # Mali debugfs
        r"\bkbasep?_\w+_debugfs\b",
    ]

    generic_patterns = [
        r"\bmodule_init\b",
        r"\bmodule_exit\b",
        r"\bplatform_driver\b",
        r"\bpci_driver\b",
        r"\bi2c_driver\b",
        r"\bspi_driver\b",
        r"\busb_driver\b",
    ]

    # Select patterns based on framework
    patterns = base_patterns.copy()
    if framework == "drm":
        patterns.extend(drm_patterns)
        patterns.extend(mali_patterns)  # Include Mali patterns for DRM framework
    elif framework == "mali":
        patterns.extend(mali_patterns)
        patterns.extend(drm_patterns)  # Mali is built on DRM
    elif framework == "generic":
        patterns.extend(generic_patterns)
    else:
        # Unknown framework - use all patterns
        patterns.extend(drm_patterns)
        patterns.extend(mali_patterns)
        patterns.extend(generic_patterns)

    MAX_HITS_PER_PATTERN = 2000
    MAX_TOTAL_ENTRYPOINTS = 1000
    hits = []
    truncated_patterns = []

    for pat in patterns:
        pattern_hits = rg(pat, scope, globs=["*.c", "*.h", "*.cc", "*.cpp"])
        if len(pattern_hits) >= MAX_HITS_PER_PATTERN:
            truncated_patterns.append(pat)
        hits.extend(pattern_hits[:MAX_HITS_PER_PATTERN])

    if truncated_patterns:
        print(f"[yellow]map_surface:[/yellow] {len(truncated_patterns)} patterns hit limit ({MAX_HITS_PER_PATTERN})")

    # Deduplicate by (file, line) - text may vary slightly
    uniq = {}
    for h in hits:
        key = (h["file"], h["line"])
        if key not in uniq:
            uniq[key] = h
    hits = list(uniq.values())

    print(f"[blue]map_surface:[/blue] Found {len(hits)} unique entrypoint hints (framework={framework})")

    if len(hits) > MAX_TOTAL_ENTRYPOINTS:
        print(f"[yellow]map_surface:[/yellow] Truncating to {MAX_TOTAL_ENTRYPOINTS} entrypoints")

    entrypoints = []
    for h in hits[:MAX_TOTAL_ENTRYPOINTS]:
        entrypoints.append({
            **h,
            "snippet": read_snippet(h["file"], h["line"], radius=25),
        })

    return {"surface_hits": entrypoints}

def build_ts_index(state: ScanState) -> dict[str, Any]:
    repo = state["repo"]
    scope = state["scope"]
    rels = git_ls_files(repo, scope)
    repo_p = Path(repo).resolve()

    print(f"[blue]build_ts_index:[/blue] Found {len(rels)} source files in {scope}")

    all_tags = []
    by_file = {}
    errors = []

    for rel_path in rels:
        abs_path = repo_p / rel_path
        if not abs_path.exists():
            continue
        if not str(abs_path).endswith('.c'):
            continue

        cmd = ["tree-sitter", "tags", "--scope", "source.c", str(abs_path)]
        try:
            r = subprocess.run(cmd, cwd=str(repo_p), capture_output=True, text=True, timeout=30)
            if r.returncode != 0:
                errors.append(f"{rel_path}: {r.stderr[:100]}")
                continue
            output = r.stdout
        except Exception as e:
            errors.append(f"{rel_path}: {e}")
            continue

        file_tags = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            parts = line.split('\t')
            if len(parts) < 3:
                continue

            name = parts[0].strip()
            kind = parts[1].strip().lstrip('|').strip()
            pos_info = parts[2].strip()

            lineno = None
            m = re.search(r'\((\d+),\s*\d+\)', pos_info)
            if m:
                lineno = int(m.group(1)) + 1

            tag = {
                "name": name,
                "file": str(abs_path),
                "line": lineno,
                "kind": kind,
                "fields": {"position": pos_info},
            }
            file_tags.append(tag)
            all_tags.append(tag)

        if file_tags:
            by_file[str(abs_path)] = file_tags

    for f, lst in by_file.items():
        lst.sort(key=lambda t: (t["line"] is None, t["line"] or 10**9))

    print(f"[blue]build_ts_index:[/blue] Extracted {len(all_tags)} tags from {len(by_file)} files")
    if errors:
        print(f"[yellow]build_ts_index warnings:[/yellow] {len(errors)} files had issues")

    return {"tags": all_tags, "tags_by_file": by_file}

def select_candidates(state: ScanState) -> dict[str, Any]:
    repo = state["repo"]
    scope = state["scope"]
    by_file = state.get("tags_by_file", {})
    framework_config = state.get("framework_config")  # NEW

    rels = git_ls_files(repo, scope)
    repo_p = Path(repo).resolve()
    files = [str((repo_p / rel).resolve()) for rel in rels]

    entrypoints = extract_entrypoints(files, by_file, framework_config)  # Pass framework_config
    call_graph = build_call_graph(files, by_file)
    candidates = score_and_rank_candidates(by_file, entrypoints, call_graph, extract_function_body)
    func_index = build_function_index(by_file)

    for c in candidates:
        c["name"] = c["symbol"]
        c["from_file"] = c["file"]
        c["from_line"] = c["def_line"]
        evidence_hits = []
        for kind, hits in (c.get("indicator_hits") or {}).items():
            for hit in hits:
                evidence_hits.append({
                    "kind": kind,
                    "line": hit.get("line"),
                    "text": hit.get("text"),
                })
        c["evidence_hits"] = evidence_hits
        c["evidence_pack"] = build_evidence_pack(c, func_index, entrypoints)

    return {"candidates": candidates, "entrypoints": entrypoints}

def enrich_candidates(state: ScanState) -> dict:
    """Enrich candidates with context for analysis."""
    candidates = state.get("candidates", [])
    by_file = state.get("tags_by_file", {})
    entrypoints = state.get("entrypoints", [])
    func_index = build_function_index(by_file)
    enriched = []

    # Check if MCP integration is enabled
    use_mcp = state.get("use_mcp", False)
    mcp_integration = None
    if use_mcp:
        from mcp_integration import get_mcp_integration, is_mcp_enabled
        if is_mcp_enabled():
            mcp_integration = get_mcp_integration()
            print("[green]MCP integration enabled for candidate enrichment[/green]")

    for c in candidates:
        file_path = c.get("file")
        symbol = c.get("symbol")
        if not file_path or not symbol:
            continue

        tags_in_file = by_file.get(file_path, [])
        tag = None
        for t in tags_in_file:
            if t["name"] == symbol:
                tag = t
                break

        context = c.get("context")
        if not context:
            if tag and tag.get("line"):
                context = extract_function_body(file_path, tag["line"], max_lines=400)
                line = tag["line"]
            else:
                context = read_snippet(file_path, 1, radius=50)
                line = 1
        else:
            line = c.get("from_line") or (tag.get("line") if tag else 1)

        candidate_dict = {
            **c,
            "name": c.get("name", symbol),
            "from_file": c.get("from_file", file_path),
            "from_line": line,
            "context": context,
            "evidence_pack": c.get("evidence_pack") or build_evidence_pack(
                {**c, "context": context, "def_line": line}, func_index, entrypoints
            ),
        }

        # Optionally enrich with MCP analysis
        if mcp_integration:
            candidate_dict = mcp_integration.enrich_candidate_with_mcp(candidate_dict)

        enriched.append(candidate_dict)

    return {"candidates": enriched}

def local_triage(state: ScanState) -> dict:
    """Use a local LLM to emit a short JSON assessment per candidate."""
    factory = get_factory()
    framework_config = state.get("framework_config")

    # Check if we're in claude_code mode - skip LLM processing
    if factory.get_provider_for_stage("triage") == "claude_code":
        print("[blue]triage:[/blue] Claude Code mode - skipping LLM triage, passing candidates through")
        # Create minimal findings for each candidate to pass to next stage
        findings = []
        for c in state["candidates"]:
            findings.append({
                "candidate": c,
                "finding": {
                    "title": f"Analysis needed: {c.get('name', c.get('symbol', 'unknown'))}",
                    "risk": "medium",
                    "confidence": 0.5,
                    "rationale": "Requires Claude Code analysis",
                    "evidence": [],
                    "counter_evidence": [],
                    "next_questions": [],
                },
                "source": "claude_code_passthrough",
            })
        return {"findings": findings}

    # Get LLM from factory
    llm = factory.get_llm_for_stage("triage")
    if llm is None:
        # Fallback to default Ollama if factory returns None
        llm = ChatOllama(model=LOCAL_MODEL, base_url=OLLAMA_BASE_URL, temperature=0)

    findings = []
    for c in state["candidates"]:
        # Use framework-aware prompt if config available
        if framework_config:
            prompt = get_framework_aware_local_triage_prompt(c, c.get("evidence_pack"), framework_config)
        else:
            prompt = get_local_triage_prompt(c, c.get("evidence_pack"))

        resp = llm.invoke(prompt).content
        blob = extract_json_blob(resp, want_array=False)
        if not blob:
            continue
        try:
            obj = json.loads(blob)
            obj = normalize_finding_dict(obj)
            f = Finding(**obj)
            findings.append({
                "candidate": c,
                "finding": f.model_dump(),
                "source": "local",
            })
        except Exception:
            continue

    return {"findings": findings}

def need_deep_dive(state: ScanState) -> Literal["deep_dive", "iterative_followup", END]:
    """Send only risky or uncertain local findings to OpenRouter."""
    if state.get("test_mode", False):
        print("[blue]need_deep_dive:[/blue] --test enabled, forcing deep_dive")
        return "deep_dive"

    for x in state["findings"]:
        f = x["finding"]
        c = x.get("candidate", {})
        risk = f["risk"]
        conf = f["confidence"]
        if c.get("priority") == "high":
            return "deep_dive"
        if risk in ("medium", "high", "critical") and 0.35 <= conf <= 0.85:
            return "deep_dive"
    if state.get("iterative_mode", False):
        return "iterative_followup"
    return END

def deep_dive(state: ScanState) -> dict:
    """
    IMPROVED: structured prompt + few-shot examples + rule-based filters
    """
    base_findings = state.get("findings", [])
    if not base_findings:
        return {"findings": [], "deep_dive_notes": {"targets": 0}}

    factory = get_factory()
    provider = factory.get_provider_for_stage("deep_dive")

    # Check if we're in claude_code mode - skip LLM processing
    if provider == "claude_code":
        print("[blue]deep_dive:[/blue] Claude Code mode - skipping LLM deep dive, passing findings through")
        return {"findings": base_findings, "deep_dive_notes": {"targets": 0, "mode": "claude_code"}}

    # Get LLM from factory
    llm = factory.get_llm_for_stage("deep_dive")
    if llm is None:
        # Fallback to hardcoded OpenRouter if factory returns None
        try:
            llm = ChatOpenAI(
                model=OPENROUTER_MODEL,
                openai_api_key=OPENROUTER_API_KEY,
                openai_api_base=OPENROUTER_BASE_URL,
                temperature=0,
                default_headers={
                    "HTTP-Referer": os.getenv("OPENROUTER_SITE_URL", "http://localhost"),
                    "X-Title": os.getenv("OPENROUTER_APP_NAME", "mali-static-ai"),
                }
            )
        except Exception as e:
            print(f"[yellow]deep_dive:[/yellow] API init failed: {e}")
            return {"findings": base_findings, "deep_dive_notes": {"targets": 0, "error": str(e)}}

    # Get heavy model if configured (for openrouter provider)
    llm_heavy = None
    if provider == "openrouter":
        heavy_model = os.getenv("OPENROUTER_HEAVY_MODEL")
        if heavy_model:
            try:
                llm_heavy = ChatOpenAI(
                    model=heavy_model,
                    openai_api_key=OPENROUTER_API_KEY,
                    openai_api_base=OPENROUTER_BASE_URL,
                    temperature=0,
                    default_headers={
                        "HTTP-Referer": os.getenv("OPENROUTER_SITE_URL", "http://localhost"),
                        "X-Title": os.getenv("OPENROUTER_APP_NAME", "mali-static-ai"),
                    }
                )
            except Exception as e:
                print(f"[yellow]deep_dive:[/yellow] Heavy model init failed: {e}")
                llm_heavy = None

    test_mode = state.get("test_mode", False)
    targets = []

    if test_mode:
        targets = base_findings[:3]
        print(f"[blue]deep_dive:[/blue] --test mode: forcing top {len(targets)} candidates")
    else:
        for x in base_findings:
            f = x["finding"]
            c = x.get("candidate", {})
            if c.get("priority") == "high":
                targets.append(x)
                continue
            if f["risk"] in ("medium", "high", "critical") and 0.35 <= f["confidence"] <= 0.85:
                targets.append(x)
        targets = targets[:8]

    if not targets:
        return {"findings": base_findings, "deep_dive_notes": {"targets": 0}}

    print(f"[blue]deep_dive:[/blue] Deep diving {len(targets)} candidates via {provider}...")

    batch_size = int(os.getenv("OPENROUTER_BATCH_SIZE", "3"))
    if batch_size < 2:
        batch_size = 2
    if batch_size > 3:
        batch_size = 3
    max_calls = int(os.getenv("OPENROUTER_MAX_CALLS", "6"))

    items = []
    for x in targets:
        items.append({
            "candidate": x["candidate"],
            "finding": x["finding"],
            "evidence_pack": x["candidate"].get("evidence_pack", {}),
        })

    def parse_batch_response(resp: str) -> list[dict[str, Any]] | None:
        blob = extract_json_blob(resp, want_array=True)
        if not blob:
            return None
        data = json.loads(blob)
        if not isinstance(data, list):
            return None
        out = []
        for obj in data:
            if not isinstance(obj, dict):
                out.append(None)
                continue
            obj = normalize_finding_dict(obj)
            try:
                f = Finding(**obj)
                out.append(f.model_dump())
            except Exception:
                out.append(None)
        return out

    framework_config = state.get("framework_config")  # NEW: Get framework config

    def build_prompt(batch: list[dict[str, Any]]) -> str:
        if framework_config:
            return get_framework_aware_batch_deep_dive_prompt(batch, framework_config)
        else:
            return get_batch_deep_dive_prompt(batch)

    def is_heavy_item(item: dict[str, Any]) -> bool:
        if not llm_heavy:
            return False
        score = item.get("candidate", {}).get("score", 0.0)
        return score >= SCORE_THRESHOLDS["heavy_model"]

    heavy_items = [item for item in items if is_heavy_item(item)]
    normal_items = [item for item in items if item not in heavy_items]

    results_map: dict[tuple[str, str], dict[str, Any]] = {}
    notes = {"targets": len(items), "calls": 0, "skipped": 0, "errors": []}

    remaining_calls = max_calls
    if heavy_items and llm_heavy:
        batch_results, batch_notes = run_batched_llm(
            llm_heavy, heavy_items, build_prompt, parse_batch_response, batch_size, remaining_calls
        )
        remaining_calls -= batch_notes["calls"]
        notes["calls"] += batch_notes["calls"]
        notes["skipped"] += batch_notes["skipped"]
        notes["errors"].extend(batch_notes["errors"])
        for item, result in zip(heavy_items, batch_results):
            if not result:
                continue
            result = apply_false_positive_filter(result, framework_config)  # Pass framework_config
            key = (item["candidate"].get("from_file"), item["candidate"].get("name"))
            results_map[key] = result

    if normal_items and remaining_calls > 0:
        batch_results, batch_notes = run_batched_llm(
            llm, normal_items, build_prompt, parse_batch_response, batch_size, remaining_calls
        )
        notes["calls"] += batch_notes["calls"]
        notes["skipped"] += batch_notes["skipped"]
        notes["errors"].extend(batch_notes["errors"])
        for item, result in zip(normal_items, batch_results):
            if not result:
                continue
            result = apply_false_positive_filter(result, framework_config)  # Pass framework_config
            key = (item["candidate"].get("from_file"), item["candidate"].get("name"))
            results_map[key] = result

    merged = []
    for item in base_findings:
        c = item.get("candidate", {})
        key = (c.get("from_file"), c.get("name"))
        if key in results_map:
            merged.append({
                "candidate": c,
                "finding": results_map[key],
                "source": "openrouter",
            })
        else:
            merged.append(item)

    return {"findings": merged, "deep_dive_notes": notes}



def self_critique(state: ScanState) -> dict:
    """
    NEW: self-review stage for critical validation of findings
    """
    factory = get_factory()
    provider = factory.get_provider_for_stage("self_critique")

    # Check if we're in claude_code mode - skip LLM processing
    if provider == "claude_code":
        print("[blue]self_critique:[/blue] Claude Code mode - skipping LLM critique")
        return {}

    print(f"[blue]self_critique:[/blue] Reviewing {len(state['findings'])} findings via {provider}...")

    # Get LLM from factory
    llm = factory.get_llm_for_stage("self_critique")
    if llm is None:
        # Fallback to hardcoded OpenRouter
        try:
            llm = ChatOpenAI(
                model=OPENROUTER_MODEL,
                openai_api_key=OPENROUTER_API_KEY,
                openai_api_base=OPENROUTER_BASE_URL,
                temperature=0,
                default_headers={
                    "HTTP-Referer": os.getenv("OPENROUTER_SITE_URL", "http://localhost"),
                    "X-Title": os.getenv("OPENROUTER_APP_NAME", "mali-static-ai"),
                }
            )
        except Exception as e:
            print(f"[yellow]self_critique:[/yellow] API init failed, skipping review: {e}")
            return {}

    validated_findings = []

    for item in state["findings"]:
        f = item["finding"]

        # Skip findings already marked as false positive
        if f.get("is_false_positive", False):
            validated_findings.append(item)
            continue

        prompt = SELF_CRITIQUE_PROMPT.format(
            original_analysis=json.dumps(f, ensure_ascii=False, indent=2)
        )

        try:
            resp = llm.invoke(prompt).content
            m = re.search(r"\{.*\}", resp, re.S)
            if m:
                critique = json.loads(m.group(0))

                if not critique.get("is_valid", True):
                    f["risk"] = critique.get("adjusted_risk", f["risk"])
                    f["confidence"] = critique.get("adjusted_confidence", f["confidence"])
                    f["rationale"] += f"\n\n[CRITIQUE] {critique.get('critique', '')}"

                validated_findings.append({
                    **item,
                    "finding": f,
                    "critique": critique
                })
            else:
                validated_findings.append(item)

        except Exception as e:
            print(f"[yellow]self_critique:[/yellow] Review failed: {e}")
            validated_findings.append(item)

    print(f"[blue]self_critique:[/blue] Review complete")
    return {"findings": validated_findings}

def need_critique(state: ScanState) -> Literal["self_critique", "iterative_followup", "write_report"]:
    """Decide whether to run self_critique after deep_dive."""
    for x in state["findings"]:
        if x.get("source") == "openrouter":
            return "self_critique"
    if state.get("iterative_mode", False):
        return "iterative_followup"
    return "write_report"


def iterative_followup(state: ScanState) -> dict:
    """
    Iteratively follow up on next_questions from findings.
    """
    if not state.get("iterative_mode", False):
        return {}

    iteration_count = state.get("iteration_count", 0)
    max_iterations = 2
    if iteration_count >= max_iterations:
        print(f"[blue]iterative_followup:[/blue] Max iterations ({max_iterations}) reached")
        return {}

    analyzed_keys = set(state.get("analyzed_symbols", []))
    findings = state.get("findings", [])
    repo = state["repo"]
    scope = state["scope"]

    func_index = build_function_index(state.get("tags_by_file", {}))
    questions_to_analyze = extract_unique_questions(
        findings,
        analyzed_keys,
        func_index,
        repo,
        scope
    )

    if not questions_to_analyze:
        print(f"[blue]iterative_followup:[/blue] No new questions to analyze")
        return {
            "iteration_count": iteration_count + 1,
            "analyzed_symbols": sorted(analyzed_keys),
        }

    questions_to_analyze = questions_to_analyze[:5]
    print(f"[blue]iterative_followup:[/blue] Analyzing {len(questions_to_analyze)} new symbols")

    entrypoints = state.get("entrypoints", [])
    framework_config = state.get("framework_config")
    new_candidates = []

    for q in questions_to_analyze:
        line = q["line"] or 1
        context = extract_function_body(q["file"], line, max_lines=400)
        indicator_hits = scan_indicators(context, framework_config)
        indicator_counts = {
            "user_control": len(indicator_hits.get("user_control", [])),
            "lifetime": len(indicator_hits.get("lifetime", [])),
            "concurrency": len(indicator_hits.get("concurrency", [])),
            "guards": len(indicator_hits.get("guards", [])),
        }

        candidate = {
            "name": q["symbol"],
            "symbol": q["symbol"],
            "from_file": q["file"],
            "from_line": line,
            "file": q["file"],
            "def_line": line,
            "context": context,
            "indicator_hits": indicator_hits,
            "indicator_counts": indicator_counts,
            "entrypoints_reaching": [],
            "reachability_path": [],
            "distance_min": None,
            "priority": "followup",
            "source_question": q["original_question"],
            "parent_finding": q["source_finding"],
            "analysis_key": q["analysis_key"],
        }
        candidate["evidence_pack"] = build_evidence_pack(candidate, func_index, entrypoints)
        new_candidates.append(candidate)

    factory = get_factory()
    provider = factory.get_provider_for_stage("iterative_followup")

    # Check if we're in claude_code mode - skip LLM processing
    if provider == "claude_code":
        print("[blue]iterative_followup:[/blue] Claude Code mode - skipping LLM followup")
        return {
            "iteration_count": iteration_count + 1,
            "analyzed_symbols": sorted(analyzed_keys),
        }

    print(f"[blue]iterative_followup:[/blue] Using {provider} for analysis")

    # Get LLM from factory
    llm = factory.get_llm_for_stage("iterative_followup")
    if llm is None:
        # Fallback to hardcoded OpenRouter
        try:
            llm = ChatOpenAI(
                model=OPENROUTER_MODEL,
                openai_api_key=OPENROUTER_API_KEY,
                openai_api_base=OPENROUTER_BASE_URL,
                temperature=0,
                default_headers={
                    "HTTP-Referer": os.getenv("OPENROUTER_SITE_URL", "http://localhost"),
                    "X-Title": os.getenv("OPENROUTER_APP_NAME", "mali-static-ai"),
                }
            )
        except Exception as e:
            print(f"[yellow]iterative_followup:[/yellow] API init failed: {e}")
            return {
                "iteration_count": iteration_count + 1,
                "analyzed_symbols": sorted(analyzed_keys),
            }

    new_findings = []

    for candidate in new_candidates:
        evidence_pack = candidate.get("evidence_pack", {})
        if framework_config:
            prompt = get_framework_aware_structured_analysis_prompt(
                candidate,
                {},
                evidence_pack,
                framework_config
            )
        else:
            prompt = get_structured_analysis_prompt(candidate, {}, evidence_pack)

        try:
            resp = llm.invoke(prompt).content
            blob = extract_json_blob(resp, want_array=False)
            if not blob:
                print(f"[yellow]iterative_followup:[/yellow] Failed to parse response for {candidate['symbol']}")
                continue

            obj = json.loads(blob)
            obj = normalize_finding_dict(obj)
            obj = apply_false_positive_filter(obj, framework_config)

            finding = Finding(**obj)
            new_findings.append({
                "candidate": candidate,
                "finding": finding.model_dump(),
                "source": f"follow_up_round_{iteration_count + 1}",
                "parent_finding": candidate.get("parent_finding"),
            })

            analyzed_keys.add(candidate.get("analysis_key") or build_analysis_key(candidate["symbol"], candidate.get("file")))

            print(
                f"[green]iterative_followup:[/green] Analyzed {candidate['symbol']} - "
                f"risk: {finding.risk}, confidence: {finding.confidence}"
            )

        except Exception as e:
            print(f"[yellow]iterative_followup:[/yellow] Failed to analyze {candidate['symbol']}: {e}")
            continue

    merged_findings = findings + new_findings

    print(
        f"[blue]iterative_followup:[/blue] Iteration {iteration_count + 1} complete: "
        f"{len(new_findings)} new findings, {len(analyzed_keys)} total symbols analyzed"
    )

    return {
        "findings": merged_findings,
        "analyzed_symbols": sorted(analyzed_keys),
        "iteration_count": iteration_count + 1,
    }


def need_iterative_followup(state: ScanState) -> str:
    """
    Dynamically decide if iterative followup is needed based on findings classification.

    Triggers iteration if:
    1. Any finding is classified as "uncertain" with needs_deeper_analysis=True
    2. High-risk findings (high/critical) with low confidence (<0.7)
    3. Findings have important next_questions

    No longer uses --iterative flag, now fully dynamic.
    """
    findings = state.get("findings", [])
    if not findings:
        return "write_report"

    # Check if we've already done iterations
    iteration_count = state.get("iteration_count", 0)
    max_iterations = 2
    if iteration_count >= max_iterations:
        print(f"[blue]need_iterative_followup:[/blue] Max iterations reached, skipping")
        return "write_report"

    # Dynamic decision based on findings
    needs_iteration = False
    reasons = []

    for finding_item in findings:
        finding = finding_item.get("finding", {})

        # Check 1: Uncertain findings that need deeper analysis
        if finding.get("classification") == "uncertain" and finding.get("needs_deeper_analysis"):
            needs_iteration = True
            reasons.append(f"Uncertain finding: {finding.get('title', 'Unknown')[:40]}")

        # Check 2: High-risk but low confidence
        risk = finding.get("risk", "low")
        confidence = finding.get("confidence", 0.0)
        if risk in ["high", "critical"] and confidence < 0.7:
            needs_iteration = True
            reasons.append(f"High-risk low-confidence: {finding.get('title', 'Unknown')[:40]}")

        # Check 3: Important next_questions exist
        next_questions = finding.get("next_questions", [])
        if len(next_questions) >= 3:  # Many questions suggests complex case
            needs_iteration = True
            reasons.append(f"Complex case with {len(next_questions)} questions")

    if needs_iteration:
        print(f"[green]need_iterative_followup:[/green] Iterating due to:")
        for r in reasons[:3]:  # Show top 3 reasons
            print(f"  - {r}")
        return "iterative_followup"
    else:
        print(f"[blue]need_iterative_followup:[/blue] No iteration needed, all findings resolved")
        return "write_report"


def classify_findings(state: ScanState) -> dict:
    """
    Explicitly classify findings as true_positive, false_positive, or uncertain.

    This is a validation step that provides explicit classification rationale.
    """
    findings = state.get("findings", [])
    if not findings:
        return {}

    framework_config = state.get("framework_config")

    factory = get_factory()
    provider = factory.get_provider_for_stage("classify_findings")

    # Check if we're in claude_code mode - skip LLM processing
    if provider == "claude_code":
        print("[blue]classify_findings:[/blue] Claude Code mode - skipping LLM classification")
        return {}

    print(f"[blue]classify_findings:[/blue] Using {provider} for classification")

    # Get LLM from factory
    llm = factory.get_llm_for_stage("classify_findings")
    if llm is None:
        # Fallback to hardcoded OpenRouter
        try:
            llm = ChatOpenAI(
                model=OPENROUTER_MODEL,
                openai_api_key=OPENROUTER_API_KEY,
                openai_api_base=OPENROUTER_BASE_URL,
                temperature=0,
                default_headers={
                    "HTTP-Referer": os.getenv("OPENROUTER_SITE_URL", "http://localhost"),
                    "X-Title": os.getenv("OPENROUTER_APP_NAME", "mali-static-ai"),
                }
            )
        except Exception as e:
            print(f"[yellow]classify_findings:[/yellow] API init failed: {e}")
            return {}

    classified_findings = []

    # Process in batches for efficiency
    from classify_prompt import get_batch_classification_prompt

    batch_size = 5
    for i in range(0, len(findings), batch_size):
        batch = findings[i:i+batch_size]

        prompt = get_batch_classification_prompt(batch, framework_config)

        try:
            resp = llm.invoke(prompt).content
            blob = extract_json_blob(resp, want_array=True)
            if not blob:
                print(f"[yellow]classify_findings:[/yellow] Failed to parse classification response")
                # Keep original findings if classification fails
                classified_findings.extend(batch)
                continue

            classifications = json.loads(blob)

            # Apply classifications to findings
            for j, classification in enumerate(classifications):
                if j >= len(batch):
                    break

                finding_item = batch[j]
                finding = finding_item["finding"]

                # Update finding with classification
                finding["classification"] = classification.get("classification", "uncertain")
                finding["classification_rationale"] = classification.get("classification_rationale", "")
                finding["needs_deeper_analysis"] = classification.get("needs_deeper_analysis", False)

                # Adjust confidence based on classification
                confidence_adj = classification.get("confidence_adjustment")
                if confidence_adj is not None:
                    finding["confidence"] = max(0.0, min(1.0, confidence_adj))

                # If classified as false_positive, update legacy flags
                if finding["classification"] == "false_positive":
                    finding["is_false_positive"] = True
                    if not finding.get("false_positive_reason"):
                        finding["false_positive_reason"] = finding["classification_rationale"]

                classified_findings.append(finding_item)

                print(
                    f"[blue]classify_findings:[/blue] {finding.get('title', 'Unknown')[:50]} → "
                    f"{finding['classification']} (confidence: {finding.get('confidence', 0.0):.2f})"
                )

        except Exception as e:
            print(f"[yellow]classify_findings:[/yellow] Classification error: {e}")
            # Keep original findings if error
            classified_findings.extend(batch)
            continue

    return {"findings": classified_findings}


def false_positive_classifier(state: ScanState) -> dict:
    """
    Specialized False Positive Classifier Agent.

    This is a second-stage validation focused on identifying false positives
    with high confidence. More conservative than classify_findings.

    Only filters out findings that are DEFINITELY false positives.
    When uncertain, keeps as true positive (conservative approach).
    """
    findings = state.get("findings", [])
    if not findings:
        return {}

    framework_config = state.get("framework_config")

    factory = get_factory()
    provider = factory.get_provider_for_stage("false_positive_classifier")

    # Check if we're in claude_code mode - skip LLM processing
    if provider == "claude_code":
        print("[blue]fp_classifier:[/blue] Claude Code mode - skipping LLM FP classification")
        return {}

    print(f"[blue]fp_classifier:[/blue] Using {provider} for FP detection")

    # Get LLM from factory
    llm = factory.get_llm_for_stage("false_positive_classifier")
    if llm is None:
        # Fallback to hardcoded OpenRouter
        try:
            llm = ChatOpenAI(
                model=OPENROUTER_MODEL,
                openai_api_key=OPENROUTER_API_KEY,
                openai_api_base=OPENROUTER_BASE_URL,
                temperature=0,
                default_headers={
                    "HTTP-Referer": os.getenv("OPENROUTER_SITE_URL", "http://localhost"),
                    "X-Title": os.getenv("OPENROUTER_APP_NAME", "mali-static-ai"),
                }
            )
        except Exception as e:
            print(f"[yellow]fp_classifier:[/yellow] API init failed: {e}")
            return {}

    filtered_findings = []

    # Process in batches
    from fp_classifier_prompt import get_batch_fp_classifier_prompt

    batch_size = 5
    fp_count = 0
    tp_count = 0

    for i in range(0, len(findings), batch_size):
        batch = findings[i:i+batch_size]

        prompt = get_batch_fp_classifier_prompt(batch, framework_config)

        try:
            resp = llm.invoke(prompt).content
            blob = extract_json_blob(resp, want_array=True)
            if not blob:
                print(f"[yellow]fp_classifier:[/yellow] Failed to parse response, keeping all findings")
                filtered_findings.extend(batch)
                continue

            classifications = json.loads(blob)

            # Apply FP classifications
            for j, classification in enumerate(classifications):
                if j >= len(batch):
                    break

                finding_item = batch[j]
                finding = finding_item["finding"]

                is_fp = classification.get("is_false_positive", False)
                fp_confidence = classification.get("confidence", 0.0)
                reasoning = classification.get("reasoning", "")

                # Conservative threshold: only filter out high-confidence FPs
                if is_fp and fp_confidence >= 0.8:
                    # Mark as definitively false positive
                    finding["classification"] = "false_positive"
                    finding["is_false_positive"] = True
                    finding["false_positive_reason"] = reasoning
                    finding["fp_classifier_confidence"] = fp_confidence
                    finding["framework_guarantee_match"] = classification.get("framework_guarantee_match", "")

                    fp_count += 1
                    print(
                        f"[red]fp_classifier:[/red] FILTERED OUT: {finding.get('title', 'Unknown')[:50]} "
                        f"(confidence: {fp_confidence:.2f})"
                    )
                else:
                    # Keep as potential true positive
                    if not is_fp:
                        finding["fp_classifier_validated"] = True
                        finding["exploit_scenario"] = classification.get("exploit_scenario", "")
                        tp_count += 1
                        print(
                            f"[green]fp_classifier:[/green] VALIDATED: {finding.get('title', 'Unknown')[:50]} "
                            f"(TP confidence: {fp_confidence:.2f})"
                        )
                    else:
                        # Low confidence FP → keep as uncertain
                        print(
                            f"[yellow]fp_classifier:[/yellow] UNCERTAIN: {finding.get('title', 'Unknown')[:50]} "
                            f"(FP confidence too low: {fp_confidence:.2f})"
                        )

                finding["fp_classifier_reasoning"] = reasoning
                finding["recommendation"] = classification.get("recommendation", "manual_review")

                filtered_findings.append(finding_item)

        except Exception as e:
            print(f"[yellow]fp_classifier:[/yellow] Classification error: {e}")
            # On error, keep all findings (conservative)
            filtered_findings.extend(batch)
            continue

    print(
        f"[blue]fp_classifier:[/blue] Complete: "
        f"{tp_count} validated TPs, {fp_count} filtered FPs, "
        f"{len(filtered_findings)} total findings"
    )

    return {"findings": filtered_findings}


def should_continue_iterating(state: ScanState) -> str:
    """
    After one iteration, decide if another round is needed.

    Uses same logic as need_iterative_followup but checks iteration count first.
    """
    iteration_count = state.get("iteration_count", 0)
    max_iterations = 2
    if iteration_count >= max_iterations:
        return "write_report"

    analyzed_keys = set(state.get("analyzed_symbols", []))
    func_index = build_function_index(state.get("tags_by_file", {}))

    questions = extract_unique_questions(
        state.get("findings", []),
        analyzed_keys,
        func_index,
        state["repo"],
        state["scope"],
    )
    if questions:
        return "iterative_followup"
    return "write_report"


def write_report(state: ScanState) -> dict:
    """
    Write two reports:
    1. report_<timestamp>.md - All findings (including false positives)
    2. report_true_positives_<timestamp>.md - Only validated true positives

    Also creates symlinks report.md and report_true_positives.md pointing to latest.
    """
    outdir = Path("out")
    outdir.mkdir(parents=True, exist_ok=True)

    # Generate timestamp suffix from thread_id or current time
    thread_id = state.get("thread_id", "")
    if thread_id and thread_id.startswith("mali-"):
        # Extract timestamp from thread_id like "mali-20260116-132032-6d1d7c"
        parts = thread_id.split("-")
        if len(parts) >= 3:
            timestamp = f"{parts[1]}-{parts[2]}"  # "20260116-132032"
        else:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    else:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    # Timestamped filenames
    report_name = f"report_{timestamp}.md"
    report_tp_name = f"report_true_positives_{timestamp}.md"
    state_name = f"state_{timestamp}.json"

    # Generate full report
    _write_full_report(state, outdir, report_name)

    # Generate true positives only report
    _write_true_positives_report(state, outdir, report_tp_name)

    # Write state JSON
    state_serializable = state.copy()
    state_serializable['framework_config'] = asdict(state['framework_config'])
    if isinstance(state_serializable.get("analyzed_symbols"), set):
        state_serializable["analyzed_symbols"] = sorted(state_serializable["analyzed_symbols"])
    (outdir / state_name).write_text(json.dumps(state_serializable, ensure_ascii=False, indent=2), encoding="utf-8")

    # Create/update symlinks to latest reports
    for link_name, target_name in [
        ("report.md", report_name),
        ("report_true_positives.md", report_tp_name),
        ("state.json", state_name),
    ]:
        link_path = outdir / link_name
        if link_path.is_symlink() or link_path.exists():
            link_path.unlink()
        link_path.symlink_to(target_name)

    print(f"[green]Wrote:[/green] {outdir/report_name}, {outdir/report_tp_name}, and {outdir/state_name}")
    print(f"[green]Symlinks:[/green] report.md, report_true_positives.md, state.json → latest")

    return {
        "report_files": {
            "report": str(outdir / report_name),
            "report_true_positives": str(outdir / report_tp_name),
            "state": str(outdir / state_name),
        }
    }


def _format_findings_section(findings: list[dict], show_fp_info: bool = True) -> list[str]:
    """Helper to format findings section for reports."""
    md = []

    def score(item):
        f = item.get("finding", {})
        risk = f.get("risk", "low")
        risk_w = {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(risk, 0)
        confidence = f.get("confidence", 0.0)
        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            confidence = 0.0
        return (risk_w, confidence)

    sorted_findings = sorted(findings, key=lambda x: score(x), reverse=True)

    for i, item in enumerate(sorted_findings, 1):
        c = item.get("candidate", {})
        f = item.get("finding", {})
        risk = f.get("risk", "unknown")
        confidence = f.get("confidence", 0.0)
        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            confidence = 0.0

        # Add classification badge
        classification = f.get("classification", "uncertain")
        classification_badge = {
            "true_positive": "✓ TP",
            "false_positive": "✗ FP",
            "uncertain": "? UNCERTAIN"
        }.get(classification, "")

        md.append(f"### {i}. [{item.get('source', 'unknown')}] {f.get('title', 'Unknown')} [{classification_badge}]\n")
        md.append(f"- risk: **{risk}** / confidence: **{confidence:.2f}**\n")

        # Add classification rationale if available
        if f.get("classification_rationale"):
            md.append(f"- **Classification**: {f['classification_rationale']}\n")

        # Add FP classifier info if available
        if show_fp_info and f.get("fp_classifier_reasoning"):
            md.append(f"- **FP Classifier**: {f['fp_classifier_reasoning']}\n")
            if f.get("fp_classifier_confidence"):
                md.append(f"  - Confidence: {f['fp_classifier_confidence']:.2f}\n")
            if f.get("framework_guarantee_match"):
                md.append(f"  - Framework Guarantee: {f['framework_guarantee_match']}\n")

        md.append(f"- candidate: `{c.get('name', c.get('symbol', 'unknown'))}` from `{c.get('from_file', c.get('file', 'unknown'))}:{c.get('from_line', 0)}`\n")
        md.append(f"- rationale:\n\n{f.get('rationale', 'No rationale')}\n")

        if f.get("exploitability_notes"):
            md.append(f"- exploitability_notes: {f['exploitability_notes']}\n")

        evidence_pack = c.get("evidence_pack", {})
        reach_path = format_reachability_path(evidence_pack.get("reachability_path", []))
        if reach_path:
            md.append(f"- reachability_path: `{reach_path}`\n")

        if show_fp_info and f.get("is_false_positive"):
            md.append(f"- **FALSE POSITIVE**: {f.get('false_positive_reason', 'N/A')}\n")

        if f.get("evidence"):
            md.append(f"- evidence:\n")
            for ev in f["evidence"][:12]:
                md.append(f"  - {ev}\n")

        if f.get("counter_evidence"):
            md.append(f"- counter_evidence:\n")
            for ce in f["counter_evidence"][:12]:
                md.append(f"  - {ce}\n")

        if f.get("framework_context"):
            md.append(f"- framework_context: {f['framework_context']}\n")

        if f.get("next_questions"):
            md.append(f"- next questions:\n")
            for nq in f["next_questions"][:12]:
                md.append(f"  - {nq}\n")

        guards = evidence_pack.get("guards_invariants") or []
        if guards:
            md.append(f"- guards/invariants:\n")
            for guard in guards[:8]:
                md.append(f"  - {guard}\n")

        if f.get("counter_evidence"):
            md.append(f"- what would falsify this:\n")
            for ce in f["counter_evidence"][:8]:
                md.append(f"  - {ce}\n")

        md.append("\n---\n")

    return md


def _write_full_report(state: ScanState, outdir: Path, filename: str = "report.md"):
    """Write full report with all findings."""
    md = []
    md.append(f"# Static Analysis Report (All Findings)\n")
    md.append(f"- repo: `{state['repo']}`\n- scope: `{state['scope']}`\n")
    md.append(f"- framework: `{state.get('framework', 'unknown')}`\n")
    md.append(f"- session: `{state.get('thread_id', 'unknown')}`\n\n")

    entrypoints = state.get("entrypoints", [])
    candidates = state.get("candidates", [])

    if entrypoints:
        md.append("## Entry Surface Summary\n")
        by_kind = {"ioctl": [], "file_ops": [], "mmap": [], "debugfs": [], "driver": []}
        for ep in entrypoints:
            label = ep.get("symbol", "unknown")
            if ep.get("file") and ep.get("line"):
                label = f"{label} ({Path(ep['file']).name}:{ep['line']})"
            for kind in ep.get("kinds", []):
                by_kind.setdefault(kind, []).append(label)
        md.append(f"- ioctl handlers: {', '.join(by_kind['ioctl']) or 'none'}\n")
        md.append(f"- file operations: {', '.join(by_kind['file_ops']) or 'none'}\n")
        md.append(f"- mmap handlers: {', '.join(by_kind['mmap']) or 'none'}\n")
        md.append(f"- debugfs hooks: {', '.join(by_kind['debugfs']) or 'none'}\n")
        md.append(f"- driver hooks: {', '.join(by_kind['driver']) or 'none'}\n")

    if candidates:
        md.append("\n## Top Candidates\n")
        md.append("| candidate | score | distance | user_ctrl | lifetime | concurrency |\n")
        md.append("| --- | --- | --- | --- | --- | --- |\n")
        for c in sorted(candidates, key=lambda x: x.get("score", 0), reverse=True)[:10]:
            counts = c.get("indicator_counts", {})
            md.append(
                f"| `{c.get('name', c.get('symbol', 'unknown'))}`"
                f" | {c.get('score', 0):.1f}"
                f" | {c.get('distance_min', '-')}"
                f" | {counts.get('user_control', 0)}"
                f" | {counts.get('lifetime', 0)}"
                f" | {counts.get('concurrency', 0)} |\n"
            )

    # Statistics
    findings = state.get("findings", [])
    tp_count = sum(1 for item in findings if item.get("finding", {}).get("classification") == "true_positive")
    fp_count = sum(1 for item in findings if item.get("finding", {}).get("classification") == "false_positive")
    uncertain_count = sum(1 for item in findings if item.get("finding", {}).get("classification") == "uncertain")

    md.append(f"\n## Findings Summary\n")
    md.append(f"- Total: {len(findings)}\n")
    md.append(f"- True Positives: {tp_count}\n")
    md.append(f"- False Positives: {fp_count}\n")
    md.append(f"- Uncertain: {uncertain_count}\n\n")

    md.append(f"## All Findings ({len(findings)})\n\n")
    md.extend(_format_findings_section(findings, show_fp_info=True))

    if not findings:
        md.append("## Diagnostics\n")
        md.append(f"- candidates: {len(candidates)}\n")
        md.append(f"- entrypoints: {len(entrypoints)}\n")
        notes = state.get("deep_dive_notes", {})
        if notes:
            md.append(f"- deep_dive: {json.dumps(notes, ensure_ascii=False)}\n")

    (outdir / filename).write_text("".join(md), encoding="utf-8")


def _write_true_positives_report(state: ScanState, outdir: Path, filename: str = "report_true_positives.md"):
    """Write report containing only true positives (FPs filtered out)."""
    md = []
    md.append(f"# Static Analysis Report (True Positives Only)\n\n")
    md.append(f"**This report contains only validated true positives with false positives filtered out.**\n\n")
    md.append(f"- repo: `{state['repo']}`\n- scope: `{state['scope']}`\n")
    md.append(f"- framework: `{state.get('framework', 'unknown')}`\n")
    md.append(f"- session: `{state.get('thread_id', 'unknown')}`\n\n")

    findings = state.get("findings", [])

    # Filter to only true positives and uncertain (conservative)
    # Exclude high-confidence false positives
    true_positives = []
    for item in findings:
        f = item.get("finding", {})
        classification = f.get("classification", "uncertain")

        # Include if:
        # 1. Classified as true_positive
        # 2. Uncertain (conservative approach)
        # 3. FP but with low confidence (<0.8) → uncertain
        if classification == "true_positive":
            true_positives.append(item)
        elif classification == "uncertain":
            true_positives.append(item)
        elif classification == "false_positive":
            # Only exclude high-confidence FPs
            fp_conf = f.get("fp_classifier_confidence", 0.0)
            if fp_conf < 0.8:
                true_positives.append(item)

    tp_count = sum(1 for item in true_positives if item.get("finding", {}).get("classification") == "true_positive")
    uncertain_count = sum(1 for item in true_positives if item.get("finding", {}).get("classification") == "uncertain")
    total_filtered = len(findings) - len(true_positives)

    md.append(f"## Summary\n")
    md.append(f"- Total findings analyzed: {len(findings)}\n")
    md.append(f"- **Validated True Positives: {tp_count}**\n")
    md.append(f"- Uncertain (requires review): {uncertain_count}\n")
    md.append(f"- False Positives filtered: {total_filtered}\n\n")

    if not true_positives:
        md.append("## Result\n\n")
        md.append("✅ **No true positives found!** All findings were identified as false positives.\n\n")
        md.append("This indicates the code appears to be following framework guarantees correctly.\n")
    else:
        md.append(f"## True Positive Findings ({len(true_positives)})\n\n")
        md.extend(_format_findings_section(true_positives, show_fp_info=False))

    (outdir / filename).write_text("".join(md), encoding="utf-8")


# -------------------------
# Build graph (improved)
# -------------------------
def build_app(checkpoint_path: str | None = None, verbose: bool = True):
    """
    Build the LangGraph analysis pipeline.

    Args:
        checkpoint_path: Path to checkpoint database. If None, uses default "checkpoints.sqlite".
                        For skills, use ".claude/state/mali-state/checkpoints.db".
        verbose: Whether to print status messages. Set False for skill execution.

    Returns:
        Compiled LangGraph application
    """
    g = StateGraph(ScanState)

    g.add_node("build_ts_index", build_ts_index)
    g.add_node("map_surface", map_surface)
    g.add_node("select_candidates", select_candidates)
    g.add_node("enrich_candidates", enrich_candidates)
    g.add_node("local_triage", local_triage)

    # Single-pass deep dive
    g.add_node("deep_dive", deep_dive)
    if verbose:
        print("[bold yellow]Using Single-Pass Deep Dive mode[/bold yellow]")

    g.add_node("self_critique", self_critique)
    g.add_node("classify_findings", classify_findings)
    g.add_node("false_positive_classifier", false_positive_classifier)
    g.add_node("iterative_followup", iterative_followup)
    g.add_node("write_report", write_report)

    g.add_edge(START, "build_ts_index")
    g.add_edge("build_ts_index", "map_surface")
    g.add_edge("map_surface", "select_candidates")
    g.add_edge("select_candidates", "enrich_candidates")
    g.add_edge("enrich_candidates", "local_triage")

    g.add_conditional_edges(
        "local_triage",
        need_deep_dive,
        {
            "deep_dive": "deep_dive",
            "iterative_followup": "iterative_followup",
            END: "write_report",
        },
    )

    g.add_conditional_edges(
        "deep_dive",
        need_critique,
        {
            "self_critique": "self_critique",
            "iterative_followup": "iterative_followup",
            "write_report": "write_report",
        }
    )

    # After self_critique, run classify_findings to explicitly classify
    g.add_edge("self_critique", "classify_findings")

    # After classification, run FP classifier agent
    g.add_edge("classify_findings", "false_positive_classifier")

    # After FP filtering, decide if iteration is needed
    g.add_conditional_edges(
        "false_positive_classifier",
        need_iterative_followup,
        {
            "iterative_followup": "iterative_followup",
            "write_report": "write_report",
        }
    )

    g.add_conditional_edges(
        "iterative_followup",
        should_continue_iterating,
        {
            "iterative_followup": "iterative_followup",
            "write_report": "write_report",
        }
    )

    g.add_edge("write_report", END)

    # Use provided checkpoint path or default
    db_path = checkpoint_path or "checkpoints.sqlite"
    conn = sqlite3.connect(
        db_path,
        check_same_thread=False,
        timeout=30.0,
    )
    conn.execute("PRAGMA journal_mode=WAL;")
    checkpointer = SqliteSaver(conn)

    return g.compile(checkpointer=checkpointer)


# -------------------------
# Main
# -------------------------
def main():
    import argparse
    ap = argparse.ArgumentParser(description="Mali Static AI - Framework-Agnostic Kernel Vulnerability Scanner")
    ap.add_argument("--repo", required=True, help="Path to repository")
    ap.add_argument("--scope", required=True, help="Scope to analyze (e.g., drivers/gpu/drm/panthor)")
    ap.add_argument("--thread", default="mali", help="Thread ID for checkpointing")
    ap.add_argument("--test", action="store_true", help="Test mode: force deep_dive on top 3 findings")
    ap.add_argument("--framework", default="drm", choices=["drm", "generic", "application", "mali"],
                    help="Framework to analyze (default: drm)")
    ap.add_argument("--no-iterative", action="store_false", dest="iterative",
                    help="Disable automatic iterative deep dive (enabled by default)")
    ap.add_argument("--use-mcp", action="store_true",
                    help="Enable MCP integration (IDA Pro, Ghidra, etc.)")
    ap.set_defaults(iterative=True)
    args = ap.parse_args()

    # Load framework configuration
    from framework_config import load_framework_config
    try:
        framework_config = load_framework_config(args.framework)
        print(f"[green]Loaded framework:[/green] {framework_config.display_name}")
    except Exception as e:
        print(f"[red]Failed to load framework '{args.framework}':[/red] {e}")
        print("[yellow]Falling back to DRM framework[/yellow]")
        framework_config = load_framework_config("drm")

    # Initialize state
    init_state: ScanState = {
        "repo": os.path.abspath(args.repo),
        "scope": args.scope,
        "test_mode": args.test,
        "thread_id": args.thread,
        "framework": args.framework,
        "framework_config": framework_config,
        "iterative_mode": args.iterative,
        "analyzed_symbols": [],
        "iteration_count": 0,
        "use_mcp": args.use_mcp,
        "surface_hits": [],
        "tags": [],
        "tags_by_file": {},
        "candidates": [],
        "findings": [],
        "entrypoints": [],
        "deep_dive_notes": {},
        "report_md": "",
    }

    app = build_app()
    config = {"configurable": {"thread_id": args.thread}}

    try:
        final = app.invoke(init_state, config)
        print("[bold green]Analysis complete![/bold green]")
        print(f"[blue]Generated reports:[/blue]")
        print(f"  - out/report.md (all findings)")
        print(f"  - out/report_true_positives.md (FPs filtered)")
        print(f"  - out/state.json")
    except Exception as e:
        import traceback
        print(f"[bold red]Error:[/bold red] {e}")
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main() or 0)
