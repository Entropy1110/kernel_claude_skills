from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Iterable
import re
import subprocess
import tempfile
import logging
import json

# Import framework configuration (optional, for backward compatibility)
try:
    from framework_config import FrameworkConfig
    FRAMEWORK_CONFIG_AVAILABLE = True
except ImportError:
    FRAMEWORK_CONFIG_AVAILABLE = False
    FrameworkConfig = Any  # Type hint fallback

logger = logging.getLogger(__name__)


CALL_GRAPH_QUERY = Path(__file__).resolve().parent / "queries" / "call_graph.scm"
MAX_GRAPH_DEPTH = 3
MAX_CANDIDATES = 25

SCORE_WEIGHTS = {
    "user_control": 3.0,
    "lifetime": 2.5,
    "concurrency": 1.5,
    "reachability": 2.0,
    "entrypoint": 3.0,
}

SCORE_THRESHOLDS = {
    "high": 10.0,
    "med": 6.0,
    "heavy_model": 14.0,
}

USER_CONTROL_PATTERNS = [
    r"\bcopy_from_user\b",
    r"\bcopy_to_user\b",
    r"\bget_user\b",
    r"\bput_user\b",
    r"\bmemdup_user\b",
    r"\bstrncpy_from_user\b",
    r"\b__user\b",
    r"\buser_ptr\b",
    r"\bvm_pgoff\b",
    r"\bdrm_ioctl\b",
]

LIFETIME_PATTERNS = [
    r"\bkmalloc\b",
    r"\bkzalloc\b",
    r"\bkcalloc\b",
    r"\bkfree\b",
    r"\bkvfree\b",
    r"\bvfree\b",
    r"\bkref_(get|put)\b",
    r"\brefcount_(inc|dec|add|sub)\b",
    r"\bdrm_gem_object_(get|put|lookup)\b",
    r"\bdrm_gem_(shmem_)?free_object\b",
    r"\bdrm_gem_\w+\b",
    r"\bxa_(store|erase|load)\b",
    r"\bidr_(alloc|remove|find)\b",
    r"\blist_(add|del|del_init)\b",
    r"\bdma_buf\b",
    r"\bbo_\w+\b",
]

CONCURRENCY_PATTERNS = [
    r"\bspin_lock\b",
    r"\bspin_unlock\b",
    r"\bmutex_lock\b",
    r"\bmutex_unlock\b",
    r"\brwlock\b",
    r"\brcu_(read_lock|read_unlock|assign_pointer|dereference)\b",
    r"\bwait_event\b",
    r"\bcompletion\b",
    r"\bfence\b",
    r"\bsync\b",
    r"\batomic_\w+\b",
]

GUARD_PATTERNS = [
    r"\baccess_ok\b",
    r"\bIS_ERR\b",
    r"\bIS_ERR_OR_NULL\b",
    r"\bWARN_ON\b",
    r"\bBUG_ON\b",
    r"\bdrm_dev_enter\b",
    r"\bdrm_dev_is_unplugged\b",
    r"\bif\s*\(",
]

FILE_OP_FIELDS = {
    "open": "file_ops",
    "release": "file_ops",
    "unlocked_ioctl": "ioctl",
    "compat_ioctl": "ioctl",
    "ioctl": "ioctl",
    "mmap": "mmap",
    "poll": "file_ops",
    "read": "file_ops",
    "write": "file_ops",
    "llseek": "file_ops",
    "show_fdinfo": "file_ops",
}

DRIVER_FIELDS = {
    "open": "driver",
    "postclose": "driver",
    "lastclose": "driver",
    "debugfs_init": "debugfs",
}


def _is_function_tag(tag: dict[str, Any]) -> bool:
    kind = (tag.get("kind") or "").lower()
    return kind.startswith("function")


def build_function_index(tags_by_file: dict[str, list[dict[str, Any]]]) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    for file_path, tags in tags_by_file.items():
        for tag in tags:
            if not _is_function_tag(tag):
                continue
            name = tag.get("name")
            if not name:
                continue
            index.setdefault(name, []).append({"file": file_path, "line": tag.get("line")})
    return index


def resolve_symbol_location(
    symbol: str,
    file_hint: str | None,
    func_index: dict[str, list[dict[str, Any]]],
) -> tuple[str | None, int | None]:
    entries = func_index.get(symbol, [])
    if not entries:
        return None, None
    if file_hint:
        for entry in entries:
            if entry["file"] == file_hint:
                return entry["file"], entry.get("line")
    entry = entries[0]
    return entry["file"], entry.get("line")


def _iter_numbered_lines(context: str) -> list[tuple[int, str]]:
    lines = []
    for raw in context.splitlines():
        m = re.match(r"^\s*(\d+)\s+(.*)$", raw)
        if not m:
            continue
        lines.append((int(m.group(1)), m.group(2)))
    return lines


def _scan_patterns(lines: list[tuple[int, str]], patterns: list[str]) -> list[dict[str, Any]]:
    hits = []
    for line_no, text in lines:
        for pat in patterns:
            if re.search(pat, text):
                hits.append({"line": line_no, "text": text.strip(), "pattern": pat})
                break
    return hits


def scan_indicators(
    context: str,
    framework_config: FrameworkConfig | None = None
) -> dict[str, list[dict[str, Any]]]:
    """Scan for vulnerability indicators using framework-specific or default patterns."""
    lines = _iter_numbered_lines(context)

    # Use framework config patterns if provided, otherwise fall back to defaults
    if framework_config:
        user_patterns = framework_config.indicator_patterns.get("user_control", USER_CONTROL_PATTERNS)
        lifetime_patterns = framework_config.indicator_patterns.get("lifetime", LIFETIME_PATTERNS)
        concurrency_patterns = framework_config.indicator_patterns.get("concurrency", CONCURRENCY_PATTERNS)
        guard_patterns = framework_config.indicator_patterns.get("guards", GUARD_PATTERNS)
    else:
        user_patterns = USER_CONTROL_PATTERNS
        lifetime_patterns = LIFETIME_PATTERNS
        concurrency_patterns = CONCURRENCY_PATTERNS
        guard_patterns = GUARD_PATTERNS

    return {
        "user_control": _scan_patterns(lines, user_patterns),
        "lifetime": _scan_patterns(lines, lifetime_patterns),
        "concurrency": _scan_patterns(lines, concurrency_patterns),
        "guards": _scan_patterns(lines, guard_patterns),
    }


def _safe_get_group(m: re.Match, group: int) -> str | None:
    """Safely extract a regex group, returning None if group doesn't exist."""
    if m.lastindex is None or group > m.lastindex:
        return None
    try:
        return m.group(group)
    except IndexError:
        return None


def _validate_c_identifier(name: str | None) -> bool:
    """Check if name is a valid C identifier."""
    if not name:
        return False
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name))


# Stricter name-based entrypoint patterns
NAME_ENTRYPOINT_PATTERNS = [
    # ioctl handlers - must end with _ioctl or be exactly named
    (r"^[a-z_]+_ioctl$", "ioctl", "name pattern *_ioctl"),
    (r"^[a-z_]+_unlocked_ioctl$", "ioctl", "name pattern *_unlocked_ioctl"),
    (r"^[a-z_]+_compat_ioctl$", "ioctl", "name pattern *_compat_ioctl"),
    # debugfs - must be debugfs_* or *_debugfs_* entry functions
    (r"^debugfs_(read|write|open|release|show)$", "debugfs", "debugfs callback"),
    (r"^[a-z_]+_debugfs_(open|read|write|show|seq_show)$", "debugfs", "debugfs callback"),
    # mmap handlers
    (r"^[a-z_]+_mmap$", "mmap", "name pattern *_mmap"),
    # vm_ops
    (r"^[a-z_]+_vm_(open|close|fault|huge_fault)$", "vm_ops", "vm_operations callback"),
    # Mali/kbase specific patterns
    (r"^kbase_api_[a-z_]+$", "ioctl", "kbase API handler"),
    (r"^kbase_(open|release|mmap|ioctl)$", "file_ops", "kbase file_ops"),
    (r"^kbasep?_[a-z_]+_debugfs_(open|read|write|show)$", "debugfs", "kbase debugfs"),
]


def extract_entrypoints(
    files: Iterable[str],
    tags_by_file: dict[str, list[dict[str, Any]]],
    framework_config: FrameworkConfig | None = None,
) -> list[dict[str, Any]]:
    """Extract entrypoints using framework-specific or default patterns.

    Hardened version with:
    - Safe regex group extraction
    - C identifier validation
    - Path existence validation
    - Logging for debugging
    - Stricter name-based patterns
    """
    func_index = build_function_index(tags_by_file)
    entrypoints: dict[str, dict[str, Any]] = {}
    extraction_stats = {"pattern_matches": 0, "name_matches": 0, "invalid_names": 0, "file_errors": 0}

    # Build patterns from framework config or use defaults
    compiled_patterns: list[tuple[re.Pattern, str, str, int]] = []  # (regex, category, field, func_group)

    if framework_config:
        # Use framework-specific patterns
        for category, patterns in framework_config.entrypoint_patterns.items():
            for pattern in patterns:
                try:
                    regex = re.compile(pattern.regex)
                    # Determine which group contains the function name (usually 1)
                    func_group = getattr(pattern, 'func_group', 1)
                    compiled_patterns.append((regex, category, pattern.field, func_group))
                except re.error as e:
                    logger.warning(f"Invalid regex pattern in framework config: {pattern.regex}: {e}")
    else:
        # Fall back to hardcoded DRM/Mali patterns
        fops_re = re.compile(
            r"\.(%s)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)"
            % "|".join(sorted(FILE_OP_FIELDS.keys()))
        )
        driver_re = re.compile(
            r"\.(%s)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)"
            % "|".join(sorted(DRIVER_FIELDS.keys()))
        )
        ioctl_re = re.compile(r"DRM_IOCTL_DEF_DRV\([^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)")
        # Mali kbase ioctl patterns
        kbase_ioctl_re = re.compile(r"KBASE_IOCTL_[A-Z_]+")
        kbase_handler_re = re.compile(r"^\s*static\s+int\s+(kbase_api_[a-z_]+)\s*\(")

        # Store as tuples for unified processing: (regex, category, field, func_group)
        compiled_patterns = [
            (ioctl_re, "ioctl", "DRM_IOCTL", 1),
            (fops_re, "file_ops", "file_operations", 2),  # group 2 is func name
            (driver_re, "driver", "drm_driver", 2),  # group 2 is func name
            (kbase_handler_re, "ioctl", "kbase_api", 1),
        ]

    def add_entrypoint(symbol: str, kind: str, file_hint: str | None, line_hint: int | None, reason: str) -> None:
        if not symbol:
            return
        # Validate symbol is a valid C identifier
        if not _validate_c_identifier(symbol):
            extraction_stats["invalid_names"] += 1
            logger.debug(f"Skipping invalid C identifier: {symbol!r}")
            return

        file_path, def_line = resolve_symbol_location(symbol, file_hint, func_index)

        # Validate file path exists
        if file_path is None:
            file_path = file_hint
        if file_path and not Path(file_path).exists():
            logger.debug(f"File not found for symbol {symbol}: {file_path}")
            # Still add it but mark file as unresolved
            pass

        if def_line is None:
            def_line = line_hint

        ep = entrypoints.setdefault(symbol, {
            "symbol": symbol,
            "file": file_path,
            "line": def_line,
            "kinds": set(),
            "reasons": [],
        })
        ep["kinds"].add(kind)
        if reason not in ep["reasons"]:
            ep["reasons"].append(reason)

    for file_path in files:
        try:
            file_p = Path(file_path)
            if not file_p.exists():
                extraction_stats["file_errors"] += 1
                continue
            lines = file_p.read_text(errors="ignore").splitlines()
        except Exception as e:
            extraction_stats["file_errors"] += 1
            logger.debug(f"Error reading file {file_path}: {e}")
            continue

        for idx, line in enumerate(lines, start=1):
            for pattern_re, category, field, func_group in compiled_patterns:
                m = pattern_re.search(line)
                if m:
                    # Safely extract function name from the designated group
                    func_name = _safe_get_group(m, func_group)

                    # For backward compat with old patterns that match field names
                    if not framework_config and category == "file_ops":
                        field_name = _safe_get_group(m, 1)
                        func_name = _safe_get_group(m, 2)
                        if field_name and func_name:
                            kind = FILE_OP_FIELDS.get(field_name, "file_ops")
                            reason = f".{field_name} assignment"
                            extraction_stats["pattern_matches"] += 1
                            add_entrypoint(func_name, kind, file_path, idx, reason)
                    elif not framework_config and category == "driver":
                        field_name = _safe_get_group(m, 1)
                        func_name = _safe_get_group(m, 2)
                        if field_name and func_name:
                            kind = DRIVER_FIELDS.get(field_name, "driver")
                            reason = f".{field_name} assignment"
                            extraction_stats["pattern_matches"] += 1
                            add_entrypoint(func_name, kind, file_path, idx, reason)
                    elif func_name and _validate_c_identifier(func_name):
                        kind = category
                        reason = f"{field} pattern"
                        extraction_stats["pattern_matches"] += 1
                        add_entrypoint(func_name, kind, file_path, idx, reason)

    # Stricter name-based pattern matching
    for symbol in func_index.keys():
        for pattern, kind, reason in NAME_ENTRYPOINT_PATTERNS:
            if re.match(pattern, symbol):
                extraction_stats["name_matches"] += 1
                add_entrypoint(symbol, kind, None, None, reason)
                break  # Only match first pattern

    logger.info(f"Entrypoint extraction stats: {extraction_stats}")

    out = []
    for ep in entrypoints.values():
        out.append({
            "symbol": ep["symbol"],
            "file": ep["file"],
            "line": ep["line"],
            "kinds": sorted(ep["kinds"]),
            "reasons": ep["reasons"][:5],  # Keep more reasons for debugging
        })
    return out


def _parse_ts_query_output(output: str) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    current_file: str | None = None
    capture_re = re.compile(
        r"capture:\s*\d+\s*-\s*call\.name,\s*start:\s*\((\d+),\s*\d+\).*text:\s*`([^`]*)`"
    )
    for raw in output.splitlines():
        if raw and not raw.startswith(" "):
            current_file = raw.strip()
            continue
        if current_file is None:
            continue
        m = capture_re.search(raw)
        if not m:
            continue
        row = int(m.group(1)) + 1
        name = m.group(2).strip()
        if name:
            calls.append({"file": current_file, "line": row, "name": name})
    return calls


def extract_ts_calls(files: Iterable[str]) -> list[dict[str, Any]]:
    if not CALL_GRAPH_QUERY.exists():
        return []
    paths = [str(Path(p).resolve()) for p in files]
    if not paths:
        return []
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as tf:
        for p in paths:
            tf.write(p + "\n")
        paths_file = tf.name

    cmd = [
        "tree-sitter",
        "query",
        str(CALL_GRAPH_QUERY),
        "--scope",
        "source.c",
        "--paths",
        paths_file,
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            return []
        return _parse_ts_query_output(r.stdout)
    finally:
        try:
            Path(paths_file).unlink()
        except OSError:
            pass


def find_enclosing_function(tags_in_file: list[dict[str, Any]], hit_line: int) -> dict[str, Any] | None:
    best = None
    for tag in tags_in_file:
        if not _is_function_tag(tag):
            continue
        line = tag.get("line")
        if line is None:
            continue
        if line <= hit_line:
            best = tag
        else:
            break
    return best


def build_call_graph(
    files: Iterable[str],
    tags_by_file: dict[str, list[dict[str, Any]]],
) -> dict[str, set[str]]:
    calls = extract_ts_calls(files)
    call_graph: dict[str, set[str]] = {}
    for call in calls:
        file_path = call["file"]
        tags_in_file = tags_by_file.get(file_path, [])
        caller = find_enclosing_function(tags_in_file, call["line"])
        if not caller:
            continue
        caller_name = caller.get("name")
        callee_name = call.get("name")
        if not caller_name or not callee_name:
            continue
        call_graph.setdefault(caller_name, set()).add(callee_name)
    return call_graph


def compute_reachability(
    entrypoints: list[dict[str, Any]],
    call_graph: dict[str, set[str]],
    max_depth: int = MAX_GRAPH_DEPTH,
) -> dict[str, dict[str, Any]]:
    reach: dict[str, dict[str, Any]] = {}
    for ep in entrypoints:
        start = ep.get("symbol")
        if not start:
            continue
        queue = [(start, 0, [start])]
        visited = {start}
        while queue:
            node, depth, path = queue.pop(0)
            if depth > max_depth:
                continue
            info = reach.setdefault(node, {
                "distance_min": depth,
                "entrypoints": set(),
                "path": path,
            })
            info["entrypoints"].add(start)
            if depth < info["distance_min"]:
                info["distance_min"] = depth
                info["path"] = path
            if depth == max_depth:
                continue
            for callee in sorted(call_graph.get(node, set())):
                if callee in visited:
                    continue
                visited.add(callee)
                queue.append((callee, depth + 1, path + [callee]))
    return reach


def _score_candidate(
    indicator_counts: dict[str, int],
    distance_min: int | None,
    is_entrypoint: bool,
) -> float:
    score = 0.0
    score += SCORE_WEIGHTS["user_control"] * indicator_counts.get("user_control", 0)
    score += SCORE_WEIGHTS["lifetime"] * indicator_counts.get("lifetime", 0)
    score += SCORE_WEIGHTS["concurrency"] * indicator_counts.get("concurrency", 0)
    if distance_min is not None:
        score += SCORE_WEIGHTS["reachability"] * max(0, (MAX_GRAPH_DEPTH - distance_min + 1))
    if is_entrypoint:
        score += SCORE_WEIGHTS["entrypoint"]
    return score


def score_and_rank_candidates(
    tags_by_file: dict[str, list[dict[str, Any]]],
    entrypoints: list[dict[str, Any]],
    call_graph: dict[str, set[str]],
    extract_body: Callable[[str, int, int], str],
) -> list[dict[str, Any]]:
    func_index = build_function_index(tags_by_file)
    reachability = compute_reachability(entrypoints, call_graph, MAX_GRAPH_DEPTH)
    entrypoint_symbols = {ep["symbol"] for ep in entrypoints}
    candidates = []

    if not reachability:
        for symbol, locations in func_index.items():
            if not locations:
                continue
            location = locations[0]
            file_path = location["file"]
            line = location.get("line") or 1
            context = extract_body(file_path, line, max_lines=400)
            indicators = scan_indicators(context)
            indicator_counts = {
                "user_control": len(indicators["user_control"]),
                "lifetime": len(indicators["lifetime"]),
                "concurrency": len(indicators["concurrency"]),
                "guards": len(indicators["guards"]),
            }
            score = _score_candidate(indicator_counts, None, symbol in entrypoint_symbols)
            candidates.append({
                "file": file_path,
                "symbol": symbol,
                "def_line": line,
                "score": score,
                "priority": "high" if score >= SCORE_THRESHOLDS["high"] else "med" if score >= SCORE_THRESHOLDS["med"] else "low",
                "entrypoints_reaching": [],
                "entrypoints_reaching_it": [],
                "distance_min": None,
                "reachability_path": [],
                "indicator_counts": indicator_counts,
                "indicator_hits": indicators,
                "context": context,
            })
        candidates.sort(key=lambda c: c["score"], reverse=True)
        return candidates[:MAX_CANDIDATES]

    for symbol, reach in reachability.items():
        locations = func_index.get(symbol)
        if not locations:
            continue
        location = locations[0]
        file_path = location["file"]
        line = location.get("line") or 1
        context = extract_body(file_path, line, max_lines=400)
        indicators = scan_indicators(context)
        indicator_counts = {
            "user_control": len(indicators["user_control"]),
            "lifetime": len(indicators["lifetime"]),
            "concurrency": len(indicators["concurrency"]),
            "guards": len(indicators["guards"]),
        }
        score = _score_candidate(indicator_counts, reach.get("distance_min"), symbol in entrypoint_symbols)
        candidates.append({
            "file": file_path,
            "symbol": symbol,
            "def_line": line,
            "score": score,
            "priority": "high" if score >= SCORE_THRESHOLDS["high"] else "med" if score >= SCORE_THRESHOLDS["med"] else "low",
            "entrypoints_reaching": sorted(reach.get("entrypoints", [])),
            "entrypoints_reaching_it": sorted(reach.get("entrypoints", [])),
            "distance_min": reach.get("distance_min"),
            "reachability_path": reach.get("path", []),
            "indicator_counts": indicator_counts,
            "indicator_hits": indicators,
            "context": context,
        })

    candidates.sort(key=lambda c: c["score"], reverse=True)
    return candidates[:MAX_CANDIDATES]


def build_evidence_pack(
    candidate: dict[str, Any],
    func_index: dict[str, list[dict[str, Any]]],
    entrypoints: list[dict[str, Any]],
) -> dict[str, Any]:
    indicators = candidate.get("indicator_hits", {})
    entrypoint_lookup = {ep["symbol"]: ep for ep in entrypoints}
    path_symbols = candidate.get("reachability_path", [])
    path = []
    for symbol in path_symbols:
        locs = func_index.get(symbol, [])
        loc = locs[0] if locs else {}
        path.append({
            "symbol": symbol,
            "file": loc.get("file"),
            "line": loc.get("line"),
        })

    def _lines_for(kind: str) -> list[str]:
        return [f"{hit['line']}: {hit['text']}" for hit in indicators.get(kind, [])][:8]

    return {
        "function_excerpt": candidate.get("context", ""),
        "reachability_path": path,
        "entrypoints_reaching": [
            entrypoint_lookup[name]
            for name in candidate.get("entrypoints_reaching", [])
            if name in entrypoint_lookup
        ],
        "user_controlled_inputs": _lines_for("user_control"),
        "lifetime_model": _lines_for("lifetime"),
        "concurrency_notes": _lines_for("concurrency"),
        "guards_invariants": _lines_for("guards"),
        "indicator_counts": candidate.get("indicator_counts", {}),
    }


def format_reachability_path(path: list[dict[str, Any]]) -> str:
    parts = []
    for node in path:
        if not node.get("symbol"):
            continue
        if node.get("file") and node.get("line"):
            parts.append(f"{node['symbol']} ({Path(node['file']).name}:{node['line']})")
        else:
            parts.append(node["symbol"])
    return " -> ".join(parts)


def extract_json_blob(text: str, want_array: bool) -> str | None:
    """Extract a JSON object or array from text, with validation.

    Hardened version with:
    - JSON validation after extraction
    - Multiple extraction attempts (find last valid JSON if first fails)
    - Logging for debugging
    """
    start_char = "[" if want_array else "{"
    end_char = "]" if want_array else "}"

    # Find all potential start positions
    candidates = []
    pos = 0
    while True:
        start = text.find(start_char, pos)
        if start == -1:
            break
        candidates.append(start)
        pos = start + 1

    if not candidates:
        return None

    # Try each candidate, return first valid JSON
    for start in candidates:
        depth = 0
        in_str = False
        escape = False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
                continue
            if ch == start_char:
                depth += 1
            elif ch == end_char:
                depth -= 1
                if depth == 0:
                    blob = text[start:i + 1]
                    # Validate it's actually valid JSON
                    try:
                        json.loads(blob)
                        return blob
                    except json.JSONDecodeError as e:
                        logger.debug(f"Invalid JSON at position {start}: {e}")
                        break  # Try next candidate

    # Fallback: return first bracket-matched blob even if invalid (for backward compat)
    start = text.find(start_char)
    if start == -1:
        return None
    depth = 0
    in_str = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            continue
        if ch == start_char:
            depth += 1
        elif ch == end_char:
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def normalize_finding_dict(obj: dict[str, Any]) -> dict[str, Any]:
    valid_risks = {"low", "medium", "high", "critical"}

    obj.setdefault("counter_evidence", [])
    obj.setdefault("framework_context", "")
    obj.setdefault("is_false_positive", False)
    obj.setdefault("false_positive_reason", "")
    obj.setdefault("next_questions", [])
    obj.setdefault("evidence", [])
    obj.setdefault("exploitability_notes", "")
    obj.setdefault("risk", "low")
    obj.setdefault("confidence", 0.0)

    if not isinstance(obj.get("counter_evidence"), list):
        obj["counter_evidence"] = []
    if not isinstance(obj.get("next_questions"), list):
        obj["next_questions"] = []
    if not isinstance(obj.get("evidence"), list):
        obj["evidence"] = []
    if not isinstance(obj.get("framework_context"), str):
        obj["framework_context"] = ""
    if not isinstance(obj.get("false_positive_reason"), str):
        obj["false_positive_reason"] = ""
    if not isinstance(obj.get("exploitability_notes"), str):
        obj["exploitability_notes"] = ""

    risk = obj.get("risk")
    if isinstance(risk, str):
        risk_norm = risk.strip().lower()
    else:
        risk_norm = ""
    if risk_norm in valid_risks:
        obj["risk"] = risk_norm
    else:
        obj["risk"] = "low"

    confidence = obj.get("confidence")
    if not isinstance(confidence, (int, float)):
        try:
            obj["confidence"] = float(confidence)
        except (TypeError, ValueError):
            obj["confidence"] = 0.0
    return obj


def batch_iter(items: list[Any], batch_size: int) -> Iterable[list[Any]]:
    for idx in range(0, len(items), batch_size):
        yield items[idx:idx + batch_size]


def run_batched_llm(
    llm: Any,
    items: list[Any],
    build_prompt: Callable[[list[Any]], str],
    parse_response: Callable[[str], list[dict[str, Any]] | None],
    batch_size: int,
    max_calls: int,
) -> tuple[list[dict[str, Any] | None], dict[str, Any]]:
    results: list[dict[str, Any] | None] = []
    notes = {"calls": 0, "skipped": 0, "errors": []}

    for batch in batch_iter(items, batch_size):
        if notes["calls"] >= max_calls:
            notes["skipped"] += len(batch)
            results.extend([None] * len(batch))
            continue
        prompt = build_prompt(batch)
        try:
            resp = llm.invoke(prompt).content
        except Exception as exc:
            notes["errors"].append(str(exc))
            results.extend([None] * len(batch))
            notes["calls"] += 1
            continue
        parsed = parse_response(resp)
        if parsed is None:
            notes["errors"].append("failed to parse JSON response")
            parsed = []
        if len(parsed) < len(batch):
            parsed.extend([None] * (len(batch) - len(parsed)))
        if len(parsed) > len(batch):
            parsed = parsed[:len(batch)]
        results.extend(parsed)
        notes["calls"] += 1
    return results, notes
