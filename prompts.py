"""
LangChain prompt improvements: inject kernel/DRM framework knowledge.
"""
from typing import Any, Literal
import json

# Import framework configuration (optional, for backward compatibility)
try:
    from framework_config import FrameworkConfig
    FRAMEWORK_CONFIG_AVAILABLE = True
except ImportError:
    FRAMEWORK_CONFIG_AVAILABLE = False
    FrameworkConfig = Any  # Type hint fallback

# ====================================
# Few-shot Examples: False Positives
# ====================================
KERNEL_FALSE_POSITIVE_EXAMPLES = """
## False Positive Learning Examples

### Example 1: Framework lifecycle misunderstanding
```c
static void driver_release(struct device *dev) {
    struct my_device *mdev = to_my_device(dev);
    kfree(mdev->buffer);
    kfree(mdev);
    // Is the dev pointer still usable here?
}
```
**Wrong analysis**: dev pointer should be set to NULL to avoid a dangling pointer
**Correct analysis**: release() is the final teardown stage; callers cannot access it afterward, so NULLing is unnecessary
**Key insight**: verify when the framework guarantees no further access

### Example 2: Normal lock release pattern
```c
void process_queue(struct queue *q) {
    spin_lock(&q->lock);
    if (list_empty(&q->list)) {
        spin_unlock(&q->lock);
        return;  // early return
    }
    // ... work ...
    spin_unlock(&q->lock);
}
```
**Wrong analysis**: early return might skip unlocking
**Correct analysis**: all paths release the lock
**Key insight**: track lock symmetry on every path

### Example 3: DRM file operation lifecycle
```c
static void drm_postclose(struct drm_device *dev, struct drm_file *file) {
    struct my_file *priv = file->driver_priv;
    cleanup_resources(priv);
    kfree(priv);
    // file->driver_priv is not set to NULL
}
```
**Wrong analysis**: driver_priv dangling pointer leads to use-after-free
**Correct analysis**: postclose is the final DRM file callback; the file struct is freed afterward
**Key insight**: postclose is the final cleanup stage in the DRM framework
"""

# ====================================
# DRM Framework Knowledge Base
# ====================================
DRM_FRAMEWORK_CHECKLIST = """
## DRM/Kernel Framework Checklist

### DRM file operation lifecycle (strict order)
1. **open** -> allocate driver_priv
2. **ioctl/mmap/poll** -> normal operations (use driver_priv)
3. **postclose** -> cleanup and free driver_priv (final stage)
4. **file struct freed** -> done by the kernel; no access afterward

Important: access to the file struct after postclose is blocked by the framework.

### Reference counting rules
- `kref_get()` / `kref_put()` must be paired
- Check `kref_put()` return value: true means the object was freed
- Do not use a pointer after `kref_put()`

### Locking patterns
- `spin_lock()` / `spin_unlock()` must be balanced on all paths
- `mutex_lock()` / `mutex_unlock()` must be balanced on all paths
- Ensure locks are released on early returns

### GEM/BO object lifecycle
- `drm_gem_object_get()` / `drm_gem_object_put()`: reference count management
- `drm_gem_object_lookup()`: increments ref, must put after use
- Userspace handle access is internally reference-counted

### debugfs
- `debugfs_create_*()` failures are safe
- NULL checks are optional per kernel policy
- No security impact: debugging-only interface
"""

# ====================================
# True Positive Indicators
# ====================================
TRUE_POSITIVE_PATTERNS = """
## Likely vulnerability patterns (check first)

### High-risk patterns
1. **User-controlled size in allocation**
   ```c
   size = user_input;  // no validation
   buf = kmalloc(size, GFP_KERNEL);  // integer overflow -> heap overflow
   ```

2. **Missing bounds check before copy**
   ```c
   copy_from_user(buf, user_ptr, user_size);  // no size check for buf
   ```

3. **TOCTOU (Time-of-check Time-of-use)**
   ```c
   if (check_permission(file))  // check
       use_file(file);           // use (file may change in between)
   ```

4. **Reference count imbalance**
   ```c
   obj = get_object();  // refcount++
   if (error)
       return -EINVAL;  // missing put_object()
   ```

5. **Lock held during user copy**
   ```c
   spin_lock(&lock);
   copy_from_user(buf, user, size);  // copy from userspace while holding lock -> DoS
   spin_unlock(&lock);
   ```

### Medium-risk patterns
- **Unvalidated array index**: `arr[user_index]` without bounds check
- **Missing NULL check**: dereference return value without validation
- **Use after free**: use pointer after free
"""

# ====================================
# Output Requirements
# ====================================
ANALYSIS_OUTPUT_REQUIREMENTS = """
## Output requirements (strict)
- Output must be STRICT JSON only (no prose).
- Provide at least 2 evidence lines with line numbers.
- Provide at least 1 counter-evidence item (why it might be safe).
- Provide exactly 3 next questions with file/symbol references (e.g., "panthor_drv.c:panthor_open").
- Include exploitability_notes (no exploit code).
"""

# ====================================
# Structured Reasoning Guide
# ====================================
STRUCTURED_REASONING_GUIDE = """
## 5-step reasoning guide

### Step 1: Understand control flow
- Identify purpose and call context
- Track input sources and outputs

### Step 2: Framework mapping
- Which lifecycle stage is this in?
- What invariants does the framework guarantee?

### Step 3: Gather counter-evidence
- Why might this be a false positive?
- Are framework guarantees mitigating the issue?

### Step 4: Pattern matching
- Compare against likely vulnerability patterns

### Step 5: Final judgment
- Is the counter_evidence decisive?
"""


def _format_evidence_pack(evidence_pack: dict | None) -> str:
    if not evidence_pack:
        return "none"
    payload = {
        "reachability_path": evidence_pack.get("reachability_path", []),
        "entrypoints_reaching": evidence_pack.get("entrypoints_reaching", []),
        "user_controlled_inputs": evidence_pack.get("user_controlled_inputs", []),
        "lifetime_model": evidence_pack.get("lifetime_model", []),
        "concurrency_notes": evidence_pack.get("concurrency_notes", []),
        "guards_invariants": evidence_pack.get("guards_invariants", []),
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def get_local_triage_prompt(candidate: dict, evidence_pack: dict | None) -> str:
    """Local LLM triage prompt."""
    return f"""
You are a Linux GPU/DRM driver static analysis reviewer.
Evaluate the vulnerability likelihood using the context (code snippet) and evidence pack.
You may speculate, but evidence must cite snippet lines.

{DRM_FRAMEWORK_CHECKLIST}

{TRUE_POSITIVE_PATTERNS}

{ANALYSIS_OUTPUT_REQUIREMENTS}

[Candidate]
name: {candidate.get('name', candidate.get('symbol', 'unknown'))}
from: {candidate.get('from_file', candidate.get('file', 'unknown'))}:{candidate.get('from_line', 0)}

[Evidence Pack]
{_format_evidence_pack(evidence_pack)}

[Context]
{candidate.get('context', 'No context available')}

## Output format (JSON only)
{{
  "title": "concise title (<= 30 chars)",
  "risk": "low|medium|high|critical",
  "confidence": 0.0~1.0,
  "rationale": "summary rationale",
  "evidence": ["line ...", "line ..."],
  "counter_evidence": ["counter point 1"],
  "next_questions": ["file.c:symbol ...", "file.c:symbol ...", "file.c:symbol ..."],
  "framework_context": "DRM/VFS lifecycle and invariants",
  "is_false_positive": true|false,
  "false_positive_reason": "reason if false positive (empty string if none)",
  "exploitability_notes": "conditions/observations/inputs for PoC (no code)"
}}
""".strip()

# ====================================
# Structured Analysis Prompt
# ====================================
def get_structured_analysis_prompt(candidate: dict, finding: dict, evidence_pack: dict | None) -> str:
    """Generate a structured analysis prompt."""
    return f"""
You are a Linux kernel/DRM driver static analysis expert.
Perform the analysis step-by-step and state the conclusion of each step.

{KERNEL_FALSE_POSITIVE_EXAMPLES}

{DRM_FRAMEWORK_CHECKLIST}

{TRUE_POSITIVE_PATTERNS}

{ANALYSIS_OUTPUT_REQUIREMENTS}

---

[Initial analysis result]
{finding}

[Code under analysis]
File: {candidate.get('from_file')}:{candidate.get('from_line')}
Function: {candidate.get('name')}

```c
{candidate.get('context')}
```

[Evidence Pack]
{_format_evidence_pack(evidence_pack)}

---

## Analysis process (step-by-step)

### Step 1: Control flow tracing
- What is the entry point? (ioctl, file_operations, internal function?)
- Where does the data come from? (userspace, other kernel functions?)
- What are the exit conditions?

### Step 2: Framework lifecycle mapping
- Which DRM/VFS lifecycle stage is this?
- What happens in the previous/next stages?
- What invariants does the framework guarantee?

### Step 3: Counter-evidence (critical thinking)
- Why might this vulnerability **not** occur?
- What protections does the framework/kernel provide?
- Are the trigger conditions realistic?

### Step 4: True-positive pattern match
- Does this match the "likely vulnerability patterns" above?
- Is user-controlled input used without validation?
- Is reference counting or locking clearly imbalanced?

### Step 5: Final judgment
- **Evidence (Exploitable)**:
  - [specific evidence 1]
  - [specific evidence 2]

- **Counter-evidence (Not exploitable)**:
  - [framework protections]
  - [unrealistic conditions]

- **Risk re-evaluation**:
  - Original: {finding.get('risk')} / {finding.get('confidence')}
  - Updated: [new_risk] / [new_confidence]
  - Reason: [concise explanation]

---

## Output format (JSON only)
{{
    "title": "concise title (<= 30 chars)",
    "risk": "low|medium|high|critical",
    "confidence": 0.0~1.0,
    "rationale": "final justification (evidence vs counter-evidence)",
    "evidence": ["specific evidence 1", "specific evidence 2"],
    "counter_evidence": ["framework protections", "unrealistic conditions"],
    "next_questions": ["file.c:symbol ...", "file.c:symbol ...", "file.c:symbol ..."],
    "framework_context": "DRM/VFS lifecycle stage and invariants",
    "is_false_positive": true|false,
    "false_positive_reason": "reason if false positive (empty string if none)",
    "exploitability_notes": "conditions/observations/inputs for PoC (no code)"
}}
""".strip()


def get_batch_deep_dive_prompt(batch: list[dict[str, Any]]) -> str:
    """Batch prompt for deep dive. Expects JSON array output aligned to inputs."""
    items = []
    for item in batch:
        items.append({
            "candidate": item.get("candidate", {}),
            "finding": item.get("finding", {}),
            "evidence_pack": item.get("evidence_pack", {}),
        })
    return f"""
You are a Linux kernel/DRM driver static analysis expert.
Analyze each input item and respond with a JSON array of the same length.

{KERNEL_FALSE_POSITIVE_EXAMPLES}

{DRM_FRAMEWORK_CHECKLIST}

{TRUE_POSITIVE_PATTERNS}

{ANALYSIS_OUTPUT_REQUIREMENTS}

[Input array]
{json.dumps(items, ensure_ascii=False, indent=2)}

## Output format
[
  {{
    "title": "concise title (<= 30 chars)",
    "risk": "low|medium|high|critical",
    "confidence": 0.0~1.0,
    "rationale": "summary rationale",
    "evidence": ["line ...", "line ..."],
    "counter_evidence": ["counter point 1"],
    "next_questions": ["file.c:symbol ...", "file.c:symbol ...", "file.c:symbol ..."],
    "framework_context": "DRM/VFS lifecycle stage and invariants",
    "is_false_positive": true|false,
    "false_positive_reason": "reason if false positive (empty string if none)",
    "exploitability_notes": "conditions/observations/inputs for PoC (no code)"
  }}
]
""".strip()

# ====================================
# Self-Critique Prompt
# ====================================
SELF_CRITIQUE_PROMPT = """
You are a security analysis reviewer. Critically re-evaluate the analysis below.

[Original analysis]
{original_analysis}

## Review questions
1. Does this analysis understand the framework behavior correctly?
2. Does it match known false positive patterns?
3. Is there a real exploit path?
4. Are risk/confidence overstated?

## Output (JSON)
{{
    "is_valid": true|false,
    "critique": "critical assessment",
    "adjusted_risk": "low|medium|high|critical",
    "adjusted_confidence": 0.0~1.0,
    "recommendation": "suggested correction"
}}
"""

# ====================================
# Rule-based Filters
# ====================================
FALSE_POSITIVE_RULES = [
    {
        "pattern": r"postclose.*driver_priv.*NULL",
        "reason": "DRM postclose is the final stage; NULLing driver_priv is unnecessary",
        "auto_downgrade": True,
        "target_risk": "low"
    },
    {
        "pattern": r"release.*\(.*\).*free.*NULL",
        "reason": "Release callbacks are the final lifecycle stage",
        "auto_downgrade": True,
        "target_risk": "low"
    },
    {
        "pattern": r"debugfs_create.*NULL.*check",
        "reason": "debugfs APIs are safe even when creation fails",
        "auto_downgrade": True,
        "target_risk": "info"
    },
    {
        "pattern": r"fdinfo.*driver_priv.*NULL",
        "reason": "fdinfo callbacks run only while the file is valid",
        "auto_downgrade": True,
        "target_risk": "low"
    }
]

def apply_false_positive_filter(finding: dict, framework_config: FrameworkConfig | None = None) -> dict:
    """Rule-based false positive filter (framework-aware)."""
    import re

    text = (finding.get("title", "") + " " +
            finding.get("rationale", "")).lower()

    # Use framework config rules if provided, otherwise fall back to defaults
    rules = framework_config.false_positive_rules if framework_config else FALSE_POSITIVE_RULES

    for rule in rules:
        pattern = rule.pattern if hasattr(rule, 'pattern') else rule["pattern"]
        if re.search(pattern, text, re.IGNORECASE):
            reason = rule.reason if hasattr(rule, 'reason') else rule["reason"]
            auto_downgrade = rule.auto_downgrade if hasattr(rule, 'auto_downgrade') else rule["auto_downgrade"]
            target_risk = rule.target_risk if hasattr(rule, 'target_risk') else rule["target_risk"]

            if auto_downgrade:
                finding["risk"] = target_risk
                finding["confidence"] = max(0.3, finding.get("confidence", 0.5) - 0.2)
                finding["rationale"] += f"\n\n[AUTO-FILTER] {reason}"
                finding["is_false_positive"] = True

    return finding


# ====================================
# Framework-Aware Prompt Functions (NEW)
# ====================================

def get_framework_aware_local_triage_prompt(
    candidate: dict,
    evidence_pack: dict | None,
    framework_config: FrameworkConfig
) -> str:
    """Local LLM triage prompt with framework-specific context."""

    # Inject framework-specific context
    role = framework_config.prompt_role
    framework_knowledge = framework_config.framework_knowledge

    # Build false positive examples section
    fp_examples = ""
    if framework_config.false_positive_examples:
        fp_examples = "\n### False Positive Avoidance Examples\n"
        for ex in framework_config.false_positive_examples[:3]:
            fp_examples += f"\n**{ex['title']}**\n"
            fp_examples += f"```c\n{ex['code']}\n```\n"
            fp_examples += f"- Wrong analysis: {ex['wrong_analysis']}\n"
            fp_examples += f"- Correct analysis: {ex['correct_analysis']}\n"
            fp_examples += f"- Key insight: {ex['key_insight']}\n"

    return f"""
You are {role}.
Evaluate the vulnerability likelihood using the context (code snippet) and evidence pack.

{framework_knowledge}
{fp_examples}

{TRUE_POSITIVE_PATTERNS}

{ANALYSIS_OUTPUT_REQUIREMENTS}

[Candidate]
name: {candidate.get('name', candidate.get('symbol', 'unknown'))}
from: {candidate.get('from_file', candidate.get('file', 'unknown'))}:{candidate.get('from_line', 0)}

[Evidence Pack]
{_format_evidence_pack(evidence_pack)}

[Context]
{candidate.get('context', 'No context available')}

## Output format (JSON only)
{{
  "title": "concise title (<= 30 chars)",
  "risk": "low|medium|high|critical",
  "confidence": 0.0~1.0,
  "rationale": "summary rationale",
  "evidence": ["line ...", "line ..."],
  "counter_evidence": ["counter point 1"],
  "next_questions": ["file.c:symbol ...", "file.c:symbol ...", "file.c:symbol ..."],
  "framework_context": "framework lifecycle and invariants",
  "is_false_positive": true|false,
  "false_positive_reason": "reason if false positive (empty string if none)",
  "exploitability_notes": "conditions/observations/inputs for PoC (no code)"
}}
""".strip()


def get_framework_aware_structured_analysis_prompt(
    candidate: dict,
    finding: dict,
    evidence_pack: dict | None,
    framework_config: FrameworkConfig
) -> str:
    """Structured analysis prompt (framework-aware)."""

    role = framework_config.prompt_role
    framework_knowledge = framework_config.framework_knowledge

    # Build false positive examples
    fp_examples_text = ""
    if framework_config.false_positive_examples:
        for ex in framework_config.false_positive_examples[:2]:
            fp_examples_text += f"\n### {ex['title']}\n"
            fp_examples_text += f"- Wrong analysis: {ex['wrong_analysis']}\n"
            fp_examples_text += f"- Correct analysis: {ex['correct_analysis']}\n"

    return f"""
You are {role}.
Below is a local LLM triage result. Perform a 5-step structured analysis based on it.

{framework_knowledge}
{fp_examples_text}

## 5-step reasoning analysis

### Step 1: Understand control flow
- Identify function purpose and call context
- Track input sources and outputs

### Step 2: Framework mapping
- Which lifecycle stage is this code in?
- What invariants does the framework guarantee?

### Step 3: Gather counter-evidence
- Why might this be a false positive?
- Are framework guarantees mitigating the issue?

### Step 4: Pattern matching
{TRUE_POSITIVE_PATTERNS}

### Step 5: Final judgment
- Is counter_evidence decisive?
- Is there a real exploit path?

[Candidate]
name: {candidate.get('name', candidate.get('symbol', 'unknown'))}
from: {candidate.get('from_file', candidate.get('file', 'unknown'))}:{candidate.get('from_line', 0)}

[Local finding]
{json.dumps(finding, ensure_ascii=False, indent=2)}

[Evidence Pack]
{_format_evidence_pack(evidence_pack)}

[Context]
{candidate.get('context', 'No context available')}

## Output format (JSON only)
{{
  "title": "title",
  "risk": "low|medium|high|critical",
  "confidence": 0.0~1.0,
  "rationale": "5-step summary",
  "evidence": ["line ..."],
  "counter_evidence": ["counter point 1"],
  "next_questions": ["file.c:symbol ..."],
  "framework_context": "framework context",
  "is_false_positive": true|false,
  "false_positive_reason": "reason",
  "exploitability_notes": "required conditions"
}}
""".strip()


def get_framework_aware_batch_deep_dive_prompt(
    batch: list[dict[str, Any]],
    framework_config: FrameworkConfig
) -> str:
    """Batch deep-dive prompt (framework-aware)."""

    role = framework_config.prompt_role
    framework_knowledge = framework_config.framework_knowledge

    batch_items = []
    for idx, item in enumerate(batch):
        c = item["candidate"]
        f = item["finding"]
        ev = item.get("evidence_pack", {})

        batch_items.append(f"""
## Candidate {idx + 1}
name: {c.get("name", "unknown")}
from: {c.get("from_file", "unknown")}:{c.get("from_line", 0)}

[Local finding]
{json.dumps(f, ensure_ascii=False, indent=2)}

[Evidence Pack]
{_format_evidence_pack(ev)}

[Context]
{c.get("context", "No context")}
""".strip())

    return f"""
You are {role}.
Below are {len(batch)} local LLM triage results. Deep-dive each one.

{framework_knowledge}

{TRUE_POSITIVE_PATTERNS}

{STRUCTURED_REASONING_GUIDE}

{chr(10).join(batch_items)}

## Output format
JSON array (exactly {len(batch)} items):
[
  {{
    "title": "...",
    "risk": "low|medium|high|critical",
    "confidence": 0.0~1.0,
    "rationale": "...",
    "evidence": ["line ..."],
    "counter_evidence": ["..."],
    "next_questions": ["file.c:symbol", ...],
    "framework_context": "...",
    "is_false_positive": true|false,
    "false_positive_reason": "...",
    "exploitability_notes": "..."
  }},
  ...
]
""".strip()
