# Mali Deep Dive Analysis

In-depth vulnerability analysis with structured reasoning.

## Description

Performs comprehensive analysis:
1. **deep_dive**: Detailed reasoning on high-priority findings
2. **self_critique**: Validation to catch false positives

Uses 5-step structured reasoning:
1. Control flow analysis
2. Framework mapping
3. Counter-evidence search
4. Pattern matching
5. Final judgment

## Prerequisites

Requires `mali-triage` to be run first.

## Usage

```
/mali-deep-dive --session-id=<session>
```

### Examples

Run deep analysis:
```
/mali-deep-dive --session-id=panthor-001
```

Limit targets:
```
/mali-deep-dive --session-id=panthor-001 --max-targets=5
```

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `--session-id` | Yes | - | Session ID from triage |
| `--max-targets` | No | 8 | Maximum findings to analyze |

## Output

Updates findings with:
- **deep_analysis**: Detailed reasoning and evidence
- **self_critique_notes**: Validation results
- Adjusted risk/confidence scores
- **next_questions**: Symbols for follow-up

## Next Steps

After deep dive, continue with:
```
/mali-classify --session-id=<session>
```
