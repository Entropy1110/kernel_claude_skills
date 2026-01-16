# Mali Iterative Follow-up

Analyze symbols from next_questions iteratively.

## Description

Performs iterative follow-up:
- Extracts `next_questions` from findings
- Resolves symbol locations in codebase
- Performs targeted analysis on related functions
- Discovers additional vulnerabilities in call chains

Supports up to 2 iteration rounds by default.

## Prerequisites

Requires classification to be run first.

## Usage

```
/mali-followup --session-id=<session>
```

### Examples

Run follow-up:
```
/mali-followup --session-id=panthor-001
```

Limit iterations:
```
/mali-followup --session-id=panthor-001 --max-iterations=1
```

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `--session-id` | Yes | - | Session ID from classify |
| `--max-iterations` | No | 2 | Maximum follow-up rounds |

## Output

Updates session with:
- New findings from follow-up analysis
- **analyzed_symbols**: Symbols that were analyzed
- **iteration_count**: Iterations performed

## Next Steps

After follow-up:
```
/mali-report --session-id=<session>
```
