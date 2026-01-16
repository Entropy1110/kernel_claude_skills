# Mali Quick Triage

Quick vulnerability screening of candidates.

## Description

Performs rapid vulnerability triage:
- Analyzes candidates from `mali-map`
- Generates initial findings with risk assessment
- Filters obvious false positives
- Prepares high-priority targets for deep analysis

## Prerequisites

Requires `mali-map` to be run first.

## Usage

```
/mali-triage --session-id=<session>
```

### Examples

Run triage:
```
/mali-triage --session-id=panthor-001
```

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `--session-id` | Yes | - | Session ID from mali-map |

## Output

Updates session with:
- **findings**: List of potential vulnerabilities
  - Risk level (high/medium/low)
  - Confidence score
  - Brief rationale

## Next Steps

After triage, continue with:
```
/mali-deep-dive --session-id=<session>
```
