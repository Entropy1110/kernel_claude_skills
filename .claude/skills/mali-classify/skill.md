# Mali Classification

Classify findings as True Positive, False Positive, or Uncertain.

## Description

Performs explicit classification:
1. **classify_findings**: Assign TP/FP/Uncertain to each finding
2. **false_positive_classifier**: High-confidence FP detection

Uses 0.8+ confidence threshold for FP filtering.

## Prerequisites

Requires `mali-deep-dive` to be run first.

## Usage

```
/mali-classify --session-id=<session>
```

### Examples

Classify findings:
```
/mali-classify --session-id=panthor-001
```

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `--session-id` | Yes | - | Session ID from deep-dive |

## Output

Updates each finding with:
- **classification**: `true_positive`, `false_positive`, `uncertain`
- **classification_confidence**: Confidence score (0-1)
- **classification_rationale**: Explanation

## Classification Criteria

**True Positive**: Clear exploitation path, user-controllable data
**False Positive**: Framework guarantees prevent issue
**Uncertain**: Requires additional context/review

## Next Steps

After classification:
```
/mali-followup --session-id=<session>  # Optional
/mali-report --session-id=<session>
```
