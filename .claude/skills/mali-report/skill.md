# Mali Report Generation

Generate markdown analysis reports.

## Description

Generates final reports:
- `report.md`: Complete report with all findings
- `report_true_positives.md`: Filtered TPs only
- `state.json`: Full analysis state

## Prerequisites

Requires analysis stages to be completed.

## Usage

```
/mali-report --session-id=<session>
```

### Examples

Generate reports:
```
/mali-report --session-id=panthor-001
```

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `--session-id` | Yes | - | Session ID from analysis |

## Output Files

### `out/report.md`
Complete report with all findings, detailed analysis, risk assessments.

### `out/report_true_positives.md`
Filtered report with validated TPs and uncertain findings only.

### `out/state.json`
JSON export of full analysis state.

## Report Format

```markdown
# Mali Static AI Analysis Report

## Summary
- Total findings: 12
- True Positives: 2
- False Positives: 9
- Uncertain: 1

## Findings
### Finding 1: Use-After-Free in handler_submit
**Risk**: High | **Confidence**: 0.92
...
```

## Workflow Complete

After report generation, analysis is complete.
Delete session when done:
```bash
python mali_skill_runner.py delete-session <session-id>
```
