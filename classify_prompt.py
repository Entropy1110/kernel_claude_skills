"""
Classification prompt for explicit false positive / true positive determination.
"""
from typing import Any


def get_classification_prompt(finding: dict, candidate: dict, framework_config: Any = None) -> str:
    """
    Prompt for classifying a finding as true_positive, false_positive, or uncertain.

    This is a separate validation step after initial analysis.
    """

    # Extract framework knowledge if available
    framework_knowledge = ""
    fp_examples = ""

    if framework_config:
        framework_knowledge = framework_config.framework_knowledge

        # Include false positive examples
        if framework_config.false_positive_examples:
            fp_examples = "\n### False Positive 회피 예시\n"
            for ex in framework_config.false_positive_examples[:3]:
                fp_examples += f"\n**{ex['title']}**\n"
                fp_examples += f"```c\n{ex['code']}\n```\n"
                fp_examples += f"- 잘못된 분석: {ex['wrong_analysis']}\n"
                fp_examples += f"- 올바른 분석: {ex['correct_analysis']}\n"
                fp_examples += f"- 핵심 인사이트: {ex['key_insight']}\n"

    return f"""
너는 Linux 커널 정적 분석 결과를 검증하는 전문가다.

아래의 분석 결과(Finding)가 실제 취약점(True Positive)인지, 오탐(False Positive)인지,
또는 확실하지 않은지(Uncertain) 명시적으로 분류해야 한다.

{framework_knowledge}
{fp_examples}

## 분류 기준

### True Positive (실제 취약점)
- 명확한 보안 취약점이 존재
- 공격자가 exploit 가능
- 프레임워크 보장을 위반
- 명확한 증거가 있음

### False Positive (오탐)
- 프레임워크가 이미 안전성을 보장
- 개발자가 올바른 패턴 사용
- 분석 시 컨텍스트를 놓침
- 실제로는 안전한 코드

### Uncertain (불확실)
- 더 많은 컨텍스트 필요
- 호출 경로 분석 필요
- 조건부 취약점 (특정 상황에서만 발생)
- 추가 조사 필요

## Finding 정보

**Title**: {finding.get('title', 'Unknown')}
**Risk**: {finding.get('risk', 'unknown')}
**Confidence**: {finding.get('confidence', 0.0)}

**Rationale**:
{finding.get('rationale', 'No rationale provided')}

**Evidence**:
{chr(10).join(f"- {e}" for e in finding.get('evidence', []))}

**Counter Evidence**:
{chr(10).join(f"- {e}" for e in finding.get('counter_evidence', []))}

**Framework Context**:
{finding.get('framework_context', 'No framework context')}

**Current is_false_positive flag**: {finding.get('is_false_positive', False)}
**Current FP reason**: {finding.get('false_positive_reason', 'N/A')}

## Candidate 정보

**Function**: `{candidate.get('name', 'unknown')}`
**File**: {candidate.get('from_file', 'unknown')}:{candidate.get('from_line', 0)}

**Code Context** (일부):
```c
{candidate.get('context', 'No context')[:800]}
```

## 출력 형식

JSON:
{{
  "classification": "true_positive|false_positive|uncertain",
  "classification_rationale": "명확한 근거 (2-4 문장)",
  "needs_deeper_analysis": true|false,
  "recommended_next_questions": ["file.c:symbol", ...],
  "confidence_adjustment": 0.0~1.0
}}

**주의사항**:
- 프레임워크 보장을 확인하라
- False positive 예시와 비교하라
- 불확실하면 "uncertain" 선택
- needs_deeper_analysis는 uncertain일 때 true 권장
""".strip()


def get_batch_classification_prompt(findings_batch: list[dict], framework_config: Any = None) -> str:
    """
    Batch classification for efficiency.
    """

    framework_knowledge = ""
    if framework_config:
        framework_knowledge = framework_config.framework_knowledge

    findings_text = []
    for i, item in enumerate(findings_batch, 1):
        finding = item.get("finding", {})
        candidate = item.get("candidate", {})

        findings_text.append(f"""
### Finding #{i}
**Title**: {finding.get('title', 'Unknown')}
**Risk**: {finding.get('risk', 'unknown')} / **Confidence**: {finding.get('confidence', 0.0)}
**Function**: `{candidate.get('name', 'unknown')}` ({candidate.get('from_file', 'unknown')})
**Rationale**: {finding.get('rationale', '')[:200]}...
**Evidence**: {', '.join(finding.get('evidence', [])[:3])}
**Counter Evidence**: {', '.join(finding.get('counter_evidence', [])[:2])}
**Current FP flag**: {finding.get('is_false_positive', False)}
""")

    return f"""
너는 Linux 커널 정적 분석 결과를 검증하는 전문가다.

아래 {len(findings_batch)}개의 분석 결과를 각각 true_positive, false_positive, uncertain으로 분류하라.

{framework_knowledge}

## 분류 기준
- **True Positive**: 실제 취약점, exploit 가능
- **False Positive**: 프레임워크 보장으로 안전
- **Uncertain**: 더 많은 분석 필요

## Findings

{''.join(findings_text)}

## 출력 형식

JSON array (정확히 {len(findings_batch)}개):
[
  {{
    "finding_index": 1,
    "classification": "true_positive|false_positive|uncertain",
    "classification_rationale": "...",
    "needs_deeper_analysis": true|false,
    "confidence_adjustment": 0.0~1.0
  }},
  ...
]
""".strip()
