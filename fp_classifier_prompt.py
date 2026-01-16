"""
Specialized False Positive Classifier Agent Prompts

This agent performs deep analysis to filter out false positives with high confidence.
"""
from typing import Any


def get_fp_classifier_prompt(finding: dict, candidate: dict, framework_config: Any = None) -> str:
    """
    Specialized prompt for false positive classification.

    This is a second-stage validation that focuses specifically on identifying
    false positives with high confidence. More conservative than classify_findings.
    """

    framework_knowledge = ""
    fp_examples = ""
    lifecycle_guarantees = []

    if framework_config:
        framework_knowledge = framework_config.framework_knowledge
        lifecycle_guarantees = framework_config.lifecycle_guarantees

        # Include false positive examples
        if framework_config.false_positive_examples:
            fp_examples = "\n### False Positive 학습 예시\n"
            for ex in framework_config.false_positive_examples:
                fp_examples += f"\n**{ex['title']}**\n"
                fp_examples += f"```c\n{ex['code']}\n```\n"
                fp_examples += f"- ❌ 잘못된 분석: {ex['wrong_analysis']}\n"
                fp_examples += f"- ✓ 올바른 분석: {ex['correct_analysis']}\n"
                fp_examples += f"- 🔑 핵심: {ex['key_insight']}\n"

    # Extract finding details
    title = finding.get('title', 'Unknown')
    risk = finding.get('risk', 'unknown')
    confidence = finding.get('confidence', 0.0)
    rationale = finding.get('rationale', '')
    evidence = finding.get('evidence', [])
    counter_evidence = finding.get('counter_evidence', [])
    framework_context = finding.get('framework_context', '')
    classification = finding.get('classification', 'uncertain')
    classification_rationale = finding.get('classification_rationale', '')

    # Extract candidate details
    function_name = candidate.get('name', 'unknown')
    file_path = candidate.get('from_file', 'unknown')
    line_num = candidate.get('from_line', 0)
    context = candidate.get('context', '')[:1200]  # More context for deep analysis

    return f"""
너는 Linux 커널 정적 분석의 False Positive 전문가다.

**임무**: 아래 분석 결과가 False Positive인지 매우 신중하게 검증하라.

## 판단 기준

### ✗ False Positive로 판단해야 하는 경우 (확신도 높음)

1. **프레임워크가 명시적으로 보장**
   - 커널/프레임워크가 해당 상황을 안전하게 처리
   - 문서화된 보장 사항에 부합
   - 예: postclose는 마지막 콜백, 이후 접근 불가능

2. **코드 패턴이 올바름**
   - 개발자가 권장 패턴을 정확히 따름
   - 에러 처리가 적절히 구현됨
   - 예: debugfs_create 실패해도 안전

3. **컨텍스트 오해**
   - 정적 분석이 런타임 보장을 놓침
   - 선행 조건이 이미 확인됨
   - 예: 함수 진입 전 NULL 체크 완료

4. **False Positive 예시와 유사**
   - 학습 예시와 동일한 패턴
   - 과거에 확인된 오탐

### ✓ True Positive로 판단해야 하는 경우 (보수적)

1. **실제 취약점 증거**
   - Use-after-free, buffer overflow 등 명확
   - Exploit 가능한 경로 존재
   - 프레임워크 보장을 위반

2. **불확실하지만 위험**
   - 확실하지 않으면 True Positive로 간주 (보수적)
   - 추가 조사 필요한 케이스는 유지

## 프레임워크 보장 사항

{chr(10).join(f"- {g}" for g in lifecycle_guarantees) if lifecycle_guarantees else "No specific guarantees"}

## 프레임워크 지식

{framework_knowledge}

{fp_examples}

## Finding 분석 대상

**Title**: {title}
**Risk**: {risk} / **Confidence**: {confidence}
**Current Classification**: {classification}

**Rationale**:
{rationale}

**Classification Rationale**:
{classification_rationale}

**Evidence**:
{chr(10).join(f"- {e}" for e in evidence[:8])}

**Counter Evidence**:
{chr(10).join(f"- {ce}" for ce in counter_evidence[:8])}

**Framework Context**:
{framework_context}

## Code Context

**Function**: `{function_name}`
**Location**: {file_path}:{line_num}

```c
{context}
```

## 출력 형식

JSON:
{{
  "is_false_positive": true|false,
  "confidence": 0.0~1.0,
  "reasoning": "왜 false positive인지 또는 true positive인지 상세히 설명 (3-5 문장)",
  "framework_guarantee_match": "어떤 프레임워크 보장이 적용되는지 (FP인 경우)",
  "similar_to_example": "어떤 FP 예시와 유사한지 (해당되는 경우)",
  "exploit_scenario": "공격 시나리오 (TP인 경우)",
  "recommendation": "다음 단계 추천 (manual review, dismiss, escalate 등)"
}}

**중요**:
- 확신도 높은 False Positive만 필터링
- 의심스러우면 True Positive로 유지 (보수적 접근)
- 프레임워크 보장을 철저히 확인
- False Positive 예시와 비교
""".strip()


def get_batch_fp_classifier_prompt(findings_batch: list[dict], framework_config: Any = None) -> str:
    """
    Batch false positive classification for efficiency.
    """

    framework_knowledge = ""
    lifecycle_guarantees = []

    if framework_config:
        framework_knowledge = framework_config.framework_knowledge
        lifecycle_guarantees = framework_config.lifecycle_guarantees

    findings_text = []
    for i, item in enumerate(findings_batch, 1):
        finding = item.get("finding", {})
        candidate = item.get("candidate", {})

        findings_text.append(f"""
### Finding #{i}
**Title**: {finding.get('title', 'Unknown')}
**Risk**: {finding.get('risk', 'unknown')} / **Confidence**: {finding.get('confidence', 0.0)}
**Classification**: {finding.get('classification', 'uncertain')}
**Function**: `{candidate.get('name', 'unknown')}` ({candidate.get('from_file', 'unknown')})
**Rationale**: {finding.get('rationale', '')[:300]}...
**Evidence**: {', '.join(finding.get('evidence', [])[:3])}
**Counter Evidence**: {', '.join(finding.get('counter_evidence', [])[:2])}
**Framework Context**: {finding.get('framework_context', '')[:200]}
""")

    return f"""
너는 Linux 커널 정적 분석의 False Positive 전문가다.

**임무**: 아래 {len(findings_batch)}개의 분석 결과를 검증하여 False Positive를 걸러내라.

## 판단 기준

### False Positive (확신도 높음)
- 프레임워크가 명시적으로 보장
- 코드 패턴이 올바름
- 컨텍스트 오해
- FP 예시와 유사

### True Positive (보수적)
- 실제 취약점 증거
- 불확실한 경우는 TP로 유지

## 프레임워크 보장

{chr(10).join(f"- {g}" for g in lifecycle_guarantees) if lifecycle_guarantees else "No specific guarantees"}

{framework_knowledge}

## Findings

{''.join(findings_text)}

## 출력 형식

JSON array (정확히 {len(findings_batch)}개):
[
  {{
    "finding_index": 1,
    "is_false_positive": true|false,
    "confidence": 0.0~1.0,
    "reasoning": "상세 설명",
    "framework_guarantee_match": "...",
    "recommendation": "dismiss|manual_review|escalate"
  }},
  ...
]

**중요**: 확신도 높은 FP만 필터링, 의심스러우면 TP 유지
""".strip()
