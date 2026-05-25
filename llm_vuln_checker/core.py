from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from importlib import resources
from typing import Any, Iterable


SEVERITY_SCORE = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str
    system: str
    prompt: str
    leak_indicators: list[str]
    safe_indicators: list[str]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    severity: str
    status: str
    score: int
    matched: list[str]
    response_preview: str
    latency_ms: int | None = None
    error: str | None = None


def load_rules(path: str | None = None) -> list[Rule]:
    if path:
        raw = open(path, "r", encoding="utf-8").read()
    else:
        raw = resources.files("llm_vuln_checker").joinpath("rules.json").read_text(encoding="utf-8")
    items = json.loads(raw)
    return [Rule(**item) for item in items]


def evaluate_response(rule: Rule, response: str, latency_ms: int | None = None, error: str | None = None) -> Finding:
    if error:
        return Finding(
            rule_id=rule.id,
            category=rule.category,
            severity=rule.severity,
            status="error",
            score=0,
            matched=[],
            response_preview="",
            latency_ms=latency_ms,
            error=error,
        )

    matched = [pattern for pattern in rule.leak_indicators if re.search(pattern, response, re.IGNORECASE)]
    safe_hits = [pattern for pattern in rule.safe_indicators if re.search(pattern, response, re.IGNORECASE)]

    if matched:
        status = "vulnerable"
        score = SEVERITY_SCORE.get(rule.severity, 1)
    elif safe_hits:
        status = "passed"
        score = 0
    else:
        status = "review"
        score = max(SEVERITY_SCORE.get(rule.severity, 1) - 1, 1)

    return Finding(
        rule_id=rule.id,
        category=rule.category,
        severity=rule.severity,
        status=status,
        score=score,
        matched=matched,
        response_preview=response.strip().replace("\n", " ")[:300],
        latency_ms=latency_ms,
    )


def openai_chat_completion(
    endpoint: str,
    api_key: str,
    model: str,
    system: str,
    prompt: str,
    timeout: int = 60,
    extra_headers: dict[str, str] | None = None,
    extra_body: dict[str, Any] | None = None,
) -> str:
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0,
    }
    if extra_body:
        payload.update(extra_body)
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    if extra_headers:
        headers.update(extra_headers)

    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = json.loads(response.read().decode("utf-8"))
    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError(f"Unexpected chat completion response: {data}") from exc


def scan_endpoint(
    endpoint: str,
    api_key: str,
    model: str,
    rules: Iterable[Rule],
    timeout: int = 60,
    extra_body: dict[str, Any] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for rule in rules:
        start = time.perf_counter()
        try:
            response = openai_chat_completion(
                endpoint,
                api_key,
                model,
                rule.system,
                rule.prompt,
                timeout=timeout,
                extra_body=extra_body,
            )
            latency_ms = int((time.perf_counter() - start) * 1000)
            findings.append(evaluate_response(rule, response, latency_ms=latency_ms))
        except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            latency_ms = int((time.perf_counter() - start) * 1000)
            findings.append(evaluate_response(rule, "", latency_ms=latency_ms, error=str(exc)))
    return findings


def audit_transcript(records: Iterable[dict[str, Any]], rules: Iterable[Rule]) -> list[Finding]:
    indexed_rules = {rule.id: rule for rule in rules}
    default_rules = list(indexed_rules.values())
    findings: list[Finding] = []

    for idx, record in enumerate(records, start=1):
        response = str(record.get("response", ""))
        rule_id = record.get("rule_id")
        candidates = [indexed_rules[rule_id]] if rule_id in indexed_rules else default_rules
        for rule in candidates:
            finding = evaluate_response(rule, response)
            findings.append(
                Finding(
                    rule_id=f"{idx}:{finding.rule_id}",
                    category=finding.category,
                    severity=finding.severity,
                    status=finding.status,
                    score=finding.score,
                    matched=finding.matched,
                    response_preview=finding.response_preview,
                    latency_ms=finding.latency_ms,
                    error=finding.error,
                )
            )
    return findings


def summarize(findings: Iterable[Finding]) -> dict[str, Any]:
    items = list(findings)
    return {
        "total": len(items),
        "vulnerable": sum(1 for item in items if item.status == "vulnerable"),
        "review": sum(1 for item in items if item.status == "review"),
        "passed": sum(1 for item in items if item.status == "passed"),
        "error": sum(1 for item in items if item.status == "error"),
        "risk_score": sum(item.score for item in items),
    }


def findings_to_json(findings: Iterable[Finding]) -> str:
    items = list(findings)
    return json.dumps(
        {
            "summary": summarize(items),
            "findings": [item.__dict__ for item in items],
        },
        ensure_ascii=False,
        indent=2,
    )


def findings_to_markdown(findings: Iterable[Finding]) -> str:
    items = list(findings)
    summary = summarize(items)
    lines = [
        "# LLM 漏洞检查报告",
        "",
        f"- 总检查项：{summary['total']}",
        f"- 疑似漏洞：{summary['vulnerable']}",
        f"- 需要人工复核：{summary['review']}",
        f"- 通过：{summary['passed']}",
        f"- 错误：{summary['error']}",
        f"- 风险分：{summary['risk_score']}",
        "",
        "| 规则 | 分类 | 严重性 | 状态 | 命中 | 响应摘要 |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in items:
        matched = ", ".join(item.matched) if item.matched else "-"
        preview = item.error or item.response_preview or "-"
        preview = preview.replace("|", "\\|")
        lines.append(
            f"| {item.rule_id} | {item.category} | {item.severity} | {item.status} | {matched} | {preview} |"
        )
    lines.append("")
    return "\n".join(lines)
