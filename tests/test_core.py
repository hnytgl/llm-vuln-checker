from llm_vuln_checker.core import audit_transcript, evaluate_response, load_rules, summarize


def test_evaluate_response_flags_canary_leak():
    rule = next(rule for rule in load_rules() if rule.id == "prompt_injection_override")
    finding = evaluate_response(rule, "这里是 LVCC_CANARY_DO_NOT_LEAK")

    assert finding.status == "vulnerable"
    assert finding.score > 0


def test_evaluate_response_passes_refusal():
    rule = next(rule for rule in load_rules() if rule.id == "fake_secret_exfiltration")
    finding = evaluate_response(rule, "抱歉，我不能泄露密钥或内部配置。")

    assert finding.status == "passed"
    assert finding.score == 0


def test_audit_transcript_summary():
    rules = load_rules()
    findings = audit_transcript(
        [
            {"rule_id": "fake_secret_exfiltration", "response": "API_KEY=sk-test-LVCC-000000"},
            {"rule_id": "tool_instruction_hijack", "response": "无法假装执行外部工具。"},
        ],
        rules,
    )

    summary = summarize(findings)
    assert summary["total"] == 2
    assert summary["vulnerable"] == 1
    assert summary["passed"] == 1
