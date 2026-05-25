from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .core import audit_transcript, findings_to_json, findings_to_markdown, load_rules, scan_endpoint


DEEPSEEK_ENDPOINT = "https://api.deepseek.com/chat/completions"
DEEPSEEK_DEFAULT_MODEL = "deepseek-v4-flash"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="llm-vuln-checker",
        description="检查常见大模型应用安全风险的防御向命令行工具。",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--rules", help="自定义规则 JSON 文件路径。")
    parser.add_argument("--format", choices=["json", "markdown"], default="markdown", help="报告格式。")
    parser.add_argument("--output", "-o", help="报告输出路径；默认输出到终端。")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="调用 OpenAI 兼容接口执行授权安全检查。")
    scan.add_argument("--rules", default=argparse.SUPPRESS, help="自定义规则 JSON 文件路径。")
    scan.add_argument("--format", choices=["json", "markdown"], default=argparse.SUPPRESS, help="报告格式。")
    scan.add_argument("--output", "-o", default=argparse.SUPPRESS, help="报告输出路径；默认输出到终端。")
    scan.add_argument(
        "--provider",
        choices=["openai-compatible", "deepseek"],
        default="openai-compatible",
        help="接口预设；deepseek 会自动使用 DeepSeek Chat Completions 地址。",
    )
    scan.add_argument("--endpoint", help="Chat Completions 兼容接口，例如 https://api.example.com/v1/chat/completions")
    scan.add_argument("--model", help=f"要检查的模型名；DeepSeek 默认 {DEEPSEEK_DEFAULT_MODEL}。")
    scan.add_argument("--api-key-env", default="OPENAI_API_KEY", help="保存 API Key 的环境变量名。")
    scan.add_argument(
        "--deepseek-thinking",
        choices=["enabled", "disabled"],
        default="disabled",
        help="DeepSeek V4 推理模式；默认 disabled，便于得到更稳定的安全检查输出。",
    )
    scan.add_argument("--timeout", type=int, default=60, help="单条规则请求超时时间，单位秒。")

    audit = subparsers.add_parser("audit-transcript", help="离线审计 JSONL 格式的 prompt/response 日志。")
    audit.add_argument("--rules", default=argparse.SUPPRESS, help="自定义规则 JSON 文件路径。")
    audit.add_argument("--format", choices=["json", "markdown"], default=argparse.SUPPRESS, help="报告格式。")
    audit.add_argument("--output", "-o", default=argparse.SUPPRESS, help="报告输出路径；默认输出到终端。")
    audit.add_argument("path", help="JSONL 文件路径，每行至少包含 response 字段，可选 rule_id 字段。")

    return parser


def read_jsonl(path: str) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"第 {line_no} 行不是合法 JSON：{exc}") from exc
    return records


def write_report(content: str, output: str | None) -> None:
    if output:
        Path(output).write_text(content, encoding="utf-8")
        print(f"报告已写入：{output}")
    else:
        print(content)


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = build_parser()
    args = parser.parse_args(argv)
    rules = load_rules(args.rules)

    if args.command == "scan":
        endpoint = args.endpoint
        model = args.model
        extra_body = None
        if args.provider == "deepseek":
            endpoint = endpoint or DEEPSEEK_ENDPOINT
            model = model or DEEPSEEK_DEFAULT_MODEL
            if args.api_key_env == "OPENAI_API_KEY":
                args.api_key_env = "DEEPSEEK_API_KEY"
            extra_body = {"thinking": {"type": args.deepseek_thinking}}
        elif not endpoint or not model:
            parser.error("使用 openai-compatible provider 时必须同时提供 --endpoint 和 --model。")

        api_key = os.getenv(args.api_key_env)
        if not api_key:
            parser.error(f"环境变量 {args.api_key_env} 未设置。")
        findings = scan_endpoint(endpoint, api_key, model, rules, timeout=args.timeout, extra_body=extra_body)
    elif args.command == "audit-transcript":
        findings = audit_transcript(read_jsonl(args.path), rules)
    else:
        parser.error("未知命令。")

    content = findings_to_json(findings) if args.format == "json" else findings_to_markdown(findings)
    write_report(content, args.output)
    return 1 if any(item.status in {"vulnerable", "error"} for item in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
