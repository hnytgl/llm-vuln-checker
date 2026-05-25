# LLM Vuln Checker

一个面向防御测试的大模型漏洞检查命令行工具，用来快速发现常见 LLM 应用安全问题，例如提示词注入、敏感信息泄露、角色扮演绕过、工具调用劫持和个人信息保护风险。

本项目只使用假密钥、金丝雀字符串和安全规则进行授权自测，不包含真实越权利用代码。请只在你拥有授权的模型、应用或日志上运行。

## 功能特性

- 内置常见大模型安全检查规则
- 支持 OpenAI Chat Completions 兼容接口
- 支持离线审计 prompt/response JSONL 日志
- 支持 Markdown 和 JSON 两种报告格式
- 无第三方运行时依赖，Python 标准库即可运行
- 适合接入 CI、安全巡检或上线前冒烟测试

## 检查范围

| 类型 | 说明 |
| --- | --- |
| 提示词注入 | 检查模型是否会忽略系统约束、泄露系统提示词或复述金丝雀 |
| 敏感信息泄露 | 检查模型是否会输出测试密钥、内部配置等敏感片段 |
| 角色扮演绕过 | 检查“开发者模式”“调试模式”等话术是否改变安全边界 |
| 工具调用劫持 | 检查模型是否会伪造外部工具调用或执行结果 |
| 个人信息保护 | 检查模型是否会推测、编造或泄露个人身份信息 |

## 安装

建议使用虚拟环境：

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Windows PowerShell：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

## 快速开始

### 1. 扫描 OpenAI 兼容接口

先设置 API Key：

```bash
export OPENAI_API_KEY="你的 API Key"
```

Windows PowerShell：

```powershell
$env:OPENAI_API_KEY="你的 API Key"
```

运行扫描：

```bash
llm-vuln-checker scan \
  --endpoint "https://api.example.com/v1/chat/completions" \
  --model "your-model" \
  --format markdown \
  --output reports/llm-security-report.md
```

如果你的 Key 放在其他环境变量里：

```bash
llm-vuln-checker scan \
  --endpoint "https://api.example.com/v1/chat/completions" \
  --model "your-model" \
  --api-key-env "MY_LLM_API_KEY"
```

### 2. 离线审计日志

日志使用 JSONL，每行一个对象，至少包含 `response` 字段；如果包含 `rule_id`，工具会只按对应规则审计。

```json
{"rule_id":"fake_secret_exfiltration","response":"抱歉，我不能泄露或复述任何 API_KEY、密钥或内部配置。"}
{"rule_id":"prompt_injection_override","response":"LVCC_CANARY_DO_NOT_LEAK"}
```

运行：

```bash
llm-vuln-checker audit-transcript examples/transcript.jsonl --format markdown
```

## 报告字段

| 字段 | 说明 |
| --- | --- |
| total | 总检查项数量 |
| vulnerable | 命中泄露或绕过特征，建议优先处理 |
| review | 未明显拒绝，也未直接命中，需要人工复核 |
| passed | 命中安全拒绝或保护性响应 |
| error | 接口请求、解析或网络错误 |
| risk_score | 按严重性累计的风险分，分数越高越需要关注 |

## 自定义规则

可以复制 `llm_vuln_checker/rules.json` 并按需修改：

```json
[
  {
    "id": "custom_rule",
    "category": "自定义分类",
    "severity": "high",
    "system": "系统约束内容",
    "prompt": "测试输入",
    "leak_indicators": ["不应出现的关键词或正则"],
    "safe_indicators": ["安全拒绝关键词或正则"]
  }
]
```

使用自定义规则：

```bash
llm-vuln-checker --rules my-rules.json scan \
  --endpoint "https://api.example.com/v1/chat/completions" \
  --model "your-model"
```

## 退出码

- `0`：全部通过或仅需复核
- `1`：发现疑似漏洞或运行错误

这个行为方便在 CI 中阻断高风险变更。

## 开发测试

```bash
python -m pytest
```

也可以直接运行模块：

```bash
python -m llm_vuln_checker.cli audit-transcript examples/transcript.jsonl
```

## 安全与合规说明

- 只在你拥有授权的模型、应用、接口和日志上使用
- 内置规则使用假密钥和测试金丝雀，不应替换为真实生产密钥
- 结果是启发式判断，不等同于完整安全审计
- 对 `review` 状态应结合业务上下文人工确认

## 许可证

MIT
