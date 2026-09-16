---
name: dsh-automation-tools
description: >-
  Automated testing and fuzzing tools for DeepSeek Harness. Use when setting up
  automated vulnerability scanning, property-based fuzzing, session replay, and
  continuous security testing for dsh deployments.
---

# DeepSeek Harness Automation & Fuzzing

> **授权前提**: 仅对自己拥有的 DeepSeek Harness 部署执行测试

## 攻击面概览 (Testing Surface Map)

| 组件 | 自动化测试入口 | 工具推荐 |
|---|---|---|
| JSON-RPC 协议 | `python/sdk/src/deepseek_harness/client.py` | atheris, hypothesis |
| JSON Schema 验证 | `packages/core/tools/src/json-schema.ts` | fast-check, jq fuzzers |
| Tool 参数 | `packages/core/tools/src/index.ts:655` | AFL, libFuzzer |
| Session 日志 | `packages/core/session/src/` | replay fuzzing |
| Credential YAML | `packages/credentials/credentials-local/src/index.ts:154` | yaml-fuzz |
| Sandbox 参数 | `packages/sandbox/sandbox/src/escalation.ts:51` | property-based testing |
| Workflow VM | `packages/workflow/workflow-worker-thread/src/runtime.ts:72` | JS engine fuzzing |

## 1. JSON-RPC 协议 Fuzz (python/sdk/src/deepseek_harness/client.py)

### 1.1 Message 类型混淆 (client.py:343)

```python
# _handle_message 路径:
# msg_id (str|int) + method (str) → IncomingRequest
# msg_id (str|int) only → response waiter
# method (str) only → Notification

# fuzz 向量:
import json, atheris

def fuzz_rpc_message(data):
    # 1. 类型混淆: id 为 float
    {"jsonrpc": "2.0", "id": 1.5, "result": "ok"}
    
    # 2. id 类型冲突: str vs int
    {"jsonrpc": "2.0", "id": "1", "result": {}}
    {"jsonrpc": "2.0", "id": 1, "result": {}}
    
    # 3. method 注入
    {"jsonrpc": "2.0", "id": "x", "method": "session.prompt\nINJECTED"}
    
    # 4. params 类型混淆
    {"jsonrpc": "2.0", "id": "x", "method": "test", "params": [1,2,3]}
    
    # 5. BigNum DoS
    {"jsonrpc": "2.0", "id": "x" * 10^7, "result": "ok"}
```

### 1.2 订阅竞争 (client.py:343-384)

```python
# _handle_message 中的 notification 分发
# 攻击: 高频通知导致队列溢出

import threading, queue

def fuzz_notification_storm():
    # 并发发送 1000 个 subagent.started notifications
    # 检查 _notification_subscribers 字典竞争
    for i in range(1000):
        notification = Notification(
            method="subagent.started",
            payload={"parentId": f"parent-{i}", "childId": f"child-{i}"}
        )
        client._notification_subscribers[f"sub-{i}"] = (queue.Queue(), None)
```

## 2. JSON Schema Property-Based Fuzzing

### 2.1 Schema 验证边界 (packages/core/tools/src/json-schema.ts:14)

```typescript
// 使用 fast-check 进行属性测试
import fc from 'fast-check';

// oneOf 多匹配攻击
const oneOfArbitrary = fc.record({
  oneOf: fc.array(fc.record({
    type: fc.constant('string'),
    enum: fc.array(fc.string(), { minLength: 1, maxLength: 1 })
  }), { minLength: 2, maxLength: 2 })
  // 两个分支都能匹配 → 验证器行为未定义?

// 类型混淆
const typeConfusionArbitrary = fc.oneof(
  fc.record({ type: ['string'], additionalProperties: false }),
  fc.record({ type: 'object', properties: { __proto__: fc.anything() } }),
  fc.record({ type: 'object', additionalProperties: { type: 'object', properties: { __proto__: { type: 'number' } } } })
);

// 检查: assertSupportedJsonSchema 在 json-schema.ts:140
fc.assert(fc.property(typeConfusionArbitrary, (schema) => {
  try {
    assertSupportedJsonSchema(schema);
    // 如果通过验证 → 检查是否正确拒绝
  } catch (e) {
    // 应当拒绝无效 schema
  }
}));
```

### 2.2 原型污染 Fuzz (packages/core/tools/src/index.ts:655)

```javascript
// 生成原型污染 payload
const protoPayloads = [
  JSON.parse('{"__proto__": {"polluted": true}}'),
  JSON.parse('{"constructor": {"prototype": {"polluted": true}}}'),
  JSON.parse('{"__defineGetter__": "polluted"}'),
  JSON.parse('{["__proto__"]: {"polluted": true}}'),
  JSON.parse('[null, {"__proto__": [{"polluted": true}]}]'),
];

// fuzz 工具参数
for (const payload of protoPayloads) {
  const result = validateJsonSchemaValue(schema, payload, 'args');
  // 检查是否正确拒绝
}
```

## 3. Session Replay Fuzzing

### 3.1 会话日志重放 (packages/core/session/src/)

```bash
# 重放现有 session 日志 — 检查事件序列完整性
# 工具: dsh --session <id> --replay

# fuzz 向量:
# 1. 事件顺序打乱
# 2. 缺失 turn/end 事件
# 3. 缺失 approval/decided
# 4. 审批日志不成对

# 使用快照测试模糊
# packages/下的 tests/ 目录使用 vitest snapshot
# fuzz: 修改 JSONL 文件中的事件顺序 → 重放 → 检查崩溃

python scripts/migrate-packed-session-fixtures.ts
# → 修改 fixture → 重放 → 验证
```

### 3.2 Session ID 枚举

```python
import uuid, itertools

def fuzz_session_ids():
    # 格式: session-<32 hex chars>
    # UUID v4 应不可预测 — 但检查种子
    
    # 攻击 1: 时间基 UUID 预测
    base = uuid.uuid1()  # 如果使用 v1 而非 v4
    
    # 攻击 2: 词表 fuzz
    common_prefixes = ["session-", "sess-", ""]
    for prefix in common_prefixes:
        for suffix_length in range(8, 64, 8):
            # fuzz 长度
            pass
```

## 4. Credential File Fuzzing

### 4.1 YAML Parser Fuzz (packages/credentials/credentials-local/src/index.ts:154)

```python
import atheris

def fuzz_yaml_parser(data):
    """parseCredentialsDocument 在 index.ts:154"""
    try:
        text = data.decode('utf-8', errors='ignore')
        parseCredentialsDocument(text, "/fake/path/.credentials.yaml")
    except:
        pass

# fuzz vector:
# 1. YAML 别名循环: &a [*a, *a, *a, ...]
# 2. Tag 注入: !!js/process.env/DEEPSEEK_API_KEY
# 3. Unicode 歧义: \u0000
# 4. 深度嵌套: {a: {b: {c: {d: ...}}}}
# 5. 巨型单行: key: "AAAA..." (10MB)
```

### 4.2 文件权限 Fuzz

```bash
# fuzz .credentials.yaml 文件权限
for mode in $(seq 0 777); do
  chmod $mode ~/.dsh/.credentials.yaml
  dsh --test-cred-read 2>&1 | grep -v "readable beyond its owner" || echo "BYPASS: $mode"
done

# fuzz: 权限过宽 → assertOwnerOnly 拒绝
# 代码: packages/credentials/credentials-local/src/index.ts:115
# 检查: mode & 0o077 == 0
```

## 5. Sandbox Config Fuzz

### 5.1 Escalation Args Fuzz (packages/sandbox/sandbox/src/escalation.ts:51)

```python
import atheris

def fuzz_escalation_args(data):
    """validateEscalationArgs 在 escalation.ts:51"""
    # 生成所有参数组合
    combinations = [
        (None, None),             # 合法: no escalation
        ("workspace-write", None), # 非法: missing justification
        (None, "reason"),          # 非法: missing sandbox_permissions
        ("", "reason"),            # 非法: empty justification
        ("workspace-write", ""),   # 非法: empty justification
        ("read-only", "reason"),   # 非法: read-only 不是 escalation target
        ("danger-full-access", "reason"),  # 检查 widening
    ]
    
    # fuzz 字符串
    for sp in [fuzzy_string, None, "", "read-only", "../../danger-full-access"]:
        for just in [fuzzy_string, None, "", " " * 10000]:
            try:
                validateEscalationArgs(sp, just)
                print(f"BYPASS: sp={sp}, just={just}")
            except:
                pass
```

### 5.2 Sandbox Mode Fuzz (packages/sandbox/sandbox-policy/src/session-mode.ts:69)

```bash
# setSandboxMode fuzz:
# 1. 非法模式: "full-access" → 应被 Schema 拒绝 (SANDBOX_MODES = ['read-only', 'workspace-write', 'danger-full-access'])
# 2. 事件顺序: sandbox/mode before turn/start
# 3. 并发切换: 两个 session 同时切换 mode
```

## 6. 自动化测试脚本

### 6.1 快速模糊启动脚本

```bash
#!/bin/bash
# fuzz-dsh.sh — 快速 fuzz 启动脚本

# 1. JSON-RPC fuzz
python -m fuzz.rpc_fuzz --host 127.0.0.1 --port 8080 --duration 300

# 2. Schema fuzz  
node scripts/fuzz-json-schema.mjs --iterations 10000

# 3. Sandbox fuzz
node scripts/fuzz-sandbox.mjs --modes "read-only,workspace-write,danger-full-access"

# 4. Credential fuzz
python scripts/fuzz-credentials.py --file ~/.dsh/.credentials.yaml
```

### 6.2 CI 集成 (.github/workflows/security-fuzz.yml)

```yaml
name: Security Fuzz
on: [push, pull_request]
jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - run: pip install atheris fast-check
      - run: pnpm install
      - run: pnpm run build:lib:host
      - run: python fuzz/rpc_fuzz.py
      - run: node fuzz/schema_fuzz.mjs
```

## 7. 验证清单

- [ ] JSON-RPC: id 类型混淆 fuzz (str vs int vs float)
- [ ] JSON Schema: oneOf 多匹配分支 fuzz
- [ ] Tool 参数: 原型污染 payload fuzz
- [ ] Session: 事件顺序打乱重放 fuzz
- [ ] Credential YAML: 别名循环 + tag 注入 fuzz
- [ ] Sandbox: escalation args 组合 fuzz
- [ ] Sandbox mode: 非法模式 fuzz
- [ ] Workflow VM: vm.runInContext 逃逸 fuzz
- [ ] 自动化 CI fuzz 集成