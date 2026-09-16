---
name: dsh-cred-audit
description: >-
  Credential audit playbook for DeepSeek Harness. Use when testing the credentials
  local provider, file permission hardening, environment variable shadowing, YAML
  parsing, and secret exposure in logs/transcripts.
---

# DeepSeek Harness Credential Audit Playbook

> **授权前提**: 仅对自己拥有的 DeepSeek Harness 部署执行测试

## 攻击面架构

```
Credential Seam (packages/credentials/credentials/)
├── LocalCredentialProvider (packages/credentials/credentials-local/src/index.ts:206)
│   ├── File: $DSH_HOME/.credentials.yaml (0600)
│   ├── Precedence: env > .credentials.yaml > <cwd>/.env > $DSH_HOME/.env
│   ├── Lock: withFileLock (cross-process writer lock)
│   └── Reload: watcher hot-reload (debounce 100ms)
├── CredentialRef: strict POSIX identifier (credentialRef at index.ts:171)
└── assertOwnerOnly (packages/credentials/credentials-local/src/index.ts:103)
```

## 1. 文件权限测试

### 1.1 权限位检查 (packages/credentials/credentials-local/src/index.ts:87)

```bash
# 检查 ~/.dsh/.credentials.yaml 权限
# 规则: mode & 0o077 == 0 (group/other bits 必须为 0)
# 代码: packages/credentials/credentials-local/src/index.ts:115

# 测试向量:
chmod 644 ~/.dsh/.credentials.yaml
# → 应拒绝: "is readable beyond its owner (mode 644)"

chmod 600 ~/.dsh/.credentials.yaml
# → 应接受

# 边界测试:
# 1. 符号链接攻击
ln -s ~/.dsh/.credentials.yaml /tmp/cred-link
# 检查: assertOwnerOnly 使用 stat() 而非 lstat() — 可能跟随符号链接

# 2. 目录权限
chmod 777 ~/.dsh/
# 目录权限不受 assertOwnerOnly 检查 — 但父目录可被写入
```

### 1.2 Race Condition in Lock (packages/credentials/credentials-local/src/index.ts:384)

```bash
# withFileLock 使用 cross-process writer lock
# 攻击: 锁竞争 — 两个进程同时写入

# 场景: 在锁释放和重新获取之间注入修改
# 代码路径: index.ts:384 → reconcileFromDisk → renderDocument → writeFileAtomic

# 利用: TOCTOU 在 lock release/reacquire 之间
# 1. Process A 持有锁
# 2. Process B 等待锁
# 3. Process A 释放锁
# 4. 外部进程修改 .credentials.yaml
# 5. Process B 获取锁 → reconcileFromDisk 意外接受外部修改
```

## 2. 环境变量污染 (Environment Variable Pollution)

### 2.1 环境优先级绕过

```bash
# 优先级 (packages/credentials/credentials-local/src/index.ts:411-413):
# 1. inherited env (wins, read-only)
# 2. ~/.dsh/.credentials.yaml (provider-managed, writable)
# 3. <cwd>/.env (read-only fallback)
# 4. $DSH_HOME/.env (read-only fallback)

# 攻击 1: 环境变量覆盖存储凭证
export DEEPSEEK_API_KEY="stolen-key"
export ANTHROPIC_API_KEY="proxy-key"
dsh  # 环境变量优先 — 无法从内部修改

# 攻击 2: .env 文件注入
# 在工作目录放置 .env
echo "DEEPSEEK_API_KEY=env-injected" > .env
# 启动 dsh — .env 层被注入

# 攻击 3: 凭证写入时的 Unshadowed 检查绕过
# 代码: packages/credentials/credentials-local/src/index.ts:410-416
# assertUnshadowed 检查 inherited env — 但 Timing Attack 可绕过
```

### 2.2 凭证写入时的 Unshadowed 检查

```typescript
// packages/credentials/credentials-local/src/index.ts:410
// assertUnshadowed: if inherited(ref) !== undefined → reject write
// 攻击: 竞争条件 — 在检查和写入之间注入环境变量

// 利用路径:
// 1. 检查 inherited(DSH_PROVIDER_KEY) → undefined (未设置)
// 2. 切换进程 → 注入 DSH_PROVIDER_KEY=x
// 3. 写入 .credentials.yaml → 被环境变量 shadow
```

## 3. YAML 解析安全 (packages/credentials/credentials-local/src/index.ts:154)

### 3.1 YAML 别名攻击

```yaml
# 代码: parseCredentialsDocument 使用 parseDocument(text, { uniqueKeys: true })
# 攻击: YAML 锚点引用导致循环解析或内存消耗

# 攻击 1: 自引用别名 (锚点限制)
key1: &anchor value
key2: *anchor  # 正常引用
# 但: 锚点不能自引用 — parseDocument 会拒绝

# 攻击 2: 深度嵌套 YAML (栈溢出/内存耗尽)
key:
  - - - - - - - - - - - - - - - - - - - - - - 
    # 嵌套 1000 层 — 可能导致堆栈溢出

# 攻击 3: 类型混淆
key: !!str 123    # 数字 → 字符串 — credentialRef 检查通过
key: !!int "abc" # 应被拒绝 — parseDocument 抛出
```

### 3.2 CredentialRef 验证绕过

```typescript
// 代码: credentialRef(key) 在 index.ts:171
// 验证: key 必须是 POSIX identifier
// 攻击: 特殊字符绕过

# 攻击向量:
key_with_special: "value"  # 检查 credentialRef 接受/拒绝
KEY_WITH_DOTS: "value"     # Unix 环境变量名可含点
key-with-dashes: "value"   # 破折号 — POSIX identifier 允许?
```

## 4. 日志与审计泄露

### 4.1 凭证在日志中的暴露

```
# 检查点: SessionEventMap (packages/core/session/src/)
# 1. agent/request 事件 — 可能包含凭证参数
# 2. tool/result 事件 — 输出可能包含密文
# 3. approval/asked + approval/decided — 审批原因可能泄露上下文
```

### 4.2 环境变量泄露

```bash
# 检查: packages/shell/shell-env/src/index.ts
# DSH_* 和 DEEPSEEK_* 环境变量在沙箱内可见

# 攻击: 通过 bash 工具读取环境变量
bash(command="env | grep DEEPSEEK")
# → 应隐藏敏感变量 — 检查环境注入逻辑

# 攻击: 通过 /proc/self/environ
bash(command="cat /proc/self/environ | tr '\\0' '\\n' | grep API")
```

## 5. 原子写入缺陷 (packages/credentials/credentials-local/src/index.ts:394)

```typescript
// writeFileAtomic 使用 mode 0o600, dirMode 0o700
// 攻击: 写入过程中进程杀死 — 临时文件残留

// 检查: writeFileAtomic 实现
// 1. 写入 .tmp 文件
// 2. rename 到目标
// 3. rename 失败 → .tmp 残留

# 攻击:
# 1. 触发凭证写入
# 2. 立即杀死进程
# 3. 检查残留的 .tmp 文件
ls -la ~/.dsh/.credentials.yaml.tmp*
```

## 6. 验证清单

- [ ] `.credentials.yaml` 权限测试 (600 强制)
- [ ] 符号链接绕过 assertOwnerOnly
- [ ] .env 文件注入 (cwd/.env 和 $DSH_HOME/.env)
- [ ] 环境变量优先级测试 (DEEPSEEK_API_KEY 覆盖)
- [ ] YAML 嵌套深度攻击
- [ ] CredentialRef 验证边界 (特殊字符)
- [ ] 日志中的凭证泄露
- [ ] /proc/self/environ 读取
- [ ] 原子写入残留文件
- [ ] 锁竞争 TOCTOU