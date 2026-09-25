---
name: aimy-src-hunt
description: >-
  Drive the aimy-skill toolkit through a full SRC / bug-bounty workflow. Use when
  the user wants to hunt or verify vulnerabilities on a target, asks which aimy
  command to run next, or needs the recon -> login -> detect -> verify -> report
  pipeline with the project's own CLI commands.
---

# SKILL: aimy-skill SRC 挖洞全流程

> **定位**：aimy-skill 是**验证判定层**——人工定向找到可疑点后，由它快速确认、取证据、出报告。
> SRC 的洞不是全站乱扫出来的，是"定向找点 + 工具验证"挖出来的。

## 0. RELATED ROUTING

- 具体漏洞打法加载对应知识技能：`sqli-sql-injection`、`idor-broken-object-authorization`、
  `xss-cross-site-scripting`、`ssrf-server-side-request-forgery`、`ssti-server-side-template-injection` 等
- 项目在工作目录中时：命令全量参考 `docs/tool_guide.md`，漏洞打法 `docs/vuln_playbooks.md`，
  报告写作 `docs/report_writing.md`

## 1. 六步工作流

### ① 信息收集

    python main.py recon https://target.com --deep
    python main.py portscan target.com --ports 80,443,8080
    python main.py dirfuzz https://target.com --max 200
    python main.py waf https://target.com            # 先判断有没有 WAF

技术栈决定打法权重：
- PHP + MySQL（老站）→ SQLi、文件包含、上传
- Java + Spring → SpEL / 反序列化 / 越权
- Node + Express → NoSQLi / 原型链污染
- Go → 注入少，重点在逻辑漏洞

### ② 攻击面梳理

    python main.py crawl https://target.com --depth 2 --max-pages 100
    python main.py param-mine https://target.com
    python main.py graphql https://target.com/api/graphql    # GraphQL 在 SRC 中高频

高价值功能点：登录/注册（逻辑绕过）、密码重置（token 可预测）、文件上传、
订单与支付（价格篡改）、API 越权（IDOR / BOLA）、OAuth 与 SSO 回调、导出与下载。

### ③ 认证登录（多数功能在登录后）

    python main.py login --auth-url https://target.com/login --auth-type form \
        --auth-user ACCOUNT --auth-pass PASS --session-file sess.json

之后**所有**检测命令都追加 `--session-file sess.json` 以保持登录态。

### ④ 定向检测（按可疑点选命令）

| 发现的可疑点 | 命令 |
|---|---|
| 数字 id 参数 | `sqlcheck "URL" --session-file sess.json` |
| 注入确认与利用 | `sqli-weaponize "URL" --session-file sess.json` |
| 输出或回显点 | `xsscheck "URL" --session-file sess.json` |
| XSS 防误报复核 | `xss-validate "URL" --session-file sess.json` |
| 命令执行点（ping 等） | `cmdi "URL"` |
| 模板渲染点 | `ssti "URL"` |
| 文件下载与路径参数 | `lfi "URL"` |
| 双账号越权对比 | `idor "URL" --my-id 1001 --other-id 1002 --session-file a.json --session-file-b b.json` |
| 请求走私 | `smuggler URL --exploit` |
| 云凭证泄露 | `cloud-pwn --raw "AKIA..."` |
| 反序列化 / JWT / CRLF | `deser` / `jwt` / `crlf` |

### ⑤ 验证利用
- 工具链自带负对照与误报过滤（`xss-validate`、二阶验证、`false_positive_filter`），
  但出报告前必须人工复测一次
- 越权成立标准：用 A 的 cookie 访问 B 的资源，返回的是 **B 的私有数据**（而非通用占位页）
- SQLi 以 `version()` / `database()` 回显作为验证完成标准，用最小证据链证明即可

### ⑥ 报告
- 要素：接口 + 参数 + payload + 响应差异 + 影响面 + 可复现步骤
- 影响分级参考：个人身份信息 > 订单与交易数据 > 普通业务数据
- 能写入（PUT / DELETE）的危害高于只读，报告中单独说明
- 敏感字段做脱敏处理后再写入报告

## 2. 高频漏洞最小验证链路

- **SQLi**：找到 id 类参数 → `sqlcheck` 初判 → `sqli-weaponize` 确认与取证据；
  核对报错是否为数据库原生错误（含表名/版本），而非框架统一错误页
- **IDOR / BOLA**：双账号录入 → `idor` 对比响应 → 确认返回他人私有字段
- **存储型 XSS**：payload 写入个人资料或评论区 → 换账号访问触发（价值远高于反射型）
- **SSRF / SSTI / CmdI**：先跑对应 detector，以 OOB 回连或时间差作为判定依据
- **业务逻辑**：工具仅作辅助，重点在支付、优惠券、兑换码、状态机流转的人工推演

## 3. 与知识技能协同

检测到具体漏洞类型后，加载对应知识技能获取深入打法，例如：

    命中 SQLi  -> 加载 sqli-sql-injection（SCENARIOS.md 含 SMB OOB、二阶注入）
    命中越权  -> 加载 idor-broken-object-authorization
    命中 WAF   -> 加载 waf-bypass-techniques
    需要出链  -> 加载 reverse-shell-techniques 与 tunneling-and-pivoting