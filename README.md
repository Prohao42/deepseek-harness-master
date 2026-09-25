# 炸炸酥网安 · DeepSeek Harness

**一个把渗透测试装进 AI Agent 的开源框架。**

项目地址：<https://github.com/Prohao42/deepseek-harness-master>

DeepSeek Harness（`dsh`）是一个插件化的 AI Agent 运行框架——在它这里，**一切皆插件**。底层基于 [Cordis](https://github.com/cordiverse/cordis)，上层把会话、工具、LLM、沙箱、技能全部拆成独立 capability，像搭积木一样组合。本项目在此基础上预装了 **103 个渗透测试技能**，让它从通用 Agent 变成开箱即用的网络安全 AI 工作台。

## 核心亮点

### 103 个渗透技能，开箱即用

覆盖安全测试全链路：

| 方向 | 代表技能 |
|---|---|
| Web 漏洞 | SQL注入、XSS、SSRF、XXE、SSTI、命令注入、文件上传 |
| 绕过技术 | WAF绕过、CSP绕过、401/403绕过、鉴权缺陷、JWT攻击 |
| 内网攻防 | AD域控（Kerberos攻击、ACL滥用、证书服务）、Windows/Linux提权、横向移动、NTLM中继 |
| 云与容器 | K8s渗透、容器逃逸、依赖混淆、子域名接管 |
| 二进制 | 堆利用、栈溢出ROP、内核利用、V8浏览器引擎利用 |
| 密码学 | RSA攻击、格密码、对称密码模式弱点 |
| 移动与AI | Android/iOS渗透、LLM提示注入、智能合约审计 |

每个技能都是结构化 playbook——不是静态知识库，而是 Agent 在测试时**主动加载并按步骤执行**的操作手册。

### 架构即安全

- **一切皆插件**：30+ 个独立包，每个能力（shell、文件系统、沙箱、审批）都是可插拔的 capability seam
- **操作有闸门**：Agent 执行高危操作前有交互式审批机制
- **默认不裸奔**：Web 服务只绑回环地址，硬拒 `0.0.0.0`，内置 DNS rebinding / CSRF 防护
- **会话可审计**：所有模型输入输出落盘为 session log，测试过程完整可回溯

### 一分钟启动

需要 Node.js ^22.19 或 >=24，以及 pnpm（推荐经 corepack）：

```sh
git clone https://github.com/Prohao42/deepseek-harness-master.git
cd deepseek-harness-master
corepack pnpm install
corepack pnpm run build
corepack pnpm dsh --profile web
```

打开 <http://127.0.0.1:3080>，输入 `@sqli-sql-injection` 即可调用对应技能，让 AI 带你走完整条测试链。

> 需要真实对话能力时，在仓库根目录创建 `.env`，写入 `DEEPSEEK_API_KEY=sk-...`。

## 适合谁

- **安全从业者**：把重复性的侦察、验证工作交给 Agent，自己专注决策
- **SRC 选手**：内置 `aimy-src-hunt` 全流程技能，从侦察到报告一条龙
- **学习者**：103 份 playbook 本身就是一份结构化的渗透测试知识库
- **研究者**：插件架构让你可以替换、扩展任何一环，做自己的 Agent 实验

## 合规声明

所有渗透测试技能仅限**授权测试**：本地靶场（DVWA、HTB）、自有资产、SRC 公告范围内使用。未经授权对他人系统进行测试属违法行为。

## 开发

从 [development guide](docs/development.md) 和 [architecture documentation](docs/architecture.md) 开始。

For agents, follow [AGENTS.md](AGENTS.md).

## License

[MIT](LICENSE)

Third-party dependencies and their licenses are disclosed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
