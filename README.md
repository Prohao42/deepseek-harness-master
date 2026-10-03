# 🛡️ DeepSeek Harness

<div align="center">

# 炸炸酥网安 · DeepSeek Harness

### 🚀 AI Agent 驱动的新一代安全测试工作台

**LLM + Security Playbook + Tool Agent + Sandbox**

让 AI Agent 理解安全流程，让渗透测试流程自动化。

<br>

[![GitHub Stars](https://img.shields.io/github/stars/Prohao42/deepseek-harness-master?style=flat-square)](https://github.com/Prohao42/deepseek-harness-master)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D22-blue?style=flat-square)]()
[![Security](https://img.shields.io/badge/security-AI%20Agent-red?style=flat-square)]()

</div>

---

# ✨ 项目介绍

**DeepSeek Harness（dsh）** 是一个插件化 AI Agent 运行框架。

它将：

- 🧠 大语言模型（LLM）
- 🤖 Agent 推理能力
- 🧩 Security Skill Playbook
- 🔧 工具调用系统
- 📦 沙箱执行环境
- 🔐 人工审批机制

组合成一个完整的 AI 安全工作流平台。

不同于传统安全工具集合：

> DeepSeek Harness 不是把工具堆在一起，而是让 Agent 根据任务自动选择技能、规划流程并执行安全验证。

---

## ✨ 联系方式
- **X (Twitter)**：[@Fakerrf5](https://x.com/Fakerrf5)
- **Telegram**：[@Prohao42](https://t.me/Prohao42)
- **抖音**：[炸炸酥~](https://www.douyin.com/user/MS4wLjABAAAAfgxDFsrK3Fgf_PnJRcPeFdjjKnqtLNTR_q4KKKZKHyGlzYz8T3mZf3V4qax05lFb)
- **知识星球**：[@炸炸酥](https://t.zsxq.com/FGUeq)
  ![图片](https://yangdada873.ggff.net/file/1790961984947_7e6b8fe85a9a6c7c6040b281f049902d.jpg)
- **微信公众号**:[炸炸酥渗透测试](https://yangdada873.ggff.net/file/1790961747832_扫码_搜索联合传播样式-标准色版.png)
  ![图片](https://yangdada873.ggff.net/file/1790961747832_扫码_搜索联合传播样式-标准色版.png)
# 🏗️ 系统架构

```
User
                          |
                          v

                  DeepSeek Harness UI

                          |
                          v

                    Agent Runtime

                    (Cordis Engine)

                          |
        +-----------------+----------------+

        |                 |                |

        v                 v                v


      LLM             Skill Engine      Memory

 DeepSeek API       Security         Session
                    Playbooks         Logs


        |                 |

        +-----------------+

                          |

                          v


              Capability Layer


        +---------+----------+---------+

        |         |          |         |

      Shell    Browser    Sandbox   Files


                          |

                          v


              Authorized Testing Target
```

---

# 🚀 核心能力

## 🧠 AI Agent Runtime

基于 Cordis 架构：

- 多能力模块组合
- 动态加载能力
- Agent 工作流编排
- 会话状态管理

---

## 🧩 Security Skill System

内置 **103+ 安全测试技能**。

技能不是静态知识库，而是 Agent 可以主动调用的安全流程。

示例：

```
skills/

├── web-security

│   ├── sql-injection
│   ├── xss
│   ├── ssrf
│   ├── ssti
│   └── upload


├── enterprise-security

│   ├── active-directory
│   ├── kerberos
│   ├── ldap
│   └── privilege-escalation


├── cloud-security

│   ├── kubernetes
│   ├── docker
│   └── cloud-misconfiguration


├── mobile-security

│   ├── android
│   └── ios


└── ai-security

    ├── prompt-injection
    └── llm-security
```

---

# 🔥 支持安全领域

| 分类 | 能力 |
|-|-|
| Web 安全 | SQL Injection、XSS、SSRF、XXE、SSTI |
| 身份安全 | JWT、OAuth、认证绕过 |
| 内网安全 | AD、Kerberos、ACL、横向移动 |
| 系统安全 | Windows/Linux 提权 |
| 云安全 | Kubernetes、Docker、云配置审计 |
| 二进制安全 | 栈溢出、ROP、漏洞分析 |
| 移动安全 | Android/iOS 安全测试 |
| AI 安全 | Prompt Injection、LLM Security |

---

# ⚡ 工作流程

用户输入：

```
分析目标 API 是否存在 SQL 注入风险
```

Agent 自动执行：

```
1. 加载 SQL Injection Skill

        ↓

2. 分析目标接口

        ↓

3. 参数识别

        ↓

4. 安全验证

        ↓

5. 风险评估

        ↓

6. 输出安全报告
```

---



## 默认安全策略

✅ 默认绑定 localhost

✅ 防止 DNS Rebinding

✅ CSRF 防护

✅ Session 审计日志

✅ 操作全过程记录

---

# 📦 快速开始

## 环境要求

```
Node.js >=22

pnpm

DeepSeek API Key
```

安装：

```bash
git clone https://github.com/Prohao42/deepseek-harness-master.git

cd deepseek-harness-master


corepack enable


corepack pnpm install


corepack pnpm run build


corepack pnpm dsh --profile web
```

启动：

```
http://127.0.0.1:3080
```

---

# 🤖 使用示例

输入：

```
@sqli-sql-injection
```

Agent：

```
Loading Skill...

SQL Injection Playbook Ready

Workflow:

✓ Target Analysis

✓ Parameter Detection

✓ Validation

✓ Report Generation
```

---

# 🛠️ 开发自己的 Skill

创建：

```
skills/my-security-skill/

├── skill.yaml

├── workflow.md

├── checklist.md

└── references.md
```

示例：

```yaml
name: my-security-skill


description:

  Custom Security Workflow


steps:

  - analysis

  - validation

  - reporting
```

---

# 🎯 应用场景

## 安全工程师

减少重复测试工作。

## SRC Hunter

自动化：

```
资产发现

↓

漏洞验证

↓

报告生成
```

## 安全学习

103 个 Playbook：

就是结构化安全知识库。


# ⚠️ 合规声明

DeepSeek Harness 仅用于：

✅ 自有资产安全测试

✅ 企业授权测试

✅ CTF / 靶场环境

✅ SRC 明确授权范围

禁止：

❌ 未授权扫描

❌ 未授权攻击

❌ 非法访问第三方系统

使用者必须确保拥有合法授权。

---


## ⭐ 如果项目对你有帮助，欢迎 Star 支持


</div>

