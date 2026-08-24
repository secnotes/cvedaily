<div align="center">

# CVE 每日监控

[English](README.md) | [中文](README_CN.md)

[![Daily Update](https://github.com/secnotes/dailycve/actions/workflows/daily-update.yml/badge.svg)](https://github.com/secnotes/dailycve/actions/workflows/daily-update.yml)
[![Last Commit](https://img.shields.io/github/last-commit/secnotes/dailycve)](https://github.com/secnotes/dailycve/commits)
[![License](https://img.shields.io/github/license/secnotes/dailycve)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-blue)](https://www.python.org/)

自动化的每日CVE监控系统，每日从MITRE CVE收集所有漏洞信息，并生成易于阅读的报告，可以快速自定义筛选高风险漏洞。

</div>

## 🚀 功能特点

- **专注MITRE CVE**: 每日从MITRE CVE数据库及相关源获取所有CVE信息
- **智能过滤**: 基于以下条件识别高风险漏洞:
  - CVSS评分 > 7.0 (高危/严重级别)
  - 列入CISA KEV (已知利用漏洞) 清单
  - EPSS评分 ≥ 0.01 (利用概率)
- **AI精选**: 可选使用OpenAI兼容API智能分类和精选高危漏洞
  - 筛选CVSS ≥ 7.0且有描述信息的漏洞进行AI分析
  - 按领域分类：桌面操作系统、移动安全、IoT、云安全、网络设备、工控、Web安全、数据库与中间件
  - 为每条精选漏洞提供AI生成的推荐理由
- **交互式报告**: 生成丰富的HTML报告，包含多种过滤功能:
  - CVSS严重等级过滤器 (严重、高危、中等、低危)
  - 状态过滤器 (最近修改、新发布)
  - 供应商过滤器，带有"显示更多"功能
  - 针对技术细节的增强型代码块渲染
- **历史归档**: 每日完整原始数据以 JSON 格式按年度归档（`docs/data/`）
- **历史浏览**: 报告页内置日期切换器，客户端加载任意已归档日的数据；URL hash（`#YYYY-MM-DD`）可直接分享链接到某一天；无 AI 精选的日子自动隐藏 AI 视图
- **自动更新**: 通过GitHub Actions定时执行

## ⚙️ 安装设置

1. **克隆仓库**:
   ```bash
   git clone https://github.com/secnotes/dailycve.git
   cd dailycve
   ```

2. **安装依赖**:
   ```bash
   pip install -r requirements.txt
   ```

3. **配置环境 (可选)**:
   ```bash
   cp .env.example .env
   # 在.env文件中添加AI API密钥以启用AI精选功能
   # 需要配置 AI_API_KEY
   ```

4. **本地运行**:
   ```bash
   python src/main.py
   ```

## 🛠️ 配置

系统使用位于 `src/config.py` 的几个配置参数:

- `CVSS_THRESHOLD`: 认为漏洞高风险的最低CVSS评分 (默认: 7.0)
- `EPSS_THRESHOLD`: 高风险分类的最低EPSS评分 (默认: 0.01)
- `LOOKBACK_DAYS`: 查找新CVE的回溯天数 (默认: 1)

## 📊 风险分类标准

满足以下任一条件的漏洞将被识别为高风险:
- CVSS评分 > 7.0 (高危或严重级别)
- 列入CISA KEV (已知利用漏洞清单)
- EPSS评分 ≥ 0.01 (更高的利用可能性)

## 🔧 自定义

您可以通过修改 `src/config.py` 来自定义系统行为:
- 调整风险阈值
- 更改报告输出路径
- 修改数据源URL
- 启用/禁用AI精选

## 🤖 AI精选

系统支持使用OpenAI兼容API对高危漏洞进行智能分类和精选。启用方法:

1. 在 `.env` 文件中添加API密钥:
   ```bash
   # 配置AI API密钥（支持多家API提供商）
   AI_API_KEY=your_api_key_here
   AI_MODEL=gpt-4o-mini
   AI_BASE_URL=https://api.openai.com/v1
   ```
2. 系统将自动执行以下操作:
   - 筛选CVSS ≥ 7.0且描述非空的漏洞
   - 将筛选后的漏洞发送至AI进行分析和分类
   - 生成「AI精选」视图，包含分类漏洞及推荐理由
3. 支持的API提供商：OpenAI、DeepSeek、阿里（DashScope）、月之暗面、智谱（GLM）等兼容OpenAI接口的服务

### AI分类类别

漏洞按以下领域进行分类:

| 类别 | 说明 |
|------|------|
| 💻 桌面操作系统 | Windows、macOS、Linux桌面漏洞 |
| 📱 移动安全 | Android、iOS、移动应用漏洞 |
| 📡 IoT安全 | 路由器、摄像头、嵌入式设备 |
| ☁️ 云安全 | AWS、Azure、GCP、云服务 |
| 🌐 网络设备 | Cisco、Fortinet、网络基础设施 |
| 🏭 工业控制 | SCADA、工业控制系统 |
| 🔐 Web安全 | 浏览器、Web框架、CMS |
| 🗄️ 数据库与中间件 | Oracle、MySQL、Apache、Nginx |
| 📌 其他 | 不属于以上类别的漏洞 |

## ⚠️ 免责声明

本项目是一个**独立的社区项目**，与 MITRE、CVE Program、NVD、CISA 等任何官方漏洞数据库均无关联，也未获得其认可或支持。"CVE" 及 CVE 标志是 The MITRE Corporation 的注册商标。本项目仅对上述来源的公开数据进行汇总，用于信息参考目的。数据的准确性与时效性完全取决于上游来源；如需权威的漏洞信息，请始终以官方来源为准。