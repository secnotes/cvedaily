# CVE 每日监控

[English](README.md) | [中文](README_CN.md)

自动化的每日CVE监控系统，每日从MITRE CVE收集所有漏洞信息，并生成易于阅读的报告，可以快速自定义筛选高风险漏洞。

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

### UI切换

启用AI精选后，HTML报告侧边栏顶部会显示切换按钮:
- **📋 全部漏洞**: 默认视图，显示所有采集的CVE
- **🤖 AI精选**: AI筛选后的分类视图，包含推荐理由

## 📈 输出文件

执行后，系统会生成:

- `docs/index.html`: 小型静态外壳（约 85 KB）--卡片由 report.js 从当日 JSON 数据按滚动分批渲染，即使单日 3000+ CVE，DOM 也只保留视口附近的卡片；过滤、AI精选切换、中英文切换、深色模式等功能不变
- `docs/assets/report.css|js`: 共享样式与渲染器，按内容哈希做缓存破坏（浏览器跨天复用缓存）
- `docs/data/[year]/cves_[date].json`: 当日完整原始数据--唯一的全量归档，报告页面直接消费
- `docs/ai/[year]/ai_curated_[date].json`: 每日 AI 精选归档，推荐理由和摘要为中英双语（启用AI时生成）；报告的 AI 视图在生成时由此数据派生

说明：每日 Markdown 归档（`docs/reports/`）已被 JSON 数据文件取代；历史报告仍保留在 git 历史中。