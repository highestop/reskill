---
"reskill": minor
---

Add ContentScanner for SKILL.md security scanning

**Changes:**
- New `ContentScanner` module with 6 detection rules: prompt injection, data exfiltration, content obfuscation, sensitive file access, stealth instructions, and oversized content
- Context-aware scanning: skips safe zones (frontmatter, code blocks, blockquotes, inline code, quoted text) to reduce false positives
- Configurable via `ScannerOptions`: override rule levels, disable rules, add custom rules
- Integrated into `reskill publish` — high-risk content blocks publishing, medium-risk shows warnings
- `--dry-run` also runs content scan for author self-checking
- New subpath export `reskill/scanner` for lightweight server-side usage

---

新增 ContentScanner，用于 SKILL.md 内容安全扫描

**变更：**
- 新增 `ContentScanner` 模块，包含 6 类检测规则：prompt injection、数据泄露、内容混淆、敏感文件访问、隐蔽指令、超大内容
- 上下文感知扫描：自动跳过安全区域（frontmatter、代码块、引用、行内代码、引号内文本），降低误报率
- 支持通过 `ScannerOptions` 配置：覆盖规则等级、禁用规则、添加自定义规则
- 集成到 `reskill publish`：高风险内容阻止发布，中风险显示警告
- `--dry-run` 模式也执行扫描，方便作者自检
- 新增子路径导出 `reskill/scanner`，供服务端轻量引入
