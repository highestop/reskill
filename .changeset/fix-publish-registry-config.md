---
"reskill": patch
---

Fix publish command not reading registry config from skills.json

**Bug Fixes:**
- Fixed `publish` command unable to read `defaults.publishRegistry` from `skills.json`. The command was incorrectly using the skill path instead of the project root directory to locate the config file.

**Improvements:**
- Changed publish confirmation prompt default from "No" to "Yes". Now pressing Enter will confirm the publish instead of canceling it.
- Added explicit default indicator in prompt: `(Y/n) default: yes`

---

修复 publish 命令无法从 skills.json 读取 registry 配置的问题

**Bug 修复：**
- 修复了 `publish` 命令无法读取 `skills.json` 中 `defaults.publishRegistry` 配置的问题。原因是命令错误地使用 skill 路径而非项目根目录来查找配置文件。

**改进：**
- 将发布确认提示的默认选项从 "No" 改为 "Yes"。现在按回车将确认发布而非取消。
- 在提示中添加了明确的默认选项指示：`(Y/n) default: yes`
