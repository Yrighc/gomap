# Release Notes 说明

本目录用于存放 GoMap 的版本发布说明（release notes）。

目标有两个：

- 为 GitHub Release 提供一份可直接复用的 Markdown 文案
- 为后续版本发布保留统一的写作结构，避免每次发版都从零整理

---

## 目录约定

当前推荐按版本号和语言拆分文件：

- 中文版：`docs/release-notes/<tag>-zh.md`
- 英文版：`docs/release-notes/<tag>-en.md`

示例：

- `docs/release-notes/v0.4.6-zh.md`
- `docs/release-notes/v0.4.6-en.md`

如果某次发版只准备中文说明，可以先只维护 `-zh.md`。

---

## 命名规则

文件名中的 `<tag>` 应与最终发布标签保持一致。

例如：

- Git tag 是 `v0.4.6`
- 中文 release notes 文件名应为 `v0.4.6-zh.md`

如果版本尚未最终确定，可以先临时使用：

- `vNext-zh.md`

待最终发版前，再统一重命名为真实 tag。

---

## 推荐结构

每份 release notes 建议保持以下结构：

1. 标题
2. 一行摘要
3. 概览
4. 重点内容
5. 新功能
6. 变更
7. 移除
8. 修复
9. 说明与注意事项
10. 升级与集成
11. 推荐阅读
12. 发布范围说明

其中：

- `概览`
  - 用来说明这次发版的整体方向
- `重点内容`
  - 给读者快速扫一遍这次最重要的变化
- `新功能 / 变更 / 移除 / 修复`
  - 用于按类型归纳具体更新
- `说明与注意事项`
  - 写清楚兼容性、边界和已知限制
- `升级与集成`
  - 说明三方调用方、CLI 用户或依赖升级方式
- `发布范围说明`
  - 明确本次说明是基于哪个 tag 范围整理的

---

## 写作原则

发布说明建议遵循下面几条原则：

- **基于真实 diff，不直接堆 commit 标题**
  - 先看 `git log <old-tag>..HEAD`
  - 再看 `git diff --stat <old-tag>..HEAD`
  - 最后按主题归纳成可读摘要
- **优先描述“用户会感知到什么变化”**
  - 不要只写内部重构名称
  - 要写清楚对调用方、CLI 用户、协议扩展方分别意味着什么
- **把架构变化翻译成维护价值**
  - 例如“执行模型统一”“字典治理收口”“扩展方式固定”
- **保留边界说明**
  - 比如哪些协议还没做
  - 哪些能力仍是兼容模式
  - 哪些抽象只是内部存在，尚未开放为 public API
- **避免过长的逐提交流水账**
  - release notes 应该帮助阅读，不是替代 `git log`

---

## 生成流程

推荐按下面流程整理 release notes：

1. 确认上一个 tag
2. 查看提交范围
3. 查看变更统计
4. 按主题归类
5. 编写 Markdown
6. 校对版本号、tag 范围和升级提示

常用命令：

```bash
git describe --tags --abbrev=0
git log --oneline <old-tag>..HEAD
git diff --stat <old-tag>..HEAD
git diff --name-only <old-tag>..HEAD
```

如果要统计更新规模，也可以使用：

```bash
git rev-list --count <old-tag>..HEAD
git diff --shortstat <old-tag>..HEAD
```

---

## 发布前检查

在正式创建 tag 前，建议至少检查：

- 文件名是否与目标 tag 一致
- 标题中的版本号是否一致
- 对比基线是否写对
- 新增协议、修复点、兼容性提示是否和当前代码一致
- 是否误把 worktree、实验分支或未合并改动写进正式说明

---

## 当前样例

当前目录中的中文样例：

- [v0.4.6-zh.md](/Users/yrighc/work/hzyz/project/GoMap/docs/release-notes/v0.4.6-zh.md)

后续新版本可直接复制这一份，再替换：

- 标题版本号
- 对比基线
- 重点内容
- 协议支持面
- 修复与兼容性说明

---

## 维护建议

建议每次准备发 tag 时：

- 先更新 release notes
- 再创建 tag
- 最后把同一份 Markdown 作为 GitHub Release 正文

这样可以保证：

- 仓库内有版本文档沉淀
- GitHub Release 页面和仓库文档保持一致
- 后续做版本回顾时可以直接引用
