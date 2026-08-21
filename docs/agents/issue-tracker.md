# Issue tracker：GitHub

本仓库的 Issue 和 PRD 使用 GitHub Issues 管理。所有操作使用 `gh` CLI。

## 约定

- **创建 Issue**：`gh issue create --title "..." --body "..."`
- **读取 Issue**：`gh issue view <number> --comments`
- **列出 Issue**：`gh issue list --state open --json number,title,body,labels,comments`
- **评论 Issue**：`gh issue comment <number> --body "..."`
- **添加或移除标签**：`gh issue edit <number> --add-label "..."` 或 `--remove-label "..."`
- **关闭 Issue**：`gh issue close <number> --comment "..."`

仓库身份从 `git remote -v` 推断；在本地仓库内运行时，`gh` 会自动使用对应的 GitHub 仓库。

## 将 Pull Request 作为 triage 请求入口

**否。**

如果以后改为“是”，外部 Pull Request 将和 Issue 使用相同的 triage 标签与状态。只处理 `CONTRIBUTOR`、`FIRST_TIME_CONTRIBUTOR` 或 `NONE`，排除组织成员和协作者提交的 PR。

GitHub 的 Issue 和 Pull Request 共用编号空间。遇到 `#42` 时，应先运行 `gh pr view 42`，失败后再尝试 `gh issue view 42`。

## 当技能要求“发布到 Issue tracker”

创建一个 GitHub Issue。

## 当技能要求“读取相关 ticket”

运行：

`gh issue view <number> --comments`

## Wayfinding 操作

`/wayfinder` 使用一个 Map Issue 和多个子 Issue：

- **Map**：带 `wayfinder:map` 标签的单一 Issue，保存 Notes、Decisions-so-far 和 Fog。
- **子任务**：优先使用 GitHub sub-issue 关联；不可用时，在 Map 的任务列表中引用，并在子 Issue 开头写入 `Part of #<map>`。
- **子任务类型**：使用 `wayfinder:research`、`wayfinder:prototype`、`wayfinder:grilling` 或 `wayfinder:task`。
- **阻塞关系**：优先使用 GitHub 原生 Issue dependencies；不可用时，在子 Issue 开头写入 `Blocked by: #<n>`。
- **Frontier 查询**：从 Map 的开放子任务中排除仍有开放阻塞项或已有负责人者，按 Map 顺序选择第一个。
- **领取任务**：`gh issue edit <n> --add-assignee @me`
- **完成任务**：提交结论评论、关闭 Issue，并将上下文链接追加到 Map 的 Decisions-so-far。
