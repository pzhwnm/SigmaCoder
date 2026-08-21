# 每个 Task 使用独立执行胶囊

每个 Coding Task 独占 Git worktree、Linux 沙盒、命名 PTY、事件流和资源预算；同一 Task 只有一个实现写者，验证器和 Reviewer 只读取绑定 `WorkspaceRevision` 的不可变快照。该边界换取可复现性、并行只读能力和明确冲突语义；代价是必须统一监管编辑器、Shell、插件与后台进程的写权限，并在 workspace 不稳定、Git 基线不忠实或租约丢失时停止验证与提升。
