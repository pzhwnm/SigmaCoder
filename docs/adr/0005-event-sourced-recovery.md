# 恢复业务状态而不恢复活进程

Task 和 Run 由 SQLite/WAL 只增事件、内容寻址 Artifact 与带事件位置的检查点重建；崩溃后创建后续 Run 和新沙盒，不尝试复活 PTY 或进程。已经开始但没有终态证据的副作用记为 `OutcomeUnknown`，并由受信 Runner 的确定性 `Reconciler` 执行 `Reconciliation`，依据外部权威事实产生成功、失败或仍未知的三态结论；模型只能请求和读取该结果，只有能够证明幂等或未执行时才可重试。这放弃“100% 无缝”和 exactly-once 的表面承诺，换取可审计且不会由模型伪造对账结果的恢复语义。
