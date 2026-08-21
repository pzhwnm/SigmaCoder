# SigmaCoder Coding Agent Harness

SigmaCoder 的领域是把开发需求转化为受约束、可验证并可由人类安全接收的代码改动。此词汇表统一描述任务、执行事实、门控和交付结果。

## Language

**Coding Task（编码任务）**：
用户可暂停、恢复并最终验收的一项持久开发工作，是 SigmaCoder 的主要业务边界。
_Avoid_：Session、会话、进程

**Agent Run（智能体运行）**：
编码任务的一次连续执行尝试；同一任务可以因暂停、恢复或纠错而包含多次运行。
_Avoid_：Task、Session

**Turn（模型轮次）**：
一次模型请求及其响应；一个轮次可以提出零个或多个工具动作。
_Avoid_：Run、工具调用

**Trajectory Event（轨迹事件）**：
编码任务中已经发生且不可被后续摘要改写的事实记录。
_Avoid_：日志行、聊天消息、状态快照

**Task Workspace（任务工作区）**：
编码任务独占的代码改动空间，与开发者当前工作区隔离。
_Avoid_：原工作区、共享仓库

**Workspace Revision（工作区版本）**：
任务工作区在一次成功变更后形成、可供验证和审查精确引用的代码状态。
_Avoid_：Git Commit、最新代码、当前状态

**Project Instructions（项目指令）**：
目标项目提供的开发规范和禁区说明；它们约束开发行为，但不能授予系统权限。
_Avoid_：安全策略、用户需求

**Runtime State Snapshot（运行状态快照）**：
某一轮开始时，系统向模型提供的当前任务、工作区、审批、验证和预算事实。
_Avoid_：Status Bar、状态栏、Trajectory

**Tool Invocation（工具调用）**：
Agent 提议、经策略判断后由 Harness 执行或拒绝的一次类型化动作。
_Avoid_：命令、Turn

**Tool Observation（工具观测）**：
工具调用产生并反馈给 Agent 的结构化事实，包括成功、失败、拒绝、超时或结果未知。
_Avoid_：异常、模型结论

**Risk Tier（风险等级）**：
依据任务范围或动作影响确定的门控级别，用于选择自动执行、审批和审查要求。
_Avoid_：模型信心、严重程度

**Scope Escalation（范围升级）**：
任务实际影响超出当前获准范围时发生的风险升级，升级后必须暂停新的变更动作。
_Avoid_：失败、重试

**Design Proposal（设计提案）**：
范围升级或中高风险任务在实现前提交的人类可读、机器可校验的变更方案。
_Avoid_：实现计划、随手笔记

**Approval Decision（审批决定）**：
授权主体针对一个确定范围和时限作出的批准或拒绝事实。
_Avoid_：永久权限、口头同意

**Verification Gate（验证门）**：
依据基线和必需检查，判定指定工作区版本是否具备进入审查或提升阶段的证据门槛。
_Avoid_：测试命令、Reviewer 结论

**Verifier Run（验证运行）**：
针对一个确定工作区版本执行的一组客观检查及其结果。
_Avoid_：Verification Gate、Review Run

**Review Run（审查运行）**：
独立 Reviewer 针对一个确定工作区版本进行的一次只读批判性检查。
_Avoid_：自审、Verifier Run

**Model Eligibility Gate（模型准入门）**：
判定一个具体模型候选是否具备承担某个 SigmaCoder 角色所需证据的门槛。
_Avoid_：模型路由、能力矩阵、单次基准分数

**Artifact（制品）**：
由内容哈希标识、可被轨迹引用但不直接内嵌其中的大型结果或证据。
_Avoid_：临时日志、轨迹事件

**OutcomeUnknown（结果未知）**：
系统无法证明一次已开始动作成功或失败的显式状态，必须先对账再决定后续行为。
_Avoid_：失败、超时、可重试

**Reconciliation（对账）**：
依据外部权威事实判定或尝试收敛 `OutcomeUnknown` 的受信过程；结果可以继续保持未知。
_Avoid_：重试、模型判断、补偿操作

**No Progress（无进展）**：
在重复动作和观测中，没有产生新的代码事实、工作区版本、验证改善、计划推进或审批变化。
_Avoid_：工具失败、等待、重复调用

**Promotion Package（提升包）**：
将任务改动及其基准、验证、审查和批准证据冻结在一起，供用户安全接收的不可变交付物。
_Avoid_：Commit、Pull Request、Patch 文件

**Promotion（提升）**：
用户批准后，将提升包中的改动应用到开发者原工作区的受检过程。
_Avoid_：Merge、Push、Deploy
