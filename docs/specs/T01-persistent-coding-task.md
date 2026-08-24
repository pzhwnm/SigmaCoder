# T01 — 创建并重开持久 Coding Task：Tier 3 可执行 SPEC

## 0. 文档状态

| 字段 | 值 |
|---|---|
| SPEC 版本 | r5 |
| 状态 | 已获人工批准，实施中 |
| 保证等级 | Tier 3（高保证） |
| 来源 Ticket | https://github.com/pzhwnm/SigmaCoder/issues/2 |
| 生成日期 | 2026-08-21 |
| 实现状态 | r4 产品实现与本地测试已完成；r5 正实施等价 mutant 治理并等待同一最终提交的双平台总门 |
| 批准边界 | r5 已于 2026-08-24 获明确批准；允许实施本文精确范围，但不授权合并或发布 |

批准本 SPEC 表示批准本文定义的行为、失败语义、依赖清单、测试门槛和 setup plan；不表示批准向远程仓库 push、创建 PR、合并或发布。行为或 setup 发生实质变化时，必须在文末追加修订记录并重新获得批准。

批准记录：**批准 T01 SPEC r5 等价 mutant 治理修订**。

---

## 1. 规范依据与优先级

本 SPEC 将以下材料收敛为本 Ticket 的可执行契约：

1. GitHub Issue #2 的正文与六条验收标准；
2. 根目录 design.md；
3. CONTEXT.md 的领域词汇；
4. ADR 0001、0002、0004、0005；
5. 本 SPEC 对上述文档未拍定的接口级细节所作的明确选择。

若实现发现本 SPEC 与上位设计存在无法同时满足的冲突，必须停止并提交 SPEC 修订，不能以实现便利为由静默改变契约。

领域用语固定如下：

- **Coding Task**：持久业务边界，不等同于 Session、Agent Run 或操作系统进程。
- **Task Workspace**：某一 Coding Task 独占的 Git linked worktree。
- **Trajectory Event**：只增事实；投影、检查点、索引和看板均不是第二事实源。
- **Checkpoint**：绑定事件位置的派生加速数据；可删除、可重建。
- **Workspace Revision**：编辑后候选树版本；T01 尚不创建 Workspace Revision，也不得把 Git commit 冒充为 Workspace Revision。

---

## 2. 目标与可观察成果

T01 交付“持久 Coding Task 的本地可信核心”：

1. 用户从一个明确的 Git commit 基准创建 Coding Task。
2. 系统分配稳定的 UUIDv4 `task_id`，在当前 data root 内通过数据库唯一约束和路径碰撞检测保证唯一，并创建 detached Task Workspace。
3. 系统使用 SQLite/WAL 中的只增事件保存 Task 事实，生成可重建投影和检查点。
4. 创建进程退出后，另一个全新的操作系统进程能够从同一 data root 执行 list/status，并从权威事件重建相同的可投影状态。
5. 重建前验证逐 Task 逻辑 sequence、哈希链及事件语义；缺失、重复、篡改或不兼容 schema 必须明确失败。
6. 用户当前 worktree 的内容、index、HEAD、当前分支引用和 Git 状态不被 Task 创建改变。
7. 输出明确说明：活进程、PTY、内存、Shell 局部状态及未完成网络事务没有被恢复。

### 2.1 T01 完成后的状态

成功执行 task start 后：

- lifecycle_state 固定为 PREPARING；
- health 为 HEALTHY；
- preparation.workspace 为 READY；
- preparation.event_store 为 READY；
- preparation.sandbox 为 NOT_REQUIRED_FOR_READ_ONLY_ANALYSIS；
- preparation.agent_run 为 NOT_STARTED。

T01 不得把 Task 推进到 ANALYZING。T02 可以在不启动执行沙盒的前提下，为 `workspace`、`search` 及已验证 Artifact 读取建立显式的只读/no-exec profile，并据此把 Task 推进到 ANALYZING；该 profile 禁止 `process`、`terminal`、`interpreter`、`edit`、网络、凭据及任何插件执行。`edit` 与 Workspace Revision 等待 T04，真实 OCI 中的 `process`/`interpreter` 等执行能力等待 T05，Agent Run 的通用重启编排等待 T03。

这是一项为解除 T01→T02→T05 增量实施环而作出的状态机澄清。批准后、进入第一个 RED 前，必须在同一 setup checkpoint 中把 `PREPARING` 的“沙盒”语义同步到 `design.md`：只读/no-exec 分析不要求执行沙盒，任何执行型能力仍必须等待符合设计的 SandboxDriver。若无法同步上位设计，实施必须暂停并修订本 SPEC，不能只在代码里形成隐含例外。

### 2.2 核心不变量

1. 基准在创建早期解析一次并冻结为完整 commit OID；后续分支移动不得改变 Task 基准。
2. 每个 Task 使用 UUIDv4 标识；data root 中的数据库对 `task_id` 和 `event_id` 强制唯一，workspace 槽位在创建前后都进行规范化路径与碰撞检测。
3. 每个 Task 的 sequence 从 1 开始、严格连续、唯一递增。
4. 已提交 Trajectory Event 禁止 UPDATE 或 DELETE。
5. 所有投影和检查点都可由有效事件链确定性重建。
6. Checkpoint 损坏时可完整重放；Trajectory Event 损坏时必须 fail closed。
7. Task 数据根和 Task Workspace 不得位于用户当前 worktree 或其 Git common directory 内。
8. Task 创建不得隐式包含 staged、unstaged、untracked 或 ignored 内容。
9. 普通 SHA-256 哈希链只用于当前信任模型下的完整性检测；不得宣称它能抵抗拥有数据库写权限并重算整条链的攻击者。
10. T01 的“重开”只恢复业务投影，不恢复活进程。

---

## 3. 范围

### 3.1 本 Ticket 包含

- Git 仓库与 commit 基准校验；
- commit-ish 到不可变 commit OID 的冻结；
- dirty source 的显式排除确认；
- detached linked worktree 的安全创建；
- Task 创建授权事件、半创建采纳判定与可见失败；
- 最小 Task 生命周期事件；
- SQLite/WAL 只增事件、投影和检查点；
- 事件规范化、sequence 校验和哈希链校验；
- task start、task list、task status；
- 版本化 JSON 机器接口；
- 正常跨进程重开；
- 创建阶段故障注入、并发、属性、变异与对抗测试；
- 原工作区零业务改动证明。

### 3.2 明确不包含

- Project Instructions、Runtime State Snapshot、Runtime State Delta、Artifact 完整能力、公共 Tool Invocation/Observation 信封和模型替身：T02；
- Agent Run 的 pause/resume/attach/cancel、真实终止旧 Runner、启动新 Runner 及可复用 S2 进程故障 Harness：T03；
- 编辑与 Workspace Revision：T04/T06；
- rootless OCI SandboxDriver：T05；
- 编辑事务前滚/回滚：T06；
- Linter、测试门、Reviewer、验证豁免与 Promotion；
- OutcomeUnknown 与确定性 Reconciliation：T14；
- PTY、后台服务、网络、凭据、控制面同步、插件和 MCP；
- 将 dirty working tree 内容导入 Task；
- 源 Git common directory 被删除后的自动迁移；
- 对恶意管理员重写整库并重算所有哈希的检测；
- exactly-once Task 创建。没有调用方幂等键时，每次成功调用只保证创建一个新的唯一 Task。

---

## 4. 公共 CLI 契约

### 4.1 命令

T01 新增以下公共命令：

    sigma task start \
      --repo PATH \
      --baseline COMMITISH \
      --objective TEXT \
      [--acknowledge-excluded-changes] \
      [--data-root PATH] \
      [--json]

    sigma task list [--data-root PATH] [--json]

    sigma task status TASK_ID [--data-root PATH] [--json]

规则：

- --repo 必须解析为现有 Git worktree。
- --baseline 必须解析为 commit 对象；tag 可接受，tree/blob 不接受。
- --objective 必须是 Unicode NFC 后 1 至 4096 个字符；空白字符串拒绝。
- --data-root 显式值优先，其次读取 SIGMACODER_DATA_ROOT，最后使用平台默认的用户本地状态目录。
- data root 规范化后不得落在源 worktree、Git common directory 或已有 Task Workspace 内。
- --json 模式禁止交互提示。stdout 只输出一个 UTF-8 JSON 文档；诊断和日志只写 stderr。
- 非 JSON 模式可以提供人类可读展示，但不得改变业务语义。
- attach 不属于 T01。

### 4.2 Dirty source 语义

如果源 worktree 存在 staged、unstaged、untracked 或 ignored 变化：

- 未提供 --acknowledge-excluded-changes 时，start 以 DIRTY_SOURCE_REQUIRES_ACK 失败且不产生 Task；
- 提供该参数时，只从已冻结 commit 创建 Task；
- 输出必须包含 source_dirty=true 和 dirty_content_included=false；
- 当前 worktree 的任何未提交内容都不得复制到 Task Workspace。

### 4.3 版本化 JSON 外壳

成功外壳：

    {
      "schema_version": 1,
      "command": "task.start",
      "ok": true,
      "data": {},
      "error": null
    }

普通失败外壳：

    {
      "schema_version": 1,
      "command": "task.status",
      "ok": false,
      "data": null,
      "error": {
        "code": "EVENT_HASH_MISMATCH",
        "message": "事件哈希校验失败。",
        "details": {}
      }
    }

稳定字段为 schema_version、command、ok、data、error、error.code 及本节定义的 TaskViewV1 字段。中文 message 可改善措辞，但不得承载机器唯一可判定的信息。schema v1 可新增可选字段，不得删除字段、改名或改变既有字段类型。

`data` 的 v1 类型是条件联合，而不是“失败时永远为 null”：

- `ok=true` 时，`data` 必须是与 command 匹配的成功对象，`error` 必须为 null；
- 普通 `ok=false` 时，`data` 必须为 null，`error` 必须存在；
- 只有 `PARTIAL_INTEGRITY_FAILURE`、`WORKSPACE_UNAVAILABLE`、`WORKSPACE_BASELINE_MISMATCH`、`TASK_PREPARATION_FAILED`、`CREATION_RECOVERY_REQUIRED` 可以在 `ok=false` 时返回经验证的非 null `data`；
- 上述部分数据不得包含未通过事件链、typed payload、causation 和状态转换校验的业务字段；
- 任何其他错误码携带非 null `data` 都是 schema 失败。

公共 JSON Schema 必须作为版本化 Artifact 交付，至少分别约束 envelope、TaskViewV1、list 结果和 error；CLI 契约测试使用 `jsonschema` 对每个成功、普通失败和允许部分数据的失败样例执行验证。实现内部模型不能代替已发布 JSON Schema。

### 4.4 TaskViewV1

start 和 status 的 data.task，list 中每个成功条目的 task，至少包含：

    {
      "task_id": "UUIDv4",
      "objective": "字符串",
      "lifecycle_state": "PREPARING",
      "health": "HEALTHY",
      "baseline": {
        "repository_realpath": "绝对规范化路径",
        "git_common_dir_realpath": "绝对规范化路径",
        "object_format": "sha1 或 sha256",
        "commit_oid": "完整小写 OID",
        "source_dirty": false,
        "dirty_content_included": false
      },
      "workspace": {
        "kind": "git_linked_worktree",
        "mode": "DETACHED",
        "path": "绝对规范化路径",
        "head_oid": "完整小写 OID",
        "availability": "AVAILABLE"
      },
      "preparation": {
        "workspace": "READY",
        "event_store": "READY",
        "sandbox": "NOT_REQUIRED_FOR_READ_ONLY_ANALYSIS",
        "agent_run": "NOT_STARTED"
      },
      "event_position": {
        "sequence": 4,
        "event_hash": "64 位小写十六进制"
      },
      "checkpoint": {
        "through_sequence": 4,
        "through_event_hash": "64 位小写十六进制",
        "load_mode": "CREATED、CHECKPOINT 或 FULL_REPLAY"
      },
      "runtime": {
        "process_restored": false,
        "terminal_restored": false,
        "memory_restored": false,
        "network_transaction_restored": false
      }
    }

TaskViewV1 的 `workspace` 与 `preparation.workspace` 必须由版本化 JSON Schema 使用互斥 `oneOf` 表达，至少包含以下状态；禁止自由组合这些字段：

1. **成功准备**：lifecycle_state=PREPARING、health=HEALTHY、workspace.availability=AVAILABLE、workspace.head_oid 为完整 OID 字符串、preparation.workspace=READY、sandbox=NOT_REQUIRED_FOR_READ_ONLY_ANALYSIS。
2. **确定从未建成**：只有 TaskWorkspaceProvisioningFailedV1 已证明 workspace 未创建时可用；lifecycle_state=NEEDS_ATTENTION、health=NEEDS_ATTENTION、workspace.availability=NOT_CREATED、workspace.head_oid=null、preparation.workspace=FAILED。
3. **恢复状态不确定**：路径、Git 管理反向指针、HEAD、baseline、clean/no-extra-files、nonce 或 action digest 任一证据缺失/冲突时使用；lifecycle_state=NEEDS_ATTENTION、health=NEEDS_ATTENTION、workspace.availability=UNVERIFIED、preparation.workspace=RECOVERY_REQUIRED。`head_oid` 只能为 null，或为在不采纳 workspace 的前提下已独立验证格式和来源的完整 OID；它绝不表示 workspace 已可信。
4. **成功准备后的丢失**：lifecycle_state=NEEDS_ATTENTION、health=NEEDS_ATTENTION、workspace.availability=MISSING、workspace.head_oid=null、preparation.workspace=READY；READY 仅陈述历史 Prepared 事实，不表示当前可用。
5. **成功准备后的基准漂移**：lifecycle_state=NEEDS_ATTENTION、health=NEEDS_ATTENTION、workspace.availability=BASELINE_MISMATCH、workspace.head_oid 为已验证的当前完整 OID、preparation.workspace=READY；不得把该 OID覆盖到 baseline 事实。

`TASK_PREPARATION_FAILED` 只允许返回“确定从未建成”变体；`CREATION_RECOVERY_REQUIRED` 只允许返回“恢复状态不确定”变体；`WORKSPACE_UNAVAILABLE` 与 `WORKSPACE_BASELINE_MISMATCH` 分别只允许返回后两种已 Prepared 退化变体。Schema 必须拒绝 AVAILABLE+null head、NOT_CREATED+READY、UNVERIFIED+HEALTHY 等矛盾组合。

若事件链有效但 workspace 丢失或 HEAD 不等于基准：

- status 仍返回已知 Task 事实；
- health 为 NEEDS_ATTENTION；
- workspace.availability 为 MISSING 或 BASELINE_MISMATCH；
- MISSING 时退出 3、`ok=false`、`error.code=WORKSPACE_UNAVAILABLE`；BASELINE_MISMATCH 时退出 3、`ok=false`、`error.code=WORKSPACE_BASELINE_MISMATCH`；
- `data.task` 只包含已通过完整语义校验的 TaskViewV1，不能把错误 workspace 的当前内容当作 Task 事实；
- 不得自动在其他位置重建 workspace；
- 不得宣称 Task 可继续执行。

若 Task 创建的前三个授权事实已经耐久，但 workspace 准备失败或崩溃后无法证明可安全采纳：

- start/status 退出 5 且 `ok=false`；
- 已知准备失败返回 `TASK_PREPARATION_FAILED`，资源归属或状态存在不确定性返回 `CREATION_RECOVERY_REQUIRED`；
- `data.task` 返回经过验证、处于 NEEDS_ATTENTION 的 TaskViewV1；
- 未通过语义校验的事件、路径或 workspace 内容不得进入 `data.task`。

### 4.5 list 的局部损坏语义

task list 必须逐 Task 验证。一个 Task 的坏链不得污染或隐藏其他 Task：

- 全部 Task 有效时，退出 0，data.items 按 task_id 词法升序；
- 部分 Task 损坏时，退出 4，ok=false，error.code=PARTIAL_INTEGRITY_FAILURE；
- data.items 仍返回有效 Task 的 TaskViewV1；
- data.invalid_items 只返回损坏 Task 的 task_id、稳定错误码和首个可定位 sequence，不返回未经验证的业务投影。
- 此处是允许 `ok=false` 且 `data` 非 null 的条件分支；`error.details` 只能重复聚合计数和定位信息，不能另造一份不一致的 items。

### 4.6 稳定退出码

| 退出码 | 类别 | 代表错误码 |
|---:|---|---|
| 0 | 成功 | 无 |
| 2 | 用法或输入 | INVALID_ARGUMENT、INVALID_GIT_REPOSITORY、UNBORN_REPOSITORY、INVALID_BASELINE、DIRTY_SOURCE_REQUIRES_ACK、UNSAFE_GIT_CHECKOUT_CONFIG、PATH_OUTSIDE_ALLOWED_ROOT |
| 3 | 目标不存在或不可用 | TASK_NOT_FOUND、WORKSPACE_UNAVAILABLE、WORKSPACE_BASELINE_MISMATCH |
| 4 | 持久化或语义完整性 | EVENT_ID_DUPLICATE、EVENT_SEQUENCE_GAP、EVENT_SEQUENCE_DUPLICATE、EVENT_PREVIOUS_HASH_MISMATCH、EVENT_HASH_MISMATCH、EVENT_PAYLOAD_INVALID、EVENT_CAUSATION_INVALID、EVENT_TRANSITION_INVALID、UNSUPPORTED_EVENT_SCHEMA、SQLITE_CORRUPT、PARTIAL_INTEGRITY_FAILURE |
| 5 | 创建或存储失败 | TASK_CREATION_FAILED、TASK_PREPARATION_FAILED、WORKSPACE_CREATE_FAILED、STORE_UNAVAILABLE、TASK_ID_COLLISION、CREATION_RECOVERY_REQUIRED |
| 6 | 并发或暂时不可用 | STORE_BUSY |

未知异常必须映射为稳定非零退出码和 INTERNAL_ERROR，不得输出成功 JSON，不得泄露 Python traceback 到 stdout。

---

## 5. Git 基准与原工作区不变量

### 5.1 基准冻结

实现必须：

1. 使用结构化 argv 调用 Git，不经过 shell；
2. 将 COMMITISH 解析为 commit 对象的完整 OID；
3. 同时记录仓库 object format；
4. 后续所有检查与 worktree 创建只使用该 OID；
5. 创建 detached linked worktree；
6. 创建后验证 Task Workspace 的 HEAD 精确等于该 OID。

分支或 tag 在步骤 2 后移动，不得改变本次 Task。

### 5.2 “原工作区零改动”的精确定义

创建前后必须保持：

- 用户当前 worktree 内已跟踪、未跟踪和 ignored 文件内容逐字节一致；
- Git index 字节一致；
- HEAD 符号引用与 OID 一致；
- 当前分支引用及既有 refs 一致；
- porcelain v2 Git 状态一致。

允许的唯一源仓库 Git 管理副作用，是 Git 为 detached linked worktree 写入或清理必要的 common-dir worktree 管理元数据。不得宣传“整个 .git 目录逐字节不变”。

### 5.3 不可信 Git 配置

T01 在可信宿主创建 worktree，因此必须在 checkout 前：

- 覆盖 hooksPath 为受控空目录；
- 禁止系统和用户级 Git 配置影响该操作；
- 关闭外部 fsmonitor、分页器和终端提示；
- 检测并拒绝会在 checkout 阶段执行外部进程的 filter 配置；
- 不初始化或更新 submodule；
- 不进行 fetch、clone 或任何网络访问；
- 不把 COMMITISH、repo path 或 workspace path拼接为 shell 字符串。

存在外部 smudge/process filter 等无法在 T01 安全禁用的配置时，以 UNSAFE_GIT_CHECKOUT_CONFIG fail closed。支持这类仓库需要后续独立能力决策。

---

## 6. 持久化、事件与检查点

### 6.1 运行时权威

- SQLite/WAL 是 T01 的运行时权威。
- synchronous 固定为 FULL。
- events 表对 `(task_id, sequence)` 建唯一约束，并对 `event_id` 建 data-root 级唯一约束；Task registry 对 UUIDv4 `task_id` 建唯一约束。
- `sequence` 是 Task 事件流的逻辑顺序，不是 SQLite rowid、提交时间或墙钟顺序；它必须在按 Task 串行化的事务中从 1 连续分配。
- 数据库层以拒绝触发器阻止已提交 event 的 UPDATE 和 DELETE。
- JSONL 不是运行时权威，本 Ticket 不需要提供 JSONL 导入导出。
- 投影与检查点和相应事件在同一 SQLite 事务提交。
- Task 间的事件、投影、检查点和 workspace 引用必须按 task_id 隔离。

### 6.2 最小事件信封

每个事件至少包含：

- event_id：UUIDv4，在 data root 内唯一；
- task_id：UUIDv4，在 data root 内唯一；
- sequence：从 1 开始的正整数，表示 Task 内逻辑因果顺序；
- event_type；
- schema_version：本票为 1；
- occurred_at：UTC RFC 3339，固定六位小数并以 Z 结束；
- actor：本票固定为 local_user；
- correlation_id：本次 CLI command 的 UUIDv4；
- causation_id：首事件为 null，后续指向直接原因事件；
- workspace_revision：本票固定为 null；
- sensitivity：本票固定为 INTERNAL；
- payload；
- previous_hash；
- event_hash。

### 6.3 T01 事件

所有 workspace 物理副作用之前，必须先在一个 SQLite 事务中耐久提交前三个事件、对应 PREPARING 投影和 through-sequence=3 的 CheckpointV1：

1. sequence 1，TaskCreatedV1  
   payload 包含 objective、repository_realpath、git_common_dir_realpath、object_format、baseline_commit、source_dirty、dirty_content_included=false。
2. sequence 2，TaskPreparationStartedV1  
   作为 workspace provisioning 提议事件，payload 包含 workspace_relative_path、ownership_nonce 和 proposed_action_digest，投影由 CREATED 进入 PREPARING。
3. sequence 3，WorkspaceProvisioningAuthorizedV1  
   payload 包含固定 `bootstrap_policy_id=builtin.workspace-provision.v1`、`decision=AUTO_ALLOWED`、规范化 workspace_relative_path、随机 128-bit `ownership_nonce`、`action_digest`、mode=DETACHED 和 baseline_commit。`action_digest` 是对 task_id、Git common-dir 身份、baseline_commit、workspace_relative_path、ownership_nonce、mode 及 bootstrap_policy_id 的规范化对象计算的 SHA-256，且必须等于上一提议事件的 proposed_action_digest。

成功时再以第二个 SQLite 事务追加：

4. sequence 4，TaskWorkspacePreparedV1  
   payload 包含 action_digest、ownership_nonce、workspace_relative_path、mode=DETACHED、head_oid、Git 管理反向指针摘要及 `recovered_after_interruption`。投影保持 PREPARING，health=HEALTHY，workspace=READY，sandbox=NOT_REQUIRED_FOR_READ_ONLY_ANALYSIS。

已耐久授权后若准备失败，必须在一个 SQLite 事务中追加：

4. sequence 4，TaskWorkspaceProvisioningFailedV1  
   payload 包含 action_digest、失败阶段、稳定错误码、已知资源状态和经过清洗的诊断。
5. sequence 5，TaskAttentionRequiredV1  
   causation_id 指向失败事件，payload 包含 reason=WORKSPACE_PROVISIONING_FAILED 或 WORKSPACE_PROVISIONING_UNCERTAIN；投影进入 NEEDS_ATTENTION。

T01 不追加 SandboxReady、RunStarted、WorkspaceRevisionCreated 或任何工具调用事件。

每个 event type 都必须有版本化 typed payload schema，默认拒绝未知必需字段、错误类型和不允许的额外字段。固定语义规则为：

- TaskCreatedV1 必须是 sequence 1 且 causation_id=null；
- TaskPreparationStartedV1 必须因果指向 TaskCreatedV1，并执行 CREATED→PREPARING；
- WorkspaceProvisioningAuthorizedV1 必须因果指向 TaskPreparationStartedV1，action_digest 必须可由 payload 与 Task 事实重算且等于 proposed_action_digest，状态保持 PREPARING；
- TaskWorkspacePreparedV1 或 TaskWorkspaceProvisioningFailedV1 必须因果指向 WorkspaceProvisioningAuthorizedV1，二者互斥；
- TaskAttentionRequiredV1 只能因果指向 TaskWorkspaceProvisioningFailedV1，并执行 PREPARING→NEEDS_ATTENTION；
- 任何 event_id 重复、typed payload 不合法、causation 不合法或状态转换不合法，即使 sequence 与哈希链合法，也必须 fail closed。

### 6.4 规范化与哈希算法

为保证跨进程稳定，事件哈希输入固定如下：

1. 对所有字符串递归做 Unicode NFC；
2. 仅允许 null、布尔、任意精度整数、字符串、数组和字符串键对象；拒绝浮点、NaN、Infinity 和二进制值；
3. 取完整事件信封但排除 event_hash；
4. 使用 CPython json 的等价规范：ensure_ascii=false、sort_keys=true、separators 为逗号和冒号、allow_nan=false；
5. 编码为 UTF-8，无 BOM、无结尾换行；
6. event_hash 为上述字节的 SHA-256 小写十六进制；
7. sequence 1 的 previous_hash 固定为 64 个字符 0；
8. sequence N 的 previous_hash 必须等于 sequence N-1 的 event_hash。

校验顺序固定为：信封 schema 支持性、task_id 一致性、UUIDv4/event_id 唯一性、逻辑 sequence 连续性、previous_hash、重算 event_hash、typed payload、causation、状态转换。单一故障输入，以及已经建立唯一、连续逻辑 sequence 后的验证阶段，发现首个错误即停止该 Task 的重建并返回对应稳定错误。

如果同一事件流同时包含两个以上、且在建立唯一逻辑 sequence 前即可独立拒绝的畸形，系统仍必须 fail closed，不得生成投影、checkpoint 或任何持久副作用；但多个适用稳定错误之间的内容级 tie-break 不是公共协议。`_prevalidation_token`、`_fallback_sort_atom` 与 `_prevalidation_order_key` 是私有实现细节，不发布 `PrevalidationOrderV1`，调用方不得依赖其 rank、编码、排序字节或具体首错选择。同一有序输入的判定仍不得依赖墙钟、随机数或外部状态；同一多重畸形集合的不同物理排列，只要求全部进入实际适用的稳定失败集合并保持零副作用。单故障 S09 映射、合法链和已建立逻辑 sequence 后的验证顺序不得因此放宽。

错误映射固定为：event_id 重复→EVENT_ID_DUPLICATE；逻辑 sequence 缺口→EVENT_SEQUENCE_GAP；逻辑 sequence 重复→EVENT_SEQUENCE_DUPLICATE；链错误→EVENT_PREVIOUS_HASH_MISMATCH 或 EVENT_HASH_MISMATCH；typed payload→EVENT_PAYLOAD_INVALID；因果边→EVENT_CAUSATION_INVALID；非法状态转换→EVENT_TRANSITION_INVALID。SQLite 物理行顺序、rowid 和 occurred_at 不定义第三种“乱序”错误；验证器不得因为哈希正确而跳过语义验证。

### 6.5 Checkpoint

CheckpointV1 至少包含：

- checkpoint_version=1；
- task_id；
- through_sequence；
- through_event_hash；
- projection_schema_version=1；
- 完整 Task 投影；
- checkpoint_hash。计算时取完整 CheckpointV1 但明确排除 `checkpoint_hash` 自身，再使用 §6.4 相同的 Unicode NFC、受限 JSON 值、键排序、紧凑分隔符和 UTF-8 规则计算 SHA-256；不得把 `event_hash` 的排除规则错误地套用成自引用输入。

规则：

- 每次打开 Task 时仍必须验证完整事件链；checkpoint 不能成为绕过历史完整性检查的信任锚。
- checkpoint 缺失、陈旧、跨 Task、超前或哈希错误，而事件链有效时，丢弃 checkpoint，从 sequence 1 完整重放并原子重建投影和 checkpoint。
- 事件链无效时，不得使用 checkpoint 继续。
- 重建派生数据不得追加 Trajectory Event。
- 相同事件序列必须生成结构等价且规范化字节一致的投影与 checkpoint。

---

## 7. 创建协议与半创建恢复

SQLite 与 Git worktree 无法共享数据库事务。T01 使用先行耐久授权事件和严格采纳判定协调，而不伪造跨资源 exactly-once：

1. 规范化并校验 repo、data root 和目标路径。
2. 记录原 worktree 指纹。
3. 检查 dirty source 并执行显式确认规则。
4. 将 COMMITISH 解析并冻结为完整 commit OID。
5. 分配 UUIDv4 task_id；在 data-root registry 唯一约束、规范化路径和已有槽位三处检测碰撞。生成随机 128-bit ownership_nonce，并把它编码进不可预测的 workspace 槽位名称。
6. 计算 action_digest，在一个 SQLite 事务中写入 TaskCreatedV1、TaskPreparationStartedV1、WorkspaceProvisioningAuthorizedV1、PREPARING 投影和 through-sequence=3 的 CheckpointV1。只有该事务耐久成功后才允许继续。
7. 使用受控 Git 配置创建 detached linked worktree，命令必须与已授权 action_digest 完全一致。
8. 校验 workspace 规范化路径、Git common-dir 管理项与 workspace `.git` 的双向指针、detached HEAD、baseline OID、clean 状态、无 untracked/ignored 额外文件、ownership_nonce 槽位和原 worktree 指纹。
9. 校验全部通过时，在一个 SQLite 事务中追加 TaskWorkspacePreparedV1、更新投影并写 through-sequence=4 的 CheckpointV1，然后返回成功 JSON。
10. 命令已知失败或校验不通过时，追加 TaskWorkspaceProvisioningFailedV1 与 TaskAttentionRequiredV1，返回允许携带可信 TaskViewV1 的失败外壳；不得删除已提交 Task 事实。

每次打开 data root 时，必须从事件投影寻找已有 WorkspaceProvisioningAuthorizedV1 但尚无 Prepared/Failed 终态的 Task。只有以下证据全部同时满足时，才可采纳已有 workspace 并追加 recovered_after_interruption=true 的 TaskWorkspacePreparedV1：

1. 规范化路径与授权的 workspace_relative_path 完全相同，且仍在 data root 管理根内；
2. Git common-dir 的 worktree 管理项反向指向该 workspace，workspace `.git` 又精确指回同一管理项；
3. HEAD 是 detached 且完整 OID 等于已授权 baseline_commit；
4. index 与 tracked tree clean，不存在 staged 或 unstaged 变化；
5. 不存在 untracked、ignored、submodule 工作树或其他 baseline 之外的额外文件；
6. workspace 槽位中的 ownership_nonce 与授权事件完全相同；
7. action_digest 可从当前权威 Task 事实逐字节重算并与授权事件相同。

任一证据缺失、冲突、不可读或状态不确定时，必须追加 TaskWorkspaceProvisioningFailedV1 与 TaskAttentionRequiredV1，返回 CREATION_RECOVERY_REQUIRED 并进入 NEEDS_ATTENTION。T01 在恢复路径中禁止自动删除、移动、checkout、reset、clean 或“尽力修复”任何不确定资源；后续人工处置不属于本 Ticket。

不存在非事件 `creation_intent` 作为业务审计的替代物。实现可以在同一 SQLite 事务内部使用普通数据库机制完成写入，但任何跨 Git 副作用的授权、成功、失败和注意状态都必须由上述 Trajectory Event 表达。

---

## 8. 跨进程重开流程

进程 B 执行 list/status 时必须：

1. 打开同一 data root，只校验 SQLite/WAL 可读性；此阶段不得检查、移动、删除或修改任何 workspace，也不得追加事件。
2. 按逻辑 sequence 读取目标 Task 的完整事件流，并依次完成信封 schema、task_id/event_id、sequence、previous_hash/event_hash、typed payload、causation 和 transition 校验。任一失败立即退出 4；不得生成业务投影、访问文件系统或追加恢复事件。
3. 只有完整事件流全部通过后，才验证 checkpoint，并从有效 checkpoint 继续或从 sequence 1 重放，生成可信投影。
4. 仅从该可信投影识别尚无 Prepared/Failed 终态的 WorkspaceProvisioningAuthorizedV1；坏链、未知 schema 或非法状态绝不能驱动恢复。
5. 对未终结授权按 §7 的七项证据执行只读采纳判定；只有全部匹配才追加 Prepared，否则追加 Failed+AttentionRequired。任何追加都必须因果绑定已验证授权并在独立事务中重新更新投影/checkpoint。
6. 对已有 Prepared 终态的 Task，只读检查 workspace 当前 availability 与 HEAD/baseline，按 TaskViewV1 oneOf 生成成功或退化状态。
7. 生成条件 JSON 外壳，并明确返回所有 runtime restoration 字段为 false。

重开不得：

- 复活或伪造旧进程；
- 创建 PTY；
- 启动 Agent Run；
- 重放外部副作用；
- 自动修复权威事件；
- 自动删除、移动、reset、clean 或 checkout 未决 workspace；
- 因读取 status 而改变原 Git worktree。

---

## 9. Tier 3 Failure Model

| ID | 失败模式与危害 | 检测方法 | 必须的失败语义 |
|---|---|---|---|
| F01 | 可移动 ref 在创建中前移，Task 绑定错误代码 | 在解析与 worktree 创建之间移动 ref | 只使用首次冻结的 commit OID |
| F02 | 创建 Task 改变用户 worktree、index、HEAD 或 refs | dirty fixture 前后指纹对比 | 用户业务状态逐字节不变；只允许 common-dir worktree 元数据 |
| F03 | 授权事件、Git worktree 和终态事件之间中断，产生伪健康半成品 | 在前三事件提交前后、Git 创建期间、采纳校验和终态事务边界注入失败 | 纯预检失败无 Task；授权已耐久后 Task 必须可见；仅七项证据全部匹配才采纳，否则不自动删除并进入 NEEDS_ATTENTION |
| F04 | 事件 sequence 缺失/重复、链篡改或语义次序非法后仍被投影 | 属性生成合法链后逐类破坏；另生成含多个前置畸形的集合；mutation | 单一损坏返回精确稳定错误码；多重前置畸形返回实际适用稳定失败集合之一；两者均停止重建、零投影/checkpoint/写入且不修链；物理存储行顺序不参与语义 |
| F05 | 坏、跨 Task、超前或陈旧 checkpoint 被当权威 | checkpoint 属性与故障测试 | 事件有效则完整重放；事件无效则拒绝 |
| F06 | 投影依赖缓存、墙钟、时区或迭代顺序 | 删除投影后由不同 OS 进程重开 | 同一事件链得到规范化一致投影 |
| F07 | 并发 start 产生重复 ID、共享路径或 SQLite 锁被误报成功 | 多进程压力与多 seed 重复 | 成功 Task 全隔离；失败明确且不污染其他 Task |
| F08 | 路径、ref、符号链接或前导连字符造成参数注入和路径逃逸 | 对抗路径、ref 与预置 symlink/junction | 结构化 argv；目标必须位于规范化 data root；碰撞 fail closed |
| F09 | checkout 执行不可信 hook、filter 或外部 fsmonitor | sentinel hook/filter 测试 | sentinel 不出现；危险配置被禁用或拒绝 |
| F10 | JSON 字段漂移、stdout 混入日志或错误退出码为 0 | schema/golden/stdio 契约测试 | 版本字段、稳定 code、确定退出码；日志仅 stderr |
| F11 | “重开”误报为进程、PTY 或内存恢复 | 进程 A 创建退出，进程 B status | 只恢复投影；runtime 恢复字段全部 false |
| F12 | Task A 的坏链阻断或污染 Task B | 只破坏 A，分别 list/status | A fail closed；B 正常重建 |
| F13 | 源 Git common directory 丢失后 Task 仍显示健康 | 创建后移动或删除源管理目录 | 事件事实保留，workspace 标记 NEEDS_ATTENTION，不伪造可用 |
| F14 | 攻击者重算出合法哈希链，但伪造 event_id、typed payload、causation 或状态转换 | 生成哈希完全合法但语义非法的事件链 | 以 EVENT_ID_DUPLICATE、EVENT_PAYLOAD_INVALID、EVENT_CAUSATION_INVALID 或 EVENT_TRANSITION_INVALID fail closed，不运行 reducer 后续步骤 |

---

## 10. 可执行场景

每个场景必须在自动化测试中以同名测试或可追踪的场景 ID 落地。

### S01 — 从 clean Git commit 创建

**Given** 参数化临时 Git 仓库有提交 C1，worktree clean。  
**When** 新 OS 进程运行 task start，指定 repo、C1、objective、独立 data root 和 JSON。  
**Then** 返回 0；TaskViewV1 为 PREPARING/HEALTHY；sandbox=NOT_REQUIRED_FOR_READ_ONLY_ANALYSIS；workspace 为 detached；workspace HEAD 与 baseline OID 都等于 C1；事件位置为 sequence 4；原 worktree 指纹不变。

### S02 — Dirty source 必须显式确认排除

**Given** 仓库同时存在 staged、unstaged、untracked 和 ignored 内容。  
**When** 未带确认参数执行 start。  
**Then** 返回 2 和 DIRTY_SOURCE_REQUIRES_ACK，零 Task、零 linked worktree。  
**When** 带确认参数再次执行。  
**Then** Task 只含 commit 内容，source_dirty=true、dirty_content_included=false，原有 dirty 状态逐字节不变。

### S03 — 基准 TOCTOU

**Given** main 在解析时指向 C1。  
**When** 测试故障点在解析后把 main 前移至 C2，再继续创建。  
**Then** Task baseline、workspace HEAD 与事件 payload 都固定为 C1。

### S04 — 无效 Git 输入零副作用失败

对非 Git 目录、unborn 仓库、不存在 ref、tree/blob OID、前导连字符 ref 和不可访问 repo 分别执行 start。每种情况都必须返回稳定输入错误，data root 中无健康 Task，原目录不变。

### S05 — 两个真实进程重开

**Given** 进程 A 成功创建 Task 后完全退出。  
**When** 独立进程 B 运行 list 和 status。  
**Then** task_id、baseline、状态、event_position 与 checkpoint 位置一致；没有依赖进程 A 的内存或模块级缓存。

### S06 — 投影和 checkpoint 可重建

**Given** 事件链有效。  
**When** 删除投影和 checkpoint 后由新进程 status。  
**Then** 从 sequence 1 重建，load_mode=FULL_REPLAY，不追加新事件，规范化投影与删除前一致。

### S07 — 有效旧 checkpoint 加尾事件

**Given** 仅用于测试、不可由产品 CLI 调用的 event-store fixture 按正式 typed schema 与哈希规则追加合法尾事件，使 checkpoint 位于 N、合法事件链尾位于 M，且 M 大于 N。  
**When** 新进程重开。  
**Then** 完整链先通过验证，reducer 从 checkpoint 继续到 M，结果绑定 M。

### S08 — 无效 checkpoint 安全退回

分别令 checkpoint 哈希错误、task_id 错误、位置超前和投影 schema 不支持。只要事件链有效，status 必须丢弃 checkpoint、完整重放并成功；不得把 checkpoint 错误伪装成事件损坏。

### S09 — 事件链损坏 fail closed

从合法链执行以下互斥变换并精确断言首个错误：删除中间 sequence→EVENT_SEQUENCE_GAP；复制 sequence→EVENT_SEQUENCE_DUPLICATE；修改 previous_hash→EVENT_PREVIOUS_HASH_MISMATCH；修改 payload、event_type 或 event_hash 但不重算链→EVENT_HASH_MISMATCH。将两个合法事件的类型/内容放到不允许的逻辑 sequence，同时重建 event_id、causation、previous_hash 和 event_hash 使其他校验全部合法时，必须得到 EVENT_TRANSITION_INVALID。另生成同时含两个以上前置畸形的事件集合；其结果必须失败，错误码属于该输入实际适用的稳定失败集合，且不得生成投影、checkpoint 或写入，但不固定这些畸形之间的私有首错 tie-break。仅改变 SQLite 物理插入/返回行顺序、但保留逻辑 sequence 与整条链不变时，读取器按 sequence 得到同一结果，不得报告顺序错误。所有失败均不写新投影、不修补、不跳过事件。

### S10 — 不兼容事件 schema

**Given** 链中存在高于当前实现支持版本的事件。  
**When** status 重建。  
**Then** 返回 UNSUPPORTED_EVENT_SCHEMA，不把未知 payload 当空对象，不降级为旧 schema。

### S11 — 创建边界失败与严格采纳

在前三个授权事件提交前、提交后、`git worktree add` 执行期间、workspace 已出现但 Prepared 事件提交前，以及 Prepared 事件提交后分别注入 I/O 失败或真实子进程终止。前三事件未提交时不得产生 Task 或 Git 副作用；一旦前三事件耐久，Task 必须保持可见。新进程只有在路径、Git 管理双向指针、detached HEAD、baseline、clean/no-extra-files、ownership_nonce 和 action_digest 七项证据全部匹配时才追加 sequence 4 Prepared 并采纳；否则追加 Failed 与 AttentionRequired、进入 NEEDS_ATTENTION、返回 CREATION_RECOVERY_REQUIRED，且不得自动删除或修复资源。

### S12 — 并发创建隔离

多个 OS 进程对同一 repo/OID 并发 start，重复多个随机 seed。每个成功请求具有 data-root 内唯一 UUIDv4、唯一 event_id 集合、无碰撞 workspace 和独立从 1 开始的事件流；预置 task_id 或槽位碰撞必须重试分配或以稳定错误 fail closed，STORE_BUSY 等失败不得污染成功 Task。

### S13 — 路径与 Git 扩展对抗

对绝对逃逸路径、点点路径、前导连字符、shell 元字符、workspace 槽位 symlink/junction、恶意 post-checkout hook、外部 filter 和 fsmonitor 运行创建。不得执行 sentinel，不得写出 managed root；危险配置返回稳定错误。

### S14 — 机器接口稳定

对 start/list/status 的成功、not found、invalid baseline、event corrupt、partial list、workspace unavailable/mismatch 和持久化准备失败进行版本化 JSON Schema 与退出码断言。必须同时证明普通失败 data=null，以及仅获准错误码可携带经验证 data；stdout 必须只有一个 JSON 文档，日志和 traceback 不得污染 stdout。

### S15 — 明确不恢复运行态

新进程 status 的 process_restored、terminal_restored、memory_restored、network_transaction_restored 必须全部为 false；不得启动替代进程来伪装恢复。

### S16 — 坏 Task 不连坐

创建 A、B 两个 Task，只损坏 A。status A 失败；status B 成功；list 返回 B 的可信 TaskViewV1 和 A 的最小 invalid item，并以 PARTIAL_INTEGRITY_FAILURE 退出。

### S17 — Workspace 丢失或基准漂移

在事件链有效的情况下删除 Task Workspace，或使其 HEAD 与 baseline 不同。status 分别以 WORKSPACE_UNAVAILABLE 或 WORKSPACE_BASELINE_MISMATCH 退出 3、ok=false，data.task 保留已验证事件事实并返回 health=NEEDS_ATTENTION 和对应 availability；不得静默重建、checkout 或移动源仓库。

### S18 — 哈希合法但事件语义非法

使用测试 event-store fixture 分别构造 event_id 重复、typed payload 字段/类型错误、causation 指向错误事件，以及 PREPARING 直接接收不允许事件的链；每条链都必须重新计算成 sequence、previous_hash 和 event_hash 完全合法。status 仍必须以对应 EVENT_ID_DUPLICATE、EVENT_PAYLOAD_INVALID、EVENT_CAUSATION_INVALID 或 EVENT_TRANSITION_INVALID 退出 4，不写投影或 checkpoint，不执行后续 reducer。

### S19 — 数据库拒绝改写已提交事件

对已提交 events 直接执行 UPDATE 和 DELETE，并在独立连接及事务中重复。SQLite 必须在数据库边界拒绝两类操作；原事件数量、规范化字节、sequence 和 event_hash 全部不变，随后跨进程 status 仍能通过完整链与语义校验。测试不得仅调用会预先拒绝的 repository 方法来冒充数据库约束已验证。

---

## 11. Must NOT

实现及测试不得：

1. 在 SPEC 获批前修改实现、配置、依赖或 Git 历史。
2. 在用户当前 worktree 中直接开发 T01。
3. 产品运行时对 `--repo` 指定的用户源 worktree 执行 checkout、reset、clean、stash、commit、创建/移动 ref，或修改其文件、index、HEAD、当前分支引用及 Git 配置。唯一允许的例外是：受控 `git worktree` 为本次 detached Task Workspace 在源 Git common directory 的 `.git/worktrees/` 管理区创建或更新必要的管理项；该例外不允许修改源 worktree 内容、index、refs、hooks、config 或其他 `.git` 状态，也不禁止批准后的 SigmaCoder 实现仓库 checkpoint commit。
4. 隐式带入 staged、unstaged、untracked 或 ignored 内容。
5. 将 branch/tag 名作为持久基准，而不冻结完整 commit OID。
6. 通过 shell 字符串执行 Git，或允许参数被解释成 Git option。
7. 在 checkout 时执行仓库 hook、filter、fsmonitor、submodule 更新或网络访问。
8. 把 data root 放进源 worktree、Git common directory 或 Task Workspace。
9. 对 Task Workspace 路径碰撞、symlink、junction 或无法证明归属的资源做“尽力而为”覆盖或删除。
10. UPDATE/DELETE 已提交事件。
11. 用投影或 checkpoint 掩盖坏事件链。
12. 自动补 sequence、重算并写回坏事件、跳过未知事件或自动修复权威历史。
13. 把 SHA-256 链描述为对受信管理员的密码学防篡改证明。
14. 将 JSONL 作为运行时事实源。
15. 声称恢复活进程、PTY、Shell CWD/env、内存、容器或未完成网络事务。
16. 启动模型、Agent Run、OCI、网络、凭据代理、Verifier、Reviewer 或 Promotion。
17. 引入 Typer、Rich、Pydantic、SQLAlchemy、Alembic、GitPython 或其他未列入 setup plan 的包。
18. 在测试中 mock 掉所有 Git、SQLite 或跨进程边界后声称端到端通过。
19. 以 import/collection 错误充当 RED。
20. 删除、放宽或 skip 失败测试来获得 GREEN。
21. 使用不执行的 coverage、mutation、secret scan 或自定义门禁并报告通过。
22. 在未重新运行完整新鲜 Gauntlet 的情况下出具最终 EVIDENCE。
23. 未经明确授权 push、开 PR、合并或发布。
24. 用非 Trajectory 的 `creation_intent`、临时日志或内存标志替代 WorkspaceProvisioningAuthorized、Prepared、Failed 与 AttentionRequired 事件。
25. 把 T02 的只读/no-exec profile 升级为 process、terminal、interpreter、edit、网络、凭据或插件执行能力。
26. 用通配符、前缀、正则、函数级整批排除或其他开放式规则批准 mutation survivor。
27. 通过 CLI 临时参数、环境变量、普通 profile 配置或运行后脚本追加等价排除。
28. 把 survivor 改写为 killed，或删除原始 survivor 名称、状态、分类和计数证据。
29. 把 timeout、no tests、skipped、not checked、suspicious、segfault、caught by type check、interrupted 或未知状态解释为等价 mutant。
30. 保留已经被测试杀死、已不再生成或未出现在本次完整 mutant 集合中的陈旧清单项。
31. 在源码、mutmut 版本、uv.lock、mutation profile、mutant 总数或 mutant 名称摘要漂移后沿用旧等价清单。
32. 为迁就现有测试而把私有 prevalidation tie-break 发布成新的公共协议。

---

## 12. 测试设计与 Tier 3 Gauntlet

### 12.1 测试入口与分层

唯一可信总入口：

    uv run python tools/gauntlet.py

gauntlet 使用固定、版本化层清单；每层必须产生可解析结果。缺层、未知退出码、异常终止、陈旧报告或输入不可读都视为失败。它必须先清除旧 coverage、mutation、secret scan 和测试报告，再执行。

本票同时覆盖：

- 主产品验收 seam：真实 CLI、Git、SQLite、Task Workspace；
- T01 限定的恢复 seam：投影/checkpoint 重建、事件完整性及未终结 WorkspaceProvisioningAuthorized 的严格采纳；
- 不扩展到 T03 的通用 Runner kill/restart，也不扩展到 T14 的外部对账。

### 12.2 测试层与硬门

| 层 | 命令或方法 | 通过标准 |
|---|---|---|
| 单元/集成/E2E | uv run pytest -q | 0 failed、0 unexpected skipped/xfail/xpass |
| 类型 | uv run mypy --strict src/sigmacoder | 0 error；公共 schema、事件和 ports 不得退化为无约束 Any |
| Lint | uv run ruff check . | 0 error，启用复杂度规则，新函数复杂度不超过 8 |
| 格式 | uv run ruff format --check . | 0 diff |
| 分支覆盖采集 | `uv run pytest -q --cov=src/sigmacoder --cov-branch --cov-report=xml:coverage.xml --cov-report=json:coverage.json` | 测试通过且生成本次运行的新鲜 XML/JSON 报告 |
| 分支覆盖硬门 | `uv run python tools/check_coverage.py --input coverage.json --total-branch-min 95 --module-branch src/sigmacoder/domain/events.py=100 --module-branch src/sigmacoder/application/task_service.py=100` | 全产品 branch coverage ≥95%；`events.py` 与 `task_service.py` 各自 branch coverage=100%；任一缺文件、缺 branch 数据或阈值不足均非零退出 |
| 改动行覆盖 | `uv run diff-cover coverage.xml --compare-branch main --fail-under=100` | changed-line coverage=100%，命令以非零退出实施阈值 |
| 属性测试 | Hypothesis | 每个核心属性至少 200 个有效例；最终 profile、seed 和 shrink 结果入 EVIDENCE |
| Mutation/events | `uv run python tools/run_mutation_profile.py events` | 持久 profile 只覆盖事件解析、哈希、typed payload、causation 与 reducer；原始 survived=49，且必须与 r5 逐项批准清单完全相等；unexpected_non_killed=0 |
| Mutation/task-service | `uv run python tools/run_mutation_profile.py task-service` | 持久 profile 覆盖创建授权、碰撞、采纳和失败转移；survivor=0 |
| 顺序/波动 | pytest-randomly | 至少 3 个记录 seed；并发与 kill 场景重复至少 20 次且 0 偶发失败 |
| 真实执行 | 安装后的 sigma，在临时真实 Git 仓库及独立 OS 进程运行 | S01、S02、S05、S11、S12、S14、S15 全通过 |
| Secret scan | detect-secrets | 真实树 0 未批准秘密；honeytoken 负控必须先失败 |
| 供应链漏洞 | `uv lock --check`、`uv sync --frozen`、`uv export --format requirements.txt --all-groups --no-emit-project --frozen --output-file build/audit-requirements.txt`、`uv run --frozen pip-audit --requirement build/audit-requirements.txt --strict` | 审计 `uv.lock` 精确锁定的全部第三方依赖并排除不可发布的本地 editable 项目；lock 一致；pip-audit 任一发现默认阻断，不因“无修复版本”而放行；只有获批的 SPEC 修订可记录限时豁免 |
| 许可证 | `uv run pip-licenses --format=json --with-system --with-authors --ignore-packages sigmacoder --output-file licenses.json` 后运行 `uv run python tools/check_licenses.py licenses.json` | 审计全部直接/传递第三方依赖；仅允许 MIT、0BSD、BSD-2-Clause、BSD-3-Clause、Apache-2.0、ISC、Python-2.0、PSF-2.0、MPL-2.0；unknown、custom、无法映射或 allowlist 外 SPDX 均阻断 |
| Source state | `uv run python tools/source_state.py` | 无 relevant staged、unstaged、deleted 或非忽略 untracked 源文件 |

不设置硬性能阈值。design.md 的 p95 指标尚无固定参考硬件；本票只记录诊断数据，不能在普通 CI 上伪造稳定性能结论。

### 12.3 必须由属性测试证明的性质

1. 相同合法事件字节序列总产生相同投影和 checkpoint。
2. 任意合法 append 序列保持逻辑 sequence 连续唯一，task_id 与 event_id 满足 data-root 唯一约束。
3. 删除或重复逻辑 sequence，以及修改 payload、previous_hash、event_hash 中任一项必被拒绝；物理行重排不改变结果；哈希合法但 typed payload、causation 或 transition 非法同样必被拒绝。
4. 重建幂等：连续两次重建的规范化结果一致。
5. 合法 task_id、路径、Unicode objective 与 Git object format round-trip 不丢失。
6. 一个 Task 的事件操作不改变另一 Task 的投影或事件位置。
7. 对含两个以上前置畸形的事件集合，任意物理排列都 fail closed，错误码属于该输入实际适用的稳定失败集合，且不产生投影、checkpoint 或持久写入；不得借此放宽单故障错误映射。

### 12.4 Mutation 要求

至少定向制造并杀死以下 mutant：

- 移除 sequence 连续性检查；
- 忽略 previous_hash；
- 颠倒哈希相等判断；
- 在坏事件后继续 reducer；
- 把当前 HEAD 代替已冻结 baseline；
- 省略 source worktree 指纹核验；
- 接受无效 checkpoint；
- 把 runtime 恢复字段改为 true。

两个 mutation profile 必须作为版本化配置持久化，显式记录目标路径、测试选择器、timeout、缓存目录和报告路径；不得靠操作者临时输入路径。每个 profile 连续运行两次，第二次不得依赖第一次的幸存/缓存状态。事件链 mutant 还必须单独只运行 property suite。工具不可用只能记录 UNAVAILABLE，且 T01 不得完成；不能把手工改代码伪装成 mutmut 通过。

task-service profile 每次仍要求原始 survivor=0。events profile 的通过条件改为 unexpected_non_killed=0；原始 49 个获批等价项仍必须透明记录为 survived，不得改写成 killed。events 的两次 full run 与一次 property-only run 必须分别满足：枚举 mutant 全集与批准基线完全一致；除 killed 和 survived 外不存在其他状态；实际 survived 名称集合与版本化等价清单逐项完全相等；清单外 survivor、清单内缺失、清单内已 killed、重复名称或其他非 killed 状态均失败。三次运行还必须具有相同 mutant 名称集合、源码指纹和 survivor 集合。

等价清单固定为 `tools/mutation_equivalents.json`，采用封闭 schema v1，不允许未知字段，并至少绑定：manifest id；本文路径与 r5；mutmut 3.7.0；uv.lock 逐字节 SHA-256；events profile 逐字节 SHA-256；预期 mutant 总数 1601；完整 mutant 名称集合 SHA-256；源文件 `src/sigmacoder/domain/events.py`；源文件逐字节 SHA-256 `facffbf2130ee09941b21018b99627335b40cd63a9fd9eea2f017ef26dfcf480`。清单必须是仓库内 UTF-8 普通文件，不得为 symlink 或 junction；49 个名称按 UTF-8 字节序排序且不得重复。每项都必须具有完整 name、category、reason_code、非空 reason 以及 source.path、source.function、source.sha256。源码任一字节变化都使相关批准全部失效。

获批类别计数固定为 TYPE_ONLY_CAST=4、OBSERVATIONALLY_EQUIVALENT_RUNTIME=14、GUARD_DOMINATED_EQUIVALENCE=11、NON_CONTRACT_DIAGNOSTIC=6、UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK=14。类别只能取这五个值。所有批准均只适用于状态 survived；listed-but-killed 属于陈旧批准，必须失败并经 SPEC 修订删除，不能被当作更强测试的成功证据。

精确 49 项如下，名称统一加前缀 `sigmacoder.domain.events.`：

| 类别 | mutant 名称 | reason_code |
|---|---|---|
| TYPE_ONLY_CAST | x__apply_event__mutmut_105 | CAST_RUNTIME_IDENTITY |
| TYPE_ONLY_CAST | x__normalized_event_copy__mutmut_2 | CAST_RUNTIME_IDENTITY |
| TYPE_ONLY_CAST | x__normalized_event_copy__mutmut_6 | CAST_RUNTIME_IDENTITY |
| TYPE_ONLY_CAST | x__validated_checkpoint_prefix__mutmut_42 | CAST_RUNTIME_IDENTITY |
| OBSERVATIONALLY_EQUIVALENT_RUNTIME | x_canonical_json_bytes__mutmut_5 | FALSEY_JSON_OPTION_EQUIVALENCE |
| OBSERVATIONALLY_EQUIVALENT_RUNTIME | x_canonical_json_bytes__mutmut_8 | FALSEY_JSON_OPTION_EQUIVALENCE |
| OBSERVATIONALLY_EQUIVALENT_RUNTIME | x_canonical_json_bytes__mutmut_21 | UTF8_CODEC_ALIAS |
| OBSERVATIONALLY_EQUIVALENT_RUNTIME | x__fallback_sort_atom__mutmut_6 | FALSEY_JSON_OPTION_EQUIVALENCE |
| OBSERVATIONALLY_EQUIVALENT_RUNTIME | x__fallback_sort_atom__mutmut_7 | FALSEY_JSON_OPTION_EQUIVALENCE |
| OBSERVATIONALLY_EQUIVALENT_RUNTIME | x__fallback_sort_atom__mutmut_10 | SCALAR_SORT_KEYS_EQUIVALENCE |
| OBSERVATIONALLY_EQUIVALENT_RUNTIME | x__fallback_sort_atom__mutmut_12 | SCALAR_SORT_KEYS_EQUIVALENCE |
| OBSERVATIONALLY_EQUIVALENT_RUNTIME | x__is_portable_relative_path__mutmut_28 | FIRST_SPLIT_COMPONENT_EQUIVALENCE |
| OBSERVATIONALLY_EQUIVALENT_RUNTIME | x__is_portable_relative_path__mutmut_31 | FIRST_SPLIT_COMPONENT_EQUIVALENCE |
| OBSERVATIONALLY_EQUIVALENT_RUNTIME | x__prevalidation_token__mutmut_6 | UTF8_CODEC_ALIAS |
| OBSERVATIONALLY_EQUIVALENT_RUNTIME | x__prevalidation_token__mutmut_15 | UTF8_CODEC_ALIAS |
| OBSERVATIONALLY_EQUIVALENT_RUNTIME | x__prevalidation_order_key__mutmut_4 | PRESERVED_PARTITION_ORDER |
| OBSERVATIONALLY_EQUIVALENT_RUNTIME | x__prevalidation_order_key__mutmut_5 | COMMON_SECONDARY_KEY_EQUIVALENCE |
| OBSERVATIONALLY_EQUIVALENT_RUNTIME | x__prevalidation_order_key__mutmut_14 | COMMON_SECONDARY_KEY_EQUIVALENCE |
| GUARD_DOMINATED_EQUIVALENCE | x_canonical_json_bytes__mutmut_13 | RESTRICTED_JSON_GUARD_DOMINATES |
| GUARD_DOMINATED_EQUIVALENCE | x_canonical_json_bytes__mutmut_18 | RESTRICTED_JSON_GUARD_DOMINATES |
| GUARD_DOMINATED_EQUIVALENCE | x__is_oid__mutmut_2 | OID_SCHEMA_GUARD_DOMINATES |
| GUARD_DOMINATED_EQUIVALENCE | x__is_portable_relative_path__mutmut_5 | PORTABLE_PATH_GUARDS_DOMINATE |
| GUARD_DOMINATED_EQUIVALENCE | x__is_portable_relative_path__mutmut_13 | PORTABLE_PATH_GUARDS_DOMINATE |
| GUARD_DOMINATED_EQUIVALENCE | x__is_portable_relative_path__mutmut_37 | PORTABLE_PATH_GUARDS_DOMINATE |
| GUARD_DOMINATED_EQUIVALENCE | x__is_uuid4__mutmut_1 | UUID_SCHEMA_GUARDS_DOMINATE |
| GUARD_DOMINATED_EQUIVALENCE | x__oid_matches_object_format__mutmut_10 | OID_SCHEMA_GUARD_DOMINATES |
| GUARD_DOMINATED_EQUIVALENCE | x__oid_matches_object_format__mutmut_21 | OBJECT_FORMAT_GUARD_DOMINATES |
| GUARD_DOMINATED_EQUIVALENCE | x__validated_checkpoint_prefix__mutmut_55 | PROJECTION_COMPARISON_DOMINATES |
| GUARD_DOMINATED_EQUIVALENCE | x_restore_task_projection__mutmut_43 | VALIDATED_CHAIN_IDENTITY |
| NON_CONTRACT_DIAGNOSTIC | x__event_int__mutmut_4 | PRIVATE_DIAGNOSTIC_ONLY |
| NON_CONTRACT_DIAGNOSTIC | x__event_payload__mutmut_5 | PRIVATE_DIAGNOSTIC_ONLY |
| NON_CONTRACT_DIAGNOSTIC | x__event_payload__mutmut_6 | PRIVATE_DIAGNOSTIC_ONLY |
| NON_CONTRACT_DIAGNOSTIC | x__event_payload__mutmut_7 | PRIVATE_DIAGNOSTIC_ONLY |
| NON_CONTRACT_DIAGNOSTIC | x__event_text__mutmut_3 | PRIVATE_DIAGNOSTIC_ONLY |
| NON_CONTRACT_DIAGNOSTIC | x__fallback_sort_atom__mutmut_14 | PRIVATE_DIAGNOSTIC_ONLY |
| UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK | x__fallback_sort_atom__mutmut_1 | PRIVATE_MULTI_FAULT_ORDER |
| UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK | x__fallback_sort_atom__mutmut_3 | PRIVATE_MULTI_FAULT_ORDER |
| UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK | x__fallback_sort_atom__mutmut_5 | PRIVATE_MULTI_FAULT_ORDER |
| UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK | x__fallback_sort_atom__mutmut_9 | PRIVATE_MULTI_FAULT_ORDER |
| UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK | x__fallback_sort_atom__mutmut_11 | PRIVATE_MULTI_FAULT_ORDER |
| UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK | x__prevalidation_token__mutmut_1 | PRIVATE_MULTI_FAULT_ORDER |
| UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK | x__prevalidation_token__mutmut_4 | PRIVATE_MULTI_FAULT_ORDER |
| UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK | x__prevalidation_token__mutmut_9 | PRIVATE_MULTI_FAULT_ORDER |
| UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK | x__prevalidation_token__mutmut_10 | PRIVATE_MULTI_FAULT_ORDER |
| UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK | x__prevalidation_token__mutmut_13 | PRIVATE_MULTI_FAULT_ORDER |
| UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK | x__prevalidation_order_key__mutmut_1 | PRIVATE_MULTI_FAULT_ORDER |
| UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK | x__prevalidation_order_key__mutmut_2 | PRIVATE_MULTI_FAULT_ORDER |
| UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK | x__prevalidation_order_key__mutmut_12 | PRIVATE_MULTI_FAULT_ORDER |
| UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK | x__prevalidation_order_key__mutmut_13 | PRIVATE_MULTI_FAULT_ORDER |

每项的非空中文 reason 必须说明其具体运行期等价、支配性 guard、非契约诊断或多故障私有 tie-break 理由，不能只复述类别名称。manifest、runner、独立 checker 均进入 repository fingerprint 和最终 mutation 报告。

`run_mutation_profile.py` 必须先完整解析原始状态，再加载并严格验证 manifest，最后做集合判定；不得在 parser 中遇到 survivor 就提前抛错。报告升级为 schema v2，透明包含 raw.total、raw.killed、raw.survived，approved_equivalents.count/names/digest，unexpected_non_killed.count/names/statuses，manifest、source、profile、lock、runner、checker 的指纹以及 gate_passed。不得只报告“有效 survivor=0”而隐藏原始 49 项。

新增独立 `tools/check_mutation_equivalents.py`；它不得复用 runner 的集合判定函数，必须独立验证 manifest 的封闭 schema、49 个精确名称、类别计数、版本与指纹，以及每次 run 的完整 status map、名称摘要、原始 survivor、获批等价项和 unexpected 三个集合。`tools/check_mutation_reports.py` 必须拒绝 schema v1、陈旧报告、缺字段、额外字段、重复项、篡改计数或指纹。manifest 与 checker 必须加入 runner 的 protected paths，写报告前后均重新核验。

### 12.5 对抗性 fixtures

临时 Git 仓库由 tests/support/git_repo_factory.py 参数化生成，记录：

- fixture schema version；
- 随机 seed；
- manifest hash；
- object format；
- clean/dirty 组合；
- branch/tag 移动；
- 恶意路径、hook/filter、symlink/junction；
- 合法链及各类损坏。

不得依赖一个固定样例仓库。fixtures 不联网、不读宿主凭据、不继承宿主 Git 用户配置。

### 12.6 Gauntlet 自身负控

在信任 tools/gauntlet.py 前，必须实际证明：

1. 从层清单删掉一个预期层时，gauntlet 非零退出；
2. 将一个层替换为已知失败命令时，gauntlet 非零退出；
3. 使用合成 coverage fixture 把总 branch coverage 降至 95% 以下时，`check_coverage.py` 非零退出；
4. 分别使用合成 coverage fixture 把 `events.py` 和 `task_service.py` 的 branch coverage 降至 100% 以下时，两个模块硬门各自非零退出；
5. 制造一条未覆盖 changed line 时，diff-cover 非零退出；
6. 注入已知 sequence 或 causation 校验缺陷时，对应 mutation profile 非零退出；
7. 临时写入明确假 honeytoken 时，secret scanner 非零退出；
8. 删除或污染旧报告后，gauntlet 不得读取旧 PASS；
9. 对 source-state 依次制造 relevant staged、unstaged modified、deleted 和非忽略 untracked 四种状态，每一种都必须使 `source_state.py` 非零退出并给出对应稳定分类；负控之间必须完整恢复状态，避免后一类借用前一类失败；
10. 向许可证 fixture 注入 unknown/custom SPDX，并向审计 fixture 注入一条发现，两种供应链检查都必须非零退出。
11. 对等价清单分别删除真实 survivor、增加不存在或拼错名称、增加 killed mutant、把已列项变成 killed；每种情况均必须失败。
12. 把已列项状态依次伪造为 timeout、no tests、skipped、not checked、suspicious、segfault、caught by type check、interrupted 或未知值；每种情况均必须失败。
13. 分别漂移 events.py 一个字节、mutmut 版本、uv.lock、profile、预期总数和名称摘要；每种情况均必须失败。
14. 对清单注入重复名、未知类别、空 reason、通配符、正则、未知字段或错误类别计数；每种情况均必须失败。
15. 删除清单、替换为 symlink/junction 或在 runner 运行中改写清单；每种情况均必须失败。
16. 篡改 schema v2 报告中的 raw survivor 数、名称、manifest/source/profile/lock/runner/checker 指纹，或用 schema v1/旧报告替换；独立 checker 必须失败。
17. 使 property-only 多出任一 survivor；门禁必须失败。
18. 对 tie-break 类注入“畸形流被接受”“产生投影/checkpoint/写入”“合法链结果改变”或“单故障错误映射改变”；均必须失败，不能被清单豁免。

完成负控后必须恢复源状态，并重新运行完整新鲜 Gauntlet。

### 12.7 平台矩阵与总判定

- Ubuntu 运行 `uv run python tools/gauntlet.py --profile ubuntu-tier3`，必须执行本节全部层，包括两个真实 mutmut profile、Git 对抗、真实跨进程、coverage、供应链与所有负控；任何 UNAVAILABLE、skip 或 substitute 都不是通过。
- Windows 运行 `uv run python tools/gauntlet.py --profile windows-compat`，必须执行除 mutmut 之外的全部适用层，并重点覆盖路径大小写、盘符、junction、文件锁、Git linked-worktree、SQLite/WAL 和真实多进程；mutmut 只能由同一最终 commit 的 Ubuntu 证据满足，Windows 报告不得伪造 mutation PASS。
- `uv run python tools/gauntlet.py` 是当前平台 profile 的 fail-closed dispatcher，但单个平台 PASS 不等于 T01 完成。
- 总判定必须同时引用同一最终 commit、同一 lock hash 和同一 SPEC r5 的 Ubuntu Tier 3 PASS 与 Windows compatibility PASS。任一平台未运行、commit 不同或报告陈旧，T01 状态只能是未完成。
- 若尚未获得 push/CI 授权且本地没有可信 Ubuntu runner，Ubuntu 证据记为 UNAVAILABLE 并暂停完成声明；不得以 Windows 结果替代。

---

## 13. Setup Plan

### 13.1 当前事实

- 当前 main 为 unborn branch，没有任何 commit。
- 当前仅有设计、ADR、agent 文档和两个二进制参考件，无 pyproject、src、tests 或 CI。
- 本机当前仅观测到 CPython 3.12.4、uv 0.6.9、Git 2.45.2.windows.1；前两者不满足 r2 锁定工具链，不能用于 RED、lock、Gauntlet 或 EVIDENCE。
- r3 规范工具链固定为 CPython 3.12.14 与 uv 0.12.5。依据为 [Python 3.12.14 官方发布页](https://www.python.org/downloads/release/python-31214/) 与 [Astral uv 0.12.5 release](https://github.com/astral-sh/uv/releases/tag/0.12.5)；后者的发布说明明确加入 Python 3.12.14。批准后才可按 §13.4 安装，当前观测不构成安装授权。
- AI-Agents-in-Depth-zh-CN.pdf：11,484,478 字节；SHA-256 为 124889C9DF0E7EB4CA51CCC69387C037066BFEFAA698CFF53724BEE1768BC56D。
- SigmaCoder-design-spec.zip：26,442 字节；SHA-256 为 9556F208556879D3050269A72930D7028E055164B4A11320E014A1C6FAA70FFC。

### 13.2 批准前

只允许：

- 写入本 SPEC；
- 只读审计 Issue、设计、ADR、Git 状态和本机工具版本；
- 展示完整 SPEC 并等待批准。

禁止创建实现文件、安装包、创建 Git commit/worktree 或运行实现测试。

### 13.3 批准后的初始化

1. 在任何 commit 前只读检查 `git config --get user.name` 与 `git config --get user.email`。任一缺失或为空时立即暂停并请求用户配置；不得由 Agent 猜测、临时伪造或写入全局身份。
2. 创建 .gitignore，排除：
   - 两个本地二进制参考件；
   - .venv、Python cache、pytest/mypy/ruff/Hypothesis/mutmut cache；
   - coverage、build、dist 和本地 SigmaCoder data root。
3. 按 §2.1 同步 `design.md` 的 PREPARING/ANALYZING 语义：T02 的只读/no-exec profile 不要求执行沙盒，执行型能力仍等待 T05。该 diff 只能作规范同步，不得加入实现代码；同步后重新运行 design/SPEC 一致性检查。
4. 建立一次本地初始文本基线提交，纳入：
   - AGENTS.md；
   - CONTEXT.md；
   - design.md；
   - design_base.md；
   - docs/，含本 SPEC；
   - .gitignore。
5. 不提交 PDF/ZIP，不使用 Git LFS，不让构建或测试依赖它们。
6. 不 push 初始提交，除非用户另行明确批准。
7. 从该基线创建分支 ticket/t01-persistent-coding-task。
8. 计划在 sibling worktree `C:\Users\36311\Desktop\AI项目\SigmaCoder-t01` 中实施，不在当前 worktree 直接开发。该路径位于当前 workspace 写权限根之外；创建前必须发起明确的文件系统权限升级请求，说明只创建此精确 sibling worktree。若权限被拒绝，立即暂停，不得退回当前 worktree 实施、改用更宽路径或请求泛化写权限。
9. 记录 baseline commit、分支、worktree 路径、Git author 来源、权限批准结果和初始 source-state 证据。

如果用户不批准上述初始基线内容或 sibling worktree 路径，实施必须暂停并修订本 SPEC。

### 13.4 Python 与包管理

- CPython 精确固定为 3.12.14，`.python-version` 必须只声明 `3.12.14`；禁止“最新 3.12.x”、范围内自动漂移或使用当前 3.12.4 生成 lock/证据。
- uv 精确固定为 0.12.5，并在 pyproject 的 `tool.uv.required-version` 使用 `==0.12.5`；禁止使用当前 0.6.9 或其他版本生成 lock/证据。
- SPEC r5 获批后，setup 必须验证按 r3 批准范围安装的 CPython 3.12.14 与 uv 0.12.5；若精确工具链不存在，须重新发起仅限这两个精确版本的网络/主机写权限请求。安装或解析结果不精确匹配时停止，不得自动改选版本。
- setup、Gauntlet 与 CI 首步分别验证 `python --version` 精确为 3.12.14、`uv --version` 精确为 0.12.5；任一不同立即失败。升级任一工具必须先修订本 SPEC 和 lock 证据。
- pyproject.toml 声明 requires-python 大于等于 3.12 且小于 3.13。
- 所有 Python 包通过 uv.lock 锁定精确版本与哈希。
- 若解析到 prerelease、yanked 包、不可接受许可证或未接受漏洞，停止 setup 并报告，不继续实现。
- T01 产品运行时不引入第三方依赖；使用 argparse、sqlite3、subprocess、dataclasses、enum、json、hashlib、pathlib 等标准库。
- 构建后端使用 hatchling，仅用于标准 src 布局和 sigma console script。

### 13.5 新依赖与理由

| 依赖 | 分组 | 理由 |
|---|---|---|
| hatchling | build | 构建 src 布局并生成 sigma console script |
| pytest | dev | 测试运行器 |
| pytest-cov | dev | 分支覆盖与 coverage.xml |
| jsonschema | dev | 验证版本化 CLI JSON Schema Artifact 与所有条件外壳 |
| hypothesis | dev | 事件链、重建和输入属性测试 |
| mypy | dev | 严格静态类型门 |
| ruff | dev | lint、格式和复杂度门 |
| diff-cover | dev | 对 main 的改动行 100% 覆盖硬门 |
| mutmut 3.x | dev | 关键不变量 AST mutation |
| pytest-randomly | dev | 顺序依赖与波动探测 |
| pip-audit | dev | 锁定依赖漏洞审计 |
| pip-licenses | dev | 许可证清单 |
| detect-secrets | dev | 差异秘密扫描与 honeytoken 负控 |

具体完整版本在批准后首次 lock 时确定并进入 uv.lock；该 lock diff 是 setup checkpoint 的一部分。不得添加表外依赖而不修订 SPEC。

`pip-audit` 的任一发现默认阻断，包括无已知修复版本的发现。唯一豁免路径是先把漏洞 ID、包与锁定版本、影响分析、补偿措施、责任人和明确到期日写入新的 SPEC 修订并重新获批；普通配置、CLI allow、EVIDENCE 备注或“仅开发依赖”不能豁免。

许可证 allowlist 精确为：MIT、0BSD、BSD-2-Clause、BSD-3-Clause、Apache-2.0、ISC、Python-2.0、PSF-2.0、MPL-2.0。`diff-cover` 的锁定传递依赖 `chardet` 使用 0BSD；该许可证是在 r3 setup 的实际依赖解析中发现并经本次修订显式纳入，不是运行时豁免。合法 SPDX `AND`/`OR` 表达式只有在每个许可证原子均属于 allowlist 时才允许；SPDX unknown、custom、不可解析或无法映射名称及含 allowlist 外许可证原子的表达式一律阻断；新增许可证只能通过 SPEC 修订和重新批准。

### 13.6 计划文件

    .python-version
    .gitignore
    pyproject.toml
    uv.lock
    docs/specs/T01-persistent-coding-task.md
    docs/evidence/T01-persistent-coding-task.md
    schemas/cli/v1/envelope.schema.json
    schemas/cli/v1/task-view.schema.json
    schemas/cli/v1/task-list.schema.json
    schemas/cli/v1/error.schema.json
    src/sigmacoder/__init__.py
    src/sigmacoder/__main__.py
    src/sigmacoder/cli.py
    src/sigmacoder/domain/tasks.py
    src/sigmacoder/domain/events.py
    src/sigmacoder/application/task_service.py
    src/sigmacoder/ports/event_store.py
    src/sigmacoder/ports/workspace.py
    src/sigmacoder/adapters/sqlite_event_store.py
    src/sigmacoder/adapters/git_workspace.py
    src/sigmacoder/protocols/cli_v1.py
    tests/support/git_repo_factory.py
    tests/unit/test_event_chain.py
    tests/unit/test_event_semantics.py
    tests/property/test_event_chain_properties.py
    tests/integration/test_task_lifecycle.py
    tests/integration/test_sqlite_reopen.py
    tests/contract/test_cli_v1.py
    tests/adversarial/test_corrupt_event_chain.py
    tests/adversarial/test_semantically_invalid_events.py
    tests/e2e/test_cli_real_run.py
    tools/gauntlet.py
    tools/check_coverage.py
    tools/check_licenses.py
    tools/run_mutation_profile.py
    tools/mutation_profiles.json
    tools/mutation_equivalents.json
    tools/check_mutation_equivalents.py
    tools/source_state.py
    .github/workflows/gauntlet.yml

实现可在不改变模块职责的前提下拆分更多同目录文件；新增顶层模块、运行时依赖、外部服务或网络能力必须修订 SPEC。

### 13.7 RED → GREEN → REFACTOR 顺序

1. 先建立可运行但尚无产品行为的测试骨架和 fail-closed gauntlet。
2. 对一个可观察行为写 RED；RED 必须因缺少该行为而失败。
3. 写最小实现获得 GREEN。
4. 运行该行为的相关层和快速类型/lint。
5. 每完成一个独立行为做 checkpoint commit。
6. REFACTOR 单独进行，保持测试全绿并单独提交。
7. 完成所有场景后运行 Tier 3 Gauntlet 和负控。
8. 最后生成 docs/evidence/T01-persistent-coding-task.md。

建议 checkpoint commit 按以下能力切片，而不是按“先搭全部基础设施”切片：

1. CLI v1 输入/错误契约；
2. Git baseline 冻结与原 worktree 保护；
3. 只增事件、投影与 checkpoint；
4. 跨进程 start/list/status；
5. 先行授权、崩溃采纳与可见失败；
6. 并发、对抗与 Tier 3 门禁。

---

## 14. 依赖与隔离方案

### 14.1 Ticket 依赖

- GitHub 原生 Blocked by：无。
- T01 是 T02、T03 及后续本地核心能力的前置票。
- 本 Ticket 不借用未来 Ticket 的接口来伪造通过。

### 14.2 环境依赖

- CPython 3.12.14（精确版本）；
- uv 0.12.5（精确版本）；
- Git；
- 支持 SQLite WAL 的本地文件系统；
- 测试平台至少 Windows 与 Ubuntu；
- 仅 setup、lock 与漏洞数据库查询可联网；产品运行和所有 Git fixtures 默认无网络。

### 14.3 实施隔离

- 当前 worktree：只保存获批设计、SPEC 与初始基线。
- 实现 worktree：独立 sibling 路径和 ticket 分支。
- 测试 repo：每个测试独立临时目录，由参数化 factory 创建。
- 测试 data root：每个测试独立临时目录，禁止使用真实用户目录。
- 宿主 Git 配置：fixtures 使用隔离的 system/global config 和固定身份。
- 并发测试：每个进程拥有独立输出文件和显式 data root，不共享隐式 cwd 状态。
- T01 不创建 Docker/OCI，也不把“没有 OCI”描述为安全沙盒已完成；T02 的只读/no-exec profile 只是拒绝所有执行型能力的状态机前置条件，不是 SandboxDriver 的替代品。

### 14.4 数据与秘密

- 事件和 CLI 输出不得包含宿主环境变量、Git 凭据或 token。
- objective 是用户输入并按 INTERNAL 持久化；机器输出会原样返回，调用方不得把秘密放入 objective。
- 测试 honeytoken 必须明显为假、只存在于临时文件并在测试后删除。
- 两个本地二进制参考件不进入实现 worktree、依赖锁、测试 fixture、secret-scan 保证范围或远程 push。

### 14.5 Git 提交与远程边界

- SPEC 批准后才允许初始基线 commit。
- 每个 GREEN 行为一个可回滚 checkpoint commit；REFACTOR 独立 commit。
- mutation 后必须证明源码恢复且 source state 干净。
- 本 Ticket 的批准不授权 push、PR、merge、release 或删除远程内容。

---

## 15. 完成定义与证据

只有同时满足以下条件，T01 才能报告完成：

1. S01 至 S19 全部有可追踪自动化测试并通过。
2. GitHub Issue #2 的六条验收标准逐条映射到测试证据。
3. 同一最终候选 commit 与 lock hash 上，Ubuntu `ubuntu-tier3`（含两个 mutation profile）和 Windows `windows-compat` 均新鲜运行并通过。
4. 所有自定义门禁的 fail-closed 负控通过。
5. 两个持久 mutation profile、属性、真实跨进程、并发和对抗层均有原始输出或内容哈希引用；task-service 两次原始 survivor=0；events 两次 full run 与一次 property-only run 均透明记录原始 survived=49，逐项等于 r5 清单，且 unexpected_non_killed=0；独立 checker 通过。
6. changed-line coverage=100%，全产品 branch coverage≥95%，`events.py` 与 `task_service.py` 各自 branch coverage=100%，且三个覆盖率硬门的独立负控均有证据。
7. 锁文件一致；pip-audit 无发现或存在单独获批且未过期的 SPEC 豁免；全部直接/传递依赖 SPDX 均在精确 allowlist 内。
8. 原用户 worktree 零业务改动有前后指纹证据。
9. source state 明确关联到最终 commit，不混入未记录修改。
10. 版本化 CLI JSON Schema Artifact 已交付并通过正反契约样例；docs/evidence/T01-persistent-coding-task.md 已生成，包含命令、版本、seed、平台、commit/lock hash、结果、限制及已知风险。
11. 未把 UNAVAILABLE、SUBSTITUTED 或未运行的层表述为 PASS。
12. 独立 fresh-context 复核若执行，必须读取 SPEC、diff、测试与 Gauntlet 证据，且不得复用实现者的推理轨迹；它是附加证据，不替代上述硬门。

最终报告必须明确：

- 实现了什么；
- 哪些不变量被何种测试证明；
- 哪些能力仍属于后续 Tickets；
- 活进程恢复未实现；
- 是否存在任何不可用门、残余风险或未推送提交。

---

## 16. 修订记录（只增）

- **r0 — 2026-08-21**：依据 Issue #2、design.md、CONTEXT.md 与 ADR 0001/0002/0004/0005，首次定义 T01 的 Tier 3 可执行契约、failure model、17 个场景、Must NOT、setup plan、依赖、隔离与 Gauntlet。状态：等待人工批准。
- **r1 — 2026-08-21**：根据三方复核升级身份、状态机与创建恢复契约：UUIDv4 与 data-root 碰撞约束；PREPARING/HEALTHY 及 T02 只读/no-exec profile；先行 WorkspaceProvisioningAuthorized 事件、ownership nonce/action digest 与严格崩溃采纳；条件 JSON 外壳和版本化 Schema；typed payload/causation/transition 校验；F14、S18、S19；精确 Git metadata 例外；coverage/mutation/source-state 负控；Ubuntu+Windows 总门；供应链默认阻断；git author、uv pin 和 sibling 权限前置。状态：等待人工批准，r0 已被本版取代。
- **r2 — 2026-08-21**：最终阻断修订：工具链精确锁定 CPython 3.12.14 与 uv 0.12.5，并保留旧版本仅作现状观测；恢复顺序改为先完整事件与语义校验、再投影、再识别授权和检查文件系统；TaskViewV1 用条件 oneOf 固定 AVAILABLE、NOT_CREATED、UNVERIFIED、MISSING 与 BASELINE_MISMATCH；删除不可由逻辑 sequence 证明的物理乱序错误码，并为 S09 固定每类变换的错误映射。状态：等待人工批准，r1 已被本版取代。
- **r3 — 2026-08-21**：修正文内版本绑定，将双平台总判定、工具链规范和批准后 setup 全部绑定当前 SPEC r3，避免执行证据继续引用旧版。状态：等待人工批准，r2 已被本版取代。
- **r4 — 2026-08-21**：r3 获人工批准后，首次真实锁定解析发现 `diff-cover 10.5.1` 必然引入 0BSD 的 `chardet 7.6.0`，触发 r3 的白名单外许可证硬阻断；本版显式把 0BSD 纳入精确 allowlist，并把漏洞审计改为从 `uv.lock` 导出全部第三方依赖后审计，以排除本地 editable 项目造成的伪失败，同时让许可证清单排除第一方 `sigmacoder`。状态：等待人工批准；在批准前暂停后续 RED 运行与产品实现，r3 已被本版取代。
- **r5 — 2026-08-24**：r4 产品实现与本地门禁完成后，新鲜 Ubuntu mutation 证据稳定产生 49 个未被现有测试区分的 survivor。本版收窄多重前置畸形的首错契约，逐项批准精确 49 项及五类理由，新增源码/lock/profile/mutmut/全集摘要绑定的封闭等价清单、schema v2 原始报告、独立 checker 和陈旧批准负控；原始 survived=49 必须透明保留，只有 approved_equivalents=49 且 unexpected_non_killed=0 才可通过。状态：2026-08-24 已获人工批准，实施中；不授权合并或发布，r4 已被本版取代。
