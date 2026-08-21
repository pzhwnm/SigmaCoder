# 本地执行域与控制面分域权威

SigmaCoder 采用本地优先的混合架构：Runner 对 Task 轨迹、worktree、工具结果和完整 Artifact 具有事实权威，控制面对组织身份、策略、集中审批和集中审计具有权威。该决定在源码隐私、离线执行与团队治理之间取平衡；代价是必须维护本地 SQLite/Artifact 与控制面 PostgreSQL/S3 两套适配器，并通过幂等 inbox/outbox 和因果事件同步，禁止共享数据库或让两端同时写同一事件流。
