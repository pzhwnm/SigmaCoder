# 模型按能力与风险路由且降级必须显式

核心通过供应商中立的 `ModelGateway` 按工具调用、上下文、结构化输出、隐私和驻留等能力选择模型；Analyst、Implementer、Reviewer 与 Summarizer 可以使用不同模型。每个 provider/model/version/adapter 组合都必须依次通过离线契约与回归检查、无副作用 shadow/canary 观察，达到版本化退出阈值后才通过持续评估驱动的 `Model Eligibility Gate` 进入相应角色生产路由池；新版本不得继承旧版本结论，fallback 也只能选择已准入候选并作为受策略约束、写入轨迹的显式状态转换。该决定减少供应商锁定，但要求维护版本化评估、能力矩阵、统一错误/用量语义、观察流量和适配器契约测试。
