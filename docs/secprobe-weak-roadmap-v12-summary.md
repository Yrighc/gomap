# GoMap secprobe v1.2 规划摘要（参考 Chujiu_reload）

日期：2026-04-22

## 1. 结论

基于 `/Users/yrighc/work/hzyz/project/Chujiu_reload` 的弱认证能力分析，GoMap `secprobe v1.2` 建议采用“统一入口、内部分型”的演进方式，而不是直接复制其 `servicebrute + hostdetection` 双模块结构。

## 2. 主要借鉴点

从 `Chujiu_reload` 中建议吸收：

- 账号口令探测与未授权探测是两类不同能力
- `redis` / `mongodb` 未授权应当作为独立探测类型表达
- 命中后的详情补采是有价值的，但应设计为可选后处理
- 服务别名映射值得借鉴，但应保持 GoMap 版本的轻量化

不建议吸收：

- Temporal 工作流
- Redis 缓冲
- 平台化结果存储
- 大而全协议面
- `x-crack` 这类外部大爆破引擎接入

## 3. 对 roadmap v1.2 的修正

原 roadmap 中 `v1.2` 的方向仍然成立，但建议进一步明确：

- `v1.2` 不只是接 `redis` / `mongodb` unauth
- 还需要同步补：
  - `ProbeKind`
  - 统一 finding 模型
  - 可选 enrichment

## 4. 推荐实施顺序

推荐顺序调整为：

1. `v1.2-a`
   - 扩展 `ProbeKind`
   - 扩展 `FindingType`
   - 搭建 `credential` / `unauthorized` 执行骨架
2. `v1.2-b`
   - 接入 Redis unauth
   - 接入 MongoDB unauth
   - 补服务别名归一化
3. `v1.2-c`
   - 接入可选 enrichment
   - 首批支持 Redis / MongoDB 成功后详情补采

## 5. 对后续路线的影响

这样调整后，后续路线更清晰：

- `v1.2`：完成“统一弱认证能力”基础升级
- `v1.3`：再做执行治理与控制面增强
- `v2.0`：再考虑平台化与可扩展输出层

## 6. 对当前项目的意义

这条路线能让 GoMap：

- 保持当前 `assetprobe` / `secprobe` 边界稳定
- 不回到历史上的“大一统扫描器”
- 又能把 `Chujiu_reload` 中真正有价值的弱认证能力吸收进来
