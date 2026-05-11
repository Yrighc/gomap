# secprobe rsync Boundary Note

日期：2026-05-11

当前不将 `rsync` 并入本轮 P2 实现，原因如下：

- `rsync` 同时存在匿名模块访问与凭证认证边界
- 第一版若同时做模块枚举、匿名确认、凭证认证，容易把 provider 写成小引擎
- 当前 `secprobe` 的推荐模型是：
  - `credential` provider 只做一次认证尝试
  - `unauthorized` checker 只做一次匿名确认

因此本轮结论为：

- `rsync` 延后
- 后续先单独设计它的模块发现与匿名访问边界
