# OCS Encryption Chat

跨平台、离线优先的剪贴板加密聊天桌面应用。

> **安全状态说明**
>
> 本仓库已从工程骨架实现为功能完整、自动化测试覆盖的应用:
> 真实 Signal Protocol(PQXDH + Double Ratchet,官方 libsignal v0.108.0)、
> SQLCipher 加密存储、Argon2id 主密码、加密备份均已接入并通过测试。
> 但**尚未完成独立第三方安全审计**。在完成审计之前,不要用于保护真实敏感通信。
> "能互相加解密"不等于安全证明;剪贴板不是可信信道;被恶意软件控制的端点不受保护。

## 产品目标

- Windows / Linux / macOS 桌面端(Avalonia UI + C#/.NET 10)
- 独立 Rust 加密核心边界(FFI,JSON 契约,无状态调用)
- Signal Protocol 技术路线;无服务器场景采用人工公钥包交换
- 剪贴板密文识别、解密归档;发送时加密并复制
- 多联系人、多会话;带外指纹验证
- 加密持久化(SQLCipher + 应用层 AEAD)、认证加密备份
- 正式运行时不需要网络、账号或自建服务器

## 已实现内容

| 层 | 内容 |
| --- | --- |
| `native/ocs-signal-bridge` | Rust FFI 桥:身份/预密钥包生成与验证、PQXDH 会话建立、Double Ratchet 加解密、Argon2id KDF、XChaCha20Poly1305 AEAD、指纹。依赖 vendored 官方 libsignal v0.108.0(`native/vendor/`) |
| `native/prebuilt/win-x64` | 预构建 `ocs_signal_bridge.dll`(Windows x64),应用与测试直接引用 |
| `src/OCS.Core` | 领域模型与抽象接口(加密引擎、加密仓库、剪贴板) |
| `src/OCS.Services` | Rust 引擎适配、vault 主密码管理、SQLCipher 仓库(事务性消息+棘轮状态持久化)、严格信封解析、聊天编排(每会话串行化、自写抑制、重放去重)、认证加密备份/恢复 |
| `src/OCS.Platform` | Avalonia 剪贴板适配(仅文本、700ms 轮询、自写抑制、超大守卫)、应用数据路径 |
| `src/OCS.App` | Avalonia UI:解锁/新建库、聊天、联系人(导入/带外验证)、密钥管理(公钥包导出/OTPK 库存)、安全中心(事件/监视开关/手动锁定)、设置(自动锁定/备份/恢复);`--selftest` 无头端到端验证 |
| `tests/OCS.Tests` | 29 个 xunit 测试,覆盖 TEST-PLAN 矩阵核心项 |

关键安全行为(均有自动化测试):

- 篡改的公钥包(签名/身份/版本/过期/重复 OTPK)→ 拒绝导入
- 指纹不匹配 → 抛错,**绝不**标记为已验证
- 一次性预密钥(OTPK)原子消费;复用已消费 OTPK → 协议栈 fail closed
- 重放同一信封 → 拒绝,无重复显示;自己的剪贴板写入 → 不递归导入
- 错误主密码 → fail closed;损坏备份 → 拒绝且活动数据库不受影响
- 超大/畸形剪贴板文本 → 安全忽略
- 数据库/WAL/vault 元数据/备份文件 → 字节级扫描无明文消息与主密码
- 同一会话并发发送 → 串行化棘轮状态更新,两条消息均可解密
- 重启后历史与棘轮状态完整,可继续会话
- 发送状态仅为"已复制 · 请手动发送",绝不显示"已送达/已读"

## 技术基线(已验证锁定)

- .NET SDK 10.0.404;Avalonia 11.3.23(骨架中的 12.0.0 未经存在性验证,按 BUILD.md 要求改为实际验证的版本)
- Rust stable 1.100.0(x86_64-pc-windows-gnu);libsignal v0.108.0(vendored,AGPL-3.0-only)
- SQLCipher 经 SQLitePCLRaw.bundle_e_sqlcipher 2.1.11 + Microsoft.Data.Sqlite.Core 10.0.15;**无明文 SQLite 回退**
- Argon2id(m=64MiB, t=3, p=4)从主密码派生包装密钥;随机 DB 密钥与 DEK 分别 AEAD 包装
- 版本锁文件:`packages.lock.json`(5 个工程)与 `native/ocs-signal-bridge/Cargo.lock` 均已提交

## 快速开始

前置:.NET 10 SDK、Rust stable(仅重建加密桥时需要)、Git。

```bash
# 构建(使用预构建的 win-x64 加密桥 DLL)
dotnet build OCS-Encryption-Chat.sln -c Release

# 运行桌面应用
dotnet run --project src/OCS.App -c Release

# 无头端到端自检(双端点互操作 + 安全矩阵,约 30 秒)
dotnet run --project src/OCS.App -c Release -- --selftest

# 自动化测试(29 项)
dotnet test tests/OCS.Tests/OCS.Tests.csproj -c Release
```

重建 Rust 加密桥(仅 Windows x64 已验证;需要 protoc 与 GNU 工具链,详见 `docs/BUILD.md`):

```bash
cd native/ocs-signal-bridge
cargo build --release
cargo test --release
# 产物复制到 native/prebuilt/win-x64/ocs_signal_bridge.dll
```

首次启动会要求创建主密码(≥8 位,建议长 passphrase)并生成加密库。
与对端交换公钥包(联系人页导出/导入),**带外比对指纹后**再标记已验证,然后即可聊天。

## 严格安全原则

- 禁止自创密码算法或自定义 Signal 协议变体。
- 不得把"能互相加解密"当作协议安全证明。
- 不得将私钥、主密码、数据库密钥写入源码、配置文件或日志。
- 不得使用明文 SQLite 作为生产环境回退(ADR-004,fail closed)。
- 发送成功只表示本地加密/复制成功,不代表原 IM 已发送或对方已收到。
- 复制到剪贴板的数据会被操作系统及其他有权限的应用访问;剪贴板不是可信安全信道。
- 本地设备已被恶意软件控制时,端到端加密无法保护显示中的明文或内存中的密钥。
- 预密钥耗尽不得静默降级;要求导出/交换新的已验证公钥包。

## 许可与第三方依赖

组合产物包含 AGPL-3.0-only 组件(libsignal、spqr),**整体须以 AGPL-3.0 兼容条款分发**(仓库根 `LICENSE` 为 AGPL-3.0 全文)。逐项版本、commit、许可证与已知限制见 `LICENSE-THIRD-PARTY.md`。独立安全审计与依赖 advisory 扫描仍是发布阻塞项(见 `docs/ROADMAP.md` M5)。