# MKconnect

让服务器和主机在不同网络下安全互联：能直连就直连，连不上自动走中继，全程端到端加密。

当前处于**阶段 1：原型验证**，支持 Linux 和 macOS。目标是验证底层选型（Rust + [iroh](https://github.com/n0-computer/iroh) 1.x）在真实网络下是否可行，并用 NAT 矩阵测试量化连通性。

## 原型能做什么

| 命令 | 作用 |
| --- | --- |
| `mk id` | 显示本机设备 ID（首次运行时生成密钥） |
| `mk trust add/remove/list` | 管理允许连入本机的设备 |
| `mk listen` | 等待其他设备连入，打印连接票据 |
| `mk ping <目标>` | 测往返延迟，显示走的是直连还是中继 |
| `mk send <目标> <文件>` | 发送文件，BLAKE3 校验，不覆盖已有文件 |
| `mk bench <目标>` | 测上传速度 |
| `mk forward <目标> --listen 127.0.0.1:2222` | 本机端口转发到对方，例如对方的 SSH |
| `mk proxy <目标>` | 供 `ssh -o ProxyCommand` 使用 |

`<目标>` 可以是 `mk listen` 打印的票据（`mk1...`）、设备 ID，或 `设备ID@IP:端口`。

所有命令都支持 `--json`，按行输出事件，便于脚本统计。

## 编译

需要 Rust 1.91 或更新版本。

```bash
cargo build --release
```

程序在 `target/release/mk`。

## 快速上手：从 Mac 连到 Linux 服务器的 SSH

1. 两台机器各执行一次 `mk id`，记下设备 ID。
2. 在服务器上信任 Mac，然后开始等待连接，只允许转发到本机 SSH：

   ```bash
   mk trust add <Mac 的设备ID>
   mk listen --forward-allow 127.0.0.1:22
   ```

   复制打印出来的连接票据。
3. 在 Mac 上用 SSH 连过去：

   ```bash
   ssh -o ProxyCommand="mk proxy <票据>" 用户名@服务器
   ```

   或者先做端口转发，再连本机端口：

   ```bash
   mk forward <票据> --listen 127.0.0.1:2222
   ssh -p 2222 用户名@127.0.0.1
   ```

## 安全设计

- 每台设备一对 Ed25519 密钥，公钥即设备 ID；私钥保存在 `~/.config/mkconnect/secret.key`，权限 600。
- 连接用 QUIC + TLS 1.3，双方互相验证设备 ID；中继只转发密文。
- `mk listen` 默认只接受信任列表里的设备；`--open` 仅用于测试。
- 端口转发只允许 `--forward-allow` 明确列出的地址。
- 收到的文件名会去掉路径，拒绝 `../` 等穿越写法；同名文件自动改名，不覆盖。

## 中继

不加参数时使用 iroh 官方公共中继，**只适合开发测试**：它们在海外、限速且没有保障。实测从这台 Mac 强制走美国西部中继，延迟约 300 ms，速度约 6.7 Mbit/s。

正式使用请自建 [iroh-relay](https://crates.io/crates/iroh-relay)，并通过 `--relay https://你的中继` 指定；中继用自签名证书时加 `--relay-ca 证书.pem`。

## 测试

```bash
cargo test                 # 单元测试与端到端测试（本机双端点直连）
sudo tests/nat-matrix/run.sh target/release/mk "$(command -v iroh-relay)"   # 仅 Linux
```

NAT 矩阵测试用 Linux 网络命名空间模拟四种 NAT（无 NAT、完全锥形、端口受限锥形、对称型），逐一测试 16 种组合能否连通、最终走直连还是中继。GitHub Actions 会在每次提交时自动运行，并把结果表写进运行摘要。

## 已有实测结果

| 项目 | 结果 |
| --- | --- |
| 本机经 127.0.0.1 测速 | 1,342 Mbit/s，为 iroh 官方测速示例（1,390 Mbit/s）的 97% |
| 本机经局域网 IP 测速 | 515 Mbit/s，与 iroh 官方示例相同，受同机 1500 字节包的处理开销限制 |
| 190 MiB 文件传输 | 校验通过，内容一致 |
| 强制走海外公共中继 | 可连通，延迟约 300 ms |
| NAT 矩阵（16 种组合，自建中继） | 全部连通，13 种直连；3 种走中继，均为“一侧对称型、另一侧端口受限或对称型”的困难组合 |

NAT 矩阵结果（每格为最终路径和平均往返延迟，模拟链路单向延迟 10 ms）：

| A \ B | 无 NAT | 完全锥形 | 端口受限锥形 | 对称型 |
| --- | --- | --- | --- | --- |
| 无 NAT | 直连 24 ms | 直连 26 ms | 直连 25 ms | 直连 24 ms |
| 完全锥形 | 直连 25 ms | 直连 25 ms | 直连 25 ms | 直连 25 ms |
| 端口受限锥形 | 直连 25 ms | 直连 26 ms | 直连 25 ms | 中继 27 ms |
| 对称型 | 直连 25 ms | 直连 24 ms | 中继 26 ms | 中继 28 ms |

走中继的 3 种组合需要“端口探测打洞”才能直连（Tailscale 的做法），iroh 1.3 目前没有，这是下一阶段要补的能力。

两台物理机器之间的千兆实测、国内宽带和 4G/5G 下的直连比例，还需要在真实网络中测量。
