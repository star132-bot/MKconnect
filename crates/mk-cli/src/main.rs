//! `mk`：MKconnect 命令行工具（阶段 1 原型）。

use std::{
    collections::HashSet, net::SocketAddr, path::PathBuf, process::ExitCode, time::Duration,
};

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use iroh::{Endpoint, RelayUrl, endpoint::Connection};
use mk_core::{
    client,
    identity::{self, TrustStore},
    net::{self, NetOptions, RelayChoice},
    proto::CLOSE_OK,
    report::{Event, Output, spawn_path_watcher},
    server::{self, ServeOptions, Trust},
    ticket,
};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "mk",
    version,
    about = "MKconnect：让服务器和主机跨网络安全互联（阶段 1 原型）"
)]
struct Cli {
    /// 以 JSON 行输出事件，便于脚本统计
    #[arg(long, global = true)]
    json: bool,
    /// 数据目录，默认 ~/.config/mkconnect（也可用环境变量 MK_HOME）
    #[arg(long, global = true, value_name = "目录")]
    home: Option<PathBuf>,
    /// 自建中继地址，可写多次；不写则使用 iroh 官方公共中继（仅适合测试）
    #[arg(long = "relay", global = true, value_name = "URL")]
    relays: Vec<RelayUrl>,
    /// 自建中继的自签名证书（PEM）
    #[arg(long, global = true, value_name = "PEM")]
    relay_ca: Option<PathBuf>,
    /// 不使用中继，只尝试直连
    #[arg(long, global = true, conflicts_with = "relay_only")]
    no_relay: bool,
    /// 只走中继、禁止直连，用于测试中继兜底
    #[arg(long, global = true)]
    relay_only: bool,
    /// 固定本地 UDP 端口
    #[arg(long, global = true)]
    port: Option<u16>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// 显示本机设备 ID（首次运行时生成密钥）
    Id,
    /// 管理允许连入本机的设备
    Trust {
        #[command(subcommand)]
        action: TrustAction,
    },
    /// 等待其他设备连入
    Listen {
        /// 允许任何设备连入（仅用于测试）
        #[arg(long)]
        open: bool,
        /// 额外允许的设备 ID，可写多次
        #[arg(long = "allow", value_name = "设备ID")]
        allow: Vec<String>,
        /// 收到的文件保存位置
        #[arg(long, default_value = "mk-received")]
        dir: PathBuf,
        /// 允许对方转发到的地址，可写多次，例如 127.0.0.1:22
        #[arg(long = "forward-allow", value_name = "地址:端口")]
        forward_allow: Vec<String>,
    },
    /// 测量往返延迟，并显示走的是直连还是中继
    Ping {
        /// 对方的连接票据或设备 ID
        target: String,
        #[arg(short, long, default_value_t = 10)]
        count: u64,
        #[arg(long, default_value_t = 1000, value_name = "毫秒")]
        interval_ms: u64,
    },
    /// 发送文件（BLAKE3 校验）
    Send { target: String, file: PathBuf },
    /// 测试上传速度
    Bench {
        target: String,
        /// 发送的数据量（MiB）
        #[arg(long, default_value_t = 256)]
        mib: u64,
    },
    /// 本机端口转发到对方，例如把本机 2222 转到对方的 SSH
    Forward {
        target: String,
        /// 本机监听地址，例如 127.0.0.1:2222
        #[arg(long)]
        listen: SocketAddr,
        /// 对方要转发到的地址
        #[arg(long, default_value = "127.0.0.1:22")]
        to: String,
    },
    /// 用标准输入输出连到对方，供 ssh -o ProxyCommand 使用
    Proxy {
        target: String,
        #[arg(long, default_value = "127.0.0.1:22")]
        to: String,
    },
}

#[derive(Debug, Subcommand)]
enum TrustAction {
    /// 允许一台设备连入
    Add { id: String },
    /// 移除一台设备
    Remove { id: String },
    /// 列出允许连入的设备
    List,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("错误：{err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_env("MK_LOG").unwrap_or_else(|_| "warn".into()))
        .with_writer(std::io::stderr)
        .init();

    let home = match &cli.home {
        Some(home) => home.clone(),
        None => identity::default_home()?,
    };
    let output = Output {
        json: cli.json,
        // ProxyCommand 模式下标准输出是 SSH 数据，事件改写到标准错误。
        to_stderr: matches!(cli.command, Command::Proxy { .. }),
    };
    let net_opts = NetOptions {
        relay: if cli.no_relay {
            RelayChoice::Disabled
        } else if cli.relays.is_empty() {
            RelayChoice::Public
        } else {
            RelayChoice::Custom(cli.relays.clone())
        },
        relay_ca: cli.relay_ca.clone(),
        relay_only: cli.relay_only,
        port: cli.port,
    };

    match cli.command {
        Command::Id => {
            let secret = identity::load_or_create_secret(&home)?;
            println!("{}", secret.public());
        }
        Command::Trust { action } => {
            let mut store = TrustStore::load(&home)?;
            match action {
                TrustAction::Add { id } => {
                    let id = identity::parse_endpoint_id(&id)?;
                    if store.add(id)? {
                        println!("已允许 {id} 连入");
                    } else {
                        println!("{id} 已在信任列表中");
                    }
                }
                TrustAction::Remove { id } => {
                    let id = identity::parse_endpoint_id(&id)?;
                    if store.remove(&id)? {
                        println!("已移除 {id}");
                    } else {
                        println!("{id} 不在信任列表中");
                    }
                }
                TrustAction::List => {
                    for id in store.ids() {
                        println!("{id}");
                    }
                }
            }
        }
        Command::Listen {
            open,
            allow,
            dir,
            forward_allow,
        } => {
            let trust = if open {
                eprintln!("警告：--open 允许任何知道本机 ID 的设备连入，仅用于测试");
                Trust::Open
            } else {
                let mut ids: HashSet<_> = TrustStore::load(&home)?.ids().into_iter().collect();
                for id in &allow {
                    ids.insert(identity::parse_endpoint_id(id)?);
                }
                if ids.is_empty() {
                    bail!(
                        "信任列表为空：请先在本机执行 mk trust add <对方设备ID>，或用 --allow 指定；测试时可加 --open"
                    );
                }
                Trust::Only(ids)
            };
            let endpoint = bind(&home, &net_opts).await?;
            emit_bound(&endpoint, output);
            let opts = ServeOptions {
                trust,
                recv_dir: dir,
                forward_allow,
            };
            server::serve(endpoint.clone(), opts, output).await?;
            close(&endpoint).await;
        }
        Command::Ping {
            target,
            count,
            interval_ms,
        } => {
            with_connection(&home, &net_opts, &target, output, |conn| async move {
                client::ping(&conn, count, Duration::from_millis(interval_ms), output).await?;
                Ok(())
            })
            .await?;
        }
        Command::Send { target, file } => {
            with_connection(&home, &net_opts, &target, output, |conn| async move {
                client::send_file(&conn, &file, output).await
            })
            .await?;
        }
        Command::Bench { target, mib } => {
            with_connection(&home, &net_opts, &target, output, |conn| async move {
                client::bench(&conn, mib * 1024 * 1024, output).await
            })
            .await?;
        }
        Command::Forward { target, listen, to } => {
            let addr = ticket::parse_target(&target)?;
            let endpoint = bind(&home, &net_opts).await?;
            let result = client::forward(&endpoint, addr, listen, to, output).await;
            close(&endpoint).await;
            result?;
        }
        Command::Proxy { target, to } => {
            with_connection(&home, &net_opts, &target, output, |conn| async move {
                client::proxy_stdio(&conn, to).await
            })
            .await?;
        }
    }
    Ok(())
}

async fn bind(home: &std::path::Path, opts: &NetOptions) -> Result<Endpoint> {
    let secret = identity::load_or_create_secret(home)?;
    net::bind(secret, opts).await
}

fn emit_bound(endpoint: &Endpoint, output: Output) {
    let addr = endpoint.addr();
    output.emit(&Event::Bound {
        endpoint_id: endpoint.id().to_string(),
        ticket: ticket::encode(&addr),
        direct_addrs: addr.ip_addrs().map(ToString::to_string).collect(),
        relay_url: addr.relay_urls().next().map(ToString::to_string),
    });
}

/// 建立连接、在后台报告路径变化、执行 `task`，最后正常关闭连接。
async fn with_connection<F, Fut>(
    home: &std::path::Path,
    opts: &NetOptions,
    target: &str,
    output: Output,
    task: F,
) -> Result<()>
where
    F: FnOnce(Connection) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let addr = ticket::parse_target(target)?;
    let endpoint = bind(home, opts).await?;
    let result = async {
        let conn = client::connect(&endpoint, addr, output).await?;
        let watcher = spawn_path_watcher(conn.clone(), output);
        let mut result = task(conn.clone()).await;
        if result.is_err() && client::rejected_as_untrusted(&conn) {
            result = Err(anyhow::anyhow!(
                "对方没有信任本机。请在对方设备上执行：mk trust add {}",
                endpoint.id()
            ));
        }
        conn.close(CLOSE_OK, b"done");
        watcher.abort();
        result
    }
    .await;
    close(&endpoint).await;
    result
}

async fn close(endpoint: &Endpoint) {
    let _ = tokio::time::timeout(Duration::from_secs(3), endpoint.close()).await;
}
