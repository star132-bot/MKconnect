//! 客户端：连接对方，执行测延迟、传文件、测速和端口转发。

use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use bytes::{Bytes, BytesMut};
use iroh::{
    Endpoint, EndpointAddr,
    endpoint::{Connection, ConnectionError},
};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
    time::Instant,
};

use crate::{
    proto::{ALPN, CLOSE_UNTRUSTED, Request, Response, expect_ok, read_msg, write_msg},
    report::{Event, Output, PathKind, current_path, mbit_per_s, ms, spawn_path_watcher},
};

/// 每次写入 QUIC 流的数据块大小。
const CHUNK: usize = 1 << 20;

/// 连接对方并输出建立耗时。
pub async fn connect(
    endpoint: &Endpoint,
    addr: EndpointAddr,
    output: Output,
) -> Result<Connection> {
    let start = Instant::now();
    let conn = endpoint.connect(addr, ALPN).await.context("连接失败")?;
    output.emit(&Event::Connected {
        remote: conn.remote_id().to_string(),
        setup_ms: ms(start.elapsed()),
    });
    Ok(conn)
}

/// 连接是否因为对方不信任本机而被关闭。
pub fn rejected_as_untrusted(conn: &Connection) -> bool {
    matches!(
        conn.close_reason(),
        Some(ConnectionError::ApplicationClosed(close)) if close.error_code == CLOSE_UNTRUSTED
    )
}

/// 每隔 `interval` 测一次往返延迟，共 `count` 次；返回结束时的路径。
pub async fn ping(
    conn: &Connection,
    count: u64,
    interval: Duration,
    output: Output,
) -> Result<PathKind> {
    let (mut send, mut recv) = conn.open_bi().await?;
    write_msg(&mut send, &Request::Ping).await?;
    expect_ok(&mut recv).await?;

    let mut rtts = Vec::with_capacity(count as usize);
    for seq in 1..=count {
        let start = Instant::now();
        send.write_all(&seq.to_be_bytes()).await?;
        let mut echo = [0u8; 8];
        match tokio::time::timeout(Duration::from_secs(5), recv.read_exact(&mut echo)).await {
            Ok(result) => result?,
            Err(_) => {
                tracing::warn!("第 {seq} 次 5 秒内无回应，停止测量");
                break;
            }
        }
        if u64::from_be_bytes(echo) != seq {
            bail!("回显序号不符");
        }
        let rtt = start.elapsed();
        rtts.push(rtt);
        output.emit(&Event::Ping {
            seq,
            rtt_ms: ms(rtt),
        });
        if seq < count {
            tokio::time::sleep(interval).await;
        }
    }
    send.finish()?;

    let final_path = current_path(conn).0;
    let received = rtts.len() as u64;
    let (min, max, sum) = rtts.iter().fold(
        (Duration::MAX, Duration::ZERO, Duration::ZERO),
        |(min, max, sum), &rtt| (min.min(rtt), max.max(rtt), sum + rtt),
    );
    output.emit(&Event::PingSummary {
        sent: count,
        received,
        min_ms: if received > 0 { ms(min) } else { 0.0 },
        avg_ms: if received > 0 {
            ms(sum) / received as f64
        } else {
            0.0
        },
        max_ms: ms(max),
        final_path,
    });
    if received == 0 {
        bail!("没有收到任何回应");
    }
    Ok(final_path)
}

/// 测速：向对方发送 `bytes` 字节，以对方确认收完为准计时。
pub async fn bench(conn: &Connection, bytes: u64, output: Output) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await?;
    write_msg(&mut send, &Request::Bench).await?;
    expect_ok(&mut recv).await?;

    // 同一块数据反复发送，Bytes 只增加引用计数，不复制。
    let chunk = Bytes::from(vec![0xA5u8; CHUNK]);
    let start = Instant::now();
    let mut sent = 0u64;
    while sent < bytes {
        let n = (bytes - sent).min(CHUNK as u64) as usize;
        send.write_chunk(chunk.slice(..n)).await?;
        sent += n as u64;
    }
    send.finish()?;
    let received = match read_msg(&mut recv).await? {
        Response::BenchDone { bytes } => bytes,
        other => bail!("意外的响应：{other:?}"),
    };
    let elapsed = start.elapsed();
    if received != sent {
        bail!("对方只收到 {received} / {sent} 字节");
    }
    output.emit(&Event::Transfer {
        what: "测速发送".into(),
        name: None,
        bytes: received,
        secs: elapsed.as_secs_f64(),
        mbit_per_s: mbit_per_s(received, elapsed),
        verified: None,
        path: current_path(conn).0,
    });
    Ok(())
}

/// 发送文件；对方用 BLAKE3 校验，校验失败视为错误。
pub async fn send_file(conn: &Connection, path: &Path, output: Output) -> Result<()> {
    let meta = fs::metadata(path)
        .await
        .with_context(|| format!("无法读取文件：{}", path.display()))?;
    if !meta.is_file() {
        bail!("不是普通文件：{}", path.display());
    }
    let size = meta.len();
    let name = path
        .file_name()
        .context("无法取得文件名")?
        .to_string_lossy()
        .into_owned();

    let (mut send, mut recv) = conn.open_bi().await?;
    write_msg(
        &mut send,
        &Request::File {
            name: name.clone(),
            size,
        },
    )
    .await?;
    expect_ok(&mut recv).await?;

    let start = Instant::now();
    let mut file = fs::File::open(path).await?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = BytesMut::with_capacity(CHUNK);
    let mut sent = 0u64;
    loop {
        buf.reserve(CHUNK);
        let n = file.read_buf(&mut buf).await?;
        if n == 0 {
            break;
        }
        let chunk = buf.split().freeze();
        hasher.update(&chunk);
        send.write_chunk(chunk).await?;
        sent += n as u64;
    }
    if sent != size {
        bail!("文件在发送过程中被修改：预期 {size} 字节，实际 {sent} 字节");
    }
    send.write_all(hasher.finalize().as_bytes()).await?;
    send.finish()?;

    let verified = match read_msg(&mut recv).await? {
        Response::FileDone { verified } => verified,
        other => bail!("意外的响应：{other:?}"),
    };
    let elapsed = start.elapsed();
    output.emit(&Event::Transfer {
        what: "发送文件".into(),
        name: Some(name),
        bytes: size,
        secs: elapsed.as_secs_f64(),
        mbit_per_s: mbit_per_s(size, elapsed),
        verified: Some(verified),
        path: current_path(conn).0,
    });
    if !verified {
        bail!("对方校验失败，文件未保存");
    }
    Ok(())
}

/// 本机监听 `listen`，每个进来的 TCP 连接都转发到对方的 `target`。
/// 与对方的连接断开后，下一个 TCP 连接到来时自动重连。
pub async fn forward(
    endpoint: &Endpoint,
    addr: EndpointAddr,
    listen: SocketAddr,
    target: String,
    output: Output,
) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("无法监听 {listen}"))?;
    output.emit(&Event::Forwarding {
        listen: listener.local_addr()?.to_string(),
        target: target.clone(),
    });

    let slot: Arc<Mutex<Option<Connection>>> = Arc::new(Mutex::new(None));
    loop {
        let (tcp, _) = tokio::select! {
            accepted = listener.accept() => accepted?,
            _ = tokio::signal::ctrl_c() => return Ok(()),
        };
        let conn = match live_connection(endpoint, &addr, &slot, output).await {
            Ok(conn) => conn,
            Err(err) => {
                tracing::warn!("无法连接对方：{err:#}");
                continue;
            }
        };
        let target = target.clone();
        tokio::spawn(async move {
            if let Err(err) = forward_one(&conn, tcp, target).await {
                tracing::warn!("转发失败：{err:#}");
            }
        });
    }
}

async fn live_connection(
    endpoint: &Endpoint,
    addr: &EndpointAddr,
    slot: &Mutex<Option<Connection>>,
    output: Output,
) -> Result<Connection> {
    let mut slot = slot.lock().await;
    if let Some(conn) = slot.as_ref().filter(|c| c.close_reason().is_none()) {
        return Ok(conn.clone());
    }
    let conn = connect(endpoint, addr.clone(), output).await?;
    spawn_path_watcher(conn.clone(), output);
    *slot = Some(conn.clone());
    Ok(conn)
}

async fn forward_one(conn: &Connection, mut tcp: TcpStream, target: String) -> Result<()> {
    tcp.set_nodelay(true)?;
    let (mut send, mut recv) = conn.open_bi().await?;
    write_msg(&mut send, &Request::Forward { target }).await?;
    expect_ok(&mut recv).await?;
    let mut stream = tokio::io::join(recv, send);
    tokio::io::copy_bidirectional(&mut tcp, &mut stream).await?;
    Ok(())
}

/// 把标准输入输出接到对方的 `target`，供 SSH 的 ProxyCommand 使用。
pub async fn proxy_stdio(conn: &Connection, target: String) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await?;
    write_msg(&mut send, &Request::Forward { target }).await?;
    expect_ok(&mut recv).await?;

    let upload = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        tokio::io::copy(&mut stdin, &mut send).await?;
        send.finish()?;
        anyhow::Ok(())
    });
    let mut stdout = tokio::io::stdout();
    tokio::io::copy(&mut recv, &mut stdout).await?;
    stdout.flush().await?;
    // 对方已关闭，不再等待本地输入。
    upload.abort();
    Ok(())
}
