//! 服务端：接受连接，只放行信任列表里的设备，按请求类型处理每条流。

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use anyhow::{Result, bail};
use iroh::{
    Endpoint, EndpointId,
    endpoint::{Connection, ConnectionError, Incoming, RecvStream, SendStream},
};
use tokio::{fs, io::AsyncWriteExt, net::TcpStream};

use crate::{
    proto::{CLOSE_OK, CLOSE_UNTRUSTED, Request, Response, read_msg, write_msg},
    report::{Event, Output, current_path, mbit_per_s, spawn_path_watcher},
};

/// 谁可以连入本机。
#[derive(Debug, Clone)]
pub enum Trust {
    /// 任何知道本机 ID 的设备都能连入，只用于测试。
    Open,
    /// 只允许这些设备。
    Only(HashSet<EndpointId>),
}

impl Trust {
    pub fn allows(&self, id: &EndpointId) -> bool {
        match self {
            Trust::Open => true,
            Trust::Only(ids) => ids.contains(id),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServeOptions {
    pub trust: Trust,
    /// 收到的文件保存在这里。
    pub recv_dir: PathBuf,
    /// 允许对方转发到的 TCP 地址，例如 `127.0.0.1:22`；为空则禁止转发。
    pub forward_allow: Vec<String>,
}

/// 持续接受连接，直到按下 Ctrl-C 或端点关闭。
pub async fn serve(endpoint: Endpoint, opts: ServeOptions, output: Output) -> Result<()> {
    let opts = Arc::new(opts);
    loop {
        let incoming = tokio::select! {
            incoming = endpoint.accept() => match incoming {
                Some(incoming) => incoming,
                None => break,
            },
            _ = tokio::signal::ctrl_c() => break,
        };
        let opts = opts.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_incoming(incoming, opts, output).await {
                tracing::warn!("连接处理失败：{err:#}");
            }
        });
    }
    Ok(())
}

async fn handle_incoming(
    incoming: Incoming,
    opts: Arc<ServeOptions>,
    output: Output,
) -> Result<()> {
    let conn = incoming.accept()?.await?;
    let remote = conn.remote_id();
    if !opts.trust.allows(&remote) {
        output.emit(&Event::Rejected {
            remote: remote.to_string(),
            reason: "不在信任列表中".into(),
        });
        conn.close(CLOSE_UNTRUSTED, b"untrusted");
        return Ok(());
    }

    output.emit(&Event::Accepted {
        remote: remote.to_string(),
    });
    let watcher = spawn_path_watcher(conn.clone(), output);

    let close_reason = loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                let opts = opts.clone();
                let conn = conn.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_stream(send, recv, &opts, &conn, output).await {
                        // 对方正常关闭连接时，进行中的流会随之结束，不算错误。
                        if closed_gracefully(&conn) {
                            tracing::debug!("连接已正常关闭：{err:#}");
                        } else {
                            tracing::warn!("请求处理失败：{err:#}");
                        }
                    }
                });
            }
            Err(err) => break err,
        }
    };
    watcher.abort();

    let reason = match close_reason {
        ConnectionError::ApplicationClosed(close) if close.error_code == CLOSE_OK => None,
        other => Some(other.to_string()),
    };
    output.emit(&Event::Closed {
        remote: remote.to_string(),
        reason,
    });
    Ok(())
}

async fn handle_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    opts: &ServeOptions,
    conn: &Connection,
    output: Output,
) -> Result<()> {
    let request: Request = read_msg(&mut recv).await?;
    match request {
        Request::Ping => {
            write_msg(&mut send, &Response::Ok).await?;
            tokio::io::copy(&mut recv, &mut send).await?;
            send.finish()?;
        }
        Request::Bench => {
            write_msg(&mut send, &Response::Ok).await?;
            let start = Instant::now();
            let mut bytes = 0u64;
            while let Some(chunk) = recv.read_chunk(usize::MAX).await? {
                bytes += chunk.len() as u64;
            }
            let elapsed = start.elapsed();
            write_msg(&mut send, &Response::BenchDone { bytes }).await?;
            send.finish()?;
            output.emit(&Event::Transfer {
                what: "测速接收".into(),
                name: None,
                bytes,
                secs: elapsed.as_secs_f64(),
                mbit_per_s: mbit_per_s(bytes, elapsed),
                verified: None,
                path: current_path(conn).0,
            });
        }
        Request::File { name, size } => {
            receive_file(send, recv, &name, size, &opts.recv_dir, conn, output).await?;
        }
        Request::Forward { target } => {
            if !opts.forward_allow.iter().any(|allowed| allowed == &target) {
                deny(&mut send, format!("本机未允许转发到 {target}")).await?;
                return Ok(());
            }
            let mut tcp = match TcpStream::connect(&target).await {
                Ok(tcp) => tcp,
                Err(err) => {
                    deny(&mut send, format!("无法连接 {target}：{err}")).await?;
                    return Ok(());
                }
            };
            tcp.set_nodelay(true)?;
            write_msg(&mut send, &Response::Ok).await?;
            let mut stream = tokio::io::join(recv, send);
            tokio::io::copy_bidirectional(&mut stream, &mut tcp).await?;
        }
    }
    Ok(())
}

fn closed_gracefully(conn: &Connection) -> bool {
    matches!(
        conn.close_reason(),
        Some(ConnectionError::ApplicationClosed(close)) if close.error_code == CLOSE_OK
    )
}

async fn deny(send: &mut SendStream, reason: String) -> Result<()> {
    write_msg(send, &Response::Denied { reason }).await?;
    send.finish()?;
    Ok(())
}

async fn receive_file(
    mut send: SendStream,
    mut recv: RecvStream,
    name: &str,
    size: u64,
    dir: &Path,
    conn: &Connection,
    output: Output,
) -> Result<()> {
    let Some(name) = sanitize_file_name(name) else {
        deny(&mut send, "文件名不合法".into()).await?;
        return Ok(());
    };
    fs::create_dir_all(dir).await?;
    let final_path = unique_path(dir, &name);
    let part_path = part_path(&final_path);
    write_msg(&mut send, &Response::Ok).await?;

    let start = Instant::now();
    let received = receive_to(&mut recv, &part_path, size).await;
    let verified = match received {
        Ok(verified) => verified,
        Err(err) => {
            let _ = fs::remove_file(&part_path).await;
            return Err(err);
        }
    };
    let elapsed = start.elapsed();
    if verified {
        fs::rename(&part_path, &final_path).await?;
    } else {
        fs::remove_file(&part_path).await?;
    }

    write_msg(&mut send, &Response::FileDone { verified }).await?;
    send.finish()?;
    output.emit(&Event::Transfer {
        what: "接收文件".into(),
        name: final_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned()),
        bytes: size,
        secs: elapsed.as_secs_f64(),
        mbit_per_s: mbit_per_s(size, elapsed),
        verified: Some(verified),
        path: current_path(conn).0,
    });
    Ok(())
}

/// 接收 `size` 字节写入文件，再读 32 字节 BLAKE3 校验值；返回校验是否通过。
async fn receive_to(recv: &mut RecvStream, path: &Path, size: u64) -> Result<bool> {
    let mut file = fs::File::create(path).await?;
    let mut hasher = blake3::Hasher::new();
    let mut remaining = size;
    while remaining > 0 {
        let want = usize::try_from(remaining).unwrap_or(usize::MAX);
        let Some(chunk) = recv.read_chunk(want).await? else {
            bail!("对方提前结束，还差 {remaining} 字节");
        };
        hasher.update(&chunk);
        file.write_all(&chunk).await?;
        remaining -= chunk.len() as u64;
    }
    let mut expected = [0u8; 32];
    recv.read_exact(&mut expected).await?;
    file.flush().await?;
    file.sync_all().await?;
    Ok(hasher.finalize().as_bytes() == &expected)
}

/// 只保留文件名本身，拒绝路径穿越和各平台不允许的字符。
pub fn sanitize_file_name(name: &str) -> Option<String> {
    const FORBIDDEN: &[char] = &['/', '\\', ':', '*', '?', '"', '<', '>', '|'];
    let name = name.trim();
    let bad = name.is_empty()
        || name.len() > 255
        || name == "."
        || name == ".."
        || name.contains(FORBIDDEN)
        || name.chars().any(char::is_control);
    (!bad).then(|| name.to_string())
}

/// 目标已存在时改名为 `名称 (1).扩展名`，避免覆盖。
fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() && !part_path(&candidate).exists() {
        return candidate;
    }
    let path = Path::new(name);
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy())
        .unwrap_or_default();
    let ext = path.extension().map(|e| e.to_string_lossy());
    for i in 1.. {
        let file = match &ext {
            Some(ext) => format!("{stem} ({i}).{ext}"),
            None => format!("{stem} ({i})"),
        };
        let candidate = dir.join(file);
        if !candidate.exists() && !part_path(&candidate).exists() {
            return candidate;
        }
    }
    unreachable!()
}

fn part_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".mkpart");
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_path_traversal() {
        assert_eq!(sanitize_file_name("报告.pdf").as_deref(), Some("报告.pdf"));
        assert_eq!(sanitize_file_name(".bashrc").as_deref(), Some(".bashrc"));
        for bad in ["", ".", "..", "../etc/passwd", "a/b", "a\\b", "c:x", "a\nb"] {
            assert!(sanitize_file_name(bad).is_none(), "应拒绝 {bad:?}");
        }
    }

    #[test]
    fn unique_path_does_not_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let first = unique_path(dir.path(), "a.txt");
        assert_eq!(first, dir.path().join("a.txt"));
        std::fs::write(&first, b"x").unwrap();
        assert_eq!(
            unique_path(dir.path(), "a.txt"),
            dir.path().join("a (1).txt")
        );
        std::fs::write(dir.path().join("b"), b"x").unwrap();
        assert_eq!(unique_path(dir.path(), "b"), dir.path().join("b (1)"));
    }
}
