//! 事件上报：把连接、路径变化和传输结果输出为中文文本或 JSON 行。
//!
//! JSON 输出是测试脚本统计直连比例和速度的依据，字段名保持稳定。

use std::{fmt, io::Write, time::Duration};

use iroh::{EndpointId, endpoint::Connection};
use n0_future::StreamExt;
use serde::Serialize;
use tokio::task::JoinHandle;

/// 当前数据走的路径。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathKind {
    Direct,
    Relay,
    None,
}

impl fmt::Display for PathKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PathKind::Direct => "直连",
            PathKind::Relay => "中继",
            PathKind::None => "无",
        })
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Bound {
        endpoint_id: String,
        ticket: String,
        direct_addrs: Vec<String>,
        relay_url: Option<String>,
    },
    Connected {
        remote: String,
        setup_ms: f64,
    },
    Accepted {
        remote: String,
    },
    Rejected {
        remote: String,
        reason: String,
    },
    Path {
        remote: String,
        kind: PathKind,
        addr: Option<String>,
        rtt_ms: Option<f64>,
    },
    Ping {
        seq: u64,
        rtt_ms: f64,
    },
    PingSummary {
        sent: u64,
        received: u64,
        min_ms: f64,
        avg_ms: f64,
        max_ms: f64,
        final_path: PathKind,
    },
    Transfer {
        what: String,
        name: Option<String>,
        bytes: u64,
        secs: f64,
        mbit_per_s: f64,
        verified: Option<bool>,
        path: PathKind,
    },
    Forwarding {
        listen: String,
        target: String,
    },
    Closed {
        remote: String,
        reason: Option<String>,
    },
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::Bound {
                endpoint_id,
                ticket,
                direct_addrs,
                relay_url,
            } => {
                writeln!(f, "设备 ID：{endpoint_id}")?;
                writeln!(f, "本机地址：{}", direct_addrs.join("  "))?;
                writeln!(f, "中继：{}", relay_url.as_deref().unwrap_or("未连接"))?;
                write!(f, "连接票据：\n{ticket}")
            }
            Event::Connected { remote, setup_ms } => {
                write!(f, "已连接 {}，建立耗时 {setup_ms:.0} ms", short(remote))
            }
            Event::Accepted { remote } => write!(f, "接受来自 {} 的连接", short(remote)),
            Event::Rejected { remote, reason } => {
                write!(f, "拒绝 {} 的连接：{reason}", short(remote))
            }
            Event::Path {
                remote,
                kind,
                addr,
                rtt_ms,
            } => {
                write!(f, "与 {} 的路径：{kind}", short(remote))?;
                if let Some(addr) = addr {
                    write!(f, "（{addr}）")?;
                }
                if let Some(rtt) = rtt_ms {
                    write!(f, "，延迟 {rtt:.1} ms")?;
                }
                Ok(())
            }
            Event::Ping { seq, rtt_ms } => write!(f, "第 {seq} 次：{rtt_ms:.1} ms"),
            Event::PingSummary {
                sent,
                received,
                min_ms,
                avg_ms,
                max_ms,
                final_path,
            } => write!(
                f,
                "发送 {sent} 次，收到 {received} 次；延迟 最小 {min_ms:.1} / 平均 {avg_ms:.1} / 最大 {max_ms:.1} ms；最终路径：{final_path}"
            ),
            Event::Transfer {
                what,
                name,
                bytes,
                secs,
                mbit_per_s,
                verified,
                path,
            } => {
                write!(f, "{what}")?;
                if let Some(name) = name {
                    write!(f, "「{name}」")?;
                }
                write!(
                    f,
                    "完成：{}，用时 {secs:.2} s，{mbit_per_s:.1} Mbit/s，路径：{path}",
                    human_bytes(*bytes)
                )?;
                match verified {
                    Some(true) => write!(f, "，校验通过"),
                    Some(false) => write!(f, "，校验失败"),
                    None => Ok(()),
                }
            }
            Event::Forwarding { listen, target } => {
                write!(f, "端口转发：本机 {listen} → 对方 {target}")
            }
            Event::Closed { remote, reason } => match reason {
                Some(reason) => write!(f, "与 {} 的连接断开：{reason}", short(remote)),
                None => write!(f, "与 {} 的连接已关闭", short(remote)),
            },
        }
    }
}

/// 输出方式：中文文本或 JSON 行；可选写到标准错误，把标准输出留给数据。
#[derive(Debug, Clone, Copy, Default)]
pub struct Output {
    pub json: bool,
    pub to_stderr: bool,
}

impl Output {
    pub fn emit(&self, event: &Event) {
        let line = if self.json {
            serde_json::to_string(event).expect("事件总能序列化")
        } else {
            event.to_string()
        };
        // 输出失败（例如管道已关闭）时忽略，不影响连接本身。
        if self.to_stderr {
            let _ = writeln!(std::io::stderr(), "{line}");
        } else {
            let _ = writeln!(std::io::stdout(), "{line}");
        }
    }
}

/// 读取连接当前选中的路径。
pub fn current_path(conn: &Connection) -> (PathKind, Option<String>, Option<Duration>) {
    let paths = conn.paths();
    match paths.iter().find(|p| p.is_selected()) {
        Some(p) => {
            let kind = if p.is_relay() {
                PathKind::Relay
            } else {
                PathKind::Direct
            };
            (kind, Some(format!("{:?}", p.remote_addr())), Some(p.rtt()))
        }
        None => (PathKind::None, None, None),
    }
}

pub fn path_event(conn: &Connection) -> Event {
    let (kind, addr, rtt) = current_path(conn);
    Event::Path {
        remote: conn.remote_id().to_string(),
        kind,
        addr,
        rtt_ms: rtt.map(ms),
    }
}

/// 在后台监听路径变化（例如从中继升级为直连），每次变化输出一条事件。
pub fn spawn_path_watcher(conn: Connection, output: Output) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut events = conn.path_events();
        output.emit(&path_event(&conn));
        while let Some(event) = events.next().await {
            if matches!(event, iroh::endpoint::PathEvent::Selected { .. }) {
                output.emit(&path_event(&conn));
            }
        }
    })
}

pub fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

pub fn mbit_per_s(bytes: u64, d: Duration) -> f64 {
    let secs = d.as_secs_f64().max(1e-9);
    bytes as f64 * 8.0 / secs / 1_000_000.0
}

pub fn short(id: &str) -> &str {
    id.get(..10).unwrap_or(id)
}

pub fn short_id(id: &EndpointId) -> String {
    short(&id.to_string()).to_string()
}

pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_field_names_are_stable() {
        let event = Event::PingSummary {
            sent: 3,
            received: 3,
            min_ms: 1.0,
            avg_ms: 2.0,
            max_ms: 3.0,
            final_path: PathKind::Direct,
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["event"], "ping_summary");
        assert_eq!(json["final_path"], "direct");
    }

    #[test]
    fn units() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1536), "1.50 KiB");
        assert!((mbit_per_s(1_000_000, Duration::from_secs(1)) - 8.0).abs() < 1e-9);
    }
}
