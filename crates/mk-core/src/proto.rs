//! 应用协议。
//!
//! 每个请求占用一条 QUIC 双向流：先发一条请求消息，对方回一条响应消息，
//! 之后按请求类型传输数据。消息格式为 4 字节大端长度加 JSON 正文。

use anyhow::{Context, Result, bail};
use iroh::endpoint::VarInt;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 协议标识，版本变化时递增。
pub const ALPN: &[u8] = b"mkconnect/0";

/// 单条消息的最大长度。
const MAX_MESSAGE_LEN: usize = 64 * 1024;

/// 正常关闭连接。
pub const CLOSE_OK: VarInt = VarInt::from_u32(0);
/// 对方不在信任列表中。
pub const CLOSE_UNTRUSTED: VarInt = VarInt::from_u32(403);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// 回显收到的字节，用于测量往返延迟。
    Ping,
    /// 发送一个文件，数据之后附 32 字节 BLAKE3 校验值。
    File { name: String, size: u64 },
    /// 测速：对方接收并丢弃数据，完成后回报收到的字节数。
    Bench,
    /// 把这条流转发到对方能访问的 TCP 地址，例如 127.0.0.1:22。
    Forward { target: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Ok,
    Denied { reason: String },
    FileDone { verified: bool },
    BenchDone { bytes: u64 },
}

pub async fn write_msg<W, T>(writer: &mut W, msg: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = serde_json::to_vec(msg)?;
    if body.len() > MAX_MESSAGE_LEN {
        bail!("消息过长：{} 字节", body.len());
    }
    writer.write_u32(body.len() as u32).await?;
    writer.write_all(&body).await?;
    Ok(())
}

pub async fn read_msg<R, T>(reader: &mut R) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let len = reader.read_u32().await.context("读取消息长度失败")? as usize;
    if len > MAX_MESSAGE_LEN {
        bail!("消息过长：{len} 字节");
    }
    let mut body = vec![0; len];
    reader
        .read_exact(&mut body)
        .await
        .context("读取消息正文失败")?;
    serde_json::from_slice(&body).context("消息格式错误")
}

/// 读取对方响应，`Denied` 转为错误。
pub async fn expect_ok<R: AsyncRead + Unpin>(reader: &mut R) -> Result<()> {
    match read_msg(reader).await? {
        Response::Ok => Ok(()),
        Response::Denied { reason } => bail!("对方拒绝：{reason}"),
        other => bail!("意外的响应：{other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn message_roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let req = Request::File {
            name: "报告.pdf".into(),
            size: 42,
        };
        write_msg(&mut a, &req).await.unwrap();
        let got: Request = read_msg(&mut b).await.unwrap();
        assert_eq!(got, req);
    }

    #[tokio::test]
    async fn oversized_message_is_rejected() {
        let (mut a, mut b) = tokio::io::duplex(16);
        a.write_u32(u32::MAX).await.unwrap();
        assert!(read_msg::<_, Request>(&mut b).await.is_err());
    }
}
