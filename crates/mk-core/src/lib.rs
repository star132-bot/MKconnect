//! MKconnect 核心库。
//!
//! 与平台无关的部分都在这里：设备身份、连接票据、网络端点、应用协议、
//! 服务端与客户端逻辑，以及连接路径（直连或中继）的观测与上报。
//! 命令行、后台服务和将来的图形界面都只是这个库的外壳。

pub mod client;
pub mod identity;
pub mod net;
pub mod proto;
pub mod report;
pub mod server;
pub mod ticket;

pub use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl};
