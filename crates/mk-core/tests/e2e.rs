//! 端到端测试：同一台机器上起两个端点，不用中继，经 127.0.0.1 直连。

use std::{collections::HashSet, net::SocketAddr, time::Duration};

use iroh::{Endpoint, EndpointAddr, SecretKey, TransportAddr};
use mk_core::{
    client,
    net::{self, NetOptions, RelayChoice},
    proto::{Request, expect_ok, write_msg},
    report::{Output, PathKind},
    server::{self, ServeOptions, Trust},
};

const QUIET: Output = Output {
    json: true,
    to_stderr: true,
};

fn direct_only() -> NetOptions {
    NetOptions {
        relay: RelayChoice::Disabled,
        ..Default::default()
    }
}

struct Pair {
    client: Endpoint,
    server_addr: EndpointAddr,
    recv_dir: tempfile::TempDir,
}

/// 启动服务端；`trust_client` 为假时服务端不信任客户端。
async fn start_pair(trust_client: bool, forward_allow: Vec<String>) -> Pair {
    let client_key = SecretKey::generate();
    let client_id = client_key.public();
    let server = net::bind(SecretKey::generate(), &direct_only())
        .await
        .unwrap();
    let client = net::bind(client_key, &direct_only()).await.unwrap();

    let port = server
        .addr()
        .ip_addrs()
        .next()
        .expect("服务端应有本地地址")
        .port();
    let loopback: SocketAddr = ([127, 0, 0, 1], port).into();
    let server_addr = EndpointAddr::from_parts(server.id(), [TransportAddr::Ip(loopback)]);

    let trusted = if trust_client {
        HashSet::from([client_id])
    } else {
        HashSet::new()
    };
    let recv_dir = tempfile::tempdir().unwrap();
    let opts = ServeOptions {
        trust: Trust::Only(trusted),
        recv_dir: recv_dir.path().to_path_buf(),
        forward_allow,
    };
    tokio::spawn(server::serve(server, opts, QUIET));

    Pair {
        client,
        server_addr,
        recv_dir,
    }
}

#[tokio::test]
async fn ping_send_and_bench_over_direct_path() {
    let pair = start_pair(true, vec![]).await;
    let conn = client::connect(&pair.client, pair.server_addr.clone(), QUIET)
        .await
        .unwrap();

    let path = client::ping(&conn, 3, Duration::from_millis(10), QUIET)
        .await
        .unwrap();
    assert_eq!(path, PathKind::Direct);

    let src_dir = tempfile::tempdir().unwrap();
    let src = src_dir.path().join("数据.bin");
    let content: Vec<u8> = (0..3_000_000u32).map(|i| (i * 7 % 251) as u8).collect();
    std::fs::write(&src, &content).unwrap();
    client::send_file(&conn, &src, QUIET).await.unwrap();
    let received = std::fs::read(pair.recv_dir.path().join("数据.bin")).unwrap();
    assert_eq!(received, content);

    // 同名文件再发一次，不能覆盖已有文件。
    client::send_file(&conn, &src, QUIET).await.unwrap();
    assert!(pair.recv_dir.path().join("数据 (1).bin").exists());

    client::bench(&conn, 8 * 1024 * 1024, QUIET).await.unwrap();
}

#[tokio::test]
async fn untrusted_client_is_rejected() {
    let pair = start_pair(false, vec![]).await;
    let conn = client::connect(&pair.client, pair.server_addr.clone(), QUIET)
        .await
        .unwrap();
    let result = client::ping(&conn, 1, Duration::from_millis(10), QUIET).await;
    assert!(result.is_err());
    assert!(client::rejected_as_untrusted(&conn));
}

#[tokio::test]
async fn forward_only_reaches_allowed_targets() {
    // 一个回显 TCP 服务，模拟服务器上的 SSH。
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = echo.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = tcp.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });

    let pair = start_pair(true, vec![echo_addr.clone()]).await;
    let conn = client::connect(&pair.client, pair.server_addr.clone(), QUIET)
        .await
        .unwrap();

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    write_msg(&mut send, &Request::Forward { target: echo_addr })
        .await
        .unwrap();
    expect_ok(&mut recv).await.unwrap();
    send.write_all(b"ssh-hello").await.unwrap();
    let mut buf = [0u8; 9];
    recv.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ssh-hello");

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    write_msg(
        &mut send,
        &Request::Forward {
            target: "127.0.0.1:22".into(),
        },
    )
    .await
    .unwrap();
    let denied = expect_ok(&mut recv).await.unwrap_err();
    assert!(denied.to_string().contains("未允许"), "{denied}");
}
