#[cfg(all(target_os = "linux", target_env = "gnu"))]
use mimalloc::MiMalloc;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::task::Poll;
use std::{sync::Arc, time::Duration};

use anyhow::{Context, anyhow};
use bytes::{Buf, Bytes};
use futures_util::StreamExt;
use futures_util::future::poll_fn;
use h3::ConnectionState;
use h3::ext::Protocol;
use h3_quinn::BidiStream;
use h3_webtransport::server::{AcceptedBi, WebTransportSession};
use http::Method;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use hyper_util::client::legacy::Client;
use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioExecutor};
use quinn::VarInt;
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tracing::level_filters::LevelFilter;
use tracing::{error, info};

mod config;
mod socks5;

// 共享给所有反代请求复用的 hyper 客户端类型，避免每次请求重建连接池。
type ReqBody =
    StreamBody<futures_util::stream::BoxStream<'static, Result<Frame<Bytes>, std::io::Error>>>;
type UpstreamClient = Client<HttpConnector, ReqBody>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let config = Arc::new(config::load_config("config.toml").await?);
    // 全程序共享一个 hyper 连接池，复用 keep-alive 连接，避免每请求重建 TCP/TLS。
    let upstream_client: UpstreamClient =
        Client::builder(TokioExecutor::new()).build(HttpConnector::new());
    let mut tls_config = load_tls_config(&config)?;
    let tcp_tls_config = tls_config.clone();
    let config_clone = config.clone();
    tokio::spawn(async move {
        if let Err(e) = handle_tcp_ssl(config_clone, tcp_tls_config).await {
            error!("Failed to handle SSL connections: {e:?}");
        }
    });
    tls_config.max_early_data_size = u32::MAX;
    let alpn: Vec<Vec<u8>> = vec![
        b"h3".to_vec(),
        b"h3-32".to_vec(),
        b"h3-31".to_vec(),
        b"h3-30".to_vec(),
        b"h3-29".to_vec(),
    ];
    tls_config.alpn_protocols = alpn;
    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls_config)?));
    server_config.transport = Arc::new(build_transport_config(config.cwnd));
    let endpoint = quinn::Endpoint::server(server_config, config.listen.parse()?)?;
    info!("listening on {}", config.listen);
    // 跟踪所有已 spawn 的 QUIC 连接任务,以便在收到 Ctrl-C 时优雅等待它们结束
    let mut conns: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            new_conn = endpoint.accept() => match new_conn {
                Some(new_conn) => {
                    let config = config.clone();
                    let upstream_client = upstream_client.clone();
                    info!(remote = %new_conn.remote_address(), "new QUIC connection");
                    conns.spawn(async move {
                        match new_conn.await {
                            Ok(conn) => {
                                tracing::debug!("HTTP/3 connection established");
                                let h3_conn = match h3::server::builder()
                                    .enable_webtransport(true)
                                    .enable_extended_connect(true)
                                    .enable_datagram(true)
                                    // 目前每条连接只服务一个 WebTransport 会话(首个会话 accept
                                    // 后会接管整条连接),多广告没有意义,固定为 1。
                                    .max_webtransport_sessions(1)
                                    .send_grease(true)
                                    .build(h3_quinn::Connection::new(conn))
                                    .await
                                {
                                    Ok(conn) => conn,
                                    Err(err) => {
                                        error!("handshaking failed: {:?}", err);
                                        return;
                                    }
                                };

                                if let Err(err) =
                                    handle_connection(h3_conn, config, upstream_client).await
                                {
                                    tracing::error!("Failed to handle connection: {err:?}");
                                }
                            }
                            Err(err) => {
                                error!("accepting connection failed: {:?}", err);
                            }
                        }
                    });
                    // 顺手回收已结束的连接任务:JoinSet 会把完成的任务一直留在集合里,
                    // 只在 shutdown 排空,长时间运行会随累计连接数无界增长。
                    while let Some(res) = conns.try_join_next() {
                        if let Err(err) = res {
                            error!("connection task panicked: {err}");
                        }
                    }
                }
                None => break, // endpoint 关闭,不再接受新连接
            },
            _ = tokio::signal::ctrl_c() => {
                info!("received Ctrl-C, initiating graceful shutdown");
                // 关闭监听 socket;已建立的连接不会立刻被切断,
                // 它们会因为 endpoint 被关闭而通过 quinn 收到错误并自然退出。
                endpoint.close(VarInt::from_u32(0), b"shutting down");
                break;
            }
        }
    }
    // 给在飞连接一段上限时间优雅结束,超时后强制 abort。
    info!(
        "waiting for {} in-flight connection task(s) to finish (max 30s)",
        conns.len()
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        match tokio::time::timeout_at(deadline, conns.join_next()).await {
            Ok(Some(_)) => {}
            Ok(None) => break, // 所有连接任务都已结束
            Err(_elapsed) => {
                let remaining = conns.len();
                conns.abort_all();
                info!("graceful shutdown timed out, aborted {remaining} task(s)");
                break;
            }
        }
    }
    Ok(())
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();
}

/// 加载证书链与私钥,构建基础 TLS 配置。ALPN 与 early data 由调用方按需追加。
fn load_tls_config(config: &config::Config) -> anyhow::Result<rustls::ServerConfig> {
    let cert_file = File::open(&config.cert).context("Failed to open cert file")?;
    let mut cert_reader = BufReader::new(cert_file);
    let cert_chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificates")?;
    let key = PrivateKeyDer::from_pem_file(&config.key)?;
    Ok(rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?)
}

fn build_transport_config(cwnd: Option<u64>) -> quinn::TransportConfig {
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.keep_alive_interval(Some(Duration::from_secs(60)));
    // 单条流的接收窗口 8 MiB;按 RTT*带宽(BDP)估算,假设 100ms RTT、~640Mbps
    // 链路 ≈ 8 MiB,够覆盖一条 WT 流满速时不被流控卡住。
    transport_config.stream_receive_window(VarInt::from_u32(8 * 1024 * 1024));
    // 整条 QUIC 连接的总接收窗口 16 MiB,约为单流窗口的 2 倍,允许同一连接
    // 上的多条 WT 流并行传输时不互相挤占。
    transport_config.receive_window(VarInt::from_u32(16 * 1024 * 1024));
    transport_config.enable_segmentation_offload(true);
    // 与客户端 MaxIdleTimeout(5min)对齐:双方都 60s keepalive、5min idle,
    // keepalive 失败时两端判定连接死亡的时机一致,避免一端先判死后另一端
    // 还在使用导致"莫名端掉"的体验。
    transport_config.max_idle_timeout(Some(VarInt::from_u32(300_000).into()));

    transport_config.congestion_controller_factory(Arc::new(cwnd.map_or_else(
        quinn::congestion::BbrConfig::default,
        |cwnd| {
            let mut config = quinn::congestion::BbrConfig::default();
            config.initial_window(cwnd);
            config
        },
    )));
    transport_config
}

/// 去掉 IPv6 字面量的方括号。`http::Uri::host()` 对 `http://[::1]:8080`
/// 返回带方括号的 `[::1]`,直接交给 `TcpStream::connect` 会被当成域名去
/// 解析而失败;去掉后 `("::1", port)` 会被按 IP 字面量处理。
fn unbracket(host: &str) -> &str {
    host.trim_start_matches('[').trim_end_matches(']')
}

async fn handle_tcp_ssl(
    config: Arc<config::Config>,
    tls_config: rustls::ServerConfig,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(&config.listen).await?;
    let acceptor = Arc::new(tokio_rustls::TlsAcceptor::from(Arc::new(tls_config)));
    let uri = config.upstream.parse::<http::Uri>()?;
    let host = unbracket(uri.host().context("Upstream URI must have a host")?);
    let port = uri.port_u16().unwrap_or(80);
    loop {
        let (stream, addr) = listener.accept().await?;
        tracing::debug!(remote = %addr, "new TCP connection");

        let acceptor = acceptor.clone();
        let host = host.to_owned();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(mut stream) => {
                    tracing::debug!("TLS connection established");
                    let mut target_stream = match tokio::net::TcpStream::connect((host, port)).await
                    {
                        Ok(s) => s,
                        Err(err) => {
                            error!("Failed to connect to upstream: {:?}", err);
                            return;
                        }
                    };
                    if let Err(err) =
                        tokio::io::copy_bidirectional(&mut stream, &mut target_stream).await
                    {
                        tracing::error!("Failed to handle connection: {err:?}");
                    }
                }
                Err(err) => {
                    error!("handshaking failed: {:?}", err);
                }
            }
        });
    }
}

async fn handle_connection(
    mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes>,
    config: Arc<config::Config>,
    upstream_client: UpstreamClient,
) -> anyhow::Result<()> {
    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let config = config.clone();
                let upstream_client = upstream_client.clone();
                let (req, stream) = resolver.resolve_request().await?;
                let ext = req.extensions();
                let path = req.uri().path();
                match req.method() {
                    &Method::CONNECT
                        if ext.get::<Protocol>() == Some(&Protocol::WEB_TRANSPORT)
                            && config.path.eq(path) =>
                    {
                        // 只提取我们关心的两个 header,避免克隆整张 HeaderMap
                        let headers = req.headers();
                        let protocol = headers
                            .get("proxy-protocol")
                            .context("missing proxy-protocol header")?
                            .to_str()?
                            .to_owned();
                        let endpoint = headers
                            .get("proxy-endpoint")
                            .context("missing proxy-endpoint header")?
                            .to_str()?
                            .to_owned();

                        if tokio::time::timeout(
                            Duration::from_secs(5),
                            poll_fn(|cx| {
                                loop {
                                    if h3_conn.settings().enable_webtransport() {
                                        return Poll::Ready(());
                                    }
                                    match h3_conn.inner.poll_control(cx) {
                                        // 刚消费了一帧(很可能就是 SETTINGS),设置已更新,
                                        // 立刻复查,而不是丢掉就绪信号干等到超时。
                                        Poll::Ready(Ok(_)) => {}
                                        // 控制流已出错,交给后面的 accept 去报错,不再空等。
                                        Poll::Ready(Err(_)) => return Poll::Ready(()),
                                        Poll::Pending => return Poll::Pending,
                                    }
                                }
                            }),
                        )
                        .await
                        .is_err()
                        {
                            error!("Client did not send settings frame within 5 seconds");
                            return Ok(());
                        }
                        let session = WebTransportSession::accept(req, stream, h3_conn).await?;
                        tracing::info!("Established webtransport session");
                        handle_webtransport_session(config, protocol, endpoint, session).await?;
                        return Ok(());
                    }
                    _ => {
                        tokio::spawn(async move {
                            if let Err(err) =
                                redirect_upstream(req, stream, config, upstream_client).await
                            {
                                error!("Failed to redirect upstream: {err:?}");
                            }
                        });
                    }
                }
            }
            Ok(None) => {
                info!("connection closed");
                break;
            }
            Err(err) => {
                error!("accepting request failed: {:?}", err);
                break;
            }
        }
    }
    Ok(())
}

/// 剥离不能出现在 HTTP/3 响应里的连接相关字段(RFC 9114 §4.2)。
/// 上游是 HTTP/1.1,hyper 会保留 `Transfer-Encoding`、`Connection` 等字段,
/// 原样转发会让 HTTP/3 客户端判定协议错误。除了固定集合,还要移除
/// `Connection` 字段点名的那些 header。
fn sanitize_response_headers(headers: &mut http::HeaderMap) {
    // http crate 没有 KEEP_ALIVE / PROXY_CONNECTION 常量,按字面量移除。
    const CONNECTION_SPECIFIC: [&str; 5] = [
        "connection",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "upgrade",
    ];
    let named: Vec<http::HeaderName> = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| http::HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in CONNECTION_SPECIFIC {
        headers.remove(name);
    }
    // TE 在 HTTP/3 中只允许取值为 "trailers",这里不做转换,直接剥离。
    headers.remove(http::header::TE);
}

async fn redirect_upstream(
    req: http::Request<()>,
    stream: h3::server::RequestStream<BidiStream<Bytes>, Bytes>,
    config: Arc<config::Config>, // 假设 config 封装在 Arc 中以便跨 task
    client: UpstreamClient,
) -> anyhow::Result<()> {
    let (mut tx, rx) = stream.split();
    // 1. 构造明文 Upstream URL (http://...)
    let path_and_query = req
        .uri()
        .path_and_query()
        .map_or("", http::uri::PathAndQuery::as_str);
    // 确保 config.upstream 是以 http:// 开头的明文地址
    let upstream_uri = format!(
        "{}{}",
        config.upstream.trim_end_matches('/'),
        path_and_query
    );

    let (mut req_parts, ()) = req.into_parts();
    req_parts.uri = upstream_uri.parse()?;
    req_parts.version = http::Version::HTTP_11; // 强制使用 HTTP/1.1 或 HTTP/2，取决于 Client 的能力

    // 构造一个异步流来拉取 H3 数据
    let request_body_stream = futures_util::stream::unfold(rx, |mut s| async move {
        match s.recv_data().await {
            Ok(Some(mut data)) => {
                // 把 h3 返回的 impl Buf 转成 Bytes,使 body 类型固定为 Frame<Bytes>,
                // 这样才能复用全程序共享的 UpstreamClient。
                let len = data.remaining();
                let bytes = data.copy_to_bytes(len);
                Some((Ok::<_, std::io::Error>(Frame::data(bytes)), s))
            }
            Ok(None) => None, // 数据传输完毕
            Err(e) => Some((Err(std::io::Error::other(format!("H3 recv error: {e}"))), s)),
        }
    });

    // 包装成 hyper 的 Body
    let hyper_req_body = StreamBody::new(request_body_stream.boxed());
    let hyper_req = http::Request::from_parts(req_parts, hyper_req_body);

    // 3. 发送请求到 Upstream (HTTP/1.1 或 HTTP/2)，复用共享 client 的连接池
    let upstream_res = client.request(hyper_req).await?;

    let (mut upstream_parts, res_body) = upstream_res.into_parts();
    sanitize_response_headers(&mut upstream_parts.headers);
    let response_headers = http::Response::from_parts(upstream_parts, ());

    tx.send_response(response_headers).await?;

    // 5. 转发响应体数据流
    let mut body = res_body;
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if let Some(data) = frame.data_ref() {
            tx.send_data(data.clone()).await?;
        }
    }

    // 显式结束流
    tx.finish().await?;

    Ok(())
}

async fn handle_webtransport_session(
    config: Arc<config::Config>,
    protocol: String,
    endpoint: String,
    session: WebTransportSession<h3_quinn::Connection, Bytes>,
) -> anyhow::Result<()> {
    match protocol.as_str() {
        "tcp" => {
            loop {
                match session.accept_bi().await {
                    Ok(Some(AcceptedBi::BidiStream(_, stream))) => {
                        let config = config.clone();
                        let endpoint = endpoint.clone();
                        tokio::spawn(async move {
                            if let Err(err) = handle_tcp(config, &endpoint, stream).await {
                                error!("Failed to handle TCP stream: {err:?}");
                            }
                        });
                    }
                    Ok(None) => break, // Session 关闭
                    Err(e) => {
                        tracing::error!("Failed to accept bidi stream: {:?}", e);
                        break;
                    }
                    _ => {} // 处理其他类型的流或忽略
                }
            }
        }
        "udp" => {
            if let Err(err) = handle_udp(session, config, &endpoint).await {
                error!("Failed to handle UDP session: {err:?}");
            }
        }
        other => anyhow::bail!("unknown proxy-protocol: {other}"),
    }
    Ok(())
}

/// 把 `host:port` 形式的 endpoint 拆成 `(host, port)`。
/// host 可以是域名或 IP 字面量;IPv6 字面量需带方括号(如 `[::1]:443`)。
/// 用于需要把域名原样传递(如 socks5 上游)而不在本端预解析的场景。
/// 纯 `IP:port` 先走 `SocketAddr::parse` 以正确处理 IPv6 方括号语法,
/// 失败再按最后一个 `:` 拆分,兼容 `domain:port` 这类 `SocketAddr` 无法
/// 直接 parse 的形式。
fn endpoint_host_port(endpoint: &str) -> anyhow::Result<(String, u16)> {
    if let Ok(addr) = endpoint.parse::<SocketAddr>() {
        return Ok((addr.ip().to_string(), addr.port()));
    }
    let (host, port) = endpoint
        .rsplit_once(':')
        .with_context(|| format!("Invalid endpoint format: {endpoint}"))?;
    let port: u16 = port
        .parse()
        .with_context(|| format!("Invalid port in endpoint: {endpoint}"))?;
    // 去掉 IPv6 字面量的方括号以便 SOCKS5 地址编码。
    let host = host.trim_start_matches('[').trim_end_matches(']');
    Ok((host.to_owned(), port))
}

async fn handle_tcp(
    config: Arc<config::Config>,
    endpoint: &str,
    mut stream: h3_webtransport::stream::BidiStream<BidiStream<Bytes>, Bytes>,
) -> anyhow::Result<()> {
    if let Some(proxy_addr) = config.socks_proxy.as_ref() {
        // 走 socks5 时把 host 原样传给上游 socks5,由其负责 DNS 解析,
        // 避免本端把域名预先解析成 IP 后丢失域名信息(也省一次本地解析)。
        // 内建 SOCKS5 客户端保留域名，让代理服务端负责 DNS 解析。
        let (host, port) = endpoint_host_port(endpoint)?;
        let mut target_stream = socks5::connect(proxy_addr, &host, port).await?;
        tracing::debug!(target = endpoint, "outgoing TCP connection established");
        tokio::io::copy_bidirectional(&mut stream, &mut target_stream).await
    } else {
        // 直连用 tokio 的 lookup_host:既支持 IP 字面量也支持域名 DNS 解析。
        // 收集全部解析结果交给 tokio 依次尝试(首个成功即返回),避免首选地址
        // (例如 IPv4-only 网络上的 IPv6)不可达时就放弃。
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(endpoint)
            .await
            .with_context(|| format!("Failed to resolve endpoint: {endpoint}"))?
            .collect();
        if addrs.is_empty() {
            anyhow::bail!("No address resolved for endpoint: {endpoint}");
        }
        let mut target_stream = TcpStream::connect(addrs.as_slice())
            .await
            .with_context(|| format!("Failed to connect to upstream addr: {endpoint}"))?;
        tracing::debug!(target = endpoint, "outgoing TCP connection established");
        tokio::io::copy_bidirectional(&mut stream, &mut target_stream).await
    }
    .map_err(|e| anyhow!("TCP proxy stream error: {e:?}"))
    .map(|_| ())
}

async fn handle_udp(
    session: WebTransportSession<h3_quinn::Connection, Bytes>,
    config: Arc<config::Config>,
    endpoint: &str,
) -> anyhow::Result<()> {
    let mut tx = session.datagram_sender();
    let mut rx = session.datagram_reader();
    if let Some(proxy_addr) = config.socks_proxy.as_ref() {
        let (mut control, relay_addr) = socks5::udp_associate(proxy_addr).await?;
        // relay 可能是 IPv6,本地 socket 必须绑定同族地址才能 send_to。
        let bind = if relay_addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = tokio::net::UdpSocket::bind(bind).await?;
        let (host, port) = endpoint_host_port(endpoint)?;
        let mut outbound = Vec::with_capacity(65_536);
        let mut inbound = vec![0u8; 65_536];
        loop {
            tokio::select! {
                result = control.read_u8() => {
                    match result {
                        Ok(_) => anyhow::bail!("unexpected data on SOCKS5 UDP control connection"),
                        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                            anyhow::bail!("SOCKS5 UDP control connection closed")
                        }
                        Err(err) => return Err(err.into()),
                    }
                }
                datagram = rx.read_datagram() => {
                    let datagram = datagram?;
                    socks5::encode_udp_packet(&mut outbound, &host, port, datagram.payload())?;
                    socket.send_to(&outbound, relay_addr).await?;
                }
                result = socket.recv_from(&mut inbound) => {
                    let (n, _) = result?;
                    let packet = socks5::decode_udp_packet(&inbound[..n])?;
                    tx.send_datagram(Bytes::copy_from_slice(&inbound[packet.payload_start..n]))?;
                }
            }
        }
    }
    // 固定绑 0.0.0.0 会让 IPv6 目标在 connect 时因地址族不匹配而失败,
    // 因此先解析目标,再按族绑定,并逐个候选地址尝试(兼顾跨地址回退)。
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(endpoint)
        .await
        .with_context(|| format!("Failed to resolve endpoint: {endpoint}"))?
        .collect();
    if addrs.is_empty() {
        anyhow::bail!("No address resolved for endpoint: {endpoint}");
    }
    let mut connected = None;
    let mut last_err = None;
    for addr in &addrs {
        let bind = if addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        match tokio::net::UdpSocket::bind(bind).await {
            Ok(socket) => match socket.connect(*addr).await {
                Ok(()) => {
                    connected = Some(socket);
                    break;
                }
                Err(err) => last_err = Some(err),
            },
            Err(err) => last_err = Some(err),
        }
    }
    let socket = connected.ok_or_else(|| {
        anyhow!(
            "Failed to connect UDP to endpoint {endpoint}: {}",
            last_err.map_or_else(|| "no candidate address".to_owned(), |err| err.to_string())
        )
    })?;
    let send_task = async {
        loop {
            let datagram = rx.read_datagram().await?;
            socket.send(datagram.payload()).await?;
        }
    };
    let recv_task = async {
        let mut buf = vec![0u8; 65_536];
        loop {
            let n = socket.recv(&mut buf).await?;
            let payload = Bytes::copy_from_slice(&buf[..n]);
            tx.send_datagram(payload)?;
        }
    };

    tokio::select! {
        res = send_task => res,
        res = recv_task => res,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_value(value: &str) -> http::HeaderValue {
        http::HeaderValue::from_bytes(value.as_bytes()).unwrap()
    }

    #[test]
    fn strips_connection_specific_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::TRANSFER_ENCODING, header_value("chunked"));
        headers.insert(
            http::header::CONNECTION,
            header_value("keep-alive, x-custom"),
        );
        headers.insert("x-custom", header_value("1"));
        headers.insert("keep-alive", header_value("timeout=5"));
        headers.insert(
            http::header::CONTENT_TYPE,
            header_value("text/plain; charset=utf-8"),
        );

        sanitize_response_headers(&mut headers);

        assert!(headers.get(http::header::TRANSFER_ENCODING).is_none());
        assert!(headers.get(http::header::CONNECTION).is_none());
        assert!(headers.get("x-custom").is_none());
        assert!(headers.get("keep-alive").is_none());
        assert_eq!(
            headers.get(http::header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
    }

    #[test]
    fn keeps_normal_response_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, header_value("12"));
        headers.insert(http::header::CONTENT_TYPE, header_value("application/json"));

        sanitize_response_headers(&mut headers);

        assert_eq!(headers.len(), 2);
    }

    #[test]
    fn unbrackets_ipv6_literals() {
        assert_eq!(unbracket("[::1]"), "::1");
        assert_eq!(unbracket("[2001:db8::1]"), "2001:db8::1");
        assert_eq!(unbracket("example.com"), "example.com");
        assert_eq!(unbracket("127.0.0.1"), "127.0.0.1");
    }
}
