use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::{sync::Arc, time::Duration};

use anyhow::{Context, anyhow};
use bytes::Bytes;
use fast_socks5::client::{Socks5Datagram, Socks5Stream};
use futures_util::StreamExt;
use h3::ConnectionState;
use h3::ext::Protocol;
use h3_quinn::BidiStream;
use h3_webtransport::server::{AcceptedBi, WebTransportSession};
use http::{HeaderMap, Method};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use hyper_util::client::legacy::Client;
use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioExecutor};
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpStream;
use tracing::level_filters::LevelFilter;
use tracing::{debug, error, info};

mod config;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();
    let config = Arc::new(config::load_config("config.toml").await?);
    let cert_file = File::open(&config.cert).context("Failed to open cert file")?;
    let mut cert_reader = BufReader::new(cert_file);
    let cert_chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificates")?;

    let key = PrivateKeyDer::from_pem_file(&config.key)?;
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;
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
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.keep_alive_interval(Some(Duration::from_secs(60)));
    transport_config.datagram_receive_buffer_size(Some(65536));
    transport_config.datagram_send_buffer_size(65536);
    server_config.transport = Arc::new(transport_config);
    let endpoint = quinn::Endpoint::server(server_config, config.listen.parse()?)?;
    info!("listening on {}", config.listen);
    while let Some(new_conn) = endpoint.accept().await {
        let config = config.clone();
        info!("new connection: {:?}", new_conn.remote_address());
        tokio::spawn(async move {
            match new_conn.await {
                Ok(conn) => {
                    info!("new http3 established");
                    let h3_conn = match h3::server::builder()
                        .enable_webtransport(true)
                        .enable_extended_connect(true)
                        .enable_datagram(true)
                        .max_webtransport_sessions((1_u64 << 62) - 1)
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

                    // tracing::info!("Establishing WebTransport session");
                    // // 3. TODO: Conditionally, if the client indicated that this is a webtransport session, we should accept it here, else use regular h3.
                    // // if this is a webtransport session, then h3 needs to stop handing the datagrams, bidirectional streams, and unidirectional streams and give them
                    // // to the webtransport session.

                    if let Err(err) = handle_connection(h3_conn, config).await {
                        tracing::error!("Failed to handle connection: {err:?}");
                    }
                }
                Err(err) => {
                    error!("accepting connection failed: {:?}", err);
                }
            }
        });
    }
    Ok(())
}

pub async fn handle_tcp_ssl(
    config: Arc<config::Config>,
    tls_config: rustls::ServerConfig,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(&config.listen).await?;
    let acceptor = Arc::new(tokio_rustls::TlsAcceptor::from(Arc::new(tls_config)));
    let uri = config.upstream.parse::<http::Uri>()?;
    let host = uri.host().context("Upstream URI must have a host")?;
    let port = uri.port_u16().unwrap_or(80);
    loop {
        let (stream, addr) = listener.accept().await?;
        info!("new connection: {:?}", addr);
        let acceptor = acceptor.clone();
        let host = host.to_owned();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(mut stream) => {
                    info!("new ssl established");
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

pub async fn handle_connection(
    mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes>,
    config: Arc<config::Config>,
) -> anyhow::Result<()> {
    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let config = config.clone();
                let (req, stream) = resolver.resolve_request().await?;
                let ext = req.extensions();
                let path = req.uri().path();
                match req.method() {
                    &Method::CONNECT
                        if ext.get::<Protocol>() == Some(&Protocol::WEB_TRANSPORT)
                            && config.path.eq(path) =>
                    {
                        let headers = req.headers().to_owned();
                        debug!("Connection settings: {:?}", h3_conn.settings());
                        let session = WebTransportSession::accept(req, stream, h3_conn).await?;
                        tracing::info!("Established webtransport session");
                        handle_webtransport_session(config, headers, session).await?;
                        return Ok(());
                    }
                    _ => {
                        tokio::spawn(async move {
                            if let Err(err) = redirect_upstream(req, stream, config).await {
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

pub async fn redirect_upstream(
    req: http::Request<()>,
    stream: h3::server::RequestStream<BidiStream<Bytes>, Bytes>,
    config: Arc<config::Config>, // 假设 config 封装在 Arc 中以便跨 task
) -> anyhow::Result<()> {
    let (mut tx, rx) = stream.split();
    // 1. 构造明文 Upstream URL (http://...)
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("");
    // 确保 config.upstream 是以 http:// 开头的明文地址
    let upstream_uri = format!(
        "{}{}",
        config.upstream.trim_end_matches('/'),
        path_and_query
    );

    let (mut req_parts, _) = req.into_parts();
    req_parts.uri = upstream_uri.parse()?;
    req_parts.version = http::Version::HTTP_11; // 强制使用 HTTP/1.1 或 HTTP/2，取决于 Client 的能力

    // 构造一个异步流来拉取 H3 数据
    let request_body_stream = futures_util::stream::unfold(rx, |mut s| async move {
        match s.recv_data().await {
            Ok(Some(data)) => Some((Ok::<_, anyhow::Error>(Frame::data(data)), s)),
            Ok(None) => None, // 数据传输完毕
            Err(e) => Some((Err(anyhow::anyhow!("H3 recv error: {}", e)), s)),
        }
    });

    // 包装成 hyper 的 Body
    let hyper_req_body = StreamBody::new(request_body_stream.boxed());
    let hyper_req = http::Request::from_parts(req_parts, hyper_req_body);

    // 3. 发送请求到 Upstream (HTTP/1.1 或 HTTP/2)
    let client = Client::builder(TokioExecutor::new()).build(HttpConnector::new());
    let upstream_res = client.request(hyper_req).await?;

    let (res_parts, res_body) = upstream_res.into_parts();
    let response_headers = http::Response::from_parts(res_parts, ());

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

pub async fn handle_webtransport_session(
    config: Arc<config::Config>,
    headers: HeaderMap,
    session: WebTransportSession<h3_quinn::Connection, Bytes>,
) -> anyhow::Result<()> {
    let protocol = headers
        .get("proxy-protocol")
        .context(format!("Corrupted proxy request {}", line!()))?
        .to_str()?;
    let endpoint = headers
        .get("proxy-endpoint")
        .context(format!("Corrupted proxy request {}", line!()))?
        .to_str()?;
    match protocol {
        "tcp" => {
            loop {
                match session.accept_bi().await {
                    Ok(Some(AcceptedBi::BidiStream(_, stream))) => {
                        let config = config.clone();
                        let endpoint = endpoint.to_owned();
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
                    _ => continue, // 处理其他类型的流或忽略
                }
            }
        }
        "udp" => {
            if let Err(err) = handle_udp(session, config, endpoint).await {
                error!("Failed to handle UDP session: {err:?}");
            }
        }
        _ => anyhow::bail!("Corrupted proxy request {}", line!()),
    }
    Ok(())
}

async fn handle_tcp(
    config: Arc<config::Config>,
    endpoint: &str,
    mut stream: h3_webtransport::stream::BidiStream<BidiStream<Bytes>, Bytes>,
) -> anyhow::Result<()> {
    if let Some(proxy_addr) = config.socks_proxy.as_ref() {
        let (target_addr, target_port) = endpoint
            .split_once(':')
            .context(format!("Invalid endpoint format: {}", endpoint))?;
        let mut target_stream = Socks5Stream::connect(
            proxy_addr,
            target_addr.to_owned(),
            target_port.parse()?,
            Default::default(),
        )
        .await
        .context("failed to connect via socks5")?;
        info!("Outgoing TCP connection established to {}", endpoint);
        tokio::io::copy_bidirectional(&mut stream, &mut target_stream).await
    } else {
        let mut target_stream = TcpStream::connect(&endpoint)
            .await
            .context(format!("Failed to connect to upstream addr: {}", endpoint))?;
        info!("Outgoing TCP connection established to {}", endpoint);
        tokio::io::copy_bidirectional(&mut stream, &mut target_stream).await
    }
    .map_err(|e| anyhow!("TCP proxy stream error: {:?}", e))
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
        let backing_socket = TcpStream::connect(proxy_addr)
            .await
            .context("Can not connect to socks server")?;
        let socket = Socks5Datagram::bind(
            backing_socket,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        )
        .await?;
        let target_addr: SocketAddr = endpoint.parse()?;
        let send_task = async {
            loop {
                let datagram = rx.read_datagram().await?;
                socket.send_to(datagram.payload(), target_addr).await?;
            }
            #[allow(unreachable_code)]
            anyhow::Ok(())
        };
        let recv_task = async {
            let mut buf = [0u8; 65536];
            loop {
                let (n, _addr) = socket.recv_from(&mut buf).await?;
                tx.send_datagram(Bytes::copy_from_slice(&buf[..n]))?;
            }
            #[allow(unreachable_code)]
            anyhow::Ok(())
        };
        tokio::select! {
            res = send_task => return res,
            res = recv_task => return res,
        }
    } else {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(endpoint).await?;
        let send_task = async {
            loop {
                let datagram = rx.read_datagram().await?;
                socket.send(datagram.payload()).await?;
            }
            #[allow(unreachable_code)]
            anyhow::Ok(())
        };
        let recv_task = async {
            let mut buf = [0u8; 65536];
            loop {
                let n = socket.recv(&mut buf).await?;
                tx.send_datagram(Bytes::copy_from_slice(&buf[..n]))?;
            }
            #[allow(unreachable_code)]
            anyhow::Ok(())
        };

        tokio::select! {
            res = send_task => return res,
            res = recv_task => return res,
        }
    }
}
