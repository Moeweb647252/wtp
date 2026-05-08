use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;
use bytes::Bytes;
use futures_util::StreamExt;
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
use tokio::net::TcpSocket;
use tracing::level_filters::LevelFilter;
use tracing::{error, info};

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
    let cert = CertificateDer::from_pem_file(&config.cert)?;
    let key = PrivateKeyDer::from_pem_file(&config.key)?;
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    let tcp_tls_config = tls_config.clone();
    let config_clone = config.clone();
    tokio::spawn(async move {
        if let Err(e) = handle_tcp_ssl(config_clone, tcp_tls_config).await {
            error!("Failed to handle SSL connections: {e:?}");
        }
    });
    tls_config.max_early_data_size = u32::MAX;
    let alpn: Vec<Vec<u8>> = vec![b"h3".to_vec()];
    tls_config.alpn_protocols = alpn;
    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls_config)?));
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.keep_alive_interval(Some(Duration::from_secs(2)));
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
                        .max_webtransport_sessions(u64::MAX)
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
                        let session = WebTransportSession::accept(req, stream, h3_conn).await?;
                        tracing::info!("Established webtransport session");
                        handle_webtransport_session(headers, session).await?;
                        return Ok(());
                    }
                    _ => redirect_upstream(req, stream, config).await?,
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
            let accepted_bi = session
                .accept_bi()
                .await?
                .context(format!("Corrupted proxy request {}", line!()))?;
            match accepted_bi {
                AcceptedBi::BidiStream(_, mut stream) => {
                    let addr: SocketAddr = endpoint.parse()?;
                    let mut target_stream = match addr {
                        SocketAddr::V4(_) => {
                            let socket = TcpSocket::new_v4()?;
                            socket.connect(addr).await?
                        }
                        SocketAddr::V6(_) => {
                            let socket = TcpSocket::new_v6()?;
                            socket.connect(addr).await?
                        }
                    };
                    tokio::io::copy_bidirectional(&mut stream, &mut target_stream).await?;
                }
                _ => anyhow::bail!("Corrupted proxy request {}", line!()),
            }
        }
        "udp" => {
            let mut tx = session.datagram_sender();
            let mut rx = session.datagram_reader();

            let addr: SocketAddr = endpoint.parse()?;
            let socket = match addr {
                SocketAddr::V4(_) => tokio::net::UdpSocket::bind("0.0.0.0:0").await?,
                SocketAddr::V6(_) => tokio::net::UdpSocket::bind("[::]:0").await?,
            };
            socket.connect(addr).await?;
            let socket = Arc::new(socket);
            let socket_clone = socket.clone();
            let send_task = async move {
                loop {
                    let datagram = rx.read_datagram().await?;
                    socket.send(datagram.payload()).await?;
                }
                #[allow(unreachable_code)]
                anyhow::Ok(())
            };
            let recv_task = async move {
                let mut buf = [0u8; 65536];
                loop {
                    let n = socket_clone.recv(&mut buf).await?;
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
        _ => anyhow::bail!("Corrupted proxy request {}", line!()),
    }
    Ok(())
}
