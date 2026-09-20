use anyhow::{Context, Result, bail};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

const VERSION: u8 = 5;
const NO_AUTH: u8 = 0;
const METHOD_USER_PASS: u8 = 2;
/// RFC 1929 用户名密码子协商的版本号:是 0x01 而不是 0x05,易踩坑点。
const AUTH_VERSION: u8 = 1;
const CMD_CONNECT: u8 = 1;
const CMD_UDP_ASSOCIATE: u8 = 3;
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

pub async fn connect(
    proxy: &str,
    auth: Option<(&str, &str)>,
    host: &str,
    port: u16,
) -> Result<TcpStream> {
    let mut stream = connect_proxy(proxy).await?;
    handshake(&mut stream, auth).await?;
    // CONNECT 回复里的 BND.ADDR/BND.PORT 是代理出站的本地地址,对调用方无用。
    let _ = request(&mut stream, CMD_CONNECT, host, port).await?;
    Ok(stream)
}

pub async fn udp_associate(
    proxy: &str,
    auth: Option<(&str, &str)>,
) -> Result<(TcpStream, SocketAddr)> {
    let mut stream = connect_proxy(proxy).await?;
    handshake(&mut stream, auth).await?;
    // UDP ASSOCIATE 只会收到一条回复,request() 在解码它时顺带返回 relay 地址;
    // 之后再读一次回复会永远阻塞(代理不会发第二条)。
    let relay = request(&mut stream, CMD_UDP_ASSOCIATE, "0.0.0.0", 0).await?;
    let relay = effective_relay(relay, stream.peer_addr()?);
    Ok((stream, relay))
}

/// RFC 1928:UDP ASSOCIATE 回复的 `BND.ADDR` 为未指定地址(`0.0.0.0`/`::`)时,
/// 客户端应改用代理自身的地址;端口仍以回复为准。
fn effective_relay(relay: SocketAddr, proxy: SocketAddr) -> SocketAddr {
    if relay.ip().is_unspecified() {
        SocketAddr::new(proxy.ip(), relay.port())
    } else {
        relay
    }
}

async fn connect_proxy(proxy: &str) -> Result<TcpStream> {
    let stream = timeout(Duration::from_secs(10), TcpStream::connect(proxy)).await??;
    // UDP ASSOCIATE 的控制连接握手后全程无数据,靠 TCP keepalive 防服务端空闲
    // 踢连;CONNECT 流顺带受益(能发现半开连接)。参数与 QUIC keepalive(60s)对齐。
    // 注意 OS 默认 2 小时才发首个探测,必须显式调小才有意义。
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(60))
        .with_retries(5);
    socket2::SockRef::from(&stream).set_tcp_keepalive(&keepalive)?;
    Ok(stream)
}

async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    auth: Option<(&str, &str)>,
) -> Result<()> {
    // 配了凭据就只提供 USERNAME/PASSWORD(0x02):必须用认证,不静默降级成无认证。
    let method = if auth.is_some() {
        METHOD_USER_PASS
    } else {
        NO_AUTH
    };
    stream.write_all(&[VERSION, 1, method]).await?;
    let mut response = [0; 2];
    stream.read_exact(&mut response).await?;
    if response != [VERSION, method] {
        if auth.is_some() {
            bail!("SOCKS5 proxy does not accept username/password authentication");
        }
        bail!("SOCKS5 proxy does not support no authentication");
    }
    if let Some((user, pass)) = auth {
        authenticate(stream, user, pass).await?;
    }
    Ok(())
}

/// RFC 1929 子协商:发送 `[0x01, ulen, uname, plen, passwd]`,status 0x00 表示成功。
async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    user: &str,
    pass: &str,
) -> Result<()> {
    // config 解析时已校验过长度,这里再做一次双保险(防止将来有新的调用方绕过)。
    let ulen = u8::try_from(user.len()).context("SOCKS5 username exceeds 255 bytes")?;
    let plen = u8::try_from(pass.len()).context("SOCKS5 password exceeds 255 bytes")?;
    if ulen == 0 || plen == 0 {
        bail!("empty SOCKS5 username or password");
    }
    let mut buf = Vec::with_capacity(3 + user.len() + pass.len());
    buf.extend_from_slice(&[AUTH_VERSION, ulen]);
    buf.extend_from_slice(user.as_bytes());
    buf.push(plen);
    buf.extend_from_slice(pass.as_bytes());
    stream.write_all(&buf).await?;
    let mut response = [0; 2];
    stream.read_exact(&mut response).await?;
    if response[0] != AUTH_VERSION {
        bail!("invalid SOCKS5 auth reply version: 0x{:02x}", response[0]);
    }
    if response[1] != 0 {
        bail!(
            "SOCKS5 username/password authentication failed: status 0x{:02x}",
            response[1]
        );
    }
    Ok(())
}

async fn request<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    command: u8,
    host: &str,
    port: u16,
) -> Result<SocketAddr> {
    let mut request = Vec::with_capacity(4 + host.len() + 3);
    request.extend_from_slice(&[VERSION, command, 0]);
    encode_host_port(&mut request, host, port)?;
    stream.write_all(&request).await?;
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != VERSION || header[2] != 0 {
        bail!("invalid SOCKS5 reply header");
    }
    if header[1] != 0 {
        bail!("SOCKS5 request rejected: 0x{:02x}", header[1]);
    }
    read_socket_addr(stream, header[3]).await
}

fn encode_host_port(out: &mut Vec<u8>, host: &str, port: u16) -> Result<()> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(ip) => {
                out.push(ATYP_IPV4);
                out.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                out.push(ATYP_IPV6);
                out.extend_from_slice(&ip.octets());
            }
        }
    } else {
        let bytes = host.as_bytes();
        let len = u8::try_from(bytes.len()).context("SOCKS5 domain exceeds 255 bytes")?;
        if len == 0 {
            bail!("empty SOCKS5 domain");
        }
        out.extend_from_slice(&[ATYP_DOMAIN, len]);
        out.extend_from_slice(bytes);
    }
    out.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

async fn read_socket_addr<S: AsyncRead + Unpin>(stream: &mut S, atyp: u8) -> Result<SocketAddr> {
    let ip = match atyp {
        ATYP_IPV4 => {
            let mut b = [0; 4];
            stream.read_exact(&mut b).await?;
            IpAddr::V4(Ipv4Addr::from(b))
        }
        ATYP_IPV6 => {
            let mut b = [0; 16];
            stream.read_exact(&mut b).await?;
            IpAddr::V6(Ipv6Addr::from(b))
        }
        // RFC 1928 允许回复里的 BND.ADDR 是域名,但实践中服务端都回 IP;
        // 有意收窄:遇到域名直接报错,真碰到这种服务端再放开。
        ATYP_DOMAIN => bail!("SOCKS5 reply address must be an IP address"),
        _ => bail!("unsupported SOCKS5 address type: 0x{atyp:02x}"),
    };
    let port = read_port(stream).await?;
    Ok(SocketAddr::new(ip, port))
}

async fn read_port<S: AsyncRead + Unpin>(stream: &mut S) -> Result<u16> {
    let mut p = [0; 2];
    stream.read_exact(&mut p).await?;
    Ok(u16::from_be_bytes(p))
}

pub struct UdpPacket {
    pub payload_start: usize,
}

pub fn encode_udp_packet(buf: &mut Vec<u8>, host: &str, port: u16, payload: &[u8]) -> Result<()> {
    buf.clear();
    buf.reserve(3 + host.len() + payload.len() + 19);
    buf.extend_from_slice(&[0, 0, 0]);
    encode_host_port(buf, host, port)?;
    buf.extend_from_slice(payload);
    Ok(())
}

pub fn decode_udp_packet(buf: &[u8]) -> Result<UdpPacket> {
    if buf.len() < 4 || buf[..2] != [0, 0] {
        bail!("invalid SOCKS5 UDP header");
    }
    if buf[2] != 0 {
        bail!("fragmented SOCKS5 UDP packets are unsupported");
    }
    let atyp = buf[3];
    let mut pos = 4;
    match atyp {
        ATYP_IPV4 => {
            let end = pos + 4;
            let b = buf.get(pos..end).context("truncated IPv4")?;
            pos = end;
            Ipv4Addr::from(<[u8; 4]>::try_from(b).unwrap()).to_string()
        }
        ATYP_IPV6 => {
            let end = pos + 16;
            let b = buf.get(pos..end).context("truncated IPv6")?;
            pos = end;
            Ipv6Addr::from(<[u8; 16]>::try_from(b).unwrap()).to_string()
        }
        ATYP_DOMAIN => {
            let len = *buf.get(pos).context("truncated domain length")? as usize;
            pos += 1;
            let end = pos + len;
            let b = buf.get(pos..end).context("truncated domain")?;
            pos = end;
            std::str::from_utf8(b)?.to_owned()
        }
        _ => bail!("unsupported SOCKS5 UDP address type: 0x{atyp:02x}"),
    };
    buf.get(pos..pos + 2).context("truncated port")?;
    pos += 2;
    Ok(UdpPacket { payload_start: pos })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trips_addresses() {
        let mut b = Vec::new();
        encode_udp_packet(&mut b, "127.0.0.1", 80, b"x").unwrap();
        assert_eq!(decode_udp_packet(&b).unwrap().payload_start, b.len() - 1);
        encode_udp_packet(&mut b, "example.com", 443, b"x").unwrap();
        assert_eq!(b[3], ATYP_DOMAIN);
        encode_udp_packet(&mut b, "::1", 53, b"x").unwrap();
        assert_eq!(b[3], ATYP_IPV6);
    }
    #[test]
    fn rejects_invalid_packets() {
        assert!(decode_udp_packet(&[0, 0, 1, ATYP_IPV4]).is_err());
        assert!(decode_udp_packet(&[0, 0, 0, ATYP_DOMAIN, 3, b'a']).is_err());
        assert!(decode_udp_packet(&[0, 0, 0, 99]).is_err());
    }

    #[test]
    fn rejects_oversized_domains() {
        let mut b = Vec::new();
        let host = "a".repeat(256);
        assert!(encode_udp_packet(&mut b, &host, 80, b"x").is_err());
    }

    #[test]
    fn preserves_payload_offset_for_ipv6() {
        let mut b = Vec::new();
        encode_udp_packet(&mut b, "::1", 53, b"payload").unwrap();
        let packet = decode_udp_packet(&b).unwrap();
        assert_eq!(&b[packet.payload_start..], b"payload");
    }

    /// 假代理:读掉固定 10 字节请求后回一条回复,然后保持连接打开。
    /// 回复只发一次,所以调用方必须只解码一次、不能去等第二条。
    async fn request_with_single_reply(reply: Vec<u8>) -> Result<SocketAddr> {
        let (mut client, mut server) = tokio::io::duplex(256);
        tokio::spawn(async move {
            // 请求固定 10 字节:[VERSION, CMD, RSV] + ATYP_IPV4 + 4 字节 IP + 2 字节端口
            let mut req = [0u8; 10];
            server.read_exact(&mut req).await.unwrap();
            server.write_all(&reply).await.unwrap();
            // 故意不关闭连接:若调用方还去读第二条回复,就会一直挂起。
            std::future::pending::<()>().await;
        });
        timeout(
            Duration::from_secs(1),
            request(&mut client, CMD_UDP_ASSOCIATE, "0.0.0.0", 0),
        )
        .await
        .expect("request must not wait for a second reply")
    }

    #[tokio::test]
    async fn decodes_ipv4_relay_reply_once() {
        let relay =
            request_with_single_reply(vec![VERSION, 0, 0, ATYP_IPV4, 127, 0, 0, 1, 0x04, 0x38])
                .await
                .unwrap();
        assert_eq!(relay, "127.0.0.1:1080".parse().unwrap());
    }

    #[tokio::test]
    async fn decodes_ipv6_relay_reply() {
        let mut reply = vec![VERSION, 0, 0, ATYP_IPV6];
        reply.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        reply.extend_from_slice(&53u16.to_be_bytes());
        let relay = request_with_single_reply(reply).await.unwrap();
        assert_eq!(relay, "[::1]:53".parse().unwrap());
    }

    #[test]
    fn relay_falls_back_to_proxy_addr_when_unspecified() {
        let proxy: SocketAddr = "192.0.2.10:1080".parse().unwrap();
        let unspecified: SocketAddr = "0.0.0.0:1080".parse().unwrap();
        assert_eq!(
            effective_relay(unspecified, proxy),
            "192.0.2.10:1080".parse().unwrap()
        );
        let explicit: SocketAddr = "198.51.100.7:9".parse().unwrap();
        assert_eq!(effective_relay(explicit, proxy), explicit);
    }

    #[tokio::test]
    async fn connect_proxy_enables_tcp_keepalive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let stream = connect_proxy(&addr.to_string()).await.unwrap();
        assert!(socket2::SockRef::from(&stream).keepalive().unwrap());
    }

    /// 假代理:校验客户端的方法协商字节,按参数回应;`auth_reply` 为 Some 时
    /// 继续校验子协商字节(凭据固定 user/pass)并按给定 status 回复。
    /// 全程 1s 超时防挂起。
    async fn run_handshake(
        auth: Option<(&str, &str)>,
        method_reply: u8,
        auth_reply: Option<u8>,
    ) -> Result<()> {
        let (mut client, mut server) = tokio::io::duplex(256);
        let expect_method = if auth.is_some() {
            METHOD_USER_PASS
        } else {
            NO_AUTH
        };
        tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [VERSION, 1, expect_method]);
            server.write_all(&[VERSION, method_reply]).await.unwrap();
            if let Some(status) = auth_reply {
                // [0x01, ulen=4, "user", plen=4, "pass"]
                let mut req = [0u8; 11];
                server.read_exact(&mut req).await.unwrap();
                assert_eq!(&req, b"\x01\x04user\x04pass");
                server.write_all(&[AUTH_VERSION, status]).await.unwrap();
            }
        });
        timeout(Duration::from_secs(1), handshake(&mut client, auth))
            .await
            .expect("handshake must not hang")
    }

    #[tokio::test]
    async fn no_auth_handshake_unchanged() {
        run_handshake(None, NO_AUTH, None).await.unwrap();
    }

    #[tokio::test]
    async fn authenticates_with_username_password() {
        run_handshake(Some(("user", "pass")), METHOD_USER_PASS, Some(0))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn rejects_wrong_password() {
        let err = run_handshake(Some(("user", "pass")), METHOD_USER_PASS, Some(1))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("authentication failed"));
    }

    #[tokio::test]
    async fn rejects_server_without_user_pass_support() {
        // 服务端回 0xFF(无可接受方法)或回 0x00(想降级成无认证)都要报错。
        for reply in [0xFF, NO_AUTH] {
            let err = run_handshake(Some(("user", "pass")), reply, None)
                .await
                .unwrap_err();
            assert!(err.to_string().contains("username/password"));
        }
    }

    #[tokio::test]
    async fn rejects_empty_or_overlong_credentials() {
        let (mut client, _server) = tokio::io::duplex(64);
        assert!(authenticate(&mut client, "", "p").await.is_err());
        assert!(authenticate(&mut client, "u", "").await.is_err());
        let long = "x".repeat(256);
        assert!(authenticate(&mut client, &long, "p").await.is_err());
        assert!(authenticate(&mut client, "u", &long).await.is_err());
    }

    /// 手工冒烟:连真实 SOCKS5 代理验证 RFC 1929 认证 + CONNECT 回包。
    /// 凭据从环境变量读,不落库。运行:
    /// `WTP_SMOKE_PROXY=user:pass:host:port cargo test smoke -- --ignored --nocapture`
    #[tokio::test]
    #[ignore = "requires a real SOCKS5 proxy"]
    async fn smoke_tcp_connect_with_auth() {
        let Ok(proxy) = std::env::var("WTP_SMOKE_PROXY") else {
            eprintln!("WTP_SMOKE_PROXY not set, skipping");
            return;
        };
        let proxy = crate::config::SocksProxy::parse(&proxy).unwrap();
        let target = std::env::var("WTP_SMOKE_TARGET").unwrap_or_else(|_| "example.com:80".into());
        let (host, port) = target.rsplit_once(':').unwrap();
        let port: u16 = port.parse().unwrap();

        let mut stream = timeout(
            Duration::from_secs(10),
            connect(&proxy.addr, proxy.auth(), host, port),
        )
        .await
        .expect("connect timed out")
        .unwrap();
        stream
            .write_all(format!("GET / HTTP/1.0\r\nHost: {host}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        // HTTP/1.0 默认短连接,服务端回完即关,read_to_end 能读到 EOF。
        let mut body = Vec::new();
        timeout(Duration::from_secs(10), stream.read_to_end(&mut body))
            .await
            .expect("read timed out")
            .unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.starts_with("HTTP/"),
            "unexpected response: {text:.100}"
        );
        eprintln!(
            "smoke tcp ok: {} bytes, status: {}",
            body.len(),
            text.lines().next().unwrap_or("")
        );
    }

    /// 错误密码必须被代理拒绝(RFC 1929 status 非 0)。
    #[tokio::test]
    #[ignore = "requires a real SOCKS5 proxy"]
    async fn smoke_wrong_password_rejected() {
        let Ok(proxy) = std::env::var("WTP_SMOKE_PROXY") else {
            eprintln!("WTP_SMOKE_PROXY not set, skipping");
            return;
        };
        let proxy = crate::config::SocksProxy::parse(&proxy).unwrap();
        let (user, _) = proxy.auth().expect("smoke proxy must have credentials");
        let err = timeout(
            Duration::from_secs(10),
            connect(
                &proxy.addr,
                Some((user, "wrong-password")),
                "example.com",
                80,
            ),
        )
        .await
        .expect("connect timed out")
        .unwrap_err();
        eprintln!("smoke wrong-password rejected as expected: {err}");
    }

    /// UDP ASSOCIATE 冒烟:经 relay 向 8.8.8.8:53 发 DNS A 查询并校验回包。
    /// 顺带覆盖 `effective_relay`(不少服务端 BND.ADDR 回 0.0.0.0)。
    #[tokio::test]
    #[ignore = "requires a real SOCKS5 proxy"]
    async fn smoke_udp_associate_with_auth() {
        let Ok(proxy) = std::env::var("WTP_SMOKE_PROXY") else {
            eprintln!("WTP_SMOKE_PROXY not set, skipping");
            return;
        };
        let proxy = crate::config::SocksProxy::parse(&proxy).unwrap();
        // control 连接必须活到 UDP 交换结束(服务端随 TCP 断开回收 relay)。
        let (_control, relay) = timeout(
            Duration::from_secs(10),
            udp_associate(&proxy.addr, proxy.auth()),
        )
        .await
        .expect("udp associate timed out")
        .expect("UDP ASSOCIATE rejected; proxy may have UDP disabled (reply 0x07/0x09)");
        let bind = if relay.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = tokio::net::UdpSocket::bind(bind).await.unwrap();

        // DNS 查询 example.com 的 A 记录:id=0x1234, RD=1, QD=1。
        let mut dns = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in ["example", "com"] {
            dns.push(u8::try_from(label.len()).unwrap());
            dns.extend_from_slice(label.as_bytes());
        }
        dns.extend_from_slice(&[0, 0, 1, 0, 1]); // 结束符 + QTYPE=A + QCLASS=IN

        let mut packet = Vec::new();
        encode_udp_packet(&mut packet, "8.8.8.8", 53, &dns).unwrap();
        socket.send_to(&packet, relay).await.unwrap();
        let mut buf = vec![0u8; 2048];
        let (n, _) = timeout(Duration::from_secs(10), socket.recv_from(&mut buf))
            .await
            .expect("dns reply timed out")
            .unwrap();
        let decoded = decode_udp_packet(&buf[..n]).unwrap();
        let payload = &buf[decoded.payload_start..n];
        assert!(payload.len() >= 12, "short DNS reply");
        assert_eq!(&payload[..2], b"\x12\x34", "DNS id mismatch");
        eprintln!(
            "smoke udp ok: dns reply {} bytes via {relay}",
            payload.len()
        );
    }
}
