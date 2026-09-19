use anyhow::{Context, Result, bail};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

const VERSION: u8 = 5;
const NO_AUTH: u8 = 0;
const CMD_CONNECT: u8 = 1;
const CMD_UDP_ASSOCIATE: u8 = 3;
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

pub async fn connect(proxy: &str, host: &str, port: u16) -> Result<TcpStream> {
    let mut stream = connect_proxy(proxy).await?;
    handshake(&mut stream).await?;
    // CONNECT 回复里的 BND.ADDR/BND.PORT 是代理出站的本地地址,对调用方无用。
    let _ = request(&mut stream, CMD_CONNECT, host, port).await?;
    Ok(stream)
}

pub async fn udp_associate(proxy: &str) -> Result<(TcpStream, SocketAddr)> {
    let mut stream = connect_proxy(proxy).await?;
    handshake(&mut stream).await?;
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
    Ok(timeout(Duration::from_secs(10), TcpStream::connect(proxy)).await??)
}

async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Result<()> {
    stream.write_all(&[VERSION, 1, NO_AUTH]).await?;
    let mut response = [0; 2];
    stream.read_exact(&mut response).await?;
    if response != [VERSION, NO_AUTH] {
        bail!("SOCKS5 proxy does not support no authentication");
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
}
