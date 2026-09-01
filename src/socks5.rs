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
    request(&mut stream, CMD_CONNECT, host, port).await?;
    Ok(stream)
}

pub async fn udp_associate(proxy: &str) -> Result<(TcpStream, SocketAddr)> {
    let mut stream = connect_proxy(proxy).await?;
    handshake(&mut stream).await?;
    request(&mut stream, CMD_UDP_ASSOCIATE, "0.0.0.0", 0).await?;
    let relay = read_reply_addr(&mut stream).await?;
    Ok((stream, relay))
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
) -> Result<()> {
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
    read_addr_body(stream, header[3]).await
}

async fn read_reply_addr<S: AsyncRead + Unpin>(stream: &mut S) -> Result<SocketAddr> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != VERSION || header[2] != 0 {
        bail!("invalid SOCKS5 UDP reply header");
    }
    if header[1] != 0 {
        bail!("SOCKS5 UDP ASSOCIATE rejected: 0x{:02x}", header[1]);
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

async fn read_addr_body<S: AsyncRead + Unpin>(stream: &mut S, atyp: u8) -> Result<()> {
    match atyp {
        ATYP_IPV4 => {
            let mut b = [0; 4];
            stream.read_exact(&mut b).await?;
        }
        ATYP_IPV6 => {
            let mut b = [0; 16];
            stream.read_exact(&mut b).await?;
        }
        ATYP_DOMAIN => {
            let mut l = [0];
            stream.read_exact(&mut l).await?;
            let mut b = vec![0; l[0] as usize];
            stream.read_exact(&mut b).await?;
        }
        _ => bail!("unsupported SOCKS5 address type: 0x{atyp:02x}"),
    }
    let mut p = [0; 2];
    stream.read_exact(&mut p).await?;
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
        ATYP_DOMAIN => bail!("SOCKS5 relay address must use an IP address"),
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
}
