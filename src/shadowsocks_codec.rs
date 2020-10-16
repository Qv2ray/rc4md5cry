use byteorder::ByteOrder;

pub trait ShadowsocksCodec {
    fn encode_shadowsocks(&self, into: &mut [u8]);
    fn decode_shadowsocks(from: &mut [u8]) -> Self;
}

impl ShadowsocksCodec for std::net::SocketAddrV4 {
    fn encode_shadowsocks(&self, into: &mut [u8]) {
        into[0] = 0x01;
        into[1..5].copy_from_slice(&self.ip().octets());
        byteorder::BigEndian::write_u16(&mut into[5..7], self.port())
    }

    fn decode_shadowsocks(_from: &mut [u8]) -> Self {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV4;
    use std::str::FromStr;

    #[test]
    fn test_encode_localhost() {
        let addr = SocketAddrV4::from_str("127.0.0.1:1080").unwrap();
        let mut buf = [0u8; 7];
        eprintln!("Buffer before: {}", hex::encode(&buf));

        addr.encode_shadowsocks(&mut buf);
        eprintln!("Buffer after:  {}", hex::encode(&buf));

        assert_eq!(buf[0], 0x01, "address type should be ipv4");
        assert_eq!(
            buf[1..5],
            [127u8, 0u8, 0u8, 1u8],
            "addresses should be sequentially encoded"
        );
        assert_eq!(
            byteorder::BigEndian::read_u16(&buf[5..7]),
            1080,
            "port should be big endian"
        );
    }
}
