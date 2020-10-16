use crypto::digest::Digest;

pub struct AttackVectorConfig {
    pub address: std::net::SocketAddrV4,
    pub rounds: usize,
    pub key: [u8; 16],
}

impl AttackVectorConfig {
    pub fn new(
        address: std::net::SocketAddrV4,
        rounds: usize,
        password: &str,
    ) -> AttackVectorConfig {
        AttackVectorConfig {
            address,
            rounds,
            key: AttackVectorConfig::derive_key(password),
        }
    }

    fn derive_key(password: &str) -> [u8; 16] {
        let mut buf: [u8; 16] = [0u8; 16];
        let mut md5 = crypto::md5::Md5::new();
        md5.input_str(password);
        md5.result(&mut buf);
        buf
    }
}
