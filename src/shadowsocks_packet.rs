use crate::rc4::Rc4;
use crypto::digest::Digest;
use crypto::md5::Md5;
use rand::Rng;

pub struct Rc4Md5IV {
    pub buffer: [u8; 16],
}

impl Rc4Md5IV {
    pub fn new(rng: &mut dyn Rng) -> Rc4Md5IV {
        let mut buffer = [0u8; 16];
        rng.fill_bytes(&mut buffer);
        Rc4Md5IV { buffer }
    }
}

#[derive(Copy, Clone)]
pub struct Rc4Md5KeyDriver {
    md5: Md5,
}

impl Rc4Md5KeyDriver {
    pub fn new(key: &[u8]) -> Rc4Md5KeyDriver {
        let mut md5 = crypto::md5::Md5::new();
        md5.input(key);
        return Rc4Md5KeyDriver { md5 };
    }

    pub fn derive(self, iv: &[u8]) -> Rc4 {
        let mut md5 = self.md5.clone();
        md5.input(iv);

        let mut md5_result = [0u8; 16];
        md5.result(&mut md5_result);

        Rc4::new(&md5_result)
    }
}
