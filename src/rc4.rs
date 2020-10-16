pub struct Rc4 {
    i: u8,
    j: u8,
    state: [u8; 256],
}

impl Rc4 {
    // Generates a new instance of RC4 by using the KSA
    // (key-scheduling algorithm) and returns it.
    pub fn new(key: &[u8]) -> Rc4 {
        let mut rc4 = Rc4 {
            i: 0,
            j: 0,
            state: [0; 256],
        };

        for i in 0..256 {
            rc4.state[i] = i as u8;
        }

        let mut j: u8 = 0;
        for i in 0..256 {
            j = j
                .wrapping_add(rc4.state[i])
                .wrapping_add(key[i % key.len()]);
            rc4.state.swap(i, j as usize);
        }

        rc4
    }

    // Generates the next byte to be combined with a byte of the plain text / cipher.
    fn next_byte(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.state[self.i as usize]);
        self.state.swap(self.i as usize, self.j as usize);
        self.state[self.state[self.i as usize].wrapping_add(self.state[self.j as usize]) as usize]
    }

    // Uses KSA (new) and PRGA (next_byte) to XOR nput with the cipher
    pub fn crypt_inplace(&mut self, input: &mut [u8]) {
        for i in 0..input.len() {
            input[i] ^= self.next_byte();
        }
    }
}

#[cfg(test)]
mod tests {

    use super::Rc4;

    #[test]
    fn new_test() {
        // The expected result (precalculated)
        let expected = [
            101, 124, 172, 10, 166, 26, 46, 91, 2, 137, 39, 243, 253, 25, 3, 30, 47, 238, 196, 38,
            94, 149, 15, 32, 248, 51, 158, 150, 106, 183, 67, 219, 95, 177, 138, 152, 13, 188, 118,
            108, 207, 151, 41, 142, 236, 103, 55, 72, 20, 244, 216, 14, 168, 90, 4, 42, 153, 64,
            250, 129, 97, 225, 87, 199, 204, 100, 16, 249, 191, 82, 43, 131, 24, 169, 69, 54, 96,
            77, 255, 84, 1, 143, 242, 123, 21, 93, 61, 102, 224, 107, 109, 79, 80, 23, 229, 6, 156,
            181, 105, 159, 33, 141, 18, 104, 9, 56, 233, 178, 127, 111, 135, 206, 202, 128, 31, 71,
            211, 222, 45, 66, 163, 189, 167, 201, 232, 17, 251, 198, 170, 155, 115, 57, 228, 98,
            190, 76, 59, 239, 37, 147, 180, 240, 197, 200, 19, 0, 213, 99, 125, 44, 195, 164, 176,
            121, 220, 212, 86, 186, 34, 214, 230, 254, 40, 203, 194, 231, 162, 226, 187, 116, 208,
            22, 68, 88, 192, 140, 205, 234, 119, 83, 136, 63, 12, 112, 217, 154, 184, 81, 70, 35,
            174, 78, 241, 179, 210, 215, 49, 144, 130, 48, 133, 7, 209, 92, 73, 193, 28, 75, 117,
            223, 50, 113, 114, 148, 173, 29, 53, 160, 8, 139, 246, 65, 252, 161, 221, 185, 27, 36,
            11, 110, 237, 165, 5, 182, 145, 171, 120, 157, 134, 175, 122, 58, 235, 52, 62, 126, 85,
            60, 132, 74, 245, 227, 218, 89, 247, 146,
        ];

        // Test key
        let key = "pwd12";

        // Generate the RC4 instance.
        let rc4 = Rc4::new(key.as_bytes());

        // Walk through the arrays and see if every element matches.
        for i in 0..rc4.state.len() {
            assert_eq!(rc4.state[i], expected[i]);
        }
    }
}
