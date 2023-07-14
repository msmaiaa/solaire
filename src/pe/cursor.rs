use crate::util::{i16_from_bytes, u16_from_bytes, u32_from_bytes, u64_from_bytes};

pub struct Cursor {
    pub bytes: Vec<u8>,
    pub position: usize,
}
impl Cursor {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, position: 0 }
    }

    pub fn read_str(&mut self, bytes: usize) -> &str {
        let result = std::str::from_utf8(&self.bytes[self.position..self.position + bytes]);
        self.position += bytes;
        result.unwrap()
    }

    pub fn read(&mut self, bytes: usize) -> Vec<u8> {
        let result = &self.bytes[self.position..self.position + bytes];
        self.position += bytes;
        result.to_vec()
    }

    pub fn skip(&mut self, bytes: usize) {
        self.position += bytes;
    }

    pub fn read_u8(&mut self) -> u8 {
        let result = self.bytes[self.position];
        self.position += 1;
        result
    }

    pub fn read_u16(&mut self) -> u16 {
        u16_from_bytes(&self.read(2))
    }

    pub fn read_i16(&mut self) -> i16 {
        i16_from_bytes(&self.read(2))
    }

    pub fn read_u32(&mut self) -> u32 {
        u32_from_bytes(&self.read(4))
    }

    pub fn read_u64(&mut self) -> u64 {
        u64_from_bytes(&self.read(8))
    }
}
