pub struct Cursor {
    pub data: Vec<u8>,
    pub position: usize,
}
impl Cursor {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, position: 0 }
    }

    pub fn read_str(&mut self, bytes: usize) -> &str {
        let result = std::str::from_utf8(&self.data[self.position..self.position + bytes]);
        self.position += bytes;
        result.unwrap()
    }

    pub fn read(&mut self, bytes: usize) -> Vec<u8> {
        let result = &self.data[self.position..self.position + bytes];
        self.position += bytes;
        result.to_vec()
    }

    pub fn skip(&mut self, bytes: usize) {
        self.position += bytes;
    }

    pub fn read_u16(&mut self) -> u16 {
        u16_from_bytes(&self.read(2))
    }

    pub fn read_u32(&mut self) -> u32 {
        u32_from_bytes(&self.read(4))
    }

    pub fn read_u64(&mut self) -> u64 {
        u64_from_bytes(&self.read(8))
    }
}

pub fn u32_from_bytes(le_bytes: &[u8]) -> u32 {
    let result = u32::from_le_bytes(le_bytes[0..4].try_into().unwrap());
    result
}

pub fn u16_from_bytes(le_bytes: &[u8]) -> u16 {
    let result = u16::from_le_bytes(le_bytes[0..2].try_into().unwrap());
    result
}

pub fn u64_from_bytes(le_bytes: &[u8]) -> u64 {
    let result = u64::from_le_bytes(le_bytes[0..8].try_into().unwrap());
    result
}
