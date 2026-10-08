//! The byte layout embedded into pixel LSBs.
//!
//! ```text
//! offset  size  field
//! 0       4     magic "PXC1"
//! 4       1     flags (bit 0 = encrypted)
//! 5       16    salt        (only present if encrypted)
//! 21      12    nonce       (only present if encrypted)
//! ...     4     body_len (u32, little-endian)
//! ...     N     body (ciphertext if encrypted, else raw UTF-8 message bytes)
//! ```

pub const MAGIC: &[u8; 4] = b"PXC1";
pub const FLAG_ENCRYPTED: u8 = 0b0000_0001;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

#[derive(Debug)]
pub struct Payload {
    pub encrypted: bool,
    pub salt: Option<[u8; SALT_LEN]>,
    pub nonce: Option<[u8; NONCE_LEN]>,
    pub body: Vec<u8>,
}

impl Payload {
    pub fn plaintext(body: Vec<u8>) -> Self {
        Self { encrypted: false, salt: None, nonce: None, body }
    }

    pub fn encrypted(salt: [u8; SALT_LEN], nonce: [u8; NONCE_LEN], body: Vec<u8>) -> Self {
        Self { encrypted: true, salt: Some(salt), nonce: Some(nonce), body }
    }

    /// Serializes to the raw byte buffer that gets embedded into pixel LSBs.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(if self.encrypted { FLAG_ENCRYPTED } else { 0 });
        if self.encrypted {
            out.extend_from_slice(&self.salt.unwrap());
            out.extend_from_slice(&self.nonce.unwrap());
        }
        out.extend_from_slice(&(self.body.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.body);
        out
    }

    /// Parses a previously serialized payload back out of a raw byte buffer.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < 5 || &buf[0..4] != MAGIC {
            return Err("no valid pixelcipher payload found (bad magic)".to_string());
        }
        let flags = buf[4];
        let encrypted = flags & FLAG_ENCRYPTED != 0;
        let mut offset = 5;

        let (salt, nonce) = if encrypted {
            if buf.len() < offset + SALT_LEN + NONCE_LEN {
                return Err("truncated payload: missing salt/nonce".to_string());
            }
            let mut salt = [0u8; SALT_LEN];
            salt.copy_from_slice(&buf[offset..offset + SALT_LEN]);
            offset += SALT_LEN;
            let mut nonce = [0u8; NONCE_LEN];
            nonce.copy_from_slice(&buf[offset..offset + NONCE_LEN]);
            offset += NONCE_LEN;
            (Some(salt), Some(nonce))
        } else {
            (None, None)
        };

        if buf.len() < offset + 4 {
            return Err("truncated payload: missing length field".to_string());
        }
        let body_len = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;

        if buf.len() < offset + body_len {
            return Err("truncated payload: body shorter than declared length".to_string());
        }
        let body = buf[offset..offset + body_len].to_vec();

        Ok(Self { encrypted, salt, nonce, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_round_trips() {
        let payload = Payload::plaintext(b"hello world".to_vec());
        let bytes = payload.to_bytes();
        let parsed = Payload::from_bytes(&bytes).unwrap();
        assert!(!parsed.encrypted);
        assert_eq!(parsed.body, b"hello world");
    }

    #[test]
    fn encrypted_round_trips_with_salt_and_nonce() {
        let salt = [7u8; SALT_LEN];
        let nonce = [9u8; NONCE_LEN];
        let payload = Payload::encrypted(salt, nonce, vec![1, 2, 3, 4]);
        let bytes = payload.to_bytes();
        let parsed = Payload::from_bytes(&bytes).unwrap();
        assert!(parsed.encrypted);
        assert_eq!(parsed.salt.unwrap(), salt);
        assert_eq!(parsed.nonce.unwrap(), nonce);
        assert_eq!(parsed.body, vec![1, 2, 3, 4]);
    }

    #[test]
    fn rejects_bad_magic() {
        let bytes = b"NOPE".to_vec();
        assert!(Payload::from_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_truncated_body() {
        let payload = Payload::plaintext(b"hello".to_vec());
        let mut bytes = payload.to_bytes();
        bytes.truncate(bytes.len() - 2); // chop off part of the body
        assert!(Payload::from_bytes(&bytes).is_err());
    }
}
