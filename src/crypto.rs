//! AES-256-GCM encryption with a PBKDF2-HMAC-SHA256 derived key, so a
//! plain passphrase (not a raw 32-byte key) can be used on the CLI.

use aes_gcm::aead::{Aead, KeyInit, Payload as AeadPayload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;

use crate::payload::{NONCE_LEN, SALT_LEN};

const PBKDF2_ROUNDS: u32 = 100_000;

fn derive_key(passphrase: &str, salt: &[u8; SALT_LEN]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, PBKDF2_ROUNDS, &mut key);
    key
}

/// Encrypts `plaintext` with a key derived from `passphrase`, generating a
/// fresh random salt and nonce. Returns (salt, nonce, ciphertext).
pub fn encrypt(
    plaintext: &[u8],
    passphrase: &str,
) -> Result<([u8; SALT_LEN], [u8; NONCE_LEN], Vec<u8>), String> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let key_bytes = derive_key(passphrase, &salt);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, AeadPayload { msg: plaintext, aad: b"" })
        .map_err(|e| format!("encryption failed: {e}"))?;

    Ok((salt, nonce_bytes, ciphertext))
}

/// Decrypts `ciphertext` using a key derived from `passphrase`, `salt`, and
/// `nonce`. Fails (rather than returning garbage) if the passphrase is
/// wrong, because AES-GCM is authenticated.
pub fn decrypt(
    ciphertext: &[u8],
    passphrase: &str,
    salt: &[u8; SALT_LEN],
    nonce_bytes: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, String> {
    let key_bytes = derive_key(passphrase, salt);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, AeadPayload { msg: ciphertext, aad: b"" })
        .map_err(|_| "decryption failed: wrong passphrase or corrupted data".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        let message = b"the secret is in the sauce";
        let (salt, nonce, ciphertext) = encrypt(message, "correct-horse").unwrap();
        let decrypted = decrypt(&ciphertext, "correct-horse", &salt, &nonce).unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn wrong_passphrase_fails_to_decrypt() {
        let message = b"top secret";
        let (salt, nonce, ciphertext) = encrypt(message, "correct-horse").unwrap();
        let result = decrypt(&ciphertext, "wrong-horse", &salt, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn same_plaintext_different_salt_gives_different_ciphertext() {
        let message = b"identical plaintext";
        let (_, _, ct1) = encrypt(message, "pw").unwrap();
        let (_, _, ct2) = encrypt(message, "pw").unwrap();
        assert_ne!(ct1, ct2); // random salt/nonce each time
    }
}
