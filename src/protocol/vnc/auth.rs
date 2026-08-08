//! VNC Authentication type 2 crypto: bit-reversed DES key and challenge-response.

use des::Des;
use des::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

/// Builds the 16-byte VNC Authentication DES response for a challenge.
///
/// Password bytes are truncated/padded to 8 octets; each key byte has its bits
/// reversed before DES-ECB encryption of the two challenge halves.
///
/// # Parameters
///
/// - `password`: VNC password (only the first 8 bytes are used).
/// - `challenge`: 16-byte server challenge.
///
/// # Returns
///
/// 16-byte ciphertext response.
///
/// # Errors
///
/// This function does not fail.
///
/// # Examples
///
/// ```
/// use brute::protocol::vnc::vnc_auth_response;
/// let challenge = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
/// let resp = vnc_auth_response("password", &challenge);
/// assert_eq!(resp.len(), 16);
/// ```
pub fn vnc_auth_response(password: &str, challenge: &[u8; 16]) -> [u8; 16] {
    let key = vnc_password_key(password);
    let cipher = Des::new_from_slice(&key).expect("DES key length is always 8");
    let mut out = [0u8; 16];
    let mut block1 = GenericArray::clone_from_slice(&challenge[0..8]);
    cipher.encrypt_block(&mut block1);
    out[0..8].copy_from_slice(&block1);
    let mut block2 = GenericArray::clone_from_slice(&challenge[8..16]);
    cipher.encrypt_block(&mut block2);
    out[8..16].copy_from_slice(&block2);
    out
}

/// Derives the 8-byte DES key from a VNC password (truncate/pad + bit reverse).
///
/// # Parameters
///
/// - `password`: Raw password string (treated as Latin-1/byte-oriented).
///
/// # Returns
///
/// 8-byte DES key material.
///
/// # Errors
///
/// This function does not fail.
///
/// # Examples
///
/// ```
/// use brute::protocol::vnc::vnc_password_key;
/// assert_eq!(vnc_password_key("pass"), [0x0e, 0x86, 0xce, 0xce, 0, 0, 0, 0]);
/// ```
pub fn vnc_password_key(password: &str) -> [u8; 8] {
    let mut key = [0u8; 8];
    for (i, byte) in password.as_bytes().iter().take(8).enumerate() {
        key[i] = byte.reverse_bits();
    }
    key
}
