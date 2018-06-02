use {Error, ErrorKind};
use key;
use super::is_base64_char;
use hex::FromHex;
use base64::{decode_config, encode_config, MIME};
use openssl::rsa::Rsa;
use std::io::Write;

mod openssh;
pub use self::openssh::*;

mod pkcs5;
pub use self::pkcs5::*;

mod pkcs8;

const AES_128_CBC: &'static str = "DEK-Info: AES-128-CBC,";

#[derive(Clone, Copy, Debug)]
/// AES encryption key.
pub enum Encryption {
    /// Key for AES128
    Aes128Cbc([u8; 16]),
    /// Key for AES256
    Aes256Cbc([u8; 16]),
}

#[derive(Clone, Debug)]
enum Format {
    Rsa,
    Openssh,
    Pkcs5Encrypted(Encryption),
    Pkcs8Encrypted,
    Pkcs8,
}

/// Decode a secret key, possibly deciphering it with the supplied
/// password.
pub fn decode_secret_key(
    secret: &str,
    password: Option<&[u8]>,
) -> Result<key::KeyPair, Error> {

    let mut format = None;
    let secret = {
        let mut started = false;
        let mut sec = String::new();
        for l in secret.lines() {
            if started == true {
                if l.chars().all(is_base64_char) {
                    sec.push_str(l)
                } else if l.starts_with(AES_128_CBC) {
                    let iv_: Vec<u8> = FromHex::from_hex(l.split_at(AES_128_CBC.len()).1)?;
                    if iv_.len() != 16 {
                        return Err(ErrorKind::CouldNotReadKey.into());
                    }
                    let mut iv = [0; 16];
                    iv.clone_from_slice(&iv_);
                    format = Some(Format::Pkcs5Encrypted(Encryption::Aes128Cbc(iv)))
                }
            }
            if l == "-----BEGIN OPENSSH PRIVATE KEY-----" {
                started = true;
                format = Some(Format::Openssh);
            } else if l == "-----BEGIN RSA PRIVATE KEY-----" {
                started = true;
                format = Some(Format::Rsa);
            } else if l == "-----BEGIN ENCRYPTED PRIVATE KEY-----" {
                started = true;
                format = Some(Format::Pkcs8Encrypted);
            } else if l == "-----BEGIN PRIVATE KEY-----" {
                started = true;
                format = Some(Format::Pkcs8);
            } else if l.starts_with("-----END ") {
                break;
            }
        }
        sec
    };

    // debug!("secret = {:?}", secret);
    let secret = decode_config(&secret, MIME)?;
    match format {
        Some(Format::Openssh) => decode_openssh(&secret, password),
        Some(Format::Rsa) => decode_rsa(&secret),
        Some(Format::Pkcs5Encrypted(enc)) => decode_pkcs5(&secret, password, enc),
        Some(Format::Pkcs8Encrypted) |
        Some(Format::Pkcs8) => self::pkcs8::decode_pkcs8(&secret, password),
        None => Err(ErrorKind::CouldNotReadKey.into()),
    }
}

pub fn encode_pkcs8_pem<W:Write>(key: &key::KeyPair, mut w: W) -> Result<(), Error> {
    let x = self::pkcs8::encode_pkcs8(key);
    w.write_all(b"-----BEGIN PRIVATE KEY-----\n")?;
    w.write_all(encode_config(&x, MIME).as_bytes())?;
    w.write_all(b"\n-----END PRIVATE KEY-----\n")?;
    Ok(())
}

pub fn encode_pkcs8_pem_encrypted<W:Write>(key: &key::KeyPair, pass: &[u8], rounds: u32, mut w: W) -> Result<(), Error> {
    let x = self::pkcs8::encode_pkcs8_encrypted(pass, rounds, key)?;
    w.write_all(b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n")?;
    w.write_all(encode_config(&x, MIME).as_bytes())?;
    w.write_all(b"\n-----END ENCRYPTED PRIVATE KEY-----\n")?;
    Ok(())
}


fn decode_rsa(secret: &[u8]) -> Result<key::KeyPair, Error> {
    Ok(key::KeyPair::RSA {
        key: Rsa::private_key_from_der(secret)?,
        hash: key::SignatureHash::SHA2_256
    })
}

fn pkcs_unpad(dec: &mut Vec<u8>) {
    let len = dec.len();
    if len > 0 {
        let padding_len = dec[len-1];
        if dec[(len - padding_len as usize)..].iter().all(|&x| x == padding_len) {
            dec.truncate(len - padding_len as usize)
        }
    }
}
