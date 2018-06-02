use {Error, ErrorKind};
use std;
use key;
use super::{Encryption, pkcs_unpad, decode_rsa};

use openssl::symm::{decrypt, Cipher};
use openssl::hash::{MessageDigest, Hasher};

/// Decode a secret key in the PKCS#5 format, possible deciphering it
/// using the supplied password.
pub fn decode_pkcs5(
    secret: &[u8],
    password: Option<&[u8]>,
    enc: Encryption,
) -> Result<key::KeyPair, Error> {
    if let Some(pass) = password {
        let sec = match enc {
            Encryption::Aes128Cbc(ref iv) => {
                let mut h = Hasher::new(MessageDigest::md5()).unwrap();
                h.update(pass).unwrap();
                h.update(&iv[..8]).unwrap();
                let md5 = h.finish().unwrap();

                let mut secret = secret.to_vec();
                let len = 32 - (secret.len() % 32);
                secret.extend(std::iter::repeat(len as u8).take(len));
                let mut dec = decrypt(
                    Cipher::aes_128_cbc(),
                    &md5,
                    Some(&iv[..]),
                    &secret
                )?;
                pkcs_unpad(&mut dec);
                dec
            }
            Encryption::Aes256Cbc(_) => unimplemented!(),
        };
        decode_rsa(&sec)
    } else {
        Err(ErrorKind::KeyIsEncrypted.into())
    }
}

