use {Error, ErrorKind, KEYTYPE_ED25519};
use encoding::Reader;
use key;
use cryptovec::CryptoVec;
use openssl::symm::{Cipher, Mode, Crypter};
use bcrypt_pbkdf;

/// Decode a secret key given in the OpenSSH format, deciphering it if
/// needed using the supplied password.
pub fn decode_openssh(
    secret: &[u8],
    password: Option<&[u8]>,
) -> Result<key::KeyPair, Error> {
    if &secret[0..15] == b"openssh-key-v1\0" {
        let mut position = secret.reader(15);

        let ciphername = position.read_string()?;
        let kdfname = position.read_string()?;
        let kdfoptions = position.read_string()?;

        let nkeys = position.read_u32()?;
        let secret_ = position.read_string()?;
        let secret = decrypt_secret_key(
            ciphername,
            kdfname,
            kdfoptions,
            password,
            secret_,
        )?;
        let mut position = secret.reader(0);
        let _check0 = position.read_u32()?;
        let _check1 = position.read_u32()?;
        for _ in 0..nkeys {

            let key_type = position.read_string()?;
            let pubkey = position.read_string()?;
            let seckey = position.read_string()?;
            let _comment = position.read_string()?;

            if key_type == KEYTYPE_ED25519 {
                assert_eq!(pubkey, &seckey[32..]);
                use key::ed25519::*;
                let mut secret = SecretKey::new_zeroed();
                secret.key.clone_from_slice(seckey);
                return Ok(key::KeyPair::Ed25519(secret))
            } else {
                return Err(ErrorKind::UnsupportedKeyType(key_type.to_vec()).into())
            }
        }
        Err(ErrorKind::CouldNotReadKey.into())

    } else {
        Err(ErrorKind::CouldNotReadKey.into())
    }
}


fn decrypt_secret_key(
    ciphername: &[u8],
    kdfname: &[u8],
    kdfoptions: &[u8],
    password: Option<&[u8]>,
    secret_key: &[u8],
) -> Result<Vec<u8>, Error> {

    if kdfname == b"none" {
        if password.is_none() {
            Ok(secret_key.to_vec())
        } else {
            Err(ErrorKind::CouldNotReadKey.into())
        }
    } else if let Some(password) = password {
        let mut key = CryptoVec::new();
        let cipher = match ciphername {
            b"aes128-cbc" => { key.resize(16 + 16); Cipher::aes_128_cbc() },
            b"aes128-ctr" => { key.resize(16 + 16); Cipher::aes_128_ctr()},
            b"aes256-cbc" => { key.resize(16 + 32); Cipher::aes_256_cbc()},
            b"aes256-ctr" => { key.resize(16 + 32); Cipher::aes_256_ctr()},
            _ => return Err(ErrorKind::CouldNotReadKey.into()),
        };

        match kdfname {
            b"bcrypt" => {
                let mut kdfopts = kdfoptions.reader(0);
                let salt = kdfopts.read_string()?;
                let rounds = kdfopts.read_u32()?;
                bcrypt_pbkdf::bcrypt_pbkdf(password, salt, rounds, &mut key);
            }
            _kdfname => {
                return Err(ErrorKind::CouldNotReadKey.into());
            }
        };
        let iv = &key[32..];
        let key = &key[..32];
        let mut c = Crypter::new(
            cipher,
            Mode::Decrypt,
            &key,
            Some(&iv)
        )?;
        c.pad(false);
        let mut dec = vec![0; secret_key.len() + 32];
        let n = c.update(&secret_key, &mut dec)?;
        let n = n + c.finalize(&mut dec[n..])?;
        dec.truncate(n);
        Ok(dec)
    } else {
        Err(ErrorKind::KeyIsEncrypted.into())
    }
}
