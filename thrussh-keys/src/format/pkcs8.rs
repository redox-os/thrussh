use {Error, ErrorKind};
use std;
use key;
use super::{Encryption, pkcs_unpad};
use yasna;
use yasna::BERReaderSeq;
use openssl::symm::{encrypt, decrypt, Cipher};
use openssl::hash::MessageDigest;
use openssl::rand::rand_bytes;
use bit_vec::BitVec;
use std::borrow::Cow;
use key::SignatureHash;
use openssl::pkey::Private;

const PBES2: &'static [u64] = &[1, 2, 840, 113549, 1, 5, 13];
const PBKDF2: &'static [u64] = &[1, 2, 840, 113549, 1, 5, 12];
const HMAC_SHA256: &'static [u64] = &[1, 2, 840, 113549, 2, 9];
const AES256CBC: &'static [u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 42];
const ED25519: &'static [u64] = &[1, 3, 101, 112];
const RSA: &'static [u64] = &[1, 2, 840, 113549, 1, 1, 1];

/// Decode a PKCS#8-encoded private key.
pub fn decode_pkcs8(
    ciphertext: &[u8],
    password: Option<&[u8]>,
) -> Result<key::KeyPair, Error> {
    let secret = if let Some(pass) = password {
        // let mut sec = Vec::new();
        Cow::Owned(yasna::parse_der(&ciphertext, |reader| {
            reader.read_sequence(|reader| {
                // Encryption parameters
                let parameters = reader.next().read_sequence(|reader| {
                    let oid = reader.next().read_oid()?;
                    if oid.components().as_slice() == PBES2 {
                        asn1_read_pbes2(reader)
                    } else {
                        Ok(Err(ErrorKind::UnknownAlgorithm(oid).into()))
                    }
                })?;
                // Ciphertext
                let ciphertext = reader.next().read_bytes()?;
                Ok(parameters.map(|p| p.decrypt(pass, &ciphertext)))
            })
        })???)
    } else {
        Cow::Borrowed(ciphertext)
    };
    yasna::parse_der(&secret, |reader| {
        reader.read_sequence(|reader| {
            let version = reader.next().read_u64()?;
            if version == 0 {
                Ok(read_key_v0(reader))
            } else if version == 1 {
                Ok(read_key_v1(reader))
            } else {
                Ok(Err(ErrorKind::CouldNotReadKey.into()))
            }
        })
    })?
}


fn asn1_read_pbes2(
    reader: &mut yasna::BERReaderSeq,
) -> Result<Result<Algorithms, Error>, yasna::ASN1Error> {
    reader.next().read_sequence(|reader| {
        // PBES2 has two components.
        // 1. Key generation algorithm
        let keygen = reader.next().read_sequence(|reader| {
            let oid = reader.next().read_oid()?;
            if oid.components().as_slice() == PBKDF2 {
                asn1_read_pbkdf2(reader)
            } else {
                Ok(Err(ErrorKind::UnknownAlgorithm(oid).into()))
            }
        })?;
        // 2. Encryption algorithm.
        let algorithm = reader.next().read_sequence(|reader| {
            let oid = reader.next().read_oid()?;
            if oid.components().as_slice() == AES256CBC {
                asn1_read_aes256cbc(reader)
            } else {
                Ok(Err(ErrorKind::UnknownAlgorithm(oid).into()))
            }
        })?;
        Ok(keygen.and_then(|keygen| {
            algorithm.map(|algo| Algorithms::Pbes2(keygen, algo))
        }))
    })
}

fn asn1_read_pbkdf2(
    reader: &mut yasna::BERReaderSeq,
) -> Result<Result<KeyDerivation, Error>, yasna::ASN1Error> {
    reader.next().read_sequence(|reader| {
        let salt = reader.next().read_bytes()?;
        let rounds = reader.next().read_u64()?;
        let digest = reader.next().read_sequence(|reader| {
            let oid = reader.next().read_oid()?;
            if oid.components().as_slice() == HMAC_SHA256 {
                reader.next().read_null()?;
                Ok(Ok(MessageDigest::sha256()))
            } else {
                Ok(Err(ErrorKind::UnknownAlgorithm(oid).into()))
            }
        })?;
        Ok(digest.map(|digest| {
            KeyDerivation::Pbkdf2 {
                salt,
                rounds,
                digest,
            }
        }))
    })
}

fn asn1_read_aes256cbc(
    reader: &mut yasna::BERReaderSeq,
) -> Result<Result<Encryption, Error>, yasna::ASN1Error> {
    let iv = reader.next().read_bytes()?;
    let mut i = [0; 16];
    i.clone_from_slice(&iv);
    Ok(Ok(Encryption::Aes256Cbc(i)))
}

fn write_key_v1(writer: &mut yasna::DERWriterSeq,
                secret: &key::ed25519::SecretKey) {

    writer.next().write_u32(1);
    // write OID
    writer.next().write_sequence(|writer| {
        writer.next().write_oid(&ObjectIdentifier::from_slice(ED25519));
    });
    let seed = yasna::construct_der(|writer| writer.write_bytes(&secret.key));
    writer.next().write_bytes(&seed);
    writer.next().write_tagged(yasna::Tag::context(1), |writer| {
        let public = &secret.key[32..];
        writer.write_bitvec(&BitVec::from_bytes(&public))
    })
}

fn read_key_v1(reader: &mut BERReaderSeq) -> Result<key::KeyPair, Error> {
    let oid = reader.next().read_sequence(|reader| {
        reader.next().read_oid()
    })?;
    if oid.components().as_slice() == ED25519 {
        use key::ed25519::{PublicKey, SecretKey};
        let secret = {
            let mut seed = SecretKey::new_zeroed();
            let s = yasna::parse_der(&reader.next().read_bytes()?, |reader| {
                reader.read_bytes()
            })?;
            clone(&s, &mut seed.key);
            seed
        };
        let _public = {
            let public = reader.next().read_tagged(yasna::Tag::context(1), |reader| {
                reader.read_bitvec()
            })?.to_bytes();
            let mut p = PublicKey::new_zeroed();
            clone(&public, &mut p.key);
            p
        };
        Ok(key::KeyPair::Ed25519(secret))
    } else {
        Err(ErrorKind::CouldNotReadKey.into())
    }
}

use openssl::rsa::Rsa;
fn write_key_v0(writer: &mut yasna::DERWriterSeq, key: &Rsa<Private>) {
    writer.next().write_u32(0);
    // write OID
    writer.next().write_sequence(|writer| {
        writer.next().write_oid(&ObjectIdentifier::from_slice(RSA));
        writer.next().write_null()
    });
    let bytes = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_u32(0);
            use num_bigint::BigUint;
            writer.next().write_biguint(&BigUint::from_bytes_be(&key.n().to_vec()));
            writer.next().write_biguint(&BigUint::from_bytes_be(&key.e().to_vec()));
            writer.next().write_biguint(&BigUint::from_bytes_be(&key.d().to_vec()));
            writer.next().write_biguint(&BigUint::from_bytes_be(&key.p().unwrap().to_vec()));
            writer.next().write_biguint(&BigUint::from_bytes_be(&key.q().unwrap().to_vec()));
            writer.next().write_biguint(&BigUint::from_bytes_be(&key.dmp1().unwrap().to_vec()));
            writer.next().write_biguint(&BigUint::from_bytes_be(&key.dmq1().unwrap().to_vec()));
            writer.next().write_biguint(&BigUint::from_bytes_be(&key.iqmp().unwrap().to_vec()));
        })
    });
    writer.next().write_bytes(&bytes);
}

fn read_key_v0(reader: &mut BERReaderSeq) -> Result<key::KeyPair, Error> {
    let oid = reader.next().read_sequence(|reader| {
        let oid = reader.next().read_oid()?;
        reader.next().read_null()?;
        Ok(oid)
    })?;
    if oid.components().as_slice() == RSA {
        let seq = &reader.next().read_bytes()?;
        let rsa: Result<Rsa<Private>, Error> = yasna::parse_der(seq, |reader| {
            reader.read_sequence(|reader| {
                let version = reader.next().read_u32()?;
                if version != 0 {
                    return Ok(Err(ErrorKind::CouldNotReadKey.into()))
                }
                use openssl::bn::BigNum;
                use openssl::rsa::Rsa;
                let mut read_key = || -> Result<Rsa<Private>, Error> {
                    Ok(Rsa::from_private_components (
                        BigNum::from_slice(&reader.next().read_biguint()?.to_bytes_be())?,
                        BigNum::from_slice(&reader.next().read_biguint()?.to_bytes_be())?,
                        BigNum::from_slice(&reader.next().read_biguint()?.to_bytes_be())?,
                        BigNum::from_slice(&reader.next().read_biguint()?.to_bytes_be())?,
                        BigNum::from_slice(&reader.next().read_biguint()?.to_bytes_be())?,
                        BigNum::from_slice(&reader.next().read_biguint()?.to_bytes_be())?,
                        BigNum::from_slice(&reader.next().read_biguint()?.to_bytes_be())?,
                        BigNum::from_slice(&reader.next().read_biguint()?.to_bytes_be())?,
                    )?)
                };
                Ok(read_key())
            })
        })?;
        Ok(key::KeyPair::RSA { key: rsa?, hash: SignatureHash::SHA2_256 })
    } else {
        Err(ErrorKind::CouldNotReadKey.into())
    }
}

#[test]
fn test_read_write_pkcs8() {
    let (public, secret) = key::ed25519::keypair();
    assert_eq!(&public.key, &secret.key[32..]);
    let key = key::KeyPair::Ed25519(secret);
    let password = b"blabla";
    let ciphertext = encode_pkcs8_encrypted(password, 100, &key).unwrap();
    let key = decode_pkcs8(&ciphertext, Some(password)).unwrap();
    match key {
        key::KeyPair::Ed25519 { .. } => println!("Ed25519"),
        key::KeyPair::RSA { .. } => println!("RSA"),
    }
}


use yasna::models::ObjectIdentifier;
use openssl::pkcs5::pbkdf2_hmac;
/// Encode a password-protected PKCS#8-encoded private key.
pub fn encode_pkcs8_encrypted(
    pass: &[u8],
    rounds: u32,
    key: &key::KeyPair,
) -> Result<Vec<u8>, Error> {

    let mut salt = [0; 64];
    rand_bytes(&mut salt)?;
    let mut iv = [0; 16];
    rand_bytes(&mut iv)?;
    let mut dkey = [0; 32]; // AES256-CBC
    pbkdf2_hmac(pass, &salt, rounds as usize, MessageDigest::sha256(), &mut dkey)?;

    let mut plaintext = encode_pkcs8(key);

    let padding_len = 32 - (plaintext.len() % 32);
    plaintext.extend(std::iter::repeat(padding_len as u8).take(padding_len));


    let ciphertext = encrypt(Cipher::aes_256_cbc(), &dkey, Some(&iv), &plaintext)?;

    Ok(yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            // Encryption parameters
            writer.next().write_sequence(|writer| {
                writer.next().write_oid(&ObjectIdentifier::from_slice(PBES2));
                asn1_write_pbes2(writer.next(), rounds as u64, &salt, &iv)
            });
            // Ciphertext
            writer.next().write_bytes(&ciphertext[..])
        })
    }))
}

/// Encode a Decode a PKCS#8-encoded private key.
pub fn encode_pkcs8(key: &key::KeyPair) -> Vec<u8> {
    yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            match *key {
                key::KeyPair::Ed25519(ref secret) => write_key_v1(writer, secret),
                key::KeyPair::RSA { ref key, .. } => write_key_v0(writer, key),
            }
        })
    })
}

fn clone(src: &[u8], dest: &mut [u8]) {
    let i = src.iter().take_while(|b| **b == 0).count();
    let src = &src[i..];
    let l = dest.len();
    (&mut dest[l - src.len()..]).clone_from_slice(src)
}



fn asn1_write_pbes2(writer: yasna::DERWriter, rounds: u64, salt: &[u8], iv: &[u8]) {
    writer.write_sequence(|writer| {
        // 1. Key generation algorithm
        writer.next().write_sequence(|writer| {
            writer.next().write_oid(&ObjectIdentifier::from_slice(PBKDF2));
            asn1_write_pbkdf2(writer.next(), rounds, salt)
        });
        // 2. Encryption algorithm.
        writer.next().write_sequence(|writer| {
            writer.next().write_oid(&ObjectIdentifier::from_slice(AES256CBC));
            writer.next().write_bytes(iv)
        });
    })
}

fn asn1_write_pbkdf2(writer: yasna::DERWriter, rounds: u64, salt: &[u8]) {
    writer.write_sequence(|writer| {
        writer.next().write_bytes(salt);
        writer.next().write_u64(rounds);
        writer.next().write_sequence(|writer| {
            writer.next().write_oid(&ObjectIdentifier::from_slice(HMAC_SHA256));
            writer.next().write_null()
        })
    })
}






enum Algorithms {
    Pbes2(KeyDerivation, Encryption),
}

impl Algorithms {
    fn decrypt(&self, password: &[u8], cipher: &[u8]) -> Result<Vec<u8>, Error> {
        match *self {
            Algorithms::Pbes2(ref der, ref enc) => {
                let mut key = enc.key();
                der.derive(password, &mut key)?;
                let out = enc.decrypt(&key, cipher)?;
                Ok(out)
            }
        }
    }
}

impl KeyDerivation {
    fn derive(&self, password: &[u8], key: &mut [u8]) -> Result<(), Error> {
        match *self {
            KeyDerivation::Pbkdf2 {
                ref salt,
                rounds,
                digest,
            } => pbkdf2_hmac(password, salt, rounds as usize, digest, key)?,
        }
        Ok(())
    }
}

enum Key {
    K128([u8; 16]),
    K256([u8; 32]),
}

impl std::ops::Deref for Key {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match *self {
            Key::K128(ref k) => k,
            Key::K256(ref k) => k,
        }
    }
}

impl std::ops::DerefMut for Key {
    fn deref_mut(&mut self) -> &mut [u8] {
        match *self {
            Key::K128(ref mut k) => k,
            Key::K256(ref mut k) => k,
        }
    }
}

impl Encryption {
    fn key(&self) -> Key {
        match *self {
            Encryption::Aes128Cbc(_) => Key::K128([0; 16]),
            Encryption::Aes256Cbc(_) => Key::K256([0; 32]),
        }
    }

    fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let (cipher, iv) = match *self {
            Encryption::Aes128Cbc(ref iv) => (Cipher::aes_128_cbc(), iv),
            Encryption::Aes256Cbc(ref iv) => (Cipher::aes_256_cbc(), iv),
        };
        let mut dec = decrypt(
            cipher,
            &key,
            Some(&iv[..]),
            ciphertext
        )?;
        pkcs_unpad(&mut dec);
        Ok(dec)
    }
}

enum KeyDerivation {
    Pbkdf2 {
        salt: Vec<u8>,
        rounds: u64,
        digest: MessageDigest,
    },
}
