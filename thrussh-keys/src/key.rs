// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
use cryptovec::CryptoVec;
use {Error, ErrorKind};
use encoding::{Encoding, Reader};
use std;
use openssl;
use sodium;
use encoding;
pub use signature::*;
use openssl::pkey::{Public, Private};

/// Keys for elliptic curve Ed25519 cryptography.
pub mod ed25519 {
    pub use sodium::ed25519::{PublicKey, SecretKey, keypair, verify_detached, sign_detached};
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
/// Name of a public key algorithm.
pub struct Name(pub &'static str);

impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0
    }
}

/// The name of the Ed25519 algorithm for SSH.
pub const ED25519: Name = Name("ssh-ed25519");
/// The name of the ssh-sha2-512 algorithm for SSH.
pub const RSA_SHA2_512: Name = Name("rsa-sha2-512");
/// The name of the ssh-sha2-256 algorithm for SSH.
pub const RSA_SHA2_256: Name = Name("rsa-sha2-256");

pub const SSH_RSA: &'static str = "ssh-rsa";

impl Name {
    /// Base name of the private key file for a key name.
    pub fn identity_file(&self) -> &'static str {
        match *self {
            ED25519 => "id_ed25519",
            RSA_SHA2_512 => "id_rsa",
            RSA_SHA2_256 => "id_rsa",
            _ => unreachable!(),
        }
    }
}

#[doc(hidden)]
pub trait Verify {
    fn verify_client_auth(&self, buffer: &[u8], sig: &[u8]) -> bool;
    fn verify_server_auth(&self, buffer: &[u8], sig: &[u8]) -> bool;
}

/// The hash function used for hashing buffers.
#[derive(Eq, PartialEq, Clone, Copy, Debug, Hash, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum SignatureHash {
    /// SHA2, 256 bits.
    SHA2_256,
    /// SHA2, 512 bits.
    SHA2_512,
}

impl SignatureHash {
    pub fn name(&self) -> Name {
        match *self {
            SignatureHash::SHA2_256 => RSA_SHA2_256,
            SignatureHash::SHA2_512 => RSA_SHA2_512,
        }
    }

    fn to_message_digest(&self) -> openssl::hash::MessageDigest {
        use openssl::hash::MessageDigest;
        match *self {
            SignatureHash::SHA2_256 => MessageDigest::sha256(),
            SignatureHash::SHA2_512 => MessageDigest::sha512(),
        }
    }
}

/// Public key
#[derive(Eq, PartialEq, Debug)]
pub enum PublicKey {
    #[doc(hidden)]
    Ed25519(sodium::ed25519::PublicKey),
    #[doc(hidden)]
    RSA {
        key: OpenSSLPKey,
        hash: SignatureHash,
    },
}

/// A public key from OpenSSL.
pub struct OpenSSLPKey(pub openssl::pkey::PKey<Public>);

use std::cmp::{Eq, PartialEq};
impl PartialEq for OpenSSLPKey {
    fn eq(&self, b: &OpenSSLPKey) -> bool {
        self.0.public_eq(&b.0)
    }
}
impl Eq for OpenSSLPKey {}
impl std::fmt::Debug for OpenSSLPKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "OpenSSLPKey {{ (hidden) }}")
    }
}

impl PublicKey {
    /// Parse a public key in SSH format.
    pub fn parse(algo: &[u8], pubkey: &[u8]) -> Result<Self, Error> {
        match algo {
            b"ssh-ed25519" => {
                let mut p = pubkey.reader(0);
                let key_algo = p.read_string()?;
                let key_bytes = p.read_string()?;
                if key_algo != b"ssh-ed25519" || key_bytes.len() != sodium::ed25519::PUBLICKEY_BYTES {
                    return Err(ErrorKind::CouldNotReadKey.into());
                }
                let mut p = sodium::ed25519::PublicKey {
                    key: [0; sodium::ed25519::PUBLICKEY_BYTES],
                    sodium: sodium::Sodium::new()
                };
                p.key.clone_from_slice(key_bytes);
                Ok(PublicKey::Ed25519(p))
            }
            b"rsa-sha2-256" | b"rsa-sha2-512" => {
                let mut p = pubkey.reader(0);
                let key_algo = p.read_string()?;
                if key_algo != b"rsa-sha2-256" && key_algo != b"rsa-sha2-512" {
                    return Err(ErrorKind::CouldNotReadKey.into());
                }
                let key_e = p.read_string()?;
                let key_n = p.read_string()?;
                use openssl::rsa::Rsa;
                use openssl::pkey::PKey;
                use openssl::bn::BigNum;
                Ok(PublicKey::RSA {
                    key: OpenSSLPKey(PKey::from_rsa(Rsa::from_public_components(
                        BigNum::from_slice(key_n)?,
                        BigNum::from_slice(key_e)?,
                    )?)?),
                    hash: {
                        if algo == b"rsa-sha2-256" {
                            SignatureHash::SHA2_256
                        } else {
                            SignatureHash::SHA2_512
                        }
                    },
                })
            }
            _ => Err(ErrorKind::CouldNotReadKey.into()),
        }
    }
}

impl PublicKey {

    /// Algorithm name for that key.
    pub fn name(&self) -> &'static str {
        match *self {
            PublicKey::Ed25519(_) => ED25519.0,
            PublicKey::RSA { ref hash, .. } => hash.name().0
        }
    }

    /// Verify a signature.
    pub fn verify_detached(&self, buffer: &[u8], sig: &[u8]) -> bool {
        match self {
            &PublicKey::Ed25519(ref public) => {
                sodium::ed25519::verify_detached(&sig, buffer, &public)
            }
            &PublicKey::RSA {
                ref key,
                ref hash,
            } => {
                use openssl::sign::*;
                let verify = || {
                    let mut verifier = Verifier::new(
                        hash.to_message_digest(),
                        &key.0,
                    )?;
                    verifier.update(buffer)?;
                    verifier.verify(&sig)
                };
                verify().unwrap_or(false)
            }
        }
    }

}


impl Verify for PublicKey {
    fn verify_client_auth(&self, buffer: &[u8], sig: &[u8]) -> bool {
        self.verify_detached(buffer, sig)
    }
    fn verify_server_auth(&self, buffer: &[u8], sig: &[u8]) -> bool {
        self.verify_detached(buffer, sig)
    }
}

/// Public key exchange algorithms.
pub enum KeyPair {
    Ed25519(sodium::ed25519::SecretKey),
    RSA {
        key: openssl::rsa::Rsa<Private>,
        hash: SignatureHash,
    },
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            KeyPair::Ed25519(ref key) => {
                write!(f, "Ed25519 {{ public: {:?}, secret: (hidden) }}", &key.key[32..])
            }
            KeyPair::RSA { .. } => {
                write!(f, "RSA {{ (hidden) }}")
            }
        }
    }
}

impl<'b> encoding::Bytes for &'b KeyPair {
    fn bytes(&self) -> &[u8] {
        self.name().as_bytes()
    }
}


impl KeyPair {
    /*
    pub fn public_components(&self) -> PublicKeyComponents {
        match self {
            &KeyPair::Ed25519(ref key) => {
                let mut public = [0; 32];
                public.clone_from_slice(&key.key[32..]);
                PublicKeyComponents::Ed25519(public)
            },
            &KeyPair::RSA { ref key, hash } => {
                let n = key.n().unwrap().to_vec();
                let e = key.e().unwrap().to_vec();
                PublicKeyComponents::RSA { n, e, hash }
            }
        }
    }
     */

    /// Copy the public key of this algorithm.
    pub fn clone_public_key(&self) -> PublicKey {
        match self {
            &KeyPair::Ed25519(ref key) => {
                let mut public = sodium::ed25519::PublicKey {
                    key: [0; 32],
                    sodium: sodium::Sodium::new(),
                };
                public.key.clone_from_slice(&key.key[32..]);
                PublicKey::Ed25519(public)
            },
            &KeyPair::RSA { ref key, ref hash } => {
                use openssl::pkey::PKey;
                use openssl::rsa::Rsa;
                let key = Rsa::from_public_components(
                    key.n().to_owned().unwrap(),
                    key.e().to_owned().unwrap()
                ).unwrap();
                PublicKey::RSA {
                    key: OpenSSLPKey(PKey::from_rsa(key).unwrap()),
                    hash: hash.clone()
                }
            }
        }
    }

    /// Name of this key algorithm.
    pub fn name(&self) -> &'static str {
        match *self {
            KeyPair::Ed25519(_) => ED25519.0,
            KeyPair::RSA { ref hash, .. } => hash.name().0,
        }
    }

    /// Generate a key pair.
    pub fn generate(t: Name) -> Option<Self> {
        match t {
            ED25519 => {
                let (public, secret) = sodium::ed25519::keypair();
                assert_eq!(&public.key, &secret.key[32..]);
                Some(KeyPair::Ed25519(secret))
            }
            _ => None,
        }
    }

    /// Sign a slice using this algorithm.
    pub fn sign_detached(&self, to_sign: &[u8]) -> Result<Signature, Error> {
        match self {
            &KeyPair::Ed25519(ref secret) => Ok(Signature::Ed25519(SignatureBytes(sodium::ed25519::sign_detached(to_sign.as_ref(), secret).0))),
            &KeyPair::RSA { ref key, ref hash } => Ok(Signature::RSA(rsa_signature(hash, key, to_sign.as_ref())?))
        }
    }

    #[doc(hidden)]
    /// This is used by the server to sign the initial DH kex
    /// message. Note: we are not signing the same kind of thing as in
    /// the function below, `add_self_signature`.
    pub fn add_signature<H: AsRef<[u8]>>(
        &self,
        buffer: &mut CryptoVec,
        to_sign: H,
    ) -> Result<(), Error> {
        match self {
            &KeyPair::Ed25519(ref secret) => {
                let signature = sodium::ed25519::sign_detached(to_sign.as_ref(), secret);

                buffer.push_u32_be((ED25519.0.len() + signature.0.len() + 8) as u32);
                buffer.extend_ssh_string(ED25519.0.as_bytes());
                buffer.extend_ssh_string(&signature.0);
            }
            &KeyPair::RSA { ref key, ref hash } => {
                // https://tools.ietf.org/html/draft-rsa-dsa-sha2-256-02#section-2.2
                let signature = rsa_signature(hash, key, to_sign.as_ref())?;
                let name = hash.name();
                buffer.push_u32_be((name.0.len() + signature.len() + 8) as u32);
                buffer.extend_ssh_string(name.0.as_bytes());
                buffer.extend_ssh_string(&signature);
            }
        }
        Ok(())
    }

    #[doc(hidden)]
    /// This is used by the client for authentication. Note: we are
    /// not signing the same kind of thing as in the above function,
    /// `add_signature`.
    pub fn add_self_signature(&self, buffer: &mut CryptoVec) -> Result<(), Error> {
        match self {
            &KeyPair::Ed25519(ref secret) => {
                let signature = sodium::ed25519::sign_detached(&buffer, secret);

                buffer.push_u32_be((ED25519.0.len() + signature.0.len() + 8) as u32);
                buffer.extend_ssh_string(ED25519.0.as_bytes());
                buffer.extend_ssh_string(&signature.0);
            }
            &KeyPair::RSA { ref key, ref hash } => {

                // https://tools.ietf.org/html/draft-rsa-dsa-sha2-256-02#section-2.2
                let signature = rsa_signature(hash, key, buffer)?;
                let name = hash.name();
                buffer.push_u32_be((name.0.len() + signature.len() + 8) as u32);
                buffer.extend_ssh_string(name.0.as_bytes());
                buffer.extend_ssh_string(&signature);
            }
        }
        Ok(())
    }
}

fn rsa_signature(hash: &SignatureHash, key: &openssl::rsa::Rsa<Private>, b: &[u8]) -> Result<Vec<u8>, Error> {
    use openssl::sign::Signer;
    use openssl::pkey::*;
    use openssl::rsa::*;
    let pkey = PKey::from_rsa(Rsa::from_private_components(
        key.n().to_owned()?,
        key.e().to_owned()?,
        key.d().to_owned()?,
        key.p().unwrap().to_owned()?,
        key.q().unwrap().to_owned()?,
        key.dmp1().unwrap().to_owned()?,
        key.dmq1().unwrap().to_owned()?,
        key.iqmp().unwrap().to_owned()?,
    )?)?;
    let mut signer = Signer::new(hash.to_message_digest(), &pkey)?;
    signer.update(b)?;
    Ok(signer.sign_to_vec()?)
}

/// Parse a public key from a byte slice.
pub fn parse_public_key(p: &[u8]) -> Result<PublicKey, Error> {
    let mut pos = p.reader(0);
    let t = pos.read_string()?;
    if t == b"ssh-ed25519" {
        if let Ok(pubkey) = pos.read_string() {
            use sodium::ed25519;
            let mut p = ed25519::PublicKey {
                key: [0; ed25519::PUBLICKEY_BYTES],
                sodium: sodium::Sodium::new(),
            };
            p.key.clone_from_slice(pubkey);
            return Ok(PublicKey::Ed25519(p));
        }
    }
    if t == b"ssh-rsa" {
        let e = pos.read_string()?;
        let n = pos.read_string()?;
        use openssl::pkey::*;
        use openssl::rsa::*;
        use openssl::bn::*;
        return Ok(PublicKey::RSA {
            key: OpenSSLPKey(PKey::from_rsa(Rsa::from_public_components(
                BigNum::from_slice(n)?,
                BigNum::from_slice(e)?,
            )?)?),
            hash: SignatureHash::SHA2_256,
        });
    }
    Err(ErrorKind::CouldNotReadKey.into())
}
