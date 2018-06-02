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
use byteorder::{ByteOrder, BigEndian};
use std;
use Error;
use msg;

use cryptovec::CryptoVec;
use session::Exchange;
use key;
use cipher;
use thrussh_keys::encoding::Encoding;
use openssl;
use sodium;

#[doc(hidden)]
pub struct Algorithm {
    local_secret: Option<sodium::scalarmult::Scalar>,
    shared_secret: Option<sodium::scalarmult::GroupElement>,
}

impl std::fmt::Debug for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Algorithm {{ local_secret: [hidden], shared_secret: [hidden] }}",
        )
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Name(&'static str);
impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0
    }
}
pub const CURVE25519: Name = Name("curve25519-sha256@libssh.org");

// We used to support curve "NIST P-256" here, but the security of
// that curve is controversial, see
// http://safecurves.cr.yp.to/rigid.html

impl Algorithm {
    #[doc(hidden)]
    pub fn server_dh(
        _name: Name,
        exchange: &mut Exchange,
        payload: &[u8],
    ) -> Result<Algorithm, Error> {
        debug!("server_dh");

        assert_eq!(payload[0], msg::KEX_ECDH_INIT);
        let mut client_pubkey = GroupElement([0; 32]);
        {
            let pubkey_len = BigEndian::read_u32(&payload[1..]) as usize;
            client_pubkey.0.clone_from_slice(
                &payload[5..(5 + pubkey_len)],
            )
        };
        debug!("client_pubkey: {:?}", client_pubkey);
        use sodium::scalarmult::*;
        use openssl::rand::*;
        let mut server_secret = Scalar([0; 32]);
        rand_bytes(&mut server_secret.0)?;
        let sodium = sodium::Sodium::new();
        let server_pubkey = sodium.scalarmult_base(&server_secret);

        // fill exchange.
        exchange.server_ephemeral.clear();
        exchange.server_ephemeral.extend(&server_pubkey.0);
        let shared = sodium.scalarmult(&server_secret, &client_pubkey);
        Ok(Algorithm {
            local_secret: None,
            shared_secret: Some(shared),
        })
    }

    #[doc(hidden)]
    pub fn client_dh(
        _name: Name,
        client_ephemeral: &mut CryptoVec,
        buf: &mut CryptoVec,
    ) -> Result<Algorithm, Error> {

        use sodium::scalarmult::*;
        use openssl::rand::*;
        let mut client_secret = Scalar([0; 32]);
        rand_bytes(&mut client_secret.0)?;
        let sodium = sodium::Sodium::new();
        let client_pubkey = sodium.scalarmult_base(&client_secret);

        // fill exchange.
        client_ephemeral.clear();
        client_ephemeral.extend(&client_pubkey.0);

        buf.push(msg::KEX_ECDH_INIT);
        buf.extend_ssh_string(&client_pubkey.0);


        Ok(Algorithm {
            local_secret: Some(client_secret),
            shared_secret: None,
        })
    }

    pub fn compute_shared_secret(&mut self, remote_pubkey_: &[u8]) -> Result<(), Error> {
        let local_secret = std::mem::replace(&mut self.local_secret, None).unwrap();

        use sodium::scalarmult::*;
        let mut remote_pubkey = GroupElement([0; 32]);
        remote_pubkey.0.clone_from_slice(remote_pubkey_);
        let sodium = sodium::Sodium::new();
        let shared = sodium.scalarmult(&local_secret, &remote_pubkey);
        self.shared_secret = Some(shared);
        Ok(())
    }

    pub fn compute_exchange_hash<K: key::PubKey>(
        &self,
        key: &K,
        exchange: &Exchange,
        buffer: &mut CryptoVec,
    ) -> Result<openssl::hash::DigestBytes, Error> {
        // Computing the exchange hash, see page 7 of RFC 5656.
        buffer.clear();
        buffer.extend_ssh_string(&exchange.client_id);
        buffer.extend_ssh_string(&exchange.server_id);
        buffer.extend_ssh_string(&exchange.client_kex_init);
        buffer.extend_ssh_string(&exchange.server_kex_init);


        key.push_to(buffer);
        buffer.extend_ssh_string(&exchange.client_ephemeral);
        buffer.extend_ssh_string(&exchange.server_ephemeral);

        if let Some(ref shared) = self.shared_secret {
            buffer.extend_ssh_mpint(&shared.0);
        }
        use openssl::hash::*;
        let hash = {
            let mut hasher = Hasher::new(MessageDigest::sha256())?;
            hasher.update(&buffer)?;
            hasher.finish()?
        };
        Ok(hash)
    }


    pub fn compute_keys(
        &self,
        session_id: &openssl::hash::DigestBytes,
        exchange_hash: &openssl::hash::DigestBytes,
        buffer: &mut CryptoVec,
        key: &mut CryptoVec,
        cipher: cipher::Name,
        is_server: bool,
    ) -> Result<super::cipher::CipherPair, Error> {
        let cipher = match cipher {
            super::cipher::chacha20poly1305::NAME => &super::cipher::chacha20poly1305::CIPHER,
            _ => unreachable!(),
        };

        // https://tools.ietf.org/html/rfc4253#section-7.2
        let mut compute_key = |c, key: &mut CryptoVec, len| -> Result<(), Error> {
            buffer.clear();
            key.clear();

            if let Some(ref shared) = self.shared_secret {
                buffer.extend_ssh_mpint(&shared.0);
            }

            buffer.extend(exchange_hash.as_ref());
            buffer.push(c);
            buffer.extend(session_id.as_ref());
            use openssl::hash::*;
            let hash = {
                let mut hasher = Hasher::new(MessageDigest::sha256())?;
                hasher.update(&buffer)?;
                hasher.finish()?
            };
            key.extend(hash.as_ref());

            while key.len() < len {
                // extend.
                buffer.clear();
                if let Some(ref shared) = self.shared_secret {
                    buffer.extend_ssh_mpint(&shared.0);
                }
                buffer.extend(exchange_hash.as_ref());
                buffer.extend(key);
                let hash = {
                    let mut hasher = Hasher::new(MessageDigest::sha256())?;
                    hasher.update(&buffer)?;
                    hasher.finish()?
                };
                key.extend(&hash.as_ref());
            }
            Ok(())
        };

        let (local_to_remote, remote_to_local) = if is_server {
            (b'D', b'C')
        } else {
            (b'C', b'D')
        };

        compute_key(local_to_remote, key, cipher.key_len)?;
        let local_to_remote = (cipher.make_sealing_cipher)(key);

        compute_key(remote_to_local, key, cipher.key_len)?;
        let remote_to_local = (cipher.make_opening_cipher)(key);

        Ok(super::cipher::CipherPair {
            local_to_remote: local_to_remote,
            remote_to_local: remote_to_local,
        })
    }
}
