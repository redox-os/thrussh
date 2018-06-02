use super::*;
use negotiation::Select;
use msg;
use cipher::CipherPair;
use negotiation;
use key::PubKey;
use thrussh_keys::encoding::{Encoding, Reader};

use kex;

impl KexInit {
    pub fn server_parse(
        mut self,
        config: &Config,
        cipher: &CipherPair,
        buf: &[u8],
        write_buffer: &mut SSHBuffer,
    ) -> Result<Kex, Error> {

        if buf[0] == msg::KEXINIT {
            debug!("server parse");
            let algo = if self.algo.is_none() {
                // read algorithms from packet.
                self.exchange.client_kex_init.extend(buf);
                super::negotiation::Server::read_kex(buf, &config.preferred)?
            } else {
                return Err(Error::Kex);
            };
            if !self.sent {
                self.server_write(config, cipher, write_buffer)?
            }
            let mut key = 0;
            debug!("config {:?} algo {:?}", config.keys, algo.key);
            while key < config.keys.len() && config.keys[key].name() != algo.key.as_ref() {
                key += 1
            }
            let next_kex = if key < config.keys.len() {
                Kex::KexDh(KexDh {
                    exchange: self.exchange,
                    key: key,
                    names: algo,
                    session_id: self.session_id,
                })
            } else {
                return Err(Error::UnknownKey);
            };

            Ok(next_kex)
        } else {
            Ok(Kex::KexInit(self))
        }
    }

    pub fn server_write(
        &mut self,
        config: &Config,
        cipher: &CipherPair,
        write_buffer: &mut SSHBuffer,
    ) -> Result<(), Error> {
        self.exchange.server_kex_init.clear();
        negotiation::write_kex(&config.preferred, &mut self.exchange.server_kex_init)?;
        self.sent = true;
        cipher.write(&self.exchange.server_kex_init, write_buffer);
        Ok(())
    }
}

impl KexDh {
    pub fn parse(
        mut self,
        config: &Config,
        buffer: &mut CryptoVec,
        buffer2: &mut CryptoVec,
        cipher: &CipherPair,
        buf: &[u8],
        write_buffer: &mut SSHBuffer,
    ) -> Result<Kex, Error> {
        debug!("KexDh: parse {:?}", self.names.ignore_guessed);
        if self.names.ignore_guessed {
            // If we need to ignore this packet.
            self.names.ignore_guessed = false;
            Ok(Kex::KexDh(self))
        } else {
            // Else, process it.
            debug!("buf = {:?}", buf);
            assert!(buf[0] == msg::KEX_ECDH_INIT);
            let mut r = buf.reader(1);
            self.exchange.client_ephemeral.extend(r.read_string()?);
            let kex = try!(kex::Algorithm::server_dh(
                self.names.kex,
                &mut self.exchange,
                buf,
            ));
            // Then, we fill the write buffer right away, so that we
            // can output it immediately when the time comes.
            let kexdhdone = KexDhDone {
                exchange: self.exchange,
                kex: kex,
                key: self.key,
                names: self.names,
                session_id: self.session_id,
            };

            let hash = try!(kexdhdone.kex.compute_exchange_hash(
                &config.keys[kexdhdone.key],
                &kexdhdone.exchange,
                buffer,
            ));
            debug!("exchange hash: {:?}", hash);
            buffer.clear();
            buffer.push(msg::KEX_ECDH_REPLY);
            config.keys[kexdhdone.key].push_to(buffer);
            // Server ephemeral
            buffer.extend_ssh_string(&kexdhdone.exchange.server_ephemeral);
            // Hash signature
            debug!(" >>>>>>>>>>>>>>> signing with key {:?}", kexdhdone.key);
            debug!("hash: {:?}", hash);
            debug!("key: {:?}", config.keys[kexdhdone.key]);
            config.keys[kexdhdone.key].add_signature(buffer, &hash)?;
            cipher.write(&buffer, write_buffer);

            cipher.write(&[msg::NEWKEYS], write_buffer);

            Ok(Kex::NewKeys(
                try!(kexdhdone.compute_keys(hash, buffer, buffer2, true)),
            ))
        }
    }
}
