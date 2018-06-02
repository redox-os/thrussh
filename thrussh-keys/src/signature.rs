use serde::{Serialize, Deserialize, Deserializer, Serializer};
use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeTuple;
use serde;
use std::fmt;
pub struct SignatureBytes(pub [u8;64]);


/// The type of a signature, depending on the algorithm used.
#[derive(Serialize, Deserialize)]
pub enum Signature {
    /// An Ed25519 signature
    Ed25519(SignatureBytes),
    /// An RSA signature
    RSA(Vec<u8>),
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        match *self {
            Signature::Ed25519(ref signature) => &signature.0,
            Signature::RSA(ref signature) => &signature
        }
    }
}

impl AsRef<[u8]> for SignatureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SignatureBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        struct Vis;
        impl<'de> Visitor<'de> for Vis {
            type Value = SignatureBytes;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("64 bytes")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut result = [0; 64];
                for x in result.iter_mut() {
                    if let Some(y) = seq.next_element()? {
                        *x = y
                    } else {
                        return Err(serde::de::Error::invalid_length(64, &self))
                    }
                }
                Ok(SignatureBytes(result))
            }
        }
        deserializer.deserialize_tuple(64, Vis)
    }
}

impl Serialize for SignatureBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        let mut tup = serializer.serialize_tuple(64)?;
        for byte in self.0.iter() {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }
}

impl fmt::Debug for SignatureBytes {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{:?}", &self.0[..])
    }
}

impl Clone for SignatureBytes {
    fn clone(&self) -> Self {
        let mut result = SignatureBytes([0;64]);
        result.0.clone_from_slice(&self.0);
        result
    }
}
