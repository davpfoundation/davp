use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::Visitor;

pub type PublicKeyBytes = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureBytes(pub [u8; 64]);

impl Serialize for SignatureBytes {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for SignatureBytes {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SigVisitor;

        impl<'de> Visitor<'de> for SigVisitor {
            type Value = SignatureBytes;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("64 bytes")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let arr: [u8; 64] = v
                    .try_into()
                    .map_err(|_| E::custom("invalid signature length"))?;
                Ok(SignatureBytes(arr))
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_bytes(&v)
            }
        }

        deserializer.deserialize_bytes(SigVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeypairBytes(pub [u8; 64]);

impl Serialize for KeypairBytes {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for KeypairBytes {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct KeypairVisitor;

        impl<'de> Visitor<'de> for KeypairVisitor {
            type Value = KeypairBytes;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("64 bytes")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let arr: [u8; 64] = v
                    .try_into()
                    .map_err(|_| E::custom("invalid keypair length"))?;
                Ok(KeypairBytes(arr))
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_bytes(&v)
            }
        }

        deserializer.deserialize_bytes(KeypairVisitor)
    }
}

impl KeypairBytes {
    pub fn generate() -> Self {
        let mut csprng = OsRng {};
        let keypair = Keypair::generate(&mut csprng);
        Self(keypair.to_bytes())
    }

    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.0)
    }

    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes = STANDARD.decode(s)?;
        let arr: [u8; 64] = bytes
            .try_into()
            .map_err(|_| anyhow!("invalid keypair length"))?;
        Ok(Self(arr))
    }

    pub fn public_key_bytes(&self) -> Result<PublicKeyBytes> {
        Ok(self.to_keypair()?.public.to_bytes())
    }

    pub fn to_keypair(&self) -> Result<Keypair> {
        Ok(Keypair::from_bytes(&self.0).map_err(|e| anyhow!(e))?)
    }
}

pub fn sign(payload: &[u8], keypair: &KeypairBytes) -> Result<SignatureBytes> {
    let kp = keypair.to_keypair()?;
    Ok(SignatureBytes(kp.sign(payload).to_bytes()))
}

pub fn verify(payload: &[u8], signature: &SignatureBytes, public_key: &PublicKeyBytes) -> Result<()> {
    let pk = PublicKey::from_bytes(public_key).map_err(|e| anyhow!(e))?;
    let sig = Signature::from_bytes(&signature.0).map_err(|e| anyhow!(e))?;
    pk.verify(payload, &sig).map_err(|e| anyhow!(e))
}
