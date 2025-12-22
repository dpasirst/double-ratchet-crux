#![cfg(feature = "async")]
//! The `SignalDoubleRatchet` provides an example of a secure implementation of the
//! `double_ratchet::CryptoProvider`. This example code is based on the recommended cryptographic
//! algorithms of the [specification]. I have not checked if the code is fully compatible with that
//! of the [Signal application](https://signal.org/) but I suspect that it is.
//!
//! For the public key cryptography part of the `CryptoProvider` I used the
//! [x25519-dalek](https://docs.rs/x25519-dalek/) crate. The implementation boils down to thin
//! wrappers around the provided types and methods. For the symmetric part I created
//! `SymmetricKey`: a newtype wrapper around a 32-byte array. A fully secure implementation of the
//! `DoubleRatchet` may take extra steps to provide security, including but not limited to the
//! examples I have implemented here:
//!  - Prevent memory content leakages using [`clear_on_drop`].
//!  - A custom implementation of [`Debug`] so secret bytes are never written to error logs when
//!    compiled in release mode.
//! I am no expert, so if this is insufficient or can otherwise be improved please let me know. For
//! example, I suspect that the `std::pin::Pin` method can be helpful here.
//!
//! Note that the `MessageKey` for Signal is just 32 bytes which acts as input to another KDF which
//! computes an encryption key, mac key and initialization vector. This last key derivation is done
//! in the `CryptoProvider::encrypt` and `CryptoProvider::decrypt` functions. The advantage of this
//! solution over having a `MessageKey` consisting of a 3-tuple of keys is that this improves the
//! speed of symmetric ratcheting in case a message arrives out of order (or a malicious message
//! with a high skip value arrives as part of a denial-of-service attempt).
//!
//! [`clear_on_drop`]: https://crates.io/crates/clear_on_drop
//! [specification]: https://signal.org/docs/specifications/doubleratchet/#recommended-cryptographic-algorithms

use async_trait::async_trait;
use clear_on_drop::clear::Clear;
use double_ratchet::{self as dr, DRError, DecryptError, KeyPair as _};

// use libcrux:: {
//     // we can't (yet? ever?) use the next line for anything other than x86_64
//     // https://hacl-star.github.io/Supported.html#list-of-supported-algorithms
//     // https://github.com/cryspen/libcrux/issues/1269
//     //aead::{Iv, Key, Tag, encrypt_detached as aes256gcm_encrypt, decrypt_detached as aes256gcm_decrypt},
// };
use libcrux_aesgcm::{
    AesGcm256Key, AesGcm256Nonce, AesGcm256Tag, AESGCM256_KEY_LEN, NONCE_LEN, TAG_LEN,
};
use libcrux_hkdf::hkdf;
use libcrux_hmac::hmac;

use rand_core::CryptoRng;
use std::convert::TryInto;
use std::fmt;
use std::hash::{Hash, Hasher};

pub type SignalDR = double_ratchet::async_::DoubleRatchet<SignalCryptoProvider>;

type SharedSecret = Vec<u8>;

pub struct SignalCryptoProvider;

#[async_trait]
impl dr::CryptoProvider for SignalCryptoProvider {
    type PublicKey = PublicKey;
    type KeyPair = KeyPair;
    type SharedSecret = SharedSecret;

    type RootKey = SymmetricKey;
    type ChainKey = SymmetricKey;
    type MessageKey = SymmetricKey;

    fn diffie_hellman(us: &KeyPair, them: &PublicKey) -> SharedSecret {
        // note: decapsulate(alg, point (public), scalar (private)) -> shared secret
        libcrux_ecdh::derive(libcrux_ecdh::Algorithm::X25519, &them.0, &us.private).unwrap()
    }

    fn kdf_rk(rk: &SymmetricKey, s: &SharedSecret) -> (SymmetricKey, SymmetricKey) {
        let salt = rk.0.as_slice();
        let ikm = s;
        let info = &b"WhisperRatchet"[..];
        let mut okm = [0; 64];
        if let Err(e) = hkdf(libcrux_hkdf::Algorithm::Sha256, &mut okm, salt, ikm, info) {
            panic!("failed to hkdf for kdf_rk {:?}", e);
        }
        (
            SymmetricKey::from(&okm[..32].try_into().unwrap()),
            SymmetricKey::from(&okm[32..].try_into().unwrap()),
        )
    }

    fn kdf_ck(ck: &SymmetricKey) -> (SymmetricKey, SymmetricKey) {
        let key = ck.0.as_slice();
        let mk = hmac(libcrux_hmac::Algorithm::Sha256, key, &[0x01], Some(32));
        let ck = hmac(libcrux_hmac::Algorithm::Sha256, key, &[0x02], Some(32));
        (
            SymmetricKey(ck.try_into().unwrap()),
            SymmetricKey(mk.try_into().unwrap()),
        )
    }

    fn encrypt(key: &SymmetricKey, pt: &[u8], ad: &[u8]) -> Vec<u8> {
        let ikm = key.0.as_slice();
        let info = b"WhisperMessageKeys";
        let mut okm = [0; 80];
        hkdf(libcrux_hkdf::Algorithm::Sha256, &mut okm, b"", ikm, info)
            .expect("encrypt hkdf failed - boom!");
        let ek = &okm[..AESGCM256_KEY_LEN].try_into().unwrap();
        let iv = &okm[AESGCM256_KEY_LEN..(AESGCM256_KEY_LEN + NONCE_LEN)]
            .try_into()
            .unwrap(); // 12

        // the following lines are commented out but here for reference. The show how to use
        // libcrux aead impl which currently only works on x86_64
        // let iv = Iv::new(iv).unwrap();
        // let aes_key = Key::from_slice(libcrux::aead::Algorithm::Aes256Gcm, ek).unwrap();
        // let (tag, mut ct) = aes256gcm_encrypt(&aes_key, pt, iv, ad).unwrap();
        let k: AesGcm256Key = <[u8; AESGCM256_KEY_LEN] as Into<AesGcm256Key>>::into(*ek);
        let nonce: AesGcm256Nonce = <[u8; NONCE_LEN] as Into<AesGcm256Nonce>>::into(*iv);
        let mut tag: AesGcm256Tag = [0; TAG_LEN].into();

        let mut ct = vec![0u8; pt.len()];
        if let Err(e) = k.encrypt(&mut ct, &mut tag, &nonce, ad, pt) {
            okm.clear();
            panic!("Encrypt Failed: {}", e);
        } else {
            ct.extend(&tag.as_ref()[..TAG_LEN]);
            okm.clear();
            ct
        }
    }

    fn decrypt(key: &SymmetricKey, ct: &[u8], ad: &[u8]) -> Result<Vec<u8>, DecryptError> {
        let ikm = key.0.as_slice();
        let info = b"WhisperMessageKeys";
        let mut okm = [0; 80];
        hkdf(libcrux_hkdf::Algorithm::Sha256, &mut okm, b"", ikm, info)
            .map_err(|err| DecryptError::DecryptFailure(format!("{:?}", err).into()))?;

        let dk = &okm[..AESGCM256_KEY_LEN]
            .try_into()
            .map_err(|err| DecryptError::DecryptFailure(format!("{err}").into()))?;

        let iv = &okm[AESGCM256_KEY_LEN..(AESGCM256_KEY_LEN + NONCE_LEN)]
            .try_into()
            .map_err(|err| DecryptError::DecryptFailure(format!("{err}").into()))?;

        let mut pt = vec![0u8; ct.len() - TAG_LEN];

        let ct_len = ct.len() - TAG_LEN;
        let k: AesGcm256Key = <[u8; AESGCM256_KEY_LEN] as Into<AesGcm256Key>>::into(*dk);
        let nonce: AesGcm256Nonce = <[u8; NONCE_LEN] as Into<AesGcm256Nonce>>::into(*iv);
        let tag: AesGcm256Tag = <[u8; TAG_LEN] as Into<AesGcm256Tag>>::into(
            ct[ct_len..]
                .try_into()
                .map_err(|err| DecryptError::DecryptFailure(format!("{err}").into()))?,
        );

        if let Err(err) = k.decrypt(&mut pt, &nonce, ad, &ct[..ct_len], &tag) {
            okm.clear();
            Err(DecryptError::DecryptFailure(format!("{err}").into()))
        } else {
            okm.clear();
            Ok(pt)
        }
    }

    fn new_public_key(key: &[u8]) -> Result<Self::PublicKey, DRError> {
        let key: [u8; 32] = key.try_into().map_err(|_| DRError::InvalidKey)?;
        Ok(PublicKey(key))
    }

    fn new_root_key(key: &[u8]) -> Result<Self::RootKey, DRError> {
        let key: [u8; 32] = key.try_into().map_err(|_| DRError::InvalidKey)?;
        Ok(SymmetricKey(key))
    }

    fn new_chain_key(key: &[u8]) -> Result<Self::ChainKey, DRError> {
        let key: [u8; 32] = key.try_into().map_err(|_| DRError::InvalidKey)?;
        Ok(SymmetricKey(key))
    }
}

#[derive(Clone, Debug)]
pub struct PublicKey([u8; 32]);

impl Eq for PublicKey {}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.0 == other.0
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

// Implementation for converting an X25519 PrivateKey to PublicKey
impl<'a> From<&'a libcrux_ecdh::X25519PrivateKey> for PublicKey {
    fn from(private_key: &'a libcrux_ecdh::X25519PrivateKey) -> PublicKey {
        // Use a match statement to handle the enum variant
        match private_key {
            // If the private key is the X25519 variant
            libcrux_ecdh::X25519PrivateKey(private_key_bytes) => {
                // Call the libcrux function to derive the public key
                let public_key_bytes = libcrux_ecdh::secret_to_public(
                    libcrux_ecdh::Algorithm::X25519,
                    private_key_bytes,
                )
                .expect("Failed to convert X25519 PrivateKey");
                // Wrap the resulting bytes in your PublicKey struct
                PublicKey(
                    public_key_bytes
                        .try_into()
                        .expect("Failed to convert X25519 PrivateKey"),
                )
            }
            // Handle all other possible variants (e.g., Kyber, PQC)
            // This is necessary because the match must be exhaustive.
            // but in this implementation, it is here for example because
            // `X25519PrivateKey`` is the only possibility
            #[allow(unreachable_patterns)]
            _ => {
                // In a production environment, you might want to return
                // a Result<PublicKey, E> instead of panicking, but for a
                // simple `From` trait, panicking on unexpected input is common.
                panic!("Cannot convert non-X25519 PrivateKey to PublicKey");
            }
        }
    }
}

impl<'a> From<&'a [u8; 32]> for PublicKey {
    fn from(public_key: &'a [u8; 32]) -> PublicKey {
        PublicKey(*public_key)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub struct KeyPair {
    private: Vec<u8>,
    public: PublicKey,
}

impl fmt::Debug for KeyPair {
    #[cfg(debug_assertions)]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "KeyPair {{ private (bytes): {:?}, public: {:?} }}",
            self.private, self.public
        )
    }

    #[cfg(not(debug_assertions))]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "KeyPair {{ private (bytes): <hidden bytes>, public: {:?} }}",
            self.public
        )
    }
}

impl dr::KeyPair for KeyPair {
    type PublicKey = PublicKey;

    fn new<R: CryptoRng + rand::Rng>(rng: &mut R) -> KeyPair {
        let (private, public) =
            libcrux_ecdh::key_gen(libcrux_ecdh::Algorithm::X25519, rng).unwrap();
        let public: [u8; 32] = public.try_into().unwrap();
        let public = PublicKey::from(&public);
        KeyPair { private, public }
    }

    fn public(&self) -> &PublicKey {
        &self.public
    }

    fn private_bytes(&self) -> Vec<u8> {
        self.private.clone()
    }

    fn new_from_bytes(private: &[u8], public: &[u8]) -> Result<Self, DRError>
    where
        Self: Sized,
    {
        let private: [u8; 32] = private.try_into().map_err(|_| DRError::InvalidKey)?;
        let public: [u8; 32] = public.try_into().map_err(|_| DRError::InvalidKey)?;
        Ok(KeyPair {
            private: private.to_vec(),
            public: PublicKey::from(&public),
        })
    }
}

#[derive(Default, Clone, Hash, PartialEq, Eq)]
pub struct SymmetricKey([u8; 32]);

impl fmt::Debug for SymmetricKey {
    #[cfg(debug_assertions)]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SymmetricKey({:?})", self.0)
    }

    #[cfg(not(debug_assertions))]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SymmetricKey(<hidden bytes>)")
    }
}

impl<'a> From<&'a [u8; 32]> for SymmetricKey {
    fn from(symmetric_key: &'a [u8; 32]) -> SymmetricKey {
        SymmetricKey(*symmetric_key)
    }
}

impl AsRef<[u8]> for SymmetricKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Drop for SymmetricKey {
    fn drop(&mut self) {
        self.0.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn signal_session() {
        let mut rng = rand::rng(); //OsRng;
        let (ad_a, ad_b) = (b"A2B:SessionID=42", b"B2A:SessionID=42");

        // Copy some values (these are usually the outcome of an X3DH key exchange)
        let bobs_prekey = KeyPair::new(&mut rng);
        let bobs_public_prekey = bobs_prekey.public().clone();
        let shared = SymmetricKey(*b"Output of a X3DH key exchange...");

        // Alice fetches Bob's prekey bundle and completes her side of the X3DH handshake
        let mut alice = SignalDR::new_alice(&shared, bobs_public_prekey, None, &mut rng);
        // Alice creates her first message to Bob
        let pt_a_0 = b"Hello Bob";
        let (h_a_0, ct_a_0) = alice.ratchet_encrypt(pt_a_0, ad_a, &mut rng).await;
        // Alice creates an initial message containing `h_a_0`, `ct_a_0` and other X3DH information

        // Bob receives the message and finishes his side of the X3DH handshake
        let mut bob = SignalDR::new_bob(shared, bobs_prekey, None);
        // Bob can now decrypt the initial message
        assert_eq!(
            Ok(Vec::from(&b"Hello Bob"[..])),
            bob.ratchet_decrypt(&h_a_0, &ct_a_0, ad_a).await
        );
        // Bob is now fully initialized: both sides can send and receive message

        let pt_a_1 = b"I will send this later";
        let (h_a_1, ct_a_1) = alice.ratchet_encrypt(pt_a_1, ad_a, &mut rng).await;
        let pt_b_0 = b"My first reply";
        let (h_b_0, ct_b_0) = bob.ratchet_encrypt(pt_b_0, ad_b, &mut rng).await;
        assert_eq!(
            Ok(Vec::from(&pt_b_0[..])),
            alice.ratchet_decrypt(&h_b_0, &ct_b_0, ad_b).await
        );
        let pt_a_2 = b"What a boring conversation";
        let (h_a_2, _ct_a_2) = alice.ratchet_encrypt(pt_a_2, ad_a, &mut rng).await;
        let pt_a_3 = b"Don't you agree?";
        let (h_a_3, ct_a_3) = alice.ratchet_encrypt(pt_a_3, ad_a, &mut rng).await;
        assert_eq!(
            Ok(Vec::from(&pt_a_3[..])),
            bob.ratchet_decrypt(&h_a_3, &ct_a_3, ad_a).await
        );

        let pt_b_1 = b"Agree with what?";
        let (h_b_1, ct_b_1) = bob.ratchet_encrypt(pt_b_1, ad_b, &mut rng).await;
        assert_eq!(
            Ok(Vec::from(&pt_b_1[..])),
            alice.ratchet_decrypt(&h_b_1, &ct_b_1, ad_b).await
        );

        assert_eq!(
            Ok(Vec::from(&pt_a_1[..])),
            bob.ratchet_decrypt(&h_a_1, &ct_a_1, ad_a).await
        );

        // No resending (that key is already deleted)
        assert!(bob.ratchet_decrypt(&h_a_1, &ct_a_1, ad_a).await.is_err());
        // No fake messages
        assert!(bob
            .ratchet_decrypt(&h_a_2, b"Incorrect ciphertext", ad_a)
            .await
            .is_err());
    }

    #[test]
    fn public_key() {
        let key = [9u8; 32];
        let public_key = PublicKey::from(&key);
        assert_eq!(public_key.as_ref(), &key);
    }

    #[test]
    fn symmetric_key() {
        let key = [8u8; 32];
        let symmetric_key = SymmetricKey(key);
        assert_eq!(symmetric_key.as_ref(), &key);
    }

    #[test]
    fn key_pair() {
        let mut rng = rand::rng(); //OsRng;
        let key_pair_ref = KeyPair::new(&mut rng);
        let new_key_pair = KeyPair::new_from_bytes(
            key_pair_ref.private_bytes().as_slice(),
            key_pair_ref.public().as_ref(),
        );
        assert!(new_key_pair.is_ok());
        let new_key_pair = new_key_pair.unwrap();
        assert_eq!(
            key_pair_ref.private_bytes().as_slice(),
            new_key_pair.private_bytes().as_slice()
        );
        assert_eq!(
            key_pair_ref.public().as_ref(),
            new_key_pair.public().as_ref()
        );
    }

    #[tokio::test]
    async fn multiple_messages_key_kdf() {
        let mut rng = rand::rng(); //OsRng;
        let (ad_a, _ad_b) = (b"A2B:SessionID=42", b"B2A:SessionID=42");

        // Copy some values (these are usually the outcome of an X3DH key exchange)
        let bobs_prekey = KeyPair::new(&mut rng);
        let bobs_public_prekey = bobs_prekey.public().clone();
        let shared = SymmetricKey(*b"Output of a X3DH key exchange...");

        // Alice fetches Bob's prekey bundle and completes her side of the X3DH handshake
        let mut alice = SignalDR::new_alice(&shared, bobs_public_prekey, None, &mut rng);
        // Alice creates her first message to Bob
        let pt_a_0 = b"Hello Bob";
        let (h_a_0, ct_a_0) = alice.ratchet_encrypt(pt_a_0, ad_a, &mut rng).await;
        // Alice creates an initial message containing `h_a_0`, `ct_a_0` and other X3DH information

        // Bob receives the message and finishes his side of the X3DH handshake
        let mut bob = SignalDR::new_bob(shared, bobs_prekey, None);
        // Bob can now decrypt the initial message
        assert_eq!(
            Ok(Vec::from(&b"Hello Bob"[..])),
            bob.ratchet_decrypt(&h_a_0, &ct_a_0, ad_a).await
        );
        // Bob is now fully initialized: both sides can send and receive message

        // we will now send multiple messages without receiving a response.
        // this will cause the kdf function to be used instead of updating the root key
        let pt_a_1 = b"I will send a first message";
        let (h_a_1, ct_a_1) = alice.ratchet_encrypt(pt_a_1, ad_a, &mut rng).await;
        let pt_a_2 = b"I will send a second message";
        let (h_a_2, ct_a_2) = alice.ratchet_encrypt(pt_a_2, ad_a, &mut rng).await;
        let pt_a_3 = b"I will send a third message";
        let (h_a_3, ct_a_3) = alice.ratchet_encrypt(pt_a_3, ad_a, &mut rng).await;

        assert_eq!(
            Ok(Vec::from(&pt_a_1[..])),
            bob.ratchet_decrypt(&h_a_1, &ct_a_1, ad_a).await
        );
        assert_eq!(
            Ok(Vec::from(&pt_a_2[..])),
            bob.ratchet_decrypt(&h_a_2, &ct_a_2, ad_a).await
        );
        assert_eq!(
            Ok(Vec::from(&pt_a_3[..])),
            bob.ratchet_decrypt(&h_a_3, &ct_a_3, ad_a).await
        );
    }
}
