use sp_core::{
    offchain::KeyTypeId,
    sr25519::Signature as Sr25519Signature,
};
use sp_runtime::{
    app_crypto::{app_crypto, sr25519},
    traits::Verify,
    MultiSignature, 
    MultiSigner,
};

pub const CRYPTO_KEY_TYPE: KeyTypeId = KeyTypeId(*b"uomi");

pub struct AuthId;

app_crypto!(sr25519, CRYPTO_KEY_TYPE);

// implemented for ocw-runtime
impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for AuthId {
    type RuntimeAppPublic = Public;
    type GenericSignature = sp_core::sr25519::Signature;
    type GenericPublic = sp_core::sr25519::Public;
}

// implemented for mock runtime in test
impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature>
for AuthId {
    type RuntimeAppPublic = Public;
    type GenericSignature = sp_core::sr25519::Signature;
    type GenericPublic = sp_core::sr25519::Public;
}
