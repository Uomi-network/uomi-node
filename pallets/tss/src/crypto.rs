use crate::CRYPTO_KEY_TYPE;
use sp_core::sr25519::Signature as Sr25519Signature;
use sp_runtime::app_crypto::{app_crypto, sr25519};
use sp_runtime::{traits::Verify, MultiSignature, MultiSigner};

// Provide String for no_std context; required by generated code in app_crypto! macro
#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use sp_std::vec::Vec;

app_crypto!(sr25519, CRYPTO_KEY_TYPE);

pub struct AuthId;

// implemented for ocw-runtime
impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for AuthId {
    type RuntimeAppPublic = Public;
    type GenericSignature = sp_core::sr25519::Signature;
    type GenericPublic = sp_core::sr25519::Public;
}

// implemented for mock runtime in test
impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature>
    for AuthId
{
    type RuntimeAppPublic = Public;
    type GenericSignature = sp_core::sr25519::Signature;
    type GenericPublic = sp_core::sr25519::Public;
}