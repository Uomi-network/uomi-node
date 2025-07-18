use crate::CRYPTO_KEY_TYPE;
use sp_core::sr25519::Signature as Sr25519Signature;
use sp_runtime::app_crypto::{app_crypto, sr25519};
use sp_runtime::{traits::Verify, MultiSignature, MultiSigner};

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