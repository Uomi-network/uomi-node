use fc_rpc::pending::ConsensusDataProvider;
use sc_consensus_babe::{CompatibleDigestItem, PreDigest, SecondaryPlainPreDigest};
use sp_consensus_babe::inherents::BabeInherentData;
use sp_runtime::{traits::Block as BlockT, DigestItem};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("BABE inherent data missing")]
    MissingInherent,
}

impl From<Error> for sp_inherents::Error {
    fn from(err: Error) -> Self {
        sp_inherents::Error::Application(Box::new(err))
    }
}

#[derive(Clone)]
pub struct BabeConsensusDataProvider {}

impl BabeConsensusDataProvider {
    pub fn new() -> Self {
        Self {}
    }
}

impl<B> ConsensusDataProvider<B> for BabeConsensusDataProvider
where
    B: BlockT,
{
    fn create_digest(
        &self,
        _parent: &<B as BlockT>::Header,
        data: &sp_inherents::InherentData,
    ) -> Result<sp_runtime::Digest, sp_inherents::Error> {
        let slot = data
            .babe_inherent_data()?
            .ok_or(sp_inherents::Error::Application(Box::new(Error::MissingInherent)))?;

        let predigest =
            PreDigest::SecondaryPlain(SecondaryPlainPreDigest { slot, authority_index: 0 });

        let logs = vec![<DigestItem as CompatibleDigestItem>::babe_pre_digest(predigest)];

        Ok(sp_runtime::Digest { logs })
    }
}
