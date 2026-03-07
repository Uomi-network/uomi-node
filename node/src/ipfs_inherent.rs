// This file is part of Uomi.

// Copyright (C) Uomi.
// SPDX-License-Identifier: GPL-3.0-or-later

//! No-op InherentDataProvider for the IPFS pallet's `ipfs-ide` inherent identifier.
//!
//! The IPFS pallet creates inherent extrinsics (`set_inherent_data`) that are computed
//! entirely from on-chain state. The client does not need to provide any external data
//! for this inherent. However, Substrate's inherent checking framework requires that
//! every inherent identifier used by the runtime has a corresponding
//! `InherentDataProvider` registered on the client side — otherwise any error returned
//! by `check_inherent` is treated as an "unhandled error" and the block is rejected.
//!
//! This provider:
//! 1. Registers the `ipfs-ide` key in `InherentData` (with an empty value)
//! 2. Handles any `ipfs-ide` errors gracefully by logging them instead of rejecting blocks

use sp_inherents::{InherentData, InherentIdentifier};

/// The inherent identifier used by the IPFS pallet.
pub const IPFS_INHERENT_IDENTIFIER: InherentIdentifier = *b"ipfs-ide";

/// A no-op inherent data provider that registers the `ipfs-ide` identifier
/// so that the client-side inherent checking can properly handle IPFS inherent errors.
pub struct IpfsInherentDataProvider;

#[async_trait::async_trait]
impl sp_inherents::InherentDataProvider for IpfsInherentDataProvider {
    async fn provide_inherent_data(
        &self,
        inherent_data: &mut InherentData,
    ) -> Result<(), sp_inherents::Error> {
        // Put an empty value to register the identifier.
        // The IPFS pallet's `create_inherent` ignores InherentData entirely
        // and computes everything from on-chain state.
        inherent_data.put_data(IPFS_INHERENT_IDENTIFIER, &())?;
        Ok(())
    }

    async fn try_handle_error(
        &self,
        identifier: &InherentIdentifier,
        _error: &[u8],
    ) -> Option<Result<(), sp_inherents::Error>> {
        if *identifier == IPFS_INHERENT_IDENTIFIER {
            // Log the error but do NOT reject the block.
            // The inherent data is deterministic from chain state and validated
            // during actual block execution.
            log::warn!(
                "IPFS inherent check returned an error — accepting block anyway \
                 (inherent validated during execution)"
            );
            Some(Ok(()))
        } else {
            None
        }
    }
}
