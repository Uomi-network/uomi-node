use frame_support::inherent::InherentIdentifier;
use crate::types::Version;

pub const PALLET_VERSION:Version = 2;
pub const PALLET_INHERENT_IDENTIFIER:InherentIdentifier = *b"uomiengi";

// This is the maximum number of inputs that can be managed in a single block by OPoC and offchain workers.
pub const MAX_INPUTS_MANAGED_PER_BLOCK:usize = 100;

// This is the maximum number of blocks that a node have to complete an update of it's running version.
pub const MAX_BLOCKS_TO_WAIT_NODE_UPDATE:u32 = 100;
