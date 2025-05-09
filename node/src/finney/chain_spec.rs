// This file is part of Uomi.

// Copyright (C) Uomi.
// SPDX-License-Identifier: GPL-3.0-or-later

// Uomi is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Uomi is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Uomi. If not, see <http://www.gnu.org/licenses/>.

//! Chain specifications.

use finney_runtime::{
    wasm_binary_unwrap, AccountId, BabeConfig, BalancesConfig,
    CommunityCouncilMembershipConfig, CommunityTreasuryPalletId, CouncilMembershipConfig,
    EVMConfig, GrandpaId,
    Precompiles, RuntimeGenesisConfig, Signature, SudoConfig,
    TechnicalCommitteeMembershipConfig, TreasuryPalletId, VestingConfig, UOMI, ElectionsConfig,
    StakerStatus, SessionConfig, StakingConfig, SessionKeys, MaxNominators, NominationPoolsConfig
};
use sp_consensus_babe::AuthorityId as BabeId;
use sc_service::ChainType;
use sp_core::{crypto::Ss58Codec, sr25519, Pair, Public};
use sp_runtime::traits::{AccountIdConversion, IdentifyAccount, Verify};
use sp_runtime::Perbill;
use pallet_im_online::sr25519::AuthorityId as ImOnlineId;

type AccountPublic = <Signature as Verify>::Signer;


pub type ChainSpec = sc_service::GenericChainSpec<finney_runtime::RuntimeGenesisConfig>;

/// Helper function to generate a crypto pair from seed
fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
    TPublic::Pair::from_string(&format!("//{}", seed), None)
        .expect("static values are valid; qed")
        .public()
}

/// Helper function to generate an account ID from seed
fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
    AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
    AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}



/// Generate an babe authority key.
pub fn authority_keys_from_seed(s: &str) -> (AccountId, AccountId, BabeId, GrandpaId, ImOnlineId) {
    (
        get_account_id_from_seed::<sr25519::Public>(s),
		get_account_id_from_seed::<sr25519::Public>(s),
        get_from_seed::<BabeId>(s),
        get_from_seed::<GrandpaId>(s),
        get_from_seed::<ImOnlineId>(s),
    )
}

/// testnet config (single validator Alice)
pub fn testnet_config() -> ChainSpec {
    let mut properties = serde_json::map::Map::new();
    properties.insert("tokenSymbol".into(), "UOMI".into());
    properties.insert("tokenDecimals".into(), 18.into());
    ChainSpec::builder(wasm_binary_unwrap(), None)
        .with_name("finney")
        .with_id("finney")
        .with_chain_type(ChainType::Development)
        .with_properties(properties)
        .with_genesis_config(testnet_genesis(
            vec![authority_keys_from_seed("Bob")],
            vec![],
            get_account_id_from_seed::<sr25519::Public>("Alice"),
            vec![
                //get_account_id_from_seed::<sr25519::Public>("Alice"),
                get_account_id_from_seed::<sr25519::Public>("Bob"),
                get_account_id_from_seed::<sr25519::Public>("Dave"),
                get_account_id_from_seed::<sr25519::Public>("Charlie"),
                get_account_id_from_seed::<sr25519::Public>("Eve"),
                get_account_id_from_seed::<sr25519::Public>("Ferdie"),
                get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
				get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
				get_account_id_from_seed::<sr25519::Public>("Charlie//stash"),
				get_account_id_from_seed::<sr25519::Public>("Dave//stash"),
				get_account_id_from_seed::<sr25519::Public>("Eve//stash"),
				get_account_id_from_seed::<sr25519::Public>("Ferdie//stash"),
                TreasuryPalletId::get().into_account_truncating(),
                CommunityTreasuryPalletId::get().into_account_truncating(),
                // Import known test account with private key
                // 0x01ab6e801c06e59ca97a14fc0a1978b27fa366fc87450e0b65459dd3515b7391
                // H160 address: 0xaaafB3972B05630fCceE866eC69CdADd9baC2771
                AccountId::from_ss58check("5FQedkNQcF2fJPwkB6Z1ZcMgGti4vcJQNs6x85YPv3VhjBBT")
                    .unwrap(),

                AccountId::from_ss58check("ajYMsCKsEAhEvHpeA4XqsfiA9v1CdzZPrCfS6pEfeGHW9j8")
                    .unwrap(),

            ],
        ))
        .build()
}

fn session_keys(
	grandpa: GrandpaId,
	babe: BabeId,
	im_online: ImOnlineId,
) -> SessionKeys {
	SessionKeys { grandpa, babe, im_online }
}

fn testnet_genesis(
    initial_authorities: Vec<(AccountId, AccountId, BabeId, GrandpaId, ImOnlineId)>,
    initial_nominators: Vec<AccountId>,
    root_key: AccountId,
    endowed_accounts: Vec<AccountId>,
) -> serde_json::Value {
    let accounts: Vec<AccountId> = vec!["Alice", "Bob", "Charlie", "Dave", "Eve"]
        .iter()
        .map(|s| get_account_id_from_seed::<sr25519::Public>(s))
        .collect();

    const INITIAL_STAKING: u128 =   1_000_000 * 1_000_000_000_000_000_000;

    let mut rng = rand::thread_rng();

    let stakers = initial_authorities
    .iter()
    .map(|x| (x.0.clone(), x.1.clone(), INITIAL_STAKING, StakerStatus::Validator))
    .chain(initial_nominators.iter().map(|x| {
        use rand::{seq::SliceRandom, Rng};
        let limit = (MaxNominators::get() as usize).min(initial_authorities.len());
        let count = rng.gen::<usize>() % limit;
        let nominations = initial_authorities
            .as_slice()
            .choose_multiple(&mut rng, count)
            .map(|choice| choice.0.clone())
            .collect::<Vec<_>>();
        (x.clone(), x.clone(), INITIAL_STAKING, StakerStatus::Nominator(nominations))
    }))
    .collect::<Vec<_>>();
    
    // Verifica che il vettore stakers non sia vuoto

    // This is supposed the be the simplest bytecode to revert without returning any data.
    // We will pre-deploy it under all of our precompiles to ensure they can be called from
    // within contracts.
    // (PUSH1 0x00 PUSH1 0x00 REVERT)
    let revert_bytecode = vec![0x60, 0x00, 0x60, 0x00, 0xFD];
    let config = RuntimeGenesisConfig {
        system: Default::default(),
        balances: BalancesConfig {
            balances: endowed_accounts
                .iter()
                .cloned()
                .map(|k| (k, 100_000_000_000 * UOMI))
                .collect(),
        },
        vesting: VestingConfig { vesting: vec![] },
        babe: BabeConfig {
			epoch_config: finney_runtime::BABE_GENESIS_EPOCH_CONFIG,
			..Default::default()
		},
        grandpa: Default::default(),
        evm: EVMConfig {
            // We need _some_ code inserted at the precompile address so that
            // the evm will actually call the address.
            accounts: Precompiles::used_addresses()
                .map(|addr| {
                    (
                        addr,
                        fp_evm::GenesisAccount {
                            nonce: Default::default(),
                            balance: Default::default(),
                            storage: Default::default(),
                            code: revert_bytecode.clone(),
                        },
                    )
                })
                .collect(),
            ..Default::default()
        },
        ethereum: Default::default(),
        sudo: SudoConfig {
            key: Some(root_key),
        },
        im_online: Default::default(),
        assets: Default::default(),
        transaction_payment: Default::default(),
        council_membership: CouncilMembershipConfig {
            members: accounts
                .clone()
                .try_into()
                .expect("Should support at least 5 members."),
            phantom: Default::default(),
        },
        technical_committee_membership: TechnicalCommitteeMembershipConfig {
            members: accounts[..3]
                .to_vec()
                .try_into()
                .expect("Should support at least 3 members."),
            phantom: Default::default(),
        },
        community_council_membership: CommunityCouncilMembershipConfig {
            members: accounts
                .try_into()
                .expect("Should support at least 5 members."),
            phantom: Default::default(),
        },
        nomination_pools: NominationPoolsConfig {
			min_create_bond: 10 * 1_000 * 1_000 * 1_000_000_000_000,
			min_join_bond: 1_000 * 1_000 * 1_000_000_000_000,
			..Default::default()
		},
        elections: ElectionsConfig::default(),
        session: SessionConfig {
			keys: initial_authorities
				.iter()
				.map(|x| {
					(
						x.0.clone(),
						x.0.clone(),
						session_keys(x.3.clone(), x.2.clone(),  x.4.clone()),
					)
				})
				.collect::<Vec<_>>(),
		},
		staking: StakingConfig {
			validator_count: initial_authorities.len() as u32,
			minimum_validator_count: initial_authorities.len() as u32,
			invulnerables: initial_authorities.iter().map(|x| x.0.clone()).collect(),
			slash_reward_fraction: Perbill::from_percent(10),
			stakers,
			..Default::default()
		},
        council: Default::default(),
        technical_committee: Default::default(),
        community_council: Default::default(),
        democracy: Default::default(),
        treasury: Default::default(),
        base_fee: Default::default(),
        community_treasury: Default::default(),
    };
    serde_json::to_value(&config).expect("Could not build genesis config.")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use sp_runtime::BuildStorage;

    #[test]
    fn test_create_development_chain_spec() {
        testnet_config().build_storage().unwrap();
    }
}
