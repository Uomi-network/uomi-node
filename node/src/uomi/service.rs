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

//! uomi Service and ServiceFactory implementation. Specialized wrapper over substrate service.

use fc_consensus::FrontierBlockImport;
use fc_rpc_core::types::{FeeHistoryCache, FilterPool};
use futures::{FutureExt, StreamExt};
use sc_client_api::{Backend, BlockBackend, BlockchainEvents};
use sc_consensus_grandpa::SharedVoterState;
use sc_consensus::BoxBlockImport;
use sc_executor::NativeElseWasmExecutor;
use sc_service::{error::Error as ServiceError, Configuration, TaskManager};
use sc_telemetry::{Telemetry, TelemetryHandle, TelemetryWorker};
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use uomi_runtime::Runtime;
use std::{collections::BTreeMap, marker::PhantomData, sync::Arc, time::Duration};
use ipfs_manager::IpfsManager;
use tss::{get_config, setup_gossip};
#[cfg(not(feature = "manual-seal"))]
use sc_consensus_babe::{BabeLink, BabeWorkerHandle, SlotProportion};

#[cfg(feature = "evm-tracing")]
use crate::{evm_tracing_types::EthApi as EthApiCmd, rpc::tracing};

pub use uomi_runtime::RuntimeApi;

use uomi_primitives::*;

/// The minimum period of blocks on which justifications will be
/// imported and generated.
const GRANDPA_JUSTIFICATION_PERIOD: u32 = 512;
type GrandpaBlockImport<C> =
    sc_consensus_grandpa::GrandpaBlockImport<FullBackend, Block, C, FullSelectChain>;

/// Extra host functions
#[cfg(feature = "runtime-benchmarks")]
pub type HostFunctions = (
    // benchmarking host functions
    frame_benchmarking::benchmarking::HostFunctions,
    // evm tracing host functions
    moonbeam_primitives_ext::moonbeam_ext::HostFunctions,
);

/// Extra host functions
#[cfg(not(feature = "runtime-benchmarks"))]
pub type HostFunctions = (
    // evm tracing host functions
    moonbeam_primitives_ext::moonbeam_ext::HostFunctions,
);

/// uomi runtime native executor.
pub struct Executor;

impl sc_executor::NativeExecutionDispatch for Executor {
    type ExtendHostFunctions = HostFunctions;

    fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
        uomi_runtime::api::dispatch(method, data)
    }

    fn native_version() -> sc_executor::NativeVersion {
        uomi_runtime::native_version()
    }
}

type FullClient = sc_service::TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<Executor>>;
type FullBackend = sc_service::TFullBackend<Block>;
type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;
type BasicImportQueue = sc_consensus::DefaultImportQueue<Block>;
type FullPool = sc_transaction_pool::FullPool<Block, FullClient>;
type GrandpaLinkHalf<C> = sc_consensus_grandpa::LinkHalf<Block, C, FullSelectChain>;

/// Build a partial chain component config
pub fn new_partial(
    config: &Configuration,
) -> Result<
sc_service::PartialComponents<
        FullClient,
        FullBackend,
        FullSelectChain,
        BasicImportQueue,
        FullPool,
        (
            Option<Telemetry>,
            BoxBlockImport<Block>,
            BabeLink<Block>,
            BabeWorkerHandle<Block>,
            GrandpaLinkHalf<FullClient>,
            Arc<fc_db::kv::Backend<Block>>,
        ),
    >,
    ServiceError,
>
{
    let build_import_queue = build_babe_grandpa_import_queue;
    let telemetry = config
        .telemetry_endpoints
        .clone()
        .filter(|x| !x.is_empty())
        .map(|endpoints| -> Result<_, sc_telemetry::Error> {
            let worker = TelemetryWorker::new(16)?;
            let telemetry = worker.handle().new_telemetry(endpoints);
            Ok((worker, telemetry))
        })
        .transpose()?;

    let executor = sc_service::new_native_or_wasm_executor(&config);

    let (client, backend, keystore_container, task_manager) =
    sc_service::new_full_parts_record_import::<Block, RuntimeApi, _>(
            config,
            telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
            executor,
            true,
        )?;  
    let client = Arc::new(client);
    let telemetry = telemetry.map(|(worker, telemetry)| {
        task_manager
            .spawn_handle()
            .spawn("telemetry", None, worker.run());
        telemetry
    });
    let select_chain = sc_consensus::LongestChain::new(backend.clone());
    let transaction_pool = sc_transaction_pool::BasicPool::new_full(
        config.transaction_pool.clone(),
        config.role.is_authority().into(),
        config.prometheus_registry(),
        task_manager.spawn_essential_handle(),
        client.clone(),
    );
    let (grandpa_block_import, grandpa_link) = sc_consensus_grandpa::block_import(
        client.clone(),
        GRANDPA_JUSTIFICATION_PERIOD,
        &client,
        select_chain.clone(),
        telemetry.as_ref().map(|x| x.handle()),
    )?;
    let frontier_backend = crate::rpc::open_frontier_backend(client.clone(), config)?;

    #[cfg(feature = "manual-seal")]
    let import_queue = sc_consensus_manual_seal::import_queue(
        Box::new(client.clone()),
        &task_manager.spawn_essential_handle(),
        config.prometheus_registry(),
    );

    #[cfg(not(feature = "manual-seal"))]
    let ((import_queue, worker_handle), block_import, babe_link) = build_import_queue(
        client.clone(),
        config,
        &task_manager,
        telemetry.as_ref().map(|x| x.handle()),
        grandpa_block_import,
        select_chain.clone(),
        OffchainTransactionPoolFactory::new(transaction_pool.clone()),
    )?;

    Ok(sc_service::PartialComponents {
        client,
        backend,
        task_manager,
        import_queue,
        keystore_container,
        select_chain,
        transaction_pool,
        other: (
            telemetry,
            block_import,
            babe_link,
            worker_handle,
            grandpa_link,
            frontier_backend,
        ),
    })
}


pub fn build_babe_grandpa_import_queue(
    client: Arc<FullClient>,
    config: &Configuration,
    task_manager: &TaskManager,
    telemetry: Option<TelemetryHandle>,
    grandpa_block_import: GrandpaBlockImport<FullClient>,
    select_chain: FullSelectChain,
    offchain_tx_pool_factory: OffchainTransactionPoolFactory<Block>,
) -> Result<
    ((BasicImportQueue, BabeWorkerHandle<Block>), BoxBlockImport<Block>, BabeLink<Block>),
    ServiceError,
> {
    // TODO should we use this instead of babe block import?
    // let _frontier_block_import =
    //     FrontierBlockImport::new(grandpa_block_import.clone(), client.clone());

    let (block_import, babe_link) = sc_consensus_babe::block_import(
        sc_consensus_babe::configuration(&*client)?,
        grandpa_block_import.clone(),
        client.clone(),
    )?;

    let frontier_block_import = FrontierBlockImport::new(block_import.clone(), client.clone());

    let slot_duration = babe_link.config().slot_duration();
    let justification_import = grandpa_block_import;
    let import_queue = sc_consensus_babe::import_queue(sc_consensus_babe::ImportQueueParams {
        link: babe_link.clone(),
        block_import: frontier_block_import.clone(),
        justification_import: Some(Box::new(justification_import)),
        client: client.clone(),
        select_chain,
        create_inherent_data_providers: move |_, ()| async move {
            let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

            let slot =
                sp_consensus_babe::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
                    *timestamp,
                    slot_duration,
                );




            Ok((slot, timestamp))
        },
        spawner: &task_manager.spawn_essential_handle(),
        registry: config.prometheus_registry(),
        telemetry,
        offchain_tx_pool_factory,
    })?;

    Ok((import_queue, Box::new(frontier_block_import), babe_link))
}

/// Builds a new service.
pub fn start_node(
    config: Configuration,
    #[cfg(feature = "evm-tracing")] evm_tracing_config: crate::evm_tracing_types::EvmTracingConfig,
) -> Result<TaskManager, ServiceError> {

    let ipfs_manager = Arc::new(IpfsManager::new().map_err(|e| ServiceError::Other(format!("Failed to initialize IPFS manager: {}", e)))?);
    ipfs_manager.start_daemon().map_err(|e| ServiceError::Other(format!("Failed to start IPFS daemon: {}", e)))?;

    let sc_service::PartialComponents {
        client,
        backend,
        mut task_manager,
        import_queue,
        keystore_container,
        select_chain,
        transaction_pool,
        other:
            (
                mut telemetry,
                block_import,
                babe_link,
                worker_handle,
                grandpa_link,
                frontier_backend,
            ),
    } = new_partial(&config)?;



    task_manager.spawn_essential_handle().spawn_blocking(
        "ipfs-manager",
        None,
        Box::pin(async move {
            let _ipfs_manager = ipfs_manager.clone();
            futures::future::pending::<()>().await;
        }),
    );
    let slot_duration = babe_link.config().slot_duration();

    let protocol_name = sc_consensus_grandpa::protocol_standard_name(
        &client
            .block_hash(0)
            .ok()
            .flatten()
            .expect("Genesis block exists; qed"),
        &config.chain_spec,
    );
    
    let mut net_config = sc_network::config::FullNetworkConfiguration::new(&config.network);

    let (grandpa_protocol_config, grandpa_notification_service) =
        sc_consensus_grandpa::grandpa_peers_set_config(protocol_name.clone());
    net_config.add_notification_protocol(grandpa_protocol_config);

    let (tss_protocol_config, tss_notification_service, tss_protocol_name) = get_config();
    net_config.add_notification_protocol(tss_protocol_config);


    let (network, system_rpc_tx, tx_handler_controller, network_starter, sync_service) =
        sc_service::build_network(sc_service::BuildNetworkParams {
            config: &config,
            net_config,
            client: client.clone(),
            transaction_pool: transaction_pool.clone(),
            spawn_handle: task_manager.spawn_handle(),
            import_queue,
            block_announce_validator_builder: None,
            warp_sync_params: None,
            block_relay: None,
        })?;



    if config.offchain_worker.enabled {
        task_manager.spawn_handle().spawn(
            "offchain-workers-runner",
            "offchain-work",
            sc_offchain::OffchainWorkers::new(sc_offchain::OffchainWorkerOptions {
                runtime_api_provider: client.clone(),
                keystore: Some(keystore_container.keystore()),
                offchain_db: backend.offchain_storage(),
                transaction_pool: Some(OffchainTransactionPoolFactory::new(
                    transaction_pool.clone(),
                )),
                network_provider: network.clone(),
                is_validator: config.role.is_authority(),
                enable_http_requests: true,
                custom_extensions: move |_| vec![],
            })
            .run(client.clone(), task_manager.spawn_handle())
            .boxed(),
        );
    }

    let filter_pool: FilterPool = Arc::new(std::sync::Mutex::new(BTreeMap::new()));
    let fee_history_cache: FeeHistoryCache = Arc::new(std::sync::Mutex::new(BTreeMap::new()));
    let overrides = fc_storage::overrides_handle(client.clone());

    // Sinks for pubsub notifications.
    // Everytime a new subscription is created, a new mpsc channel is added to the sink pool.
    // The MappingSyncWorker sends through the channel on block import and the subscription emits a notification to the subscriber on receiving a message through this channel.
    // This way we avoid race conditions when using native substrate block import notification stream.
    let pubsub_notification_sinks: fc_mapping_sync::EthereumBlockNotificationSinks<
        fc_mapping_sync::EthereumBlockNotification<Block>,
    > = Default::default();
    let pubsub_notification_sinks = Arc::new(pubsub_notification_sinks);
    #[cfg(feature = "evm-tracing")]
    let ethapi_cmd = evm_tracing_config.ethapi.clone();

    #[cfg(feature = "evm-tracing")]
    let tracing_requesters =
        if ethapi_cmd.contains(&EthApiCmd::Debug) || ethapi_cmd.contains(&EthApiCmd::Trace) {
            tracing::spawn_tracing_tasks(
                &evm_tracing_config,
                config.prometheus_registry().cloned(),
                tracing::SpawnTasksParams {
                    task_manager: &task_manager,
                    client: client.clone(),
                    substrate_backend: backend.clone(),
                    frontier_backend: frontier_backend.clone(),
                    filter_pool: Some(filter_pool.clone()),
                    overrides: overrides.clone(),
                },
            )
        } else {
            tracing::RpcRequesters {
                debug: None,
                trace: None,
            }
        };



    // Frontier offchain DB task. Essential.
    // Maps emulated ethereum data to substrate native data.
    task_manager.spawn_essential_handle().spawn(
        "frontier-mapping-sync-worker",
        Some("frontier"),
        fc_mapping_sync::kv::MappingSyncWorker::new(
            client.import_notification_stream(),
            Duration::new(6, 0),
            client.clone(),
            backend.clone(),
            overrides.clone(),
            frontier_backend.clone(),
            3,
            0,
            fc_mapping_sync::SyncStrategy::Parachain,
            sync_service.clone(),
            pubsub_notification_sinks.clone(),
        )
        .for_each(|()| futures::future::ready(())),
    );

    // Frontier `EthFilterApi` maintenance. Manages the pool of user-created Filters.
    // Each filter is allowed to stay in the pool for 100 blocks.
    const FILTER_RETAIN_THRESHOLD: u64 = 100;
    task_manager.spawn_essential_handle().spawn(
        "frontier-filter-pool",
        Some("frontier"),
        fc_rpc::EthTask::filter_pool_task(
            client.clone(),
            filter_pool.clone(),
            FILTER_RETAIN_THRESHOLD,
        ),
    );

    const FEE_HISTORY_LIMIT: u64 = 2048;
    task_manager.spawn_essential_handle().spawn(
        "frontier-fee-history",
        Some("frontier"),
        fc_rpc::EthTask::fee_history_task(
            client.clone(),
            overrides.clone(),
            fee_history_cache.clone(),
            FEE_HISTORY_LIMIT,
        ),
    );

    #[cfg(not(feature = "manual-seal"))]
    let force_authoring = config.force_authoring;
    #[cfg(not(feature = "manual-seal"))]
    let backoff_authoring_blocks: Option<()> = None;

    let role = config.role.clone();
    let name = config.network.node_name.clone();
    let enable_grandpa = !config.disable_grandpa;
    let prometheus_registry = config.prometheus_registry().cloned();
    let is_authority = config.role.is_authority();

    let block_data_cache = Arc::new(fc_rpc::EthBlockDataCacheTask::new(
        task_manager.spawn_handle(),
        overrides.clone(),
        50,
        50,
        prometheus_registry.clone(),
    ));

    // Channel for the rpc handler to communicate with the authorship task.
    #[cfg(feature = "manual-seal")]
    let (command_sink, commands_stream) = futures::channel::mpsc::channel(1024);

    let pending_create_inherent_data_providers = move |_, ()| async move {
        let current = sp_timestamp::InherentDataProvider::from_system_time();
        let next_slot = current.timestamp().as_millis() + slot_duration.as_millis();
        let timestamp = sp_timestamp::InherentDataProvider::new(next_slot.into());
        let slot =
            sp_consensus_babe::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
                *timestamp,
                slot_duration,
            );


        Ok((slot, timestamp))
    };

    let c = client.clone();


    let rpc_extensions_builder = {
        let client = client.clone();
        let network = network.clone();
        let transaction_pool = transaction_pool.clone();
        let sync = sync_service.clone();
        let keystore = keystore_container.keystore().clone();
        let select_chain = select_chain.clone();
        let pubsub_notification_sinks = pubsub_notification_sinks.clone();
        let justification_stream = grandpa_link.justification_stream();
        let shared_authority_set = grandpa_link.shared_authority_set().clone();
        let finality_provider = sc_consensus_grandpa::FinalityProofProvider::new_for_service(
            backend.clone(),
            Some(shared_authority_set.clone()),
        );

        Box::new(move |deny_unsafe, subscription: sc_rpc::SubscriptionTaskExecutor| {
            let shared_voter_state = sc_consensus_grandpa::SharedVoterState::empty();
            let deps = crate::rpc::FullDeps {
                client: client.clone(),
                select_chain: select_chain.clone(),
                pool: transaction_pool.clone(),
                graph: transaction_pool.pool().clone(),
                network: network.clone(),
                sync: sync.clone(),
                is_authority,
                deny_unsafe,
                frontier_backend: frontier_backend.clone(),
                filter_pool: filter_pool.clone(),
                fee_history_limit: FEE_HISTORY_LIMIT,
                fee_history_cache: fee_history_cache.clone(),
                block_data_cache: block_data_cache.clone(),
                overrides: overrides.clone(),
                enable_evm_rpc: true, // enable EVM RPC for dev node by default
                pending_create_inherent_data_providers: pending_create_inherent_data_providers,
                babe: crate::rpc::BabeDeps {
                    keystore: keystore.clone(),
                    worker_handle: worker_handle.clone(),
                },
                grandpa: crate::rpc::GrandpaDeps {
                    shared_voter_state,
                    shared_authority_set: shared_authority_set.clone(),
                    justification_stream: justification_stream.clone(),
                    subscription_executor: subscription.clone(),
                    finality_provider: finality_provider.clone(),
                },
                #[cfg(feature = "manual-seal")]
                command_sink: Some(command_sink.clone()),
            };

            crate::rpc::create_full(
                deps,
                subscription,
                pubsub_notification_sinks.clone(),
                #[cfg(feature = "evm-tracing")]
                crate::rpc::EvmTracingConfig {
                    tracing_requesters: tracing_requesters.clone(),
                    trace_filter_max_count: evm_tracing_config.ethapi_trace_max_count,
                    enable_txpool: ethapi_cmd.contains(&EthApiCmd::TxPool),
                },
            )
            .map_err::<ServiceError, _>(Into::into)
        })
    };


    let _rpc_handlers = sc_service::spawn_tasks(sc_service::SpawnTasksParams {
        network: network.clone(),
        client: client.clone(),
        keystore: keystore_container.keystore(),
        task_manager: &mut task_manager,
        transaction_pool: transaction_pool.clone(),
        rpc_builder: rpc_extensions_builder,
        backend,
        system_rpc_tx,
        tx_handler_controller,
        sync_service: sync_service.clone(),
        config,
        telemetry: telemetry.as_mut(),
    })?;

    if role.is_authority() {
        let proposer_factory = sc_basic_authorship::ProposerFactory::new(
            task_manager.spawn_handle(),
            client.clone(),
            transaction_pool.clone(),
            prometheus_registry.as_ref(),
            telemetry.as_ref().map(|x| x.handle()),
        );

        let slot_duration = babe_link.config().slot_duration();

        #[cfg(feature = "manual-seal")]
        let babe = sc_consensus_manual_seal::run_manual_seal(
            sc_consensus_manual_seal::ManualSealParams {
                block_import,
                env: proposer_factory,
                client: client.clone(),
                pool: transaction_pool.clone(),
                commands_stream,
                select_chain,
                consensus_data_provider: Some(Box::new(
                    sc_consensus_manual_seal::consensus::babe::BabeConsensusDataProvider::new(
                        client.clone(),
                    ),
                )),
                create_inherent_data_providers: move |_, ()| async move {
                    let timestamp = sp_timestamp::InherentDataProvider::from_system_time();
                    let slot =
                        sp_consensus_babe::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
                            *timestamp,
                            slot_duration.clone(),
                        );

                    Ok((slot, timestamp))
                },
            },
        );

        #[cfg(not(feature = "manual-seal"))]
        let babe_config = sc_consensus_babe::BabeParams {
            keystore: keystore_container.keystore(),
            client: client.clone(),
            select_chain,
            env: proposer_factory,
            block_import,
            sync_oracle: sync_service.clone(),
            justification_sync_link: sync_service.clone(),
            create_inherent_data_providers: move |parent, ()| {
                let client_clone = client.clone();
                async move {
                    let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

                    let slot =
                        sp_consensus_babe::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
                            *timestamp,
                            slot_duration,
                        );

                    let storage_proof =
                        sp_transaction_storage_proof::registration::new_data_provider(
                            &*client_clone,
                            &parent,
                        )?;


                    Ok((slot, timestamp, storage_proof))
                }
            },
            force_authoring,
            backoff_authoring_blocks,
            babe_link,
            block_proposal_slot_portion: SlotProportion::new(0.5),
            max_block_proposal_slot_portion: None,
            telemetry: telemetry.as_ref().map(|x| x.handle()),
        };
        let babe = sc_consensus_babe::start_babe(babe_config)?;

        // we spawn the future on a background thread managed by service.
        task_manager
            .spawn_essential_handle()
            .spawn_blocking("babe-proposer", Some("block-authoring"), babe);
    }

    // if the node isn't actively participating in consensus then it doesn't
    // need a keystore, regardless of which protocol we use below.
    let keystore = if role.is_authority() {
        Some(keystore_container.keystore())
    } else {
        None
    };

    let grandpa_config = sc_consensus_grandpa::Config {
        // FIXME #1578 make this available through chainspec
        gossip_duration: Duration::from_millis(333),
        justification_generation_period: GRANDPA_JUSTIFICATION_PERIOD,
        name: Some(name),
        observer_enabled: false,
        keystore,
        local_role: role,
        telemetry: telemetry.as_ref().map(|x| x.handle()),
        protocol_name,
    };

    if enable_grandpa {
        // start the full GRANDPA voter
        // NOTE: non-authorities could run the GRANDPA observer protocol, but at
        // this point the full voter should provide better guarantees of block
        // and vote data availability than the observer. The observer has not
        // been tested extensively yet and having most nodes in a network run it
        // could lead to finality stalls.
        let grandpa_config = sc_consensus_grandpa::GrandpaParams {
            config: grandpa_config,
            link: grandpa_link,
            network:network.clone(),
            sync: Arc::new(sync_service.clone()),
            notification_service: grandpa_notification_service,
            voting_rule: sc_consensus_grandpa::VotingRulesBuilder::default().build(),
            prometheus_registry,
            shared_voter_state: SharedVoterState::empty(),
            telemetry: telemetry.as_ref().map(|x| x.handle()),
            offchain_tx_pool_factory: OffchainTransactionPoolFactory::new(transaction_pool),
        };

        // the GRANDPA voter task is considered infallible, i.e.
        // if it fails we take down the service with it.
        task_manager.spawn_essential_handle().spawn_blocking(
            "grandpa-voter",
            None,
            sc_consensus_grandpa::run_grandpa_voter(grandpa_config)?,
        );
    }

    
    task_manager.spawn_essential_handle().spawn_blocking(
        "tss-p2p",
        None,
        setup_gossip(
            c, 
            network, 
            sync_service, 
            tss_notification_service, 
            tss_protocol_name, 
            keystore_container,
            PhantomData::<Block>,
            PhantomData::<pallet_tss::Event<Runtime>>
        ).unwrap(),
    );


    network_starter.start_network();

    Ok(task_manager)
}
