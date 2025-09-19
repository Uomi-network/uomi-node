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

//! Uomi CLI handlers.
use crate::{
    cli::{Cli, Subcommand},
    local::{self, development_config},
    uomi::{self, mainnet_config, chain_spec as chain_spec_uomi},
};
use sc_cli::{
       Result, SubstrateCli,
};
use sc_service::PartialComponents;

#[cfg(feature = "runtime-benchmarks")]
use frame_benchmarking_cli::{BenchmarkCmd, ExtrinsicFactory, SUBSTRATE_REFERENCE_HARDWARE};

trait IdentifyChain {
    fn is_dev(&self) -> bool;
    fn is_uomi(&self) -> bool;
}

impl IdentifyChain for dyn sc_service::ChainSpec {
    fn is_dev(&self) -> bool {
        self.id().starts_with("dev")
    }
    fn is_uomi(&self) -> bool {
        self.id().starts_with("uomi")
    }
}

impl<T: sc_service::ChainSpec + 'static> IdentifyChain for T {
    fn is_dev(&self) -> bool {
        <dyn sc_service::ChainSpec>::is_dev(self)
    }
    fn is_uomi(&self) -> bool {
        <dyn sc_service::ChainSpec>::is_uomi(self)
    }
}

fn load_spec(id: &str) -> std::result::Result<Box<dyn sc_service::ChainSpec>, String> {
    Ok(match id {
        "dev" => Box::new(development_config()),
        "uomi" => Box::new(mainnet_config()),
        path => {
            Box::new(chain_spec_uomi::ChainSpec::from_json_file(std::path::PathBuf::from(path))?)
        },
    })
}

impl SubstrateCli for Cli {
    fn impl_name() -> String {
        "Uomi".into()
    }

    fn impl_version() -> String {
        env!("SUBSTRATE_CLI_IMPL_VERSION").into()
    }

    fn description() -> String {
            "Uomi".into()
    }

    fn author() -> String {
        env!("CARGO_PKG_AUTHORS").into()
    }

    fn support_url() -> String {
        "https://github.com/Uomi-network/uomi-node/issues/new".into()
    }

    fn copyright_start_year() -> i32 {
        2024
    }

    fn load_spec(&self, id: &str) -> std::result::Result<Box<dyn sc_service::ChainSpec>, String> {
        load_spec(id)
    }
}


/// Parse command line arguments into service configuration.
pub fn run() -> Result<()> {
    let cli = Cli::from_args();

    match &cli.subcommand {
        Some(Subcommand::BuildSpec(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.sync_run(|config| cmd.run(config.chain_spec, config.network))
        }
        Some(Subcommand::CheckBlock(cmd)) => {
			let runner = cli.create_runner(cmd)?;
            if runner.config().chain_spec.is_uomi() {
			runner.async_run(|config| {
				let PartialComponents { client, task_manager, import_queue, .. } =
					uomi::new_partial(&config)?;
				Ok((cmd.run(client, import_queue), task_manager))
			})
            } else {
                runner.async_run(|config| {
                    let PartialComponents { client, task_manager, import_queue, .. } =
                        local::new_partial(&config)?;
                    Ok((cmd.run(client, import_queue), task_manager))
                })
            }
		},
        Some(Subcommand::ExportBlocks(cmd)) => {
			let runner = cli.create_runner(cmd)?;
            if runner.config().chain_spec.is_uomi() {
                runner.async_run(|config| {
                    let PartialComponents { client, task_manager, .. } = uomi::new_partial(&config)?;
                    Ok((cmd.run(client, config.database), task_manager))
                })
            } else {
                runner.async_run(|config| {
                    let PartialComponents { client, task_manager, .. } = local::new_partial(&config)?;
                    Ok((cmd.run(client, config.database), task_manager))
                })
            }
		},
        Some(Subcommand::ExportState(cmd)) => {
			let runner = cli.create_runner(cmd)?;
            if runner.config().chain_spec.is_uomi() {
                runner.async_run(|config| {
                    let PartialComponents { client, task_manager, .. } = uomi::new_partial(&config)?;
                    Ok((cmd.run(client, config.chain_spec), task_manager))
                })
            } else {
                runner.async_run(|config| {
                    let PartialComponents { client, task_manager, .. } = local::new_partial(&config)?;
                    Ok((cmd.run(client, config.chain_spec), task_manager))
                })
            }
		},
		Some(Subcommand::ImportBlocks(cmd)) => {
			let runner = cli.create_runner(cmd)?;
            if runner.config().chain_spec.is_uomi() {
                runner.async_run(|config| {
                    let PartialComponents { client, task_manager, import_queue, .. } =
                        uomi::new_partial(&config)?;
                    Ok((cmd.run(client, import_queue), task_manager))
                })
            } else {
                runner.async_run(|config| {
                    let PartialComponents { client, task_manager, import_queue, .. } =
                        local::new_partial(&config)?;
                    Ok((cmd.run(client, import_queue), task_manager))
                })
            }
		},
		Some(Subcommand::PurgeChain(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.sync_run(|config| cmd.run(config.database))
		},
        Some(Subcommand::Revert(cmd)) => {
			let runner = cli.create_runner(cmd)?;
            if runner.config().chain_spec.is_uomi() {
                runner.async_run(|config| {
                    let PartialComponents { client, task_manager, backend, .. } =
                        uomi::new_partial(&config)?;
                    let aux_revert = Box::new(|client, _, blocks| {
                        sc_consensus_grandpa::revert(client, blocks)?;
                        Ok(())
                    });
                    Ok((cmd.run(client, backend, Some(aux_revert)), task_manager))
                })
            } else {
                runner.async_run(|config| {
                    let PartialComponents { client, task_manager, backend, .. } =
                        local::new_partial(&config)?;
                    let aux_revert = Box::new(|client, _, blocks| {
                        sc_consensus_grandpa::revert(client, blocks)?;
                        Ok(())
                    });
                    Ok((cmd.run(client, backend, Some(aux_revert)), task_manager))
                })
            }
			
		},
        Some(Subcommand::Key(cmd)) => cmd.run(&cli),
        Some(Subcommand::Sign(cmd)) => cmd.run(),
        Some(Subcommand::Verify(cmd)) => cmd.run(),
        Some(Subcommand::Vanity(cmd)) => cmd.run(),
        #[cfg(feature = "runtime-benchmarks")]
        Some(Subcommand::Benchmark(cmd)) => {
            use crate::benchmarking::*;
            use sp_keyring::Sr25519Keyring;
            use sp_runtime::traits::HashingFor;

            let runner = cli.create_runner(cmd)?;

            match cmd {
                BenchmarkCmd::Pallet(cmd) => {
                    if chain_spec.is_uomi() {
                        runner.sync_run(|config| {
                            cmd.run::<HashingFor<uomi_runtime::Block>, uomi::HostFunctions>(
                                config,
                            )
                        })
                    } else {
                        runner.sync_run(|config| {
                            cmd.run::<HashingFor<local_runtime::Block>, local::HostFunctions>(
                                config,
                            )
                        })
                    }
                }
                BenchmarkCmd::Block(cmd) => {

                    if chain_spec.is_uomi() {    
                        runner.sync_run(|config| {
                            let params = uomi::new_partial(&config)?;
                            cmd.run(params.client)
                        })
                    } else {
                        runner.sync_run(|config| {
                            let params = local::new_partial(&config)?;
                            cmd.run(params.client)
                        })
                    }
                    
                }
                BenchmarkCmd::Storage(cmd) => {

                    if chain_spec.is_uomi() {
                        runner.sync_run(|config| {
                            let params = uomi::new_partial(&config)?;
                            let db = params.backend.expose_db();
                            let storage = params.backend.expose_storage();

                            cmd.run(config, params.client, db, storage)
                        })
                    } else {
                        runner.sync_run(|config| {
                            let params = local::new_partial(&config)?;
                            let db = params.backend.expose_db();
                            let storage = params.backend.expose_storage();

                            cmd.run(config, params.client, db, storage)
                        })
                    }
                    
                }
                BenchmarkCmd::Overhead(cmd) => {
                    if chain_spec.is_uomi() {
                        runner.sync_run(|config| {
                            let params = uomi::new_partial(&config)?;
                            let ext_builder = RemarkBuilder::new(params.client.clone());
                            let inherent_data = uomi_benchmark_inherent_data()
                                .map_err(|e| format!("generating inherent data: {:?}", e))?;

                            cmd.run(
                                config,
                                params.client,
                                inherent_data,
                                Vec::new(),
                                &ext_builder,
                            )
                        })
                    } else {
                        runner.sync_run(|config| {
                            let params = local::new_partial(&config)?;
                            let ext_builder = RemarkBuilder::new(params.client.clone());
                            let inherent_data = local_benchmark_inherent_data()
                                .map_err(|e| format!("generating inherent data: {:?}", e))?;

                            cmd.run(
                                config,
                                params.client,
                                inherent_data,
                                Vec::new(),
                                &ext_builder,
                            )
                        })
                    }
                }
                BenchmarkCmd::Extrinsic(cmd) => {
                    if chain_spec.is_uomi() {
                        runner.sync_run(|config| {
                            let params = uomi::new_partial(&config)?;
                            let remark_builder = RemarkBuilder::new(params.client.clone());
                            let tka_builder = TransferKeepAliveBuilder::new(
                                params.client.clone(),
                                Sr25519Keyring::Alice.to_account_id(),
                                params.client.existential_deposit(),
                            );
                            let ext_factory = ExtrinsicFactory(vec![
                                Box::new(remark_builder),
                                Box::new(tka_builder),
                            ]);
                            let inherent_data = uomi_benchmark_inherent_data()
                                .map_err(|e| format!("generating inherent data: {:?}", e))?;

                            cmd.run(params.client, inherent_data, Vec::new(), &ext_factory)
                        })
                    } else {
                        runner.sync_run(|config| {
                            let params = local::new_partial(&config)?;
                            let remark_builder = RemarkBuilder::new(params.client.clone());
                            let tka_builder = TransferKeepAliveBuilder::new(
                                params.client.clone(),
                                Sr25519Keyring::Alice.to_account_id(),
                                params.client.existential_deposit(),
                            );
                            let ext_factory = ExtrinsicFactory(vec![
                                Box::new(remark_builder),
                                Box::new(tka_builder),
                            ]);
                            let inherent_data = local_benchmark_inherent_data()
                                .map_err(|e| format!("generating inherent data: {:?}", e))?;

                            cmd.run(params.client, inherent_data, Vec::new(), &ext_factory)
                        })
                    }
                    
                }
                BenchmarkCmd::Machine(cmd) => {
                    runner.sync_run(|config| cmd.run(&config, SUBSTRATE_REFERENCE_HARDWARE.clone()))
                }
            }
        }
        Some(Subcommand::TryRuntime) => Err("The `try-runtime` subcommand has been migrated to a \
        standalone CLI (https://github.com/paritytech/try-runtime-cli). It is no longer \
        being maintained here and will be removed entirely some time after January 2024. \
        Please remove this subcommand from your runtime and use the standalone CLI."
            .into()),
        None => {
            let runner = cli.create_runner(&cli.run)?;
      

            #[cfg(feature = "evm-tracing")]
            let evm_tracing_config = crate::evm_tracing_types::EvmTracingConfig {
                ethapi: cli.eth_api_options.ethapi,
                ethapi_max_permits: cli.eth_api_options.ethapi_max_permits,
                ethapi_trace_max_count: cli.eth_api_options.ethapi_trace_max_count,
                ethapi_trace_cache_duration: cli.eth_api_options.ethapi_trace_cache_duration,
                eth_log_block_cache: cli.eth_api_options.eth_log_block_cache,
                eth_statuses_cache: cli.eth_api_options.eth_statuses_cache,
                max_past_logs: cli.eth_api_options.max_past_logs,
                tracing_raw_max_memory_usage: cli.eth_api_options.tracing_raw_max_memory_usage,
            };

            runner.run_node_until_exit(|config| async move {
                log::info!("🧠 Uomi engine active, starting to process requests");
                if config.chain_spec.is_uomi() {
                    return uomi::start_node::<sc_network::NetworkWorker<_, _>>(config, #[cfg(feature = "evm-tracing")] evm_tracing_config).map_err(Into::into);
                } else {
                    return local::start_node::<sc_network::NetworkWorker<_, _>>(config, #[cfg(feature = "evm-tracing")] evm_tracing_config).map_err(Into::into);
                }

            })
        },
    }
    
}

