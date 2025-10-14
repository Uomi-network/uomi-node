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


#[cfg(feature = "evm-tracing")]
use crate::evm_tracing_types::EthApiOptions;
#[cfg(feature = "sc-cli")]
use sc_cli::RunCmd;

/// An overarching CLI command definition.
#[derive(Debug, clap::Parser)]
pub struct Cli {
    /// Possible subcommand with parameters.
    #[clap(subcommand)]
    pub subcommand: Option<Subcommand>,

    #[allow(missing_docs)]
    #[clap(flatten)]
    #[cfg(feature = "sc-cli")]
    pub run: RunCmd,

    #[allow(missing_docs)]
    #[cfg(feature = "evm-tracing")]
    #[clap(flatten)]
    pub eth_api_options: EthApiOptions,

    /// Enable Ethereum compatible JSON-RPC servers (disabled by default).
    #[clap(name = "enable-evm-rpc", long)]
    pub enable_evm_rpc: bool,

    /// Proposer's maximum block size limit in bytes
    #[clap(long, default_value = sc_basic_authorship::DEFAULT_BLOCK_SIZE_LIMIT.to_string())]
    pub proposer_block_size_limit: usize,

    /// Proposer's soft deadline in percents of block size
    #[clap(long, default_value = "50")]
    pub proposer_soft_deadline_percent: u8,
}

/// Possible subcommands of the main binary.
#[derive(Debug, clap::Subcommand)]
pub enum Subcommand {
    /// Key management cli utilities (only with sc-cli feature)
    #[cfg(feature = "sc-cli")]
    #[clap(subcommand)]
    Key(sc_cli::KeySubcommand),
    #[cfg(feature = "sc-cli")]
    Verify(sc_cli::VerifyCmd),
    #[cfg(feature = "sc-cli")]
    Vanity(sc_cli::VanityCmd),
    #[cfg(feature = "sc-cli")]
    Sign(sc_cli::SignCmd),
    #[cfg(feature = "sc-cli")]
    BuildSpec(sc_cli::BuildSpecCmd),
    #[cfg(feature = "sc-cli")]
    CheckBlock(sc_cli::CheckBlockCmd),
    #[cfg(feature = "sc-cli")]
    ExportBlocks(sc_cli::ExportBlocksCmd),
    #[cfg(feature = "sc-cli")]
    ExportState(sc_cli::ExportStateCmd),
    #[cfg(feature = "sc-cli")]
    ImportBlocks(sc_cli::ImportBlocksCmd),
    #[cfg(feature = "sc-cli")]
    PurgeChain(sc_cli::PurgeChainCmd),
    #[cfg(feature = "sc-cli")]
    Revert(sc_cli::RevertCmd),
    #[cfg(all(feature = "runtime-benchmarks", feature = "sc-cli"))]
    #[clap(name = "benchmark", about = "Benchmark runtime pallets.")]
    #[clap(subcommand)]
    Benchmark(frame_benchmarking_cli::BenchmarkCmd),
    /// Placeholder / fallback (always present)
    TryRuntime,
}


