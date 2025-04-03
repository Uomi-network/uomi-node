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

//! Uomi library.


#![warn(unused_extern_crates)]

/// Development node support.
pub mod local;

/// uomi mainnet node.
pub mod uomi;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

mod consensus_data_provider;
mod cli;
mod command;
mod evm_tracing_types;
mod rpc;

pub use cli::*;
pub use command::*;
