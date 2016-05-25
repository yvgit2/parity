// Copyright 2015, 2016 Ethcore (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

pub use block_queue::BlockQueueConfig;
pub use blockchain::BlockChainConfig;
pub use trace::{Config as TraceConfig, Switch};
pub use evm::VMType;
use util::journaldb;

/// Client configuration. Includes configs for all sub-systems.
#[derive(Debug, Default)]
pub struct ClientConfig {
	/// Block queue configuration.
	pub queue: BlockQueueConfig,
	/// Blockchain configuration.
	pub blockchain: BlockChainConfig,
	/// Trace configuration.
	pub tracing: TraceConfig,
	/// VM type.
	pub vm_type: VMType,
	/// The JournalDB ("pruning") algorithm to use.
	pub pruning: journaldb::Algorithm,
	/// The name of the client instance.
	pub name: String,
}
