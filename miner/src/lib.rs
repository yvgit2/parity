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

#![warn(missing_docs)]
#![cfg_attr(all(nightly, feature="dev"), feature(plugin))]
#![cfg_attr(all(nightly, feature="dev"), plugin(clippy))]

//! Miner module
//! Keeps track of transactions and mined block.
//!
//! Usage example:
//!
//! ```rust
//! extern crate ethcore_util as util;
//! extern crate ethcore;
//! extern crate ethminer;
//! use std::env;
//! use util::network::{NetworkService, NetworkConfiguration};
//! use ethcore::client::{Client, ClientConfig};
//! use ethcore::ethereum;
//! use ethminer::{Miner, MinerService};
//!
//! fn main() {
//!		let miner: Miner = Miner::default();
//!		// get status
//!		assert_eq!(miner.status().transactions_in_pending_queue, 0);
//!
//!		// Check block for sealing
//!		//assert!(miner.sealing_block(client.deref()).lock().unwrap().is_some());
//! }
//! ```


#[macro_use]
extern crate log;
#[macro_use]
extern crate ethcore_util as util;
extern crate ethcore;
extern crate env_logger;
extern crate rayon;

mod miner;
mod external;
mod transaction_queue;

pub use transaction_queue::{TransactionQueue, AccountDetails, TransactionImportResult, TransactionOrigin};
pub use miner::{Miner};
pub use external::{ExternalMiner, ExternalMinerService};

use std::collections::BTreeMap;
use util::{H256, U256, Address, Bytes};
use ethcore::client::{BlockChainClient, Executed};
use ethcore::block::{ClosedBlock};
use ethcore::receipt::{Receipt};
use ethcore::error::{Error, ExecutionError};
use ethcore::transaction::SignedTransaction;

/// Miner client API
pub trait MinerService : Send + Sync {

	/// Returns miner's status.
	fn status(&self) -> MinerStatus;

	/// Get the author that we will seal blocks as.
	fn author(&self) -> Address;

	/// Set the author that we will seal blocks as.
	fn set_author(&self, author: Address);

	/// Get the extra_data that we will seal blocks with.
	fn extra_data(&self) -> Bytes;

	/// Set the extra_data that we will seal blocks with.
	fn set_extra_data(&self, extra_data: Bytes);

	/// Get current minimal gas price for transactions accepted to queue.
	fn minimal_gas_price(&self) -> U256;

	/// Set minimal gas price of transaction to be accepted for mining.
	fn set_minimal_gas_price(&self, min_gas_price: U256);

	/// Get the gas limit we wish to target when sealing a new block.
	fn gas_floor_target(&self) -> U256;

	/// Set the gas limit we wish to target when sealing a new block.
	fn set_gas_floor_target(&self, target: U256);

	/// Get current transactions limit in queue.
	fn transactions_limit(&self) -> usize;

	/// Set maximal number of transactions kept in the queue (both current and future).
	fn set_transactions_limit(&self, limit: usize);

	/// Imports transactions to transaction queue.
	fn import_transactions<T>(&self, transactions: Vec<SignedTransaction>, fetch_account: T) ->
		Vec<Result<TransactionImportResult, Error>>
		where T: Fn(&Address) -> AccountDetails;

	/// Imports own (node owner) transaction to queue.
	fn import_own_transaction<T>(&self, chain: &BlockChainClient, transaction: SignedTransaction, fetch_account: T) ->
		Result<TransactionImportResult, Error>
		where T: Fn(&Address) -> AccountDetails;

	/// Returns hashes of transactions currently in pending
	fn pending_transactions_hashes(&self) -> Vec<H256>;

	/// Removes all transactions from the queue and restart mining operation.
	fn clear_and_reset(&self, chain: &BlockChainClient);

	/// Called when blocks are imported to chain, updates transactions queue.
	fn chain_new_blocks(&self, chain: &BlockChainClient, imported: &[H256], invalid: &[H256], enacted: &[H256], retracted: &[H256]);

	/// New chain head event. Restart mining operation.
	fn update_sealing(&self, chain: &BlockChainClient);

	/// Submit `seal` as a valid solution for the header of `pow_hash`.
	/// Will check the seal, but not actually insert the block into the chain.
	fn submit_seal(&self, chain: &BlockChainClient, pow_hash: H256, seal: Vec<Bytes>) -> Result<(), Error>;

	/// Get the sealing work package and if `Some`, apply some transform.
	fn map_sealing_work<F, T>(&self, chain: &BlockChainClient, f: F) -> Option<T> where F: FnOnce(&ClosedBlock) -> T;

	/// Query pending transactions for hash.
	fn transaction(&self, hash: &H256) -> Option<SignedTransaction>;

	/// Get a list of all transactions.
	fn all_transactions(&self) -> Vec<SignedTransaction>;

	/// Get a list of all pending transactions.
	fn pending_transactions(&self) -> Vec<SignedTransaction>;

	/// Get a list of all pending receipts.
	fn pending_receipts(&self) -> BTreeMap<H256, Receipt>;

	/// Returns highest transaction nonce for given address.
	fn last_nonce(&self, address: &Address) -> Option<U256>;

	/// Suggested gas price.
	fn sensible_gas_price(&self) -> U256 { x!(20000000000u64) }

	/// Suggested gas limit.
	fn sensible_gas_limit(&self) -> U256 { x!(21000) }

	/// Account balance
	fn balance(&self, chain: &BlockChainClient, address: &Address) -> U256;

	/// Call into contract code using pending state.
	fn call(&self, chain: &BlockChainClient, t: &SignedTransaction) -> Result<Executed, ExecutionError>;

	/// Get storage value in pending state.
	fn storage_at(&self, chain: &BlockChainClient, address: &Address, position: &H256) -> H256;

	/// Get account nonce in pending state.
	fn nonce(&self, chain: &BlockChainClient, address: &Address) -> U256;

	/// Get contract code in pending state.
	fn code(&self, chain: &BlockChainClient, address: &Address) -> Option<Bytes>;
}

/// Mining status
#[derive(Debug)]
pub struct MinerStatus {
	/// Number of transactions in queue with state `pending` (ready to be included in block)
	pub transactions_in_pending_queue: usize,
	/// Number of transactions in queue with state `future` (not yet ready to be included in block)
	pub transactions_in_future_queue: usize,
	/// Number of transactions included in currently mined block
	pub transactions_in_pending_block: usize,
}
