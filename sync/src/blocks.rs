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

use util::*;
use ethcore::header::{ Header as BlockHeader};

known_heap_size!(0, HeaderId, SyncBlock);

struct SyncBlock {
	header: Bytes,
	body: Option<Bytes>,
	next: Option<H256>,
}

/// Used to identify header by transactions and uncles hashes
#[derive(Eq, PartialEq, Hash)]
struct HeaderId {
	transactions_root: H256,
	uncles: H256
}

/// Downloader block collection
pub struct BlockCollection {
	/// Heads of subchains to download
	heads: Vec<H256>,
	/// Downloaded blocks.
	blocks: HashMap<H256, SyncBlock>,
	/// Downloaded blocks by parent.
	parents: HashMap<H256, H256>,
	/// Used to map body to header.
	header_ids: HashMap<HeaderId, H256>,
	/// First block in `blocks`.
	head: Option<H256>,
	/// Set of block header hashes being downloaded
	downloading_headers: HashSet<H256>,
	/// Set of block bodies being downloaded identified by block hash.
	downloading_bodies: HashSet<H256>,
}

impl BlockCollection {
	pub fn new() -> BlockCollection {
		BlockCollection {
			blocks: HashMap::new(),
			header_ids: HashMap::new(),
			heads: Vec::new(),
			parents: HashMap::new(),
			head: None,
			downloading_headers: HashSet::new(),
			downloading_bodies: HashSet::new(),
		}
	}

	pub fn clear(&mut self) {
		self.blocks.clear();
		self.parents.clear();
		self.header_ids.clear();
		self.heads.clear();
		self.head = None;
		self.downloading_headers.clear();
		self.downloading_bodies.clear();
	}

	fn insert_header(&mut self, header: Bytes) -> Result<H256, UtilError> {
		let info: BlockHeader = try!(UntrustedRlp::new(&header).as_val());
		let hash = info.hash();
		debug_assert!(!self.blocks.contains_key(&hash));

		let mut block = SyncBlock {
			header: header,
			next: None,
			body: None,
		};
		let header_id = HeaderId {
			transactions_root: info.transactions_root,
			uncles: info.uncles_hash
		};
		if header_id.transactions_root == rlp::SHA3_NULL_RLP && header_id.uncles == rlp::SHA3_EMPTY_LIST_RLP {
			// empty body, just mark as downloaded
			let mut body_stream = RlpStream::new_list(2);
			body_stream.append_raw(&rlp::NULL_RLP, 1);
			body_stream.append_raw(&rlp::EMPTY_LIST_RLP, 1);
			block.body = Some(body_stream.out());
		}
		else {
			self.header_ids.insert(header_id, hash.clone());
		}

		if let Some(p) = self.parents.get(&hash) {
			block.next = Some(p.clone());
		}
		if let Some(ref mut parent) = self.blocks.get_mut(&info.parent_hash) {
			parent.next = Some(hash.clone());
		}
		self.parents.insert(info.parent_hash.clone(), hash.clone());
		self.blocks.insert(hash.clone(), block);
		Ok(hash)
	}

	pub fn reset_to(&mut self, hashes: Vec<H256>) {
		self.clear();
		self.heads = hashes;
	}

	pub fn insert_headers(&mut self, headers: Vec<Bytes>) {
		for h in headers.into_iter() {
			if let Err(e) =  self.insert_header(h) {
				trace!(target: "sync", "Ignored invalid header: {:?}", e);
			}
		}
		self.update_heads();
	}

	fn insert_body(&mut self, b: Bytes) -> Result<(), UtilError> {
		let body = UntrustedRlp::new(&b);
		let tx = try!(body.at(0));
		let tx_root = ordered_trie_root(tx.iter().map(|r| r.as_raw().to_vec()).collect()); //TODO: get rid of vectors here
		let uncles = try!(body.at(1)).as_raw().sha3();
		let header_id = HeaderId {
			transactions_root: tx_root,
			uncles: uncles
		};
		match self.header_ids.get(&header_id).cloned() {
			Some(h) => {
				self.header_ids.remove(&header_id);
				match self.blocks.get_mut(&h) {
					Some(ref mut block) => {
						trace!(target: "sync", "Got body {}", h);
						block.body = Some(body.as_raw().to_vec());
					},
					None => warn!("Got body with no header {}", h)
				}
			}
			None => trace!(target: "sync", "Ignored unknown/stale block body")
		};
		Ok(())
	}

	pub fn insert_bodies(&mut self, bodies: Vec<Bytes>) {
		for b in bodies.into_iter() {
			if let Err(e) =  self.insert_body(b) {
				trace!(target: "sync", "Ignored invalid body: {:?}", e);
			}
		}
	}

	// update subchain headers
	fn update_heads(&mut self) {
		let mut new_heads = Vec::new();
		let old_subchains: HashSet<_> = { self.heads.iter().map(Clone::clone).collect() };
		for s in self.heads.drain(..) {
			let mut h = s.clone();
			loop {
				match self.blocks.get(&h) {
					Some(block) if block.next.is_some() => {
						h = block.next.unwrap();
						if old_subchains.contains(&h) {
							trace!("Completed subchain {:?}", s);
							break; // reached head of the other subchain, merge by not adding
						}
					},
					_ => {
						new_heads.push(h);
						break;
					}
				}
			}
		}
		self.heads = new_heads;
	}

	pub fn needed_bodies(&mut self, count: usize, _ignore_downloading: bool) -> Vec<H256> {
		if self.head.is_none() {
			return Vec::new();
		}
		let mut needed_bodies: Vec<H256> = Vec::new();
		let mut head = self.head;
		while head.is_some() && needed_bodies.len() < count {
			match self.blocks.get(&head.unwrap()) {
				Some(block) if block.body.is_none() && block.next.is_some() => {
					needed_bodies.push(head.unwrap().clone());
					head = block.next.clone();
				}
				Some(block) => {
					head = block.next.clone();
				}
				_ => break,
			}
		}
		self.downloading_bodies.extend(needed_bodies.iter());
		needed_bodies
	}

	pub fn needed_headers(&mut self, count: usize, ignore_downloading: bool) -> Option<(H256, usize)> {
		// find subchain to download
		let mut download = None;
		{
			for h in &self.heads {
				if ignore_downloading || !self.downloading_headers.contains(&h) {
					self.downloading_headers.insert(h.clone());
					download = Some(h.clone());
					break;
				}
			}
		}
		download.map(|h| (h, count))
	}

	pub fn clear_download(&mut self, hash: &H256) {
		self.downloading_headers.remove(hash);
		self.downloading_bodies.remove(hash);
	}

	pub fn drain(&mut self) -> Vec<Bytes> {
		if self.blocks.is_empty() || self.head.is_none() {
			return Vec::new();
		}

		let mut drained = Vec::new();
		let mut hashes = Vec::new();
		{
			let mut head = self.head.unwrap().clone();
			let mut blocks = Vec::new();
			loop {
				match self.blocks.get(&head) {
					Some(block) if block.body.is_some() && block.next.is_some() => {
						self.head = block.next.clone();
						blocks.push(block);
						hashes.push(head);
						head = block.next.unwrap().clone();
					}
					_ => break,
				}
			}

			for block in blocks.drain(..) {
				let mut block_rlp = RlpStream::new_list(3);
				block_rlp.append_raw(&block.header, 1);
				let body = Rlp::new(&block.body.as_ref().unwrap()); // incomplete blocks are filtered out in the loop above
				block_rlp.append_raw(body.at(0).as_raw(), 1);
				block_rlp.append_raw(body.at(1).as_raw(), 1);
				drained.push(block_rlp.out());
			}
		}
		for h in hashes {
			self.blocks.remove(&h);
		}
		drained
	}

	pub fn is_empty(&self) -> bool {
		self.blocks.is_empty()
	}

	pub fn contains(&self, hash: &H256) -> bool {
		self.blocks.contains_key(hash)
	}

	pub fn heap_size(&self) -> usize {
		//TODO: other collections
		self.blocks.heap_size_of_children()
	}

	pub fn is_downloading(&self, hash: &H256) -> bool {
		self.downloading_headers.contains(hash) || self.downloading_bodies.contains(hash)
	}

}

#[cfg(test)]
mod test {

	use super::BlockCollection;
	use ethcore::client::{TestBlockChainClient, EachBlockWith, BlockId, BlockChainClient};

	fn is_empty(bc: &BlockCollection) -> bool {
		bc.heads.is_empty() &&
		bc.blocks.is_empty() &&
		bc.parents.is_empty() &&
		bc.header_ids.is_empty() &&
		bc.head.is_none() &&
		bc.downloading_headers.is_empty() &&
		bc.downloading_bodies.is_empty()
	}

	#[test]
	fn create_clear() {
		let mut bc = BlockCollection::new();
		assert!(is_empty(&bc));
		let client = TestBlockChainClient::new();
		client.add_blocks(100, EachBlockWith::Nothing);
		let hashes = (0 .. 100).map(|i| (&client as &BlockChainClient).block_hash(BlockId::Number(i)).unwrap()).collect();
		bc.reset_to(hashes);
		assert!(!is_empty(&bc));
		bc.clear();
		assert!(is_empty(&bc));
	}
}

