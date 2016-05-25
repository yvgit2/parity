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

//! Transaction Execution environment.
use common::*;
use state::*;
use engine::*;
use evm::{self, Ext, Factory};
use externalities::*;
use substate::*;
use trace::{Trace, Tracer, NoopTracer, ExecutiveTracer};
use crossbeam;

pub use types::executed::{Executed, ExecutionResult};

/// Max depth to avoid stack overflow (when it's reached we start a new thread with VM)
/// TODO [todr] We probably need some more sophisticated calculations here (limit on my machine 132)
/// Maybe something like here: `https://github.com/ethereum/libethereum/blob/4db169b8504f2b87f7d5a481819cfb959fc65f6c/libethereum/ExtVM.cpp`
const MAX_VM_DEPTH_FOR_THREAD: usize = 64;

/// Returns new address created from address and given nonce.
pub fn contract_address(address: &Address, nonce: &U256) -> Address {
	let mut stream = RlpStream::new_list(2);
	stream.append(address);
	stream.append(nonce);
	From::from(stream.out().sha3())
}

/// Transaction execution options.
pub struct TransactOptions {
	/// Enable call tracing.
	pub tracing: bool,
	/// Check transaction nonce before execution.
	pub check_nonce: bool,
}

/// Transaction executor.
pub struct Executive<'a> {
	state: &'a mut State,
	info: &'a EnvInfo,
	engine: &'a Engine,
	vm_factory: &'a Factory,
	depth: usize,
}

impl<'a> Executive<'a> {
	/// Basic constructor.
	pub fn new(state: &'a mut State, info: &'a EnvInfo, engine: &'a Engine, vm_factory: &'a Factory) -> Self {
		Executive {
			state: state,
			info: info,
			engine: engine,
			vm_factory: vm_factory,
			depth: 0,
		}
	}

	/// Populates executive from parent properties. Increments executive depth.
	pub fn from_parent(state: &'a mut State, info: &'a EnvInfo, engine: &'a Engine, vm_factory: &'a Factory, parent_depth: usize) -> Self {
		Executive {
			state: state,
			info: info,
			engine: engine,
			vm_factory: vm_factory,
			depth: parent_depth + 1,
		}
	}

	/// Creates `Externalities` from `Executive`.
	pub fn as_externalities<'_, T>(&'_ mut self, origin_info: OriginInfo, substate: &'_ mut Substate, output: OutputPolicy<'_, '_>, tracer: &'_ mut T) -> Externalities<'_, T> where T: Tracer {
		Externalities::new(self.state, self.info, self.engine, self.vm_factory, self.depth, origin_info, substate, output, tracer)
	}

	/// This function should be used to execute transaction.
	pub fn transact(&'a mut self, t: &SignedTransaction, options: TransactOptions) -> Result<Executed, ExecutionError> {
		let check = options.check_nonce;
		match options.tracing {
			true => self.transact_with_tracer(t, check, ExecutiveTracer::default()),
			false => self.transact_with_tracer(t, check, NoopTracer),
		}
	}

	/// Execute transaction/call with tracing enabled
	pub fn transact_with_tracer<T>(&'a mut self, t: &SignedTransaction, check_nonce: bool, mut tracer: T) -> Result<Executed, ExecutionError> where T: Tracer {
		let sender = try!(t.sender().map_err(|e| {
			let message = format!("Transaction malformed: {:?}", e);
			ExecutionError::TransactionMalformed(message)
		}));
		let nonce = self.state.nonce(&sender);

		let schedule = self.engine.schedule(self.info);
		let base_gas_required = U256::from(t.gas_required(&schedule));

		if t.gas < base_gas_required {
			return Err(From::from(ExecutionError::NotEnoughBaseGas { required: base_gas_required, got: t.gas }));
		}

		let init_gas = t.gas - base_gas_required;

		// validate transaction nonce
		if check_nonce && t.nonce != nonce {
			return Err(From::from(ExecutionError::InvalidNonce { expected: nonce, got: t.nonce }));
		}

		// validate if transaction fits into given block
		if self.info.gas_used + t.gas > self.info.gas_limit {
			return Err(From::from(ExecutionError::BlockGasLimitReached {
				gas_limit: self.info.gas_limit,
				gas_used: self.info.gas_used,
				gas: t.gas
			}));
		}

		// TODO: we might need bigints here, or at least check overflows.
		let balance = self.state.balance(&sender);
		let gas_cost = U512::from(t.gas) * U512::from(t.gas_price);
		let total_cost = U512::from(t.value) + gas_cost;

		// avoid unaffordable transactions
		if U512::from(balance) < total_cost {
			return Err(From::from(ExecutionError::NotEnoughCash { required: total_cost, got: U512::from(balance) }));
		}

		// NOTE: there can be no invalid transactions from this point.
		self.state.inc_nonce(&sender);
		self.state.sub_balance(&sender, &U256::from(gas_cost));

		let mut substate = Substate::new();

		let (gas_left, output) = match t.action {
			Action::Create => {
				let new_address = contract_address(&sender, &nonce);
				let params = ActionParams {
					code_address: new_address.clone(),
					address: new_address,
					sender: sender.clone(),
					origin: sender.clone(),
					gas: init_gas,
					gas_price: t.gas_price,
					value: ActionValue::Transfer(t.value),
					code: Some(t.data.clone()),
					data: None,
				};
				(self.create(params, &mut substate, &mut tracer), vec![])
			},
			Action::Call(ref address) => {
				let params = ActionParams {
					code_address: address.clone(),
					address: address.clone(),
					sender: sender.clone(),
					origin: sender.clone(),
					gas: init_gas,
					gas_price: t.gas_price,
					value: ActionValue::Transfer(t.value),
					code: self.state.code(address),
					data: Some(t.data.clone()),
				};
				// TODO: move output upstream
				let mut out = vec![];
				(self.call(params, &mut substate, BytesRef::Flexible(&mut out), &mut tracer), out)
			}
		};

		// finalize here!
		Ok(try!(self.finalize(t, substate, gas_left, output, tracer.traces().pop())))
	}

	fn exec_vm<T>(&mut self, params: ActionParams, unconfirmed_substate: &mut Substate, output_policy: OutputPolicy, tracer: &mut T)
		-> evm::Result where T: Tracer {
		// Ordinary execution - keep VM in same thread
		if (self.depth + 1) % MAX_VM_DEPTH_FOR_THREAD != 0 {
			let vm_factory = self.vm_factory;
			let mut ext = self.as_externalities(OriginInfo::from(&params), unconfirmed_substate, output_policy, tracer);
			trace!(target: "executive", "ext.schedule.have_delegate_call: {}", ext.schedule().have_delegate_call);
			return vm_factory.create().exec(params, &mut ext);
		}

		// Start in new thread to reset stack
		// TODO [todr] No thread builder yet, so we need to reset once for a while
		// https://github.com/aturon/crossbeam/issues/16
		crossbeam::scope(|scope| {
			let vm_factory = self.vm_factory;
			let mut ext = self.as_externalities(OriginInfo::from(&params), unconfirmed_substate, output_policy, tracer);

			scope.spawn(move || {
				vm_factory.create().exec(params, &mut ext)
			})
		}).join()
	}

	/// Calls contract function with given contract params.
	/// NOTE. It does not finalize the transaction (doesn't do refunds, nor suicides).
	/// Modifies the substate and the output.
	/// Returns either gas_left or `evm::Error`.
	pub fn call<T>(&mut self, params: ActionParams, substate: &mut Substate, mut output: BytesRef, tracer: &mut T)
		-> evm::Result where T: Tracer {
		// backup used in case of running out of gas
		self.state.snapshot();

		// at first, transfer value to destination
		if let ActionValue::Transfer(val) = params.value {
			self.state.transfer_balance(&params.sender, &params.address, &val);
		}
		trace!("Executive::call(params={:?}) self.env_info={:?}", params, self.info);

		let delegate_call = params.code_address != params.address;

		if self.engine.is_builtin(&params.code_address) {
			// if destination is builtin, try to execute it

			let default = [];
			let data = if let Some(ref d) = params.data { d as &[u8] } else { &default as &[u8] };

			let trace_info = tracer.prepare_trace_call(&params);

			let cost = self.engine.cost_of_builtin(&params.code_address, data);
			match cost <= params.gas {
				true => {
					self.engine.execute_builtin(&params.code_address, data, &mut output);
					self.state.clear_snapshot();

					// trace only top level calls to builtins to avoid DDoS attacks
					if self.depth == 0 {
						let mut trace_output = tracer.prepare_trace_output();
						if let Some(mut out) = trace_output.as_mut() {
							*out = output.to_owned();
						}

						tracer.trace_call(
							trace_info,
							cost,
							trace_output,
							self.depth,
							vec![],
							delegate_call
						);
					}

					Ok(params.gas - cost)
				},
				// just drain the whole gas
				false => {
					self.state.revert_snapshot();

					tracer.trace_failed_call(trace_info, self.depth, vec![], delegate_call);

					Err(evm::Error::OutOfGas)
				}
			}
		} else {
			let trace_info = tracer.prepare_trace_call(&params);
			let mut trace_output = tracer.prepare_trace_output();
			let mut subtracer = tracer.subtracer();
			let gas = params.gas;

			if params.code.is_some() {
				// part of substate that may be reverted
				let mut unconfirmed_substate = Substate::new();

				let res = {
					self.exec_vm(params, &mut unconfirmed_substate, OutputPolicy::Return(output, trace_output.as_mut()), &mut subtracer)
				};

				trace!(target: "executive", "res={:?}", res);

				let traces = subtracer.traces();
				match res {
					Ok(gas_left) => tracer.trace_call(
						trace_info,
						gas - gas_left,
						trace_output,
						self.depth,
						traces,
						delegate_call
					),
					_ => tracer.trace_failed_call(trace_info, self.depth, traces, delegate_call),
				};

				trace!(target: "executive", "substate={:?}; unconfirmed_substate={:?}\n", substate, unconfirmed_substate);

				self.enact_result(&res, substate, unconfirmed_substate);
				trace!(target: "executive", "enacted: substate={:?}\n", substate);
				res
			} else {
				// otherwise it's just a basic transaction, only do tracing, if necessary.
				self.state.clear_snapshot();

				tracer.trace_call(trace_info, U256::zero(), trace_output, self.depth, vec![], delegate_call);
				Ok(params.gas)
			}
		}
	}

	/// Creates contract with given contract params.
	/// NOTE. It does not finalize the transaction (doesn't do refunds, nor suicides).
	/// Modifies the substate.
	pub fn create<T>(&mut self, params: ActionParams, substate: &mut Substate, tracer: &mut T) -> evm::Result where T:
		Tracer {
		// backup used in case of running out of gas
		self.state.snapshot();

		// part of substate that may be reverted
		let mut unconfirmed_substate = Substate::new();

		// create contract and transfer value to it if necessary
		let prev_bal = self.state.balance(&params.address);
		if let ActionValue::Transfer(val) = params.value {
			self.state.sub_balance(&params.sender, &val);
			self.state.new_contract(&params.address, val + prev_bal);
		} else {
			self.state.new_contract(&params.address, prev_bal);
		}

		let trace_info = tracer.prepare_trace_create(&params);
		let mut trace_output = tracer.prepare_trace_output();
		let mut subtracer = tracer.subtracer();
		let gas = params.gas;
		let created = params.address.clone();

		let res = {
			self.exec_vm(params, &mut unconfirmed_substate, OutputPolicy::InitContract(trace_output.as_mut()), &mut subtracer)
		};

		match res {
			Ok(gas_left) => tracer.trace_create(
				trace_info,
				gas - gas_left,
				trace_output,
				created,
				self.depth,
				subtracer.traces()
			),
			_ => tracer.trace_failed_create(trace_info, self.depth, subtracer.traces())
		};

		self.enact_result(&res, substate, unconfirmed_substate);
		res
	}

	/// Finalizes the transaction (does refunds and suicides).
	fn finalize(&mut self, t: &SignedTransaction, substate: Substate, result: evm::Result, output: Bytes, trace: Option<Trace>) -> ExecutionResult {
		let schedule = self.engine.schedule(self.info);

		// refunds from SSTORE nonzero -> zero
		let sstore_refunds = U256::from(schedule.sstore_refund_gas) * substate.sstore_clears_count;
		// refunds from contract suicides
		let suicide_refunds = U256::from(schedule.suicide_refund_gas) * U256::from(substate.suicides.len());
		let refunds_bound = sstore_refunds + suicide_refunds;

		// real ammount to refund
		let gas_left_prerefund = match result { Ok(x) => x, _ => x!(0) };
		let refunded = cmp::min(refunds_bound, (t.gas - gas_left_prerefund) / U256::from(2));
		let gas_left = gas_left_prerefund + refunded;

		let gas_used = t.gas - gas_left;
		let refund_value = gas_left * t.gas_price;
		let fees_value = gas_used * t.gas_price;

		trace!("exec::finalize: t.gas={}, sstore_refunds={}, suicide_refunds={}, refunds_bound={}, gas_left_prerefund={}, refunded={}, gas_left={}, gas_used={}, refund_value={}, fees_value={}\n",
			t.gas, sstore_refunds, suicide_refunds, refunds_bound, gas_left_prerefund, refunded, gas_left, gas_used, refund_value, fees_value);

		trace!("exec::finalize: Refunding refund_value={}, sender={}\n", refund_value, t.sender().unwrap());
		self.state.add_balance(&t.sender().unwrap(), &refund_value);
		trace!("exec::finalize: Compensating author: fees_value={}, author={}\n", fees_value, &self.info.author);
		self.state.add_balance(&self.info.author, &fees_value);

		// perform suicides
		for address in &substate.suicides {
			self.state.kill_account(address);
		}

		match result {
			Err(evm::Error::Internal) => Err(ExecutionError::Internal),
			Err(_) => {
				Ok(Executed {
					gas: t.gas,
					gas_used: t.gas,
					refunded: U256::zero(),
					cumulative_gas_used: self.info.gas_used + t.gas,
					logs: vec![],
					contracts_created: vec![],
					output: output,
					trace: trace,
				})
			},
			_ => {
				Ok(Executed {
					gas: t.gas,
					gas_used: gas_used,
					refunded: refunded,
					cumulative_gas_used: self.info.gas_used + gas_used,
					logs: substate.logs,
					contracts_created: substate.contracts_created,
					output: output,
					trace: trace,
				})
			},
		}
	}

	fn enact_result(&mut self, result: &evm::Result, substate: &mut Substate, un_substate: Substate) {
		match *result {
			Err(evm::Error::OutOfGas)
				| Err(evm::Error::BadJumpDestination {..})
				| Err(evm::Error::BadInstruction {.. })
				| Err(evm::Error::StackUnderflow {..})
				| Err(evm::Error::OutOfStack {..}) => {
					self.state.revert_snapshot();
			},
			Ok(_) | Err(evm::Error::Internal) => {
				self.state.clear_snapshot();
				substate.accrue(un_substate);
			}
		}
	}
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
	use super::*;
	use common::*;
	use evm::{Factory, VMType};
	use substate::*;
	use tests::helpers::*;
	use trace::trace;
	use trace::{Trace, Tracer, NoopTracer, ExecutiveTracer};

	#[test]
	fn test_contract_address() {
		let address = Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
		let expected_address = Address::from_str("3f09c73a5ed19289fb9bdc72f1742566df146f56").unwrap();
		assert_eq!(expected_address, contract_address(&address, &U256::from(88)));
	}

	// TODO: replace params with transactions!
	evm_test!{test_sender_balance: test_sender_balance_jit, test_sender_balance_int}
	fn test_sender_balance(factory: Factory) {
		let sender = Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
		let address = contract_address(&sender, &U256::zero());
		let mut params = ActionParams::default();
		params.address = address.clone();
		params.sender = sender.clone();
		params.gas = U256::from(100_000);
		params.code = Some("3331600055".from_hex().unwrap());
		params.value = ActionValue::Transfer(U256::from(0x7));
		let mut state_result = get_temp_state();
		let mut state = state_result.reference_mut();
		state.add_balance(&sender, &U256::from(0x100u64));
		let info = EnvInfo::default();
		let engine = TestEngine::new(0);
		let mut substate = Substate::new();

		let gas_left = {
			let mut ex = Executive::new(&mut state, &info, &engine, &factory);
			ex.create(params, &mut substate, &mut NoopTracer).unwrap()
		};

		assert_eq!(gas_left, U256::from(79_975));
		assert_eq!(state.storage_at(&address, &H256::new()), H256::from(&U256::from(0xf9u64)));
		assert_eq!(state.balance(&sender), U256::from(0xf9));
		assert_eq!(state.balance(&address), U256::from(0x7));
		// 0 cause contract hasn't returned
		assert_eq!(substate.contracts_created.len(), 0);

		// TODO: just test state root.
	}

	evm_test!{test_create_contract_out_of_depth: test_create_contract_out_of_depth_jit, test_create_contract_out_of_depth_int}
	fn test_create_contract_out_of_depth(factory: Factory) {
		// code:
		//
		// 7c 601080600c6000396000f3006000355415600957005b60203560003555 - push 29 bytes?
		// 60 00 - push 0
		// 52
		// 60 1d - push 29
		// 60 03 - push 3
		// 60 17 - push 17
		// f0 - create
		// 60 00 - push 0
		// 55 sstore
		//
		// other code:
		//
		// 60 10 - push 16
		// 80 - duplicate first stack item
		// 60 0c - push 12
		// 60 00 - push 0
		// 39 - copy current code to memory
		// 60 00 - push 0
		// f3 - return

		let code = "7c601080600c6000396000f3006000355415600957005b60203560003555600052601d60036017f0600055".from_hex().unwrap();

		let sender = Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681").unwrap();
		let address = contract_address(&sender, &U256::zero());
		// TODO: add tests for 'callcreate'
		//let next_address = contract_address(&address, &U256::zero());
		let mut params = ActionParams::default();
		params.address = address.clone();
		params.sender = sender.clone();
		params.origin = sender.clone();
		params.gas = U256::from(100_000);
		params.code = Some(code.clone());
		params.value = ActionValue::Transfer(U256::from(100));
		let mut state_result = get_temp_state();
		let mut state = state_result.reference_mut();
		state.add_balance(&sender, &U256::from(100));
		let info = EnvInfo::default();
		let engine = TestEngine::new(0);
		let mut substate = Substate::new();

		let gas_left = {
			let mut ex = Executive::new(&mut state, &info, &engine, &factory);
			ex.create(params, &mut substate, &mut NoopTracer).unwrap()
		};

		assert_eq!(gas_left, U256::from(62_976));
		// ended with max depth
		assert_eq!(substate.contracts_created.len(), 0);
	}

	evm_test!{test_call_to_create: test_call_to_create_jit, test_call_to_create_int}
	fn test_call_to_create(factory: Factory) {
		// code:
		//
		// 7c 601080600c6000396000f3006000355415600957005b60203560003555 - push 29 bytes?
		// 60 00 - push 0
		// 52
		// 60 1d - push 29
		// 60 03 - push 3
		// 60 17 - push 17
		// f0 - create
		// 60 00 - push 0
		// 55 sstore
		//
		// other code:
		//
		// 60 10 - push 16
		// 80 - duplicate first stack item
		// 60 0c - push 12
		// 60 00 - push 0
		// 39 - copy current code to memory
		// 60 00 - push 0
		// f3 - return

		let code = "7c601080600c6000396000f3006000355415600957005b60203560003555600052601d60036017f0600055".from_hex().unwrap();

		let sender = Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681").unwrap();
		let address = contract_address(&sender, &U256::zero());
		// TODO: add tests for 'callcreate'
		//let next_address = contract_address(&address, &U256::zero());
		let mut params = ActionParams::default();
		params.address = address.clone();
		params.code_address = address.clone();
		params.sender = sender.clone();
		params.origin = sender.clone();
		params.gas = U256::from(100_000);
		params.code = Some(code.clone());
		params.value = ActionValue::Transfer(U256::from(100));
		let mut state_result = get_temp_state();
		let mut state = state_result.reference_mut();
		state.add_balance(&sender, &U256::from(100));
		let info = EnvInfo::default();
		let engine = TestEngine::new(5);
		let mut substate = Substate::new();
		let mut tracer = ExecutiveTracer::default();

		let gas_left = {
			let mut ex = Executive::new(&mut state, &info, &engine, &factory);
			let output = BytesRef::Fixed(&mut[0u8;0]);
			ex.call(params, &mut substate, output, &mut tracer).unwrap()
		};

		let expected_trace = vec![ Trace {
			depth: 0,
			action: trace::Action::Call(trace::Call {
				from: x!("cd1722f3947def4cf144679da39c4c32bdc35681"),
				to: x!("b010143a42d5980c7e5ef0e4a4416dc098a4fed3"),
				value: x!(100),
				gas: x!(100000),
				input: vec![],
			}),
			result: trace::Res::Call(trace::CallResult {
				gas_used: U256::from(55_248),
				output: vec![],
			}),
			subs: vec![Trace {
				depth: 1,
				action: trace::Action::Create(trace::Create {
					from: x!("b010143a42d5980c7e5ef0e4a4416dc098a4fed3"),
					value: x!(23),
					gas: x!(67979),
					init: vec![96, 16, 128, 96, 12, 96, 0, 57, 96, 0, 243, 0, 96, 0, 53, 84, 21, 96, 9, 87, 0, 91, 96, 32, 53, 96, 0, 53, 85]
				}),
				result: trace::Res::Create(trace::CreateResult {
					gas_used: U256::from(3224),
					address: Address::from_str("c6d80f262ae5e0f164e5fde365044d7ada2bfa34").unwrap(),
					code: vec![96, 0, 53, 84, 21, 96, 9, 87, 0, 91, 96, 32, 53, 96, 0, 53]
				}),
				subs: vec![]
			}]
		}];
		assert_eq!(tracer.traces(), expected_trace);
		assert_eq!(gas_left, U256::from(44_752));
	}

	evm_test!{test_create_contract: test_create_contract_jit, test_create_contract_int}
	fn test_create_contract(factory: Factory) {
		// code:
		//
		// 60 10 - push 16
		// 80 - duplicate first stack item
		// 60 0c - push 12
		// 60 00 - push 0
		// 39 - copy current code to memory
		// 60 00 - push 0
		// f3 - return

		let code = "601080600c6000396000f3006000355415600957005b60203560003555".from_hex().unwrap();

		let sender = Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681").unwrap();
		let address = contract_address(&sender, &U256::zero());
		// TODO: add tests for 'callcreate'
		//let next_address = contract_address(&address, &U256::zero());
		let mut params = ActionParams::default();
		params.address = address.clone();
		params.sender = sender.clone();
		params.origin = sender.clone();
		params.gas = U256::from(100_000);
		params.code = Some(code.clone());
		params.value = ActionValue::Transfer(x!(100));
		let mut state_result = get_temp_state();
		let mut state = state_result.reference_mut();
		state.add_balance(&sender, &U256::from(100));
		let info = EnvInfo::default();
		let engine = TestEngine::new(5);
		let mut substate = Substate::new();
		let mut tracer = ExecutiveTracer::default();

		let gas_left = {
			let mut ex = Executive::new(&mut state, &info, &engine, &factory);
			ex.create(params.clone(), &mut substate, &mut tracer).unwrap()
		};

		let expected_trace = vec![Trace {
			depth: 0,
			action: trace::Action::Create(trace::Create {
				from: params.sender,
				value: x!(100),
				gas: params.gas,
				init: vec![96, 16, 128, 96, 12, 96, 0, 57, 96, 0, 243, 0, 96, 0, 53, 84, 21, 96, 9, 87, 0, 91, 96, 32, 53, 96, 0, 53, 85],
			}),
			result: trace::Res::Create(trace::CreateResult {
				gas_used: U256::from(3224),
				address: params.address,
				code: vec![96, 0, 53, 84, 21, 96, 9, 87, 0, 91, 96, 32, 53, 96, 0, 53]
			}),
			subs: vec![]
		}];

		assert_eq!(tracer.traces(), expected_trace);
		assert_eq!(gas_left, U256::from(96_776));
	}

	evm_test!{test_create_contract_value_too_high: test_create_contract_value_too_high_jit, test_create_contract_value_too_high_int}
	fn test_create_contract_value_too_high(factory: Factory) {
		// code:
		//
		// 7c 601080600c6000396000f3006000355415600957005b60203560003555 - push 29 bytes?
		// 60 00 - push 0
		// 52
		// 60 1d - push 29
		// 60 03 - push 3
		// 60 e6 - push 230
		// f0 - create a contract trying to send 230.
		// 60 00 - push 0
		// 55 sstore
		//
		// other code:
		//
		// 60 10 - push 16
		// 80 - duplicate first stack item
		// 60 0c - push 12
		// 60 00 - push 0
		// 39 - copy current code to memory
		// 60 00 - push 0
		// f3 - return

		let code = "7c601080600c6000396000f3006000355415600957005b60203560003555600052601d600360e6f0600055".from_hex().unwrap();

		let sender = Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681").unwrap();
		let address = contract_address(&sender, &U256::zero());
		// TODO: add tests for 'callcreate'
		//let next_address = contract_address(&address, &U256::zero());
		let mut params = ActionParams::default();
		params.address = address.clone();
		params.sender = sender.clone();
		params.origin = sender.clone();
		params.gas = U256::from(100_000);
		params.code = Some(code.clone());
		params.value = ActionValue::Transfer(U256::from(100));
		let mut state_result = get_temp_state();
		let mut state = state_result.reference_mut();
		state.add_balance(&sender, &U256::from(100));
		let info = EnvInfo::default();
		let engine = TestEngine::new(0);
		let mut substate = Substate::new();

		let gas_left = {
			let mut ex = Executive::new(&mut state, &info, &engine, &factory);
			ex.create(params, &mut substate, &mut NoopTracer).unwrap()
		};

		assert_eq!(gas_left, U256::from(62_976));
		assert_eq!(substate.contracts_created.len(), 0);
	}

	evm_test!{test_create_contract_without_max_depth: test_create_contract_without_max_depth_jit, test_create_contract_without_max_depth_int}
	fn test_create_contract_without_max_depth(factory: Factory) {
		// code:
		//
		// 7c 601080600c6000396000f3006000355415600957005b60203560003555 - push 29 bytes?
		// 60 00 - push 0
		// 52
		// 60 1d - push 29
		// 60 03 - push 3
		// 60 17 - push 17
		// f0 - create
		// 60 00 - push 0
		// 55 sstore
		//
		// other code:
		//
		// 60 10 - push 16
		// 80 - duplicate first stack item
		// 60 0c - push 12
		// 60 00 - push 0
		// 39 - copy current code to memory
		// 60 00 - push 0
		// f3 - return

		let code = "7c601080600c6000396000f3006000355415600957005b60203560003555600052601d60036017f0".from_hex().unwrap();

		let sender = Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681").unwrap();
		let address = contract_address(&sender, &U256::zero());
		let next_address = contract_address(&address, &U256::zero());
		let mut params = ActionParams::default();
		params.address = address.clone();
		params.sender = sender.clone();
		params.origin = sender.clone();
		params.gas = U256::from(100_000);
		params.code = Some(code.clone());
		params.value = ActionValue::Transfer(U256::from(100));
		let mut state_result = get_temp_state();
		let mut state = state_result.reference_mut();
		state.add_balance(&sender, &U256::from(100));
		let info = EnvInfo::default();
		let engine = TestEngine::new(1024);
		let mut substate = Substate::new();

		{
			let mut ex = Executive::new(&mut state, &info, &engine, &factory);
			ex.create(params, &mut substate, &mut NoopTracer).unwrap();
		}

		assert_eq!(substate.contracts_created.len(), 1);
		assert_eq!(substate.contracts_created[0], next_address);
	}

	// test is incorrect, mk
	// TODO: fix (preferred) or remove
	evm_test_ignore!{test_aba_calls: test_aba_calls_jit, test_aba_calls_int}
	fn test_aba_calls(factory: Factory) {
		// 60 00 - push 0
		// 60 00 - push 0
		// 60 00 - push 0
		// 60 00 - push 0
		// 60 18 - push 18
		// 73 945304eb96065b2a98b57a48a06ae28d285a71b5 - push this address
		// 61 03e8 - push 1000
		// f1 - message call
		// 58 - get PC
		// 55 - sstore

		let code_a = "6000600060006000601873945304eb96065b2a98b57a48a06ae28d285a71b56103e8f15855".from_hex().unwrap();

		// 60 00 - push 0
		// 60 00 - push 0
		// 60 00 - push 0
		// 60 00 - push 0
		// 60 17 - push 17
		// 73 0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6 - push this address
		// 61 0x01f4 - push 500
		// f1 - message call
		// 60 01 - push 1
		// 01 - add
		// 58 - get PC
		// 55 - sstore
		let code_b = "60006000600060006017730f572e5295c57f15886f9b263e2f6d2d6c7b5ec66101f4f16001015855".from_hex().unwrap();

		let address_a = Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
		let address_b = Address::from_str("945304eb96065b2a98b57a48a06ae28d285a71b5" ).unwrap();
		let sender = Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681").unwrap();

		let mut params = ActionParams::default();
		params.address = address_a.clone();
		params.sender = sender.clone();
		params.gas = U256::from(100_000);
		params.code = Some(code_a.clone());
		params.value = ActionValue::Transfer(U256::from(100_000));

		let mut state_result = get_temp_state();
		let mut state = state_result.reference_mut();
		state.init_code(&address_a, code_a.clone());
		state.init_code(&address_b, code_b.clone());
		state.add_balance(&sender, &U256::from(100_000));

		let info = EnvInfo::default();
		let engine = TestEngine::new(0);
		let mut substate = Substate::new();

		let gas_left = {
			let mut ex = Executive::new(&mut state, &info, &engine, &factory);
			ex.call(params, &mut substate, BytesRef::Fixed(&mut []), &mut NoopTracer).unwrap()
		};

		assert_eq!(gas_left, U256::from(73_237));
		assert_eq!(state.storage_at(&address_a, &H256::from(&U256::from(0x23))), H256::from(&U256::from(1)));
	}

	// test is incorrect, mk
	// TODO: fix (preferred) or remove
	evm_test_ignore!{test_recursive_bomb1: test_recursive_bomb1_jit, test_recursive_bomb1_int}
	fn test_recursive_bomb1(factory: Factory) {
		// 60 01 - push 1
		// 60 00 - push 0
		// 54 - sload
		// 01 - add
		// 60 00 - push 0
		// 55 - sstore
		// 60 00 - push 0
		// 60 00 - push 0
		// 60 00 - push 0
		// 60 00 - push 0
		// 60 00 - push 0
		// 30 - load address
		// 60 e0 - push e0
		// 5a - get gas
		// 03 - sub
		// f1 - message call (self in this case)
		// 60 01 - push 1
		// 55 - sstore
		let sender = Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681").unwrap();
		let code = "600160005401600055600060006000600060003060e05a03f1600155".from_hex().unwrap();
		let address = contract_address(&sender, &U256::zero());
		let mut params = ActionParams::default();
		params.address = address.clone();
		params.gas = U256::from(100_000);
		params.code = Some(code.clone());
		let mut state_result = get_temp_state();
		let mut state = state_result.reference_mut();
		state.init_code(&address, code.clone());
		let info = EnvInfo::default();
		let engine = TestEngine::new(0);
		let mut substate = Substate::new();

		let gas_left = {
			let mut ex = Executive::new(&mut state, &info, &engine, &factory);
			ex.call(params, &mut substate, BytesRef::Fixed(&mut []), &mut NoopTracer).unwrap()
		};

		assert_eq!(gas_left, U256::from(59_870));
		assert_eq!(state.storage_at(&address, &H256::from(&U256::zero())), H256::from(&U256::from(1)));
		assert_eq!(state.storage_at(&address, &H256::from(&U256::one())), H256::from(&U256::from(1)));
	}

	// test is incorrect, mk
	// TODO: fix (preferred) or remove
	evm_test_ignore!{test_transact_simple: test_transact_simple_jit, test_transact_simple_int}
	fn test_transact_simple(factory: Factory) {
		let keypair = KeyPair::create().unwrap();
		let t = Transaction {
			action: Action::Create,
			value: U256::from(17),
			data: "3331600055".from_hex().unwrap(),
			gas: U256::from(100_000),
			gas_price: U256::zero(),
			nonce: U256::zero()
		}.sign(&keypair.secret());
		let sender = t.sender().unwrap();
		let contract = contract_address(&sender, &U256::zero());

		let mut state_result = get_temp_state();
		let mut state = state_result.reference_mut();
		state.add_balance(&sender, &U256::from(18));
		let mut info = EnvInfo::default();
		info.gas_limit = U256::from(100_000);
		let engine = TestEngine::new(0);

		let executed = {
			let mut ex = Executive::new(&mut state, &info, &engine, &factory);
			let opts = TransactOptions { check_nonce: true, tracing: false };
			ex.transact(&t, opts).unwrap()
		};

		assert_eq!(executed.gas, U256::from(100_000));
		assert_eq!(executed.gas_used, U256::from(41_301));
		assert_eq!(executed.refunded, U256::from(58_699));
		assert_eq!(executed.cumulative_gas_used, U256::from(41_301));
		assert_eq!(executed.logs.len(), 0);
		assert_eq!(executed.contracts_created.len(), 0);
		assert_eq!(state.balance(&sender), U256::from(1));
		assert_eq!(state.balance(&contract), U256::from(17));
		assert_eq!(state.nonce(&sender), U256::from(1));
		assert_eq!(state.storage_at(&contract, &H256::new()), H256::from(&U256::from(1)));
	}

	evm_test!{test_transact_invalid_sender: test_transact_invalid_sender_jit, test_transact_invalid_sender_int}
	fn test_transact_invalid_sender(factory: Factory) {
		let t = Transaction {
			action: Action::Create,
			value: U256::from(17),
			data: "3331600055".from_hex().unwrap(),
			gas: U256::from(100_000),
			gas_price: U256::zero(),
			nonce: U256::zero()
		}.invalid_sign();
		let mut state_result = get_temp_state();
		let mut state = state_result.reference_mut();
		let mut info = EnvInfo::default();
		info.gas_limit = U256::from(100_000);
		let engine = TestEngine::new(0);

		let res = {
			let mut ex = Executive::new(&mut state, &info, &engine, &factory);
			let opts = TransactOptions { check_nonce: true, tracing: false };
			ex.transact(&t, opts)
		};

		match res {
			Err(ExecutionError::TransactionMalformed(_)) => (),
			_ => assert!(false, "Expected an invalid transaction error.")
		}
	}

	evm_test!{test_transact_invalid_nonce: test_transact_invalid_nonce_jit, test_transact_invalid_nonce_int}
	fn test_transact_invalid_nonce(factory: Factory) {
		let keypair = KeyPair::create().unwrap();
		let t = Transaction {
			action: Action::Create,
			value: U256::from(17),
			data: "3331600055".from_hex().unwrap(),
			gas: U256::from(100_000),
			gas_price: U256::zero(),
			nonce: U256::one()
		}.sign(&keypair.secret());
		let sender = t.sender().unwrap();

		let mut state_result = get_temp_state();
		let mut state = state_result.reference_mut();
		state.add_balance(&sender, &U256::from(17));
		let mut info = EnvInfo::default();
		info.gas_limit = U256::from(100_000);
		let engine = TestEngine::new(0);

		let res = {
			let mut ex = Executive::new(&mut state, &info, &engine, &factory);
			let opts = TransactOptions { check_nonce: true, tracing: false };
			ex.transact(&t, opts)
		};

		match res {
			Err(ExecutionError::InvalidNonce { expected, got })
				if expected == U256::zero() && got == U256::one() => (),
			_ => assert!(false, "Expected invalid nonce error.")
		}
	}

	evm_test!{test_transact_gas_limit_reached: test_transact_gas_limit_reached_jit, test_transact_gas_limit_reached_int}
	fn test_transact_gas_limit_reached(factory: Factory) {
		let keypair = KeyPair::create().unwrap();
		let t = Transaction {
			action: Action::Create,
			value: U256::from(17),
			data: "3331600055".from_hex().unwrap(),
			gas: U256::from(80_001),
			gas_price: U256::zero(),
			nonce: U256::zero()
		}.sign(&keypair.secret());
		let sender = t.sender().unwrap();

		let mut state_result = get_temp_state();
		let mut state = state_result.reference_mut();
		state.add_balance(&sender, &U256::from(17));
		let mut info = EnvInfo::default();
		info.gas_used = U256::from(20_000);
		info.gas_limit = U256::from(100_000);
		let engine = TestEngine::new(0);

		let res = {
			let mut ex = Executive::new(&mut state, &info, &engine, &factory);
			let opts = TransactOptions { check_nonce: true, tracing: false };
			ex.transact(&t, opts)
		};

		match res {
			Err(ExecutionError::BlockGasLimitReached { gas_limit, gas_used, gas })
				if gas_limit == U256::from(100_000) && gas_used == U256::from(20_000) && gas == U256::from(80_001) => (),
			_ => assert!(false, "Expected block gas limit error.")
		}
	}

	evm_test!{test_not_enough_cash: test_not_enough_cash_jit, test_not_enough_cash_int}
	fn test_not_enough_cash(factory: Factory) {

		let keypair = KeyPair::create().unwrap();
		let t = Transaction {
			action: Action::Create,
			value: U256::from(18),
			data: "3331600055".from_hex().unwrap(),
			gas: U256::from(100_000),
			gas_price: U256::one(),
			nonce: U256::zero()
		}.sign(&keypair.secret());
		let sender = t.sender().unwrap();

		let mut state_result = get_temp_state();
		let mut state = state_result.reference_mut();
		state.add_balance(&sender, &U256::from(100_017));
		let mut info = EnvInfo::default();
		info.gas_limit = U256::from(100_000);
		let engine = TestEngine::new(0);

		let res = {
			let mut ex = Executive::new(&mut state, &info, &engine, &factory);
			let opts = TransactOptions { check_nonce: true, tracing: false };
			ex.transact(&t, opts)
		};

		match res {
			Err(ExecutionError::NotEnoughCash { required , got })
				if required == U512::from(100_018) && got == U512::from(100_017) => (),
			_ => assert!(false, "Expected not enough cash error. {:?}", res)
		}
	}

	evm_test!{test_sha3: test_sha3_jit, test_sha3_int}
	fn test_sha3(factory: Factory) {
		let code = "6064640fffffffff20600055".from_hex().unwrap();

		let sender = Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
		let address = contract_address(&sender, &U256::zero());
		// TODO: add tests for 'callcreate'
		//let next_address = contract_address(&address, &U256::zero());
		let mut params = ActionParams::default();
		params.address = address.clone();
		params.sender = sender.clone();
		params.origin = sender.clone();
		params.gas = U256::from(0x0186a0);
		params.code = Some(code.clone());
		params.value = ActionValue::Transfer(U256::from_str("0de0b6b3a7640000").unwrap());
		let mut state_result = get_temp_state();
		let mut state = state_result.reference_mut();
		state.add_balance(&sender, &U256::from_str("152d02c7e14af6800000").unwrap());
		let info = EnvInfo::default();
		let engine = TestEngine::new(0);
		let mut substate = Substate::new();

		let result = {
			let mut ex = Executive::new(&mut state, &info, &engine, &factory);
			ex.create(params, &mut substate, &mut NoopTracer)
		};

		match result {
			Err(_) => {
			},
			_ => {
				panic!("Expected OutOfGas");
			}
		}
	}
}
