use ruint::aliases::U256;
use alloy::primitives::{keccak256, Address};
use std::collections::HashMap;
use std::collections::HashSet;
use std::rc::Rc;
use std::vec::Vec;

const STOP: u8 = 0x00;
const ADD: u8 = 0x01;
const MUL: u8 = 0x02;
const SUB: u8 = 0x03;
const DIV: u8 = 0x04;
const LT: u8 = 0x10;
const GT: u8 = 0x11;
const EQ: u8 = 0x14;
const ISZERO: u8 = 0x15;
const SHA3: u8 = 0x20;
const CALLDATALOAD: u8 = 0x35;
const MLOAD: u8 = 0x51;
const MSTORE: u8 = 0x52;
const POP: u8 = 0x50;
const SLOAD: u8 = 0x54;
const SSTORE: u8 = 0x55;
const JUMP: u8 = 0x56;
const JUMPI: u8 = 0x57;
const JUMPDEST: u8 = 0x5b;
const PUSH1: u8 = 0x60;
const PUSH32: u8 = 0x7f;
const DUP1: u8 = 0x80;
const DUP16: u8 = 0x8f;
const SWAP1: u8 = 0x90;
const SWAP16: u8 = 0x9f;
const CALL: u8 = 0xf1;
const RETURNDATASIZE: u8 = 0x3d;
const RETURNDATACOPY: u8 = 0x3e;
const RETURN: u8 = 0xf3;
const REVERT: u8 = 0xfd;

#[derive(Debug, PartialEq)]
pub enum ExecutionResult {
    Success(Vec<u8>),
    Revert(Vec<u8>),
    OutOfGas,
    InvalidOpcode,
    InvalidJump,
    StackUnderflow
}

#[derive(Debug, Clone, Default)]
pub struct Account {
    pub balance: U256,
    pub code: Rc<Vec<u8>>,
    pub jumpdests: Rc<HashSet<usize>>,
    pub storage: HashMap<U256, U256>,
    pub nonce: u64
}

#[derive(Debug)]
pub struct Frame {
    pub pc: usize,
    pub stack: Vec<U256>,
    pub memory: Vec<u8>,
    pub memory_size_words: u64,
    pub calldata: Vec<u8>,
    pub gas: u64,

    pub code: Rc<Vec<u8>>,
    pub jumpdests: Rc<HashSet<usize>>,
    pub caller: Address,
    pub callee: Address,
}

#[derive(Debug)]
pub struct Machine {
    pub accounts: HashMap<Address, Account>,
    pub call_stack: Vec<Frame>,
    pub return_data: Vec<u8>,

    #[doc(hidden)]
    last_call_return: (usize, usize),
}

impl Machine {
    pub fn new(code: Vec<u8>, calldata: Vec<u8>, storage: HashMap<U256, U256>, gas_limit: u64) -> Self {
        let caller = Address::ZERO;
        let callee: Address = "0x1000000000000000000000000000000000000000".parse().unwrap();

        let code_rc = Rc::new(code);
        let jumpdests_rc = Rc::new(Self::analyze_jumpdests(&code_rc));

        let mut accounts = HashMap::new();
        accounts.insert(callee, Account {
            balance: U256::ZERO,
            code: code_rc.clone(),
            jumpdests: jumpdests_rc.clone(),
            storage,
            nonce: 0
        });

        let initial_frame = Frame {
            pc: 0,
            stack: Vec::with_capacity(1024),
            memory: Vec::new(),
            memory_size_words: 0,
            calldata,
            gas: gas_limit,
            code: code_rc.clone(),
            jumpdests: jumpdests_rc,
            caller,
            callee,
        };

        Self {
            accounts,
            call_stack: vec![initial_frame],
            return_data: Vec::new(),
            last_call_return: (0, 0),
        }
    }

    fn analyze_jumpdests(code: &[u8]) -> HashSet<usize> {
        let mut dests = HashSet::new();
        let mut i = 0;
        while i < code.len() {
            let opcode = code[i];
            if opcode == JUMPDEST {
                dests.insert(i);
            } else if (PUSH1..=PUSH32).contains(&opcode) {
                i += (opcode - PUSH1 + 1) as usize;
            }
            i += 1;
        }
        dests
    }

    pub fn run(&mut self) -> ExecutionResult {
        loop {
              if self.call_stack.is_empty() {
                  return ExecutionResult::Success(std::mem::take(&mut self.return_data));
              }
              if let Err(e) = self.step() {
                  return e;
              }
        }
    }

    fn handle_frame_end(&mut self, success: bool, offset: usize, size: usize) {
        let ended_frame = self.call_stack.pop().unwrap();
        if size > 0 {
            self.return_data = ended_frame.memory.get(offset..offset + size).unwrap_or_default().to_vec();
        } else {
            self.return_data.clear();
        }

        if let Some(caller_frame) = self.call_stack.last_mut() {
            caller_frame.gas += ended_frame.gas;
            caller_frame.stack.push(if success { U256::from(1) } else { U256::ZERO });

            let (ret_offset, ret_size) = self.last_call_return;
            let size_to_copy = self.return_data.len().min(ret_size);
            if size_to_copy > 0 {
                caller_frame.memory_resize(ret_offset + size_to_copy);
                caller_frame.memory[ret_offset..ret_offset + size_to_copy].copy_from_slice(&self.return_data[..size_to_copy]);
            }
        }
    }

    fn step(&mut self) -> Result<(), ExecutionResult> {
        let frame = self.call_stack.last_mut().unwrap();
        if frame.pc >= frame.code.len() {
            self.handle_frame_end(true, 0, 0);
            return Ok(());
        }

        let opcode = frame.read_opcode();

        let cost = Self::get_opcode_cost(opcode);
        if frame.gas < cost {
            frame.gas = 0;
            return Err(ExecutionResult::OutOfGas);
        }
        frame.gas -= cost;

        match opcode {
            STOP => self.handle_frame_end(true, 0, 0),
            RETURN => {
                let offset = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?.as_limbs()[0] as usize;
                let size = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?.as_limbs()[0] as usize;
                frame.charge_memory_expansion_gas(offset, size)?;
                self.handle_frame_end(true, offset, size);
            }
            REVERT => {
                let offset = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?.as_limbs()[0] as usize;
                let size = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?.as_limbs()[0] as usize;
                frame.charge_memory_expansion_gas(offset, size)?;
                self.handle_frame_end(false, offset, size);
                return Err(ExecutionResult::Revert(self.return_data.clone()));
            }
            ADD => {
                let a = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?;
                let b = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?;
                let (res, _) = a.overflowing_add(b);
                frame.stack.push(res);
            }
            MUL => {
                let a = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?;
                let b = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?;
                let (res, _) = a.overflowing_mul(b);
                frame.stack.push(res);
            }
            SUB => {
                let b = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?;
                let a = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?;
                let (res, _) = a.overflowing_sub(b);
                frame.stack.push(res);
            }
            DIV => {
                let b = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?;
                let a = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?;
                if b.is_zero() {
                    frame.stack.push(U256::ZERO);
                } else {
                    frame.stack.push(a / b);
                }
            }
            LT => {
                let b = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?;
                let a = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?;
                frame.stack.push(if a < b { U256::from(1) } else { U256::ZERO });
            }
            GT => {
                let b = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?;
                let a = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?;
                frame.stack.push(if a > b { U256::from(1) } else { U256::ZERO });
            }
            EQ => {
                let b = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?;
                let a = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?;
                frame.stack.push(if a == b { U256::from(1) } else { U256::ZERO });
            }
            ISZERO => {
                let a = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?;
                frame.stack.push(if a.is_zero() { U256::from(1) } else { U256::ZERO });
            }
            SHA3 => {
                let offset = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?.as_limbs()[0] as usize;
                let size = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?.as_limbs()[0] as usize;

                frame.charge_memory_expansion_gas(offset, size)?;
                frame.memory_resize(offset + size);
                let data = &frame.memory[offset..offset+size];
                let hash = keccak256(data);

                frame.stack.push(U256::from_be_bytes(hash.0));

            }
            CALLDATALOAD => {
                let offset = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?.as_limbs()[0] as usize;
                let mut data = [0u8; 32];

                if offset < frame.calldata.len() {
                    let end = (offset + 32).min(frame.calldata.len());
                    let slice = &frame.calldata[offset..end];
                    data[..slice.len()].copy_from_slice(slice);
                }

                frame.stack.push(U256::from_be_bytes(data));
            }
            MLOAD => {
                let offset = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?.as_limbs()[0] as usize;
                frame.charge_memory_expansion_gas(offset, 32)?;
                frame.memory_resize(offset + 32);
                let mut data = [0u8; 32];
                data.copy_from_slice(&frame.memory[offset..offset + 32]);
                frame.stack.push(U256::from_be_bytes(data));
            }
            MSTORE => {
                let offset = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?.as_limbs()[0] as usize;
                let value = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?;
                frame.charge_memory_expansion_gas(offset, 32)?;
                frame.memory_resize(offset + 32);
                frame.memory[offset..offset + 32].copy_from_slice(&value.to_be_bytes::<32>());
            }
            SLOAD => {
                let key = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?;
                let value = self.accounts.get(&frame.callee).map_or(U256::ZERO, |acc| acc.storage.get(&key).cloned().unwrap_or_default());
                frame.stack.push(value);
            }
            SSTORE => {
                let key = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?;
                let value = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?;
                self.accounts
                        .entry(frame.callee)
                        .or_default()
                        .storage
                        .insert(key, value);
            }
            JUMP => {
                let dest = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?.as_limbs()[0] as usize;
                if !frame.jumpdests.contains(&dest) {
                    return Err(ExecutionResult::InvalidJump);
                }
                frame.pc = dest;
            }
            JUMPI => {
                let dest = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?.as_limbs()[0] as usize;
                let cond = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?;

                if !frame.jumpdests.contains(&dest) {
                    return Err(ExecutionResult::InvalidJump);
                } else if !cond.is_zero() {
                    frame.pc = dest;
                }
            }
            JUMPDEST => {
                //
            }
            op if (PUSH1..=PUSH32).contains(&op) => {
                let num_bytes_to_push = (op - PUSH1 + 1) as usize;
                let start = frame.pc;
                let end = frame.pc + num_bytes_to_push;

                if end > frame.code.len() {
                    let mut value_bytes_padded = vec![0; num_bytes_to_push];
                    let existing_bytes = &frame.code[start..frame.code.len()];
                    value_bytes_padded[..existing_bytes.len()].copy_from_slice(existing_bytes);
                    frame.stack.push(U256::from_be_slice(&value_bytes_padded));
                    frame.pc = frame.code.len();
                } else {
                    let value_bytes = &frame.code[start..end];
                    frame.stack.push(U256::from_be_slice(value_bytes));
                    frame.pc = end;
                }
            }
            POP => {
                frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?;
            }
            op if (DUP1..=DUP16).contains(&op) => {
                let index = (op - DUP1) as usize;
                 if frame.stack.len() <= index {
                     return Err(ExecutionResult::StackUnderflow);
                 }
                let val = frame.stack[frame.stack.len() - 1 - index].clone();
                frame.stack.push(val);
            }
            op if (SWAP1..=SWAP16).contains(&op) => {
                let index = (op - SWAP1 + 1) as usize;
                 if frame.stack.len() <= index {
                     return Err(ExecutionResult::StackUnderflow);
                 }
                let a = frame.stack.len() - 1;
                let b = frame.stack.len() - 1 - index;
                frame.stack.swap(a, b);
            }
            CALL => {
                let gas_limit_u256 = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?;
                let to_address_u256 = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?;
                let to_address = Address::from_word(to_address_u256.to_be_bytes().into());
                let _value = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?;
                let args_offset = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?.as_limbs()[0] as usize;
                let args_size = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?.as_limbs()[0] as usize;
                let ret_offset = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?.as_limbs()[0] as usize;
                let ret_size = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?.as_limbs()[0] as usize;

                frame.charge_memory_expansion_gas(args_offset, args_size)?;
                frame.charge_memory_expansion_gas(ret_offset, ret_size)?;
                self.last_call_return = (ret_offset, ret_size);

                // 1/64
                let gas_limit = if gas_limit_u256 > U256::from(u64::MAX) { frame.gas } else { gas_limit_u256.as_limbs()[0] };
                let gas_to_send = (frame.gas - (frame.gas / 64)).min(gas_limit);
                frame.gas -= gas_to_send;

                let target_account = self.accounts.get(&to_address).cloned().unwrap_or_default();
                let target_code = target_account.code.clone();
                let new_calldata = if args_size > 0 {
                    frame.memory[args_offset..args_offset + args_size].to_vec()
                } else {
                    vec![]
                };

                let new_frame = Frame {
                    pc: 0,
                    gas: gas_to_send,
                    calldata: new_calldata,
                    code: target_code,
                    jumpdests: target_account.jumpdests,
                    caller: frame.callee,
                    callee: to_address,
                    stack: vec![],
                    memory: vec![],
                    memory_size_words: 0,
                };

                self.call_stack.push(new_frame);
            }
            RETURNDATASIZE => {
                frame.stack.push(U256::from(self.return_data.len()));
            }
            RETURNDATACOPY => {
                let mem_offset = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?.as_limbs()[0] as usize;
                let return_offset = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?.as_limbs()[0] as usize;
                let size = frame.stack.pop().ok_or(ExecutionResult::StackUnderflow)?.as_limbs()[0] as usize;

                if return_offset.saturating_add(size) > self.return_data.len() {
                    return Err(ExecutionResult::InvalidOpcode);
                }

                frame.charge_memory_expansion_gas(mem_offset, size)?;
                frame.memory_resize(mem_offset + size);
                frame.memory[mem_offset..mem_offset + size].copy_from_slice(&self.return_data[return_offset..return_offset + size]);
            }
            _ => {
                return Err(ExecutionResult::InvalidOpcode);
            }
        }
        Ok(())
    }

    fn get_opcode_cost(opcode: u8) -> u64 {
        match opcode {
            STOP | JUMPDEST => 0,
            ADD | SUB | POP | LT | GT | EQ | ISZERO => 3,
            MUL | DIV => 5,
            PUSH1..=PUSH32 => 3,
            DUP1..=DUP16 => 3,
            SWAP1..=SWAP16 => 3,
            MLOAD | MSTORE => 3,
            SSTORE => 20000,
            SLOAD => 800,
            JUMP => 8,
            JUMPI => 10,
            SHA3 => 30,
            _ => 0,
        }
    }
}

impl Frame {
    fn charge_memory_expansion_gas(&mut self, offset: usize, size: usize) -> Result<(), ExecutionResult> {
        let new_size_bytes = offset.saturating_add(size);
        if new_size_bytes == 0 {
            return Ok(());
        }

        let new_size_words = ((new_size_bytes - 1) / 32 + 1) as u64;
        if new_size_words > self.memory_size_words {
            let old_cost = self.calculate_memory_cost(self.memory_size_words);
            let new_cost = self.calculate_memory_cost(new_size_words);
            let cost_diff = new_cost - old_cost;
            if self.gas < cost_diff {
                return Err(ExecutionResult::OutOfGas);
            }
            self.gas -= cost_diff;
            self.memory_size_words = new_size_words
        }

        Ok(())
    }

    fn calculate_memory_cost(&self, words: u64) -> u64 {
        const G_MEMORY: u64 = 3;
        (words * G_MEMORY) + (words*words / 512)
    }

    fn read_opcode(&mut self) -> u8 {
        if self.pc >= self.code.len() {
            return STOP;
        }
        let opcode = self.code[self.pc];
        self.pc += 1;
        opcode
    }

    fn memory_resize(&mut self, new_size: usize) {
        if new_size > self.memory.len() {
            self.memory.resize(new_size, 0);
        }
    }
}