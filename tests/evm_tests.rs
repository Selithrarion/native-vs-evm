use native_vs_evm::evm::*;
use ruint::aliases::U256;
use std::collections::HashMap;
use ruint::uint;
use std::rc::Rc;
use alloy::primitives::{Address};

fn assemble(code: &str) -> Vec<u8> {
    let mut bytecode = Vec::new();
    let mut parts = code.split_whitespace().peekable();
    while let Some(part) = parts.next() {
        let uppercase_part = part.to_uppercase();
        match uppercase_part.as_str() {
            "STOP" => bytecode.push(0x00),
            "ADD" => bytecode.push(0x01),
            "MUL" => bytecode.push(0x02),
            "SUB" => bytecode.push(0x03),
            "DIV" => bytecode.push(0x04),
            "LT" => bytecode.push(0x10),
            "GT" => bytecode.push(0x11),
            "EQ" => bytecode.push(0x14),
            "ISZERO" => bytecode.push(0x15),
            "SHA3" => bytecode.push(0x20),
            "CALLDATALOAD" => bytecode.push(0x35),
            "RETURNDATASIZE" => bytecode.push(0x3d),
            "RETURNDATACOPY" => bytecode.push(0x3e),
            "POP" => bytecode.push(0x50),
            "MLOAD" => bytecode.push(0x51),
            "MSTORE" => bytecode.push(0x52),
            "SLOAD" => bytecode.push(0x54),
            "SSTORE" => bytecode.push(0x55),
            "JUMP" => bytecode.push(0x56),
            "JUMPI" => bytecode.push(0x57),
            "JUMPDEST" => bytecode.push(0x5b),
            "CALL" => bytecode.push(0xf1),
            "RETURN" => bytecode.push(0xf3),
            "REVERT" => bytecode.push(0xfd),
            _ if uppercase_part.starts_with("DUP") => {
                let num_str = &uppercase_part[3..];
                let num = num_str.parse::<u8>().unwrap();
                bytecode.push(0x80 + num - 1);
            }
            _ if uppercase_part.starts_with("SWAP") => {
                let num_str = &uppercase_part[4..];
                let num = num_str.parse::<u8>().unwrap();
                bytecode.push(0x90 + num - 1);
            }
            _ if uppercase_part.starts_with("PUSH") => {
                let num_bytes_str = &uppercase_part[4..];
                let num_bytes = num_bytes_str.parse::<u8>().unwrap();
                bytecode.push(0x60 + num_bytes - 1);

                if let Some(data_part) = parts.next() {
                    let bytes = if data_part.starts_with("0x") {
                        let hex_val = &data_part[2..];
                        let padded_hex = format!("{:0>width$}", hex_val, width = (num_bytes as usize) * 2);
                        hex::decode(padded_hex).unwrap()
                    } else {
                        let num = U256::from_str_radix(data_part, 10).expect("Invalid decimal number");
                        let arr = num.to_be_bytes::<32>();
                        arr[32 - num_bytes as usize..].to_vec()
                    };
                    bytecode.extend(bytes);
                } else {
                    panic!("PUSH instruction is missing data");
                }
            }
            _ => {
                panic!("Unknown assembly instruction: {}", part);
            }
        }
    }
    bytecode
}

#[test]
fn test_add_and_stop() {
    let bytecode = assemble("PUSH1 0x05 PUSH1 0x0a ADD PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN");
    let mut machine = Machine::new(bytecode, vec![], HashMap::new(), 1_000_000);
    let result = machine.run();
    let expected_return = U256::from(15).to_be_bytes::<32>().to_vec();
    assert_eq!(result, ExecutionResult::Success(expected_return));
}

#[test]
fn test_sload_sstore() {
    let bytecode = assemble("PUSH1 0x42 PUSH1 0x01 SSTORE PUSH1 0x01 SLOAD PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN");
    let mut machine = Machine::new(bytecode, vec![], HashMap::new(), 1_000_000);
    let result = machine.run();
    let expected_return = U256::from(0x42).to_be_bytes::<32>().to_vec();
    assert_eq!(result, ExecutionResult::Success(expected_return));
}

#[test]
fn test_calldataload() {
    let bytecode = assemble("PUSH1 0x00 CALLDATALOAD PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN");
    let calldata = hex::decode("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap();
    let mut machine = Machine::new(bytecode, calldata.clone(), HashMap::new(), 1_000_000);
    let result = machine.run();

    let expected_return = U256::from_be_slice(&calldata[0..32]).to_be_bytes::<32>().to_vec();
    assert_eq!(result, ExecutionResult::Success(expected_return));
}

#[test]
fn test_mload_mstore() {
    let value_str = "123456789abcdef";
    let bytecode = assemble(&format!(
        "PUSH32 0x{} PUSH1 0x00 MSTORE PUSH1 0x00 MLOAD PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN",
        value_str
    ));
    let mut machine = Machine::new(bytecode, vec![], HashMap::new(), 1_000_000);
    let result = machine.run();

    let expected_value = U256::from_str_radix(value_str, 16).unwrap();
    let expected_return = expected_value.to_be_bytes::<32>().to_vec();
    assert_eq!(result, ExecutionResult::Success(expected_return));
}

#[test]
fn test_arithmetic() {
    let bytecode = assemble("PUSH1 0x0a PUSH1 0x05 MUL PUSH1 0x02 SUB PUSH1 0x04 DIV PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN");
    let mut machine = Machine::new(bytecode, vec![], HashMap::new(), 1_000_000);
    let result = machine.run();

    let expected_return = U256::from(12).to_be_bytes::<32>().to_vec();
    assert_eq!(result, ExecutionResult::Success(expected_return));
}

#[test]
fn test_jumpi_and_iszero() {
    let bytecode = assemble("PUSH1 0x05 PUSH1 0x03 GT ISZERO PUSH1 0x0e JUMPI PUSH1 0xaa PUSH1 0x11 JUMP JUMPDEST PUSH1 0xbb JUMPDEST PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN");
    let mut machine = Machine::new(bytecode, vec![], HashMap::new(), 1_000_000);
    let result = machine.run();

    let expected_return = U256::from(0xaa).to_be_bytes::<32>().to_vec();
    assert_eq!(result, ExecutionResult::Success(expected_return));
}

#[test]
fn test_sha3() {
    let bytecode = assemble("PUSH5 0x68656c6c6f PUSH1 0x00 MSTORE PUSH1 0x05 PUSH1 0x1b SHA3 PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN");
    let mut machine = Machine::new(bytecode, vec![], HashMap::new(), 1_000_000);
    let result = machine.run();

    let expected_hash = uint!(0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8_U256);
    let expected_return = expected_hash.to_be_bytes::<32>().to_vec();
    assert_eq!(result, ExecutionResult::Success(expected_return));
}

#[test]
fn test_out_of_gas() {
    let bytecode = assemble("PUSH1 0x01 PUSH1 0x02 ADD STOP");
    let mut machine = Machine::new(bytecode, vec![], HashMap::new(), 5);
    let result = machine.run();
    assert_eq!(result, ExecutionResult::OutOfGas);
}

#[test]
fn test_invalid_jump() {
    let bytecode = assemble("PUSH1 0x05 JUMP STOP");
    let mut machine = Machine::new(bytecode, vec![], HashMap::new(), 1_000_000);
    let result = machine.run();
    assert_eq!(result, ExecutionResult::InvalidJump);
}

#[test]
fn test_invalid_opcode() {
    let bytecode = vec![0x0c, 0x00];
    let mut machine = Machine::new(bytecode, vec![], HashMap::new(), 1_000_000);
    let result = machine.run();
    assert_eq!(result, ExecutionResult::InvalidOpcode);
}

#[test]
fn test_revert() {
    let bytecode = assemble("PUSH1 0xde PUSH1 0x00 MSTORE PUSH1 0x01 PUSH1 0x1f REVERT");
    let mut machine = Machine::new(bytecode, vec![], HashMap::new(), 1_000_000);
    let result = machine.run();
    assert_eq!(result, ExecutionResult::Revert(vec![0xde]));
}

#[test]
fn test_simple_call_and_return_data() {
    let sub_code = assemble("PUSH1 0xAA PUSH1 0x1f MSTORE PUSH1 0x01 PUSH1 0x1f RETURN");
    let sub_address: Address = "0x2000000000000000000000000000000000000000".parse().unwrap();

    let main_code = assemble(&format!(
        "PUSH1 0x01 PUSH1 0x00 PUSH1 0x00 PUSH1 0x00 PUSH1 0x00 PUSH20 0x{} PUSH2 5000 CALL POP RETURNDATASIZE PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN",
        sub_address.to_string().strip_prefix("0x").unwrap()
    ));

    let mut machine = Machine::new(main_code, vec![], HashMap::new(), 1_000_000);
    machine.accounts.insert(sub_address, Account {
        code: Rc::new(sub_code),
        ..Default::default()
    });

    let result = machine.run();
    let expected_return = U256::from(1).to_be_bytes::<32>().to_vec();
    assert_eq!(result, ExecutionResult::Success(expected_return));
}