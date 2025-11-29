use native_vs_evm::evm::{ExecutionResult, Machine};
use std::collections::HashMap;

fn main() {
    // PUSH1 0x05, PUSH1 0x0a, ADD, PUSH1 0x00, MSTORE, PUSH1 0x20, PUSH1 0x00, RETURN
    let bytecode = hex::decode("6005600a0160005260206000f3").unwrap();

    let mut machine = Machine::new(bytecode, vec![], HashMap::new(), 1_000_000);
    let result = machine.run();

    println!("EVM execution finished.");
    println!("Final state: {:?}", machine);

    match result {
        ExecutionResult::Success(return_data) => {
            if return_data.is_empty() {
                println!("Success! No data returned.");
            } else {
                println!("Success! Return data (hex): 0x{}", hex::encode(&return_data));
            }
        }
        ExecutionResult::Revert(return_data) => {
            println!("Execution reverted! Return data (hex): 0x{}", hex::encode(&return_data));
        }
        ExecutionResult::OutOfGas => println!("Error: Out of Gas!"),
        ExecutionResult::InvalidOpcode => println!("Error: Invalid Opcode!"),
        ExecutionResult::InvalidJump => println!("Error: Invalid Jump Destination!"),
        ExecutionResult::StackUnderflow => println!("Error: Stack Underflow!"),
    }
}