use criterion::{black_box, criterion_group, criterion_main, Criterion};
use native_vs_evm::evm::Machine;
use std::collections::HashMap;

fn bench_simple_add(c: &mut Criterion) {
    let bytecode = hex::decode("6005600a01").unwrap(); // PUSH1 0x05, PUSH1 0x0a, ADD

    c.bench_function("simple_add", |b| {
        b.iter(|| {
            let mut machine = Machine::new(bytecode.clone(), vec![], HashMap::new(), 1_000_000);
            let result = machine.run();
            black_box(result);
        })
    });
}

criterion_group!(benches, bench_simple_add);
criterion_main!(benches);