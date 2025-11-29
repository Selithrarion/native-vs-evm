use criterion::{black_box, criterion_group, criterion_main, Criterion};
use native_vs_evm::evm::Machine;
use ruint::aliases::U256;
use std::collections::HashMap;

fn bench_math_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("Math: (5 + 10) * 2");

    group.bench_function("Native Rust", |b| {
        b.iter(|| {
            let a = U256::from(5);
            let b = U256::from(10);
            let multiplier = U256::from(2);
            let res = (a + b) * multiplier;
            black_box(res);
        })
    });


    // PUSH1 0x02, PUSH1 0x0a, PUSH1 0x05, ADD, MUL
    // [2, 10, 5] -> ADD -> [2, 15] -> MUL -> [30]
    let bytecode = hex::decode("6002600a60050102").unwrap();
    group.bench_function("Tiny EVM", |b| {
        b.iter(|| {
            let mut machine = Machine::new(bytecode.clone(), vec![], HashMap::new(), 1_000_000);
            let res = machine.run();
            black_box(res);
        })
    });

    group.finish();
}

criterion_group!(benches, bench_math_comparison);
criterion_main!(benches);