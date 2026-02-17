use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use srx::{compression::{CompressionAlgo, Compressor}, crypto::{derive_key, generate_salt, Encryptor, generate_nonce}};

fn compression_benchmark(c: &mut Criterion) {
    let data_1mb = vec![0u8; 1024 * 1024];
    let data_10mb = vec![0u8; 10 * 1024 * 1024];
    let data_100kb = vec![0u8; 100 * 1024];
    
    let mut group = c.benchmark_group("compression");
    
    group.throughput(Throughput::Bytes(data_100kb.len() as u64));
    group.bench_function("zstd_100kb", |b| {
        let compressor = Compressor::new(CompressionAlgo::Zstd, 3);
        b.iter(|| compressor.compress(black_box(&data_100kb)))
    });
    
    group.throughput(Throughput::Bytes(data_1mb.len() as u64));
    group.bench_function("zstd_1mb", |b| {
        let compressor = Compressor::new(CompressionAlgo::Zstd, 3);
        b.iter(|| compressor.compress(black_box(&data_1mb)))
    });
    
    group.throughput(Throughput::Bytes(data_1mb.len() as u64));
    group.bench_function("lz4_1mb", |b| {
        let compressor = Compressor::new(CompressionAlgo::Lz4, 0);
        b.iter(|| compressor.compress(black_box(&data_1mb)))
    });
    
    group.throughput(Throughput::Bytes(data_10mb.len() as u64));
    group.bench_function("zstd_10mb", |b| {
        let compressor = Compressor::new(CompressionAlgo::Zstd, 3);
        b.iter(|| compressor.compress(black_box(&data_10mb)))
    });
    
    group.finish();
}

fn encryption_benchmark(c: &mut Criterion) {
    let data_1mb = vec![0u8; 1024 * 1024];
    let data_256kb = vec![0u8; 256 * 1024];
    
    let salt = generate_salt();
    let key = derive_key("benchmark_password", &salt).unwrap();
    let encryptor = Encryptor::new(&key);
    
    let mut group = c.benchmark_group("encryption");
    
    group.throughput(Throughput::Bytes(data_256kb.len() as u64));
    group.bench_function("encrypt_256kb", |b| {
        let nonce = generate_nonce();
        b.iter(|| encryptor.encrypt(black_box(&data_256kb), black_box(&nonce)))
    });
    
    group.throughput(Throughput::Bytes(data_1mb.len() as u64));
    group.bench_function("encrypt_1mb", |b| {
        let nonce = generate_nonce();
        b.iter(|| encryptor.encrypt(black_box(&data_1mb), black_box(&nonce)))
    });
    
    group.finish();
}

fn key_derivation_benchmark(c: &mut Criterion) {
    let salt = generate_salt();
    
    c.bench_function("argon2id_key_derivation", |b| {
        b.iter(|| derive_key(black_box("benchmark_password"), black_box(&salt)))
    });
}

criterion_group!(benches, compression_benchmark, encryption_benchmark, key_derivation_benchmark);
criterion_main!(benches);
