use clap::{Parser, Subcommand};
use srx_rs::{compression::CompressionAlgo, Packer, Unpacker};

#[derive(Parser)]
#[command(name = "srx")]
#[command(about = "Modern compressed + encrypted archive format", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Pack {
        #[arg(value_name = "INPUT")]
        input: String,
        #[arg(value_name = "OUTPUT")]
        output: String,
        #[arg(short, long)]
        password: String,
        #[arg(short = 'a', long, default_value = "zstd")]
        algo: String,
        #[arg(short = 'l', long, default_value = "3")]
        level: i32,
    },
    Unpack {
        #[arg(value_name = "INPUT")]
        input: String,
        #[arg(short, long)]
        password: String,
    },
    Info {
        #[arg(value_name = "INPUT")]
        input: String,
        #[arg(short, long)]
        password: String,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Pack { input, output, password, algo, level } => {
            let compression_algo = match algo.to_lowercase().as_str() {
                "zstd" => CompressionAlgo::Zstd,
                "lz4" => CompressionAlgo::Lz4,
                "none" => CompressionAlgo::None,
                _ => {
                    eprintln!("Unknown compression algorithm: {algo}");
                    std::process::exit(1);
                }
            };

            let packer = Packer::new(password)
                .compression_algo(compression_algo)
                .compression_level(level);

            packer.pack(&input, &output)
                .map(|_| {
                    if let Ok(metadata) = std::fs::metadata(&output) {
                        let orig_metadata = std::fs::metadata(&input).unwrap();
                        let ratio = metadata.len() as f64 / orig_metadata.len() as f64;
                        println!("Created {} ({:.1}% of original)", output, ratio * 100.0);
                    }
                })
        }
        Commands::Unpack { input, password } => {
            let unpacker = Unpacker::new(password);
            unpacker.unpack(&input)
                .map(|_| println!("Extracted successfully"))
        }
        Commands::Info { input, password } => {
            let unpacker = Unpacker::new(password);
            unpacker.info(&input)
                .map(|info| {
                    println!("Filename: {}", info.filename);
                    println!("Original size: {} bytes", info.original_size);
                    println!("Compressed size: {} bytes", info.compressed_size);
                    let ratio = info.compressed_size as f64 / info.original_size.max(1) as f64;
                    println!("Ratio: {:.1}%", ratio * 100.0);
                    println!("Chunks: {}", info.chunk_count);
                    println!("Compression: {:?}", info.compression_algo);
                    println!("Encrypted: {}", info.encrypted);
                })
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
