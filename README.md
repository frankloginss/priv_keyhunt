# Bitcoin Private Key Finder

A command-line utility written in Rust that searches for Bitcoin private keys corresponding to a specified Bitcoin address. The tool efficiently checks a range of private keys, utilizing cryptographic operations to derive public keys and validate them against the target address.

## Features

- **Command-Line Interface**: Simple to use with command-line arguments for specifying target address, batch size, and range of private keys.
- **Efficient Key Checking**: Skips private keys with more than two leading zeros to reduce unnecessary checks.
- **Performance Monitoring**: Displays the number of keys checked per second and the elapsed time for the operation.
- **Signal Handling**: Gracefully handles interrupt signals (like Ctrl+C) to show the last checked hex value before exiting.

## Prerequisites

- Rust (1.54 or later)
- Cargo (comes with Rust installation)

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/frankloginss/priv_keyhunt.git
   cd priv_keyhunt
   ```

2. Build the project:

   ```bash
   cargo build --release
   ```

## Usage

Run the program with the required arguments:

```bash
./target/release/priv_keyhunt --target <TARGET_ADDRESS> --batch <BATCH_SIZE> --range <START:END>
```

### Arguments

- `--target` (`-t`): Target Bitcoin address to find.
- `--batch` (`-b`): Number of keys to process in each batch.
- `--range` (`-r`): Range of private keys in hexadecimal format (e.g., `start:end`).

### Example

```bash
./target/release/bitcoin-private-key-finder --target 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa --batch 1000 --range 0:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
```

## Performance Considerations

This tool is designed to be efficient, but keep in mind that searching for private keys is computationally intensive. The performance may vary based on your machine's specifications.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.

## Acknowledgments

- [Rust Programming Language](https://www.rust-lang.org/)
- [Bitcoin Crate](https://crates.io/crates/bitcoin)
- [Num BigInt Crate](https://crates.io/crates/num-bigint)
- [Clap Crate](https://crates.io/crates/clap)
- [Signal Hook Crate](https://crates.io/crates/signal-hook)
