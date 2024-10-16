use clap::{Arg, Command};
use num_bigint::BigInt;
use num_traits::{ToPrimitive, Zero};
use bitcoin::util::address::Address;
use bitcoin::network::constants::Network;
use bitcoin::util::key::PrivateKey;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use std::str::FromStr;
use std::time::{Instant, Duration};
use signal_hook::iterator::Signals;
use signal_hook::consts::SIGINT;
use std::thread;
use std::sync::{Arc, Mutex};
use bitcoin::hashes::hex::ToHex;
use indicatif::{ProgressBar, ProgressStyle};
use rand::{Rng, thread_rng};
use std::collections::HashSet;

const SECP256K1_ORDER_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const MAX_ZEROS: usize = 2; // Maximum zeros allowed
const CHECK_INTERVAL_SECS: u64 = 1; // Check interval in seconds

fn main() {
    let matches = Command::new("Bitcoin Private Key Finder")
        .version("1.0")
        .author("Your Name <you@example.com>")
        .about("Finds Bitcoin private keys that generate a specified address")
        .arg(Arg::new("target_address")
            .short('t')
            .long("target")
            .required(true)
            .help("Target Bitcoin address to find"))
        .arg(Arg::new("batch_size")
            .short('b')
            .long("batch")
            .required(true)
            .help("Number of keys to process in each batch")
            .value_parser(clap::value_parser!(u64)))
        .arg(Arg::new("range")
            .short('r')
            .long("range")
            .required(true)
            .help("Range of private keys in hex format, e.g., start:end"))
        .arg(Arg::new("random")
            .short('R')
            .long("random")
            .action(clap::ArgAction::SetTrue)
            .help("Process keys randomly"))
        .get_matches();

    let target_address_str = matches.get_one::<String>("target_address").expect("Required argument");
    let _batch_size = *matches.get_one::<u64>("batch_size").expect("Required argument");

    // Parse and validate the range
    let range: Vec<&str> = matches.get_one::<String>("range").expect("Required argument").split(':').collect();
    if range.len() != 2 {
        eprintln!("Invalid range format. Use 'start:end'.");
        return;
    }

    let start = BigInt::parse_bytes(range[0].as_bytes(), 16)
        .expect(&format!("Invalid start value: {}", range[0]));

    let end = BigInt::parse_bytes(range[1].as_bytes(), 16)
        .expect(&format!("Invalid end value: {}", range[1]));

    if start >= end {
        eprintln!("Start value must be less than end value.");
        std::process::exit(1);
    }

    let secp = Secp256k1::new();
    let target_address = Address::from_str(target_address_str)
        .expect(&format!("Invalid target address: {}", target_address_str));
    let secp256k1_max_key = BigInt::parse_bytes(SECP256K1_ORDER_HEX.as_bytes(), 16).unwrap();

    let last_checked_hex = Arc::new(Mutex::new(String::new()));
    let last_checked_hex_clone = Arc::clone(&last_checked_hex);
    let mut signals = Signals::new(&[SIGINT]).unwrap();

    // Handle SIGINT
    thread::spawn(move || {
        for _ in signals.forever() {
            let last_hex = last_checked_hex_clone.lock().unwrap();
            println!("Last hex value checked: {}", *last_hex);
            std::process::exit(0);
        }
    });

    let total_keys = (&end - &start).to_u64().unwrap_or(u64::MAX);
    let progress_bar = ProgressBar::new(total_keys);
    progress_bar.set_style(ProgressStyle::default_bar().template("{bar:40.cyan/blue} {pos}/{len} | {msg}").expect("Failed to create progress style"));

    let mut total_checked_keys: u64 = 0;
    let check_interval = Duration::from_secs(CHECK_INTERVAL_SECS);
    let mut last_print_time = Instant::now();
    let random_check = matches.get_one::<bool>("random").is_some();

    pollards_rho(
        target_address,
        &start,
        &end,
        &secp,
        &secp256k1_max_key,
        total_keys,
        &mut total_checked_keys,
        check_interval,
        &mut last_print_time,
        last_checked_hex,
        progress_bar,
        random_check,
    );
}

fn pollards_rho(
    target_address: Address,
    start: &BigInt,
    end: &BigInt,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    secp256k1_max_key: &BigInt,
    total_keys: u64,
    total_checked_keys: &mut u64,
    check_interval: Duration,
    last_print_time: &mut Instant,
    last_checked_hex: Arc<Mutex<String>>,
    progress_bar: ProgressBar,
    random_check: bool,
) {
    let mut current = start.clone();
    let mut rng = thread_rng();
    let mut tried_keys = HashSet::new(); // HashSet to track previously tried keys

    while &current <= end {
        if random_check {
            // Generate a random key while avoiding duplicates
            let mut found_new_key = false;

            while !found_new_key {
                let random_key = random_bigint(&mut rng, start, end);
                if !tried_keys.contains(&random_key) {
                    current = random_key; // Set current to the new random key
                    tried_keys.insert(current.clone()); // Add to tried keys
                    found_new_key = true; // Found a new key
                }

                // Check if we have exhausted all possible keys
                if tried_keys.len() >= total_keys as usize {
                    println!("All possible keys have been tried. Exiting...");
                    return;
                }
            }
        }

        let hex_value = format!("{:x}", current);
        let hex_value_str = hex_value.as_str();

        // Update the last checked hex value in a thread-safe manner
        {
            let mut last_hex = last_checked_hex.lock().unwrap();
            *last_hex = hex_value_str.to_string();
        }

        if count_zeros(&hex_value) > MAX_ZEROS {
            current += BigInt::from(1);
            continue;
        }

        let padded_value = format!("{:0>64}", hex_value);
        let private_key_num = BigInt::parse_bytes(padded_value.as_bytes(), 16).unwrap();

        // Validate private key range
        if private_key_num > BigInt::zero() && private_key_num < *secp256k1_max_key {
            if let Ok(secret_key) = SecretKey::from_str(&padded_value) {
                let priv_key = PrivateKey::new(secret_key, Network::Bitcoin);
                let pub_key = priv_key.public_key(secp);
                let pub_key_hex = pub_key.to_bytes().to_hex();
                let derived_address = Address::p2pkh(&pub_key, Network::Bitcoin);

                if derived_address == target_address {
                    println!("\nFound matching private key: {}", padded_value);
                    println!("Compressed Public Key (Hex): {}", pub_key_hex);
                    println!("Derived Address: {}", derived_address);
                    return;
                }
            }
        }

        *total_checked_keys += 1;

        // Update the progress bar after each key
        progress_bar.inc(1);

        // Update the progress bar message and keys per second
        let keys_per_second = *total_checked_keys as f64 / last_print_time.elapsed().as_secs_f64();
        let remaining_keys = total_keys - *total_checked_keys;

        // Calculate the estimated time remaining and round up
        let estimated_time_remaining = if keys_per_second > 0.0 {
            (remaining_keys as f64 / keys_per_second).ceil() as u64
        } else {
            u64::MAX // Handle division by zero
        };

        // Format estimated time remaining into hours, minutes, and seconds
        let hours = estimated_time_remaining / 3600;
        let minutes = (estimated_time_remaining % 3600) / 60;
        let seconds = estimated_time_remaining % 60;

        let estimated_time_remaining_str = format!(
            "{}h {}m {}s",
            hours, minutes, seconds
        );

        progress_bar.set_message(format!(
            "Keys/s: {:.2} | Checking: {} | Time Remaining: {}",
            keys_per_second,
            hex_value,
            estimated_time_remaining_str
        ));

        current += BigInt::from(1);

        // Reset checked keys and print interval message after the defined interval
        if last_print_time.elapsed() >= check_interval {
            *total_checked_keys = 0;
            *last_print_time = Instant::now();
        }
    }

    progress_bar.finish_with_message("Search completed.");
    println!("Start: {}, End: {}", start.to_str_radix(16), end.to_str_radix(16));
}


fn count_zeros(hex_value: &str) -> usize {
    hex_value.chars().take_while(|&c| c == '0').count()
}

fn random_bigint<R: Rng>(rng: &mut R, start: &BigInt, end: &BigInt) -> BigInt {
    let range = end - start;
    let random_u64: u64 = rng.gen_range(0..range.to_u64().unwrap_or(u64::MAX));
    start + BigInt::from(random_u64)
}
