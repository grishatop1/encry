use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process;
use std::io;
use std::fs;
use std::fs::File;

use clap::Parser;

use sha3::{Digest, Sha3_256};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm // Or `Aes128Gcm`
};

mod utils;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Decrypt file
    #[arg(long, short, action)]
    decrypt: bool,

    #[clap(group = "input")]
    input_file: String
}

fn main() {
    let args = Args::parse();

    let path = Path::new(&args.input_file);
    if !path.is_file() {
        println!("Not a file or it doesn't exists...");
        process::exit(1);
    }

    let stdin = io::stdin();
    let mut input = &mut String::new();
    print!("Enter password: ");
    io::stdout().flush().unwrap();
    stdin.read_line(&mut input).unwrap();

    println!("Reading the file...");
    let data: Vec<u8>;
    match fs::read(path) {
        Ok(f_data) => data = f_data,
        Err(_) => {
            println!("Failed to read file :(");
            process::exit(1);
        }
    }

    if !&args.decrypt {
        encrypt(path.to_path_buf(), input.to_string(), data);
    }
}

fn encrypt(path: PathBuf, password: String, data: Vec<u8>) {
    println!("Encrypting...");

    let mut hasher = Sha3_256::new();
    hasher.update(password);
    let encrypt_hash = hasher.finalize();

    let mut hasher = Sha3_256::new();
    hasher.update(encrypt_hash);
    let password_hash = hasher.finalize();

    let cipher = Aes256Gcm::new(&encrypt_hash);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, &*data).unwrap();

    let output_path = utils::append_ext("encrypted", &path);

    let mut file = File::create(output_path).unwrap();
    file.write_all(&password_hash).unwrap();
    file.write_all(&ciphertext).unwrap();

    println!("Done.");
}